#!/usr/bin/env node
// mcp-http-proxy — HTTP/SSE proxy that enforces an approved tool manifest at call time.
//
// Usage:
//   mcp-http-proxy --manifest <file> --upstream <url> [--port <port>] [--strict] [--auto-update] [--allow-all]
//   mcp-http-proxy --manifest <file> --upstream https://mcp.notion.com/mcp --port 9876
//   mcp-http-proxy --manifest <file> --upstream <url> --auth-secret <hex>   # enable per-agent token validation
//   mcp-http-proxy --manifest <file> --upstream <url> --receipt-key <file>  # enable signed receipts
//
// The proxy listens on a local port and forwards HTTP requests to the upstream
// MCP server, intercepting tools/list and tools/call just like the stdio proxy.
//
// Modes:
//   default      — logs drift to stderr, strips unapproved tools silently
//   --strict     — exits with error on any drift (added, removed, or schema change)
//   --auto-update — updates the manifest file on disk when new tools are detected
//   --allow-all  — passes all tools through without filtering (including dangerous
//                   ones). Still logs drift and dangerous-tool calls for audit.
//                   Use only when you trust the upstream server.
//
// Auth (--auth-secret <hex>):
//   When set, the proxy validates per-agent HMAC-SHA256 tokens on every tools/call.
//   Tokens are extracted from the Authorization: Bearer <token> HTTP header or
//   from _meta.auth.token in the MCP request body. Tools with requiredScopes in
//   the manifest require a valid token with sufficient scopes. Unscoped tools
//   pass without a token.
//
// Receipts (--receipt-key <file>):
//   When set, the proxy loads an Ed25519 keypair and emits signed, hash-chained
//   receipts for every tools/call. Receipts are appended to --receipt-dir (or
//   the default path). Each receipt contains: tool name, args digest, timestamp,
//   result digest, and an Ed25519 signature chained to the previous receipt.
//
// The proxy handles both:
//   - HTTP POST requests (JSON-RPC over HTTP)
//   - SSE streaming responses (Server-Sent Events for streaming results)
//
// For SSE, the proxy buffers the stream, parses JSON-RPC messages, intercepts
// tools/list and tools/call responses, and re-emits the SSE stream.
import { createServer, request } from "node:http";
import { readFileSync, writeFileSync, existsSync, mkdirSync, appendFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { homedir } from "node:os";
import { buildManifest, diffManifest, checkCall, preserveProxyPolicy, canonicalJson } from "../lib/manifest.js";
import { atomicWriteJson } from "../lib/fleet.js";
import { redact } from "../lib/redact.js";
import { DevIssuer, TokenValidator, extractToken, stripAuth } from "../lib/auth.js";
import { SignedReceiptChain, makeReceiptSink, loadReceipts } from "../lib/receipts.js";
import { hashJson } from "../lib/hash.js";

const args = process.argv.slice(2);

// Parse flags
const strictMode = args.includes("--strict");
const autoUpdate = args.includes("--auto-update");
const allowAll = args.includes("--allow-all");

const manifestIdx = args.indexOf("--manifest");
if (manifestIdx === -1 || !args[manifestIdx + 1]) {
  console.error("mcp-http-proxy: --manifest <file> is required");
  console.error("Usage: mcp-http-proxy --manifest <file> --upstream <url> [--port <port>] [--strict] [--auto-update]");
  process.exit(2);
}
const manifestPath = args[manifestIdx + 1];

const upstreamIdx = args.indexOf("--upstream");
if (upstreamIdx === -1 || !args[upstreamIdx + 1]) {
  console.error("mcp-http-proxy: --upstream <url> is required");
  process.exit(2);
}
const upstreamUrl = args[upstreamIdx + 1];

const portIdx = args.indexOf("--port");
const port = portIdx !== -1 && args[portIdx + 1] ? parseInt(args[portIdx + 1], 10) : 9876;

// Parse --auth-secret <hex>: enables per-agent token validation.
// Also supports --auth-secret-file <path> to read the secret from a file
// (useful for launchd/daemon configs where putting the secret in the
// command line would expose it in process listings).
const authSecretIdx = args.indexOf("--auth-secret");
const authSecretFileIdx = args.indexOf("--auth-secret-file");
let authSecret = authSecretIdx !== -1 && args[authSecretIdx + 1] ? args[authSecretIdx + 1] : null;
if (!authSecret && authSecretFileIdx !== -1 && args[authSecretFileIdx + 1]) {
  try {
    authSecret = readFileSync(args[authSecretFileIdx + 1], "utf8").trim();
  } catch (e) {
    console.error(`mcp-http-proxy: failed to read auth secret file: ${e.message}`);
    process.exit(2);
  }
}

// Parse --receipt-key <file>: enables signed, chained receipts.
const receiptKeyIdx = args.indexOf("--receipt-key");
const receiptKeyPath = receiptKeyIdx !== -1 && args[receiptKeyIdx + 1] ? args[receiptKeyIdx + 1] : null;

// Parse --receipt-dir <dir>: where to store receipt chain files.
const receiptDirIdx = args.indexOf("--receipt-dir");
const receiptDir = receiptDirIdx !== -1 && args[receiptDirIdx + 1]
  ? args[receiptDirIdx + 1]
  : join(homedir(), ".local", "share", "maos-mcp", "receipts");

// Set up token validator if auth-secret is provided.
let tokenValidator = null;
if (authSecret) {
  const devIssuer = new DevIssuer({ secret: authSecret });
  tokenValidator = new TokenValidator({ devIssuer });
  log("Auth enabled: per-agent token validation with HMAC-SHA256");
}

// Set up signed receipt chain if receipt-key is provided.
let receiptChain = null;
let receiptSink = null;
if (receiptKeyPath) {
  try {
    const keyDoc = JSON.parse(readFileSync(receiptKeyPath, "utf8"));
    if (!keyDoc.privateKey) {
      console.error("mcp-http-proxy: receipt key file missing privateKey field");
      process.exit(2);
    }
    // Ensure receipt directory exists
    if (!existsSync(receiptDir)) mkdirSync(receiptDir, { recursive: true });
    const receiptFile = join(receiptDir, "receipts.ndjson");
    receiptChain = new SignedReceiptChain({ privateKey: keyDoc.privateKey, receipts: loadReceipts(receiptFile) });
    receiptSink = makeReceiptSink(receiptFile);
    log(`Receipts enabled: signed chain → ${receiptFile} (keyId: ${receiptChain.keyId})`);
  } catch (e) {
    console.error(`mcp-http-proxy: failed to load receipt key: ${e.message}`);
    process.exit(2);
  }
}

// Load manifest
let manifest;
try {
  manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
} catch (e) {
  console.error(`mcp-http-proxy: failed to load manifest: ${e.message}`);
  process.exit(2);
}

let approvedNames = new Set(manifest.tools.map((t) => t.name));
let driftedNames = new Set();

// Parse upstream URL
const upstream = new URL(upstreamUrl);
const upstreamHeaders = {
  "Content-Type": "application/json",
  "Accept": "application/json, text/event-stream",
};

// Copy auth headers from upstream URL (e.g. embedded query params or basic auth)
if (upstream.username) {
  upstreamHeaders["Authorization"] = `Basic ${Buffer.from(`${upstream.username}:${upstream.password}`).toString("base64")}`;
}

// Log to stderr (redacted to prevent secret leakage)
function log(msg) {
  process.stderr.write(`[mcp-http-proxy] ${redact(msg)}\n`);
}

// Pass through GET (SSE stream) and DELETE (session close) requests to the
// upstream without interception. These are part of the MCP streamable-http
// transport and don't carry tool/call or tools/list payloads to inspect.
// For GET SSE streams, we pipe the response through without buffering.
async function proxyPassthrough(req, res) {
  const opts = {
    hostname: upstream.hostname,
    port: upstream.port,
    path: upstream.pathname + (upstream.search || ""),
    method: req.method,
    headers: {
      ...upstreamHeaders,
      ...req.headers,
      Host: upstream.host,
    },
  };
  // Remove content-type for GET (no body)
  if (req.method === "GET") {
    delete opts.headers["Content-Type"];
    delete opts.headers["Content-Length"];
  }

  const upstreamReq = request(opts, (upstreamRes) => {
    // Forward status and headers
    res.writeHead(upstreamRes.statusCode, upstreamRes.headers);
    // Pipe the response through (handles SSE streams and regular responses)
    upstreamRes.pipe(res);
  });

  upstreamReq.on("error", (e) => {
    log(`passthrough error: ${redact(e.message)}`);
    if (!res.headersSent) {
      res.writeHead(502, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "upstream error", detail: redact(e.message) }));
    }
  });

  // For DELETE, send the request body through (if any)
  if (req.method === "DELETE") {
    req.pipe(upstreamReq);
  } else {
    upstreamReq.end();
  }
}

// Forward a request to the upstream server, collect the response (handling SSE),
// intercept tools/list and tools/call, and send the response back to the client.
async function handleRequest(req, res) {
  // Read request body
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const bodyStr = Buffer.concat(chunks).toString("utf8");

  let rpcMsg;
  try {
    rpcMsg = JSON.parse(bodyStr);
  } catch {
    res.writeHead(400, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "invalid JSON" }));
    return;
  }

  // Intercept tools/call — block unapproved tools + enforce auth scopes
  let authToken = null;
  let callManifest = null;
  if (rpcMsg.method === "tools/call" && rpcMsg.id != null) {
    const toolName = rpcMsg.params?.name;

    // Extract and validate auth token if auth-secret is configured.
    if (tokenValidator) {
      // Check Authorization: Bearer <token> HTTP header first, then _meta.auth.token
      const authHeader = req.headers["authorization"];
      let rawToken = null;
      if (authHeader && authHeader.startsWith("Bearer ")) {
        rawToken = authHeader.slice(7);
      } else {
        rawToken = extractToken(rpcMsg);
      }
      if (rawToken) {
        authToken = await tokenValidator.validate(rawToken);
        if (!authToken || !authToken.isValid) {
          const reason = !authToken
            ? "invalid auth token (signature verification failed)"
            : authToken.isExpired
              ? `auth token expired at ${authToken.expiresAt}`
              : "auth token is inactive";
          log(`BLOCKED tools/call: ${reason}`);
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({
            jsonrpc: "2.0",
            id: rpcMsg.id,
            error: { code: -32600, message: `mcp-http-proxy: ${reason}` },
          }));
          return;
        }
        log(`Auth: agent "${authToken.subject}" scopes=[${authToken.scopes.join(", ")}]`);
      }
    }

    // checkCall validates manifest membership, danger flag, and scope requirements.
    // In --allow-all mode, skip the check but still log dangerous calls.
    callManifest = manifest;
    const check = allowAll
      ? { allowed: true, reason: null }
      : driftedNames.has(toolName)
        ? { allowed: false, reason: `tool "${toolName}" contract drifted; explicit reapproval required` }
        : checkCall(manifest, toolName, rpcMsg.params?.arguments ?? {}, authToken);
    if (!check.allowed) {
      log(`BLOCKED tools/call: ${check.reason}`);
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({
        jsonrpc: "2.0",
        id: rpcMsg.id,
        error: { code: -32601, message: `mcp-http-proxy: ${check.reason}` },
      }));
      return;
    }
    if (allowAll) {
      const entry = (callManifest ?? manifest).tools.find((t) => t.name === toolName);
      if (entry?.allowed === false) {
        log(`ALLOW-ALL: dangerous tool "${toolName}" called (score=${entry.dangerScore}, confidence=${entry.dangerConfidence}) — forwarded`);
      }
    }
  }

  // Strip auth metadata from the request before forwarding to upstream.
  // The upstream MCP server should not see trustcard-internal auth fields.
  let forwardBody = bodyStr;
  if (authToken && rpcMsg.params?._meta) {
    const cleaned = stripAuth(rpcMsg);
    forwardBody = JSON.stringify(cleaned);
  }

  // Forward to upstream
  const upstreamPath = upstream.pathname + upstream.search;
  // Forward client's session ID header to upstream if present.
  const fwdHeaders = { ...upstreamHeaders };
  const clientSessionId = req.headers["mcp-session-id"];
  if (clientSessionId) {
    fwdHeaders["Mcp-Session-Id"] = clientSessionId;
  }
  const upstreamReq = await fetch(`${upstream.origin}${upstreamPath}`, {
    method: "POST",
    headers: fwdHeaders,
    body: forwardBody,
  });

  // Check if response is SSE
  const contentType = upstreamReq.headers.get("content-type") || "";

  if (contentType.includes("text/event-stream")) {
    // SSE streaming — buffer events, intercept tools/list, re-emit
    // Forward upstream session ID header if present.
    const responseHeaders = {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      "Connection": "keep-alive",
    };
    const sessionId = upstreamReq.headers.get("mcp-session-id");
    if (sessionId) {
      responseHeaders["Mcp-Session-Id"] = sessionId;
    }
    res.writeHead(200, responseHeaders);

    const reader = upstreamReq.body.getReader();
    const decoder = new TextDecoder();
    let sseBuffer = "";
    let collectedData = "";
    let isToolsList = rpcMsg.method === "tools/list" && rpcMsg.id != null;

    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        const text = decoder.decode(value, { stream: true });
        sseBuffer += text;
        collectedData += text;

        // Process complete SSE events (separated by \n\n, handling CRLF)
        sseBuffer = sseBuffer.replace(/\r\n/g, "\n");
        let eventEnd;
        while ((eventEnd = sseBuffer.indexOf("\n\n")) >= 0) {
          const eventStr = sseBuffer.slice(0, eventEnd);
          sseBuffer = sseBuffer.slice(eventEnd + 2);

          // Parse SSE event
          const lines = eventStr.split("\n");
          let eventType = "message";
          let dataLines = [];
          for (const line of lines) {
            if (line.startsWith("event:")) eventType = line.slice(6).trim();
            else if (line.startsWith("data:")) dataLines.push(line.slice(5).trim());
          }
          const dataStr = dataLines.join("\n");

          // Try to parse as JSON-RPC
          if (isToolsList && dataStr) {
            try {
              const msg = JSON.parse(dataStr);
              if (msg.id != null && msg.result?.tools) {
                // This is the tools/list response — intercept it
                const liveTools = msg.result.tools || [];
                const diff = diffManifest(manifest, liveTools);
      driftedNames = new Set(diff.drifted.map((t) => t.name));

                if (diff.added.length > 0) {
                  log(`DRIFT: ${diff.added.length} new tool(s): ${diff.added.join(", ")}`);
                }
                if (diff.removed.length > 0) {
                  log(`DRIFT: ${diff.removed.length} removed: ${diff.removed.join(", ")}`);
                }
                if (diff.drifted.length > 0) {
                  for (const d of diff.drifted) {
                    log(`DRIFT: "${d.name}" schema changed`);
                  }
                }
                if (diff.ok) {
                  log(`tools/list OK: ${liveTools.length} tools match manifest`);
                }

                if (strictMode && !diff.ok) {
                  log(`STRICT MODE: drift detected, returning error`);
                  const errorEvent = `event: message\ndata: ${JSON.stringify({
                    jsonrpc: "2.0",
                    id: msg.id,
                    error: {
                      code: -32603,
                      message: `mcp-http-proxy: manifest drift in strict mode — ${diff.added.length} added, ${diff.removed.length} removed, ${diff.drifted.length} drifted`,
                    },
                  })}\n\n`;
                  res.write(errorEvent);
                  res.end();
                  return;
                }

                if (autoUpdate && diff.added.length > 0) {
                  const newManifest = preserveProxyPolicy(manifest, buildManifest(liveTools, manifest.serverInfo, manifest.spec));
                  try {
                    const original = readFileSync(manifestPath, "utf8");
          if (canonicalJson(JSON.parse(original)) !== canonicalJson(manifest)) throw new Error("manifest changed on disk; reload policy before auto-update");
          atomicWriteJson(manifestPath, newManifest, { expected: original });
                    manifest = newManifest;
                    driftedNames.clear();
                    approvedNames = new Set(newManifest.tools.map((t) => t.name));
                    log(`AUTO-UPDATE: manifest updated — ${diff.added.length} new tool(s) approved`);
                  } catch (e) {
                    log(`AUTO-UPDATE FAILED: ${e.message}`);
                  }
                  const approved = liveTools.filter((t) => manifest.tools.find((m) => m.name === t.name)?.allowed === true && !driftedNames.has(t.name));
                  res.write(`event: ${eventType}\ndata: ${JSON.stringify({ ...msg, result: { ...msg.result, tools: approved } })}\n\n`);
                } else if (allowAll) {
                  // --allow-all: pass all tools through without filtering
                  const dangerousCount = liveTools.filter((t) => {
                    const entry = manifest.tools.find((m) => m.name === t.name);
                    return entry?.allowed === false;
                  }).length;
                  if (dangerousCount > 0) {
                    log(`ALLOW-ALL: passing through ${dangerousCount} dangerous tool(s) unfiltered`);
                  }
                  res.write(`event: ${eventType}\ndata: ${dataStr}\n\n`);
                } else {
                  // Default: strip unapproved tools
                  const filteredTools = liveTools.filter((t) => approvedNames.has(t.name) && !driftedNames.has(t.name) && manifest.tools.find((m) => m.name === t.name)?.allowed === true);
                  if (filteredTools.length !== liveTools.length) {
                    log(`Filtered ${liveTools.length - filteredTools.length} unapproved tool(s)`);
                  }
                  const filteredMsg = { ...msg, result: { ...msg.result, tools: filteredTools } };
                  res.write(`event: ${eventType}\ndata: ${JSON.stringify(filteredMsg)}\n\n`);
                }
                continue; // Don't re-emit the original event
              }
            } catch {
              // Not JSON — pass through
            }
          }

          // Pass through the event
          // For tools/call responses over SSE, emit a receipt if configured.
          if (rpcMsg.method === "tools/call" && rpcMsg.id != null && receiptChain && dataStr) {
            try {
              const msg = JSON.parse(dataStr);
              if (msg.id != null && msg.result && !msg.error) {
                const toolName = rpcMsg.params?.name;
                const toolArgs = rpcMsg.params?.arguments ?? {};
                const entry = (callManifest ?? manifest).tools.find((t) => t.name === toolName);
                const receipt = receiptChain.append({
                  schema: "trustcard.dev/receipt@1",
                  at: new Date().toISOString(),
                  server: manifest.serverInfo?.name ?? manifest.spec ?? null,
                  tool: toolName,
                  toolDigest: entry?.schemaHash ?? null,
                  toolsetDigest: callManifest.tools.every((t) => t.contractDigest) ? hashJson({ toolset: callManifest.tools.map((t) => t.contractDigest).sort() }) : null,
                  policyDigest: hashJson(callManifest),
                  serverDigest: null,
                  protocolVersion: null,
                  argumentsDigest: hashJson(toolArgs),
                  resultDigest: msg.result !== undefined ? hashJson(msg.result) : null,
                  annotations: null,
                  capabilityDigest: entry?.contractDigest ?? null,
                  relyingParty: authToken?.subject ?? null,
                  environment: null,
                });
                receiptSink?.(receipt);
                log(`Receipt #${receipt.seq}: ${receipt.receiptDigest?.slice(0, 16) ?? "?"}`);
              }
            } catch {
              // Not JSON or parse error — still pass through
            }
          }
          res.write(`event: ${eventType}\ndata: ${dataStr}\n\n`);
        }
      }
    } catch (e) {
      log(`SSE stream error: ${redact(e.message)}`);
    }
    res.end();
  } else {
    // Regular JSON response
    const responseText = await upstreamReq.text();
    let responseMsg;
    try {
      responseMsg = JSON.parse(responseText);
    } catch {
      // Not JSON — pass through
      res.writeHead(upstreamReq.status, { "Content-Type": contentType });
      res.end(responseText);
      return;
    }

    // Intercept tools/list response
    if (rpcMsg.method === "tools/list" && rpcMsg.id != null && responseMsg.result?.tools) {
      const liveTools = responseMsg.result.tools || [];
      const diff = diffManifest(manifest, liveTools);
      driftedNames = new Set(diff.drifted.map((t) => t.name));

      if (diff.added.length > 0) log(`DRIFT: ${diff.added.length} new tool(s): ${diff.added.join(", ")}`);
      if (diff.removed.length > 0) log(`DRIFT: ${diff.removed.length} removed: ${diff.removed.join(", ")}`);
      if (diff.drifted.length > 0) {
        for (const d of diff.drifted) log(`DRIFT: "${d.name}" schema changed`);
      }
      if (diff.ok) log(`tools/list OK: ${liveTools.length} tools match manifest`);

      if (strictMode && !diff.ok) {
        log(`STRICT MODE: drift detected, returning error`);
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({
          jsonrpc: "2.0",
          id: rpcMsg.id,
          error: {
            code: -32603,
            message: `mcp-http-proxy: manifest drift in strict mode — ${diff.added.length} added, ${diff.removed.length} removed, ${diff.drifted.length} drifted`,
          },
        }));
        return;
      }

      if (autoUpdate && diff.added.length > 0) {
        const newManifest = preserveProxyPolicy(manifest, buildManifest(liveTools, manifest.serverInfo, manifest.spec));
        try {
          const original = readFileSync(manifestPath, "utf8");
          if (canonicalJson(JSON.parse(original)) !== canonicalJson(manifest)) throw new Error("manifest changed on disk; reload policy before auto-update");
          atomicWriteJson(manifestPath, newManifest, { expected: original });
          manifest = newManifest;
                    driftedNames.clear();
          approvedNames = new Set(newManifest.tools.map((t) => t.name));
          log(`AUTO-UPDATE: manifest updated — ${diff.added.length} new tool(s) approved`);
        } catch (e) {
          log(`AUTO-UPDATE FAILED: ${e.message}`);
        }
      } else if (allowAll) {
        // --allow-all: pass all tools through without filtering
        const dangerousCount = liveTools.filter((t) => {
          const entry = manifest.tools.find((m) => m.name === t.name);
          return entry?.allowed === false;
        }).length;
        if (dangerousCount > 0) {
          log(`ALLOW-ALL: passing through ${dangerousCount} dangerous tool(s) unfiltered`);
        }
      } else {
        // Default: strip unapproved tools
        const filteredTools = liveTools.filter((t) => approvedNames.has(t.name) && !driftedNames.has(t.name) && manifest.tools.find((m) => m.name === t.name)?.allowed === true);
        if (filteredTools.length !== liveTools.length) {
          log(`Filtered ${liveTools.length - filteredTools.length} unapproved tool(s)`);
        }
        responseMsg = { ...responseMsg, result: { ...responseMsg.result, tools: filteredTools } };
      }
    }

    if (rpcMsg.method === "tools/list" && responseMsg.result?.tools && !allowAll) {
      responseMsg.result.tools = responseMsg.result.tools.filter((t) => manifest.tools.find((m) => m.name === t.name)?.allowed === true && !driftedNames.has(t.name));
    }

    // Log allowed calls + emit signed receipts
    if (rpcMsg.method === "tools/call" && rpcMsg.id != null && !responseMsg.error) {
      log(`ALLOWED tools/call: ${rpcMsg.params?.name}`);
      // Emit a signed, chained receipt if receipt chain is configured.
      if (receiptChain) {
        try {
          const toolName = rpcMsg.params?.name;
          const toolArgs = rpcMsg.params?.arguments ?? {};
          const result = responseMsg.result;
          const entry = (callManifest ?? manifest).tools.find((t) => t.name === toolName);
          const receipt = receiptChain.append({
            schema: "trustcard.dev/receipt@1",
            at: new Date().toISOString(),
            server: manifest.serverInfo?.name ?? manifest.spec ?? null,
            tool: toolName,
            toolDigest: entry?.schemaHash ?? null,
            toolsetDigest: callManifest.tools.every((t) => t.contractDigest) ? hashJson({ toolset: callManifest.tools.map((t) => t.contractDigest).sort() }) : null,
                  policyDigest: hashJson(callManifest),
            serverDigest: null,
            protocolVersion: null,
            argumentsDigest: hashJson(toolArgs),
            resultDigest: result !== undefined ? hashJson(result) : null,
            annotations: null,
            capabilityDigest: entry?.contractDigest ?? null,
            relyingParty: authToken?.subject ?? null,
            environment: null,
          });
          receiptSink?.(receipt);
          log(`Receipt #${receipt.seq}: ${receipt.receiptDigest?.slice(0, 16) ?? "?"}`);
        } catch (e) {
          log(`Receipt error: ${redact(e.message)}`);
        }
      }
    }

    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(responseMsg));
  }
}

// Create HTTP server
const server = createServer(async (req, res) => {
  // Health check endpoint
  if (req.method === "GET" && req.url === "/health") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({
      status: "ok",
      tools: manifest.tools.length,
      mode: strictMode ? "strict" : autoUpdate ? "auto-update" : allowAll ? "allow-all" : "default",
      auth: authSecret ? "enabled" : "disabled",
      receipts: receiptKeyPath ? "enabled" : "disabled",
    }));
    return;
  }

  // Pass through GET (SSE stream) and DELETE (session close) to upstream.
  // These are part of the MCP streamable-http transport — GET opens a
  // server-sent events stream for notifications, DELETE closes a session.
  // The proxy doesn't need to inspect these; just forward them.
  if (req.method === "GET" || req.method === "DELETE") {
    return proxyPassthrough(req, res);
  }

  if (req.method !== "POST") {
    res.writeHead(405, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "method not allowed" }));
    return;
  }

  try {
    await handleRequest(req, res);
  } catch (e) {
    log(`request error: ${redact(e.message)}`);
    if (!res.headersSent) {
      res.writeHead(502, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "proxy error", detail: redact(e.message) }));
    }
  }
});

const hostIdx = args.indexOf("--host");
const host = hostIdx !== -1 ? args[hostIdx + 1] : "127.0.0.1";
server.listen(port, host, () => {
  const actualPort = server.address().port;
  const modeLabel = strictMode ? "strict" : autoUpdate ? "auto-update" : allowAll ? "allow-all" : "default";
  const authLabel = authSecret ? "auth: ON" : "auth: off";
  const receiptLabel = receiptKeyPath ? "receipts: ON" : "receipts: off";
  log(`HTTP proxy started on port ${actualPort} — mode: ${modeLabel}, ${authLabel}, ${receiptLabel}, manifest: ${manifest.tools.length} tools, upstream: ${redact(upstreamUrl)}`);
  log(`  Health check: http://localhost:${actualPort}/health`);
  log(`  Configure your MCP client to use: http://localhost:${actualPort}`);
});

process.on("SIGTERM", () => { server.close(); process.exit(0); });
process.on("SIGINT", () => { server.close(); process.exit(0); });
