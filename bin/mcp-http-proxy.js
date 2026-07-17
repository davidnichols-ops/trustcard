#!/usr/bin/env node
// mcp-http-proxy — HTTP/SSE proxy that enforces an approved tool manifest at call time.
//
// Usage:
//   mcp-http-proxy --manifest <file> --upstream <url> [--port <port>] [--strict] [--auto-update]
//   mcp-http-proxy --manifest <file> --upstream https://mcp.notion.com/mcp --port 9876
//
// The proxy listens on a local port and forwards HTTP requests to the upstream
// MCP server, intercepting tools/list and tools/call just like the stdio proxy.
//
// Modes:
//   default      — logs drift to stderr, strips unapproved tools silently
//   --strict     — exits with error on any drift (added, removed, or schema change)
//   --auto-update — updates the manifest file on disk when new tools are detected
//
// The proxy handles both:
//   - HTTP POST requests (JSON-RPC over HTTP)
//   - SSE streaming responses (Server-Sent Events for streaming results)
//
// For SSE, the proxy buffers the stream, parses JSON-RPC messages, intercepts
// tools/list and tools/call responses, and re-emits the SSE stream.
import { createServer } from "node:http";
import { readFileSync, writeFileSync } from "node:fs";
import { buildManifest, diffManifest, checkCall } from "../lib/manifest.js";
import { redact } from "../lib/redact.js";

const args = process.argv.slice(2);

// Parse flags
const strictMode = args.includes("--strict");
const autoUpdate = args.includes("--auto-update");

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

// Load manifest
let manifest;
try {
  manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
} catch (e) {
  console.error(`mcp-http-proxy: failed to load manifest: ${e.message}`);
  process.exit(2);
}

let approvedNames = new Set(manifest.tools.map((t) => t.name));

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

  // Intercept tools/call — block unapproved tools
  if (rpcMsg.method === "tools/call" && rpcMsg.id != null) {
    const toolName = rpcMsg.params?.name;
    const check = checkCall(manifest, toolName);
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
  }

  // Forward to upstream
  const upstreamPath = upstream.pathname + upstream.search;
  const upstreamReq = await fetch(`${upstream.origin}${upstreamPath}`, {
    method: "POST",
    headers: upstreamHeaders,
    body: bodyStr,
  });

  // Check if response is SSE
  const contentType = upstreamReq.headers.get("content-type") || "";

  if (contentType.includes("text/event-stream")) {
    // SSE streaming — buffer events, intercept tools/list, re-emit
    res.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      "Connection": "keep-alive",
    });

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

        // Process complete SSE events (separated by \n\n)
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
                  const newManifest = buildManifest(liveTools, manifest.serverInfo, manifest.spec);
                  try {
                    writeFileSync(manifestPath, JSON.stringify(newManifest, null, 2));
                    manifest = newManifest;
                    approvedNames = new Set(newManifest.tools.map((t) => t.name));
                    log(`AUTO-UPDATE: manifest updated — ${diff.added.length} new tool(s) approved`);
                  } catch (e) {
                    log(`AUTO-UPDATE FAILED: ${e.message}`);
                  }
                  // In auto-update, pass through unmodified
                  res.write(`event: ${eventType}\ndata: ${dataStr}\n\n`);
                } else {
                  // Default: strip unapproved tools
                  const filteredTools = liveTools.filter((t) => approvedNames.has(t.name));
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
        const newManifest = buildManifest(liveTools, manifest.serverInfo, manifest.spec);
        try {
          writeFileSync(manifestPath, JSON.stringify(newManifest, null, 2));
          manifest = newManifest;
          approvedNames = new Set(newManifest.tools.map((t) => t.name));
          log(`AUTO-UPDATE: manifest updated — ${diff.added.length} new tool(s) approved`);
        } catch (e) {
          log(`AUTO-UPDATE FAILED: ${e.message}`);
        }
      } else {
        // Default: strip unapproved tools
        const filteredTools = liveTools.filter((t) => approvedNames.has(t.name));
        if (filteredTools.length !== liveTools.length) {
          log(`Filtered ${liveTools.length - filteredTools.length} unapproved tool(s)`);
        }
        responseMsg = { ...responseMsg, result: { ...responseMsg.result, tools: filteredTools } };
      }
    }

    // Log allowed calls
    if (rpcMsg.method === "tools/call" && rpcMsg.id != null && !responseMsg.error) {
      log(`ALLOWED tools/call: ${rpcMsg.params?.name}`);
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
    res.end(JSON.stringify({ status: "ok", tools: manifest.tools.length, mode: strictMode ? "strict" : autoUpdate ? "auto-update" : "default" }));
    return;
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

server.listen(port, () => {
  const actualPort = server.address().port;
  const modeLabel = strictMode ? "strict" : autoUpdate ? "auto-update" : "default";
  log(`HTTP proxy started on port ${actualPort} — mode: ${modeLabel}, manifest: ${manifest.tools.length} tools, upstream: ${redact(upstreamUrl)}`);
  log(`  Health check: http://localhost:${actualPort}/health`);
  log(`  Configure your MCP client to use: http://localhost:${actualPort}`);
});

process.on("SIGTERM", () => { server.close(); process.exit(0); });
process.on("SIGINT", () => { server.close(); process.exit(0); });
