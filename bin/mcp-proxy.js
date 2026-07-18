#!/usr/bin/env node
// mcp-proxy — stdio proxy that enforces an approved tool manifest at call time.
//
// Usage:
//   mcp-proxy --manifest <file> -- <server-cmd> [args...]
//   mcp-proxy --manifest <file> --strict -- <server-cmd> [args...]
//   mcp-proxy --manifest <file> --auto-update -- <server-cmd> [args...]
//
// The proxy spawns the real MCP server as a child process and transparently
// forwards JSON-RPC messages, intercepting two methods:
//
//   tools/list  — compares the live tool list against the manifest, logs drift,
//                 and optionally strips unapproved tools from the response.
//   tools/call  — blocks calls to tools not in the manifest.
//
// Modes:
//   default      — logs drift to stderr, strips unapproved tools silently
//   --strict     — exits with error on any drift (added, removed, or schema change)
//   --auto-update — updates the manifest file on disk when new tools are detected,
//                   then allows them through. Logs a warning for each update.
//
// All other methods pass through untouched. The proxy is client-agnostic:
// any MCP client that speaks stdio JSON-RPC works without modification.
import { spawn } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { buildManifest, diffManifest, checkCall } from "../lib/manifest.js";
import { redact } from "../lib/redact.js";

const args = process.argv.slice(2);

// Parse flags
const strictMode = args.includes("--strict");
const autoUpdate = args.includes("--auto-update");
const cwdIdx = args.indexOf("--cwd");
const cwd = cwdIdx !== -1 && args[cwdIdx + 1] ? args[cwdIdx + 1] : undefined;

// Parse --manifest <file>
const manifestIdx = args.indexOf("--manifest");
if (manifestIdx === -1 || !args[manifestIdx + 1]) {
  console.error("mcp-proxy: --manifest <file> is required");
  console.error('Usage: mcp-proxy --manifest <file> [--strict|--auto-update] [--cwd <dir>] -- <server-cmd> [args...]');
  process.exit(2);
}
const manifestPath = args[manifestIdx + 1];

// Parse -- <server-cmd> [args...]
const dashIdx = args.indexOf("--");
if (dashIdx === -1 || !args[dashIdx + 1]) {
  console.error("mcp-proxy: expected -- <server-cmd> after manifest");
  process.exit(2);
}
const serverCmd = args[dashIdx + 1];
const serverArgs = args.slice(dashIdx + 2);

// Load manifest
let manifest;
try {
  manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
} catch (e) {
  console.error(`mcp-proxy: failed to load manifest: ${e.message}`);
  process.exit(2);
}

let approvedNames = new Set(manifest.tools.map((t) => t.name));

// --- JSON-RPC plumbing ---
// The proxy maintains two stdio pipes:
//   client <-> proxy <-> server
// We buffer line-delimited JSON on both sides.

const server = spawn(serverCmd, serverArgs, {
  env: process.env,
  stdio: ["pipe", "pipe", "pipe"],
  cwd: cwd || undefined,
});

let clientBuffer = "";
let serverBuffer = "";
const pendingServer = new Map();  // id -> method (tracking requests forwarded to server)
let nextRedirectId = 1;

// Log to stderr (stdout is reserved for JSON-RPC to the client)
// All log messages are redacted to prevent secret leakage
function log(msg) {
  process.stderr.write(`[mcp-proxy] ${redact(msg)}\n`);
}

// Send a JSON-RPC message to the client (us → client)
function sendToClient(msg) {
  process.stdout.write(JSON.stringify(msg) + "\n");
}

// Send a JSON-RPC message to the server (us → server)
function sendToServer(msg) {
  server.stdin.write(JSON.stringify(msg) + "\n");
}

// Handle a JSON-RPC message from the CLIENT (client → proxy)
function handleClientMessage(msg) {
  if (msg.method === "tools/call" && msg.id != null) {
    const toolName = msg.params?.name;
    const check = checkCall(manifest, toolName);
    if (!check.allowed) {
      log(`BLOCKED tools/call: ${check.reason}`);
      sendToClient({
        jsonrpc: "2.0",
        id: msg.id,
        error: {
          code: -32601,
          message: `mcp-proxy: ${check.reason}`,
        },
      });
      return;
    }
    // Approved — forward to server
    pendingServer.set(msg.id, "tools/call");
    sendToServer(msg);
    return;
  }

  if (msg.method === "tools/list" && msg.id != null) {
    // Forward to server, but remember to diff the response
    pendingServer.set(msg.id, "tools/list");
    sendToServer(msg);
    return;
  }

  // Everything else: pass through
  if (msg.id != null) {
    pendingServer.set(msg.id, msg.method || "unknown");
  }
  sendToServer(msg);
}

// Handle a JSON-RPC message from the SERVER (server → proxy)
function handleServerMessage(msg) {
  if (msg.id != null && pendingServer.has(msg.id)) {
    const method = pendingServer.get(msg.id);
    pendingServer.delete(msg.id);

    if (method === "tools/list" && msg.result) {
      const liveTools = msg.result.tools || [];
      const diff = diffManifest(manifest, liveTools);

      if (diff.added.length > 0) {
        log(`DRIFT: ${diff.added.length} new tool(s) not in manifest: ${diff.added.join(", ")}`);
      }
      if (diff.removed.length > 0) {
        log(`DRIFT: ${diff.removed.length} approved tool(s) missing: ${diff.removed.join(", ")}`);
      }
      if (diff.drifted.length > 0) {
        for (const d of diff.drifted) {
          log(`DRIFT: "${d.name}" schema changed (approved=${d.approved} live=${d.live})`);
        }
      }
      if (diff.ok) {
        log(`tools/list OK: ${liveTools.length} tools match manifest`);
      }

      // --strict mode: exit on any drift
      if (strictMode && !diff.ok) {
        log(`STRICT MODE: drift detected, exiting. Regenerate manifest with:`);
        log(`  mcp-trustcard scan ${cwd ? "--cwd " + cwd + " " : ""}-- ${serverCmd} ${serverArgs.join(" ")} --save-manifest ${manifestPath}`);
        sendToClient({
          jsonrpc: "2.0",
          id: msg.id,
          error: {
            code: -32603,
            message: `mcp-proxy: manifest drift detected in strict mode — ${diff.added.length} added, ${diff.removed.length} removed, ${diff.drifted.length} drifted`,
          },
        });
        server.kill("SIGTERM");
        process.exit(1);
      }

      // --auto-update mode: update manifest on disk when new tools appear
      if (autoUpdate && diff.added.length > 0) {
        const newManifest = buildManifest(liveTools, manifest.serverInfo, manifest.spec);
        try {
          writeFileSync(manifestPath, JSON.stringify(newManifest, null, 2));
          manifest = newManifest;
          approvedNames = new Set(newManifest.tools.map((t) => t.name));
          log(`AUTO-UPDATE: manifest updated on disk — ${diff.added.length} new tool(s) approved: ${diff.added.join(", ")}`);
          log(`  New hash: ${newManifest.manifestHash}`);
          // In auto-update mode, allow all tools through (they're now approved)
          sendToClient(msg);
          return;
        } catch (e) {
          log(`AUTO-UPDATE FAILED: could not write manifest: ${e.message}`);
          // Fall through to default filtering behavior
        }
      }

      // Default: strip unapproved AND dangerous tools from the response
      // so the client never sees them
      const filteredTools = liveTools.filter((t) => {
        if (!approvedNames.has(t.name)) return false;
        // Also check if the tool is marked as dangerous in the manifest
        const entry = manifest.tools.find((m) => m.name === t.name);
        if (entry && entry.allowed === false) {
          log(`BLOCKED dangerous tool "${t.name}" (score=${entry.dangerScore}, confidence=${entry.dangerConfidence}) — stripped from tools/list`);
          return false;
        }
        return true;
      });
      const blockedCount = liveTools.length - filteredTools.length;
      if (blockedCount > 0) {
        log(`Filtered ${blockedCount} tool(s) from response (unapproved or dangerous)`);
        // Log the regeneration command so the user knows what to do
        log(`To approve new tools, regenerate manifest:`);
        log(`  mcp-trustcard scan ${cwd ? "--cwd " + cwd + " " : ""}-- ${serverCmd} ${serverArgs.join(" ")} --save-manifest ${manifestPath}`);
      }
      sendToClient({
        ...msg,
        result: { ...msg.result, tools: filteredTools },
      });
      return;
    }

    if (method === "tools/call") {
      // Log the call for audit trail
      log(`ALLOWED tools/call (id=${msg.id})`);
    }
  }

  // Pass through to client
  sendToClient(msg);
}

// --- stdio piping ---

// Read from client (our stdin) → forward to server (with interception)
process.stdin.setEncoding("utf8");
process.stdin.on("data", (data) => {
  clientBuffer += data;
  let idx;
  while ((idx = clientBuffer.indexOf("\n")) >= 0) {
    const line = clientBuffer.slice(0, idx).trim();
    clientBuffer = clientBuffer.slice(idx + 1);
    if (!line) continue;
    try {
      const msg = JSON.parse(line);
      handleClientMessage(msg);
    } catch {
      // Not valid JSON — forward raw to server
      server.stdin.write(line + "\n");
    }
  }
});

// Read from server → forward to client (with interception)
server.stdout.setEncoding("utf8");
server.stdout.on("data", (data) => {
  serverBuffer += data;
  let idx;
  while ((idx = serverBuffer.indexOf("\n")) >= 0) {
    const line = serverBuffer.slice(0, idx).trim();
    serverBuffer = serverBuffer.slice(idx + 1);
    if (!line) continue;
    try {
      const msg = JSON.parse(line);
      handleServerMessage(msg);
    } catch {
      // Not valid JSON — forward raw to client
      process.stdout.write(line + "\n");
    }
  }
});

// Pass server stderr through (redacted, for debugging)
server.stderr.on("data", (data) => {
  process.stderr.write(redact(data.toString()));
});

// Lifecycle
server.on("exit", (code, signal) => {
  log(`server exited (code=${code} signal=${signal})`);
  process.exit(code ?? 1);
});

process.stdin.on("end", () => {
  log("client disconnected");
  server.kill("SIGTERM");
});

process.on("SIGTERM", () => {
  server.kill("SIGTERM");
  process.exit(0);
});

process.on("SIGINT", () => {
  server.kill("SIGTERM");
  process.exit(0);
});

const modeLabel = strictMode ? "strict" : autoUpdate ? "auto-update" : "default";
log(`proxy started — mode: ${modeLabel}, manifest: ${manifest.tools.length} tools, server: ${serverCmd} ${serverArgs.join(" ")}`);
