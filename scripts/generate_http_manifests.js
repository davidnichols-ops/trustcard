#!/usr/bin/env node
// Generate manifests for HTTP-based MCP servers.
// Handles both JSON and SSE (Server-Sent Events) responses.
// For OAuth-based servers (notion, linear, atlassian), this script
// reads stored OAuth tokens from Devin's auth directory.
//
// Usage: node scripts/generate_http_manifests.js
import { writeFileSync, readFileSync, existsSync, readdirSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { buildManifest } from "../lib/manifest.js";

const MANIFEST_DIR = join(homedir(), ".config/devin/manifests");

// Try to read OAuth token from Devin's auth store
function getOAuthToken(serverName, serverUrl) {
  // Devin stores OAuth tokens in ~/.local/share/devin/mcp/oauth/<hash>.json
  // Each file has: server_name, url, client_id, access_token, [refresh_token, expires_at]
  const oauthDir = join(homedir(), ".local/share/devin/mcp/oauth");
  if (existsSync(oauthDir)) {
    for (const file of readdirSync(oauthDir)) {
      if (!file.endsWith(".json")) continue;
      try {
        const data = JSON.parse(readFileSync(join(oauthDir, file), "utf8"));
        // Match by server_name or by URL
        if ((data.server_name === serverName || data.url === serverUrl) && data.access_token) {
          return data.access_token;
        }
      } catch {}
    }
  }
  return null;
}

// Parse SSE response text and extract JSON-RPC messages
function parseSSEResponse(text) {
  const messages = [];
  const events = text.split("\n\n");
  for (const event of events) {
    const lines = event.split("\n");
    let dataLines = [];
    for (const line of lines) {
      if (line.startsWith("data:")) {
        dataLines.push(line.slice(5).trim());
      }
    }
    if (dataLines.length > 0) {
      const dataStr = dataLines.join("\n");
      try {
        messages.push(JSON.parse(dataStr));
      } catch {}
    }
  }
  return messages;
}

// Send a JSON-RPC request to an HTTP MCP server and parse the response
async function rpcCall(url, method, params, headers = {}) {
  const body = JSON.stringify({ jsonrpc: "2.0", id: 1, method, params: params ?? {} });

  const fetchHeaders = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
    ...headers,
  };

  const response = await fetch(url, {
    method: "POST",
    headers: fetchHeaders,
    body,
  });

  const contentType = response.headers.get("content-type") || "";
  const text = await response.text();

  if (contentType.includes("text/event-stream")) {
    return parseSSEResponse(text);
  } else {
    try {
      return [JSON.parse(text)];
    } catch {
      return [];
    }
  }
}

// Generate manifest for a single server
async function generateManifest(name, url, headers = {}) {
  const outfile = join(MANIFEST_DIR, `${name}.json`);
  console.log(`Generating manifest for ${name} (${url})...`);

  try {
    // Initialize
    const initMessages = await rpcCall(url, "initialize", {
      protocolVersion: "2025-06-18",
      capabilities: {},
      clientInfo: { name: "mcp-trustcard", version: "0.4.0" },
    }, headers);

    const initResult = initMessages.find((m) => m.result)?.result;
    if (!initResult) {
      const errMsg = initMessages.find((m) => m.error)?.error?.message || "no result";
      console.log(`  SKIPPED: ${errMsg}`);
      return false;
    }

    console.log(`  Server: ${initResult.serverInfo?.name ?? name} ${initResult.serverInfo?.version ?? ""}`);

    // tools/list
    const toolsMessages = await rpcCall(url, "tools/list", {}, headers);
    const toolsResult = toolsMessages.find((m) => m.result?.tools)?.result;
    if (!toolsResult || !toolsResult.tools || toolsResult.tools.length === 0) {
      console.log(`  NO TOOLS found (may need authentication)`);
      return false;
    }

    const tools = toolsResult.tools;
    const manifest = buildManifest(tools, initResult.serverInfo, url);
    writeFileSync(outfile, JSON.stringify(manifest, null, 2));

    console.log(`  Manifest saved: ${outfile}`);
    console.log(`  Tools: ${manifest.tools.length}`);
    console.log(`  Hash: ${manifest.manifestHash}`);

    // Show dangerous params if any
    const dangerous = tools.filter((t) => {
      const props = t.inputSchema?.properties || {};
      return Object.keys(props).some((p) => ["path", "command", "sql", "url", "webhook"].includes(p.toLowerCase()));
    });
    if (dangerous.length > 0) {
      console.log(`  ⚠ ${dangerous.length} tool(s) with dangerous params: ${dangerous.map((t) => t.name).slice(0, 5).join(", ")}`);
    }

    return true;
  } catch (e) {
    console.log(`  FAILED: ${e.message}`);
    return false;
  }
}

// Server definitions
const servers = [
  { name: "deepwiki", url: "https://mcp.deepwiki.com/mcp", headers: {} },
  { name: "figma", url: "https://mcp.figma.com/mcp", headers: {} },
  { name: "roboflow", url: "https://mcp.roboflow.com/mcp", headers: {} },
  { name: "notion", url: "https://mcp.notion.com/mcp", headers: {} },
  { name: "linear", url: "https://mcp.linear.app/mcp", headers: {} },
  { name: "atlassian", url: "https://mcp.atlassian.com/v1/mcp", headers: {} },
];

// Add API key for roboflow if available
if (process.env.ROBOFLOW_API_KEY) {
  servers.find((s) => s.name === "roboflow").headers = {
    "x-api-key": process.env.ROBOFLOW_API_KEY,
  };
}

// Try to add OAuth tokens for authenticated servers
for (const srv of servers) {
  const token = getOAuthToken(srv.name, srv.url);
  if (token) {
    srv.headers["Authorization"] = `Bearer ${token}`;
    console.log(`Found OAuth token for ${srv.name}`);
  }
}

// Generate manifests
const results = [];
for (const srv of servers) {
  const ok = await generateManifest(srv.name, srv.url, srv.headers);
  results.push({ name: srv.name, ok });
  console.log();
}

// Summary
console.log("Summary:");
console.log("─".repeat(50));
for (const r of results) {
  const status = r.ok ? "✓" : "✗";
  console.log(`  ${status} ${r.name}`);
}
const succeeded = results.filter((r) => r.ok).length;
console.log(`\n${succeeded}/${results.length} manifests generated.`);
console.log(`Manifests in: ${MANIFEST_DIR}`);
