#!/usr/bin/env node
// Env probe fixture: a minimal MCP server with one tool, `env_keys`, which
// returns the sorted NAMES of the environment variables it can see. Tests use
// it to prove that untrusted-server discovery spawns children with the
// allowlisted environment, not the operator's full shell env.
//
// Values are never returned — only variable names, so a probe can never be a
// secret-exfiltration channel itself.
function send(msg) {
  process.stdout.write(JSON.stringify(msg) + "\n");
}

const TOOLS = [
  {
    name: "env_keys",
    description: "Return the sorted names of environment variables visible to this process.",
    inputSchema: { type: "object", properties: {} },
  },
];

let buffer = "";
process.stdin.on("data", (chunk) => {
  buffer += chunk.toString();
  let idx;
  while ((idx = buffer.indexOf("\n")) >= 0) {
    const line = buffer.slice(0, idx).trim();
    buffer = buffer.slice(idx + 1);
    if (line) handle(line);
  }
});

function handle(line) {
  let msg;
  try { msg = JSON.parse(line); } catch { return; }
  if (msg.method === "initialize") {
    send({ jsonrpc: "2.0", id: msg.id, result: {
      protocolVersion: "2025-06-18",
      capabilities: {},
      serverInfo: { name: "env-probe", version: "1.0.0" },
    }});
    return;
  }
  if (msg.method === "tools/list") {
    send({ jsonrpc: "2.0", id: msg.id, result: { tools: TOOLS } });
    return;
  }
  if (msg.method === "tools/call") {
    const keys = Object.keys(process.env).sort();
    send({ jsonrpc: "2.0", id: msg.id, result: {
      content: [{ type: "text", text: JSON.stringify(keys) }],
    }});
    return;
  }
  if (msg.id != null) {
    send({ jsonrpc: "2.0", id: msg.id, error: { code: -32601, message: `method not found: ${msg.method}` } });
  }
}

process.stdin.on("end", () => process.exit(0));
