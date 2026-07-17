import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { writeFileSync, readFileSync } from "node:fs";
import { buildManifest } from "../lib/manifest.js";
import { redact } from "../lib/redact.js";

// Create a fake upstream MCP HTTP server that responds to JSON-RPC over HTTP.
function createFakeUpstream(approvedTools, extraTools) {
  const allTools = [...approvedTools, ...extraTools];
  const toolDefs = allTools.map((t) => ({
    name: t,
    description: "tool " + t,
    inputSchema: { type: "object", properties: {} },
  }));

  const server = createServer((req, res) => {
    let body = "";
    req.on("data", (d) => { body += d; });
    req.on("end", () => {
      let msg;
      try { msg = JSON.parse(body); } catch {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "invalid JSON" }));
        return;
      }

      if (msg.method === "initialize" && msg.id != null) {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({
          jsonrpc: "2.0", id: msg.id, result: {
            protocolVersion: "2025-06-18",
            capabilities: { tools: { listChanged: true } },
            serverInfo: { name: "fake-http-server", version: "1.0" },
          },
        }));
      } else if (msg.method === "tools/list" && msg.id != null) {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({
          jsonrpc: "2.0", id: msg.id, result: { tools: toolDefs },
        }));
      } else if (msg.method === "tools/call" && msg.id != null) {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({
          jsonrpc: "2.0", id: msg.id,
          result: { content: [{ type: "text", text: "ok:" + msg.params.name }] },
        }));
      } else {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: {} }));
      }
    });
  });

  return new Promise((resolve) => {
    server.listen(0, () => {
      const port = server.address().port;
      resolve({ server, port, url: `http://localhost:${port}` });
    });
  });
}

// Spawn the HTTP proxy and return its port
function spawnHttpProxy(manifestPath, upstreamUrl, flags = []) {
  return new Promise((resolve, reject) => {
    const proxy = spawn("node", [
      "bin/mcp-http-proxy.js",
      "--manifest", manifestPath,
      "--upstream", upstreamUrl,
      "--port", "0",
      ...flags,
    ], {
      cwd: process.cwd(),
      stdio: ["pipe", "pipe", "pipe"],
    });

    let stderr = "";
    proxy.stderr.on("data", (d) => {
      stderr += d.toString();
      // Look for the "proxy started" message to get the port
      const portMatch = stderr.match(/port (\d+)/);
      if (portMatch && !proxy.portResolved) {
        proxy.portResolved = true;
        proxy.port = parseInt(portMatch[1], 10);
        resolve({ proxy, port: proxy.port, stderr });
      }
    });

    const timeout = setTimeout(() => {
      proxy.kill();
      reject(new Error("proxy startup timeout"));
    }, 5000);

    proxy.on("exit", () => clearTimeout(timeout));
  });
}

// Send a JSON-RPC request to the HTTP proxy
async function rpcCall(port, method, params) {
  const response = await fetch(`http://localhost:${port}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params: params ?? {} }),
  });
  return response.json();
}

test("http proxy: forwards initialize", async () => {
  const upstream = await createFakeUpstream(["read_file"], []);
  const manifest = buildManifest(
    [{ name: "read_file", inputSchema: { type: "object" } }],
    { name: "fake-http-server", version: "1.0" },
  );
  const manifestPath = "/tmp/test-http-manifest.json";
  writeFileSync(manifestPath, JSON.stringify(manifest));

  const { proxy, port } = await spawnHttpProxy(manifestPath, upstream.url);
  try {
    const resp = await rpcCall(port, "initialize", {
      protocolVersion: "2025-06-18",
      capabilities: {},
      clientInfo: { name: "test", version: "1.0" },
    });
    assert.ok(resp.result, "initialize response received");
    assert.equal(resp.result.serverInfo.name, "fake-http-server");
  } finally {
    proxy.kill();
    upstream.server.close();
  }
});

test("http proxy: strips unapproved tools from tools/list", async () => {
  const upstream = await createFakeUpstream(["read_file"], ["delete_everything", "exfiltrate"]);
  const manifest = buildManifest(
    [{ name: "read_file", inputSchema: { type: "object" } }],
  );
  const manifestPath = "/tmp/test-http-manifest2.json";
  writeFileSync(manifestPath, JSON.stringify(manifest));

  const { proxy, port } = await spawnHttpProxy(manifestPath, upstream.url);
  try {
    const resp = await rpcCall(port, "tools/list", {});
    assert.ok(resp.result, "tools/list response received");
    const toolNames = resp.result.tools.map((t) => t.name);
    assert.ok(toolNames.includes("read_file"), "approved tool visible");
    assert.ok(!toolNames.includes("delete_everything"), "unapproved tool stripped");
    assert.ok(!toolNames.includes("exfiltrate"), "unapproved tool stripped");
    assert.equal(toolNames.length, 1, "only 1 tool visible");
  } finally {
    proxy.kill();
    upstream.server.close();
  }
});

test("http proxy: blocks calls to unapproved tools", async () => {
  const upstream = await createFakeUpstream(["read_file"], ["delete_everything"]);
  const manifest = buildManifest(
    [{ name: "read_file", inputSchema: { type: "object" } }],
  );
  const manifestPath = "/tmp/test-http-manifest3.json";
  writeFileSync(manifestPath, JSON.stringify(manifest));

  const { proxy, port } = await spawnHttpProxy(manifestPath, upstream.url);
  try {
    const resp = await rpcCall(port, "tools/call", { name: "delete_everything", arguments: {} });
    assert.ok(resp.error, "call was blocked with error");
    assert.ok(resp.error.message.includes("delete_everything"));
    assert.ok(resp.error.message.includes("not in approved manifest"));
  } finally {
    proxy.kill();
    upstream.server.close();
  }
});

test("http proxy: allows calls to approved tools", async () => {
  const upstream = await createFakeUpstream(["read_file"], []);
  const manifest = buildManifest(
    [{ name: "read_file", inputSchema: { type: "object" } }],
  );
  const manifestPath = "/tmp/test-http-manifest4.json";
  writeFileSync(manifestPath, JSON.stringify(manifest));

  const { proxy, port } = await spawnHttpProxy(manifestPath, upstream.url);
  try {
    const resp = await rpcCall(port, "tools/call", { name: "read_file", arguments: {} });
    assert.ok(resp.result, "call succeeded");
    assert.equal(resp.result.content[0].text, "ok:read_file");
  } finally {
    proxy.kill();
    upstream.server.close();
  }
});

test("http proxy: health check endpoint", async () => {
  const upstream = await createFakeUpstream(["read_file"], []);
  const manifest = buildManifest(
    [{ name: "read_file", inputSchema: { type: "object" } }],
  );
  const manifestPath = "/tmp/test-http-manifest5.json";
  writeFileSync(manifestPath, JSON.stringify(manifest));

  const { proxy, port } = await spawnHttpProxy(manifestPath, upstream.url);
  try {
    const resp = await fetch(`http://localhost:${port}/health`);
    const data = await resp.json();
    assert.equal(data.status, "ok");
    assert.equal(data.tools, 1);
  } finally {
    proxy.kill();
    upstream.server.close();
  }
});

// --- Redaction tests ---

test("redact: redacts GitHub tokens", () => {
  const input = "Using token ghp_1234567890abcdef1234 for auth";
  const output = redact(input);
  assert.ok(!output.includes("ghp_1234567890abcdef1234"), "token redacted");
  assert.ok(output.includes("***REDACTED***"), "redaction marker present");
});

test("redact: redacts OpenAI keys", () => {
  const input = "OPENAI_API_KEY=sk-1234567890abcdef1234567";
  const output = redact(input);
  assert.ok(!output.includes("sk-1234567890abcdef1234567"), "key redacted");
});

test("redact: redacts Bearer tokens", () => {
  const input = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
  const output = redact(input);
  assert.ok(!output.includes("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"), "JWT redacted");
  assert.ok(output.includes("***REDACTED***"), "redaction marker present");
});

test("redact: does not modify non-secret text", () => {
  const input = "Server started on port 9876 with 14 tools";
  const output = redact(input);
  assert.equal(output, input, "non-secret text unchanged");
});

test("redact: handles null/undefined input", () => {
  assert.equal(redact(null), null);
  assert.equal(redact(undefined), undefined);
  assert.equal(redact(""), "");
});

// --- SSE integration tests ---

// Create a fake upstream that responds with SSE (Server-Sent Events)
function createSSEUpstream(approvedTools, extraTools) {
  const allTools = [...approvedTools, ...extraTools];
  const toolDefs = allTools.map((t) => ({
    name: t,
    description: "tool " + t,
    inputSchema: { type: "object", properties: {} },
  }));

  const server = createServer((req, res) => {
    let body = "";
    req.on("data", (d) => { body += d; });
    req.on("end", () => {
      let msg;
      try { msg = JSON.parse(body); } catch {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "invalid JSON" }));
        return;
      }

      // Respond with SSE format
      res.writeHead(200, {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
      });

      if (msg.method === "initialize" && msg.id != null) {
        const sseMsg = {
          jsonrpc: "2.0", id: msg.id, result: {
            protocolVersion: "2025-06-18",
            capabilities: { tools: { listChanged: true } },
            serverInfo: { name: "fake-sse-server", version: "1.0" },
          },
        };
        res.write(`event: message\ndata: ${JSON.stringify(sseMsg)}\n\n`);
      } else if (msg.method === "tools/list" && msg.id != null) {
        const sseMsg = {
          jsonrpc: "2.0", id: msg.id,
          result: { tools: toolDefs },
        };
        res.write(`event: message\ndata: ${JSON.stringify(sseMsg)}\n\n`);
      } else if (msg.method === "tools/call" && msg.id != null) {
        const sseMsg = {
          jsonrpc: "2.0", id: msg.id,
          result: { content: [{ type: "text", text: "ok:" + msg.params.name }] },
        };
        res.write(`event: message\ndata: ${JSON.stringify(sseMsg)}\n\n`);
      } else {
        res.write(`event: message\ndata: ${JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: {} })}\n\n`);
      }
      res.end();
    });
  });

  return new Promise((resolve) => {
    server.listen(0, () => {
      const port = server.address().port;
      resolve({ server, port, url: `http://localhost:${port}` });
    });
  });
}

// Send a JSON-RPC request to the proxy and parse SSE response
async function rpcCallSSE(port, method, params) {
  const response = await fetch(`http://localhost:${port}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "Accept": "text/event-stream" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params: params ?? {} }),
  });
  const text = await response.text();
  // Parse SSE — find the data: line
  const events = text.split("\n\n");
  for (const event of events) {
    const lines = event.split("\n");
    for (const line of lines) {
      if (line.startsWith("data:")) {
        try { return JSON.parse(line.slice(5).trim()); } catch {}
      }
    }
  }
  return null;
}

test("http proxy SSE: forwards initialize over SSE", async () => {
  const upstream = await createSSEUpstream(["read_file"], []);
  const manifest = buildManifest(
    [{ name: "read_file", inputSchema: { type: "object" } }],
    { name: "fake-sse-server", version: "1.0" },
  );
  const manifestPath = "/tmp/test-sse-manifest1.json";
  writeFileSync(manifestPath, JSON.stringify(manifest));

  const { proxy, port } = await spawnHttpProxy(manifestPath, upstream.url);
  try {
    const resp = await rpcCallSSE(port, "initialize", {
      protocolVersion: "2025-06-18",
      capabilities: {},
      clientInfo: { name: "test", version: "1.0" },
    });
    assert.ok(resp, "SSE response received");
    assert.ok(resp.result, "initialize result present");
    assert.equal(resp.result.serverInfo.name, "fake-sse-server");
  } finally {
    proxy.kill();
    upstream.server.close();
  }
});

test("http proxy SSE: strips unapproved tools from SSE tools/list", async () => {
  const upstream = await createSSEUpstream(["read_file"], ["delete_everything", "exfiltrate"]);
  const manifest = buildManifest(
    [{ name: "read_file", inputSchema: { type: "object" } }],
  );
  const manifestPath = "/tmp/test-sse-manifest2.json";
  writeFileSync(manifestPath, JSON.stringify(manifest));

  const { proxy, port } = await spawnHttpProxy(manifestPath, upstream.url);
  try {
    const resp = await rpcCallSSE(port, "tools/list", {});
    assert.ok(resp, "SSE tools/list response received");
    const toolNames = resp.result.tools.map((t) => t.name);
    assert.ok(toolNames.includes("read_file"), "approved tool visible in SSE");
    assert.ok(!toolNames.includes("delete_everything"), "unapproved tool stripped from SSE");
    assert.ok(!toolNames.includes("exfiltrate"), "unapproved tool stripped from SSE");
    assert.equal(toolNames.length, 1, "only 1 tool visible in SSE");
  } finally {
    proxy.kill();
    upstream.server.close();
  }
});

test("http proxy SSE: blocks calls to unapproved tools over SSE", async () => {
  const upstream = await createSSEUpstream(["read_file"], ["delete_everything"]);
  const manifest = buildManifest(
    [{ name: "read_file", inputSchema: { type: "object" } }],
  );
  const manifestPath = "/tmp/test-sse-manifest3.json";
  writeFileSync(manifestPath, JSON.stringify(manifest));

  const { proxy, port } = await spawnHttpProxy(manifestPath, upstream.url);
  try {
    // tools/call is blocked before reaching upstream — returns JSON, not SSE
    const resp = await rpcCall(port, "tools/call", { name: "delete_everything", arguments: {} });
    assert.ok(resp.error, "SSE call was blocked with error");
    assert.ok(resp.error.message.includes("delete_everything"));
    assert.ok(resp.error.message.includes("not in approved manifest"));
  } finally {
    proxy.kill();
    upstream.server.close();
  }
});

test("http proxy SSE: allows calls to approved tools over SSE", async () => {
  const upstream = await createSSEUpstream(["read_file"], []);
  const manifest = buildManifest(
    [{ name: "read_file", inputSchema: { type: "object" } }],
  );
  const manifestPath = "/tmp/test-sse-manifest4.json";
  writeFileSync(manifestPath, JSON.stringify(manifest));

  const { proxy, port } = await spawnHttpProxy(manifestPath, upstream.url);
  try {
    const resp = await rpcCallSSE(port, "tools/call", { name: "read_file", arguments: {} });
    assert.ok(resp, "SSE tools/call response received");
    assert.ok(resp.result, "call succeeded over SSE");
    assert.equal(resp.result.content[0].text, "ok:read_file");
  } finally {
    proxy.kill();
    upstream.server.close();
  }
});
