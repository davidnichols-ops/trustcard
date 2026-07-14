import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { writeFileSync, readFileSync } from "node:fs";
import { buildManifest } from "../lib/manifest.js";

// Spawn a fake MCP server that exposes a known set of tools.
// The proxy will enforce a manifest that only approves a subset.
function spawnFakeServer(approvedTools, extraTools) {
  const allTools = [...approvedTools, ...extraTools];
  const code = `
    let buf = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (d) => {
      buf += d;
      let idx;
      while ((idx = buf.indexOf("\\n")) >= 0) {
        const line = buf.slice(0, idx).trim();
        buf = buf.slice(idx + 1);
        if (!line) continue;
        try { handle(JSON.parse(line)); } catch {}
      }
    });
    function send(msg) { process.stdout.write(JSON.stringify(msg) + "\\n"); }
    function handle(msg) {
      if (msg.method === "initialize" && msg.id != null) {
        send({ jsonrpc: "2.0", id: msg.id, result: {
          protocolVersion: "2025-06-18",
          capabilities: { tools: { listChanged: true } },
          serverInfo: { name: "fake-server", version: "1.0" },
        }});
      } else if (msg.method === "notifications/initialized") {
      } else if (msg.method === "tools/list" && msg.id != null) {
        const tools = ${JSON.stringify(allTools.map(t => ({
          name: t,
          description: "tool " + t,
          inputSchema: { type: "object", properties: {} },
        })))};
        send({ jsonrpc: "2.0", id: msg.id, result: { tools } });
      } else if (msg.method === "tools/call" && msg.id != null) {
        send({ jsonrpc: "2.0", id: msg.id, result: { content: [{ type: "text", text: "ok:" + msg.params.name }] } });
      }
    }
  `;
  return code;
}

// Run a test: spawn proxy with a manifest, send JSON-RPC messages, collect responses.
async function runProxyTest(manifest, serverCode) {
  const manifestPath = "/tmp/test-manifest.json";
  const serverPath = "/tmp/test-fake-server.js";
  writeFileSync(manifestPath, JSON.stringify(manifest));
  writeFileSync(serverPath, serverCode);

  return new Promise((resolve, reject) => {
    const proxy = spawn("node", [
      "bin/mcp-proxy.js",
      "--manifest", manifestPath,
      "--", "node", serverPath,
    ], {
      cwd: process.cwd(),
      env: { ...process.env, PATH: "/opt/homebrew/bin:" + process.env.PATH },
      stdio: ["pipe", "pipe", "pipe"],
    });

    const responses = {};
    let buf = "";
    const send = (msg) => proxy.stdin.write(JSON.stringify(msg) + "\n");

    proxy.stdout.on("data", (d) => {
      buf += d.toString();
      let idx;
      while ((idx = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, idx).trim();
        buf = buf.slice(idx + 1);
        if (!line) continue;
        try {
          const msg = JSON.parse(line);
          if (msg.id != null) responses[msg.id] = msg;
        } catch {}
      }
    });

    const timeout = setTimeout(() => {
      proxy.kill();
      reject(new Error("test timeout"));
    }, 5000);

    // Initialize
    send({ jsonrpc: "2.0", id: 1, method: "initialize", params: {
      protocolVersion: "2025-06-18", capabilities: {},
      clientInfo: { name: "test", version: "1.0" },
    }});
    send({ jsonrpc: "2.0", method: "notifications/initialized", params: {} });

    // tools/list after 200ms
    setTimeout(() => send({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }), 200);

    // approved call after 400ms
    setTimeout(() => send({ jsonrpc: "2.0", id: 3, method: "tools/call", params: {
      name: "read_file", arguments: {}
    }}), 400);

    // blocked call after 500ms
    setTimeout(() => send({ jsonrpc: "2.0", id: 4, method: "tools/call", params: {
      name: "delete_everything", arguments: {}
    }}), 500);

    // collect and finish after 800ms
    setTimeout(() => {
      clearTimeout(timeout);
      proxy.kill();
      resolve(responses);
    }, 800);
  });
}

test("proxy forwards initialize and tools/list", async () => {
  const manifest = buildManifest(
    [{ name: "read_file", inputSchema: { type: "object" } }],
    { name: "fake-server", version: "1.0" },
  );
  const serverCode = spawnFakeServer(["read_file"], []);
  const responses = await runProxyTest(manifest, serverCode);

  assert.ok(responses[1], "initialize response received");
  assert.equal(responses[1].result.serverInfo.name, "fake-server");
});

test("proxy strips unapproved tools from tools/list", async () => {
  const manifest = buildManifest(
    [{ name: "read_file", inputSchema: { type: "object" } }],
  );
  const serverCode = spawnFakeServer(["read_file"], ["delete_everything", "exfiltrate"]);
  const responses = await runProxyTest(manifest, serverCode);

  assert.ok(responses[2], "tools/list response received");
  const toolNames = responses[2].result.tools.map((t) => t.name);
  assert.ok(toolNames.includes("read_file"), "approved tool visible");
  assert.ok(!toolNames.includes("delete_everything"), "unapproved tool stripped");
  assert.ok(!toolNames.includes("exfiltrate"), "unapproved tool stripped");
  assert.equal(toolNames.length, 1, "only 1 tool visible");
});

test("proxy allows calls to approved tools", async () => {
  const manifest = buildManifest(
    [{ name: "read_file", inputSchema: { type: "object" } }],
  );
  const serverCode = spawnFakeServer(["read_file"], []);
  const responses = await runProxyTest(manifest, serverCode);

  assert.ok(responses[3], "approved call response received");
  assert.ok(responses[3].result, "call succeeded");
  assert.equal(responses[3].result.content[0].text, "ok:read_file");
});

test("proxy blocks calls to unapproved tools", async () => {
  const manifest = buildManifest(
    [{ name: "read_file", inputSchema: { type: "object" } }],
  );
  const serverCode = spawnFakeServer(["read_file"], ["delete_everything"]);
  const responses = await runProxyTest(manifest, serverCode);

  assert.ok(responses[4], "blocked call response received");
  assert.ok(responses[4].error, "call was blocked with error");
  assert.equal(responses[4].error.code, -32601);
  assert.ok(responses[4].error.message.includes("delete_everything"));
  assert.ok(responses[4].error.message.includes("not in approved manifest"));
});

// Run a proxy test with extra flags (e.g. --strict, --auto-update)
async function runProxyTestWithFlags(manifest, serverCode, flags, manifestPath = "/tmp/test-manifest-flags.json") {
  const serverPath = "/tmp/test-fake-server-flags.js";
  writeFileSync(manifestPath, JSON.stringify(manifest));
  writeFileSync(serverPath, serverCode);

  return new Promise((resolve, reject) => {
    const proxyArgs = ["bin/mcp-proxy.js", "--manifest", manifestPath, ...flags, "--", "node", serverPath];
    const proxy = spawn("node", proxyArgs, {
      cwd: process.cwd(),
      env: { ...process.env, PATH: "/opt/homebrew/bin:" + process.env.PATH },
      stdio: ["pipe", "pipe", "pipe"],
    });

    const responses = {};
    let stderrBuf = "";
    let buf = "";
    const send = (msg) => proxy.stdin.write(JSON.stringify(msg) + "\n");

    proxy.stdout.on("data", (d) => {
      buf += d.toString();
      let idx;
      while ((idx = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, idx).trim();
        buf = buf.slice(idx + 1);
        if (!line) continue;
        try {
          const msg = JSON.parse(line);
          if (msg.id != null) responses[msg.id] = msg;
        } catch {}
      }
    });

    proxy.stderr.on("data", (d) => { stderrBuf += d.toString(); });

    const timeout = setTimeout(() => {
      proxy.kill();
      reject(new Error("test timeout"));
    }, 5000);

    send({ jsonrpc: "2.0", id: 1, method: "initialize", params: {
      protocolVersion: "2025-06-18", capabilities: {},
      clientInfo: { name: "test", version: "1.0" },
    }});
    send({ jsonrpc: "2.0", method: "notifications/initialized", params: {} });
    setTimeout(() => send({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }), 200);

    setTimeout(() => {
      clearTimeout(timeout);
      proxy.kill();
      resolve({ responses, stderr: stderrBuf });
    }, 800);
  });
}

test("proxy --strict mode returns error on drift and exits", async () => {
  const manifest = buildManifest(
    [{ name: "read_file", inputSchema: { type: "object" } }],
  );
  const serverCode = spawnFakeServer(["read_file"], ["new_tool"]);
  const { responses, stderr } = await runProxyTestWithFlags(manifest, serverCode, ["--strict"]);

  assert.ok(responses[2], "tools/list response received");
  assert.ok(responses[2].error, "strict mode returns error instead of filtered list");
  assert.ok(stderr.includes("STRICT MODE"), "stderr logs strict mode drift");
  assert.ok(stderr.includes("mcp-trustcard scan"), "stderr includes regeneration command");
});

test("proxy --auto-update mode updates manifest on disk when new tools appear", async () => {
  const manifestPath = "/tmp/test-manifest-autoupdate.json";
  const manifest = buildManifest(
    [{ name: "read_file", inputSchema: { type: "object" } }],
  );
  writeFileSync(manifestPath, JSON.stringify(manifest));
  const serverCode = spawnFakeServer(["read_file"], ["new_tool"]);
  const { responses, stderr } = await runProxyTestWithFlags(manifest, serverCode, ["--auto-update"], manifestPath);

  // In auto-update mode, all tools should be visible (manifest was updated)
  assert.ok(responses[2], "tools/list response received");
  assert.ok(responses[2].result, "auto-update returns result (not error)");
  const toolNames = responses[2].result.tools.map((t) => t.name);
  assert.ok(toolNames.includes("new_tool"), "new tool visible in auto-update mode");

  // Manifest file on disk should now include the new tool
  const updatedManifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  const updatedNames = updatedManifest.tools.map((t) => t.name);
  assert.ok(updatedNames.includes("new_tool"), "manifest file updated with new tool");
  assert.ok(stderr.includes("AUTO-UPDATE"), "stderr logs auto-update");
});

test("proxy --strict mode allows through when no drift", async () => {
  const manifest = buildManifest(
    [{ name: "read_file", inputSchema: { type: "object", properties: {} } }],
  );
  const serverCode = spawnFakeServer(["read_file"], []);
  const { responses, stderr } = await runProxyTestWithFlags(manifest, serverCode, ["--strict"]);

  assert.ok(responses[2], "tools/list response received");
  assert.ok(responses[2].result, "no error when no drift in strict mode");
  assert.ok(stderr.includes("tools/list OK"), "stderr confirms no drift");
});
