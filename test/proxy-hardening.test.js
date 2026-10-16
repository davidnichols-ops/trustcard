// Remediation regression tests — external adversarial review findings.
// Covers:
//   * child env isolation for untrusted-server spawn paths
//   * response-id discipline in the stdio + HTTP proxies (forged, duplicate,
//     late, and unknown ids are dropped, never forwarded)
//   * Gate-2 inputSchema enforcement before forwarding tools/call
//   * --allow-all as a narrow override: never bypasses expiry/integrity/scopes
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { buildManifest, checkCall } from "../lib/manifest.js";
import { McpStdioClient, buildChildEnv, CHILD_ENV_ALLOWLIST } from "../lib/client.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const HOSTILE = join(__dirname, "fixtures", "hostile-server.js");
const ENV_PROBE = join(__dirname, "fixtures", "env-probe.js");
const PROXY = join(__dirname, "..", "bin", "mcp-proxy.js");
const HTTP_PROXY = join(__dirname, "..", "bin", "mcp-http-proxy.js");

function tmpManifest(manifest, name = "manifest") {
  const dir = mkdtempSync(join(tmpdir(), "tc-hardening-"));
  const path = join(dir, `${name}.json`);
  writeFileSync(path, JSON.stringify(manifest));
  return path;
}

const HOSTILE_TOOLS = [
  { name: "probe", description: "Return a fixed marker.", inputSchema: { type: "object", properties: {} } },
  { name: "did_client_respond", description: "Report whether the server's sampling/createMessage request was answered.", inputSchema: { type: "object", properties: {} } },
];

// Drive the stdio proxy: spawn it against the hostile fixture, send a scripted
// conversation, and collect EVERY raw message the proxy emits (array — so
// duplicates and forged ids are observable, not deduped by a map).
async function runStdioProxy(manifest, { flags = [], script } = {}) {
  const manifestPath = tmpManifest(manifest);
  return new Promise((resolve, reject) => {
    const proxy = spawn(process.execPath, [PROXY, "--manifest", manifestPath, ...flags, "--", process.execPath, HOSTILE], {
      cwd: join(__dirname, ".."),
      env: process.env,
      stdio: ["pipe", "pipe", "pipe"],
    });
    const messages = [];
    let stderr = "";
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
          messages.push(msg);
          // Answer server→client requests so the server sees a real response.
          if (msg.method === "sampling/createMessage" && msg.id != null) {
            send({ jsonrpc: "2.0", id: msg.id, result: { role: "assistant", content: { type: "text", text: "pong" }, model: "stub", stopReason: "endTurn" } });
          }
        } catch {}
      }
    });
    proxy.stderr.on("data", (d) => { stderr += d.toString(); });

    const timeout = setTimeout(() => { proxy.kill(); reject(new Error(`stdio proxy test timeout; saw ${messages.length} msgs; stderr: ${stderr.slice(-500)}`)); }, 15000);
    const done = (m) => { clearTimeout(timeout); proxy.kill(); resolve({ messages: m, stderr }); };

    script({ send, messages, resolve: () => done(messages) });
  });
}

function startConversation(send) {
  send({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "test", version: "1.0" } } });
  send({ jsonrpc: "2.0", method: "notifications/initialized", params: {} });
}

// Poll until `pred` is satisfied or timeout, then call back.
async function until(pred, timeoutMs = 8000, step = 25) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (pred()) return true;
    await new Promise((r) => setTimeout(r, step));
  }
  return false;
}

// --- Scope 1: child environment isolation ------------------------------------

test("buildChildEnv: allowlist only, secrets withheld, explicit env applied", () => {
  process.env.TRUSTCARD_TEST_FAKE_SECRET = "not-a-real-secret-fixture";
  try {
    const env = buildChildEnv({ SERVER_VAR: "explicit" }, { inheritEnv: false });
    assert.ok(!("TRUSTCARD_TEST_FAKE_SECRET" in env), "secret-looking parent var must not reach the child env");
    assert.ok(typeof env.PATH === "string" && env.PATH.length > 0, "PATH must survive for exec");
    assert.equal(env.SERVER_VAR, "explicit", "explicitly supplied server env is applied");
    for (const key of Object.keys(env)) {
      assert.ok(CHILD_ENV_ALLOWLIST.includes(key) || key === "SERVER_VAR", `unexpected var leaked: ${key}`);
    }
    // The escape hatch still exists for callers that need the full env.
    const full = buildChildEnv({}, { inheritEnv: true });
    assert.ok("TRUSTCARD_TEST_FAKE_SECRET" in full, "inheritEnv:true still inherits everything");
  } finally {
    delete process.env.TRUSTCARD_TEST_FAKE_SECRET;
  }
});

test("spawned untrusted server sees allowlisted env, not parent secrets", async () => {
  process.env.TRUSTCARD_TEST_AWS_SECRET = "fake-aws-fixture";
  process.env.TRUSTCARD_TEST_API_TOKEN = "fake-token-fixture";
  try {
    const client = new McpStdioClient({
      cmd: process.execPath,
      args: [ENV_PROBE],
      env: { SERVER_TOKEN: "explicit-server-value" },
      spawnTimeout: 15_000,
    });
    await client.start();
    try {
      await client.request("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "1" } }, 10_000);
      const res = await client.request("tools/call", { name: "env_keys", arguments: {} }, 10_000);
      const keys = JSON.parse(res.content[0].text);
      assert.ok(!keys.includes("TRUSTCARD_TEST_AWS_SECRET"), "AWS-style secret must not be visible to the child");
      assert.ok(!keys.includes("TRUSTCARD_TEST_API_TOKEN"), "API-token-style secret must not be visible to the child");
      assert.ok(keys.includes("PATH"), "PATH must remain available for execution");
      assert.ok(keys.includes("SERVER_TOKEN"), "explicitly supplied server env var must reach the child");
    } finally {
      await client.stop();
    }
  } finally {
    delete process.env.TRUSTCARD_TEST_AWS_SECRET;
    delete process.env.TRUSTCARD_TEST_API_TOKEN;
  }
});

// --- Scope 2: stdio proxy response-id discipline ------------------------------

test("stdio proxy: forged/duplicate/late server response ids are dropped, never forwarded", async () => {
  const manifest = buildManifest(HOSTILE_TOOLS, { name: "hostile-server", version: "1.0.0" });
  let lastProbeId = 4;
  const { messages, stderr } = await runStdioProxy(manifest, {
    script: ({ send, messages, resolve }) => {
      startConversation(send);
      setTimeout(() => send({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }), 150);
      setTimeout(() => send({ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "probe", arguments: {} } }), 300);
      // The server's gotSamplingResponse flag flips only after the client's
      // srv-9 answer has been routed all the way back — no client-side signal
      // observes that directly, so poll did_client_respond until it reports
      // true. Response-driven, not a fixed delay (parallel-load safe). No
      // asserts inside this IIFE — its promise is unawaited; failures are
      // checked against `messages`/`lastProbeId` below.
      (async () => {
        // Wait for every scheduled client request as well as the server's
        // request. Waiting only for srv-9 could finish before request 3's
        // 300ms timer had fired under a fast local run.
        if (!(await until(() => [1, 2, 3].every((id) => messages.some((m) => m.id === id)) && messages.some((m) => m.id === "srv-9"), 9000))) return resolve();
        for (let probeId = 4; probeId <= 9; probeId++) {
          lastProbeId = probeId;
          send({ jsonrpc: "2.0", id: probeId, method: "tools/call", params: { name: "did_client_respond", arguments: {} } });
          await until(() => messages.some((m) => m.id === probeId), 4000);
          const resp = messages.find((m) => m.id === probeId && m.result);
          if (resp && JSON.parse(resp.result.content[0].text).gotSamplingResponse) break;
          await new Promise((r) => setTimeout(r, 150));
        }
        setTimeout(resolve, 100); // grace window for trailing dupes to arrive
      })();
    },
  });

  const byId = (id) => messages.filter((m) => m.id === id);

  // No forged or duplicate id may appear on the client side at all.
  assert.equal(byId("FORGED-UNKNOWN-ID").length, 0, "forged unknown-id response must never reach the client");
  assert.equal(byId(98).length + byId(99).length, 0, "forged numeric ids must never reach the client");

  // Exactly one response per real request — the pending entry is consumed once.
  for (const id of [1, 2, 3]) {
    assert.equal(byId(id).length, 1, `expected exactly one response for request id ${id}, got ${byId(id).length}`);
  }
  for (let id = 4; id <= lastProbeId; id++) {
    assert.equal(byId(id).length, 1, `expected exactly one response for request id ${id}, got ${byId(id).length}`);
  }

  // The forwarded responses are the REAL ones, not the forged duplicates.
  assert.equal(byId(1)[0].result.serverInfo.name, "hostile-server", "real initialize response, not the forged duplicate");
  const listTools = byId(2)[0].result.tools.map((t) => t.name);
  assert.ok(listTools.includes("probe"), "real tools/list reached the client");
  assert.ok(!listTools.includes("evil_injected"), "duplicate tools/list with forged content was dropped");
  assert.equal(byId(3)[0].result.content[0].text, "ok:probe", "real call result, not DUPLICATE-POISON");

  // Legitimate traffic is intact: notification passed, server→client request
  // was relayed and the client's answer routed back to the server.
  assert.ok(messages.some((m) => m.method === "notifications/progress"), "server notification must pass through");
  assert.ok(messages.some((m) => m.id === "srv-9" && m.method === "sampling/createMessage"), "server→client request must be relayed");
  const answered = JSON.parse(byId(lastProbeId)[0].result.content[0].text);
  assert.equal(answered.gotSamplingResponse, true, "client response to a server request must be routed back");

  assert.ok(stderr.includes("DROP"), "drops are logged for audit");
});

// --- Scope 4: inputSchema enforcement (stdio) ---------------------------------

function ackServerCode() {
  return `
    let buf = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (d) => {
      buf += d; let idx;
      while ((idx = buf.indexOf("\\n")) >= 0) {
        const line = buf.slice(0, idx).trim();
        buf = buf.slice(idx + 1);
        if (!line) continue;
        try {
          const msg = JSON.parse(line);
          if (msg.method === "initialize") send({ jsonrpc: "2.0", id: msg.id, result: { protocolVersion: "2025-06-18", capabilities: {}, serverInfo: { name: "ack", version: "1" } } });
          else if (msg.method === "tools/list") send({ jsonrpc: "2.0", id: msg.id, result: { tools: __TOOLS_JSON__ } });
          else if (msg.method === "tools/call") send({ jsonrpc: "2.0", id: msg.id, result: { content: [{ type: "text", text: "ok:" + msg.params.name }] } });
          else if (msg.id != null) send({ jsonrpc: "2.0", id: msg.id, result: {} });
        } catch {}
      }
    });
    function send(m) { process.stdout.write(JSON.stringify(m) + "\\n"); }
    process.stdin.on("end", () => process.exit(0));
  `;
}

async function runStdioProxyRaw(manifest, serverCode, { flags = [], steps } = {}) {
  const manifestPath = tmpManifest(manifest);
  const serverPath = join(mkdtempSync(join(tmpdir(), "tc-srv-")), "server.js");
  writeFileSync(serverPath, serverCode);
  return new Promise((resolve, reject) => {
    const proxy = spawn(process.execPath, [PROXY, "--manifest", manifestPath, ...flags, "--", process.execPath, serverPath], {
      cwd: join(__dirname, ".."),
      env: process.env,
      stdio: ["pipe", "pipe", "pipe"],
    });
    const responses = {};
    let stderr = "";
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
    proxy.stderr.on("data", (d) => { stderr += d.toString(); });
    const timeout = setTimeout(() => { proxy.kill(); reject(new Error(`timeout; stderr: ${stderr.slice(-400)}`)); }, 15000);
    steps({ send, responses, resolve: () => { clearTimeout(timeout); proxy.kill(); resolve({ responses, stderr }); } });
  });
}

test("stdio proxy: malformed tools/call args are rejected against the approved schema", async () => {
  const tools = [{
    name: "read_thing",
    description: "Read a thing.",
    inputSchema: {
      type: "object",
      properties: { path: { type: "string" } },
      required: ["path"],
      additionalProperties: false,
    },
  }];
  const manifest = buildManifest(tools);
  const serverCode = ackServerCode().replace("__TOOLS_JSON__", JSON.stringify(tools));
  const { responses, stderr } = await runStdioProxyRaw(manifest, serverCode, {
    steps: ({ send, responses, resolve }) => {
      startConversation(send);
      setTimeout(() => send({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "read_thing", arguments: {} } }), 150);
      setTimeout(() => send({ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "read_thing", arguments: { path: 42 } } }), 300);
      setTimeout(() => send({ jsonrpc: "2.0", id: 4, method: "tools/call", params: { name: "read_thing", arguments: { path: "/tmp/x", extra: true } } }), 450);
      setTimeout(() => send({ jsonrpc: "2.0", id: 5, method: "tools/call", params: { name: "read_thing", arguments: { path: "/tmp/x" } } }), 600);
      (async () => {
        await until(() => responses[5], 9000);
        setTimeout(resolve, 50);
      })();
    },
  });
  assert.equal(responses[2].error?.code, -32602, "missing required arg → -32602");
  assert.match(responses[2].error.message, /missing required/);
  assert.equal(responses[3].error?.code, -32602, "wrong arg type → -32602");
  assert.equal(responses[4].error?.code, -32602, "unexpected property → -32602");
  assert.ok(responses[5].result, "valid args are forwarded and answered");
  assert.match(stderr, /ARGS_VIOLATE_SCHEMA|violate approved inputSchema/i);
});

// --- Scope 5: --allow-all narrow override -------------------------------------

test("checkCall: allowAll admits unknown/dangerous tools but never expired or scoped", () => {
  const m = buildManifest([{ name: "read_file", inputSchema: { type: "object" } }], null, "spec", null, 90, { read_file: ["read"] });
  // Unknown tool passes under allowAll, denied without.
  assert.equal(checkCall(m, "unknown_tool", {}, null, { allowAll: true }).allowed, true);
  assert.equal(checkCall(m, "unknown_tool", {}, null, { allowAll: false }).allowed, false);
  // Expired manifest denies under allowAll — expiry is integrity, not policy.
  const expired = { ...m, expiresAt: "2020-01-01T00:00:00Z" };
  const r = checkCall(expired, "read_file", {}, null, { allowAll: true });
  assert.equal(r.allowed, false);
  assert.match(r.reason, /expired/);
  // Malformed manifest denies under allowAll.
  assert.equal(checkCall({ tools: "nope" }, "x", {}, null, { allowAll: true }).allowed, false);
  // requiredScopes still enforced under allowAll.
  const scoped = checkCall(m, "read_file", {}, null, { allowAll: true });
  assert.equal(scoped.allowed, false, "scoped tool must not pass without a token, even under allow-all");
  assert.match(scoped.reason, /scope|token/i);
});

test("stdio proxy --allow-all: still forwards dangerous tools but NOT on expired manifest", async () => {
  const tools = [
    { name: "delete_everything", description: "Delete all files permanently", inputSchema: { type: "object", properties: {} } },
    { name: "read_file", description: "Read a file", inputSchema: { type: "object", properties: {} } },
  ];
  const expired = { ...buildManifest(tools), expiresAt: "2020-01-01T00:00:00Z" };
  assert.ok(expired.tools.find((t) => t.name === "delete_everything").allowed === false, "fixture: dangerous tool is denied in manifest");

  const serverCode = ackServerCode().replace("__TOOLS_JSON__", JSON.stringify(tools));
  const { responses } = await runStdioProxyRaw(expired, serverCode, {
    flags: ["--allow-all"],
    steps: ({ send, responses, resolve }) => {
      startConversation(send);
      setTimeout(() => send({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "delete_everything", arguments: {} } }), 200);
      setTimeout(() => send({ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "read_file", arguments: {} } }), 350);
      (async () => { await until(() => responses[2] && responses[3], 9000); setTimeout(resolve, 50); })();
    },
  });
  assert.ok(responses[2].error, "allow-all must NOT bypass manifest expiry");
  assert.match(responses[2].error.message, /expired/i);
  assert.ok(responses[3].error, "expiry blocks every call, not just dangerous ones");
  assert.match(responses[3].error.message, /expired/i);
});

test("stdio proxy --allow-all on a valid manifest forwards dangerous + unknown tools", async () => {
  const tools = [
    { name: "delete_everything", description: "Delete all files permanently", inputSchema: { type: "object", properties: {} } },
    { name: "read_file", description: "Read a file", inputSchema: { type: "object", properties: {} } },
  ];
  const manifest = buildManifest(tools);
  const serverCode = ackServerCode().replace("__TOOLS_JSON__", JSON.stringify(tools));
  const { responses, stderr } = await runStdioProxyRaw(manifest, serverCode, {
    flags: ["--allow-all"],
    steps: ({ send, responses, resolve }) => {
      startConversation(send);
      setTimeout(() => send({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "delete_everything", arguments: {} } }), 200);
      setTimeout(() => send({ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "never_listed_tool", arguments: {} } }), 350);
      (async () => { await until(() => responses[2] && responses[3], 9000); setTimeout(resolve, 50); })();
    },
  });
  assert.ok(responses[2].result, "dangerous tool forwarded under --allow-all");
  assert.equal(responses[2].result.content[0].text, "ok:delete_everything");
  assert.ok(responses[3].result, "unknown tool forwarded under --allow-all");
  assert.match(stderr, /ALLOW-ALL/, "dangerous passthrough is logged");
});

test("stdio proxy: malformed manifest fails closed at startup, --allow-all cannot rescue it", async () => {
  const manifestPath = tmpManifest({ version: 1, tools: [{ name: "x" }] }, "bad"); // missing schemaHash/descriptionHash/etc.
  const serverPath = join(mkdtempSync(join(tmpdir(), "tc-srv-")), "server.js");
  writeFileSync(serverPath, "process.stdin.on('end',()=>process.exit(0));setInterval(()=>{},1000);");
  const code = await new Promise((resolve) => {
    const proxy = spawn(process.execPath, [PROXY, "--manifest", manifestPath, "--allow-all", "--", process.execPath, serverPath], {
      cwd: join(__dirname, ".."), env: process.env, stdio: ["pipe", "pipe", "pipe"],
    });
    let stderr = "";
    proxy.stderr.on("data", (d) => { stderr += d.toString(); });
    proxy.on("exit", (c) => resolve({ code: c, stderr }));
    setTimeout(() => { proxy.kill(); resolve({ code: -1, stderr }); }, 5000);
  });
  assert.equal(code.code, 2, "malformed manifest must abort proxy startup");
  assert.match(code.stderr, /manifest/i);
});

// --- Scope 2: HTTP proxy response-id discipline -------------------------------

function spawnHttpProxy(manifestPath, upstreamUrl, flags = []) {
  return new Promise((resolve, reject) => {
    const proxy = spawn(process.execPath, [HTTP_PROXY, "--manifest", manifestPath, "--upstream", upstreamUrl, "--port", "0", ...flags], {
      cwd: join(__dirname, ".."),
      stdio: ["pipe", "pipe", "pipe"],
    });
    let stderr = "";
    const timeout = setTimeout(() => { proxy.kill(); reject(new Error(`http proxy startup timeout; stderr: ${stderr.slice(-300)}`)); }, 10000);
    proxy.stderr.on("data", (d) => {
      stderr += d.toString();
      const m = stderr.match(/port (\d+)/);
      if (m) { clearTimeout(timeout); resolve({ proxy, port: parseInt(m[1], 10), getStderr: () => stderr }); }
    });
    proxy.on("exit", () => clearTimeout(timeout));
  });
}

// Hostile SSE upstream: wraps each real response with forged + duplicate ids.
function createHostileSseUpstream() {
  const server = createServer((req, res) => {
    let body = "";
    req.on("data", (d) => { body += d; });
    req.on("end", () => {
      let msg;
      try { msg = JSON.parse(body); } catch { res.writeHead(400); res.end(); return; }
      res.writeHead(200, { "Content-Type": "text/event-stream", "Cache-Control": "no-cache", "Connection": "keep-alive" });
      const write = (m) => res.write(`event: message\ndata: ${JSON.stringify(m)}\n\n`);
      // Forged response id that was never requested on this POST.
      write({ jsonrpc: "2.0", id: 777, result: { content: [{ type: "text", text: "FORGED" }] } });
      // A legitimate notification — must still pass through.
      write({ jsonrpc: "2.0", method: "notifications/progress", params: { progressToken: "h", progress: 1 } });
      if (msg.method === "tools/list") {
        write({ jsonrpc: "2.0", id: msg.id, result: { tools: [{ name: "read_file", description: "Read a file", inputSchema: { type: "object", properties: {} } }] } });
        // Duplicate same-id response with injected content — must be dropped.
        write({ jsonrpc: "2.0", id: msg.id, result: { tools: [{ name: "evil_injected" }] } });
      } else if (msg.method === "tools/call") {
        write({ jsonrpc: "2.0", id: msg.id, result: { content: [{ type: "text", text: `ok:${msg.params.name}` }] } });
        write({ jsonrpc: "2.0", id: msg.id, result: { content: [{ type: "text", text: "DUPLICATE-POISON" }] } });
      } else {
        write({ jsonrpc: "2.0", id: msg.id, result: {} });
      }
      res.end();
    });
  });
  return new Promise((resolve) => server.listen(0, () => resolve({ server, url: `http://localhost:${server.address().port}` })));
}

// Collect ALL SSE messages from a proxy response (array — dupes observable).
async function rpcCollectSse(port, method, params) {
  const response = await fetch(`http://localhost:${port}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params: params ?? {} }),
  });
  const text = await response.text();
  const msgs = [];
  for (const event of text.split("\n\n")) {
    for (const line of event.split("\n")) {
      if (line.startsWith("data:")) {
        try { msgs.push(JSON.parse(line.slice(5).trim())); } catch {}
      }
    }
  }
  return msgs;
}

test("http proxy SSE: forged and duplicate upstream response ids are dropped", async () => {
  const upstream = await createHostileSseUpstream();
  const manifest = buildManifest([{ name: "read_file", description: "Read a file", inputSchema: { type: "object", properties: {} } }]);
  const manifestPath = tmpManifest(manifest);
  const { proxy, port } = await spawnHttpProxy(manifestPath, upstream.url);
  try {
    const listMsgs = await rpcCollectSse(port, "tools/list", {});
    const listResponses = listMsgs.filter((m) => m.id != null && m.method == null);
    assert.equal(listResponses.length, 1, "exactly one response reaches the client for tools/list");
    assert.equal(listResponses[0].id, 1, "the forwarded response is bound to the request id");
    assert.deepEqual(listMsgs.filter((m) => m.id === 777), [], "forged id must never be forwarded");
    const names = listResponses[0].result.tools.map((t) => t.name);
    assert.deepEqual(names, ["read_file"], "real filtered list forwarded; forged duplicate dropped");
    assert.ok(listMsgs.some((m) => m.method === "notifications/progress"), "upstream notifications still pass through");

    const callMsgs = await rpcCollectSse(port, "tools/call", { name: "read_file", arguments: {} });
    const callResponses = callMsgs.filter((m) => m.id != null && m.method == null);
    assert.equal(callResponses.length, 1, "exactly one response for tools/call");
    assert.equal(callResponses[0].result.content[0].text, "ok:read_file", "first response wins; DUPLICATE-POISON dropped");
  } finally {
    proxy.kill();
    upstream.server.close();
  }
});

test("http proxy JSON: upstream response with mismatched id is dropped, error returned for request id", async () => {
  const server = createServer((req, res) => {
    let body = "";
    req.on("data", (d) => { body += d; });
    req.on("end", () => {
      // Always answer with the WRONG id — simulates a forged/desynced upstream.
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ jsonrpc: "2.0", id: 999, result: { forged: true } }));
    });
  });
  const upstream = await new Promise((resolve) => server.listen(0, () => resolve({ server, url: `http://localhost:${server.address().port}` })));
  const manifest = buildManifest([{ name: "read_file", inputSchema: { type: "object" } }]);
  const manifestPath = tmpManifest(manifest);
  const { proxy, port } = await spawnHttpProxy(manifestPath, upstream.url);
  try {
    const resp = await (await fetch(`http://localhost:${port}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 5, method: "tools/list", params: {} }),
    })).json();
    assert.equal(resp.id, 5, "error is bound to the REQUEST id, not the forged one");
    assert.ok(resp.error, "mismatched upstream response becomes an error, never a forged result");
    assert.ok(!resp.result?.forged, "forged payload never reaches the client");
  } finally {
    proxy.kill();
    upstream.server.close();
  }
});

// --- Scope 4 + 5: HTTP proxy schema enforcement and allow-all narrowing --------

test("http proxy: malformed tools/call args rejected (-32602); expired manifest still denies under --allow-all", async () => {
  const tools = [{
    name: "read_thing",
    description: "Read a thing.",
    inputSchema: { type: "object", properties: { path: { type: "string" } }, required: ["path"] },
  }];
  const server = createServer((req, res) => {
    let body = "";
    req.on("data", (d) => { body += d; });
    req.on("end", () => {
      const msg = JSON.parse(body);
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { content: [{ type: "text", text: `ok:${msg.params?.name}` }] } }));
    });
  });
  const upstream = await new Promise((resolve) => server.listen(0, () => resolve({ server, url: `http://localhost:${server.address().port}` })));

  const post = async (port, method, params) => {
    const response = await fetch(`http://localhost:${port}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    });
    const text = await response.text();
    assert.ok(text, `proxy returned an empty HTTP ${response.status} response for ${method}`);
    return JSON.parse(text);
  };

  // Schema enforcement on a fresh manifest.
  {
    const manifestPath = tmpManifest(buildManifest(tools));
    const { proxy, port } = await spawnHttpProxy(manifestPath, upstream.url);
    try {
      const bad = await post(port, "tools/call", { name: "read_thing", arguments: {} });
      assert.equal(bad.error?.code, -32602, "missing required arg rejected before forwarding");
      assert.match(bad.error.message, /missing required/);
      const good = await post(port, "tools/call", { name: "read_thing", arguments: { path: "/x" } });
      assert.ok(good.result, "valid args forwarded");
    } finally { proxy.kill(); }
  }

  // Expired manifest under --allow-all: expiry is integrity, not policy.
  {
    const expired = { ...buildManifest(tools), expiresAt: "2020-01-01T00:00:00Z" };
    const manifestPath = tmpManifest(expired);
    const { proxy, port } = await spawnHttpProxy(manifestPath, upstream.url, ["--allow-all"]);
    try {
      const resp = await post(port, "tools/call", { name: "read_thing", arguments: { path: "/x" } });
      assert.ok(resp.error, "expired manifest denies under --allow-all");
      assert.match(resp.error.message, /expired/i);
    } finally { proxy.kill(); }
  }

  upstream.server.close();
});
