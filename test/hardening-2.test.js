// Regression coverage for the external-review remediation pass:
//   A) npm/spec handling never touches a shell — backticks and $() stay literal
//   B) CLI contract — unknown commands fail, --require-scopes tool=scope,
//      inspect exits nonzero on invalid manifests, secrets via file/env
//   C) fleet UX — legacy manifests classify as legacy-format, not drift;
//      renew defaults to a 14-day window; dry-run prints a preview marker
//   D) behavior --server passes flags/specs verbatim and surfaces child stderr
//   E) scanner calibration — UNKNOWN scores 0, unauthenticated list is WARN,
//      high-confidence destructive capability FAILs and drops the score
//   I) HTTP fleet gap — gate preview/apply leaves entry UNGATED until applied,
//      then renew/status see it as gated
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync, spawn } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync, readFileSync, existsSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createServer } from "node:http";
import { isNpmSpec, assertNpmSpec } from "../lib/npm.js";
import { runHealthcheck } from "../lib/checks.js";
import { packageIdentity } from "../lib/fingerprint.js";
import { renewManifest, buildManifest, legacyManifestHash } from "../lib/manifest.js";
import { renewServer, listGated, parseHttpGated, TRUSTCARD_HTTP_GATE_KEY } from "../lib/fleet.js";
import { FIXTURE, fixtureCmd, TOOL_SEARCH, TOOL_FETCH, clone } from "./helpers.js";

const BIN = new URL("../bin/mcp-trustcard.js", import.meta.url).pathname;
const REPO = join(dirname(fileURLToPath(import.meta.url)), "..");

function run(args, opts = {}) {
  const r = spawnSync(process.execPath, [BIN, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], timeout: 60_000, ...opts });
  return { code: r.status ?? 1, out: r.stdout ?? "", err: r.stderr ?? "" };
}

// Async variant for tests that host an in-process fixture server — a blocking
// spawnSync would deadlock against our own event loop.
function runAsync(args, opts = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [BIN, ...args], { stdio: ["ignore", "pipe", "pipe"], ...opts });
    let out = "", err = "";
    child.stdout.on("data", (c) => { out += c; });
    child.stderr.on("data", (c) => { err += c; });
    const timer = setTimeout(() => { child.kill("SIGKILL"); reject(new Error("CLI timed out")); }, 60_000);
    child.on("close", (code) => { clearTimeout(timer); resolve({ code: code ?? 1, out, err }); });
    child.on("error", (e) => { clearTimeout(timer); reject(e); });
  });
}

function tmpdirFor(t) {
  const dir = mkdtempSync(join(tmpdir(), "tc-h2-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}

// ─── A) shell injection ──────────────────────────────────────────────────────

test("A: npm spec validation rejects shell metacharacters", () => {
  for (const s of [
    "$(touch /tmp/x)", "`touch /tmp/x`", "pkg; rm -rf /", "pkg && evil",
    "pkg | tee out", "pkg > out", "pkg < in", "pkg\ninject", "pkg arg",
    "--registry=evil.example", "pkg@>=1 <2", "@scope/pkg name",
    "file:./x", "git+https://evil", "a".repeat(300), "",
  ]) assert.equal(isNpmSpec(s), false, `should reject: ${JSON.stringify(s).slice(0, 40)}`);
  for (const s of ["pkg", "@scope/pkg", "pkg@1.2.3", "@scope/pkg@^2.0.0", "pkg@latest", "pkg@beta.2", "pkg-name_test~1"])
    assert.equal(isNpmSpec(s), true, `should accept: ${s}`);
});

test("A: healthcheck on a hostile spec refuses to spawn and executes nothing", async (t) => {
  const dir = tmpdirFor(t);
  const marker = join(dir, "pwned");
  const hostile = `$(touch ${marker})`;
  assert.equal(isNpmSpec(hostile), false);
  const r = await runHealthcheck(hostile);
  assert.equal(r.invalidSpec, true);
  assert.equal(r.checks.installability.status, "FAIL");
  assert.equal(r.checks.handshake.status, "FAIL");
  assert.equal(existsSync(marker), false, "command substitution must never execute");
});

test("A: backtick substitution in a spec is a literal npm argument, not a command", async (t) => {
  const dir = tmpdirFor(t);
  const marker = join(dir, "pwned");
  const r = await runHealthcheck("`touch " + marker + "`");
  assert.equal(r.checks.installability.status, "FAIL");
  assert.equal(existsSync(marker), false);
});

test("A: failed npm lookup stops before spawn and excludes unrun checks", async () => {
  const r = await runHealthcheck("missing-package", {
    checkInstallability: async () => ({
      status: "FAIL", detail: "npm view failed: 404", score: 0, max: 15,
      meta: { lookupFailed: true },
    }),
  });
  assert.equal(r.lookupFailed, true);
  assert.equal(r.checks.handshake.status, "FAIL");
  assert.match(r.checks.handshake.detail, /not spawned/);
  assert.equal(r.max, 15);
  assert.equal(r.score, 0);
});

test("A: npm package without a bin is classified as non-runnable, not config-required", async () => {
  const r = await runHealthcheck("ordinary-library", {
    checkInstallability: async () => ({
      status: "WARN", detail: "ordinary-library@1.0.0 (no bin)", score: 10, max: 15,
      meta: { name: "ordinary-library", version: "1.0.0", noBin: true },
    }),
  });
  assert.equal(r.nonRunnable, true);
  assert.equal(r.configRequired, undefined);
  assert.equal(r.checks.handshake.status, "SKIPPED");
  assert.equal(r.checks.authentication.status, "UNKNOWN");
  assert.doesNotMatch(r.checks.authentication.detail, /requires config/);
  assert.equal(r.max, 15);
});

test("E: local scan excludes npm installability and unproven secret absence from denominator", async () => {
  const r = await runHealthcheck(fixtureCmd("stable"));
  assert.equal(r.checks.installability.status, "SKIPPED");
  assert.equal(r.checks.installability.max, 0);
  assert.equal(r.checks.secretExposure.status, "UNKNOWN");
  assert.equal(r.checks.secretExposure.max, 0);
  assert.equal(r.max, 75);
});

test("A: fingerprint packageIdentity rejects hostile specs without executing them", async (t) => {
  const dir = tmpdirFor(t);
  const marker = join(dir, "pwned");
  const r = await packageIdentity(`a; touch ${marker}`);
  assert.equal(r.ok, false);
  assert.match(r.error, /invalid npm package spec/);
  assert.equal(existsSync(marker), false);
});

test("A: gen-manifest rejects a hostile spec before any child process", (t) => {
  const dir = tmpdirFor(t);
  const marker = join(dir, "pwned");
  const r = run(["gen-manifest", `$(touch ${marker})`, "--save-manifest", join(dir, "m.json")]);
  assert.equal(r.code, 2);
  assert.match(r.err + r.out, /invalid npm package spec/);
  assert.equal(existsSync(marker), false);
});

// ─── B) CLI contract ─────────────────────────────────────────────────────────

test("B: unknown commands fail with a suggestion instead of scanning", () => {
  const r = run(["verfy"]);
  assert.equal(r.code, 2);
  assert.match(r.err, /did you mean/);
  const r2 = run(["not a command!!"]);
  assert.equal(r2.code, 2);
  assert.match(r2.err, /unknown command/);
});

test("B: --require-scopes accepts documented tool=scope syntax, wildcard, and colon form", (t) => {
  const dir = tmpdirFor(t);
  const out = join(dir, "m.json");
  const r = run(["gen-manifest", "--", process.execPath, FIXTURE, "--save-manifest", out,
    "--require-scopes", "search=read:docs,write:docs", "--require-scopes", "fetch_document:read"]);
  assert.equal(r.code, 0, r.err);
  const m = JSON.parse(readFileSync(out, "utf8"));
  assert.deepEqual(m.tools.find((x) => x.name === "search").requiredScopes, ["read:docs", "write:docs"]);
  assert.deepEqual(m.tools.find((x) => x.name === "fetch_document").requiredScopes, ["read"]);

  const out2 = join(dir, "m2.json");
  const r2 = run(["gen-manifest", "--", process.execPath, FIXTURE, "--save-manifest", out2, "--require-scopes", "*=audit"]);
  assert.equal(r2.code, 0, r2.err);
  const m2 = JSON.parse(readFileSync(out2, "utf8"));
  for (const tool of m2.tools) assert.deepEqual(tool.requiredScopes, ["audit"]);
});

test("B: --require-scopes naming a nonexistent tool exits 2 (no silent drop)", (t) => {
  const dir = tmpdirFor(t);
  const r = run(["gen-manifest", "--", process.execPath, FIXTURE, "--save-manifest", join(dir, "m.json"),
    "--require-scopes", "no_such_tool=read"]);
  assert.equal(r.code, 2);
  assert.match(r.err, /does not expose.*no_such_tool/);
  // --allow-tool on a nonexistent tool fails the same way
  const r2 = run(["gen-manifest", "--", process.execPath, FIXTURE, "--save-manifest", join(dir, "m.json"),
    "--allow-tool", "ghost_tool"]);
  assert.equal(r2.code, 2);
  assert.match(r2.err, /does not expose.*ghost_tool/);
});

test("B: inspect exits nonzero on corrupt proxy manifests", (t) => {
  const dir = tmpdirFor(t);
  // Tampered proxy manifest → nonzero
  const proxy = buildManifest([TOOL_SEARCH]);
  proxy.manifestHash = "sha256:tampered";
  const proxyPath = join(dir, "proxy.json");
  writeFileSync(proxyPath, JSON.stringify(proxy));
  const r1 = run(["inspect", proxyPath]);
  assert.equal(r1.code, 1, "corrupt proxy manifest must fail");
  assert.match(r1.out, /MISMATCH/);

  // Untampered proxy manifest → 0
  const goodPath = join(dir, "good.json");
  writeFileSync(goodPath, JSON.stringify(buildManifest([TOOL_SEARCH])));
  assert.equal(run(["inspect", goodPath]).code, 0);
});

test("B: inspect nonzero on invalid signed/provenance manifests", async (t) => {
  const dir = tmpdirFor(t);
  const { buildManifest: buildProv, generatePublisherKeypair, signManifest } = await import("../lib/provenance.js");
  const kp = generatePublisherKeypair();
  const m = buildProv({ serverInfo: { name: "s", version: "1" }, protocolVersion: "2025-06-18", tools: [TOOL_SEARCH], publisher: { keyId: kp.keyId, publicKey: kp.publicKey } });
  const signed = signManifest(m, kp.privateKey);
  signed.tools[0].description = "tampered after signing";
  const p = join(dir, "signed.json");
  writeFileSync(p, JSON.stringify(signed));
  const r = run(["inspect", p]);
  assert.equal(r.code, 1);
  assert.match(r.out, /Verified:\s+NO/);

  // An unsigned provenance manifest whose digests were corrupted → nonzero
  const bad = buildProv({ serverInfo: { name: "s", version: "1" }, protocolVersion: "2025-06-18", tools: [TOOL_SEARCH], publisher: { keyId: kp.keyId, publicKey: kp.publicKey } });
  bad.toolsetDigest = "sha256:corrupt";
  const bp = join(dir, "badprov.json");
  writeFileSync(bp, JSON.stringify(bad));
  const r2 = run(["inspect", bp]);
  assert.equal(r2.code, 1);
  assert.match(r2.out, /INVALID/);

  // Well-formed unsigned provenance manifest → 0
  const gp = join(dir, "prov.json");
  writeFileSync(gp, JSON.stringify(buildProv({ serverInfo: { name: "s", version: "1" }, protocolVersion: "2025-06-18", tools: [TOOL_SEARCH], publisher: { keyId: kp.keyId, publicKey: kp.publicKey } })));
  const r3 = run(["inspect", gp]);
  assert.equal(r3.code, 0, r3.err + r3.out);
  assert.match(r3.out, /unsigned/);
});

test("B: auth secrets come from file or env, not argv", (t) => {
  const dir = tmpdirFor(t);
  const secretFile = join(dir, "secret.txt");
  writeFileSync(secretFile, "0123456789abcdef".repeat(4), { mode: 0o600 });

  // --secret-file works
  const issued = run(["auth-issue", "--subject", "agent-7", "--scopes", "read:files", "--secret-file", secretFile, "--quiet"]);
  assert.equal(issued.code, 0, issued.err);
  const token = issued.out.trim();

  const verified = run(["auth-verify", token, "--secret-file", secretFile]);
  assert.equal(verified.code, 0, verified.err);
  assert.match(verified.out, /agent-7/);

  // TRUSTCARD_AUTH_SECRET env works without any argv secret
  const issued2 = run(["auth-issue", "--subject", "agent-8", "--scopes", "x", "--quiet"], {
    env: { ...process.env, TRUSTCARD_AUTH_SECRET: "deadbeef".repeat(8) },
  });
  assert.equal(issued2.code, 0, issued2.err);
  assert.doesNotMatch(issued2.err, /--secret/);

  // no secret anywhere → exit 2 with guidance pointing at file/env, not argv
  const missing = run(["auth-issue", "--subject", "agent-9", "--quiet"], { env: { ...process.env, TRUSTCARD_AUTH_SECRET: "" } });
  assert.equal(missing.code, 2);
  assert.match(missing.err, /--secret-file|TRUSTCARD_AUTH_SECRET/);
});

test("B: clientInfo version derives from package.json, not a literal", async () => {
  const { TRUSTCARD_VERSION } = await import("../lib/version.js");
  const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
  assert.equal(TRUSTCARD_VERSION, pkg.version);
});

// ─── C) fleet UX ─────────────────────────────────────────────────────────────

test("C: legacy manifests classify as legacy-format, not drift", (t) => {
  const m = buildManifest([TOOL_SEARCH]);
  const legacy = structuredClone(m);
  delete legacy.tools[0].contractDigest;
  const r = renewManifest(legacy, [clone(TOOL_SEARCH)]);
  assert.equal(r.renewed, false);
  assert.equal(r.code, "legacy-format");
  assert.match(r.reason, /reapproval required/);
});

test("C: renewServer reports legacy-format action, reapproval-required reason", async (t) => {
  const dir = tmpdirFor(t);
  // A real legacy manifest predates contractDigest — its recorded hash is the
  // legacy format (name:schemaHash:allowed), so it verifies as legacy-v1.
  const m = buildManifest([TOOL_SEARCH]);
  delete m.tools[0].contractDigest;
  delete m.tools[0].declaredScopesHash;
  m.manifestHash = legacyManifestHash(m.tools);
  const manifestPath = join(dir, "m.json");
  writeFileSync(manifestPath, JSON.stringify(m), { mode: 0o600 });
  const r = await renewServer({ name: "x", manifest: manifestPath }, { list: async () => ({ tools: [clone(TOOL_SEARCH)] }) });
  assert.equal(r.ok, false);
  assert.equal(r.action, "legacy-format");
  assert.match(r.reason, /reapproval/);
});

test("C: renew defaults to a 14-day window and reapprove --dry-run shows a preview mark", (t) => {
  const dir = tmpdirFor(t);
  // Manifest fresh for 80 days → skipped under the default 14d window.
  const m = buildManifest([TOOL_SEARCH]);
  m.expiresAt = new Date(Date.now() + 80 * 86_400_000).toISOString();
  const manifestPath = join(dir, "m.json");
  writeFileSync(manifestPath, JSON.stringify(m));
  const cfg = join(dir, "config.json");
  writeFileSync(cfg, JSON.stringify({ mcpServers: { test: { command: process.execPath, args: ["x/mcp-proxy.js", "--manifest", manifestPath, "--", "echo"] } } }));
  const r = run(["renew", "--config", cfg]);
  assert.equal(r.code, 0, r.err);
  assert.match(r.out, /skipped/, "80-day-left manifest is outside the 14d window");

  // reapprove --dry-run on a REAL fixture server behind a wrapped entry:
  // legacy manifest → rebuild preview → "would-reapprove" with the ◌ mark.
  const m2 = buildManifest([TOOL_SEARCH, TOOL_FETCH]);
  delete m2.tools[0].contractDigest;
  delete m2.tools[0].declaredScopesHash;
  delete m2.tools[1].contractDigest;
  delete m2.tools[1].declaredScopesHash;
  m2.manifestHash = legacyManifestHash(m2.tools);
  // Reapprove only runs on manifests that need it — an expired manifest is
  // eligible; a fresh one is "skipped".
  const mPath2 = join(dir, "legacy.json");
  writeFileSync(mPath2, JSON.stringify(m2));
  const cfg2 = join(dir, "config2.json");
  writeFileSync(cfg2, JSON.stringify({ mcpServers: { live: { command: process.execPath, args: ["x/mcp-proxy.js", "--manifest", mPath2, "--", process.execPath, FIXTURE] } } }));
  const r2 = run(["reapprove", "--config", cfg2, "--dry-run"]);
  assert.equal(r2.code, 0, r2.err);
  assert.match(r2.out, /◌.*would-reapprove/, "dry-run must show a preview mark");
  assert.match(r2.out, /would-reapprove/);
  // And nothing was written: the manifest on disk is still the legacy file.
  assert.equal(JSON.parse(readFileSync(mPath2, "utf8")).manifestHash, m2.manifestHash);
});

// ─── D) behavior --server ────────────────────────────────────────────────────

test("D: --server args pass flags and non-path args verbatim to the child", async () => {
  // The fix under test: previously every arg was resolved as a path, mangling
  // `-y` and npm specs into `/cwd/-y` etc. Now only path-looking args resolve.
  const { SandboxRuntime } = await import("../lib/behavior.js");
  // a fixture server that fails handshake quickly with a known stderr string
  const dir = mkdtempSync(join(tmpdir(), "tc-badserver-"));
  const failing = join(dir, "fail.js");
  writeFileSync(failing, 'process.stderr.write("BOOT_FAIL_MARKER_42");\nprocess.exit(3);\n');
  const rt = new SandboxRuntime({ cmd: process.execPath, args: [failing], spawnTimeout: 3_000 });
  await assert.rejects(rt.start(), /BOOT_FAIL_MARKER_42/);
  rmSync(dir, { recursive: true, force: true });
});

test("D: behavior CLI surfaces bounded child stderr on handshake failure", (t) => {
  const dir = tmpdirFor(t);
  const failing = join(dir, "fail.js");
  writeFileSync(failing, 'process.stderr.write("EXPECTED_STDERR_TOKEN_77");\nprocess.exit(3);\n');
  const mPath = join(dir, "m.json");
  writeFileSync(mPath, JSON.stringify({ server: { cmd: process.execPath, args: [failing] } }));
  const r = run(["behavior", mPath, "--timeout", "3000"]);
  assert.equal(r.code, 1);
  assert.match(r.err + r.out, /EXPECTED_STDERR_TOKEN_77/);
});

// ─── E) scanner calibration ──────────────────────────────────────────────────

test("E: UNKNOWN checks score zero; unauthenticated enumeration is WARN not PASS", async () => {
  const r = await runHealthcheck(fixtureCmd("stable"));
  assert.equal(r.checks.authentication.status, "WARN", "unauthenticated list must not be a green PASS");
  assert.ok(r.checks.authentication.score < 5);
  for (const [name, c] of Object.entries(r.checks)) {
    if (c.status === "UNKNOWN") assert.equal(c.score, 0, `${name} UNKNOWN must earn no credit`);
  }
});

test("E: high-confidence destructive capability FAILs and sinks the score", async () => {
  const dir = mkdtempSync(join(tmpdir(), "tc-danger-"));
  const stateFile = join(dir, "state.json");
  writeFileSync(stateFile, JSON.stringify({
    tools: [
      TOOL_SEARCH,
      { name: "delete_all_files", description: "Delete all files recursively. Permanently removes data without recovery.", inputSchema: { type: "object", properties: { path: { type: "string" } }, required: ["path"] } },
      { name: "execute_shell", description: "Run an arbitrary shell command.", inputSchema: { type: "object", properties: { command: { type: "string" } }, required: ["command"] } },
      { name: "drop_table", description: "Drop a database table, removing all rows.", inputSchema: { type: "object", properties: { table: { type: "string" } }, required: ["table"] } },
    ],
  }));
  try {
    const r = await runHealthcheck(fixtureCmd("mutable", { FAKE_SERVER_STATE_FILE: stateFile }));
    assert.equal(r.checks.destructive.status, "FAIL", `${r.checks.destructive.detail}`);
    assert.equal(r.checks.destructive.score, 0);
    assert.ok(r.score < 60, `score ${r.score} should be materially reduced`);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// ─── I) HTTP fleet gap ───────────────────────────────────────────────────────

test("I: parseHttpGated recognizes only marker-carrying loopback entries", () => {
  const good = {
    url: "http://127.0.0.1:9876/mcp",
    _meta: { [TRUSTCARD_HTTP_GATE_KEY]: { manifest: "m.json", upstream: "https://api.example/mcp" } },
  };
  const g = parseHttpGated("svc", good, "/cfg");
  assert.equal(g.url, "https://api.example/mcp", "discovery must hit upstream, not the proxy");
  assert.equal(g.proxyUrl, "http://127.0.0.1:9876/mcp");
  assert.equal(g.manifest, "m.json");

  // No marker → ungated
  assert.equal(parseHttpGated("svc", { url: "https://api.example/mcp" }, "/cfg"), null);
  // Marker without upstream → ungated
  assert.equal(parseHttpGated("svc", { url: "http://127.0.0.1:9", _meta: { [TRUSTCARD_HTTP_GATE_KEY]: { manifest: "m" } } }, "/cfg"), null);
  // Marker but non-loopback url → ungated (marker is decorative, not trusted)
  assert.equal(parseHttpGated("svc", { url: "https://api.example/mcp", _meta: { [TRUSTCARD_HTTP_GATE_KEY]: { manifest: "m", upstream: "https://api.example/mcp" } } }, "/cfg"), null);
});

test("I: gate --apply writes a manifest and wraps an HTTP entry; renew sees it gated", async (t) => {
  const dir = tmpdirFor(t);
  // A live HTTP MCP fixture: streamable-http POST endpoint answering
  // initialize + tools/list.
  const server = createServer(async (req, res) => {
    const chunks = []; for await (const c of req) chunks.push(c);
    const msg = JSON.parse(Buffer.concat(chunks));
    res.setHeader("content-type", "application/json");
    if (msg.id == null) return res.end();
    const result = msg.method === "initialize"
      ? { protocolVersion: "2025-06-18", serverInfo: { name: "http-svc", version: "1.0" } }
      : { tools: [TOOL_SEARCH] };
    res.end(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result }));
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  t.after(() => { server.closeAllConnections(); server.close(); });
  const upstream = `http://127.0.0.1:${server.address().port}/mcp`;

  const cfgPath = join(dir, "config.json");
  writeFileSync(cfgPath, JSON.stringify({ mcpServers: { svc: { url: upstream, headers: { Authorization: "Bearer ${env:TC_TEST_TOKEN}" } } } }));
  const env = { ...process.env, TC_TEST_TOKEN: "test-token-123" };

  // Preview: writes nothing, exits 0.
  const preview = await runAsync(["gate", "--config", cfgPath], { env });
  assert.equal(preview.code, 0, preview.err);
  assert.equal(readFileSync(cfgPath, "utf8"), JSON.stringify({ mcpServers: { svc: { url: upstream, headers: { Authorization: "Bearer ${env:TC_TEST_TOKEN}" } } } }), "preview must not write the config");
  assert.match(preview.out, /mcp-http-proxy/);

  // Apply: manifest written + entry wrapped. Entry stays "ungated" until the
  // operator also runs the printed proxy — but status/gate machinery sees the
  // loopback marker and treats it as gated for renew/status purposes.
  const applied = await runAsync(["gate", "--config", cfgPath, "--apply"], { env });
  assert.equal(applied.code, 0, applied.err);
  const cfg = JSON.parse(readFileSync(cfgPath, "utf8"));
  const entry = cfg.mcpServers.svc;
  assert.match(entry.url, /^http:\/\/127\.0\.0\.1:\d+/);
  const marker = entry._meta[TRUSTCARD_HTTP_GATE_KEY];
  assert.equal(marker.upstream, upstream);
  assert.ok(existsSync(marker.manifest), "manifest file written");
  const manifest = JSON.parse(readFileSync(marker.manifest, "utf8"));
  assert.equal(manifest.tools.length, 1);
  assert.equal(manifest.tools[0].name, "search");

  // status sees it as gated (http-gated), not UNGATED.
  const st = await runAsync(["status", "--config", cfgPath, "--json"], { env });
  assert.equal(st.code, 0, st.err);
  const stBody = JSON.parse(st.out);
  assert.equal(stBody.gated[0].name, "svc");
  assert.equal(stBody.ungated.length, 0);

  // renew re-attests through the upstream marker (injected list proves the
  // probe path is exercised via renewServer).
  const { gated } = listGated(cfgPath);
  assert.equal(gated[0].url, upstream);
  const r = await renewServer(gated[0], { list: async () => ({ tools: [clone(TOOL_SEARCH)] }) });
  assert.equal(r.ok, true, `renew must succeed against the upstream: ${r.reason}`);
  assert.equal(r.action, "renewed");
});

test("I: gate refuses to write on --apply when discovery fails", (t) => {
  const dir = tmpdirFor(t);
  const cfgPath = join(dir, "config.json");
  writeFileSync(cfgPath, JSON.stringify({ mcpServers: { dead: { url: "http://127.0.0.1:1/mcp" } } }));
  const r = run(["gate", "--config", cfgPath, "--apply"], { timeout: 60_000 });
  assert.equal(r.code, 1);
  assert.equal(existsSync(join(dir, "trustcard-manifests", "dead.manifest.json")), false);
});
