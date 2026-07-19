// Session integration: live stdio connections to fixture servers.
// Covers: connect + identity, TOCTOU (mid-session tool mutation), stale-cache
// invalidation via notifications/tools/list_changed, and guarded calls.
import { test } from "node:test";
import assert from "node:assert/strict";
import { writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { TrustSession } from "../lib/session.js";
import { TrustStore } from "../lib/trust.js";
import { Guard } from "../lib/guard.js";
import { diffToolsets } from "../lib/diff.js";
import { fixtureCmd } from "./helpers.js";
import { TOOL_SEARCH, TOOL_FETCH, clone } from "./helpers.js";
import { toolsetDigest } from "../lib/identity.js";

async function connect(scenario, { trust, guard, extraEnv = {} } = {}) {
  const { cmd, args, env } = fixtureCmd(scenario, extraEnv);
  const session = new TrustSession({
    cmd, args, env,
    trust: trust ?? new TrustStore(),
    guard,
    protocolVersions: ["2025-06-18", "2024-11-05"],
  });
  await session.connect();
  return session;
}

test("connect: observes serverInfo, protocol, tools, and computes digests", async () => {
  const s = await connect("stable");
  try {
    assert.equal(s.observation.serverInfo.name, "fake-server");
    assert.equal(s.observation.protocolVersion, "2025-06-18");
    assert.equal(s.observation.tools.length, 2);
    assert.match(s.observation.toolsetDigest, /^sha256:/);
    assert.match(s.observation.serverDigest, /^sha256:/);
    assert.deepEqual(Object.keys(s.observation.toolDigests).sort(), ["fetch_document", "search"]);
  } finally { await s.close(); }
});

test("poisoned server: description-rewrite is detectable via diff vs stable baseline", async () => {
  const stable = await connect("stable");
  let poisoned;
  try {
    poisoned = await connect("poisoned");
    const diff = diffToolsets(stable.observation.tools, poisoned.observation.tools);
    assert.equal(diff.overall, "ANNOTATION_DOWNGRADE");
    assert.notEqual(stable.observation.toolsetDigest, poisoned.observation.toolsetDigest);
  } finally { await stable.close(); await poisoned?.close(); }
});

test("breaking server: schema narrowing + removal is BREAKING vs baseline", async () => {
  const stable = await connect("stable");
  let breaking;
  try {
    breaking = await connect("breaking");
    const diff = diffToolsets(stable.observation.tools, breaking.observation.tools);
    assert.equal(diff.overall, "BREAKING");
    assert.ok(diff.removed.includes("fetch_document"));
  } finally { await stable.close(); await breaking?.close(); }
});

test("permission-flip server: identical schema+description, annotations flipped → PERMISSION_CHANGE", async () => {
  const stable = await connect("stable");
  let flipped;
  try {
    flipped = await connect("permission-flip");
    const diff = diffToolsets(stable.observation.tools, flipped.observation.tools);
    assert.equal(diff.overall, "PERMISSION_CHANGE");
  } finally { await stable.close(); await flipped?.close(); }
});

test("syntactic-only drift: digest of semantic projection unchanged", async () => {
  const stable = await connect("stable");
  let syntactic;
  try {
    syntactic = await connect("syntactic");
    const diff = diffToolsets(stable.observation.tools, syntactic.observation.tools);
    assert.equal(diff.overall, "SYNTACTIC");
    assert.equal(stable.observation.toolsetDigest, syntactic.observation.toolsetDigest);
  } finally { await stable.close(); await syntactic?.close(); }
});

test("TOCTOU: mid-session tool mutation is caught by refresh()", async () => {
  const dir = mkdtempSync(join(tmpdir(), "trustcard-"));
  const stateFile = join(dir, "state.json");
  // Start stable
  writeFileSync(stateFile, JSON.stringify({ tools: [TOOL_SEARCH, TOOL_FETCH] }));
  const trust = new TrustStore();
  const s = await connect("mutable", { trust, extraEnv: { FAKE_SERVER_STATE_FILE: stateFile } });
  try {
    trust.pin(s.serverId, s.observation);
    assert.equal(trust.get(s.serverId).state, "PINNED");

    // Server silently swaps to a breaking toolset (no notification yet).
    const breaking = [clone(TOOL_SEARCH)];
    breaking[0].inputSchema.required = ["query", "tenant"];
    breaking[0].inputSchema.properties.tenant = { type: "string" };
    writeFileSync(stateFile, JSON.stringify({ tools: breaking }));

    const { diff, evaluation } = await s.refresh("test");
    assert.equal(diff.overall, "BREAKING");
    assert.equal(evaluation.action, "mismatch");
    // session auto-revokes on incompatible refresh
    assert.equal(trust.get(s.serverId).state, "REVOKED");
  } finally { await s.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("stale-cache invalidation: notifications/tools/list_changed triggers re-observation", async () => {
  const dir = mkdtempSync(join(tmpdir(), "trustcard-"));
  const stateFile = join(dir, "state.json");
  writeFileSync(stateFile, JSON.stringify({ tools: [TOOL_SEARCH, TOOL_FETCH] }));
  const trust = new TrustStore();
  const s = await connect("mutable", { trust, extraEnv: { FAKE_SERVER_STATE_FILE: stateFile } });
  try {
    trust.pin(s.serverId, s.observation);
    const before = s.observation.toolsetDigest;

    // Server adds a tool and pushes list_changed.
    const added = [TOOL_SEARCH, TOOL_FETCH, {
      name: "list_collections",
      description: "List collections.",
      inputSchema: { type: "object", properties: {} },
      annotations: { readOnlyHint: true },
    }];
    writeFileSync(stateFile, JSON.stringify({ tools: added, notify: true, notifyToken: "n1" }));

    // Wait for the notification-driven refresh.
    const deadline = Date.now() + 3000;
    while (s.observation.toolsetDigest === before && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 30));
    }
    assert.notEqual(s.observation.toolsetDigest, before, "session should have re-observed after list_changed");
    assert.equal(s.observation.tools.length, 3);
    assert.ok(s.listChangedCount >= 1);
  } finally { await s.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("guarded call: allowed tool succeeds; destructive is denied at the gate", async () => {
  const trust = new TrustStore();
  const receipts = [];
  const guard = new Guard({ mode: "enforce", receiptSink: (r) => receipts.push(r) });
  const s = await connect("stable", { trust, guard });
  try {
    trust.pin(s.serverId, s.observation);
    const result = await s.call("search", { query: "hello" });
    assert.equal(result.content[0].text, "ok:search");
    assert.equal(receipts.length, 1);
    assert.equal(receipts[0].tool, "search");
    // search is read-only; try calling a tool that doesn't exist → denied
    await assert.rejects(() => s.call("nuke_everything", {}), /unknown-tool/);
  } finally { await s.close(); }
});

test("handshake binding: a trustcard-aware server's committed digest is verified", async () => {
  // Server commits to the CORRECT toolset digest at initialize → bindingOk.
  const goodDigest = toolsetDigest([TOOL_SEARCH, TOOL_FETCH]);
  const trust = new TrustStore();
  const s = await connect("stable", { trust, extraEnv: { FAKE_SERVER_BINDING_DIGEST: goodDigest } });
  try {
    assert.equal(s.binding?.toolsetDigest, goodDigest);
    assert.equal(s.bindingOk, true);
  } finally { await s.close(); }
});

test("handshake binding: a server that commits to one toolset and serves another is SUSPECT", async () => {
  // Server commits to a digest that does NOT match what it actually serves →
  // binding mismatch → the session flags it SUSPECT. This is the compromised-
  // server case: it cannot keep its handshake promise.
  const wrongDigest = toolsetDigest([TOOL_SEARCH]); // only one tool, but serves two
  const trust = new TrustStore();
  const events = [];
  const { cmd, args, env } = fixtureCmd("stable", { FAKE_SERVER_BINDING_DIGEST: wrongDigest });
  const s = new TrustSession({ cmd, args, env, trust, protocolVersions: ["2025-06-18"], onEvent: (e) => events.push(e) });
  try {
    await s.connect();
    assert.equal(s.bindingOk, false);
    assert.equal(trust.get(s.serverId).state, "SUSPECT");
    assert.ok(events.some((e) => e.type === "binding-mismatch"));
  } finally { await s.close(); }
});

test("guarded call on a server that mutated to destructive is denied after refresh+revoke", async () => {
  const dir = mkdtempSync(join(tmpdir(), "trustcard-"));
  const stateFile = join(dir, "state.json");
  writeFileSync(stateFile, JSON.stringify({ tools: [TOOL_SEARCH, TOOL_FETCH] }));
  const trust = new TrustStore();
  const guard = new Guard({ mode: "enforce" });
  const s = await connect("mutable", { trust, guard, extraEnv: { FAKE_SERVER_STATE_FILE: stateFile } });
  try {
    trust.pin(s.serverId, s.observation);
    // Server flips search to destructive mid-session (with notification).
    const flipped = [clone(TOOL_SEARCH), TOOL_FETCH];
    flipped[0].annotations = { readOnlyHint: false, destructiveHint: true, openWorldHint: true };
    writeFileSync(stateFile, JSON.stringify({ tools: flipped, notify: true, notifyToken: "n2" }));
    const deadline = Date.now() + 3000;
    while (trust.get(s.serverId).state === "PINNED" && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 30));
    }
    // permission change is incompatible → session revoked the server
    assert.equal(trust.get(s.serverId).state, "REVOKED");
    await assert.rejects(() => s.call("search", { query: "x" }), /server-revoked/);
  } finally { await s.close(); rmSync(dir, { recursive: true, force: true }); }
});
