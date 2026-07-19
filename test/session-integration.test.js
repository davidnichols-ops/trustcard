// v2 integration: the descriptor core + change vector running on the LIVE
// session/guard path (not just unit tests of the modules).
import { test } from "node:test";
import assert from "node:assert/strict";
import { writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { TrustSession } from "../lib/session.js";
import { TrustStore } from "../lib/trust.js";
import { Guard, GuardDenial, GuardApprovalRequired } from "../lib/guard.js";
import { InvocationPolicy, requireApprovalForDestructive } from "../lib/policy.js";
import { buildDescriptor, signDescriptor, verifyDescriptor } from "../lib/descriptor.js";
import { interfaceDigest, implementationIdentity } from "../lib/descriptor.js";
import { generatePublisherKeypair } from "../lib/provenance.js";
import { fixtureCmd } from "./helpers.js";
import { TOOL_SEARCH, TOOL_FETCH, clone } from "./helpers.js";

async function connect(scenario, opts = {}) {
  const { cmd, args, env } = fixtureCmd(scenario, opts.extraEnv ?? {});
  const session = new TrustSession({ cmd, args, env, trust: opts.trust ?? new TrustStore(), guard: opts.guard, protocolVersions: ["2025-06-18", "2024-11-05"], implementation: opts.implementation ?? null, publisherKeyId: opts.publisherKeyId ?? null });
  await session.connect();
  return session;
}

test("live refresh emits a change vector (interface axis) on a breaking mutation", async () => {
  const dir = mkdtempSync(join(tmpdir(), "trustcard-"));
  const stateFile = join(dir, "state.json");
  writeFileSync(stateFile, JSON.stringify({ tools: [TOOL_SEARCH, TOOL_FETCH] }));
  const trust = new TrustStore();
  const s = await connect("mutable", { trust, extraEnv: { FAKE_SERVER_STATE_FILE: stateFile } });
  try {
    trust.pin(s.serverId, s.observation);
    const breaking = [clone(TOOL_SEARCH)];
    breaking[0].inputSchema.required = ["query", "tenant"];
    breaking[0].inputSchema.properties.tenant = { type: "string" };
    writeFileSync(stateFile, JSON.stringify({ tools: breaking }));
    const { diff, vector } = await s.refresh("test");
    assert.equal(diff.overall, "BREAKING");
    // the change vector now rides along on the live path
    assert.ok(vector, "refresh should return a change vector");
    assert.equal(vector.vector.interface, "BREAKING");
    assert.equal(vector.compatible, false);
  } finally { await s.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("a descriptor built from the LIVE observed toolset verifies + pins by content address", async () => {
  const keys = generatePublisherKeypair();
  const s = await connect("stable", {});
  try {
    const tool = s.observation.tools.find((t) => t.name === "search");
    const impl = implementationIdentity({ kind: "npm-dist", integrity: "sha512-AAAABBBBCCCC" });
    const descriptor = signDescriptor(buildDescriptor({ tool, implementation: impl, publisher: { publisher: "acme", keyId: keys.keyId, publicKey: keys.publicKey } }), keys.privateKey);
    // round-trips and verifies
    assert.equal(verifyDescriptor(descriptor).ok, true);
    // the observed capability identity matches what the descriptor commits to
    assert.equal(descriptor.capability.interfaceDigest, interfaceDigest(tool));
    assert.equal(descriptor.implementation.kind, "npm-dist");
  } finally { await s.close(); }
});

test("Gate 2 end-to-end: trusted tool, unauthorized invocation denied on a live session", async () => {
  // The server is trusted and PINNED. But the invocation policy requires approval
  // for destructive calls, and the live flip to destructive is gated.
  const dir = mkdtempSync(join(tmpdir(), "trustcard-"));
  const stateFile = join(dir, "state.json");
  writeFileSync(stateFile, JSON.stringify({ tools: [TOOL_SEARCH] }));
  const trust = new TrustStore();
  const policy = new InvocationPolicy({ rules: [requireApprovalForDestructive()] });
  // allow destructive at Gate 1 so ONLY Gate 2 is exercised
  const guard = new Guard({ mode: "enforce", policy: { allowDestructive: true }, invocationPolicy: policy, relyingParty: "agent-a", environment: "prod" });
  const s = await connect("mutable", { trust, guard, extraEnv: { FAKE_SERVER_STATE_FILE: stateFile } });
  try {
    trust.pin(s.serverId, s.observation);
    // read-only search is fine through both gates
    const ok = await s.call("search", { query: "x" });
    assert.equal(ok.content[0].text, "ok:search");
    // flip search to destructive; Gate 1 still allows (allowDestructive), Gate 2 gates it
    const flipped = [clone(TOOL_SEARCH)];
    flipped[0].annotations = { readOnlyHint: false, destructiveHint: true };
    writeFileSync(stateFile, JSON.stringify({ tools: flipped, notify: true, notifyToken: "g2" }));
    const deadline = Date.now() + 3000;
    while (trust.get(s.serverId).state === "PINNED" && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 30));
    }
    // permission change (expansion) revokes at Gate 1 — re-approve so the tool is
    // trusted again, then Gate 2 is the ONLY thing gating the invocation
    if (trust.get(s.serverId).state === "REVOKED") {
      trust.approve(s.serverId);
    }
    // destructive invocation is gated by Gate 2 (require-approval), distinct from Gate-1 deny
    await assert.rejects(() => s.call("search", { query: "x" }), (e) => e instanceof GuardApprovalRequired || e instanceof GuardDenial);
  } finally { await s.close(); rmSync(dir, { recursive: true, force: true }); }
});

test("Gate 2 arg constraint bound to the live descriptor identity", async () => {
  // A confused-deputy style constraint: the read-only fetch tool may not receive
  // an out-of-scope identifier. Keyed on the capability's descriptor identity.
  const { InvocationPolicy, constrainArg } = await import("../lib/policy.js");
  const trust = new TrustStore();
  const policy = new InvocationPolicy({ rules: [constrainArg("fetch_document", "id", (id) => /^doc-\d+$/.test(id))] });
  const guard = new Guard({ mode: "enforce", invocationPolicy: policy, relyingParty: "agent-a", environment: "prod" });
  const s = await connect("stable", { trust, guard });
  try {
    trust.pin(s.serverId, s.observation);
    // in-scope id allowed
    assert.equal((await s.call("fetch_document", { id: "doc-42" })).content[0].text, "ok:fetch_document");
    // out-of-scope id denied at Gate 2 (the tool is trusted; the invocation is not)
    await assert.rejects(() => s.call("fetch_document", { id: "../../etc/passwd" }), /arg-out-of-policy-scope/);
  } finally { await s.close(); }
});
