// Guard: the enforcement gate. Unit-tested with a stub session (no network).
import { test } from "node:test";
import assert from "node:assert/strict";
import { Guard, GuardDenial, validateArgs } from "../lib/guard.js";
import { TrustStore } from "../lib/trust.js";
import { toolsetDigest, serverDigest, toolDigest } from "../lib/identity.js";
import { TOOL_SEARCH, TOOL_FETCH, clone } from "./helpers.js";

const SID = { name: "fake-server", version: "1.0.0" };

function makeSession(tools, { pinned = true } = {}) {
  const trust = new TrustStore();
  const observation = {
    tools,
    toolsetDigest: toolsetDigest(tools),
    serverDigest: serverDigest({ serverInfo: SID, protocolVersion: "2025-06-18", tools }),
    toolDigests: Object.fromEntries(tools.map((t) => [t.name, toolDigest(t)])),
    protocolVersion: "2025-06-18",
  };
  trust.observe(SID, observation);
  if (pinned) trust.pin(SID, observation);
  return { serverId: SID, trust, observation };
}

const DESTRUCTIVE_TOOL = {
  name: "delete_all",
  description: "Delete all documents permanently.",
  inputSchema: { type: "object", properties: {} },
  annotations: { readOnlyHint: false, destructiveHint: true },
};

test("allows a read-only call on a pinned server", async () => {
  const guard = new Guard({ mode: "enforce" });
  const session = makeSession([TOOL_SEARCH]);
  const ok = await guard.authorizeCall({ session, tool: "search", args: { query: "x" } });
  assert.equal(ok, true);
});

test("denies when server is not pinned (requirePinned default)", async () => {
  const guard = new Guard({ mode: "enforce" });
  const session = makeSession([TOOL_SEARCH], { pinned: false });
  await assert.rejects(() => guard.authorizeCall({ session, tool: "search", args: {} }), (e) => {
    assert.ok(e instanceof GuardDenial);
    assert.equal(e.reason, "server-not-pinned");
    return true;
  });
});

test("denies a revoked server, always", async () => {
  const guard = new Guard({ mode: "enforce" });
  const session = makeSession([TOOL_SEARCH]);
  session.trust.revoke(SID, "BREAKING_CHANGE");
  await assert.rejects(() => guard.authorizeCall({ session, tool: "search", args: {} }), /server-revoked/);
});

test("denies unknown tools (not in the verified toolset)", async () => {
  const guard = new Guard({ mode: "enforce" });
  const session = makeSession([TOOL_SEARCH]);
  await assert.rejects(() => guard.authorizeCall({ session, tool: "evil_tool", args: {} }), /unknown-tool/);
});

test("denies destructive tools unless policy allows", async () => {
  const guard = new Guard({ mode: "enforce" });
  const session = makeSession([TOOL_SEARCH, DESTRUCTIVE_TOOL]);
  await assert.rejects(() => guard.authorizeCall({ session, tool: "delete_all", args: {} }), /destructive-tool/);
  const permissive = new Guard({ mode: "enforce", policy: { allowDestructive: true } });
  const ok = await permissive.authorizeCall({ session, tool: "delete_all", args: {} });
  assert.equal(ok, true);
});

test("audit mode allows but emits an event", async () => {
  const events = [];
  const guard = new Guard({ mode: "audit", onEvent: (e) => events.push(e) });
  const session = makeSession([TOOL_SEARCH, DESTRUCTIVE_TOOL]);
  const ok = await guard.authorizeCall({ session, tool: "delete_all", args: {} });
  assert.equal(ok, false); // decision was "deny"...
  assert.equal(events.at(-1).type, "guard-deny"); // ...but no throw in audit mode
});

test("allowlist restricts to named tools", async () => {
  const guard = new Guard({ mode: "enforce", policy: { allowedTools: ["search"] } });
  const session = makeSession([TOOL_SEARCH, TOOL_FETCH]);
  await guard.authorizeCall({ session, tool: "search", args: { query: "x" } });
  await assert.rejects(() => guard.authorizeCall({ session, tool: "fetch_document", args: { id: "1" } }), /tool-not-allowlisted/);
});

test("strict mode validates args against pinned inputSchema", async () => {
  const guard = new Guard({ mode: "enforce" });
  const session = makeSession([TOOL_SEARCH]);
  // missing required "query"
  await assert.rejects(
    () => guard.authorizeCall({ session, tool: "search", args: {}, strict: true }),
    /args-violate-schema/
  );
  // limit above maximum
  await assert.rejects(
    () => guard.authorizeCall({ session, tool: "search", args: { query: "x", limit: 500 }, strict: true }),
    /args-violate-schema/
  );
  // valid
  const ok = await guard.authorizeCall({ session, tool: "search", args: { query: "x", limit: 5 }, strict: true });
  assert.equal(ok, true);
});

test("receipt binds toolset digest + args digest to result digest", () => {
  const receipts = [];
  const guard = new Guard({ receiptSink: (r) => receipts.push(r) });
  const session = makeSession([TOOL_SEARCH]);
  guard.recordReceipt({ session, tool: "search", args: { query: "x" }, result: { content: [] } });
  assert.equal(receipts.length, 1);
  const r = receipts[0];
  assert.equal(r.toolsetDigest, session.observation.toolsetDigest);
  assert.equal(r.toolDigest, session.observation.toolDigests.search);
  assert.match(r.argumentsDigest, /^sha256:/);
  assert.match(r.resultDigest, /^sha256:/);
});

// --- validateArgs unit coverage ---
test("validateArgs: required, types, enum, additionalProperties, nested", () => {
  const schema = {
    type: "object",
    properties: {
      name: { type: "string", minLength: 2 },
      age: { type: "integer", minimum: 0 },
      role: { enum: ["a", "b"] },
      addr: { type: "object", properties: { zip: { type: "string" } }, required: ["zip"] },
    },
    required: ["name"],
    additionalProperties: false,
  };
  assert.equal(validateArgs(schema, { name: "ab", age: 3, role: "a", addr: { zip: "1" } }), null);
  assert.match(validateArgs(schema, {}), /missing required/);
  assert.match(validateArgs(schema, { name: "ab", extra: 1 }), /unexpected property/);
  assert.match(validateArgs(schema, { name: "a" }), /minLength/);
  assert.match(validateArgs(schema, { name: "ab", age: -1 }), /minimum/);
  assert.match(validateArgs(schema, { name: "ab", role: "c" }), /enum/);
  assert.match(validateArgs(schema, { name: "ab", addr: {} }), /missing required/);
});
