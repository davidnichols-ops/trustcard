// Trust state machine: transitions, re-pin policy, revocation stickiness.
import { test } from "node:test";
import assert from "node:assert/strict";
import { TrustStore, REASONS } from "../lib/trust.js";
import { diffToolsets } from "../lib/diff.js";
import { toolsetDigest, serverDigest, toolDigest } from "../lib/identity.js";
import { TOOL_SEARCH, TOOL_FETCH, clone } from "./helpers.js";

const SID = { name: "fake-server", version: "1.0.0" };

function obs(tools, protocolVersion = "2025-06-18") {
  return {
    tools,
    toolsetDigest: toolsetDigest(tools),
    serverDigest: serverDigest({ serverInfo: SID, protocolVersion, tools }),
    toolDigests: Object.fromEntries(tools.map((t) => [t.name, toolDigest(t)])),
    protocolVersion,
  };
}

test("UNKNOWN → OBSERVED → PINNED lifecycle", () => {
  const events = [];
  const ts = new TrustStore({ onEvent: (e) => events.push(e) });
  assert.equal(ts.get(SID).state, "UNKNOWN");
  ts.observe(SID, obs([TOOL_SEARCH]));
  assert.equal(ts.get(SID).state, "OBSERVED");
  ts.pin(SID, obs([TOOL_SEARCH]));
  assert.equal(ts.get(SID).state, "PINNED");
  assert.deepEqual(events.map((e) => e.reason), [REASONS.FIRST_OBSERVATION, REASONS.PIN_CREATED]);
});

test("identical re-observation → stays PINNED (digest match)", () => {
  const ts = new TrustStore();
  ts.observe(SID, obs([TOOL_SEARCH]));
  ts.pin(SID, obs([TOOL_SEARCH]));
  const fresh = obs([clone(TOOL_SEARCH)]);
  const diff = diffToolsets([TOOL_SEARCH], fresh.tools);
  const r = ts.evaluate(SID, fresh, diff);
  assert.equal(r.action, "ok");
  assert.equal(ts.get(SID).state, "PINNED");
});

test("compatible change (added tool) → auto re-pin, stays PINNED", () => {
  const ts = new TrustStore({ policy: { allowAutoRepin: true } });
  ts.observe(SID, obs([TOOL_SEARCH]));
  ts.pin(SID, obs([TOOL_SEARCH]));
  const bigger = obs([TOOL_SEARCH, TOOL_FETCH]);
  const diff = diffToolsets([TOOL_SEARCH], bigger.tools);
  const r = ts.evaluate(SID, bigger, diff);
  assert.equal(r.action, "repinned");
  assert.equal(ts.get(SID).state, "PINNED");
  assert.equal(ts.get(SID).pin.toolsetDigest, bigger.toolsetDigest);
});

test("breaking change → MISMATCH, and evaluate reports it", () => {
  const ts = new TrustStore();
  ts.observe(SID, obs([TOOL_SEARCH, TOOL_FETCH]));
  ts.pin(SID, obs([TOOL_SEARCH, TOOL_FETCH]));
  const shrunk = obs([TOOL_SEARCH]);
  const diff = diffToolsets([TOOL_SEARCH, TOOL_FETCH], shrunk.tools);
  const r = ts.evaluate(SID, shrunk, diff);
  assert.equal(r.action, "mismatch");
  assert.equal(ts.get(SID).state, "MISMATCH");
  assert.equal(ts.get(SID).history.at(-1).reason, REASONS.BREAKING_CHANGE);
});

test("permission change → MISMATCH with PERMISSION_CHANGE reason", () => {
  const ts = new TrustStore();
  const flipped = clone(TOOL_SEARCH);
  flipped.annotations = { readOnlyHint: false, destructiveHint: true };
  ts.observe(SID, obs([TOOL_SEARCH]));
  ts.pin(SID, obs([TOOL_SEARCH]));
  const diff = diffToolsets([TOOL_SEARCH], [flipped]);
  ts.evaluate(SID, obs([flipped]), diff);
  assert.equal(ts.get(SID).state, "MISMATCH");
  assert.equal(ts.get(SID).history.at(-1).reason, REASONS.PERMISSION_CHANGE);
});

test("REVOKED is terminal: subsequent transitions are refused", () => {
  const ts = new TrustStore();
  ts.observe(SID, obs([TOOL_SEARCH]));
  ts.pin(SID, obs([TOOL_SEARCH]));
  ts.revoke(SID, REASONS.BREAKING_CHANGE, {});
  assert.equal(ts.get(SID).state, "REVOKED");
  // try to move it — refused
  const diff = diffToolsets([TOOL_SEARCH], [TOOL_SEARCH]);
  ts.evaluate(SID, obs([TOOL_SEARCH]), diff);
  assert.equal(ts.get(SID).state, "REVOKED");
  ts.suspect(SID, REASONS.SIGNATURE_MISSING);
  assert.equal(ts.get(SID).state, "REVOKED");
});

test("manual approve() resets even from REVOKED and re-pins", () => {
  const ts = new TrustStore();
  ts.observe(SID, obs([TOOL_SEARCH]));
  ts.pin(SID, obs([TOOL_SEARCH]));
  ts.revoke(SID, REASONS.BREAKING_CHANGE, {});
  ts.approve(SID);
  assert.equal(ts.get(SID).state, "PINNED");
});

test("MISMATCH can be approved back to PINNED (human re-approval)", () => {
  const ts = new TrustStore();
  ts.observe(SID, obs([TOOL_SEARCH, TOOL_FETCH]));
  ts.pin(SID, obs([TOOL_SEARCH, TOOL_FETCH]));
  const diff = diffToolsets([TOOL_SEARCH, TOOL_FETCH], [TOOL_SEARCH]);
  ts.evaluate(SID, obs([TOOL_SEARCH]), diff);
  assert.equal(ts.get(SID).state, "MISMATCH");
  ts.approve(SID);
  assert.equal(ts.get(SID).state, "PINNED");
});

test("policy allowNewTools=false: added tool → MISMATCH not repin", () => {
  const ts = new TrustStore({ policy: { allowNewTools: false } });
  ts.observe(SID, obs([TOOL_SEARCH]));
  ts.pin(SID, obs([TOOL_SEARCH]));
  const diff = diffToolsets([TOOL_SEARCH], [TOOL_SEARCH, TOOL_FETCH]);
  const r = ts.evaluate(SID, obs([TOOL_SEARCH, TOOL_FETCH]), diff);
  assert.equal(r.action, "mismatch");
  assert.equal(ts.get(SID).history.at(-1).reason, REASONS.TOOL_ADDED);
});

test("every transition emits an audit event with from/to/reason", () => {
  const events = [];
  const ts = new TrustStore({ onEvent: (e) => events.push(e) });
  ts.observe(SID, obs([TOOL_SEARCH]));
  ts.pin(SID, obs([TOOL_SEARCH]));
  ts.revoke(SID, REASONS.MANUAL_REVOKE);
  assert.equal(events.length, 3);
  for (const e of events) {
    assert.ok(e.at && e.server && e.from !== undefined && e.to && e.reason);
  }
});
