// Tests for the security model additions: trust level projection, manifest
// expiration, and block explanations. These verify the P0/P1 features added
// in response to the pre-freeze security review.
import { test } from "node:test";
import assert from "node:assert/strict";
import { trustLevel, TRUST_LEVELS } from "../lib/trust.js";
import { buildManifest, checkCall } from "../lib/manifest.js";

// --- Trust level projection ---

test("trustLevel maps all six internal states to four human-facing levels", () => {
  assert.equal(trustLevel("PINNED"), "TRUSTED");
  assert.equal(trustLevel("OBSERVED"), "OBSERVED");
  assert.equal(trustLevel("UNKNOWN"), "OBSERVED");
  assert.equal(trustLevel("SUSPECT"), "OBSERVED");
  assert.equal(trustLevel("MISMATCH"), "UNTRUSTED");
  assert.equal(trustLevel("REVOKED"), "REVOKED");
});

test("trustLevel defaults to OBSERVED for unknown states", () => {
  assert.equal(trustLevel("GARBAGE"), "OBSERVED");
  assert.equal(trustLevel(undefined), "OBSERVED");
  assert.equal(trustLevel(null), "OBSERVED");
});

test("TRUST_LEVELS exports the five level names", () => {
  assert.deepEqual(TRUST_LEVELS, ["TRUSTED", "VERIFIED", "OBSERVED", "UNTRUSTED", "REVOKED"]);
});

// --- Manifest expiration ---

test("proxy manifest includes expiresAt by default (90 days)", () => {
  const tools = [{ name: "read", description: "read a file", inputSchema: { type: "object", properties: {} } }];
  const m = buildManifest(tools);
  assert.ok(m.expiresAt, "expiresAt should be set by default");
  // Should be roughly 90 days from now
  const expiry = Date.parse(m.expiresAt);
  const now = Date.now();
  const days90 = 90 * 24 * 60 * 60 * 1000;
  assert.ok(expiry > now + days90 - 60_000, "expiry should be ~90 days in the future");
  assert.ok(expiry < now + days90 + 60_000, "expiry should be ~90 days in the future");
});

test("proxy manifest accepts custom expiry via expiresInDays", () => {
  const tools = [{ name: "read", description: "read", inputSchema: { type: "object" } }];
  const m = buildManifest(tools, null, null, null, 7);
  assert.ok(m.expiresAt);
  const expiry = Date.parse(m.expiresAt);
  const now = Date.now();
  const days7 = 7 * 24 * 60 * 60 * 1000;
  assert.ok(expiry > now + days7 - 60_000, "expiry should be ~7 days in the future");
  assert.ok(expiry < now + days7 + 60_000, "expiry should be ~7 days in the future");
});

test("proxy manifest supports no-expiry with expiresInDays=null", () => {
  const tools = [{ name: "read", description: "read", inputSchema: { type: "object" } }];
  const m = buildManifest(tools, null, null, null, null);
  assert.equal(m.expiresAt, null);
});

test("checkCall blocks all calls when manifest is expired", () => {
  const tools = [{ name: "read", description: "read", inputSchema: { type: "object" } }];
  // Create a manifest that's already expired
  const m = buildManifest(tools, null, null, null, -1);
  assert.ok(Date.parse(m.expiresAt) < Date.now(), "manifest should be expired");
  const result = checkCall(m, "read");
  assert.equal(result.allowed, false);
  assert.match(result.reason, /manifest expired/);
});

test("checkCall allows calls when manifest is not expired", () => {
  const tools = [{ name: "read", description: "read", inputSchema: { type: "object" } }];
  const m = buildManifest(tools, null, null, null, 90);
  const result = checkCall(m, "read");
  assert.equal(result.allowed, true);
});

test("checkCall on manifest with no expiresAt still works (backward compat)", () => {
  const tools = [{ name: "read", description: "read", inputSchema: { type: "object" } }];
  const m = buildManifest(tools, null, null, null, null);
  // Manually remove expiresAt to simulate an old manifest
  delete m.expiresAt;
  const result = checkCall(m, "read");
  assert.equal(result.allowed, true);
});

// --- Block explanation structure ---

test("expired manifest denial reason includes regeneration hint", () => {
  const tools = [{ name: "read", description: "read", inputSchema: { type: "object" } }];
  const m = buildManifest(tools, null, null, null, -1);
  const result = checkCall(m, "read");
  assert.equal(result.allowed, false);
  assert.match(result.reason, /gen-manifest/);
});

test("dangerous tool denial includes score and confidence", () => {
  const tools = [{
    name: "delete_file",
    description: "delete a file from the filesystem permanently",
    inputSchema: { type: "object", properties: { path: { type: "string" } } },
  }];
  const m = buildManifest(tools);
  const entry = m.tools.find((t) => t.name === "delete_file");
  assert.equal(entry.allowed, false, "delete_file should be flagged as dangerous");
  const result = checkCall(m, "delete_file");
  assert.equal(result.allowed, false);
  assert.match(result.reason, /dangerous/);
  assert.match(result.reason, /score=/);
});
