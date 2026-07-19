// Audit probes for descriptor identity (§6) and gate separation (§2).
// These pin the *classification* of MCP-specific changes so the release report
// can state precisely which changes are informational / authorization-relevant /
// trust-breaking.
import { test } from "node:test";
import assert from "node:assert/strict";
import { changeVector } from "../lib/change.js";
import { TOOL_SEARCH } from "./helpers.js";

const clone = (v) => JSON.parse(JSON.stringify(v));
const mk = (tools, impl = null, pub = "k1") => ({ tools, implementation: impl ?? { kind: "unresolved" }, publisherKeyId: pub });

test("description rewrite (same schema) → ANNOTATION_DOWNGRADE, incompatible", () => {
  const desc = clone(TOOL_SEARCH);
  desc.description = "Entirely different prose that rewrites what the tool is for, in full.";
  const v = changeVector(mk([TOOL_SEARCH]), mk([desc]));
  assert.equal(v.vector.interface, "ANNOTATION_DOWNGRADE");
  assert.equal(v.compatible, false, "a description rewrite changes agent behavior — not auto-compatible");
});

test("permission expansion (readOnly→destructive) → PERMISSION axis EXPANSION", () => {
  const perm = clone(TOOL_SEARCH);
  perm.annotations = { readOnlyHint: false, destructiveHint: true, openWorldHint: true };
  const v = changeVector(mk([TOOL_SEARCH]), mk([perm]));
  assert.equal(v.vector.permission, "EXPANSION");
  assert.equal(v.compatible, false);
});

test("implementation swap with identical interface → implementation REPLACED", () => {
  const a = { kind: "npm-dist", integrity: "sha512-A", algorithm: "sha512" };
  const b = { kind: "npm-dist", integrity: "sha512-B", algorithm: "sha512" };
  const v = changeVector(mk([TOOL_SEARCH], a), mk([TOOL_SEARCH], b));
  assert.equal(v.vector.interface, "NONE");
  assert.equal(v.vector.implementation, "REPLACED");
  assert.equal(v.compatible, false, "same interface + swapped artifact is NOT compatible");
});

test("publisher key change (same tools, same impl) → provenance movement, incompatible", () => {
  // old key + new key present = KEY_ROTATION (the publisher rotated its key)
  const rot = changeVector(mk([TOOL_SEARCH], null, "k1"), mk([TOOL_SEARCH], null, "k2"));
  assert.equal(rot.vector.provenance, "KEY_ROTATION");
  assert.equal(rot.compatible, false, "any provenance movement requires re-approval");
  // key removed entirely = PUBLISHER_CHANGE (lost provenance)
  const gone = changeVector(mk([TOOL_SEARCH], null, "k1"), mk([TOOL_SEARCH], null, null));
  assert.equal(gone.vector.provenance, "PUBLISHER_CHANGE");
  assert.equal(gone.compatible, false);
});

test("tool rename → interface change (name is in the projection)", () => {
  const renamed = clone(TOOL_SEARCH);
  renamed.name = "search_v2";
  const v = changeVector(mk([TOOL_SEARCH]), mk([renamed]));
  assert.notEqual(v.vector.interface, "NONE");
  assert.equal(v.compatible, false, "renaming a tool is a contract change, not cosmetic");
});

test("pure no-op (identical everything) → all NONE, compatible", () => {
  const v = changeVector(mk([TOOL_SEARCH]), mk([clone(TOOL_SEARCH)]));
  assert.deepEqual(v.vector, { interface: "NONE", permission: "NONE", implementation: "NONE", provenance: "NONE" });
  assert.equal(v.compatible, true);
});
