import { test } from "node:test";
import assert from "node:assert/strict";
import { changeVector, isVectorCompatible, AXIS_LEVEL } from "../lib/change.js";

const TOOL = {
  name: "search",
  description: "Find things",
  inputSchema: { type: "object", properties: { q: { type: "string" } }, required: ["q"] },
  annotations: { readOnlyHint: true },
};
const IMPL_A = { kind: "npm-dist", integrity: "sha512-AAAA" };
const IMPL_B = { kind: "npm-dist", integrity: "sha512-BBBB" };

test("THE case v1 cannot represent: I_id unchanged, M_id changed", () => {
  const cv = changeVector(
    { tools: [TOOL], implementation: IMPL_A, publisherKeyId: "k1" },
    { tools: [TOOL], implementation: IMPL_B, publisherKeyId: "k1" }
  );
  assert.equal(cv.vector.interface, "NONE"); // v1 would report "no change"
  assert.equal(cv.vector.implementation, "REPLACED"); // the substrate catches it
  assert.equal(cv.compatible, false); // must NOT be auto-accepted
});

test("identical everything → no change, compatible", () => {
  const cv = changeVector(
    { tools: [TOOL], implementation: IMPL_A, publisherKeyId: "k1" },
    { tools: [TOOL], implementation: IMPL_A, publisherKeyId: "k1" }
  );
  assert.deepEqual(cv.vector, { interface: "NONE", permission: "NONE", implementation: "NONE", provenance: "NONE" });
  assert.equal(cv.compatible, true);
});

test("permission expansion is not auto-acceptable", () => {
  const dangerous = [{ ...TOOL, annotations: { readOnlyHint: false, destructiveHint: true } }];
  const cv = changeVector({ tools: [TOOL] }, { tools: dangerous });
  assert.equal(cv.vector.permission, "EXPANSION");
  assert.equal(cv.compatible, false);
});

test("permission reduction (added safety hint) is auto-acceptable", () => {
  const dangerous = [{ ...TOOL, annotations: { readOnlyHint: false, destructiveHint: true } }];
  const cv = changeVector({ tools: dangerous }, { tools: [TOOL] });
  assert.equal(cv.vector.permission, "REDUCTION");
  // the interface axis must not double-count a pure permission move as breaking
  assert.equal(cv.vector.interface, "NONE");
  assert.equal(cv.compatible, true);
});

test("schema narrowing is still interface-BREAKING regardless of permission axis", () => {
  const narrowed = [{ ...TOOL, inputSchema: { type: "object", properties: { q: { type: "integer" } }, required: ["q", "x"] } }];
  const cv = changeVector({ tools: [TOOL] }, { tools: narrowed });
  assert.equal(cv.vector.interface, "BREAKING");
  assert.equal(cv.compatible, false);
});

test("provenance key rotation requires re-approval", () => {
  const cv = changeVector(
    { tools: [TOOL], publisherKeyId: "k1" },
    { tools: [TOOL], publisherKeyId: "k2" }
  );
  assert.equal(cv.vector.provenance, "KEY_ROTATION");
  assert.equal(cv.compatible, false);
});

test("unresolved implementation on both sides is not a change", () => {
  const cv = changeVector({ tools: [TOOL], implementation: null }, { tools: [TOOL], implementation: null });
  assert.equal(cv.vector.implementation, "NONE");
  assert.equal(cv.compatible, true);
});

test("isVectorCompatible: only all-safe vectors pass", () => {
  assert.equal(isVectorCompatible({ interface: "NONE", permission: "NONE", implementation: "NONE", provenance: "NONE" }), true);
  assert.equal(isVectorCompatible({ interface: "NON_BREAKING", permission: "REDUCTION", implementation: "NONE", provenance: "NONE" }), true);
  assert.equal(isVectorCompatible({ interface: "NONE", permission: "NONE", implementation: "REPLACED", provenance: "NONE" }), false);
  assert.equal(isVectorCompatible({ interface: "NONE", permission: "EXPANSION", implementation: "NONE", provenance: "NONE" }), false);
});

test("axis levels are strictly ordered", () => {
  assert.ok(AXIS_LEVEL.interface.BREAKING > AXIS_LEVEL.interface.NON_BREAKING);
  assert.ok(AXIS_LEVEL.implementation.REPLACED > AXIS_LEVEL.implementation.NONE);
  assert.ok(AXIS_LEVEL.provenance.PUBLISHER_CHANGE > AXIS_LEVEL.provenance.KEY_ROTATION);
});
