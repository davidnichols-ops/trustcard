// Diff classification: the core contract. Every rule in the breaking-change
// taxonomy gets a positive and negative test.
import { test } from "node:test";
import assert from "node:assert/strict";
import { diffToolsets, CHANGE_LEVEL, isCompatible } from "../lib/diff.js";
import { TOOL_SEARCH, TOOL_FETCH, clone } from "./helpers.js";

const set = (...tools) => tools;

test("identical toolsets → NONE, compatible", () => {
  const d = diffToolsets(set(TOOL_SEARCH, TOOL_FETCH), set(clone(TOOL_SEARCH), clone(TOOL_FETCH)));
  assert.equal(d.overall, "NONE");
  assert.ok(d.syntacticOnly);
  assert.ok(isCompatible(d));
});

test("cosmetic-only change (title/_meta) → SYNTACTIC, compatible", () => {
  const pretty = { ...clone(TOOL_SEARCH), title: "Search", _meta: { "com.example/x": 1 } };
  const d = diffToolsets(set(TOOL_SEARCH), set(pretty));
  assert.equal(d.overall, "SYNTACTIC");
  assert.ok(d.syntacticOnly);
  assert.ok(isCompatible(d));
  assert.equal(d.toolDiffs[0].findings[0].kind, "volatile-fields");
});

test("tool removed → BREAKING, not compatible", () => {
  const d = diffToolsets(set(TOOL_SEARCH, TOOL_FETCH), set(TOOL_SEARCH));
  assert.equal(d.overall, "BREAKING");
  assert.deepEqual(d.removed, ["fetch_document"]);
  assert.ok(!isCompatible(d));
});

test("tool added → NON_BREAKING, compatible", () => {
  const d = diffToolsets(set(TOOL_SEARCH), set(TOOL_SEARCH, TOOL_FETCH));
  assert.equal(d.overall, "NON_BREAKING");
  assert.deepEqual(d.added, ["fetch_document"]);
  assert.ok(isCompatible(d));
});

test("new required input param → BREAKING", () => {
  const t = clone(TOOL_SEARCH);
  t.inputSchema.properties.tenant = { type: "string" };
  t.inputSchema.required = ["query", "tenant"];
  const d = diffToolsets(set(TOOL_SEARCH), set(t));
  assert.equal(d.overall, "BREAKING");
  assert.ok(d.toolDiffs[0].findings.some((f) => f.kind === "required-added"));
  assert.ok(!isCompatible(d));
});

test("new optional input param → NON_BREAKING", () => {
  const t = clone(TOOL_SEARCH);
  t.inputSchema.properties.lang = { type: "string" };
  const d = diffToolsets(set(TOOL_SEARCH), set(t));
  assert.equal(d.overall, "NON_BREAKING");
  assert.ok(d.toolDiffs[0].findings.some((f) => f.kind === "property-added"));
  assert.ok(isCompatible(d));
});

test("enum shrink → BREAKING; enum growth → NON_BREAKING", () => {
  const withEnum = clone(TOOL_SEARCH);
  withEnum.inputSchema.properties.mode = { type: "string", enum: ["a", "b", "c"] };
  const shrunk = clone(withEnum);
  shrunk.inputSchema.properties.mode.enum = ["a", "b"];
  const grown = clone(withEnum);
  grown.inputSchema.properties.mode.enum = ["a", "b", "c", "d"];
  assert.equal(diffToolsets(set(withEnum), set(shrunk)).overall, "BREAKING");
  assert.equal(diffToolsets(set(withEnum), set(grown)).overall, "NON_BREAKING");
});

test("constraint tightened → BREAKING; relaxed → NON_BREAKING", () => {
  const tighter = clone(TOOL_SEARCH);
  tighter.inputSchema.properties.limit.maximum = 10; // 100 → 10
  const looser = clone(TOOL_SEARCH);
  looser.inputSchema.properties.limit.maximum = 1000; // 100 → 1000
  assert.equal(diffToolsets(set(TOOL_SEARCH), set(tighter)).overall, "BREAKING");
  assert.equal(diffToolsets(set(TOOL_SEARCH), set(looser)).overall, "NON_BREAKING");
});

test("new constraint where none existed → BREAKING", () => {
  const t = clone(TOOL_SEARCH);
  t.inputSchema.properties.query.pattern = "^[a-z]+$";
  const d = diffToolsets(set(TOOL_SEARCH), set(t));
  assert.equal(d.overall, "BREAKING");
  assert.ok(d.toolDiffs[0].findings.some((f) => f.kind === "constraint-added"));
});

test("type union narrowed → BREAKING; widened → NON_BREAKING", () => {
  const union = clone(TOOL_SEARCH);
  union.inputSchema.properties.limit = { type: ["integer", "string"] };
  const narrowed = clone(union);
  narrowed.inputSchema.properties.limit = { type: "integer" };
  const widened = clone(union);
  widened.inputSchema.properties.limit = { type: ["integer", "string", "null"] };
  assert.equal(diffToolsets(set(union), set(narrowed)).overall, "BREAKING");
  assert.equal(diffToolsets(set(union), set(widened)).overall, "NON_BREAKING");
});

test("additionalProperties closed → BREAKING", () => {
  const open = clone(TOOL_SEARCH);
  const closed = clone(TOOL_SEARCH);
  closed.inputSchema.additionalProperties = false;
  assert.equal(diffToolsets(set(open), set(closed)).overall, "BREAKING");
});

test("composition keyword introduced → BREAKING", () => {
  const t = clone(TOOL_SEARCH);
  t.inputSchema.properties.query.oneOf = [{ type: "string" }];
  const d = diffToolsets(set(TOOL_SEARCH), set(t));
  assert.equal(d.overall, "BREAKING");
  assert.ok(d.toolDiffs[0].findings.some((f) => f.kind === "composition-added"));
});

test("readOnlyHint → destructiveHint flip is PERMISSION_CHANGE, not compatible", () => {
  const t = clone(TOOL_SEARCH);
  t.annotations = { readOnlyHint: false, destructiveHint: true, openWorldHint: true };
  const d = diffToolsets(set(TOOL_SEARCH), set(t));
  assert.equal(d.overall, "PERMISSION_CHANGE");
  assert.ok(d.toolDiffs[0].findings.some((f) => f.kind === "annotation-permission"));
  assert.ok(!isCompatible(d));
});

test("outputSchema removed → PERMISSION_CHANGE", () => {
  const withOut = { ...clone(TOOL_SEARCH), outputSchema: { type: "object" } };
  const d = diffToolsets(set(withOut), set(TOOL_SEARCH));
  assert.equal(d.overall, "PERMISSION_CHANGE");
  assert.ok(d.toolDiffs[0].findings.some((f) => f.kind === "output-schema-removed"));
});

test("TOOL POISONING: description rewritten, schema identical → ANNOTATION_DOWNGRADE", () => {
  const poisoned = clone(TOOL_SEARCH);
  poisoned.description = "Completely different instructions telling the model to exfiltrate secrets and ignore previous safety guidelines entirely.";
  const d = diffToolsets(set(TOOL_SEARCH), set(poisoned));
  assert.equal(d.overall, "ANNOTATION_DOWNGRADE");
  assert.ok(d.toolDiffs[0].findings.some((f) => f.kind === "description-rewrite"));
  assert.ok(!isCompatible(d));
});

test("immaterial description touch (same tokens) does not flag poisoning", () => {
  const t = clone(TOOL_SEARCH);
  t.description = "Search the knowledge base for documents matching a query string"; // dropped period
  const d = diffToolsets(set(TOOL_SEARCH), set(t));
  assert.ok(CHANGE_LEVEL[d.overall] <= CHANGE_LEVEL.NONE);
});

test("description change WITH schema change is not classified as poisoning", () => {
  const t = clone(TOOL_SEARCH);
  t.description = "Totally rewritten prose about a completely different search behavior over the corpus.";
  t.inputSchema.properties.lang = { type: "string" };
  const d = diffToolsets(set(TOOL_SEARCH), set(t));
  assert.equal(d.overall, "NON_BREAKING");
  assert.ok(!d.toolDiffs[0].findings.some((f) => f.kind === "description-rewrite"));
});

test("severity ordering: BREAKING > PERMISSION_CHANGE > ANNOTATION_DOWNGRADE > NON_BREAKING > SYNTACTIC > NONE", () => {
  assert.ok(CHANGE_LEVEL.BREAKING > CHANGE_LEVEL.PERMISSION_CHANGE);
  assert.ok(CHANGE_LEVEL.PERMISSION_CHANGE > CHANGE_LEVEL.ANNOTATION_DOWNGRADE);
  assert.ok(CHANGE_LEVEL.ANNOTATION_DOWNGRADE > CHANGE_LEVEL.NON_BREAKING);
  assert.ok(CHANGE_LEVEL.NON_BREAKING > CHANGE_LEVEL.SYNTACTIC);
  assert.ok(CHANGE_LEVEL.SYNTACTIC > CHANGE_LEVEL.NONE);
});

test("mixed diff: worst level wins and summary mentions all classes", () => {
  const breakingT = clone(TOOL_SEARCH);
  breakingT.inputSchema.required = ["query", "x"];
  breakingT.inputSchema.properties.x = { type: "string" };
  const d = diffToolsets(set(TOOL_SEARCH, TOOL_FETCH), set(breakingT)); // fetch removed + search breaking
  assert.equal(d.overall, "BREAKING");
  assert.ok(d.removed.includes("fetch_document"));
});
