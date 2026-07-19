// Identity: digests must be stable, order-independent, and sensitive to
// exactly the semantic surface — nothing else.
import { test } from "node:test";
import assert from "node:assert/strict";
import { toolDigest, toolsetDigest, serverDigest, toolProjection, volatileFields } from "../lib/identity.js";
import { TOOL_SEARCH, TOOL_FETCH, clone } from "./helpers.js";

test("toolDigest: identical definitions → identical digest regardless of key order", () => {
  const a = clone(TOOL_SEARCH);
  const b = {};
  for (const k of Object.keys(a).reverse()) b[k] = a[k]; // reversed key order
  assert.equal(toolDigest(a), toolDigest(b));
});

test("toolDigest: volatile fields do NOT change the digest", () => {
  const a = clone(TOOL_SEARCH);
  const b = { ...clone(TOOL_SEARCH), title: "Search!", icons: [{ src: "x" }], _meta: { "com.example/x": 1 }, tags: ["beta"] };
  assert.equal(toolDigest(a), toolDigest(b));
  assert.deepEqual(volatileFields(b).sort(), ["_meta", "icons", "tags", "title"]);
});

test("toolDigest: semantic changes DO change the digest", () => {
  const base = toolDigest(TOOL_SEARCH);
  const descChanged = { ...clone(TOOL_SEARCH), description: "Rewritten description." };
  const schemaChanged = clone(TOOL_SEARCH);
  schemaChanged.inputSchema.properties.query.minLength = 2;
  const annChanged = clone(TOOL_SEARCH);
  annChanged.annotations.destructiveHint = true;
  assert.notEqual(toolDigest(descChanged), base);
  assert.notEqual(toolDigest(schemaChanged), base);
  assert.notEqual(toolDigest(annChanged), base);
});

test("toolsetDigest: order-independent over the set", () => {
  const d1 = toolsetDigest([TOOL_SEARCH, TOOL_FETCH]);
  const d2 = toolsetDigest([TOOL_FETCH, TOOL_SEARCH]);
  assert.equal(d1, d2);
});

test("toolsetDigest: adding or removing a tool changes the set digest", () => {
  const d1 = toolsetDigest([TOOL_SEARCH, TOOL_FETCH]);
  const d2 = toolsetDigest([TOOL_SEARCH]);
  assert.notEqual(d1, d2);
});

test("serverDigest: binds serverInfo + protocol + toolset", () => {
  const base = serverDigest({ serverInfo: { name: "s", version: "1" }, protocolVersion: "2025-06-18", tools: [TOOL_SEARCH] });
  const same = serverDigest({ serverInfo: { name: "s", version: "1" }, protocolVersion: "2025-06-18", tools: [TOOL_SEARCH] });
  const diffProto = serverDigest({ serverInfo: { name: "s", version: "1" }, protocolVersion: "2024-11-05", tools: [TOOL_SEARCH] });
  const diffVer = serverDigest({ serverInfo: { name: "s", version: "2" }, protocolVersion: "2025-06-18", tools: [TOOL_SEARCH] });
  assert.equal(base, same);
  assert.notEqual(base, diffProto);
  assert.notEqual(base, diffVer);
});

test("toolProjection: drops volatile, keeps annotation subset", () => {
  const t = { ...clone(TOOL_SEARCH), title: "X", icons: [], annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false, customHint: "ignored" } };
  const p = toolProjection(t);
  assert.equal(p.title, undefined);
  assert.equal(p.icons, undefined);
  assert.equal(p.annotations.customHint, undefined);
  assert.equal(p.annotations.readOnlyHint, true);
});
