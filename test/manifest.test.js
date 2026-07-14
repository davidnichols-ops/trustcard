import { test } from "node:test";
import assert from "node:assert/strict";
import { buildManifest, diffManifest, checkCall, hash, canonicalJson } from "../lib/manifest.js";

test("canonicalJson sorts keys and strips whitespace", () => {
  assert.equal(canonicalJson({ b: 1, a: 2 }), '{"a":2,"b":1}');
  assert.equal(canonicalJson({ a: { c: 3, b: 2 } }), '{"a":{"b":2,"c":3}}');
  assert.equal(canonicalJson(null), "null");
  assert.equal(canonicalJson([3, 1, 2]), "[3,1,2]");
});

test("hash is deterministic and 16 chars", () => {
  const h1 = hash({ type: "object", properties: { x: { type: "string" } } });
  const h2 = hash({ type: "object", properties: { x: { type: "string" } } });
  assert.equal(h1, h2);
  assert.equal(h1.length, 16);
});

test("hash differs for different schemas", () => {
  const h1 = hash({ type: "object", properties: { x: { type: "string" } } });
  const h2 = hash({ type: "object", properties: { x: { type: "number" } } });
  assert.notEqual(h1, h2);
});

test("hash is order-independent", () => {
  const h1 = hash({ a: 1, b: 2 });
  const h2 = hash({ b: 2, a: 1 });
  assert.equal(h1, h2);
});

test("buildManifest captures tool names and schema hashes", () => {
  const tools = [
    { name: "read_file", inputSchema: { type: "object", properties: { path: { type: "string" } } } },
    { name: "write_file", inputSchema: { type: "object", properties: { path: { type: "string" }, content: { type: "string" } } } },
  ];
  const m = buildManifest(tools, { name: "test-server", version: "1.0" }, "test-spec");
  assert.equal(m.version, 1);
  assert.equal(m.spec, "test-spec");
  assert.equal(m.tools.length, 2);
  assert.equal(m.tools[0].name, "read_file");
  assert.ok(m.tools[0].schemaHash);
  assert.ok(m.manifestHash);
});

test("diffManifest detects added tools", () => {
  const manifest = buildManifest([
    { name: "read_file", inputSchema: { type: "object" } },
  ]);
  const live = [
    { name: "read_file", inputSchema: { type: "object" } },
    { name: "exfiltrate", inputSchema: { type: "object" } },
  ];
  const diff = diffManifest(manifest, live);
  assert.deepEqual(diff.added, ["exfiltrate"]);
  assert.deepEqual(diff.removed, []);
  assert.deepEqual(diff.drifted, []);
  assert.equal(diff.ok, false);
});

test("diffManifest detects removed tools", () => {
  const manifest = buildManifest([
    { name: "read_file", inputSchema: { type: "object" } },
    { name: "write_file", inputSchema: { type: "object" } },
  ]);
  const live = [
    { name: "read_file", inputSchema: { type: "object" } },
  ];
  const diff = diffManifest(manifest, live);
  assert.deepEqual(diff.added, []);
  assert.deepEqual(diff.removed, ["write_file"]);
  assert.equal(diff.ok, false);
});

test("diffManifest detects schema drift", () => {
  const manifest = buildManifest([
    { name: "read_file", inputSchema: { type: "object", properties: { path: { type: "string" } } } },
  ]);
  const live = [
    { name: "read_file", inputSchema: { type: "object", properties: { path: { type: "number" } } } },
  ];
  const diff = diffManifest(manifest, live);
  assert.equal(diff.drifted.length, 1);
  assert.equal(diff.drifted[0].name, "read_file");
  assert.notEqual(diff.drifted[0].approved, diff.drifted[0].live);
  assert.equal(diff.ok, false);
});

test("diffManifest reports ok when everything matches", () => {
  const tools = [
    { name: "read_file", inputSchema: { type: "object", properties: { path: { type: "string" } } } },
    { name: "list_dir", inputSchema: { type: "object" } },
  ];
  const manifest = buildManifest(tools);
  const diff = diffManifest(manifest, tools);
  assert.equal(diff.ok, true);
  assert.deepEqual(diff.added, []);
  assert.deepEqual(diff.removed, []);
  assert.deepEqual(diff.drifted, []);
});

test("checkCall allows approved tools", () => {
  const manifest = buildManifest([
    { name: "read_file", inputSchema: { type: "object" } },
  ]);
  const result = checkCall(manifest, "read_file", { path: "/etc/passwd" });
  assert.equal(result.allowed, true);
  assert.equal(result.reason, null);
});

test("checkCall blocks unapproved tools", () => {
  const manifest = buildManifest([
    { name: "read_file", inputSchema: { type: "object" } },
  ]);
  const result = checkCall(manifest, "delete_everything", {});
  assert.equal(result.allowed, false);
  assert.ok(result.reason.includes("delete_everything"));
  assert.ok(result.reason.includes("not in approved manifest"));
});

test("manifestHash changes when tools change", () => {
  const m1 = buildManifest([{ name: "read_file", inputSchema: { type: "object" } }]);
  const m2 = buildManifest([
    { name: "read_file", inputSchema: { type: "object" } },
    { name: "write_file", inputSchema: { type: "object" } },
  ]);
  assert.notEqual(m1.manifestHash, m2.manifestHash);
});

test("manifestHash is stable for same tools", () => {
  const tools = [{ name: "read_file", inputSchema: { type: "object" } }];
  const m1 = buildManifest(tools);
  const m2 = buildManifest(tools);
  assert.equal(m1.manifestHash, m2.manifestHash);
});
