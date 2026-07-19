// RFC 8785 (JCS) canonicalization — tested against the RFC's own examples.
import { test } from "node:test";
import assert from "node:assert/strict";
import { canon, jsonEqual } from "../lib/canon.js";
import { hashJson } from "../lib/hash.js";

test("JCS: object keys are sorted, whitespace removed", () => {
  assert.equal(canon({ b: 1, a: 2 }), '{"a":2,"b":1}');
  assert.equal(canon({ z: { y: 1, x: 2 }, a: [3, 2, 1] }), '{"a":[3,2,1],"z":{"x":2,"y":1}}');
});

test("JCS: RFC 8785 §3.2.2.2 string examples", () => {
  assert.equal(canon("hello"), '"hello"');
  assert.equal(canon('quote " and backslash \\'), '"quote \\" and backslash \\\\"');
  assert.equal(canon("tab\tnewline\n"), '"tab\\tnewline\\n"');
  // Control chars escape as \u00XX; non-ASCII emitted literally.
  assert.equal(canon(""), '"\\u0001"');
  assert.equal(canon("é"), '"é"');
  assert.equal(canon("💩"), '"💩"');
});

test("JCS: RFC 8785 number canonicalization", () => {
  assert.equal(canon(0), "0");
  assert.equal(canon(-0), "0"); // no negative zero
  assert.equal(canon(1), "1");
  assert.equal(canon(-1), "-1");
  assert.equal(canon(3.14), "3.14");
  assert.equal(canon(1e21), "1e+21"); // exponential at >= 1e21
  assert.equal(canon(1e20), "100000000000000000000"); // integer below threshold
  assert.equal(canon(0.000001), "0.000001");
  assert.equal(canon(1e-7), "1e-7");
  assert.equal(canon(123456789012345680000), "123456789012345680000");
});

test("JCS: rejects non-finite numbers", () => {
  assert.throws(() => canon(NaN), TypeError);
  assert.throws(() => canon(Infinity), TypeError);
});

test("JCS: undefined object values dropped, array undefined → null (JSON semantics)", () => {
  assert.equal(canon({ a: undefined, b: 1 }), '{"b":1}');
  assert.equal(canon([undefined, 1]), "[null,1]");
});

test("JCS: determinism — same logical value, different key order, same bytes", () => {
  const a = { name: "x", schema: { type: "object", properties: { q: { type: "string" } }, required: ["q"] } };
  const b = { schema: { required: ["q"], properties: { q: { type: "string" } }, type: "object" }, name: "x" };
  assert.equal(canon(a), canon(b));
  assert.equal(hashJson(a), hashJson(b));
});

test("jsonEqual: structural equality", () => {
  assert.ok(jsonEqual({ a: [1, { b: 2 }] }, { a: [1, { b: 2 }] }));
  assert.ok(!jsonEqual({ a: 1 }, { a: 2 }));
  assert.ok(!jsonEqual([1, 2], [2, 1]));
  assert.ok(!jsonEqual({ a: 1 }, { a: 1, b: 2 }));
});

test("hashJson: stable, prefixed, base64url", () => {
  const h = hashJson({ hello: "world" });
  assert.match(h, /^sha256:[A-Za-z0-9_-]{43}$/);
  assert.equal(h, hashJson({ hello: "world" }));
  assert.notEqual(h, hashJson({ hello: "world!" }));
});
