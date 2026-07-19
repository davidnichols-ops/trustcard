// CLI end-to-end: keygen → sign → verify → diff → pins, all through the real
// bin/mcp-trustcard.js entry point against fixture toolsets on disk.
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildManifest } from "../lib/provenance.js";
import { toolsetDigest } from "../lib/identity.js";
import { TOOL_SEARCH, TOOL_FETCH, clone } from "./helpers.js";

const BIN = new URL("../bin/mcp-trustcard.js", import.meta.url).pathname;

function run(args, { expectFail = false } = {}) {
  try {
    const out = execFileSync(process.execPath, [BIN, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
    return { code: 0, out };
  } catch (e) {
    if (!expectFail) throw e;
    return { code: e.status ?? 1, out: (e.stdout ?? "") + (e.stderr ?? "") };
  }
}

function manifestFile(dir, tools, name = "m.json", kp = { keyId: "sha256:unsigned", publicKey: "" }) {
  const m = buildManifest({ serverInfo: { name: "s", version: "1" }, protocolVersion: "2025-06-18", tools, publisher: { keyId: kp.keyId, publicKey: kp.publicKey } });
  const p = join(dir, name);
  writeFileSync(p, JSON.stringify(m));
  return p;
}

test("keygen → sign → verify round trip via CLI", () => {
  const dir = mkdtempSync(join(tmpdir(), "trustcard-cli-"));
  try {
    const keyPath = join(dir, "pub.key.json");
    run(["keygen", "--out", keyPath]);
    const kp = JSON.parse(execFileSync("cat", [keyPath], { encoding: "utf8" }));
    assert.match(kp.keyId, /^sha256:/);

    const mPath = manifestFile(dir, [TOOL_SEARCH, TOOL_FETCH], "m.json", kp);
    const signedPath = join(dir, "signed.json");
    run(["sign", mPath, "--key", keyPath, "--out", signedPath]);

    const v = run(["verify", signedPath, "--json"]);
    const report = JSON.parse(v.out);
    assert.equal(report.ok, true);
    assert.equal(report.keyId, kp.keyId);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("verify rejects a tampered manifest (exit 1)", () => {
  const dir = mkdtempSync(join(tmpdir(), "trustcard-cli-"));
  try {
    const keyPath = join(dir, "pub.key.json");
    run(["keygen", "--out", keyPath]);
    const mPath = manifestFile(dir, [TOOL_SEARCH]);
    const signedPath = join(dir, "signed.json");
    run(["sign", mPath, "--key", keyPath, "--out", signedPath]);
    // tamper
    const signed = JSON.parse(execFileSync("cat", [signedPath], { encoding: "utf8" }));
    signed.tools[0].description = "poisoned instructions";
    writeFileSync(signedPath, JSON.stringify(signed));
    const v = run(["verify", signedPath, "--json"], { expectFail: true });
    assert.equal(v.code, 1);
    assert.equal(JSON.parse(v.out).ok, false);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("diff classifies breaking change and exits 1", () => {
  const dir = mkdtempSync(join(tmpdir(), "trustcard-cli-"));
  try {
    const oldP = manifestFile(dir, [TOOL_SEARCH, TOOL_FETCH], "old.json");
    const newP = manifestFile(dir, [TOOL_SEARCH], "new.json"); // fetch removed
    const r = run(["diff", oldP, newP, "--json"], { expectFail: true });
    assert.equal(r.code, 1);
    const diff = JSON.parse(r.out);
    assert.equal(diff.overall, "BREAKING");
    assert.deepEqual(diff.removed, ["fetch_document"]);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("diff of identical toolsets exits 0 with NONE", () => {
  const dir = mkdtempSync(join(tmpdir(), "trustcard-cli-"));
  try {
    const a = manifestFile(dir, [TOOL_SEARCH], "a.json");
    const b = manifestFile(dir, [clone(TOOL_SEARCH)], "b.json");
    const r = run(["diff", a, b, "--json"]);
    assert.equal(r.code, 0);
    assert.equal(JSON.parse(r.out).overall, "NONE");
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("pins: empty store prints guidance, --json returns structure", () => {
  const dir = mkdtempSync(join(tmpdir(), "trustcard-cli-"));
  try {
    const pinsPath = join(dir, "pins.json");
    const r = run(["pins", "--json", "--pins", pinsPath]);
    const data = JSON.parse(r.out);
    assert.ok(data.servers !== undefined && data.publishers !== undefined);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
