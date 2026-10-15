// CLI end-to-end: keygen → sign → verify → diff → pins, all through the real
// bin/mcp-trustcard.js entry point against fixture toolsets on disk.
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildManifest } from "../lib/provenance.js";
import { buildManifest as buildProxyManifest } from "../lib/manifest.js";
import { toolsetDigest } from "../lib/identity.js";
import { TOOL_SEARCH, TOOL_FETCH, clone, FIXTURE } from "./helpers.js";

const BIN = new URL("../bin/mcp-trustcard.js", import.meta.url).pathname;

function run(args, { expectFail = false } = {}) {
  try {
    const out = execFileSync(process.execPath, [BIN, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
    return { code: 0, out, err: "" };
  } catch (e) {
    if (!expectFail) throw e;
    return { code: e.status ?? 1, out: (e.stdout ?? "") + (e.stderr ?? "") };
  }
}

// Split capture when the test needs stdout/stderr independently.
function runSplit(args, { expectFail = false } = {}) {
  const r = spawnSync(process.execPath, [BIN, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  const code = r.status ?? 1;
  if (code !== 0 && !expectFail) throw new Error(`unexpected failure (code ${code}): ${r.stderr || r.stdout}`);
  return { code, out: r.stdout ?? "", err: r.stderr ?? "" };
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

// --- Regression: `sign` document-class + publisher coherence -------------------
// `sign` must fail fast on proxy-enforcement manifests, never report success
// for an unverifiable/keyless manifest, and refuse a publisher identity that
// contradicts the signing key.

test("sign refuses a proxy-enforcement manifest (exit 2, no output written)", () => {
  const dir = mkdtempSync(join(tmpdir(), "trustcard-cli-"));
  try {
    const keyPath = join(dir, "k.json");
    run(["keygen", "--out", keyPath]);
    const proxy = buildProxyManifest([TOOL_SEARCH], { name: "s", version: "1" }, "spec");
    const proxyPath = join(dir, "proxy.json");
    writeFileSync(proxyPath, JSON.stringify(proxy));
    const out = join(dir, "signed.json");
    const r = runSplit(["sign", proxyPath, "--key", keyPath, "--out", out], { expectFail: true });
    assert.equal(r.code, 2);
    assert.match(r.err, /proxy-enforcement manifest/);
    assert.equal(existsSync(out), false);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("sign of a keyless manifest embeds publisher identity and verifies", () => {
  const dir = mkdtempSync(join(tmpdir(), "trustcard-cli-"));
  try {
    const keyPath = join(dir, "k.json");
    run(["keygen", "--out", keyPath]);
    const m = manifestFile(dir, [TOOL_SEARCH]); // keyless publisher placeholder
    const signed = join(dir, "signed.json");
    const r = runSplit(["sign", m, "--key", keyPath, "--out", signed]);
    assert.equal(r.code, 0);
    const doc = JSON.parse(readFileSync(signed, "utf8"));
    const key = JSON.parse(readFileSync(keyPath, "utf8"));
    assert.equal(doc.publisher.keyId, key.keyId);
    assert.equal(doc.publisher.publicKey, key.publicKey);
    assert.equal(doc.signature.keyId, key.keyId);
    assert.equal(run(["verify", signed]).code, 0);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("sign refuses a manifest whose declared publisher contradicts --key", () => {
  const dir = mkdtempSync(join(tmpdir(), "trustcard-cli-"));
  try {
    const kA = join(dir, "a.json"), kB = join(dir, "b.json");
    run(["keygen", "--out", kA]);
    run(["keygen", "--out", kB]);
    // declare publisher B but sign with key A
    const m = manifestFile(dir, [TOOL_SEARCH], "m.json", JSON.parse(readFileSync(kB, "utf8")));
    const r = runSplit(["sign", m, "--key", kA, "--out", join(dir, "x.json")], { expectFail: true });
    assert.equal(r.code, 2);
    assert.match(r.err, /publisher|does not match/i);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// --- Regression: verify trust anchoring --------------------------------------
// Without an anchor, a valid signature is self-asserted (exit 0, clearly
// labeled). With an anchor, a stranger's key must fail (exit 1).

test("verify --publisher-key: attacker key does not satisfy the trusted publisher", () => {
  const dir = mkdtempSync(join(tmpdir(), "trustcard-cli-"));
  try {
    const victim = join(dir, "victim.json"), attacker = join(dir, "attacker.json");
    run(["keygen", "--out", victim]);
    run(["keygen", "--out", attacker]);
    const m = manifestFile(dir, [TOOL_SEARCH]); // keyless → signer embeds its own identity
    const signed = join(dir, "signed-by-attacker.json");
    run(["sign", m, "--key", attacker, "--out", signed]);
    // unanchored: valid but self-asserted, still exit 0
    const selfAsserted = runSplit(["verify", signed]);
    assert.equal(selfAsserted.code, 0);
    assert.match(selfAsserted.out, /SELF-ASSERTED/);
    // wrong anchor: cryptographically valid but untrusted → exit 1
    const r = runSplit(["verify", signed, "--publisher-key", victim], { expectFail: true });
    assert.equal(r.code, 1);
    assert.match(r.out, /UNTRUSTED/);
    // right anchor: exit 0, anchored
    const ok = runSplit(["verify", signed, "--publisher-key", attacker]);
    assert.equal(ok.code, 0);
    assert.match(ok.out, /ANCHORED/);
    // bare keyId string also anchors
    const attackerKey = JSON.parse(readFileSync(attacker, "utf8"));
    const byKeyId = runSplit(["verify", signed, "--publisher-key", attackerKey.keyId]);
    assert.equal(byKeyId.code, 0);
    assert.match(byKeyId.out, /ANCHORED/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("verify --pins uses the publisher keyring as the trust anchor", () => {
  const dir = mkdtempSync(join(tmpdir(), "trustcard-cli-"));
  try {
    const keyPath = join(dir, "k.json"), otherPath = join(dir, "other.json");
    run(["keygen", "--out", keyPath]);
    run(["keygen", "--out", otherPath]);
    const key = JSON.parse(readFileSync(keyPath, "utf8"));
    const m = manifestFile(dir, [TOOL_SEARCH]);
    const signed = join(dir, "s.json");
    run(["sign", m, "--key", keyPath, "--out", signed]);
    // pins file containing the signer's publisher pin → anchored
    const pinsPath = join(dir, "pins.json");
    writeFileSync(pinsPath, JSON.stringify({
      schema: "trustcard.dev/pins@1",
      servers: {},
      publishers: { [key.keyId]: { publicKey: key.publicKey, firstSeen: "2026-01-01T00:00:00Z", source: "test" } },
    }));
    const ok = runSplit(["verify", signed, "--pins", pinsPath]);
    assert.equal(ok.code, 0);
    assert.match(ok.out, /ANCHORED/);
    // a pin store missing that publisher → untrusted
    const otherKey = JSON.parse(readFileSync(otherPath, "utf8"));
    writeFileSync(pinsPath, JSON.stringify({
      schema: "trustcard.dev/pins@1", servers: {},
      publishers: { [otherKey.keyId]: { publicKey: otherKey.publicKey, firstSeen: "2026-01-01T00:00:00Z", source: "test" } },
    }));
    const r = runSplit(["verify", signed, "--pins", pinsPath], { expectFail: true });
    assert.equal(r.code, 1);
    assert.match(r.out, /UNTRUSTED/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// --- Regression: manifest CLI contract ----------------------------------------
// `manifest` emits pure JSON on stdout, confirms on stderr, embeds (but does
// not sign with) the publisher key, and expires in 90 days unless --no-expiry.

test("manifest: pure JSON stdout, stderr confirms unsigned, 90-day expiry default", () => {
  const dir = mkdtempSync(join(tmpdir(), "trustcard-cli-"));
  try {
    const keyPath = join(dir, "k.json");
    run(["keygen", "--out", keyPath]);
    const r = runSplit(["manifest", "--key", keyPath, "--", "node", FIXTURE]);
    assert.equal(r.code, 0);
    const doc = JSON.parse(r.out); // stdout must be clean JSON — no banner noise
    const key = JSON.parse(readFileSync(keyPath, "utf8"));
    assert.equal(doc.publisher.keyId, key.keyId);
    assert.equal(doc.publisher.publicKey, key.publicKey);
    assert.equal(doc.signature, undefined); // NOT signed
    assert.match(r.err, /NOT signed|unsigned/i);
    // default expiry ≈ 90 days
    const daysLeft = (Date.parse(doc.expiresAt) - Date.now()) / 86_400_000;
    assert.ok(daysLeft > 88 && daysLeft <= 90.01, `expiresAt ~90d, got ${daysLeft}`);
    // --no-expiry emits expiresAt: null
    const r2 = runSplit(["manifest", "--no-expiry", "--", "node", FIXTURE]);
    const doc2 = JSON.parse(r2.out);
    assert.equal(doc2.expiresAt, null);
    // --expires-in overrides
    const r3 = runSplit(["manifest", "--expires-in", "7", "--", "node", FIXTURE]);
    const doc3 = JSON.parse(r3.out);
    const d3 = (Date.parse(doc3.expiresAt) - Date.now()) / 86_400_000;
    assert.ok(d3 > 6 && d3 <= 7.01, `expiresAt ~7d, got ${d3}`);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
