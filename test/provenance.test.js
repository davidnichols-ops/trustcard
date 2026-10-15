// Provenance: manifest build → sign → verify, plus every tamper case.
import { test } from "node:test";
import assert from "node:assert/strict";
import { generatePublisherKeypair, buildManifest, signManifest, verifyManifest, bindingConsistency, publisherFromSecret, isProxyManifest, normalizeTrustedKey } from "../lib/provenance.js";
import { buildManifest as buildProxyManifest } from "../lib/manifest.js";
import { toolsetDigest, serverDigest } from "../lib/identity.js";
import { TOOL_SEARCH, TOOL_FETCH, clone } from "./helpers.js";

function makeManifest(kp, tools = [TOOL_SEARCH, TOOL_FETCH]) {
  return buildManifest({
    serverInfo: { name: "fake-server", version: "1.0.0" },
    protocolVersion: "2025-06-18",
    tools,
    publisher: { keyId: kp.keyId, publicKey: kp.publicKey },
  });
}

test("keygen → build → sign → verify round trip", () => {
  const kp = generatePublisherKeypair();
  const manifest = makeManifest(kp);
  const signed = signManifest(manifest, kp.privateKey);
  const result = verifyManifest(signed);
  assert.ok(result.ok, result.errors.join("; "));
  assert.equal(result.keyId, kp.keyId);
});

test("publisherFromSecret recovers the same keyId", () => {
  const kp = generatePublisherKeypair();
  const recovered = publisherFromSecret(kp.privateKey);
  assert.equal(recovered.keyId, kp.keyId);
  assert.equal(recovered.publicKey, kp.publicKey);
});

test("manifest digests are internally consistent", () => {
  const kp = generatePublisherKeypair();
  const m = makeManifest(kp);
  assert.equal(m.toolsetDigest, toolsetDigest([TOOL_SEARCH, TOOL_FETCH]));
  assert.equal(m.serverDigest, serverDigest({ serverInfo: { name: "fake-server", version: "1.0.0" }, protocolVersion: "2025-06-18", tools: [TOOL_SEARCH, TOOL_FETCH] }));
});

test("tampered tool definition → verification fails", () => {
  const kp = generatePublisherKeypair();
  const signed = signManifest(makeManifest(kp), kp.privateKey);
  const tampered = clone(signed);
  tampered.tools[0].description = "injected malicious instruction";
  const result = verifyManifest(tampered);
  assert.ok(!result.ok);
  assert.ok(result.errors.some((e) => e.includes("toolsetDigest") || e.includes("manifestDigest") || e.includes("signature")));
});

test("tampered signature → verification fails", () => {
  const kp = generatePublisherKeypair();
  const signed = signManifest(makeManifest(kp), kp.privateKey);
  const tampered = clone(signed);
  tampered.signature.value = Buffer.from("forged").toString("base64url");
  assert.ok(!verifyManifest(tampered).ok);
});

test("wrong key → verification fails", () => {
  const kp1 = generatePublisherKeypair();
  const kp2 = generatePublisherKeypair();
  const signed = signManifest(makeManifest(kp1), kp1.privateKey);
  signed.publisher = { keyId: kp2.keyId, publicKey: kp2.publicKey };
  signed.signature.keyId = kp2.keyId;
  assert.ok(!verifyManifest(signed).ok);
});

test("unsigned manifest → verification fails with 'missing signature'", () => {
  const kp = generatePublisherKeypair();
  const result = verifyManifest(makeManifest(kp));
  assert.ok(!result.ok);
  assert.ok(result.errors.some((e) => e.includes("signature")));
});

test("expired manifest → verification fails", () => {
  const kp = generatePublisherKeypair();
  const m = makeManifest(kp);
  m.expiresAt = "2020-01-01T00:00:00Z";
  const signed = signManifest(m, kp.privateKey);
  const result = verifyManifest(signed);
  assert.ok(!result.ok);
  assert.ok(result.errors.some((e) => e.includes("expired")));
});

// --- Regression: sign contract (external review findings) --------------------
// `sign` must fail fast on proxy manifests and must never emit a manifest the
// verifier itself would reject (e.g. a keyless publisher placeholder).

test("sign refuses a proxy-enforcement manifest (wrong document class)", () => {
  const kp = generatePublisherKeypair();
  const proxy = buildProxyManifest([TOOL_SEARCH], { name: "s", version: "1" }, "spec");
  assert.ok(isProxyManifest(proxy));
  assert.throws(() => signManifest(proxy, kp.privateKey), /proxy-enforcement manifest/);
});

test("sign embeds publisher identity derived from the secret for a keyless manifest", () => {
  const kp = generatePublisherKeypair();
  const m = buildManifest({
    serverInfo: { name: "s", version: "1" }, protocolVersion: "2025-06-18",
    tools: [TOOL_SEARCH], publisher: { keyId: "unpublished", publicKey: "" },
  });
  const signed = signManifest(m, kp.privateKey);
  assert.equal(signed.publisher.keyId, kp.keyId);
  assert.equal(signed.publisher.publicKey, kp.publicKey);
  const v = verifyManifest(signed);
  assert.ok(v.ok, v.errors.join("; "));
});

test("sign refuses a manifest declaring a different publisher", () => {
  const signer = generatePublisherKeypair();
  const other = generatePublisherKeypair();
  const m = buildManifest({
    serverInfo: { name: "s", version: "1" }, protocolVersion: "2025-06-18",
    tools: [TOOL_SEARCH], publisher: { keyId: other.keyId, publicKey: other.publicKey },
  });
  assert.throws(() => signManifest(m, signer.privateKey), /publisher.*does not match/i);
});

test("sign refuses a malformed (non-manifest) input", () => {
  const kp = generatePublisherKeypair();
  assert.throws(() => signManifest({ hello: "world" }, kp.privateKey), /not a provenance manifest|proxy-enforcement/);
  assert.throws(() => signManifest(null, kp.privateKey), /provenance manifest|proxy-enforcement/);
});

// --- Regression: verifier trust anchoring ------------------------------------
// A valid signature proves only that the holder of *some* key signed. Trust
// requires an out-of-band anchor; without one the result is self-asserted.

test("verify: attacker self-signed manifest does not satisfy a trusted publisher anchor", () => {
  const victim = generatePublisherKeypair();
  const attacker = generatePublisherKeypair();
  const signed = signManifest(makeManifest(attacker), attacker.privateKey);
  // Cryptographically valid…
  const plain = verifyManifest(signed);
  assert.ok(plain.ok);
  assert.equal(plain.trust.level, "self-asserted");
  assert.equal(plain.trusted, false); // valid but unanchored is never "trusted"
  // …but it does not satisfy the explicit trusted publisher.
  const anchored = verifyManifest(signed, { trustedKeys: [{ keyId: victim.keyId, publicKey: victim.publicKey }] });
  assert.ok(anchored.ok);            // crypto still valid — validity ≠ trust
  assert.equal(anchored.trust.level, "untrusted");
  assert.equal(anchored.trust.anchored, false);
  assert.equal(anchored.trusted, false);
});

test("verify: the real publisher key anchors trust", () => {
  const kp = generatePublisherKeypair();
  const signed = signManifest(makeManifest(kp), kp.privateKey);
  for (const anchor of [
    { keyId: kp.keyId, publicKey: kp.publicKey }, // key-file-shaped
    kp.keyId,                                     // bare keyId
    kp.publicKey,                                 // bare public key
  ]) {
    const r = verifyManifest(signed, { trustedKeys: [anchor] });
    assert.ok(r.ok);
    assert.equal(r.trust.level, "anchored");
    assert.equal(r.trusted, true);
  }
});

test("normalizeTrustedKey parses keyId, public key, and key-file shapes", () => {
  const kp = generatePublisherKeypair();
  assert.deepEqual(normalizeTrustedKey(kp.keyId), { keyId: kp.keyId });
  assert.deepEqual(normalizeTrustedKey(kp.publicKey), { publicKey: kp.publicKey });
  assert.deepEqual(normalizeTrustedKey({ keyId: kp.keyId, publicKey: kp.publicKey, privateKey: "secret" }), { keyId: kp.keyId, publicKey: kp.publicKey });
  assert.equal(normalizeTrustedKey(""), null);
  assert.equal(normalizeTrustedKey({}), null);
});

test("bindingConsistency: matching observation is consistent; drift is not", () => {
  const kp = generatePublisherKeypair();
  const m = makeManifest(kp);
  const goodObs = {
    toolsetDigest: toolsetDigest([TOOL_SEARCH, TOOL_FETCH]),
    serverInfo: { name: "fake-server", version: "1.0.0" },
  };
  assert.ok(bindingConsistency(m, goodObs).consistent);
  const badObs = { toolsetDigest: toolsetDigest([TOOL_SEARCH]), serverInfo: { name: "fake-server" } };
  const bad = bindingConsistency(m, badObs);
  assert.ok(!bad.consistent);
  assert.ok(bad.problems[0].includes("toolset drift"));
});
