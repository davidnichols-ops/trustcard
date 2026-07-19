// Provenance: manifest build → sign → verify, plus every tamper case.
import { test } from "node:test";
import assert from "node:assert/strict";
import { generatePublisherKeypair, buildManifest, signManifest, verifyManifest, bindingConsistency, publisherFromSecret } from "../lib/provenance.js";
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
