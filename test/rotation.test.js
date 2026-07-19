import { test } from "node:test";
import assert from "node:assert/strict";
import { generatePublisherKeypair } from "../lib/provenance.js";
import {
  buildRotationCertificate,
  verifyRotationCertificate,
  buildRevocationCertificate,
  verifyRevocationCertificate,
  certificateDigest,
  ROTATION_SCHEMA,
  REVOCATION_SCHEMA,
} from "../lib/rotation.js";

const oldKey = generatePublisherKeypair();
const newKey = generatePublisherKeypair();

test("key rotation: a valid old-signs-new certificate verifies", () => {
  const cert = buildRotationCertificate({ oldPrivateKey: oldKey.privateKey, newPublicKey: newKey.publicKey, newKeyId: newKey.keyId });
  assert.equal(cert.schema, ROTATION_SCHEMA);
  assert.equal(cert.oldKeyId, oldKey.keyId);
  assert.equal(cert.newKeyId, newKey.keyId);
  const v = verifyRotationCertificate(cert);
  assert.equal(v.ok, true, v.errors.join("; "));
  assert.equal(v.oldKeyId, oldKey.keyId);
  assert.equal(v.newKeyId, newKey.keyId);
});

test("key rotation: forged rotation (signed by the WRONG key) fails", () => {
  // attacker tries to rotate oldKey to their key, but signs with attacker's key
  const attacker = generatePublisherKeypair();
  const cert = buildRotationCertificate({ oldPrivateKey: attacker.privateKey, newPublicKey: attacker.publicKey, newKeyId: attacker.keyId });
  // then tamper to claim it's rotating the VICTIM's key
  const forged = { ...cert, oldKeyId: oldKey.keyId, oldPublicKey: oldKey.publicKey };
  assert.equal(verifyRotationCertificate(forged).ok, false);
});

test("key rotation: tampered new key fails verification", () => {
  const cert = buildRotationCertificate({ oldPrivateKey: oldKey.privateKey, newPublicKey: newKey.publicKey, newKeyId: newKey.keyId });
  const bad = JSON.parse(JSON.stringify(cert));
  bad.newPublicKey = generatePublisherKeypair().publicKey; // swap the successor
  assert.equal(verifyRotationCertificate(bad).ok, false);
});

test("key rotation: certificate is content-addressed", () => {
  const cert = buildRotationCertificate({ oldPrivateKey: oldKey.privateKey, newPublicKey: newKey.publicKey, newKeyId: newKey.keyId });
  assert.equal(cert.digest, certificateDigest(cert));
  assert.match(cert.digest, /^sha256:/);
});

test("revocation: a valid self-signed revocation verifies", () => {
  const cert = buildRevocationCertificate({ privateKey: oldKey.privateKey, reason: "key-compromise" });
  assert.equal(cert.schema, REVOCATION_SCHEMA);
  assert.equal(cert.keyId, oldKey.keyId);
  const v = verifyRevocationCertificate(cert);
  assert.equal(v.ok, true, v.errors.join("; "));
  assert.equal(v.keyId, oldKey.keyId);
});

test("revocation: only the holder of the key can revoke it (self-signed)", () => {
  const attacker = generatePublisherKeypair();
  const cert = buildRevocationCertificate({ privateKey: attacker.privateKey, reason: "malicious" });
  // claim it revokes the victim's key
  const forged = { ...cert, keyId: oldKey.keyId, publicKey: oldKey.publicKey };
  assert.equal(verifyRevocationCertificate(forged).ok, false);
});

test("revocation: tampered certificate fails", () => {
  const cert = buildRevocationCertificate({ privateKey: oldKey.privateKey, reason: "key-compromise" });
  const bad = JSON.parse(JSON.stringify(cert));
  bad.reason = "edited-after-signing";
  assert.equal(verifyRevocationCertificate(bad).ok, false);
});
