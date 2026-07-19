// Publisher key rotation + revocation.
//
// TRUST-SUBSTRATE §12.1 (#3): key compromise is mostly a *UX* attack — the
// cryptography detects a new key instantly, but "yes, we rotated, please re-pin"
// is a social attack. Old-key-signs-new-key turns that back into a verifiable
// cryptographic fact: a rotation is only trusted if the OLD key signs the new
// one. Without it, every rotation is a fresh TOFU moment.
//
// A rotation certificate:
//   { schema, type:"key-rotation", oldKeyId, oldPublicKey, newKeyId, newPublicKey,
//     issuedAt, signature(oldKey over the payload) }
// A revocation certificate:
//   { schema, type:"revocation", keyId, publicKey, reason, issuedAt,
//     signature(revoked key over the payload) }   — self-signed: only the holder
//     of the key can revoke it, and a revoked key's revocation is still verifiable.
//
// Signing coverage: signature excluded from the payload (same rule as manifests
// and descriptors). Certificates are content-addressed by their digest.
import { createPublicKey, createPrivateKey, sign as edSign, verify as edVerify } from "node:crypto";
import { canon } from "./canon.js";
import { hashJson, sha256Base64Url } from "./hash.js";
import { publisherFromSecret } from "./provenance.js";

export const ROTATION_SCHEMA = "trustcard.dev/key-rotation@1";
export const REVOCATION_SCHEMA = "trustcard.dev/revocation@1";

const b64u = (buf) => Buffer.from(buf).toString("base64url");

function signingPayload(cert) {
  const { signature, digest, ...unsigned } = cert;
  return unsigned;
}

export function certificateDigest(cert) {
  return hashJson(signingPayload(cert));
}

function signCertPayload(unsigned, privateKeyB64u) {
  const privateKey = createPrivateKey({ key: Buffer.from(privateKeyB64u, "base64url"), type: "pkcs8", format: "der" });
  const sig = edSign(null, Buffer.from(canon(unsigned), "utf8"), privateKey);
  const pub = publisherFromSecret(privateKeyB64u);
  return { algorithm: "ed25519", keyId: pub.keyId, value: b64u(sig) };
}

// Build + sign a rotation certificate. The OLD private key signs, proving the
// holder of the old key authorizes the new one. newPublicKey/newKeyId describe
// the successor; oldPublicKey/oldKeyId are embedded so anyone can verify.
// expiresAt is optional (null = no expiry); when set, verifiers reject the
// certificate once it lapses, so a stolen old key cannot re-authorize forever.
export function buildRotationCertificate({ oldPrivateKey, newPublicKey, newKeyId, issuedAt = new Date().toISOString(), expiresAt = null }) {
  const old = publisherFromSecret(oldPrivateKey);
  const unsigned = {
    schema: ROTATION_SCHEMA,
    type: "key-rotation",
    oldKeyId: old.keyId,
    oldPublicKey: old.publicKey,
    newKeyId,
    newPublicKey,
    issuedAt,
    expiresAt,
  };
  const signature = signCertPayload(unsigned, oldPrivateKey);
  const cert = { ...unsigned, digest: hashJson(unsigned), signature };
  return cert;
}

// Verify a rotation certificate: internal consistency + the OLD key's signature
// over the payload + that the embedded old keyId matches the embedded old key.
export function verifyRotationCertificate(cert) {
  const errors = [];
  if (!cert || typeof cert !== "object") return { ok: false, errors: ["certificate is not an object"] };
  if (cert.schema !== ROTATION_SCHEMA) errors.push(`unknown schema "${cert.schema}"`);
  if (cert.type !== "key-rotation") errors.push(`not a key-rotation certificate`);
  for (const f of ["oldKeyId", "oldPublicKey", "newKeyId", "newPublicKey"]) {
    if (!cert[f]) errors.push(`missing ${f}`);
  }
  if (!cert.signature?.value) errors.push("missing signature");

  // embedded old keyId must match embedded old public key.
  if (cert.oldPublicKey) {
    const derived = sha256Base64Url(Buffer.from(cert.oldPublicKey, "base64url"));
    if (cert.oldKeyId && cert.oldKeyId !== derived) {
      errors.push(`oldKeyId ${cert.oldKeyId} does not match oldPublicKey (${derived})`);
    }
  }
  // digest self-consistency.
  if (cert.digest && cert.digest !== certificateDigest(cert)) {
    errors.push("digest mismatch");
  }
  // expiry (when set) — a lapsed rotation must not keep authorizing.
  if (cert.expiresAt && Date.parse(cert.expiresAt) < Date.now()) {
    errors.push(`rotation certificate expired at ${cert.expiresAt}`);
  }
  // signature must verify under the OLD public key.
  if (cert.signature?.value && cert.oldPublicKey) {
    try {
      const publicKey = createPublicKey({ key: Buffer.from(cert.oldPublicKey, "base64url"), type: "spki", format: "der" });
      const okSig = edVerify(null, Buffer.from(canon(signingPayload(cert)), "utf8"), publicKey, Buffer.from(cert.signature.value, "base64url"));
      if (!okSig) errors.push("signature verification failed (old key)");
    } catch (e) {
      errors.push(`signature verification error: ${e.message}`);
    }
  }
  return { ok: errors.length === 0, errors, oldKeyId: cert.oldKeyId ?? null, newKeyId: cert.newKeyId ?? null };
}

// Build + sign a revocation certificate (self-signed by the revoked key).
export function buildRevocationCertificate({ privateKey, reason = "revoked", issuedAt = new Date().toISOString() }) {
  const pub = publisherFromSecret(privateKey);
  const unsigned = {
    schema: REVOCATION_SCHEMA,
    type: "revocation",
    keyId: pub.keyId,
    publicKey: pub.publicKey,
    reason,
    issuedAt,
  };
  const signature = signCertPayload(unsigned, privateKey);
  return { ...unsigned, digest: hashJson(unsigned), signature };
}

// Verify a revocation: it must be self-signed by the key it revokes.
export function verifyRevocationCertificate(cert) {
  const errors = [];
  if (!cert || typeof cert !== "object") return { ok: false, errors: ["certificate is not an object"] };
  if (cert.schema !== REVOCATION_SCHEMA) errors.push(`unknown schema "${cert.schema}"`);
  if (cert.type !== "revocation") errors.push("not a revocation certificate");
  if (!cert.keyId || !cert.publicKey) errors.push("missing keyId/publicKey");
  if (!cert.signature?.value) errors.push("missing signature");
  if (cert.publicKey) {
    const derived = sha256Base64Url(Buffer.from(cert.publicKey, "base64url"));
    if (cert.keyId && cert.keyId !== derived) errors.push(`keyId does not match publicKey`);
  }
  if (cert.digest && cert.digest !== certificateDigest(cert)) errors.push("digest mismatch");
  if (cert.signature?.value && cert.publicKey) {
    try {
      const publicKey = createPublicKey({ key: Buffer.from(cert.publicKey, "base64url"), type: "spki", format: "der" });
      const okSig = edVerify(null, Buffer.from(canon(signingPayload(cert)), "utf8"), publicKey, Buffer.from(cert.signature.value, "base64url"));
      if (!okSig) errors.push("signature verification failed");
    } catch (e) {
      errors.push(`signature verification error: ${e.message}`);
    }
  }
  return { ok: errors.length === 0, errors, keyId: cert.keyId ?? null };
}
