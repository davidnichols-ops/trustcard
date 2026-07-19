// Capability Descriptor: the protocol-neutral trust object.
//
// This module is the v2 identity + provenance core, layered ADDITIVELY on top
// of the v1 modules (identity.js / provenance.js). v1 stays intact; this file
// introduces the separations docs/TRUST-SUBSTRATE.md derived, corrected where
// the real code proved the document wrong:
//
//   IDENTITY (objective, content-addressed)
//     interfaceDigest      I_id  = H(JCS(normalize(semantic projection)))
//     implementation       M_id  = typed artifact identity (npm-dist | source | unresolved)
//     publisher            P_id  = keyId = H(Ed25519 public key)
//
//   DESCRIPTOR (signed objective claim)
//     binds interface -> implementation -> provenance, content-addressed by
//     descriptorDigest. Contains NO local trust state.
//
//   TRUST DECISION / AUTHORIZATION — deliberately NOT here. Those are local,
//   relying-party-specific, and live in trust.js / guard.js.
//
// Design decisions that intentionally differ from TRUST-SUBSTRATE (see
// docs/DESCRIPTOR.md for the full reasoning):
//   * There is no C_id = H(namespace || I_id). A namespace is naming, not
//     identity; the capability's identity IS its interface digest. Namespace is
//     carried as a signed claim, never hashed into identity.
//   * interfaceDigest is kept alongside the embedded interface. It is redundant
//     but load-bearing: it is what pins, receipts, and diffs reference without
//     recomputing.
//   * Implementation identity is honest, not aspirational. `npm-dist` proves
//     "which tarball was published", NOT "what code executed". `unresolved` is
//     a first-class value, never a silent omission.

import { createPublicKey, createPrivateKey, sign as edSign, verify as edVerify } from "node:crypto";
import { canon, jsonEqual } from "./canon.js";
import { hashJson, sha256Base64Url } from "./hash.js";
import { toolProjection, toolsetDigest, toolDigest } from "./identity.js";
import { publisherFromSecret } from "./provenance.js";

export const DESCRIPTOR_SCHEMA = "trustcard.dev/descriptor@1";

const b64u = (buf) => Buffer.from(buf).toString("base64url");

// --- Interface identity ------------------------------------------------------
// The interface identity is the existing semantic projection, digested. It is
// deliberately NOT renamed in a breaking way: toolDigest() is the v1 name and
// stays as an alias; interfaceDigest() is the protocol-neutral name for the
// same bytes. Identity bytes are unchanged, so every existing pin survives.
export function interfaceDigest(tool) {
  return toolDigest(tool);
}

export function interfaceProjection(tool) {
  return toolProjection(tool);
}

// --- Implementation identity -------------------------------------------------
// A typed, honest statement about the code that provides a capability.
//
//   { kind: "npm-dist",   integrity: "sha512-...", algorithm: "sha512" }
//       The npm tarball content hash (dist.integrity). Proves which tarball the
//       registry served. Does NOT prove what executed: postinstall scripts, the
//       npx cache, and transitive dependencies are outside its scope.
//   { kind: "source",     digest: "sha256:..." }
//       A source-commit or build-artifact digest, when the publisher has one.
//   { kind: "unresolved" }
//       No trustworthy artifact identity is derivable. This is a real value,
//       not an error: a descriptor with an unresolved implementation makes a
//       weaker claim and policy should treat it accordingly.
//
// package name+version is NEVER an implementation identity: it is a mutable
// pointer, not a content hash.
export function implementationIdentity(impl) {
  if (!impl || typeof impl !== "object") return { kind: "unresolved" };
  if (impl.kind === "npm-dist" && typeof impl.integrity === "string" && impl.integrity.length > 0) {
    const algorithm = impl.integrity.split("-")[0];
    return { kind: "npm-dist", integrity: impl.integrity, algorithm };
  }
  if (impl.kind === "source" && typeof impl.digest === "string" && impl.digest.length > 0) {
    return { kind: "source", digest: impl.digest };
  }
  return { kind: "unresolved" };
}

// A comparable digest for an implementation identity. `unresolved` has no
// digest (returns null) so it can never be silently equal to a real one.
export function implementationDigest(impl) {
  const id = implementationIdentity(impl);
  if (id.kind === "unresolved") return null;
  return hashJson(id);
}

export function implementationsEqual(a, b) {
  return jsonEqual(implementationIdentity(a), implementationIdentity(b));
}

// --- Descriptor signing payload ----------------------------------------------
// The signed bytes are the descriptor with `signature` and `descriptorDigest`
// removed (descriptorDigest is defined as the hash of this payload, so neither
// can be inside it) — the same coverage rule as v1 manifests (hash.js).
export function descriptorSigningPayload(descriptor) {
  if (!descriptor || typeof descriptor !== "object") throw new TypeError("descriptor must be an object");
  const { signature, descriptorDigest, ...unsigned } = descriptor;
  return unsigned;
}

export function descriptorDigest(descriptor) {
  return hashJson(descriptorSigningPayload(descriptor));
}

// Build an unsigned descriptor for ONE capability (one tool/interface).
export function buildDescriptor({
  tool,
  namespace = null,
  implementation = null,
  publisher,
  issuedAt = new Date().toISOString(),
  expiresAt = null,
  claims = null,
}) {
  if (!tool || typeof tool !== "object") throw new TypeError("tool is required");
  if (!publisher?.keyId || !publisher?.publicKey) throw new TypeError("publisher { keyId, publicKey } is required");
  const projection = interfaceProjection(tool);
  const descriptor = {
    schema: DESCRIPTOR_SCHEMA,
    capability: {
      namespace: namespace ?? tool.name ?? null,
      interfaceDigest: interfaceDigest(tool),
      interface: projection,
    },
    implementation: implementationIdentity(implementation),
    provenance: {
      publisher: publisher.publisher ?? publisher.keyId,
      keyId: publisher.keyId,
      publicKey: publisher.publicKey,
    },
    issuedAt,
    expiresAt,
  };
  if (claims && typeof claims === "object") descriptor.claims = claims;
  descriptor.descriptorDigest = descriptorDigest(descriptor);
  return descriptor;
}

export function signDescriptor(descriptor, privateKeyB64u) {
  const privateKey = createPrivateKey({ key: Buffer.from(privateKeyB64u, "base64url"), type: "pkcs8", format: "der" });
  const payload = canon(descriptorSigningPayload(descriptor));
  const sig = edSign(null, Buffer.from(payload, "utf8"), privateKey);
  const pub = publisherFromSecret(privateKeyB64u);
  return {
    ...descriptor,
    descriptorDigest: descriptorDigest(descriptor),
    signature: { algorithm: "ed25519", keyId: pub.keyId, value: b64u(sig) },
  };
}

// Verify internal consistency + signature. Returns { ok, errors[], keyId, descriptorDigest }.
export function verifyDescriptor(descriptor) {
  const errors = [];
  if (!descriptor || typeof descriptor !== "object") return { ok: false, errors: ["descriptor is not an object"], keyId: null, descriptorDigest: null };
  if (descriptor.schema !== DESCRIPTOR_SCHEMA) errors.push(`unknown schema "${descriptor.schema}"`);
  if (!descriptor.capability?.interfaceDigest) errors.push("missing capability.interfaceDigest");
  if (!descriptor.capability?.interface) errors.push("missing capability.interface");
  if (!descriptor.provenance?.publicKey) errors.push("missing provenance.publicKey");
  if (!descriptor.signature?.value) errors.push("missing signature");

  const keyId = descriptor.provenance?.publicKey
    ? sha256Base64Url(Buffer.from(descriptor.provenance.publicKey, "base64url"))
    : null;
  if (keyId && descriptor.provenance.keyId && descriptor.provenance.keyId !== keyId) {
    errors.push(`provenance.keyId ${descriptor.provenance.keyId} does not match publicKey (${keyId})`);
  }

  // interface digest must match the embedded projection.
  if (descriptor.capability?.interface && descriptor.capability?.interfaceDigest) {
    // Recompute the interface digest from the embedded projection by hashing the
    // projection directly (it is already the semantic projection).
    const recomputed = hashJson(descriptor.capability.interface);
    if (recomputed !== descriptor.capability.interfaceDigest) {
      errors.push(`interfaceDigest mismatch: descriptor says ${descriptor.capability.interfaceDigest}, embedded interface hashes to ${recomputed}`);
    }
  }

  // content-address self-consistency.
  const recomputedDescriptor = descriptorDigest(descriptor);
  if (descriptor.descriptorDigest && descriptor.descriptorDigest !== recomputedDescriptor) {
    errors.push(`descriptorDigest mismatch: descriptor says ${descriptor.descriptorDigest}, payload hashes to ${recomputedDescriptor}`);
  }

  // signature over the same coverage rule.
  if (descriptor.signature?.value && descriptor.provenance?.publicKey) {
    try {
      const publicKey = createPublicKey({ key: Buffer.from(descriptor.provenance.publicKey, "base64url"), type: "spki", format: "der" });
      const payload = canon(descriptorSigningPayload(descriptor));
      const okSig = edVerify(null, Buffer.from(payload, "utf8"), publicKey, Buffer.from(descriptor.signature.value, "base64url"));
      if (!okSig) errors.push("signature verification failed");
      if (descriptor.signature.keyId && keyId && descriptor.signature.keyId !== keyId) {
        errors.push(`signature.keyId ${descriptor.signature.keyId} ≠ publisher key ${keyId}`);
      }
    } catch (e) {
      errors.push(`signature verification error: ${e.message}`);
    }
  }

  if (descriptor.expiresAt && Date.parse(descriptor.expiresAt) < Date.now()) {
    errors.push(`descriptor expired at ${descriptor.expiresAt}`);
  }

  return { ok: errors.length === 0, errors, keyId, descriptorDigest: recomputedDescriptor };
}

// --- Server-manifest ⇄ descriptor-bundle adapters -----------------------------
// A v1 server manifest already embeds full tool definitions; these adapters
// prove the "server manifest = a bundle of capability descriptors" claim with
// real conversions rather than prose.

// Derive one descriptor per tool from a v1 observation/manifest-shaped object.
// Implementation identity is supplied by the caller (it is not in the manifest).
export function manifestToDescriptors({ tools = [], implementation = null, publisher, namespacePrefix = null, issuedAt, expiresAt = null, claims = null }) {
  return (tools ?? []).map((tool) => buildDescriptor({
    tool,
    namespace: namespacePrefix ? `${namespacePrefix}/${tool.name}` : tool.name,
    implementation,
    publisher,
    issuedAt: issuedAt ?? new Date().toISOString(),
    expiresAt,
    claims,
  }));
}

// Bundle descriptors back into a server-manifest-shaped unsigned object, so the
// v1 signing/verification path (provenance.js) can operate over them unchanged.
// The interface embedded in each descriptor becomes the manifest's tool entry.
export function descriptorsToManifestTools(descriptors) {
  return (descriptors ?? []).map((d) => d?.capability?.interface).filter(Boolean);
}

// The set of interface identities in a bundle — the protocol-neutral analog of
// v1's toolsetDigest. Identical bytes to toolsetDigest over the same interfaces.
export function descriptorSetDigest(descriptors) {
  const interfaces = descriptorsToManifestTools(descriptors);
  return toolsetDigest(interfaces);
}
