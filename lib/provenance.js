// Provenance: who vouches for this exact toolset?
//
// A trustcard manifest binds:
//   server identity (name+version) + protocol versions + complete tool definitions
// to a publisher's Ed25519 key. Verification proves:
//   1. integrity    — the tool definitions are bit-identical to what the
//                     publisher signed (via JCS + SHA-256 digests);
//   2. authenticity — the holder of the publisher key signed them;
//   3. continuity   — the key is the same key this client pinned before (TOFU).
//
// Threat-model notes:
//   - A compromised *server* cannot forge the publisher's signature, so an
//     attacker who mutates tools/list at runtime is caught by digest mismatch.
//   - A compromised *publisher key* is out of scope; key rotation is break-glass
//     (old key signs the new one) and always requires client re-approval.
//   - Signatures are detached and the signing payload is the manifest with the
//     `signature` field removed, canonicalized with JCS.
import { generateKeyPairSync, sign as edSign, verify as edVerify, createPublicKey, createPrivateKey } from "node:crypto";
import { canon } from "./canon.js";
import { sha256Base64Url, hashManifestPayload, signingPayload } from "./hash.js";
import { MANIFEST_SCHEMA_VERSION, toolsetDigest, serverDigest, toolDigest } from "./identity.js";

const b64u = (buf) => Buffer.from(buf).toString("base64url");

export function generatePublisherKeypair() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pubDer = publicKey.export({ type: "spki", format: "der" });
  const privDer = privateKey.export({ type: "pkcs8", format: "der" });
  return {
    publicKey: b64u(pubDer),
    privateKey: b64u(privDer),
    keyId: sha256Base64Url(pubDer),
  };
}

export function publisherFromSecret(privateKeyB64u) {
  const privateKey = createPrivateKey({ key: Buffer.from(privateKeyB64u, "base64url"), type: "pkcs8", format: "der" });
  const publicKey = createPublicKey(privateKey);
  const pubDer = publicKey.export({ type: "spki", format: "der" });
  return { publicKey: b64u(pubDer), keyId: sha256Base64Url(pubDer) };
}

// Build an unsigned manifest from a live observation.
export function buildManifest({ serverInfo, protocolVersion, supportedVersions, tools, publisher, generatedBy = "mcp-trustcard", expiresAt = null }) {
  const manifest = {
    schema: MANIFEST_SCHEMA_VERSION,
    server: {
      name: serverInfo?.name ?? null,
      version: serverInfo?.version ?? null,
    },
    protocol: {
      negotiated: protocolVersion ?? null,
      supported: supportedVersions ?? (protocolVersion ? [protocolVersion] : []),
    },
    tools: tools ?? [],
    toolsetDigest: toolsetDigest(tools),
    toolDigests: Object.fromEntries((tools ?? []).map((t) => [t.name, toolDigest(t)])),
    publisher: {
      keyId: publisher.keyId,
      publicKey: publisher.publicKey,
    },
    issuedAt: new Date().toISOString(),
    expiresAt,
    generator: generatedBy,
  };
  manifest.serverDigest = serverDigest({ serverInfo, protocolVersion, tools });
  manifest.manifestDigest = hashManifestPayload(manifest);
  return manifest;
}

// A proxy-enforcement manifest (gen-manifest / lib/manifest.js output) is a
// local call-time policy document — it is NEVER a provenance object and must
// not be signed. Detected by shape, not by filename.
export function isProxyManifest(m) {
  if (!m || typeof m !== "object") return false;
  if (m.schema === MANIFEST_SCHEMA_VERSION) return false;
  if (m.version === 1 || typeof m.manifestHash === "string") return true;
  return Array.isArray(m.tools) && m.tools.some((t) => t && typeof t === "object" && typeof t.schemaHash === "string");
}

// Publisher placeholders produced by `manifest` without --key and by fixtures.
const KEYLESS_KEY_IDS = new Set(["unpublished", "unsigned", "", "sha256:unsigned", "sha256:unpublished"]);

export function signManifest(manifest, privateKeyB64u) {
  if (isProxyManifest(manifest)) {
    throw new Error(
      "input is a proxy-enforcement manifest (gen-manifest format). Proxy manifests are local call-time " +
      "policy and are not signed; 'sign' expects a provenance manifest from 'mcp-trustcard manifest'."
    );
  }
  if (!manifest || typeof manifest !== "object" || manifest.schema !== MANIFEST_SCHEMA_VERSION) {
    throw new Error(`input is not a provenance manifest (expected schema "${MANIFEST_SCHEMA_VERSION}")`);
  }
  const privateKey = createPrivateKey({ key: Buffer.from(privateKeyB64u, "base64url"), type: "pkcs8", format: "der" });
  const pub = publisherFromSecret(privateKeyB64u);

  // Publisher identity is derived from the signing secret — never trusted from
  // the input. A manifest that already declares a *different* key is a
  // conflict: signing it would produce a document no verifier accepts.
  const claimed = manifest.publisher ?? {};
  const claimedPub = typeof claimed.publicKey === "string" && claimed.publicKey ? claimed.publicKey : null;
  const claimedKeyId = typeof claimed.keyId === "string" && !KEYLESS_KEY_IDS.has(claimed.keyId) ? claimed.keyId : null;
  if (claimedPub && claimedPub !== pub.publicKey) {
    throw new Error(`manifest publisher.publicKey does not match the signing key (${pub.keyId}); refusing to sign a manifest whose declared publisher differs from the signer`);
  }
  if (claimedKeyId && claimedKeyId !== pub.keyId) {
    throw new Error(`manifest publisher.keyId ${claimedKeyId} does not match the signing key ${pub.keyId}; refusing to sign a manifest whose declared publisher differs from the signer`);
  }
  const publisher = { ...claimed, keyId: pub.keyId, publicKey: pub.publicKey };

  const { signature: _s, manifestDigest: _d, publisher: _p, ...rest } = manifest;
  const unsignedPayload = { ...rest, publisher };
  const payload = canon(unsignedPayload); // == signingPayload(unsignedPayload)
  const sig = edSign(null, Buffer.from(payload, "utf8"), privateKey);
  return {
    ...unsignedPayload,
    manifestDigest: hashManifestPayload(unsignedPayload),
    signature: {
      algorithm: "ed25519",
      keyId: pub.keyId,
      value: b64u(sig),
    },
  };
}

// --- Trust anchoring ---------------------------------------------------------
// Cryptographic validity and trust are different questions. A manifest signed
// by a key nobody knows is *valid* but *self-asserted*: an attacker can mint
// a keypair and produce a perfectly valid signature for a malicious manifest.
// Trust requires an out-of-band anchor: an explicit publisher public key /
// keyId supplied by the relying party, or a pin-store entry the relying party
// recorded earlier (TOFU continuity).

// Normalize one trust anchor into { keyId?, publicKey? }.
// Accepts "sha256:..." keyIds, base64url spki public keys, or key-file-shaped
// objects ({ keyId, publicKey } — privateKey fields are ignored, never used).
export function normalizeTrustedKey(input) {
  if (!input) return null;
  if (typeof input === "string") {
    const s = input.trim();
    if (!s) return null;
    return s.startsWith("sha256:") ? { keyId: s } : { publicKey: s };
  }
  if (typeof input === "object") {
    const out = {};
    if (typeof input.publicKey === "string" && input.publicKey) out.publicKey = input.publicKey;
    if (typeof input.keyId === "string" && input.keyId) out.keyId = input.keyId;
    return out.publicKey || out.keyId ? out : null;
  }
  return null;
}

function anchorMatches(anchor, publisher, keyId) {
  if (!anchor.publicKey && !anchor.keyId) return false;
  if (anchor.publicKey && anchor.publicKey !== publisher?.publicKey) return false;
  if (anchor.keyId && anchor.keyId !== keyId) return false;
  return true;
}

// Verify a manifest's internal consistency + signature.
// Returns { ok, errors[], keyId, trusted, trust }.
//   ok      — structural + cryptographic validity only (unchanged semantics).
//   trust   — { level: "anchored" | "self-asserted" | "untrusted", anchored, keyId, detail }
//   trusted — ok AND anchored. With no anchors supplied a manifest can never
//             be "trusted": its key is self-asserted, so trusted === false even
//             when the signature is cryptographically valid.
export function verifyManifest(manifest, { trustedKeys = null } = {}) {
  const errors = [];
  if (!manifest || typeof manifest !== "object") return { ok: false, errors: ["manifest is not an object"], keyId: null, trusted: false, trust: { level: "untrusted", anchored: false, keyId: null, detail: "manifest is not an object" } };
  if (manifest.schema !== MANIFEST_SCHEMA_VERSION) errors.push(`unknown schema "${manifest.schema}"`);
  if (!manifest.signature?.value) errors.push("missing signature");
  if (!manifest.publisher?.publicKey) errors.push("missing publisher.publicKey");

  const keyId = manifest.publisher?.publicKey ? sha256Base64Url(Buffer.from(manifest.publisher.publicKey, "base64url")) : null;
  if (keyId && manifest.publisher.keyId && manifest.publisher.keyId !== keyId) {
    errors.push(`publisher.keyId ${manifest.publisher.keyId} does not match publicKey (${keyId})`);
  }

  // digest self-consistency
  const recomputed = hashManifestPayload(manifest);
  if (manifest.manifestDigest && manifest.manifestDigest !== recomputed) {
    errors.push(`manifestDigest mismatch: manifest says ${manifest.manifestDigest}, payload hashes to ${recomputed}`);
  }
  const recomputedToolset = toolsetDigest(manifest.tools);
  if (manifest.toolsetDigest && manifest.toolsetDigest !== recomputedToolset) {
    errors.push(`toolsetDigest mismatch: manifest says ${manifest.toolsetDigest}, tools hash to ${recomputedToolset}`);
  }
  const recomputedServer = serverDigest({ serverInfo: manifest.server, protocolVersion: manifest.protocol?.negotiated, tools: manifest.tools });
  if (manifest.serverDigest && manifest.serverDigest !== recomputedServer) {
    errors.push(`serverDigest mismatch: manifest says ${manifest.serverDigest}, recomputed ${recomputedServer}`);
  }

  // signature
  if (manifest.signature?.value && manifest.publisher?.publicKey) {
    try {
      const publicKey = createPublicKey({ key: Buffer.from(manifest.publisher.publicKey, "base64url"), type: "spki", format: "der" });
      const payload = canon(signingPayload(manifest));
      const okSig = edVerify(null, Buffer.from(payload, "utf8"), publicKey, Buffer.from(manifest.signature.value, "base64url"));
      if (!okSig) errors.push("signature verification failed");
      if (manifest.signature.keyId && keyId && manifest.signature.keyId !== keyId) {
        errors.push(`signature.keyId ${manifest.signature.keyId} ≠ publisher key ${keyId}`);
      }
    } catch (e) {
      errors.push(`signature verification error: ${e.message}`);
    }
  }

  if (manifest.expiresAt && Date.parse(manifest.expiresAt) < Date.now()) {
    errors.push(`manifest expired at ${manifest.expiresAt}`);
  }

  // Trust anchoring — evaluated independently of the cryptographic checks so
  // callers can distinguish "valid signature" from "trusted publisher".
  const anchors = (trustedKeys ?? []).map(normalizeTrustedKey).filter(Boolean);
  let trust;
  if (anchors.length === 0) {
    trust = {
      level: "self-asserted",
      anchored: false,
      keyId,
      detail: "no out-of-band trust anchor supplied — the publisher key is self-asserted; a valid signature only proves the holder of that key signed it",
    };
  } else if (!keyId) {
    trust = {
      level: "untrusted",
      anchored: false,
      keyId: null,
      detail: "no usable publisher key in manifest — cannot be anchored",
    };
  } else {
    const matched = anchors.some((a) => anchorMatches(a, manifest.publisher, keyId));
    trust = matched
      ? { level: "anchored", anchored: true, keyId, detail: "publisher key matches a supplied trust anchor" }
      : { level: "untrusted", anchored: false, keyId, detail: "publisher key does not match any supplied trust anchor — cryptographic validity alone does not establish trust" };
  }

  const ok = errors.length === 0;
  return { ok, errors, keyId, trusted: ok && trust.anchored, trust };
}

// Compare a verified manifest against a live observation.
// Catches a server that serves different tools than its publisher signed.
export function bindingConsistency(manifest, observation) {
  const problems = [];
  if (manifest.toolsetDigest !== observation.toolsetDigest) {
    problems.push(`toolset drift: manifest ${manifest.toolsetDigest} vs observed ${observation.toolsetDigest}`);
  }
  if (manifest.server?.name && observation.serverInfo?.name && manifest.server.name !== observation.serverInfo.name) {
    problems.push(`server name drift: manifest "${manifest.server.name}" vs observed "${observation.serverInfo.name}"`);
  }
  return { consistent: problems.length === 0, problems };
}
