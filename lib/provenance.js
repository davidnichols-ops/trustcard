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

export function signManifest(manifest, privateKeyB64u) {
  const privateKey = createPrivateKey({ key: Buffer.from(privateKeyB64u, "base64url"), type: "pkcs8", format: "der" });
  const payload = canon(signingPayload(manifest));
  const sig = edSign(null, Buffer.from(payload, "utf8"), privateKey);
  const pub = publisherFromSecret(privateKeyB64u);
  const { signature: _s, manifestDigest: _d, ...unsignedPayload } = manifest;
  return {
    ...unsignedPayload,
    manifestDigest: hashManifestPayload(manifest),
    signature: {
      algorithm: "ed25519",
      keyId: pub.keyId,
      value: b64u(sig),
    },
  };
}

// Verify a manifest's internal consistency + signature.
// Returns { ok, errors[], keyId }.
export function verifyManifest(manifest) {
  const errors = [];
  if (!manifest || typeof manifest !== "object") return { ok: false, errors: ["manifest is not an object"], keyId: null };
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

  return { ok: errors.length === 0, errors, keyId };
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
