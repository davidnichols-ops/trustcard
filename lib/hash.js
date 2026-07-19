// Hashing primitives. All trustcard digests are SHA-256 over RFC 8785 (JCS)
// canonical bytes, rendered as `sha256:<base64url>` — the same style as
// SRI/npm integrity fields, so digests interoperate with existing tooling.
import { createHash } from "node:crypto";
import { canon } from "./canon.js";

export function sha256Base64Url(bytes) {
  return "sha256:" + createHash("sha256").update(bytes).digest("base64url");
}

// Canonical-hash any JSON value.
export function hashJson(value) {
  return sha256Base64Url(canon(value));
}

// The manifest signing payload excludes `signature` AND `manifestDigest`:
// the digest is defined as the hash of this payload, so neither can be in it.
export function signingPayload(manifest) {
  if (!manifest || typeof manifest !== "object") throw new TypeError("manifest must be an object");
  const { signature, manifestDigest, ...unsigned } = manifest;
  return unsigned;
}

export function hashManifestPayload(manifest) {
  return hashJson(signingPayload(manifest));
}
