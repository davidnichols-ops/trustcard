// Receipts: reproducibility for tool calls.
//
// A receipt binds {exact contract version} × {exact arguments} → {result digest}.
// Two calls are *reproducible* when contract digest and arguments digest match;
// comparing resultDigests then tells you whether the server's behavior is
// deterministic under an identical contract — which is the only notion of
// reproducibility that means anything when tools are mutable.
import { readFileSync, appendFileSync, existsSync } from "node:fs";
import { createPublicKey, createPrivateKey, sign as edSign, verify as edVerify, randomBytes } from "node:crypto";
import { canon } from "./canon.js";
import { hashJson, sha256Base64Url } from "./hash.js";
import { publisherFromSecret } from "./provenance.js";

const b64u = (buf) => Buffer.from(buf).toString("base64url");

export function makeReceiptSink(path) {
  return (receipt) => {
    appendFileSync(path, JSON.stringify(receipt) + "\n");
  };
}

export function loadReceipts(path) {
  if (!existsSync(path)) return [];
  return readFileSync(path, "utf8")
    .split("\n")
    .filter(Boolean)
    .map((l) => JSON.parse(l));
}

// Group receipts by (tool, toolsetDigest, argumentsDigest) and report which
// groups produced more than one distinct result — non-reproducible behavior
// under an identical contract.
export function reproducibilityReport(receipts) {
  const groups = new Map();
  for (const r of receipts) {
    const key = [r.tool, r.toolsetDigest, r.argumentsDigest].join("|");
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(r);
  }
  const rows = [];
  for (const [key, rs] of groups) {
    const results = new Set(rs.map((r) => r.resultDigest));
    rows.push({
      tool: rs[0].tool,
      toolsetDigest: rs[0].toolsetDigest,
      argumentsDigest: rs[0].argumentsDigest,
      calls: rs.length,
      distinctResults: results.size,
      reproducible: results.size <= 1,
    });
  }
  return rows;
}

// --- Signed, chained receipts (v2, additive) ---------------------------------
// A v1 receipt is an unsigned local log line: useful for debugging, worthless as
// evidence (anyone can forge or edit it). SignedReceiptChain upgrades a receipt
// into verifiable, replay-resistant evidence:
//   * signed by the relying party's Ed25519 key (non-repudiation);
//   * chained: each receipt embeds the previous receipt's digest, so deletions
//     and reorderings break the chain;
//   * sequenced + nonced: monotonic `seq` makes gaps detectable; `nonce` +
//     timestamp defeat replay.
// The unsigned v1 receipt fields are preserved; signing adds
// { seq, nonce, parentReceipt, receiptDigest, signature }.

export function receiptSigningPayload(receipt) {
  const { signature, receiptDigest, ...unsigned } = receipt;
  return unsigned;
}

export function receiptDigest(receipt) {
  return hashJson(receiptSigningPayload(receipt));
}

export class SignedReceiptChain {
  constructor({ privateKey, relyingParty = null } = {}) {
    if (!privateKey) throw new TypeError("SignedReceiptChain requires a privateKey");
    this.privateKey = privateKey;
    this.relyingParty = relyingParty;
    const pub = publisherFromSecret(privateKey);
    this.keyId = pub.keyId;
    this.publicKey = pub.publicKey;
    this.seq = 0;
    this.head = null; // digest of the most recent receipt
  }

  // Sign + chain a base receipt object. Returns the signed receipt.
  append(baseReceipt) {
    this.seq += 1;
    const unsigned = {
      ...baseReceipt,
      relyingParty: baseReceipt.relyingParty ?? this.relyingParty,
      seq: this.seq,
      nonce: b64u(randomBytes(16)),
      parentReceipt: this.head,
    };
    const digest = receiptDigest(unsigned);
    const privateKey = createPrivateKey({ key: Buffer.from(this.privateKey, "base64url"), type: "pkcs8", format: "der" });
    const sig = edSign(null, Buffer.from(canon(receiptSigningPayload(unsigned)), "utf8"), privateKey);
    const receipt = {
      ...unsigned,
      receiptDigest: digest,
      signature: { algorithm: "ed25519", keyId: this.keyId, value: b64u(sig) },
    };
    this.head = digest;
    return receipt;
  }
}

// Verify a single signed receipt's STRUCTURE: signature present, digest
// self-consistent. This does NOT verify the cryptographic signature (the public
// key is not on the receipt) — use verifyReceiptSignature(receipt, publicKey)
// for that. Returns { ok, errors[], keyId }.
export function verifyReceipt(receipt) {
  const errors = [];
  if (!receipt || typeof receipt !== "object") return { ok: false, errors: ["receipt is not an object"], keyId: null };
  if (!receipt.signature?.value) errors.push("missing signature");
  if (!receipt.signature?.keyId) errors.push("missing signature.keyId");
  if (receipt.receiptDigest && receipt.receiptDigest !== receiptDigest(receipt)) {
    errors.push("receiptDigest mismatch");
  }
  return { ok: errors.length === 0, errors, keyId: receipt.signature?.keyId ?? null };
}

// Full signature verification of a receipt against a known public key.
export function verifyReceiptSignature(receipt, publicKeyB64u) {
  const errors = [];
  if (!receipt?.signature?.value) return { ok: false, errors: ["missing signature"] };
  const derivedKeyId = sha256Base64Url(Buffer.from(publicKeyB64u, "base64url"));
  if (receipt.signature.keyId && receipt.signature.keyId !== derivedKeyId) {
    errors.push(`signature.keyId ${receipt.signature.keyId} ≠ public key ${derivedKeyId}`);
  }
  try {
    const publicKey = createPublicKey({ key: Buffer.from(publicKeyB64u, "base64url"), type: "spki", format: "der" });
    const okSig = edVerify(null, Buffer.from(canon(receiptSigningPayload(receipt)), "utf8"), publicKey, Buffer.from(receipt.signature.value, "base64url"));
    if (!okSig) errors.push("signature verification failed");
  } catch (e) {
    errors.push(`signature verification error: ${e.message}`);
  }
  return { ok: errors.length === 0, errors, keyId: derivedKeyId };
}

// Verify an ordered list of receipts forms an unbroken, UNFORGED chain.
//
// For each receipt this (a) RECOMPUTES receiptDigest from the payload and
// requires it to match the embedded field — otherwise an attacker could tamper
// the body and keep the original digest, and the parentReceipt links would
// still line up; and (b) checks monotonic seq and that each parentReceipt
// matches the previous receipt's *actual* digest. Returns
// { ok, errors[], count, gaps[] }.
export function verifyReceiptChain(receipts) {
  const errors = [];
  const gaps = [];
  let prev = null;
  let prevActualDigest = null;
  for (let i = 0; i < receipts.length; i++) {
    const r = receipts[i];
    // (a) content integrity: the embedded receiptDigest must be the real hash.
    const actualDigest = receiptDigest(r);
    if (r.receiptDigest !== actualDigest) {
      errors.push(`receipt ${i} digest mismatch: embedded ${r.receiptDigest} ≠ computed ${actualDigest} (content forged)`);
    }
    if (i === 0) {
      if (r.parentReceipt !== null && r.parentReceipt !== undefined) {
        errors.push("first receipt has a non-null parentReceipt");
      }
    } else {
      if (r.seq !== prev.seq + 1) {
        gaps.push({ index: i, expectedSeq: prev.seq + 1, gotSeq: r.seq });
        errors.push(`seq gap at index ${i}: expected ${prev.seq + 1}, got ${r.seq}`);
      }
      // (b) link to the previous receipt's ACTUAL digest, not its claim.
      if (r.parentReceipt !== prevActualDigest) {
        errors.push(`chain break at index ${i}: parentReceipt ${r.parentReceipt} ≠ previous receiptDigest ${prevActualDigest}`);
      }
    }
    prev = r;
    prevActualDigest = actualDigest;
  }
  return { ok: errors.length === 0, errors, count: receipts.length, gaps };
}
