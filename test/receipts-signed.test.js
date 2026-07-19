import { test } from "node:test";
import assert from "node:assert/strict";
import { generatePublisherKeypair } from "../lib/provenance.js";
import {
  SignedReceiptChain,
  verifyReceipt,
  verifyReceiptSignature,
  verifyReceiptChain,
  receiptDigest,
} from "../lib/receipts.js";
import { Guard } from "../lib/guard.js";
import { TrustStore } from "../lib/trust.js";
import { toolsetDigest, serverDigest, toolDigest } from "../lib/identity.js";
import { TOOL_SEARCH } from "./helpers.js";

const keys = generatePublisherKeypair();
const SID = { name: "fake-server", version: "1.0.0" };

function makeSession(tools) {
  const trust = new TrustStore();
  const observation = {
    tools,
    toolsetDigest: toolsetDigest(tools),
    serverDigest: serverDigest({ serverInfo: SID, protocolVersion: "2025-06-18", tools }),
    toolDigests: Object.fromEntries(tools.map((t) => [t.name, toolDigest(t)])),
    protocolVersion: "2025-06-18",
  };
  trust.observe(SID, observation);
  trust.pin(SID, observation);
  return { serverId: SID, trust, observation };
}

const base = (tool = "search") => ({ schema: "trustcard.dev/receipt@1", at: new Date().toISOString(), tool, argumentsDigest: "sha256:x" });

test("signed receipt verifies against the relying party's public key", () => {
  const chain = new SignedReceiptChain({ privateKey: keys.privateKey, relyingParty: "agent-a" });
  const r = chain.append(base());
  assert.equal(r.seq, 1);
  assert.equal(r.parentReceipt, null);
  assert.match(r.receiptDigest, /^sha256:/);
  assert.equal(r.signature.keyId, keys.keyId);
  assert.equal(verifyReceipt(r).ok, true);
  assert.equal(verifyReceiptSignature(r, keys.publicKey).ok, true);
});

test("a forged/edited receipt fails signature verification", () => {
  const chain = new SignedReceiptChain({ privateKey: keys.privateKey });
  const r = chain.append(base());
  const bad = JSON.parse(JSON.stringify(r));
  bad.tool = "exfiltrate"; // tamper after signing
  assert.equal(verifyReceipt(bad).ok, false); // digest no longer self-consistent
  assert.equal(verifyReceiptSignature(bad, keys.publicKey).ok, false);
});

test("wrong public key fails verification", () => {
  const chain = new SignedReceiptChain({ privateKey: keys.privateKey });
  const r = chain.append(base());
  const other = generatePublisherKeypair();
  assert.equal(verifyReceiptSignature(r, other.publicKey).ok, false);
});

test("chain: seq is monotonic and parentReceipt links to the previous digest", () => {
  const chain = new SignedReceiptChain({ privateKey: keys.privateKey });
  const r1 = chain.append(base());
  const r2 = chain.append(base());
  const r3 = chain.append(base());
  assert.deepEqual([r1.seq, r2.seq, r3.seq], [1, 2, 3]);
  assert.equal(r2.parentReceipt, r1.receiptDigest);
  assert.equal(r3.parentReceipt, r2.receiptDigest);
  assert.equal(verifyReceiptChain([r1, r2, r3]).ok, true);
});

test("chain: a deleted middle receipt breaks the chain (detectable)", () => {
  const chain = new SignedReceiptChain({ privateKey: keys.privateKey });
  const r1 = chain.append(base());
  chain.append(base()); // r2 — dropped
  const r3 = chain.append(base());
  const res = verifyReceiptChain([r1, r3]); // missing r2
  assert.equal(res.ok, false);
  assert.ok(res.errors.some((e) => /chain break|seq gap/.test(e)));
});

test("chain: reordering receipts breaks the chain", () => {
  const chain = new SignedReceiptChain({ privateKey: keys.privateKey });
  const r1 = chain.append(base());
  const r2 = chain.append(base());
  assert.equal(verifyReceiptChain([r2, r1]).ok, false);
});

test("nonces are unique across receipts (replay resistance)", () => {
  const chain = new SignedReceiptChain({ privateKey: keys.privateKey });
  const a = chain.append(base());
  const b = chain.append(base());
  assert.notEqual(a.nonce, b.nonce);
});

test("guard emits signed+chained receipts when a receiptKey is configured", async () => {
  const receipts = [];
  const guard = new Guard({ mode: "enforce", receiptKey: keys.privateKey, relyingParty: "agent-a", receiptSink: (r) => receipts.push(r) });
  const session = makeSession([TOOL_SEARCH]);
  await guard.authorizeCall({ session, tool: "search", args: { query: "x" } });
  guard.recordReceipt({ session, tool: "search", args: { query: "x" }, result: { content: [] } });
  guard.recordReceipt({ session, tool: "search", args: { query: "y" }, result: { content: [] } });
  assert.equal(receipts.length, 2);
  assert.equal(receipts[0].seq, 1);
  assert.equal(receipts[1].parentReceipt, receipts[0].receiptDigest);
  assert.equal(verifyReceiptSignature(receipts[0], keys.publicKey).ok, true);
  // v1 fields still present (backward compatible)
  assert.match(receipts[0].toolsetDigest, /^sha256:/);
  assert.match(receipts[0].argumentsDigest, /^sha256:/);
});

test("guard without a receiptKey emits the v1 unsigned receipt unchanged", async () => {
  const receipts = [];
  const guard = new Guard({ mode: "enforce", receiptSink: (r) => receipts.push(r) });
  const session = makeSession([TOOL_SEARCH]);
  guard.recordReceipt({ session, tool: "search", args: { query: "x" }, result: { content: [] } });
  assert.equal(receipts[0].signature, undefined);
  assert.equal(receipts[0].seq, undefined);
  assert.match(receipts[0].argumentsDigest, /^sha256:/);
});
