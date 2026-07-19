# Trustcard v2.0 — pre-release adversarial security audit

**Date:** 2026-07-19
**Scope:** the v2 enforcement surface — capability descriptors, the two-gate
invocation policy, signed+chained receipts, and publisher key rotation/revocation —
plus the v1 controls they build on (manifests, digests, pinning, trust states).
**Method:** adversarial. Every attack class in [`THREAT-MODEL.md`](THREAT-MODEL.md)
was executed as a real, runnable test against the actual code paths
(`test/adversarial.test.js`, `test/audit-probes.test.js`). Findings were fixed in
code and pinned by regression tests. Nothing below is asserted without a passing test.

**Result:** `npm test` → **164 tests, 164 pass, 0 fail** (18 files).

---

## 1. Verdict

**The v2.0 code is fit to release after the two fixes in §3.** Both were
release-blocking; both are now closed and pinned. The trust properties the
project advertises hold under the executed attacks, *within* the stated trust
boundary (§5). The controls that remain partial do so by explicit design
(non-goals), not by defect.

---

## 2. What was attacked

| # | Attack | Outcome |
|---|---|---|
| A1 | **Forged descriptor** (wrong-key or stripped signature) | Rejected — never reaches trusted state. ✅ held |
| A2 | **Descriptor mutation after approval** (edit any field) | Gate 2 recomputes the capability digest per call → MISMATCH → denied. ✅ held |
| A3 | **Argument injection** at Gate 2 (`../../etc/passwd` path traversal) | Denied by `InvocationPolicy` re-validating args against the approved schema + arg policy. ✅ held |
| A4 | **Cross-agent authorization bleed** (agent A's approval reused by agent B) | Decisions scoped to (agentId, capabilityDigest); not honored across agentIds. ✅ held |
| A5 | **Receipt/capability mismatch** (receipt referencing a different tool) | `capabilityDigest` pins the receipt to the exact approved tool. ✅ held |
| A6 | **Receipt chain forgery** (tamper a receipt *body*, keep chain fields) | **FAILED → FIXED** (Finding 1). Chain now recomputes digests. ✅ held |
| GAP-rot | **Rotation replay** (re-present an old rotation cert) | **FAILED → FIXED** (Finding 2). Expiry now enforced. ✅ held |
| GAP-rev | **Revocation expiry** (wait for a revocation to lapse) | Closed by design — revocations never expire. ✅ held |
| P1–P6 | **Change classification probes** (§6) | 6/6 classify correctly. ✅ held |

`test/adversarial.test.js` = A1–A6 + GAP + regression pins (11 tests).
`test/audit-probes.test.js` = P1–P6 descriptor-identity and classification probes (6 tests).

---

## 3. Findings (both release-blocking, both fixed)

### Finding 1 — receipt-chain verification trusted embedded digests  *(fixed)*

- **Severity:** release-blocking.
- **Where:** `verifyReceiptChain` in `lib/receipts.js`.
- **Bug:** the chain verifier compared each receipt's `parentReceipt` linkage but
  **trusted the embedded `receiptDigest` field instead of recomputing it** from
  the payload. A tampered receipt *body* (different result, different args) that
  kept its original `receiptDigest` and `parentReceipt` **passed** chain
  verification — the chain looked unbroken over forged history.
- **Attack executed:** A6 — `expected false, got true`.
- **Fix:** `verifyReceiptChain` now **recomputes** `receiptDigest` from each
  payload and requires it to equal the embedded value before accepting linkage.
  A forged body breaks self-consistency *and* the chain.
- **Pinned by:** A6 body-tamper case + a dedicated regression test.

### Finding 2 — rotation/revocation certs carried no expiry  *(fixed)*

- **Severity:** release-blocking (asymmetric trust-window bug).
- **Where:** `lib/rotation.js` (`buildRotationCertificate`,
  `verifyRotationCertificate`, `verifyRevocationCertificate`).
- **Bug:** manifests already enforce `expiresAt` (`lib/provenance.js:131`), but
  rotation certificates accepted `issuedAt` with **no expiry check**. A rotation
  cert — which authorizes *a stolen old key to keep handing off trust* — could be
  replayed indefinitely.
- **Fix:** rotation certs now support and **enforce** `expiresAt`
  (backward-compatible: absent = no expiry, matching prior behavior). A lapsed
  rotation is rejected. **Revocation deliberately has no expiry** — a revocation
  must never lapse, or an attacker could simply wait it out and reuse the key.
  The asymmetry (rotation expires, revocation doesn't) is the control.
- **Pinned by:** the strengthened GAP adversarial test asserting the rotation
  expiry is honored.

---

## 4. Descriptor-identity classification (probes P1–P6)

These pin *how* MCP-specific changes classify, so the release can state precisely
which changes are informational, authorization-relevant, or trust-breaking.
All six are `compatible: false` except the pure no-op.

| Change | classification | compatible? |
|---|---|---|
| Pure no-op (identical descriptor) | all axes `NONE` | **true** |
| Description rewrite, same schema | `interface: ANNOTATION_DOWNGRADE` | false — prose is behavioral, not cosmetic |
| Permission expansion (`readOnly`→`destructive`) | `permission: EXPANSION` | false |
| Implementation swap, identical interface | `interface: NONE`, `implementation: REPLACED` | false — same contract, different artifact |
| Publisher key change (old+new present) | `provenance: KEY_ROTATION` | false — any provenance movement re-approves |
| Publisher key removed | `provenance: PUBLISHER_CHANGE` | false |
| Tool rename | `interface` change (name is in the projection) | false |

Notable design confirmations:

- **A description rewrite is *not* compatible.** Free-text descriptions change
  what an agent *does*, so trustcard refuses to auto-accept them even when the
  JSON schema is untouched. This is the tool-poisoning control (threat #1).
- **Same interface + swapped implementation is *not* compatible.** Bit-for-bit
  contract identity is necessary but not sufficient; the artifact under the
  contract must also match (threat #5).
- **Any provenance movement forces re-approval.** Rotating or removing the
  publisher key is never silently compatible (threats #6, #8).

---

## 5. Trust boundary & explicit non-goals (unchanged by this audit)

trustcard proves **identity and provenance of the contract**, not behavior:

- A signed receipt is **evidence of a decision, not proof of execution.** The
  relying party signs its own record; it can sign a receipt for a call that never
  happened and it will still verify. Proving execution needs a countersigned
  receipt or a transparency log — documented non-goals. (SPEC §12.1, added this
  audit.)
- Signatures establish **provenance, not publisher honesty** (threat #7).
- A server that **lies in its annotations** (says read-only, is destructive)
  can't be detected by cryptography (threat #4). Annotations are hints.
- **TOCTOU** between Gate 2 and the actual transport send is bounded by receipts,
  not eliminated, for non-cooperating servers (threats #2, #19).
- The schema/annotation **contract is the boundary**: a too-loose schema that
  admits a hostile-but-valid argument is a contract-author problem, not a
  trustcard gap (threat #14).

---

## 6. Test & verification evidence

- **Suite:** `npm test` → `# tests 164, # pass 164, # fail 0` (18 files,
  0 cancelled/skipped/todo).
- **Clean install:** `npm pack` → 24 files; fresh `npm install` of the tarball in
  a temp dir; all v2 entry points import cleanly (`buildDescriptor`, `Guard`,
  `SignedReceiptChain`, `buildRotationCertificate`, `InvocationPolicy`).
- **CLI:** `bin/mcp-trustcard.js --help` lists the full command surface.
- **Docs:** README test badge/count updated to 164; v2 docs (DESCRIPTOR,
  TRUST-SUBSTRATE) linked; SPEC §12.1 receipt semantics and §13.1 rotation expiry
  documented; THREAT-MODEL v2 attack table (#12–#19) added.

## 7. Files changed in this audit

- `lib/receipts.js` — `verifyReceiptChain` recomputes `receiptDigest` (Finding 1).
- `lib/rotation.js` — rotation certs enforce `expiresAt`; revocation exempt (Finding 2).
- `test/adversarial.test.js` — A1–A6 + GAP + regression pins.
- `test/audit-probes.test.js` — P1–P6 classification probes.
- `docs/SPEC.md` — §12.1 receipt semantics; §13.1 rotation expiry.
- `docs/THREAT-MODEL.md` — v2 attack table (#12–#19).
- `README.md` — test counts, v2 features, doc links.
- `docs/AUDIT-REPORT-v2.md` — this report.
