# Trustcard Protocol Specification v1

Status: draft. This document is the normative reference for the trustcard
manifest format, identity digests, change classification, trust-state machine,
and the client/server behaviors that close the discovery↔execution gap.

The key words **MUST**, **SHOULD**, and **MAY** are to be interpreted as in
RFC 2119.

---

## 1. Canonicalization

All digests are computed over the **RFC 8785 (JSON Canonicalization Scheme,
JCS)** byte serialization of a JSON value. JCS is chosen because:

- it is a published, implementation-independent standard with test vectors;
- it is deterministic for all JSON-representable values;
- it requires no schema — two parties canonicalize the same value identically.

Implementations **MUST** produce byte-identical output to RFC 8785. Numbers
**MUST** use the ECMAScript `Number::toString` shortest round-trip form with
`e+n` / `e-n` exponents and no leading zeros; object keys **MUST** be sorted
by UTF-16 code units; only the mandatory JSON string escapes are emitted.

The reference implementation is `lib/canon.js`.

## 2. Digests

A digest is `sha256:<base64url>` — the SHA-256 of the JCS bytes, base64url
encoded, prefixed with `sha256:`. This mirrors SRI/npm `integrity` syntax so
trustcard digests interoperate with existing supply-chain tooling.

```
digest(value) = "sha256:" + base64url(SHA256(JCS(value)))
```

## 3. Tool identity

### 3.1 The semantic projection

A tool definition has a **semantic projection**: the subset of fields that
change what an agent can do, or what it believes a tool does. The projection
contains exactly:

| field | why it is semantic |
|---|---|
| `name` | the call target |
| `description` | instructions to the model (poisoning vector) |
| `inputSchema` | the accepted-arguments contract |
| `outputSchema` | the structured-output contract |
| `annotations.{title,readOnlyHint,destructiveHint,idempotentHint,openWorldHint}` | behavioral permission hints |
| `execution` | dispatch semantics (e.g. `taskSupport`) |

All other fields — `title` (top-level), `icons`, `tags`, and arbitrary `_meta`
— are **volatile**: they **MUST NOT** appear in the projection. Changing only
volatile fields is a *syntactic* change and **MUST NOT** alter the digest.

### 3.2 Digests

```
toolDigest(tool)        = digest(projection(tool))
toolsetDigest(tools)    = digest({ toolset: sort([ toolDigest(t) for t in tools ]) })
serverDigest(binding)   = digest({
                            server: { name, version, title },
                            protocolVersion,
                            toolset: toolsetDigest(tools)
                          })
```

- `toolsetDigest` is **order-independent** (digests are sorted before hashing).
- `serverDigest` binds *who answered* (serverInfo), *which protocol was
  negotiated*, and *the exact toolset* into one value. Any drift in any of
  the three changes it.

## 4. Change classification

Given a pinned toolset and a newly observed toolset, the differ classifies the
transition into one of six ordered levels:

```
NONE  <  SYNTACTIC  <  NON_BREAKING  <  ANNOTATION_DOWNGRADE  <  PERMISSION_CHANGE  <  BREAKING
```

A transition is **compatible** (auto-repinnable) iff its level ≤ NON_BREAKING.

### 4.1 Syntactic

Only volatile fields changed. Semantic digests are identical.

### 4.2 Semantic, non-breaking

- a tool is **added**;
- an **optional** input property is added;
- an input domain is **widened** (type added to a union, enum grown, constraint
  relaxed, `additionalProperties` opened, constraint removed);
- a `required` entry is removed;
- an `outputSchema` is added.

### 4.3 Semantic, breaking

- a tool is **removed**;
- a **required** input property is added;
- an input domain is **narrowed**: type removed from a union, enum/const shrunk,
  `minimum/minLength/...` increased, `maximum/maxLength/...` decreased,
  `pattern`/`format`/`multipleOf`/`uniqueItems` added or tightened,
  `additionalProperties` closed, a composition keyword (`oneOf/anyOf/allOf/not/if`)
  introduced;
- the `outputSchema` is narrowed in a way that can invalidate prior consumers.

### 4.4 Permission change

- any of `readOnlyHint` / `destructiveHint` / `idempotentHint` / `openWorldHint`
  changes;
- `execution` (e.g. `taskSupport`) changes;
- the `outputSchema` is removed (structured output no longer guaranteed).

### 4.5 Annotation downgrade (suspected tool poisoning)

- the `description` is **materially rewritten** (token-set Jaccard < 0.6)
  **while the schemas are unchanged**. This is the signature of a tool-poisoning
  attack: the machine-checkable contract is untouched, but the instructions to
  the model are replaced. It is incompatible and **MUST NOT** be auto-repinned.

The reference implementation is `lib/diff.js`.

## 5. The manifest

A trustcard manifest is a signed JSON document binding a server's identity and
its complete tool definitions to a publisher key. Filename convention:
`trustcard.manifest.json`.

```jsonc
{
  "schema": "trustcard.dev/manifest@1",
  "server":    { "name": "...", "version": "..." },
  "protocol":  { "negotiated": "2025-06-18", "supported": ["2025-06-18"] },
  "tools":     [ /* complete tool definitions, as served by tools/list */ ],
  "toolsetDigest":  "sha256:...",
  "toolDigests":    { "<toolName>": "sha256:..." },
  "serverDigest":   "sha256:...",
  "publisher": { "keyId": "sha256:...", "publicKey": "<base64url spki>" },
  "issuedAt":  "2026-07-19T00:00:00Z",
  "expiresAt": null,
  "generator": "mcp-trustcard@1.0.0",
  "manifestDigest": "sha256:...",
  "signature": { "algorithm": "ed25519", "keyId": "sha256:...", "value": "<base64url>" }
}
```

### 5.1 Signing payload

The signing payload is the manifest with **both** `signature` and
`manifestDigest` removed, canonicalized with JCS. `manifestDigest` is defined
as `digest(payload)`, so neither it nor `signature` can be part of the payload.

```
manifestDigest = digest(manifest − {signature, manifestDigest})
signature.value = Ed25519_sign(secretKey, JCS(manifest − {signature, manifestDigest}))
```

### 5.2 Publisher keys

- Algorithm: **Ed25519** (small keys, fast verify, deterministic signatures,
  native to Node's `node:crypto` — no dependencies).
- `publicKey` is the base64url of the DER `spki` encoding.
- `keyId = digest(publicKey_bytes)` — the key is self-certifying; `keyId` is a
  pure function of the key bytes, so a claimed `keyId` that doesn't match the
  embedded `publicKey` is rejected.

### 5.3 Verification

A verifier **MUST** check, in order:

1. `schema` is a known version;
2. `publisher.keyId == digest(publisher.publicKey)`;
3. `manifestDigest == digest(payload)` (internal consistency);
4. `toolsetDigest == toolsetDigest(tools)`;
5. `serverDigest == serverDigest(server, protocol.negotiated, tools)`;
6. `Ed25519_verify(publisher.publicKey, signature.value, JCS(payload))`;
7. `expiresAt` is unset or in the future.

Any failure **MUST** fail verification. The reference implementation reports
*all* failures, not just the first.

## 6. Trust-state machine

Every server a client knows is in exactly one state:

```
                 observe()
   UNKNOWN ──────────────────► OBSERVED ── pin() ──► PINNED
                                                      │  │
                       compatible re-diff (≤NON_BREAKING)  │
                                                      ▼  ▼
                                              re-pin   incompatible diff
                                                      │
                        ┌─────────────────────────────┤
                        ▼                             ▼
                    MISMATCH ── approve() ──► PINNED   SUSPECT (unsigned-when-required)
                        │                             │
                        └──── policy denies ──────────┤
                                                      ▼
                                                   REVOKED   (terminal per session)
```

- **REVOKED** is terminal for the session: once a server changes its contract
  incompatibly or its provenance fails, the safe default is to stop routing
  calls until a human re-pins (`approve()` is the only exit).
- Every transition **MUST** emit an audit event `{ at, server, from, to, reason,
  detail }` with a stable machine-readable `reason` code (see
  `lib/trust.js#REASONS`).

## 7. Closing the discovery↔execution gap (TOCTOU)

Three mechanisms, in decreasing strength:

### 7.1 Handshake binding (cooperating servers)

A trustcard-aware server **SHOULD** attach a binding to its `initialize` result
under the `_meta` key `io.github.davidnichols-ops/trustcard`:

```jsonc
{ "_meta": { "io.github.davidnichols-ops/trustcard": {
    "schema": "trustcard.dev/manifest@1",
    "toolsetDigest": "sha256:...",
    "serverDigest": "sha256:...",
    "manifestDigest": "sha256:..."
} } }
```

The client recomputes the digests from its own `tools/list` and compares.
Mismatch ⇒ the server committed to one toolset and served another ⇒ SUSPECT.
This commits the server to a toolset *at handshake time*, before any call.

### 7.2 Change notification (stale-cache invalidation)

A server that sets `capabilities.tools.listChanged = true` and sends
`notifications/tools/list_changed` triggers the client to **immediately**
re-enumerate, re-diff against the pin, and re-evaluate trust. An incompatible
re-diff **MUST** move the server to MISMATCH and, per policy, REVOKED.

### 7.3 Per-call re-assertion (the residual window)

The window that remains is a server mutating between the last enumeration and
a call *without* sending a notification. Mitigations:

- the guard re-validates call arguments against the **pinned** inputSchema in
  strict mode (a server that silently widened/changed args fails the call);
- every call emits a receipt recording the digest under which it was made, so a
  later audit detects that the contract had drifted;
- a server that wants to be trusted for high-stakes calls **SHOULD** implement
  §7.1 so the window is bounded by the handshake.

## 8. Registry integration

The manifest is designed to live in the official MCP registry's extension
point: `server.json` `_meta` under a reverse-DNS key. See
`docs/REGISTRY-INTEGRATION.md`. The registry entry carries `{ manifestUrl,
manifestDigest, publisher.keyId }`; clients fetch the manifest, verify it
against the pinned publisher key, and check the digest — without the registry
needing to understand the format.

## 9. Reproducibility receipts

A receipt binds an exact contract version to a call:

```jsonc
{ "schema": "trustcard.dev/receipt@1",
  "at": "...", "server": {...}, "tool": "search",
  "toolDigest": "...", "toolsetDigest": "...", "serverDigest": "...",
  "protocolVersion": "...", "argumentsDigest": "...", "resultDigest": "..." }
```

Two calls are *reproducible* iff `toolsetDigest` and `argumentsDigest` match;
comparing `resultDigest` then measures whether the server is deterministic
under an identical contract — the only meaningful notion of reproducibility
when tools are mutable. See `lib/receipts.js`.

---

## 10. Capability Descriptors (v2)

This section specifies the protocol-neutral descriptor layer implemented in
`lib/descriptor.js` and `lib/change.js`. It is additive: everything in §1–§9 is
unchanged. For rationale and honest non-goals see `docs/DESCRIPTOR.md`.

### 10.1 Definitions

- **Interface identity** `I_id = SHA-256(JCS(semantic projection))`. Byte-equal
  to `toolDigest` (§3). The capability's identity IS its interface digest;
  there is no separate `C_id`, and `namespace` is a signed naming claim, never
  part of the identity hash.
- **Implementation identity** — a typed object:
  `{kind:"npm-dist", integrity, algorithm}` | `{kind:"source", digest}` |
  `{kind:"unresolved"}`. A package name+version is NOT an implementation
  identity. `unresolved` is an explicit value, never an omission. `npm-dist`
  proves the published tarball, not the executing process.
- **Publisher provenance** — `{publisher, keyId, publicKey}`; `keyId =
  SHA-256(spki(publicKey))`, as in §5.2.

### 10.2 Descriptor format

Schema `trustcard.dev/descriptor@1`:

```jsonc
{ "schema": "trustcard.dev/descriptor@1",
  "capability":  { "namespace": "...", "interfaceDigest": "sha256:...", "interface": {...} },
  "implementation": { "kind": "...", "...": "..." },
  "provenance":  { "publisher": "...", "keyId": "...", "publicKey": "..." },
  "issuedAt": "...", "expiresAt": null,
  "claims": { "...": "..." },              // optional, advisory only
  "descriptorDigest": "sha256:...",
  "signature": { "algorithm": "ed25519", "keyId": "...", "value": "..." } }
```

### 10.3 Signing payload and verification

The signed bytes are the descriptor with `signature` and `descriptorDigest`
removed, canonicalized with JCS — identical coverage to §5.1.
`descriptorDigest = SHA-256(JCS(signing payload))` is the content address.
Verification (`verifyDescriptor`) MUST check, in order: schema; presence of
`capability.interfaceDigest`, `capability.interface`, `provenance.publicKey`,
`signature.value`; `keyId` consistency; that `interfaceDigest` equals
`SHA-256(JCS(embedded interface))`; `descriptorDigest` self-consistency; the
Ed25519 signature; and `expiresAt`. A descriptor MUST NOT contain local trust
state (`trust`, `policy`); verifiers reject unknown trust-bearing fields only
by convention — the normative rule is that none are defined.

### 10.4 Server manifest as a bundle

A v1 server manifest (§5) is interoperable with a set of descriptors:
`manifestToDescriptors` derives one descriptor per tool;
`descriptorSetDigest(bundle)` over the embedded interfaces equals
`toolsetDigest` (§3.2) over the same interfaces. A server provides
capabilities; it is not itself a capability.

### 10.5 Change vector

`changeVector(prior, current)` classifies a transition across four axes, each
ordered by consequence:

```
interface:      NONE < SYNTACTIC < NON_BREAKING < ANNOTATION_DOWNGRADE < BREAKING
permission:     NONE < REDUCTION < EXPANSION
implementation: NONE < UNRESOLVED < REPLACED
provenance:     NONE < KEY_ROTATION < PUBLISHER_CHANGE
```

The interface axis reuses §4 verbatim, except that a change consisting ONLY of
permission-relevant annotations is reported on the permission axis (interface
`NONE`) so it is not double-counted. `I_id` unchanged with a changed
implementation yields `{interface:"NONE", implementation:"REPLACED"}`.
`isVectorCompatible(vector)` is the auto-accept decision: true iff interface ≤
NON_BREAKING, permission ∈ {NONE, REDUCTION}, implementation = NONE, provenance
= NONE. Callers that only need the §4 answer keep using `isCompatible(diff)`.

### 10.6 Descriptor pins

`PinStore` gains a descriptor-keyed pin space alongside server pins
(`pinDescriptor` / `getDescriptorPin`), keyed by `descriptorDigest`. The two
spaces coexist; server pins (§6) are unaffected.

---

## 11. Gate 2 — Invocation Authorization (v2)

§6 (trust state) is **Gate 1**: *is this still the capability I established?*
It is objective and cacheable. Gate 1 can never answer the second question —
*given that, may THIS invocation, with THESE arguments, in THIS environment,
run?* That is **Gate 2** (`lib/policy.js`, wired into `Guard.authorizeCall`).
The two are strictly ordered: an invocation is evaluated by Gate 2 only after
Gate 1 has established continuity.

### 11.1 The decision is per-relying-party, not global

Gate 2 is deliberately **not** a general policy language. A shared language
would force global agreement on what an invocation "means" and destroy the
per-relying-party trust model (§ TRUST-SUBSTRATE §10.3). Instead there is a
small set of composable rule predicates; first match wins; default allow:

```
denyTools([...])                          → deny named tools
requireApprovalForDestructive()           → destructiveHint → require-approval
restrictToolToEnvironments(tool, [envs])  → deny tool outside listed envs
constrainArg(tool, arg, predicate)        → deny when arg present && !predicate(arg)
forbidArg(tool, arg)                      → deny when arg present at all
```

The canonical use is the **confused-deputy bound**: a tool can be fully trusted
(Gate 1) while a specific invocation is out of scope —
`constrainArg("fetch", "id", id => /^doc-\d+$/.test(id))` denies
`fetch_document("../../etc/passwd")` even though `fetch_document` is PINNED.

### 11.2 Verdicts

`"allow" | "deny" | "require-approval"`. In `enforce` mode `deny` throws
`GuardDenial`; `require-approval` throws the distinct `GuardApprovalRequired`
so the caller can route it to a human rather than treating it as a hard denial.
A throwing rule predicate is treated as non-matching — it never widens access.

### 11.3 Scoped decision store

`ScopedDecisions` caches Gate-2 decisions keyed `(relyingParty, capability,
environment)` with a `*` environment fallback. It stores **decisions, not
capabilities** — "trusted for read in dev, denied in prod" — and is invalidated
by the caller when the underlying descriptor or scope changes (continuity
remains Gate 1's job). A decision recorded for one relying party never leaks to
another.

---

## 12. Signed, Chained Receipts (v2)

A §9 receipt is an unsigned local log line — useful for debugging, worthless as
evidence. `SignedReceiptChain` (`lib/receipts.js`) upgrades it. The v1 fields
are preserved byte-for-byte; signing adds:

```jsonc
{ /* ...all v1 receipt fields... */
  "relyingParty": "...", "seq": 7, "nonce": "<16 random bytes b64url>",
  "parentReceipt": "sha256:<digest of previous receipt, null for first>",
  "receiptDigest": "sha256:...",   // = SHA-256(JCS(payload)); the content address
  "signature": { "algorithm": "ed25519", "keyId": "...", "value": "..." } }
```

- **Non-repudiation** — signed by the relying party's Ed25519 key; verify with
  `verifyReceiptSignature(receipt, publicKey)`.
- **Tamper-evidence** — `receiptDigest` is the hash of the payload, so any edit
  breaks self-consistency (`verifyReceipt`) and the signature.
- **Replay resistance** — `nonce` + `at` timestamp; `seq` is monotonic.
- **Chain integrity** — each receipt embeds `parentReceipt`; a deleted or
  reordered receipt breaks the chain (`verifyReceiptChain` reports gaps/breaks).

Signing coverage excludes `signature` and `receiptDigest` (the digest is the
hash of the payload — same rule as manifests and descriptors). A guard emits
signed receipts only when configured with `receiptKey`; without one it emits
the v1 unsigned receipt unchanged.

### 12.1 What a signed receipt proves — and does not

The receipt is signed by the **relying party** (the client that made the call),
not by the server. This is a deliberate and load-bearing distinction:

- **Proves** — the relying party *recorded this authorization decision* at this
  sequence position, over this exact (capabilityDigest, argumentsDigest,
  resultDigest), and has not repudiated it. `verifyReceiptChain` additionally
  proves the presented history is unbroken, un-reordered, and un-forged (each
  `receiptDigest` is recomputed, not trusted).
- **Does NOT prove** — that the call *executed*, that the server *ran* anything,
  or that the recorded result is *true*. A relying party can sign a receipt for
  a call that never happened and it will still verify — because the signature
  attests to the relying party's *record*, not to server behavior. Proving
  execution would require a *countersigned* receipt (server co-signs) or a
  transparency log; both are documented non-goals. A signed receipt is
  **evidence of a decision, not proof of execution.**

`verifyReceipt` is structural only (digest self-consistency + signature
presence). `verifyReceiptSignature` adds the cryptographic check against a known
public key. `verifyReceiptChain` adds ordering/integrity across a sequence.
None of them, alone or together, assert that any tool actually ran.

---

## 13. Publisher Key Rotation & Revocation (v2)

Key compromise is mostly a **UX attack**, not a crypto attack: the crypto
detects a new key instantly, but "we rotated, please re-pin" is a social claim.
Old-key-signs-new-key turns it back into a verifiable fact (`lib/rotation.js`).

### 13.1 Rotation certificate

```jsonc
{ "schema": "trustcard.dev/key-rotation@1", "type": "key-rotation",
  "oldKeyId": "...", "oldPublicKey": "...",
  "newKeyId": "...", "newPublicKey": "...",
  "issuedAt": "...", "expiresAt": null,
  "digest": "sha256:...",
  "signature": { "algorithm": "ed25519", "keyId": "<oldKeyId>", "value": "..." } }
```

Signed by the **old** private key. `verifyRotationCertificate` checks schema,
embedded-old-keyId consistency, digest self-consistency, expiry (when
`expiresAt` is set — a lapsed rotation must not keep authorizing a stolen old
key), and the old key's signature. Without it, every rotation is a fresh TOFU moment; with it, a client
that pinned the old key can cryptographically confirm the rotation and re-pin
the new key without trusting a third party. A forged rotation (signed by any
key other than the old one) fails verification.

### 13.2 Revocation certificate

```jsonc
{ "schema": "trustcard.dev/revocation@1", "type": "revocation",
  "keyId": "...", "publicKey": "...", "reason": "...", "issuedAt": "...",
  "digest": "sha256:...", "signature": { "...", "keyId": "<keyId>" } }
```

**Self-signed**: only the holder of a key can revoke it, and a revoked key's
own revocation remains verifiable (you can confirm the key revoked itself).
`verifyRevocationCertificate` checks the keyId↔publicKey binding, digest, and
self-signature. A certificate claiming to revoke a key it does not hold fails.
