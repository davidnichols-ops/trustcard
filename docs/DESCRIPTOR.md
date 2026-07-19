# The Capability Descriptor

The v2 identity + provenance core. This document describes what a descriptor
is, what it proves, and — just as important — what it does not prove.

It implements the separations derived in `TRUST-SUBSTRATE.md`, **corrected
where the real v1 code proved the document wrong**. Those corrections are
called out explicitly below; they are deliberate, not drift.

---

## 1. The object

A **capability descriptor** is a signed, content-addressed statement binding
three objective identities:

```
interface identity   I_id  — the contract (what you call / what it means)
implementation       M_id  — the code that provides it
publisher provenance P_id  — who vouches, with which Ed25519 key
```

A descriptor contains **no local trust state**. Trust decisions, policy, and
authorization are separate subsystems (`trust.js`, `guard.js`) that reference
descriptors; they are never embedded in the signed object.

```jsonc
{
  "schema": "trustcard.dev/descriptor@1",
  "capability": {
    "namespace": "search",                 // a NAME, not part of identity
    "interfaceDigest": "sha256:...",        // I_id
    "interface": { /* semantic projection */ }
  },
  "implementation": {
    "kind": "npm-dist",                     // or "source" | "unresolved"
    "integrity": "sha512-...",
    "algorithm": "sha512"
  },
  "provenance": {
    "publisher": "io.example",
    "keyId": "sha256:...",
    "publicKey": "..."
  },
  "issuedAt": "...", "expiresAt": null,
  "descriptorDigest": "sha256:...",          // content address of the payload
  "signature": { "algorithm": "ed25519", "keyId": "...", "value": "..." }
}
```

---

## 2. Interface identity (I_id)

`I_id = SHA-256( JCS( semantic projection ) )`.

The projection is v1's `toolProjection()`, unchanged: `name`, `description`,
`inputSchema`, `outputSchema`, the behavioral annotation subset, and
`execution`. Presentation (`title`, `icons`, `_meta`) is excluded.

**This is byte-identical to v1's `toolDigest`.** The identity bytes did not
change, so every existing pin, receipt, and diff survives. `interfaceDigest()`
is the protocol-neutral name; `toolDigest()` remains as the v1 alias.

We did **not** add an aggressive semantic-normalization layer (sorting enums,
collapsing type-unions, etc.). The reason is the asymmetry the task demands:
**false drift is recoverable (re-pin); false equivalence is a silent security
hole.** A normalization that maps two behaviorally-different schemas to the
same identity is a vulnerability, so none is performed. Identity prefers false
drift over false equivalence. (Normalization is an open research question in
`TRUST-SUBSTRATE.md` §18.2, not a v2 feature.)

---

## 3. Implementation identity (M_id)

A **typed, honest** statement about the providing code:

| kind | meaning | what it proves | what it does NOT prove |
|---|---|---|---|
| `npm-dist` | npm `dist.integrity` (tarball content hash) | which tarball the registry served | what code *executed* — postinstall scripts, the npx cache, and transitive dependencies are outside scope |
| `source` | a source-commit or build-artifact digest | the publisher asserts this source produced the capability | that the build was reproducible, or that this source is what's deployed |
| `unresolved` | no trustworthy artifact identity available | **nothing** — a real, explicit value | it is never a silent omission; policy should treat it as a weaker claim |

**A package name + version is never an implementation identity.** It is a
mutable pointer, not a content hash. `implementationIdentity({name, version})`
returns `{ kind: "unresolved" }`.

This is where the design most refuses to overclaim. v1 already *fetched* npm
`dist.integrity` (in `fingerprint.js`) but only printed it; v2 makes it a typed
identity with an explicit security boundary. The honest residual gap — a
tarball hash does not prove runtime behavior — is attack #20 in
`THREAT-MODEL.md` and remains a documented non-goal.

---

## 4. Capability identity — and the namespace correction

`TRUST-SUBSTRATE.md` proposed `C_id = H(namespace ‖ I_id)`. **We did not
implement this.** Against the real code it fails:

- A namespace is *naming*, not identity. The same `search` contract can live at
  `io.a/search` and `io.b/search`. Folding namespace into identity makes a
  rename indistinguishable from a contract change (false drift) and is
  redundant, because the tool's `name` is already inside the projection.
- Two providers serving a semantically identical interface *should* yield the
  same capability identity — that is what lets a client recognize "this is the
  same capability, re-hosted."

So: **the capability's identity is its interface digest.** `namespace` is
carried as a signed *claim* inside the descriptor (so a publisher can assert a
name), but it is never hashed into identity. This is a deliberate, documented
divergence from the substrate document — the smallest model that stays true.

---

## 5. The descriptor

**Signature coverage.** The signed bytes are the descriptor with `signature`
and `descriptorDigest` removed (the digest is defined as the hash of that
payload, so neither can be inside it) — the same coverage rule v1 uses for
manifests. `capability`, `implementation`, `provenance`, `issuedAt`,
`expiresAt`, and any `claims` are all under the signature.

**Embedded interface + redundant digest.** The interface projection is embedded
(so the descriptor is self-contained and independently verifiable), and
`interfaceDigest` is kept alongside it. The redundancy is load-bearing: pins,
receipts, and diffs reference the digest without recomputing, and
`verifyDescriptor` re-derives it from the embedded projection to catch
inconsistency.

**Content-addressed.** `descriptorDigest` is the content address. It is what
the v2 pin store keys on (`PinStore.pinDescriptor`), so the pinned thing is a
signed `(interface, implementation, provenance)` binding — not a server name.

---

## 6. Server/provider relationship

A **server is a provider of capabilities, not a capability.** v2 does not
delete server identity — it remains operationally useful — but it stops being
the trust anchor.

```
Server S
  provides Capability A   ── descriptor D_A (independently verifiable)
  provides Capability B   ── descriptor D_B
  provides Capability C   ── descriptor D_C
```

`Server S ≠ Capability A`. The adapters `manifestToDescriptors()` and
`descriptorsToManifestTools()` convert between a v1 server manifest and a
bundle of descriptors. The claim "a server manifest is a bundle of capability
descriptors" is therefore a real, tested conversion, not prose:
`descriptorSetDigest(bundle) === toolsetDigest(tools)` over the same
interfaces.

One honest caveat the investigation surfaced: v1's `serverDigest` folds in
`protocolVersion` and `serverInfo.title`. Protocol negotiation is an
operational fact, and `title` is presentation that `toolProjection` elsewhere
treats as volatile. Neither belongs in a capability identity — which is exactly
why the descriptor anchors on `interfaceDigest` and leaves server-level facts
out. `serverDigest` is retained for v1 compatibility only.

---

## 7. The change vector

v1's ordered taxonomy (`NONE < SYNTACTIC < … < BREAKING`) is correct and kept
for the **interface** axis. But it cannot represent two real changes. v2 adds
`changeVector()`, classifying a transition across independent axes:

```jsonc
{
  "interface":      "NONE|SYNTACTIC|NON_BREAKING|ANNOTATION_DOWNGRADE|BREAKING",
  "permission":     "NONE|REDUCTION|EXPANSION",
  "implementation": "NONE|UNRESOLVED|REPLACED",
  "provenance":     "NONE|KEY_ROTATION|PUBLISHER_CHANGE"
}
```

The decisive case:

```
I_id unchanged, M_id changed
  → { interface: "NONE", implementation: "REPLACED" }
  → compatible: false        (v1 reported "no change")
```

That is the compromised/redeployed-server case: a stable contract served by
different code. It is no longer invisible.

**`isVectorCompatible()`** preserves v1's simple "can this be auto-accepted?"
contract — callers need not understand the lattice. A change is auto-acceptable
only when *every* axis stays in its safe band: interface ≤ NON_BREAKING,
permission not EXPANSION, implementation NONE, provenance NONE. One subtlety
the implementation forced: v1 reports a pure permission-annotation move as
`PERMISSION_CHANGE` on its single ladder. The vector routes that to the
permission axis (which knows direction) and reports the interface axis as
`NONE`, so a permission *reduction* (an added safety hint) is correctly
auto-acceptable rather than blocked.

---

## 8. What a descriptor proves — and does not

**Proves:**
- the interface contract is bit-identical to what the publisher signed;
- the holder of the publisher key signed that exact (interface, implementation,
  validity) binding;
- continuity — the descriptor is the same one you pinned (content-address).

**Does not prove:**
- that the capability is *benevolent* (a signed descriptor can describe
  malicious behavior perfectly — attack #20);
- that the `implementation` digest reflects *runtime* behavior (`npm-dist`
  proves the tarball, not the executing process);
- anything about *this specific invocation* being safe — that is a separate
  authorization decision (`guard.js`), not part of the descriptor.

The descriptor is **evidence, not a verdict.** It gives a relying party an
objective, verifiable object to pin and to diff; the decision remains local.

---

## 9. From descriptor to decision: the two gates (v2)

The descriptor answers Gate 1 — *is this still the capability I pinned?* — but
trust in a capability is not authorization for every use of it. v2 closes that
gap on the live path:

- **Gate 1 (continuity)** runs in `guard.authorizeCall` from the trust store
  (§6 SPEC): REVOKED/MISMATCH/PINNED, plus the diff taxonomy.
- **Gate 2 (authorization)** runs immediately after, in `lib/policy.js`: a
  per-relying-party decision about *this* invocation — these args, this
  environment. A tool can be fully PINNED while `fetch_document("../../etc/
  passwd")` is denied. This is the confused-deputy bound; it is deliberately
  not a global policy language (that would destroy the per-relying-party
  model). See SPEC §11.
- **Signed, chained receipts** (`lib/receipts.js#SignedReceiptChain`) turn the
  log line into verifiable evidence: Ed25519-signed, hash-chained
  (`parentReceipt`), sequenced, and nonced. Deletion or reordering breaks the
  chain. See SPEC §12.
- **Old-key-signs-new-key rotation** (`lib/rotation.js`) makes key compromise a
  cryptographic fact rather than a social claim: a rotation is only trusted if
  the old key signed it; revocation is only valid self-signed. See SPEC §13.

None of this changes the descriptor's honest limits above: a signed descriptor
can still describe a malicious-but-stable capability, and `npm-dist` still
proves the tarball, not the runtime. The two gates decide *whether to act*;
the descriptor is the *evidence they act on*.
