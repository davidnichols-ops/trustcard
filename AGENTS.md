# trustcard — repo knowledge for agents

## What this is

trustcard is **cryptographic trust infrastructure for MCP servers**. v1 turned
the original health-probe CLI into a protocol: content-addressed tool identity
+ Ed25519-signed manifests + TOFU pinning + a trust-state machine + an
enforcement guard. The scanner (`scan`) survives as the reference *verifier*.

Read `docs/ANALYSIS.md` first — it explains *why* the probe abstraction was
insufficient and what the protocol replaces it with.

> **Session context**: if you are picking up work from the OpenHands sessions
> that built v2, read `.devin/OPENHANDS-CONTEXT.md` first. It has the
> session-derived state: what was committed, what is uncommitted in the
> working tree (a release-hardening audit — do not drop it), which audit
> tasks remain, and what a continuation agent should do.

## Commands

- Test: `npm test`  → `node --test "test/*.test.js"` (273 tests, all should pass)
  - IMPORTANT: the glob `"test/*.test.js"` is required. Bare `node --test`
    also matches `test/helpers.js` and the fixture servers, which hang the
    runner (child processes keep stdio open). Don't "simplify" the glob away.
- CLI: `node bin/mcp-trustcard.js <subcommand>` (keygen/manifest/sign/verify/
  diff/pin/pins/fingerprint/scan/gen-manifest/inspect)
- No runtime deps. Pure Node stdlib. Don't add dependencies.

## Architecture map (lib/)

- `canon.js` — RFC 8785 (JCS) canonicalization. **Every digest depends on this
  being byte-exact.** Numbers use ECMAScript shortest round-trip with `e+n`/`e-n`
  exponents, no `-0`; keys sorted by UTF-16 code units. There are RFC test
  vectors in `test/canon.test.js` — keep them passing.
- `hash.js` — `digest(value) = "sha256:"+base64url(SHA256(JCS(value)))`.
  `signingPayload()` excludes BOTH `signature` and `manifestDigest` (the digest
  is the hash of the payload, so it can't be in it — a real bug fixed here).
- `identity.js` — the semantic projection (what makes a tool *that* tool).
  Semantic: name, description, inputSchema, outputSchema, annotations{title,
  readOnlyHint, destructiveHint, idempotentHint, openWorldHint}, execution.
  Volatile (excluded): top-level title, icons, tags, `_meta`. Changing only
  volatile fields must NOT change `toolDigest`.
- `diff.js` — five-level taxonomy NONE<SYNTACTIC<NON_BREAKING<
  ANNOTATION_DOWNGRADE<PERMISSION_CHANGE<BREAKING. Compatible = ≤NON_BREAKING.
  ANNOTATION_DOWNGRADE = description materially rewritten (Jaccard<0.6) with
  unchanged schema = suspected tool poisoning.
- `trust.js` — state machine UNKNOWN→OBSERVED→PINNED→MISMATCH/SUSPECT→REVOKED.
  REVOKED is terminal per session (sticky); only `approve()` exits it.
  Also exports `trustLevel(state)` — human-facing projection onto
  TRUSTED/VERIFIED/OBSERVED/UNTRUSTED/REVOKED (the internal state machine
  is unchanged; this is a derived view for UIs and APIs).
- `provenance.js` — manifest build/sign/verify. Ed25519 via node:crypto.
  Signed manifests carry `expiresAt`; `verifyManifest` rejects expired ones.
- `manifest.js` — proxy-enforcement manifest (separate from signed manifests).
  `buildManifest` includes `expiresAt` (default 90 days); `checkCall` blocks
  all calls when the manifest is expired. `--allow-tool` overrides record
  `manualOverride: true` so the override is visible in audit.
- `pin.js` — TOFU pin store (servers + publisher keys), atomic writes,
  fail-closed on corrupt file.
- `session.js` — live connection: negotiates protocol, verifies handshake
  binding, subscribes to `notifications/tools/list_changed` → re-diff.
- `guard.js` — the enforcement gate. `wrapClient`/`session.call` route every
  tools/call through `guard.authorizeCall`. Modes: enforce/audit/off. Gate 1
  (trust-state continuity) then Gate 2 (invocation policy). Emits signed,
  chained receipts when given a `receiptKey`.
- `middleware.js` — `wrapClient(rawClient, {guard, session})` for existing
  frameworks; also re-verifies toolset digest on every `tools/list`.
- `policy.js` — **Gate 2 (v2).** Per-invocation authorization: composable rule
  predicates (`denyTools`, `constrainArg`, `forbidArg`,
  `restrictToolToEnvironments`, `requireApprovalForDestructive`) +
  `ScopedDecisions` (per-relying-party decision cache). NOT a policy language.
- `rotation.js` — **(v2).** Old-key-signs-new-key rotation certificates +
  self-signed revocation certificates (`buildRotationCertificate`,
  `verifyRotationCertificate`, `buildRevocationCertificate`,
  `verifyRevocationCertificate`).
- `observe.js`, `fingerprint.js`, `receipts.js`, `report.js` — probe, full
  card, reproducibility, rendering.
- `danger-detector.js` — three-engine fusion: (1) heuristic (destructive verbs
  + dangerous params + suspicious phrases, context-aware scoring for verbs like
  "clear"/"reset" that are only destructive with destructive nouns), (2) semantic
  (TF-IDF cosine similarity against curated dangerous-action corpus), (3) injection
  (prompt-injection marker detection — `<IMPORTANT>`, `[SYSTEM OVERRIDE]`, "ignore
  previous instructions", sensitive file paths, secrecy instructions, base64 blobs).
  Safe tool patterns (create_directory, mkdir, sequentialthinking) override to
  non-dangerous unless the injection detector flags the description.
- `descriptor.js` — **v2 core.** Protocol-neutral capability descriptor.
  `interfaceDigest()` (byte-equal to `toolDigest`), typed `implementationIdentity`
  (`npm-dist`/`source`/`unresolved`), `buildDescriptor`/`signDescriptor`/
  `verifyDescriptor`, `descriptorDigest` (content address), and manifest⇄descriptor
  adapters. Purely additive over v1 — no v1 bytes changed.
- `change.js` — **v2.** `changeVector()` classifies a transition across 4 axes
  (interface/permission/implementation/provenance). Represents the case v1
  can't: `I_id` same + `M_id` changed → `implementation:"REPLACED"`.
  `isVectorCompatible()` keeps the simple auto-accept boolean.

## Invariants / gotchas (don't break these)

1. **Volatile fields never move the digest.** If you add a field to the
   projection, `test/identity.test.js` ("volatile fields do NOT change the
   digest") will catch a regression — update it deliberately, not casually.
2. **REVOKED is sticky.** Don't add a transition that silently un-revokes.
3. **Fail closed everywhere.** Corrupt pin file, bad signature, key drift,
   binding mismatch → never trusted, always with a reason code.
4. **TOCTOU is only fully closed for cooperating servers** (handshake binding).
   The residual window (mutation without notification) is bounded by strict
   arg validation + receipts, not eliminated. Don't claim otherwise in docs.
5. Fixture servers (`test/fixtures/fake-server.js`) exit on stdin `end` — keep
   that or tests leak processes. The `mutable` scenario reads a state file so
   tests can mutate tools mid-session and fire `list_changed`.
6. **v2 is additive - never break v1 identity bytes.** `interfaceDigest()` must
   stay byte-equal to `toolDigest()`; every existing pin/receipt depends on it.
   The descriptor carries NO local trust state (no `trust`/`policy` fields).
7. **Implementation identity is honest, not aspirational.** A package
   name+version is `{kind:"unresolved"}`, never a digest. `npm-dist` proves the
   tarball, not the running process. Don't claim runtime proof in docs.
8. **Prefer false drift over false equivalence.** No aggressive schema
   normalization that could map two behaviorally-different contracts to the
   same identity. This is why there is no enum-sorting/type-collapsing layer.
9. **Gate 1 ≠ Gate 2.** Gate 1 (trust-state continuity, `trust.js`/`diff.js`)
   is objective; Gate 2 (invocation authorization, `policy.js`) is per-relying-
   party. A tool can be trusted while a specific invocation is denied. Don't
   let Gate 2 leak global verdicts across relying parties.
10. **Signed receipts are optional.** Without a `receiptKey` the guard emits the
    v1 unsigned receipt byte-for-byte. `verifyReceipt` is STRUCTURAL only —
    cryptographic verification needs `verifyReceiptSignature(receipt, pubkey)`.
11. **Rotation is old-signs-new.** A rotation cert is only trusted if the OLD
    key signed it; a revocation cert is only valid self-signed. Anything else
    is a social claim, not a cryptographic fact — fail closed.

## MCP facts (as of this writing)

- Latest protocol version is date-stamped (e.g. `2025-06-18`, draft newer).
  `lib/client.js#PROTOCOL_VERSIONS` lists newest-first; `observe.js`/`session.js`
  negotiate by trying each until one succeeds.
- `capabilities.tools.listChanged` advertises `notifications/tools/list_changed`.
- `ToolAnnotations` (`readOnlyHint` etc.) are **hints** — "Clients should never
  make tool use decisions based on ToolAnnotations received from untrusted
  servers." trustcard's whole point is establishing that trust cryptographically.
- Registry `server.json` extension point: `_meta` under reverse-DNS keys.
  Ours: `io.github.davidnichols-ops/trustcard`. (Second label `modelcontextprotocol`
  /`mcp` is reserved; `io.github.*` is fine.)

## Conventions

- ESM (`"type":"module"`). Node ≥ 18 (CI uses 22).
- No build step, no transpile, no deps. Tests use `node:test` + `node:assert`.
- Exit codes: scan <50 → 1; diff PERMISSION_CHANGE+/BREAKING → 1; verify/
  fingerprint failures → 1. CI depends on these.
