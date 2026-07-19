# trustcard — repo knowledge for agents

## What this is

trustcard is **cryptographic trust infrastructure for MCP servers**. v1 turned
the original health-probe CLI into a protocol: content-addressed tool identity
+ Ed25519-signed manifests + TOFU pinning + a trust-state machine + an
enforcement guard. The scanner (`scan`) survives as the reference *verifier*.

Read `docs/ANALYSIS.md` first — it explains *why* the probe abstraction was
insufficient and what the protocol replaces it with.

## Commands

- Test: `npm test`  → `node --test "test/*.test.js"` (87 tests, all should pass)
  - IMPORTANT: the glob `"test/*.test.js"` is required. Bare `node --test`
    also matches `test/helpers.js` and the fixture servers, which hang the
    runner (child processes keep stdio open). Don't "simplify" the glob away.
- CLI: `node bin/mcp-trustcard.js <subcommand>` (keygen/manifest/sign/verify/
  diff/pin/pins/fingerprint/scan)
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
- `provenance.js` — manifest build/sign/verify. Ed25519 via node:crypto.
- `pin.js` — TOFU pin store (servers + publisher keys), atomic writes,
  fail-closed on corrupt file.
- `session.js` — live connection: negotiates protocol, verifies handshake
  binding, subscribes to `notifications/tools/list_changed` → re-diff.
- `guard.js` — the enforcement gate. `wrapClient`/`session.call` route every
  tools/call through `guard.authorizeCall`. Modes: enforce/audit/off.
- `middleware.js` — `wrapClient(rawClient, {guard, session})` for existing
  frameworks; also re-verifies toolset digest on every `tools/list`.
- `observe.js`, `fingerprint.js`, `receipts.js`, `report.js` — probe, full
  card, reproducibility, rendering.

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
