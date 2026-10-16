# trustcard — repo knowledge for agents

## What this is

trustcard is **cryptographic trust infrastructure for MCP servers**, and the start of a protocol-neutral trust substrate for executable capabilities. v3.0.3 builds on v1 identity/provenance/v2 policy/receipts with three new layers:

1. **Behavioral verification** (`lib/behavior.js`) — sandboxed, deterministic probing that can fail a server whose static contract is unchanged.
2. **Evidence substrate** (`lib/evidence.js`, `lib/evidence-store.js`) — content-addressed, immutable observations.
3. **HTTP/SSE transport parity** (`lib/client-http.js`) — experimental streamable-http and SSE client.

Read `docs/INDEX.md` first, then `docs/SECURITY-MODEL.md`, `docs/SPEC.md`, and `docs/BEHAVIOR.md`.

## Commands

- Test: `npm test` → `node --test test/*.test.js` (629 tests, all should pass)
  - IMPORTANT: the `test/*.test.js` glob is required. Bare `node --test`
    also matches `test/helpers.js` and the fixture servers, which hang the
    runner (child processes keep stdio open). Don't "simplify" the glob away.
  - The glob must be unquoted in the `package.json` script so the shell expands
    it before Node receives the paths; a quoted glob becomes a literal path.
- CLI: `node bin/mcp-trustcard.js <subcommand>` (keygen/manifest/sign/verify/
  diff/pin/pins/fingerprint/scan/gen-manifest/inspect/auth-issue/auth-verify/
  behavior/evidence)
- Also `bin/mcp-proxy.js` and `bin/mcp-http-proxy.js` for call-time enforcement.
- No runtime deps. Pure Node stdlib. Don't add dependencies.

## Architecture map (lib/)

- `canon.js` — RFC 8785 (JCS) canonicalization. **Every digest depends on this
  being byte-exact.** Numbers use ECMAScript shortest round-trip with `e+n`/`e-n`
  exponents, no `-0`; keys sorted by UTF-16 code units. RFC test vectors in
  `test/canon.test.js`.
- `hash.js` — `digest(value) = "sha256:"+base64url(SHA256(JCS(value)))`.
  `signingPayload()` excludes BOTH `signature` and `manifestDigest`.
- `identity.js` — semantic projection for tool/server digests. Semantic:
  name, description, inputSchema, outputSchema, annotations{title,
  readOnlyHint, destructiveHint, idempotentHint, openWorldHint}, execution.
  Volatile (excluded): top-level title, icons, tags, `_meta`.
- `diff.js` — five-level taxonomy
  NONE<SYNTACTIC<NON_BREAKING<ANNOTATION_DOWNGRADE<PERMISSION_CHANGE<BREAKING.
  Compatible = ≤NON_BREAKING.
- `change.js` — multi-axis change vector (interface/permission/implementation/
  provenance) for descriptors.
- `trust.js` — state machine
  UNKNOWN→OBSERVED→PINNED→MISMATCH/SUSPECT→REVOKED. REVOKED is sticky.
  `trustLevel()` projects onto TRUSTED/VERIFIED/OBSERVED/UNTRUSTED/REVOKED.
- `provenance.js` — manifest build/sign/verify. Ed25519 via node:crypto.
  Signed manifests carry `expiresAt`; `verifyManifest` rejects expired ones.
- `manifest.js` — proxy-enforcement manifest. `buildManifest` includes
  `expiresAt` (default 90 days); `checkCall` blocks all calls when expired.
  `--allow-tool` records `manualOverride: true`. `--require-scopes` adds
  `requiredScopes` per tool.
- `pin.js` — TOFU pin store (servers + publisher keys), atomic writes,
  fail-closed on corrupt file.
- `session.js` — live connection: negotiates protocol, verifies handshake
  binding, subscribes to `notifications/tools/list_changed` → re-diff.
- `guard.js` — the enforcement gate. `wrapClient`/`session.call` route every
  `tools/call` through `guard.authorizeCall`. Modes: enforce/audit/off.
  Emits signed, chained receipts when given a `receiptKey`.
- `middleware.js` — `wrapClient(rawClient, {guard, session})`; re-verifies
  toolset digest on every `tools/list`.
- `policy.js` — Gate 2 per-invocation authorization: composable rule
  predicates (`allowTools`, `denyTools`, `constrainArg`, `forbidArg`,
  `restrictToolToEnvironments`, `requireApprovalForDestructive`,
  `requireScopes`) + `ScopedDecisions`. Verdict precedence:
  deny > require-approval > allow. Rule predicates that throw fail closed.
  `defaultVerdict` defaults to `allow`; set to `deny` for default-deny.
- `auth.js` — Per-agent auth scope enforcement. `DevIssuer`
  (HMAC-SHA256 JWT-like tokens), `IdpIntrospector` (RFC 7662 OAuth 2.1
  token introspection), `TokenValidator` (local first, then introspection),
  `scopeSatisfies` (wildcards `*` and `prefix:*`), `extractToken`/`stripAuth`.
- `rotation.js` — old-key-signs-new-key rotation certificates + self-signed
  revocation certificates.
- `behavior.js` — **v3.** Behavioral verification engine. Exports
  `SandboxRuntime`, `InputGenerator`, `OutputComparator`, `BehaviorEngine`,
  `BehaviorReport`, `BehaviorFinding`, `RegressionCorpus`, `ReferenceObservation`.
  Key invariant: static identity can pass while behavioral verification fails.
- `evidence.js` / `evidence-store.js` / `evidence-adapters.js` — **v3.**
  Content-addressed evidence records and local store. Records are immutable;
  corrections use `supersedes`. `EVIDENCE_LAYERS` is the predicate registry.
- `evidence-predicates.js` — predicate and layer vocabulary for evidence.
- `existence.js` — existence probes for npm and GitHub repos (evidence layer).
- `observe.js`, `fingerprint.js`, `receipts.js`, `report.js`, `checks.js` —
  scan, identity card, reproducibility, rendering.
- `danger-detector.js` — three-engine fusion: heuristic, semantic (TF-IDF),
  injection markers.
- `descriptor.js` — protocol-neutral capability descriptor.
  `interfaceDigest()` is byte-equal to `toolDigest()`. `implementationIdentity`
  is typed (`npm-dist`/`source`/`unresolved`). `buildDescriptor`/`signDescriptor`/
  `verifyDescriptor` and manifest⇄descriptor adapters.
- `mcp-server.js` — minimal framework for well-behaved MCP servers.
  `examples/bruce-lee/` is the reference server.
- `client-http.js` — **v3.** MCP `streamable-http` and SSE client.
  Experimental; `McpHttpClient` matches `McpStdioClient` interface.
- `redact.js` — auth-token and sensitive-value redaction helpers.

## Entry points

- `package.json` main → `lib/guard.js`.
- `bin/mcp-trustcard.js` — primary CLI.
- `bin/mcp-proxy.js` — stdio proxy.
- `bin/mcp-http-proxy.js` — HTTP/SSE proxy.

## Reference MCP server

`examples/bruce-lee/` — deterministic, hash-chained agent decision audit log.
Demonstrates trustcard-aware handshake, honest annotations, safe param names,
structured JSON-RPC error codes, fail-closed log integrity, zero runtime deps.
Tests in `test/bruce-lee.test.js`.

## Invariants / gotchas (don't break these)

1. **Volatile fields never move the digest.** If you add a field to the
   projection, `test/identity.test.js` will catch it.
2. **REVOKED is sticky.** Don't add a transition that silently un-revokes.
3. **Fail closed everywhere.** Corrupt pin file, bad signature, key drift,
   binding mismatch → never trusted, always with a reason code.
4. **TOCTOU is only fully closed for cooperating servers** (handshake binding).
   The residual window is bounded by strict arg validation + receipts, not
   eliminated. Don't claim otherwise in docs.
5. Fixture servers exit on stdin `end` — keep that or tests leak processes.
6. **v1 identity bytes are sacred.** `interfaceDigest()` must stay byte-equal
   to `toolDigest()`; every existing pin/receipt depends on it.
7. **Implementation identity is honest, not aspirational.** A package
   name+version is `{kind:"unresolved"}`, never a digest. `npm-dist` proves the
   tarball, not the running process.
8. **Prefer false drift over false equivalence.** No aggressive schema
   normalization that could map two behaviorally-different contracts to the
   same identity.
9. **Gate 1 ≠ Gate 2.** Gate 1 (trust-state continuity) is objective; Gate 2
   (invocation authorization) is per-relying-party.
10. **Signed receipts are optional.** Without a `receiptKey` the guard emits the
    v1 unsigned receipt byte-for-byte. `verifyReceipt` is STRUCTURAL only.
11. **Rotation is old-signs-new.** A rotation cert is only trusted if the OLD
    key signed it; a revocation cert is only valid self-signed.
12. **Behavioral verification is additive and honest.** It does not modify
    `toolDigest`/`toolsetDigest`/`serverDigest`. The sandbox is a **process
    harness**, not an OS jail: capability labels (`network: "not-observed"`,
    `filesystem: "cwd-isolated"`, `subprocesses: "stderr-only"`) must be truthful.
13. **Evidence is immutable.** Never edit evidence records in place; corrections
    link via `supersedes`. Scores are derived from evidence, not stored in it.

## MCP facts (as of this writing)

- Latest protocol version is date-stamped (e.g. `2025-06-18`).
  `lib/client.js#PROTOCOL_VERSIONS` lists newest-first; `observe.js`/`session.js`/
  `client-http.js` negotiate by trying each until one succeeds.
- `capabilities.tools.listChanged` advertises `notifications/tools/list_changed`.
- `ToolAnnotations` (`readOnlyHint` etc.) are **hints** — "Clients should never
  make tool use decisions based on ToolAnnotations received from untrusted
  servers." trustcard establishes that trust cryptographically.
- Registry `server.json` extension point: `_meta` under reverse-DNS keys.
  Ours: `io.github.davidnichols-ops/trustcard`.

## Conventions

- ESM (`"type":"module"`). Node ≥ 18 (CI uses 22).
- No build step, no transpile, no deps. Tests use `node:test` + `node:assert`.
- Exit codes: scan <50 → 1; diff PERMISSION_CHANGE+/BREAKING → 1; verify/
  fingerprint failures → 1; behavior `warn`/`fail` or missing args → 1.
