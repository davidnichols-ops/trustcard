# Trustcard Security Model

> **The one-sentence version:** trustcard guarantees that the tool an agent
> calls is bit-for-bit the tool a known publisher signed and the client pinned
> — or it stops the call and says exactly what changed. It does not guarantee
> the tool is *good*.

This document states what trustcard guarantees, what it does not, and the
mechanism behind each claim. It is the document to read before deploying
trustcard in any context where someone will ask "but does it protect against
X?"

For the attack-by-attack analysis, see [THREAT-MODEL.md](THREAT-MODEL.md).
For the wire format and field semantics, see [SPEC.md](SPEC.md).
For the protocol design rationale, see [TRUST-SUBSTRATE.md](TRUST-SUBSTRATE.md).

## Security guarantees

| Property | Guaranteed? | Mechanism | Code |
|---|---|---|---|
| Detect tool definition drift | **Yes** | Capability digest (SHA-256 of JCS-canonicalized semantic projection). Any change to name, description, inputSchema, outputSchema, or annotations alters the digest. | `lib/identity.js` |
| Detect tool addition/removal | **Yes** | toolsetDigest is the sorted hash of all tool digests. Adding or removing a tool changes it. | `lib/identity.js` |
| Classify change severity | **Yes** | Five-level taxonomy: NONE < SYNTACTIC < NON_BREAKING < ANNOTATION_DOWNGRADE < PERMISSION_CHANGE < BREAKING. Each maps to a trust-state transition. | `lib/diff.js` |
| Verify publisher authorization | **Yes** | Ed25519 signature over the JCS-canonicalized manifest payload. Verification proves the holder of the publisher key signed these exact tool definitions. | `lib/provenance.js` |
| Verify publisher key continuity | **Yes** | TOFU pinning: the first-seen publisher key is pinned; a different key for the same keyId is flagged as drift, never auto-overwritten. | `lib/pin.js` |
| Detect server serving different tools than signed | **Yes** | `bindingConsistency()` compares the manifest's toolsetDigest against the live observation's toolsetDigest. Mismatch → MISMATCH state. | `lib/provenance.js` |
| Prevent unauthorized tool calls | **Yes** | Guard enforces: server must be PINNED, tool must be in the verified toolset, destructive tools require explicit opt-in, Gate 2 policy rules evaluated per-call. | `lib/guard.js`, `lib/policy.js` |
| Prevent calls to unknown tools | **Yes** | Tools not in the verified toolset are denied (`allowUnknownTools: false` by default). | `lib/guard.js` |
| Prevent calls with schema-violating args | **Yes** (strict mode) | `validateArgs()` walks the approved inputSchema against call args. Enabled with `strict: true`. | `lib/guard.js` |
| Prove what was authorized and called | **Yes** (with receipt key) | Signed, hash-chained Ed25519 receipts bind the exact contract version (toolDigest, toolsetDigest, args digest, result digest) to each call. | `lib/receipts.js` |
| Detect receipt chain tampering | **Yes** | `verifyReceiptChain` recomputes each receipt's digest from its payload and checks parentReceipt links against *actual* digests, not embedded claims. | `lib/receipts.js` |
| Detect manifest tampering | **Yes** | `verifyManifest` recomputes manifestDigest, toolsetDigest, and serverDigest from the payload and requires all to match. | `lib/provenance.js` |
| Enforce manifest freshness | **Yes** (signed manifests) | `expiresAt` field in signed manifests; `verifyManifest` rejects expired manifests. | `lib/provenance.js` |
| Enforce rotation freshness | **Yes** | Rotation certificates carry `expiresAt`; `verifyRotationCertificate` rejects lapsed certs. Revocation has no expiry by design. | `lib/rotation.js` |
| Detect dangerous tool capabilities | **Partial** | Three-engine static analysis: (1) heuristic verb/param matching with context-aware scoring, (2) TF-IDF semantic similarity, (3) prompt-injection marker detection (`<IMPORTANT>`, `[SYSTEM OVERRIDE]`, "ignore previous instructions", sensitive file paths, secrecy instructions). Catches declared destructive capabilities and description weaponization. Cannot detect a tool that *lies* in its description without using known injection patterns. | `lib/danger-detector.js` |
| Close TOCTOU window (discovery → call) | **Partial** | Fully closed for cooperating servers (handshake binding). For non-cooperating servers, bounded by `list_changed` re-diff + strict arg validation + receipts. Not eliminated. | `lib/session.js` |
| Enforce per-agent auth scopes | **Yes** (with auth configured) | Tools declare `requiredScopes` in the manifest. The proxy extracts a bearer token from each `tools/call` request, validates it (dev-issuer HMAC or OAuth 2.1 introspection), and blocks calls where the token's scopes don't satisfy the tool's requirements. Wildcard scopes (`*`, `read:*`) supported. | `lib/auth.js`, `lib/manifest.js`, `bin/mcp-proxy.js` |
| **Prove tool behavior** | **No** | Out of scope. trustcard pins the *contract* (definition), not what the code does when called. A signed read-only tool can still behave badly. | — |
| **Prevent malicious publishers** | **No** | Out of scope for cryptography. Signatures prove provenance, not intent. The scanner and social accountability are the mitigation. | — |
| **Guarantee publisher key safety** | **No** | Key compromise is a standard key-hygiene problem. Rotation is break-glass (old key signs new). No HSM/KMS integration. | — |
| **Guarantee registry integrity** | **No** | The registry is transport, not a trust root. A compromised registry can substitute manifests, but cannot forge publisher signatures. | — |
| **Provide a universal PKI** | **No** | TOFU + break-glass rotation is a deliberate choice for a decentralized ecosystem. If a key directory later exists, publisher keys can be anchored without format changes. | — |

## The two gates

trustcard separates two questions that are often conflated:

### Gate 1 — Trust-state continuity (objective, cacheable)

> "Is this still the capability I established?"

Answered by comparing the live observation against the pinned state:
toolsetDigest, serverDigest, publisher key. The result is a trust-state
transition (UNKNOWN → OBSERVED → PINNED → MISMATCH/SUSPECT → REVOKED).
This is objective — every client with the same pin reaches the same verdict.

**Code:** `lib/trust.js`, `lib/diff.js`, `lib/identity.js`

### Gate 2 — Invocation authorization (subjective, per-relying-party)

> "Given that the capability is still trusted, may *this* invocation — with
> *these* args, in *this* environment, by *this* relying party — run?"

Answered by composable rule predicates evaluated against the invocation.
A tool can be trusted (Gate 1 passes) while a specific invocation is denied
(Gate 2 blocks it). Gate 2 only ever *restricts* — it never widens access.

**Code:** `lib/policy.js`, `lib/guard.js` (the `invocationPolicy` path)

### Why the separation matters

Collapsing the two gates (as v1 did) forces a single global policy, which
destroys the per-relying-party model. An agent running in production and an
agent running in dev have the same trust state (Gate 1) but different
authorization (Gate 2: "allow `delete` in dev, deny in prod").

## Trust-state machine → trust level projection

The internal state machine has six states. For human-facing UIs and
high-level APIs, these project onto four trust levels:

```
Internal state    Trust level    Human meaning
──────────────    ───────────    ──────────────────────────────────
PINNED            TRUSTED        Green — pinned, verified, calls allowed
OBSERVED          OBSERVED       Yellow — seen but not pinned, calls denied
                  VERIFIED       Yellow — signed manifest verified but not pinned
SUSPECT           OBSERVED       Yellow — something looks off, calls denied
UNKNOWN           OBSERVED       Yellow — never seen, calls denied
MISMATCH          UNTRUSTED      Red — contract changed, calls blocked
REVOKED           REVOKED        Red — terminal, calls blocked, human re-pin required
```

The internal state machine is unchanged. The trust level is a derived
projection for display and API consumers:

```json
{
  "state": "PINNED",
  "trustLevel": "TRUSTED"
}
```

**Code:** `lib/trust.js` (state machine), `trustLevel()` projection function
in the same module.

## Manifest freshness

### Signed manifests (publisher provenance)

Signed manifests (`lib/provenance.js`) carry `issuedAt` and `expiresAt`.
Verification (`verifyManifest`) rejects an expired manifest. This prevents
a signed manifest from being valid forever — a publisher must re-sign
periodically, and a manifest signed five years ago is not trusted even if
the signature is still cryptographically valid.

```
Valid signature + not expired + not revoked = trusted.
Any failure = not trusted.
```

### Proxy manifests (call-time enforcement)

Proxy manifests (`lib/manifest.js`, produced by `gen-manifest`) carry
`createdAt` and `expiresAt`. The proxy's `checkCall` rejects calls when
the manifest has expired. The default expiry is 90 days from generation;
override with `--expires-in <days>` on `gen-manifest`.

An expired proxy manifest means the agent must re-generate it (re-run
`gen-manifest`), which re-runs the danger detector against the current
tool definitions. This ensures the danger analysis is fresh.

## Per-agent auth scopes (OAuth 2.1 + dev issuer)

trustcard enforces per-agent authorization at the proxy layer. Tools can
declare `requiredScopes` in the manifest, and the proxy validates a bearer
token against those scopes before forwarding the call to the server.

### How scopes are declared

Scopes come from three sources (in priority order):

1. **CLI override**: `gen-manifest --require-scopes <tool>:<scope1,scope2>`
   (repeatable). Use `*` as the tool name to apply to all tools.
2. **Server-declared**: `tool.annotations._meta.requiredScopes` — the server
   advertises what scopes its tools need.
3. **None**: a tool without `requiredScopes` is unscoped — any valid token
   (or no token at all) can call it.

### How tokens are validated

The proxy supports two token sources, configurable via CLI flags:

- **Dev issuer** (`--auth-secret <hex>`): HMAC-SHA256-signed JWT-like tokens
  issued by `mcp-trustcard auth-issue`. For local development only — no
  refresh tokens, no revocation, no PKCE flow.
- **External IdP** (`--auth-introspect <url>`): RFC 7662 token introspection
  against any OAuth 2.1 provider (Auth0, Okta, Keycloak, GitHub). Supports
  authenticated introspection via `--auth-client-id` / `--auth-client-secret`.
  Results are cached for 60 seconds by default.

Both can be active simultaneously — the proxy tries local verification first
(fast, no network), then falls back to IdP introspection.

### How tokens are extracted

The proxy looks for the token in two places (first match wins):

1. **Per-call**: `params._meta.auth.token` or `params._meta.authorization`
   (Bearer header style) on the `tools/call` request.
2. **Session-level**: the `MCP_AUTH_TOKEN` environment variable (override
   with `--auth-token-env`).

Auth metadata is stripped from the request before forwarding to the server —
the server never sees the trustcard-internal auth fields.

### Scope matching

Scopes are strings: `read:files`, `write:db`, `admin`, etc. Matching supports
wildcards:

- `*` matches everything
- `read:*` matches `read:files`, `read:db`, etc.

A call is allowed only if every required scope is satisfied by the token's
granted scopes. Missing scopes are reported in the denial message.

### Gate 2 integration

In addition to the proxy-layer check, `requireScopes` is available as a Gate 2
policy rule (`lib/policy.js`) for programmatic use via the Guard. This allows
scope checks to be combined with other invocation policies (environment
restrictions, argument constraints, destructive-tool approval) in a single
policy chain.

**Code:** `lib/auth.js` (token validation), `lib/manifest.js` (scope check in
`checkCall`), `lib/policy.js` (`requireScopes` rule), `bin/mcp-proxy.js`
(proxy enforcement).

## Schema versioning and migration

trustcard uses reverse-DNS schema identifiers with `@version` suffixes:

| Artifact | Schema | Code constant |
|---|---|---|
| Manifest | `trustcard.dev/manifest@1` | `MANIFEST_SCHEMA_VERSION` |
| Receipt | `trustcard.dev/receipt@1` | — |
| Capability descriptor | `trustcard.dev/descriptor@1` | — |
| Key rotation cert | `trustcard.dev/key-rotation@1` | `ROTATION_SCHEMA_VERSION` |
| Revocation cert | `trustcard.dev/revocation@1` | `REVOCATION_SCHEMA_VERSION` |
| Pin store | `trustcard.dev/pins@1` | `PINFILE_SCHEMA` |

### Migration contract

When a schema advances from `@N` to `@N+1`:

1. **A v(N+1) verifier MUST read vN.** Old schemas are accepted; the verifier
   applies vN semantics to vN data and v(N+1) semantics to v(N+1) data.
2. **A vN verifier MUST reject v(N+1).** An unknown schema is a verification
   failure, not a fallback. This prevents a vN client from silently accepting
   a v(N+1) manifest whose new fields it doesn't understand.
3. **A v(N+1) verifier MUST reject unknown critical fields.** A field is
   "critical" if its presence changes the trust decision. The manifest's
   `schema` field identifies which fields are defined for that version; any
   unrecognized field in a vN manifest is treated as a verification failure.
4. **Signatures are preserved across reads.** A v(N+1) verifier reading a vN
   manifest verifies the vN signature against the vN payload — it does not
   re-sign or upgrade the manifest in place.
5. **Manifest versions are immutable.** A manifest with `schema: "@1"` is
   always `@1`. To produce an `@2` manifest, generate a new manifest with
   the `@2` schema and sign it. There is no in-place upgrade.

This contract is enforced by `verifyManifest` (line 93: unknown schema →
error) and by the pin store (line 33: schema must match `PINFILE_SCHEMA`).

## What trustcard is not

- **Not a sandbox.** trustcard does not restrict what a tool can do at
  runtime. A signed read-only tool can still read sensitive files if the
  server implementation chooses to. Use least-privilege environments and
  OS-level isolation for runtime containment.
- **Not a policy engine.** Gate 2 is a small set of composable rule
  predicates, not a policy language. There is no DSL, no policy file, no
  hot-reload. Policies are defined in application code at Guard
  construction time. This is deliberate — a policy language would force
  global agreement and destroy the per-relying-party model.
- **Not a registry.** trustcard defines the manifest format and the
  verification protocol. It does not operate a public key directory or a
  manifest lookup service. The pin store is local TOFU state, not a
  registry.
- **Not an AI safety system.** The danger detector is static analysis
  (regex + TF-IDF + injection markers), not model inference. It catches
  *declared* destructive capabilities and *known* prompt-injection patterns,
  not *behavioral* dangers. A tool that lies in its description without
  using known injection markers will not be caught by the danger detector.
  The injection detector is pattern-based, not semantic — novel injection
  techniques that avoid the known markers will pass through.

## Known limitations

- **Naive scan client.** The scan client deliberately stays naive — it does
  not declare `capabilities.tools.taskSupport: 'required'` or other advanced
  capabilities. This is by design: it tests what a naive agent experiences.
  Servers that require augmented capabilities (e.g. the `everything` server's
  `simulate-research-query`) will error out during scanning. This surfaces the
  discovery gap, not a bug.
- **Pattern-based injection detection.** The injection detector matches known
  patterns (`<IMPORTANT>`, `[SYSTEM OVERRIDE]`, "ignore previous instructions",
  etc.). Novel injection techniques that avoid these markers will pass through.
  The detector is not semantic — it does not understand the *intent* of a
  description, only whether it contains known attack patterns.
- **Single probe.** Secret exposure is `UNKNOWN` unless a secret surfaces in
  one scan run. A real audit needs fuzzing and traffic replay.
- **No runtime sandboxing.** trustcard enforces the *contract*, not the
  *behavior*. A signed read-only tool can still behave badly. Use OS-level
  isolation for runtime containment.

## Deployment model

trustcard is designed for the **per-agent enforcement** model: each agent
(or agent framework) runs its own proxy with its own manifest and pin store.
There is no shared state across proxy instances.

```
  Agent ←→ mcp-proxy (manifest + pin store) ←→ MCP server
```

This means:
- Trust state is per-agent. A server REVOKED by agent A is still PINNED
  for agent B until B's own proxy detects the same issue.
- Pin stores are not synchronized. Each agent has its own TOFU state.
- Rate limits and call counts are per-proxy, not global.

For horizontal scaling, run one proxy per agent instance. Do not share a
single proxy across multiple agents — the trust state and policy scope are
per-relying-party by design.
