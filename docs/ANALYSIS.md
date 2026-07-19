# Trustcard v2 — analysis & verdict

This document answers the question the v2 work started with: **is the existing
Trustcard abstraction fundamentally sufficient?** It isn't — and the reason is
instructive, because it's the same reason most MCP security tooling today is
insufficient.

## 1. What the original trustcard actually is

The v0.x `mcp-trustcard` is a **health probe**. It spawns a server, completes
the handshake, enumerates tools, and scores eight checks (installability,
handshake, schema validity, destructive verbs, auth hints, secret patterns,
protocol version, latency). It answers: *"does this server behave right now,
probabilistically, on the axes I thought to measure?"*

That is genuinely useful — it caught that 3/10 well-known servers can't start
without undocumented configuration. But it has a structural ceiling.

## 2. Why the abstraction is insufficient

The probe model shares one fatal assumption with every scanner: **that the
thing you measured is the thing that will execute.** For MCP tools that
assumption is false in at least eight ways, and none of them are detectable by
probing harder.

### 2.1 No identity — "the same tool" is undefined

A health score is a number attached to a server name. But a tool is not its
name. Two `tools/list` responses with the same tool names can differ in
description, schema, or annotations, and the probe has no way to say "this is a
*different* tool than yesterday" — only "the score moved." Without a
content-addressed identity for a tool definition, every downstream concept
(versioning, caching, pinning, reproducibility) is undefined.

**Fix:** `toolDigest = SHA-256(JCS(semantic projection))`. See `docs/SPEC.md`.

### 2.2 The TOCTOU gap between discovery and execution

An agent's lifecycle is: enumerate tools → build a plan (possibly cached in a
prompt, a vector index, or a fine-tune) → call a tool. The server can mutate
its tool definitions at any point in that gap. The probe observes the tool at
discovery time; the call happens later against a potentially different
contract. This is a classic time-of-check/time-of-use race, and it's the
single most exploitable property of MCP for agents.

**Fix:** three layers — (a) a handshake binding so a cooperating server
commits to a `toolsetDigest` at `initialize`; (b) `notifications/tools/list_changed`
drives immediate re-enumeration + re-diff; (c) the guard re-verifies the
digest and can re-validate call arguments against the *pinned* schema.

### 2.3 Syntactic vs semantic change is never distinguished

The probe treats any change as score drift. But "the publisher added a `title`
to a tool" and "the publisher added a required parameter" are not the same
event. One is cosmetic; the other breaks every cached plan. Conflating them
means either false alarms (alert on cosmetic change) or missed breaks (ignore
drift as noise).

**Fix:** the semantic projection splits volatile fields (title/icons/_meta)
from semantic fields (name/description/schemas/annotations/execution). Only
semantic changes move the digest; the differ classifies the rest as SYNTACTIC.

### 2.4 No breaking-change taxonomy

"Schema changed" is not a decision. A client needs to know: can I keep using
my cached contract (compatible), must I re-plan (breaking), or must I
re-*trust* (permission/poisoning)? v2 implements a five-level taxonomy:
NONE < SYNTACTIC < NON_BREAKING < ANNOTATION_DOWNGRADE < PERMISSION_CHANGE <
BREAKING, with an explicit rule set over JSON Schema (required-added,
enum-shrink, constraint-tightening, type-narrowing, additionalProperties-close,
composition-introduced, output-schema-removed).

### 2.5 No server identity or provenance

The probe knows what a server *does*, not *who vouches for it*. A compromised
or malicious server can serve different tools to different clients, or mutate
after a good scan. Without provenance, a good score is a claim the server
makes about itself.

**Fix:** an Ed25519-signed manifest binding {server identity, protocol,
complete tool definitions} to a publisher key. A compromised *server* cannot
forge the publisher's signature, so runtime mutation is caught by digest
mismatch. Key continuity is TOFU-pinned.

### 2.6 No trust state — every observation is independent

The probe is memoryless. Trust is inherently stateful: you saw something
before, you decided to rely on it, and now you must detect that it changed.
v2 models this as an explicit state machine (UNKNOWN → OBSERVED → PINNED →
MISMATCH / SUSPECT → REVOKED) where every transition is an auditable event
with a machine-readable reason code.

### 2.7 No enforcement point

A score is advisory; nothing *stops* a call. The strongest version of the
system is one where the analysis is wired to a gate. v2 adds the Guard: a
middleware that authorizes every `tools/call` against the current trust state
and policy (deny if revoked/mismatch, deny unknown tools, deny destructive
unless allowed, strict mode validates args against the pinned schema).

### 2.8 No reproducibility

If a tool can change, then "calling `search` with these args" is not a
reproducible statement — it depends on *which version* of `search`. v2 emits
receipts binding {toolset digest, tool digest, arguments digest} → {result
digest}, making reproducibility a checkable property of a call log rather than
an assumption.

## 3. Verdict

| Dimension | v0.x probe | v2 protocol |
|---|---|---|
| Cryptographic tool identity | ✗ | ✓ content-addressed digests |
| Syntactic vs semantic | ✗ | ✓ semantic projection + SYNTACTIC class |
| Breaking-change classification | ✗ | ✓ five-level taxonomy + rule set |
| Version negotiation | observe only | ✓ negotiate + pin + binding |
| Stale-cache invalidation | ✗ | ✓ list_changed → re-diff |
| Server identity / provenance | ✗ | ✓ Ed25519 signed manifest + TOFU keys |
| Trust-state transitions | ✗ | ✓ auditable state machine |
| Permission-change detection | heuristics | ✓ annotation/execution drift class |
| Malicious-server model | ✗ | ✓ compromised-server caught by digest |
| TOCTOU race | ✗ | ✓ binding + re-verify + arg re-validation |
| Reproducibility | ✗ | ✓ signed receipts |
| Registry compatibility | proposal only | ✓ `_meta` extension (see docs) |

**The health probe is not the product; it is one signal.** The defensible
primitive is *content-addressed tool identity with signed provenance and an
enforcement gate*. v2 keeps the probe as the `scan` subcommand (it feeds the
`UNKNOWN`-state first observation) and builds the protocol around it.

## 4. What Trustcard should *be*

Evaluated against the four candidate forms:

- **A formal manifest** — yes, primarily. A signed, content-addressed document
  (`trustcard.manifest.json`) is the interoperable artifact any registry,
  client, or verifier can produce and check.
- **A protocol extension** — yes, secondarily. The handshake binding (a
  `_meta` key on `initialize`) and the `list_changed` invalidation contract
  are behavioral agreements between client and server that close the TOCTOU
  gap for cooperating servers.
- **A middleware standard** — yes, for adoption. The Guard/wrapClient contract
  is how existing agent frameworks get enforcement without forking their MCP
  client.
- **A scanner** — no longer the core. It remains as the empirical verifier and
  the declared-vs-observed drift detector.

So: **Trustcard is a signed tool-manifest standard plus a verification and
enforcement middleware, with the scanner as its reference verifier.**
