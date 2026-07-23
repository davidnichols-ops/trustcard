# trustcard

> **Cryptographic trust infrastructure for executable capabilities.**
>
> Content-addressed capability identity, signed provenance, trust continuity, and call-time enforcement — with an empirical health scanner for MCP servers.

[![tests](https://img.shields.io/badge/tests-passing-brightgreen)](#development)
[![manifest](https://img.shields.io/badge/manifest-trustcard.dev%2Fmanifest%401-blue)](docs/SPEC.md)

Agents increasingly execute capabilities they did not build, inspect, or previously encounter:

- MCP tools
- APIs
- plugins
- packages
- workflows
- remote services
- other agents

The fundamental problem is simple:

> **Before an agent calls a capability, how does it know what it is, who authorized it, whether it has changed, and whether this specific call is allowed?**

Today, the usual model is:

```text
discover → connect → call
```

trustcard adds the missing trust layer:

```text
discover
    ↓
identify
    ↓
verify provenance
    ↓
compare against trusted state
    ↓
evaluate policy
    ↓
allow / warn / block
    ↓
record evidence
```

## The core primitive

trustcard turns an executable capability into a **content-addressed, verifiable object**.

```text
┌──────────────────────────────────────────────────────────────┐
│                     EXECUTABLE CAPABILITY                   │
│                                                              │
│   What does it expose?       →  Capability identity          │
│   Who authorized it?          →  Signed provenance            │
│   Has it changed?             →  Change classification         │
│   Is this the thing I trust? →  Trust continuity              │
│   May this call happen?       →  Policy enforcement            │
│   What happened?              →  Tamper-evident receipt        │
└──────────────────────────────────────────────────────────────┘
```

For MCP, a tool's identity is derived from a canonical semantic projection:

```text
toolDigest   = SHA-256(JCS(semantic tool projection))
toolsetDigest = SHA-256(JCS(sorted tool digests))
serverDigest  = SHA-256(JCS(server identity + protocol + toolset))
```

The result is a stable identity for **what the capability actually is**.

Not:

```text
"the server responded successfully once"
```

But:

```text
"this exact capability contract is the one I approved"
```

## The trust model

trustcard combines five layers:

### 1. Capability identity

Every tool, toolset, and server receives a deterministic cryptographic identity.

The identity is based on the fields that affect what an agent can do or believe. Cosmetic or volatile metadata does not create a false trust event.

### 2. Provenance

Publishers can sign complete capability manifests with Ed25519.

A server can claim:

```text
"I serve this toolset."
```

A publisher can attest:

```text
"I authorized this exact toolset."
```

A client can verify:

```text
"The capability I received is the capability that was signed."
```

### 3. Trust continuity

Clients can pin observed or signed state:

```text
UNKNOWN
   ↓
OBSERVED
   ↓
PINNED
   ↓
      ┌───────────────┐
      │               │
      ▼               │
  MISMATCH        SUSPECT
      │               │
      └───────┬───────┘
              ▼
           REVOKED
```

For human-facing UIs and high-level APIs, these six internal states project
onto four trust levels:

```text
Internal state    Trust level    Meaning
──────────────    ───────────    ──────────────────
PINNED            TRUSTED        Green — verified, calls allowed
OBSERVED          OBSERVED       Yellow — seen but not pinned
SUSPECT           OBSERVED       Yellow — something looks off
UNKNOWN           OBSERVED       Yellow — never seen
MISMATCH          UNTRUSTED      Red — contract changed
REVOKED           REVOKED        Red — terminal, human re-pin required
```

A later connection is not merely:

```text
"the server is reachable"
```

It becomes:

```text
"the server is still the capability I previously trusted"
```

### 4. Change classification

A digest mismatch is not enough.

trustcard classifies the semantic meaning of change:

```text
NONE
  ↓
SYNTACTIC
  ↓
NON_BREAKING
  ↓
ANNOTATION_DOWNGRADE
  ↓
PERMISSION_CHANGE
  ↓
BREAKING
```

This lets policy distinguish between:

```text
description changed
```

and:

```text
a new destructive capability appeared
```

and:

```text
a previously safe parameter became unrestricted
```

The client learns not merely that something changed, but **what the change means**.

### 5. Call-time enforcement

Trustcard applies a two-gate model to invocation:

```text
GATE 1
Is this the capability we approved?
        │
        ▼
Capability identity + trust state
        │
        ▼
GATE 2
May this agent make this call?
        │
        ▼
Policy + pinned schema + arguments
        │
        ▼
      ALLOW
```

A trusted server is not automatically authorized to perform every call.

Trust is not permission.

## Quickstart

```bash
npm install -g mcp-trustcard
```

Or use it without installation:

```bash
npx mcp-trustcard <command>
```

### Inspect a capability

```bash
mcp-trustcard fingerprint @modelcontextprotocol/server-memory
```

```text
Trustcard: memory-server
────────────────────────────────────────────────────────
Server       memory-server@0.6.3
Protocol     2025-06-18
Tools        9
Toolset      sha256:077EddEANnTm…
Server       sha256:FiELfkb8KDtT…
Manifest     VERIFIED
Pin          MATCH
────────────────────────────────────────────────────────
```

### Pin trust on first use

```bash
mcp-trustcard pin @modelcontextprotocol/server-memory
mcp-trustcard pins
```

Later connections can detect and classify drift.

### Compare two capability states

```bash
mcp-trustcard diff old.json new.json --verbose
```

### Sign a capability manifest

```bash
mcp-trustcard keygen --out publisher.key.json

mcp-trustcard manifest \
  your-server \
  --key publisher.key.json \
  --out manifest.json

mcp-trustcard sign \
  manifest.json \
  --key publisher.key.json \
  --out signed.json
```

## Use it as middleware

Trustcard can sit between an MCP client and server.

```js
import { TrustSession } from "mcp-trustcard/lib/session.js";
import { TrustStore } from "mcp-trustcard/lib/trust.js";
import { Guard } from "mcp-trustcard/lib/guard.js";
import { wrapClient } from "mcp-trustcard/lib/middleware.js";

const trust = new TrustStore({
  policy: { requireSignature: true }
});

const guard = new Guard({
  mode: "enforce",
  policy: { allowDestructive: false }
});

const session = new TrustSession({
  cmd,
  args,
  env,
  trust,
  guard,
  protocolVersions
});

await session.connect();

trust.pin(
  session.serverId,
  session.observation
);

const secure = wrapClient(rawMcpClient, {
  guard,
  session,
  strictArgs: true
});

await secure.request("tools/call", {
  name: "search",
  arguments: { query: "x" }
});
```

The call can be denied when:

- the server is revoked
- the server no longer matches its trusted identity
- the tool is unknown
- the tool is not in the approved manifest
- the tool is destructive under policy
- the arguments violate the approved schema

## The MCP scanner

Trustcard also includes the original reason the project exists:

```bash
mcp-trustcard scan <server>
```

The scanner is the **empirical layer**.

It answers:

> **What does this server actually do when a client connects to it?**

The protocol answers:

> **Is this the capability I intended to trust?**

Both questions matter.

### Scan a server

```bash
mcp-trustcard scan @modelcontextprotocol/server-github
```

```bash
mcp-trustcard scan @modelcontextprotocol/server-github --json
```

```bash
mcp-trustcard scan --strict <server>
```

```bash
mcp-trustcard scan --threshold 70 <server>
```

### The eight checks

| Check | Points | Question |
|---|---:|---|
| Installability | 15 | Can the package be resolved? |
| Protocol handshake | 25 | Does it speak MCP correctly? |
| Tool schema validity | 15 | Are its schemas valid? |
| Destructive capabilities | 10 | Does it expose dangerous capabilities? |
| Authentication | 10 | Does it clearly handle authentication? |
| Secret exposure | 10 | Does it expose secret-shaped material? |
| Protocol version | 10 | Does it negotiate a supported protocol? |
| Latency / failure rate | 5 | Does it respond reliably? |

The score is useful for:

- CI
- discovery
- regression detection
- ecosystem visibility

But a score is not a trust decision.

A server scoring `95` can still be the wrong capability for a particular agent.

A server scoring `60` can still be acceptable under a constrained policy.

**Trustcard separates empirical health from cryptographic identity.**

### Danger detection — three engines

The destructive-capabilities check uses a **three-engine fusion**:

1. **Heuristic engine** — word-boundary regex for destructive verbs (`delete`,
   `destroy`, `drop`, `kill`, …) and write/exec verbs, plus `inputSchema`
   parameter analysis for dangerous inputs (`command`, `sql`, `path`, `url`,
   `webhook`, `script`). Context-aware scoring: verbs like `clear` and `reset`
   are only destructive when paired with destructive nouns (files, data, cache,
   database) — not when used in cognitive tools ("clear thoughts").
2. **Semantic engine** — TF-IDF vectors over tool names + descriptions, compared
   against a curated corpus of dangerous-action patterns using cosine similarity.
   Catches novel attacks that avoid known verbs (e.g. "invalidate stored data").
3. **Injection engine (v2.2)** — scans tool descriptions for prompt-injection
   markers: `<IMPORTANT>` tags, `[SYSTEM OVERRIDE]` brackets, "ignore previous
   instructions", "do not tell the user", sensitive file paths (`~/.ssh/id_rsa`),
   secrecy instructions, base64 blobs, and exfiltration language. This is a
   separate threat class from destructive actions — a tool can have a benign
   schema ("add two numbers") with a weaponized description.

**Fusion logic:** when multiple engines flag a tool, confidence is `high`. When
only one flags it, `medium`/`low`. A tool is marked dangerous when the fused
score exceeds 0.3.

**Safe tool patterns:** idempotent non-destructive operations (`create_directory`,
`mkdir`, `sequentialthinking`) are whitelisted — the override applies unless the
injection detector flags the description (a poisoned `create_directory` is still
dangerous).

## Call-time protection

A scan is a snapshot.

Capabilities can change after the scan.

The proxy enforces an approved manifest at runtime:

```bash
# Generate a manifest (includes danger analysis + 90-day expiry by default)
mcp-trustcard gen-manifest \
  @modelcontextprotocol/server-memory \
  --save-manifest memory.json

# For local commands (e.g. a Python server):
mcp-trustcard gen-manifest \
  --save-manifest my-server.json \
  --allow-tool dangerous_but_reviewed_tool \
  --expires-in 30 \
  -- uv run my-server mcp serve

# Inspect a manifest or pin store
mcp-trustcard inspect memory.json

# Enforce at call time (stdio)
mcp-proxy \
  --manifest memory.json \
  -- npx -y @modelcontextprotocol/server-memory
```

For remote HTTP/SSE servers:

```bash
mcp-http-proxy \
  --manifest notion.json \
  --upstream https://example.com/mcp \
  --port 9876 \
  --strict
```

The proxy can detect:

- new tools
- removed tools
- changed schemas
- unapproved calls
- manifest drift
- manifest expiration

It can then:

```text
ALLOW
WARN
BLOCK
```

according to policy.

### Manifest expiration

Manifests carry an `expiresAt` timestamp (default: 90 days). An expired
manifest blocks all calls until regenerated, ensuring the danger analysis
stays fresh. Override with `--expires-in <days>` or `--no-expiry`.

### Tool overrides

Tools flagged as dangerous by the danger detector can be explicitly allowed
with `--allow-tool <name>` (repeatable). The override is recorded in the
manifest as `manualOverride: true` so it's visible in audit. Use this only
for tools you've reviewed and that have their own safety constraints.

### Per-agent auth scopes

The proxy can enforce per-agent authorization using OAuth 2.1 token scopes.
Tools declare `requiredScopes` in the manifest; the proxy validates a bearer
token against those scopes before forwarding the call.

```bash
# 1. Generate a manifest with scope requirements
mcp-trustcard gen-manifest \
  --save-manifest my-server.json \
  --require-scopes delete_file=write:files \
  --require-scopes *:read:files \
  -- uv run my-server mcp serve

# 2. Issue a dev-mode token (for local development)
export TRUSTCARD_AUTH_SECRET="my-shared-secret"
TOKEN=$(mcp-trustcard auth-issue \
  --subject agent-readonly \
  --scopes read:files \
  --secret "$TRUSTCARD_AUTH_SECRET" \
  --quiet)

# 3. Start the proxy with auth enforcement
MCP_AUTH_TOKEN="$TOKEN" mcp-proxy \
  --manifest my-server.json \
  --auth-secret "$TRUSTCARD_AUTH_SECRET" \
  -- uv run my-server mcp serve
```

For external OAuth 2.1 providers (Auth0, Okta, Keycloak, GitHub):

```bash
mcp-proxy \
  --manifest my-server.json \
  --auth-introspect https://your-idp/oauth/introspect \
  --auth-client-id $CLIENT_ID \
  --auth-client-secret $CLIENT_SECRET \
  -- npx -y @modelcontextprotocol/server-github
```

Scope matching supports wildcards: `*` matches everything, `read:*` matches
`read:files`, `read:db`, etc. A call is allowed only if every required scope
is satisfied by the token's granted scopes.

### Why blocked?

Every denial includes a structured explanation — not just "DENIED" but
the tool name, the reason code (`MANIFEST_EXPIRED`, `TOOL_NOT_APPROVED`,
`DANGEROUS_TOOL`, `INSUFFICIENT_SCOPES`), the danger score, and the action to take.

## Signed, chained receipts

Trustcard can bind a call to the capability that authorized it:

```text
{
  capability: toolsetDigest,
  tool: toolDigest,
  arguments: argsDigest,
  result: resultDigest
}
```

Receipts are signed and hash-chained:

```text
receipt[n]
    ↓
hash
    ↓
receipt[n+1]
```

This makes the history tamper-evident.

A receipt is evidence of a decision and an observed interaction.

It is **not** proof that a server behaved honestly internally.

## Capability descriptors

The trust model is not fundamentally MCP-specific.

MCP is the first supported protocol.

The deeper abstraction is:

```text
                ┌─────────────┐
MCP ───────────▶│             │
OpenAPI ───────▶│ Capability  │
Function calls ─▶│ Descriptor │
Plugins ────────▶│             │
Agents ─────────▶│             │
                └──────┬──────┘
                       │
                       ▼
              Canonical identity
              Provenance
              Change
              Policy
              Receipts
```

A capability descriptor projects different execution surfaces into one canonical trust model.

The goal is simple:

> **Trust should attach to what a capability can do, not to the protocol that happens to transport it.**

## What trustcard does not claim

For the full guarantees table, see [`docs/SECURITY-MODEL.md`](docs/SECURITY-MODEL.md).

Trustcard is not a sandbox.

A signed capability can still be malicious.

A publisher can sign bad software.

A trusted server can have a vulnerability.

A receipt can prove what was authorized and observed, not that the server's internal execution was honest.

Trustcard addresses:

```text
identity
provenance
continuity
change
authorization
evidence
```

It does not replace:

```text
sandboxing
least privilege
runtime isolation
code auditing
secret management
```

Those are complementary controls.

## Documentation

- [`docs/SECURITY-MODEL.md`](docs/SECURITY-MODEL.md) — **what trustcard guarantees and what it doesn't** (read this first)
- [`docs/SPEC.md`](docs/SPEC.md) — normative protocol specification
- [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) — threats and non-goals
- [`docs/DESCRIPTOR.md`](docs/DESCRIPTOR.md) — protocol-neutral capability descriptors
- [`docs/ANALYSIS.md`](docs/ANALYSIS.md) — why health probing alone was insufficient
- [`docs/TRUST-SUBSTRATE.md`](docs/TRUST-SUBSTRATE.md) — generalization beyond MCP
- [`docs/AUDIT-REPORT-v2.md`](docs/AUDIT-REPORT-v2.md) — adversarial architecture audit
- [`docs/REGISTRY-INTEGRATION.md`](docs/REGISTRY-INTEGRATION.md) — registry integration
- [`docs/MIGRATION.md`](docs/MIGRATION.md) — v0.x → v1
- [`examples/production-agent/`](examples/production-agent/) — reference deployment architecture
- [`CHANGELOG.md`](CHANGELOG.md) — release history

## Development

```bash
npm test
npm run test:fast
```

Trustcard is implemented with Node.js standard-library primitives, including:

```text
node:crypto
node:child_process
```

## The short version

```text
A scanner tells you what a server looked like.

A signature tells you who authorized a capability.

A digest tells you what the capability is.

A pin tells you whether it changed.

A policy tells you whether the call is allowed.

A receipt tells you what was authorized and observed.

trustcard combines all of them.
```

## License

MIT
