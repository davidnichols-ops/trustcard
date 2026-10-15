# trustcard

> **Cryptographic trust infrastructure for executable capabilities.**
>
<p align="center">
  <img src="https://github.com/user-attachments/assets/40336664-70f6-4df2-9572-5817833a89cb" alt="trust_card" width="140" style="margin-bottom:8px;" />
</p>

<p align="center">
  <a href="#development"><img src="https://img.shields.io/badge/tests-passing-brightgreen" alt="tests"></a>
  <a href="docs/SPEC.md"><img src="https://img.shields.io/badge/manifest-trustcard.dev%2Fmanifest%401-blue" alt="manifest"></a>
</p>

> Content-addressed capability identity, signed provenance, trust continuity, call-time enforcement, behavioral verification, and tamper-evident evidence — for MCP servers, and eventually any executable capability consumers.

Agents increasingly call capabilities they did not build, inspect, or previously encounter:

- MCP tools
- remote APIs
- plugins
- packages
- workflows
- other agents

The fundamental problem is simple:

> **Before an agent calls a capability, how does it know what it is, who authorized it, whether it has changed, whether the running code honors the contract, and whether this specific call is allowed?[...]

The usual model is:

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
verify behavior
    ↓
record evidence
    ↓
allow / warn / block
```

## The core primitives

trustcard turns an executable capability into a **content-addressed, verifiable object**.

```text
┌──────────────────────────────────────────────────────────────┐
│                     EXECUTABLE CAPABILITY                   │
│                                                              │
│   What does it expose?        →  Capability identity          │
│   Who authorized it?          →  Signed provenance            │
│   Has it changed?             →  Change classification         │
│   Is this the thing I trust?  →  Trust continuity              │
│   May this call happen?       →  Policy enforcement            │
│   Does the code honor it?     →  Behavioral verification      │
│   What happened?              →  Tamper-evident evidence       │
└──────────────────────────────────────────────────────────────┘
```

For MCP, a tool's identity is derived from a canonical semantic projection:

```text
toolDigest      = SHA-256(JCS(semantic tool projection))
toolsetDigest   = SHA-256(JCS(sorted tool digests))
serverDigest    = SHA-256(JCS(server identity + protocol + toolset))
```

The result is a stable identity for **what the capability actually is**:

```text
"this exact capability contract is the one I approved"
```

not merely:

```text
"the server responded successfully once"
```

## The trust model

trustcard combines six layers:

### 1. Capability identity

Every tool, toolset, and server receives a deterministic cryptographic identity.

The identity is based on the fields that affect what an agent can do or believe. Cosmetic or volatile metadata does not create a false trust event.

### 2. Provenance

Publishers can sign complete capability manifests with Ed25519.

```text
server:    "I serve this toolset."
publisher: "I authorized this exact toolset."
client:    "The capability I received is the capability that was signed."
```

### 3. Trust continuity

Clients pin observed or signed state. A later connection is not just "reachable" — it is "still the capability I previously trusted."

```text
UNKNOWN → OBSERVED → PINNED → MISMATCH/SUSPECT → REVOKED
```

`REVOKED` is terminal and sticky; only explicit re-approval exits it.

For human-facing UIs, the internal states project onto four trust levels:

```text
PINNED     → TRUSTED
OBSERVED   → OBSERVED
SUSPECT    → OBSERVED
UNKNOWN    → OBSERVED
MISMATCH   → UNTRUSTED
REVOKED    → REVOKED
```

### 4. Change classification

A digest mismatch is not enough. trustcard classifies the semantic meaning of change:

```text
NONE < SYNTACTIC < NON_BREAKING < ANNOTATION_DOWNGRADE < PERMISSION_CHANGE < BREAKING
```

This lets policy distinguish a renamed title, a widened optional argument, a rewritten description, a permission downgrade, and a removed required parameter.

### 5. Call-time enforcement

trustcard applies a two-gate model:

```text
GATE 1: Is this still the capability we approved?
        → capability identity + trust state

GATE 2: May this agent make this call?
        → policy + pinned schema + arguments + environment
```

A trusted server is not automatically authorized to perform every call. Trust is not permission.

### 6. Behavioral verification

Static identity can pass while runtime behavior diverges. `mcp-trustcard behavior` executes a server as a process-isolated stdio child (fresh cwd, minimal environment — not an OS sandbox), fires deterministic seeded probes, and compares observations against a reference baseline.

It catches:

- prompt-injection markers minted in tool output
- secret canary leakage
- exfiltration URLs in output or stderr
- unexpected network/filesystem/process events
- schema violations and output-shape drift
- nondeterministic behavior

The acceptance test is intentionally strong: **static verification can accept a server while behavioral verification fails it, for the same unchanged contract.**

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

### Pin trust on first use

```bash
mcp-trustcard pin @modelcontextprotocol/server-memory
mcp-trustcard pins
```

Later connections detect and classify drift.

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

### Verify behavior against a reference

```bash
# Build a manifest from a live probe
mcp-trustcard manifest @modelcontextprotocol/server-memory --out manifest.json

# Capture a reference behavior report
mcp-trustcard behavior manifest.json --server @modelcontextprotocol/server-memory \
  --json --out reference.json

# Later, verify the same or a different build/region
mcp-trustcard behavior manifest.json --server @modelcontextprotocol/server-memory \
  --json --out target.json

# Compare two reports directly
mcp-trustcard behavior diff reference.json target.json
```

## CLI commands

| Command | Purpose |
|---|---|
| `fingerprint <spec>` | Full identity card: digests, provenance, pin continuity |
| `scan <spec>` | Empirical health scorecard |
| `manifest <spec>` | Build an unsigned crypto manifest from a live probe |
| `keygen` | Generate a publisher Ed25519 keypair |
| `sign <manifest.json>` | Sign a manifest |
| `verify <signed.json>` | Verify signature, digests, and optional live binding |
| `diff <old.json> <new.json>` | Classify changes (BREAKING/PERMISSION/ANNOTATION_DOWNGRADE/NON_BREAKING/SYNTACTIC) |
| `pin <spec>` / `unpin <key>` / `pins` | TOFU pin-store management |
| `gen-manifest <spec> --save-manifest <file>` | Build a proxy-enforcement manifest |
| `inspect <file>` | Inspect a manifest or pin store |
| `auth-issue` / `auth-verify` | Issue or verify dev-mode scoped tokens |
| `descriptor build <tool-or-manifest.json>` | Build a protocol-neutral capability descriptor |
| `descriptor sign <desc.json>` | Sign a descriptor |
| `descriptor verify <desc.json>` | Verify a signed descriptor |
| `descriptor diff <old.json> <new.json>` | Compare two descriptors |
| `descriptor pin <desc.json>` | Pin a descriptor to the local store |
| `behavior <manifest.json> [--server <spec>]` | Run behavioral probes and emit a report |
| `behavior <manifest.json> -- <cmd> [args...]` | Run behavioral probes against a local server |
| `behavior diff <ref.json> <target.json>` | Compare two behavior reports |
| `evidence query` / `stats` / `verify` / `export` / `contradictions` | Query and audit the local evidence store |

Use `--help` on any subcommand for options.

## Use it as middleware

trustcard can sit between an MCP client and server.

```js
import { TrustSession } from "mcp-trustcard/lib/session.js";
import { TrustStore } from "mcp-trustcard/lib/trust.js";
import { Guard } from "mcp-trustcard/lib/guard.js";
import { wrapClient } from "mcp-trustcard/lib/middleware.js";

const trust = new TrustStore({ policy: { requireSignature: true } });
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

A call can be denied when:

- the server is revoked
- the server no longer matches its trusted identity
- the tool is unknown
- the tool is not in the approved manifest
- the tool is destructive under policy
- the arguments violate the approved schema
- the caller lacks required OAuth 2.1 scopes

## The MCP scanner

`mcp-trustcard scan` is the empirical layer. It answers:

> **What does this server actually do when a client connects?**

The protocol answers:

> **Is this the capability I intended to trust?**

Both questions matter.

### Scan a server

```bash
mcp-trustcard scan @modelcontextprotocol/server-github
mcp-trustcard scan @modelcontextprotocol/server-github --json
mcp-trustcard scan --strict <server>
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

A score is useful for CI, discovery, regression detection, and ecosystem visibility. **A score is not a trust decision.** A server scoring `95` can still be the wrong capability for a particular agent[...] 

### Danger detection — three engines

The destructive-capabilities check uses a **three-engine fusion**:

1. **Heuristic engine** — word-boundary regex for destructive verbs and dangerous parameters, with context-aware scoring (`clear` is only destructive when paired with destructive nouns).
2. **Semantic engine** — TF-IDF vectors over tool names and descriptions compared against a curated dangerous-action corpus.
3. **Injection engine** — scans descriptions for prompt-injection markers (`<IMPORTANT>`, `[SYSTEM OVERRIDE]`, "ignore previous instructions", sensitive paths, secrecy instructions, base64 blobs, ex[...] 

Safe tool patterns (`create_directory`, `mkdir`, `sequentialthinking`) are whitelisted unless the injection detector flags the description.

## Call-time protection

A scan is a snapshot. Capabilities can change after the scan. The proxy enforces an approved manifest at runtime:

```bash
# Build a manifest (includes danger analysis + 90-day expiry by default)
mcp-trustcard gen-manifest \
  @modelcontextprotocol/server-memory \
  --save-manifest memory.json

# For local commands (e.g. a Python server)
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

The proxy can detect new tools, removed tools, changed schemas, unapproved calls, manifest drift, and manifest expiration. It responds:

```text
ALLOW
WARN
BLOCK
```

according to policy.

### Manifest expiration

Manifests carry an `expiresAt` timestamp (default: 90 days). An expired manifest blocks all calls until regenerated, ensuring the danger analysis stays fresh. Override with `--expires-in <days>` or `-[...]`

### Tool overrides

Tools flagged as dangerous can be explicitly allowed with `--allow-tool <name>` (repeatable). The override is recorded in the manifest as `manualOverride: true` so it's visible in audit.

### Per-agent auth scopes

The proxy can enforce per-agent authorization using OAuth 2.1 token scopes:

```bash
# 1. Build a manifest with scope requirements
mcp-trustcard gen-manifest \
  --save-manifest my-server.json \
  --require-scopes delete_file=write:files \
  --require-scopes *=read:files \
  -- uv run my-server mcp serve

# 2. Issue a dev-mode token (for local development)
# Secrets go via TRUSTCARD_AUTH_SECRET or --secret-file <path|->;
# --secret <hex> works but exposes the key in the process list.
export TRUSTCARD_AUTH_SECRET="my-shared-secret"
TOKEN=$(mcp-trustcard auth-issue \
  --subject agent-readonly \
  --scopes read:files \
  --quiet)

# 3. Start the proxy with auth enforcement
MCP_AUTH_TOKEN="$TOKEN" mcp-proxy \
  --manifest my-server.json \
  --auth-secret-file <(echo "$TRUSTCARD_AUTH_SECRET") \
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

Scope matching supports wildcards: `*` matches everything, `read:*` matches `read:files`, `read:db`, etc. A call is allowed only if every required scope is satisfied by the token's granted scopes.

## Behavioral verification

Static trust tells you the contract has not changed. It does not tell you the running code honors the contract.

`mcp-trustcard behavior` runs the server as a process-isolated stdio child (fresh cwd and minimal environment — not an OS sandbox; the child can still reach the network and filesystem), fires deterministic probes, and compares the results against a captured reference or baseline expectations.

```bash
mcp-trustcard behavior <manifest.json> [--server <spec>] [--json]
mcp-trustcard behavior <manifest.json> -- <cmd> [args...] [--json]
mcp-trustcard behavior diff reference.json target.json
```

Probe categories include valid, boundary, malformed, long strings, unicode, path-like, URL-like, prompt-injection, and secret-canary inputs. Reports include `divergenceClass`, `severity`, `confidence`[...] 

See [`docs/BEHAVIOR.md`](docs/BEHAVIOR.md) for the full model.

## Evidence and the observatory

trustcard records verifiable observations in a local evidence store:

```bash
mcp-trustcard evidence query --subject <name>
mcp-trustcard evidence history --subject <name>
mcp-trustcard evidence verify
mcp-trustcard evidence export --json-out evidence.json
```

Evidence records are content-addressed, immutable, and forward-compatible. They are the source of truth from which scores and trust decisions are derived. The long-term vision is a peer-to-peer observ[...] 

## Signed, chained receipts

trustcard can bind a call to the capability that authorized it:

```json
{
  "schema": "trustcard.dev/receipt@1",
  "at": "2026-08-15T19:28:00.000Z",
  "server": { "name": "server-memory", "version": "1.0.0" },
  "tool": "read_file",
  "toolsetDigest": "sha256:...",
  "argumentsDigest": "sha256:...",
  "resultDigest": "sha256:..."
}
```

Receipts are signed and hash-chained, making the history tamper-evident. A receipt is evidence of a decision and an observed interaction; it is **not** proof that a server behaved honestly internally.

## Capability descriptors

trustcard is not fundamentally MCP-specific. The deeper abstraction is a protocol-neutral capability descriptor that projects different execution surfaces into one canonical trust model:

```text
                ┌─────────────┐
MCP ───────────▶│             │
OpenAPI ───────▶│ Capability  │
Function calls ─▶│ Descriptor  │
Plugins ───────▶│             │
Agents ────────▶│             │
                └──────┬──────┘
                       │
                       ▼
              Canonical identity
              Provenance
              Change
              Policy
              Receipts
              Evidence
```

For example, build and sign a descriptor for one tool:

```bash
mcp-trustcard descriptor build manifest.json --key publisher.key.json --tool read_file --out desc.json
mcp-trustcard descriptor sign desc.json --key publisher.key.json --out signed-desc.json
mcp-trustcard descriptor verify signed-desc.json
```

The goal is simple:

> **Trust should attach to what a capability can do, not to the protocol that happens to transport it.**

## What trustcard does not claim

For the full guarantees table, see [`docs/SECURITY-MODEL.md`](docs/SECURITY-MODEL.md).

trustcard is not a sandbox. A signed capability can still be malicious. A publisher can sign bad software. A trusted server can have a vulnerability. A receipt can prove what was authorized and observ[...] 

trustcard addresses:

```text
identity
provenance
continuity
change
authorization
behavioral verification
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

See [`docs/INDEX.md`](docs/INDEX.md) for a map of the documentation.

Key documents:

- [`docs/SECURITY-MODEL.md`](docs/SECURITY-MODEL.md) — what trustcard guarantees and what it doesn't
- [`docs/SPEC.md`](docs/SPEC.md) — normative protocol specification
- [`docs/BEHAVIOR.md`](docs/BEHAVIOR.md) — behavioral verification model
- [`docs/ROADMAP-2Y.md`](docs/ROADMAP-2Y.md) — two-year dependency-gate plan
- [`docs/MIGRATION.md`](docs/MIGRATION.md) — version migration notes
- [`docs/KNOWN-LIMITATIONS.md`](docs/KNOWN-LIMITATIONS.md) — documented gaps

## Development

```bash
npm test
npm run test:fast
```

trustcard is implemented with Node.js standard-library primitives, including `node:crypto`, `node:child_process`, and `node:fs`. There are no runtime dependencies.

## The short version

```text
A scanner tells you what a server looked like.
A signature tells you who authorized a capability.
A digest tells you what the capability is.
A pin tells you whether it changed.
A policy tells you whether the call is allowed.
Behavioral verification tells you whether the code honored the contract.
Evidence tells you what was observed and when.

trustcard combines all of them.
```

## License

MIT

## Operations release candidate

The local 3.2.0-rc.1 candidate adds a reusable MCP governance skill, config-bound operations MCP, fleet renewal/reapproval and a local tool-access console. See [operations and deployment limits](docs/OPERATIONS.md). These features require the candidate package; they are not assumed to exist in the published 3.1.0 release.
