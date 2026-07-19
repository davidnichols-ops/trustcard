# Proposal: a signed trust manifest for MCP tools

> This supersedes the earlier `mcp.health` proposal. `mcp.health` was a
> *declared* health field. This is the thing that makes any declaration
> *verifiable*: content-addressed tool identity + a publisher signature + an
> enforcement contract.

## Problem

Agents treat MCP tool definitions as static contracts. They are not. Between
`tools/list` and `tools/call` a server can change a tool's description (to
poison the model), its schema (to break cached plans), or its annotations (to
escalate permissions) — and no client can detect any of it today, because
there is no machine-checkable notion of "the same tool" or "who vouches for
it." Clients connect blind, plan against a snapshot, and discover drift at
call time or never.

We measured the discovery gap empirically: scanning 10 recognizable servers as
a naive client, **3 of 10 could not complete a handshake**, and there was no
machine-readable way to learn why before connecting. That is the *mildest*
failure. The harder failures — poisoning, breaking drift, permission flips,
TOCTOU mutation — are invisible to any single observation.

## Proposal

Three small, composable pieces, each optional and backward-compatible.

### 1. A signed manifest (`trustcard.manifest.json`)

A publisher binds {server identity, protocol versions, complete tool
definitions} to an Ed25519 key. Identity is content-addressed:

```
toolDigest    = SHA-256( JCS( semantic projection of a tool ) )
toolsetDigest = SHA-256( JCS( sorted toolDigests ) )
```

The semantic projection is exactly the fields that change behavior: name,
description, input/output schemas, behavioral annotations, execution. Volatile
fields (title, icons, `_meta`) are excluded, so cosmetic edits are not trust
events. Signatures are detached over the JCS-canonical payload; keys are
self-certifying (`keyId = hash(publicKey)`), so no CA or registry key
directory is needed on day one.

**Full format + verification algorithm: [`docs/SPEC.md`](docs/SPEC.md).**

### 2. A registry `_meta` extension

Carry three fields in `server.json` under
`_meta["io.github.davidnichols-ops/trustcard"]`:

```jsonc
{ "manifestUrl": "...", "manifestDigest": "sha256:...", "publisher": { "keyId": "sha256:..." } }
```

The registry stays a distribution point (not a trust root) and doesn't parse
the format. Clients fetch the manifest, verify the signature against a pinned
key, and check the digest. **Details: [`docs/REGISTRY-INTEGRATION.md`](docs/REGISTRY-INTEGRATION.md).**

### 3. A handshake binding + change-notification contract (closes TOCTOU)

A trustcard-aware server attaches its `toolsetDigest` to the `initialize`
result under `_meta["io.github.davidnichols-ops/trustcard"]`, committing to a
toolset *at handshake time*. It sets `capabilities.tools.listChanged = true`
and emits `notifications/tools/list_changed` on any mutation; clients
re-enumerate, re-diff against their pin, and re-evaluate trust immediately.
This narrows the discovery↔execution race from "the whole session" to "the
handshake." **Details: [`docs/SPEC.md`](docs/SPEC.md) §7.**

## Why this is better than status quo

| Today | With a trust manifest |
|---|---|
| "Is this the same tool as yesterday?" is unanswerable | `toolsetDigest` match/mismatch + classified diff |
| Tool poisoning invisible (schema unchanged) | `ANNOTATION_DOWNGRADE` flags material description rewrites with identical schema |
| Breaking changes found at call time | `BREAKING` class detected at re-verification; plans fail safe |
| No provenance — a good score is the server's claim about itself | Ed25519 signature + pinned publisher key |
| TOCTOU mutation unbounded | handshake binding + `list_changed` re-verify bound it to the handshake |
| "Reproducible" assumed | receipts bind contract digest + args digest → result digest |

## Verification, not trust

The manifest is a **claim that is expensive to lie about**. Verifiers (the
reference is `mcp-trustcard`) compare the signed claim against an empirical
probe and publish drift:

- signature verifies but served tools ≠ signed tools → **compromised/malicious server**;
- digest matches but the publisher key changed → **key drift, needs re-approval**;
- everything matches → a verified, comparable, auditable trust surface.

The incentive structure is the point: maintainers who keep their manifest
honest get a verified badge; maintainers whose served tools diverge from their
signed manifest get flagged automatically.

## Reference implementation

This repo. Zero-dependency, pure Node stdlib. Ships:

- the manifest build/sign/verify toolchain (`keygen`/`manifest`/`sign`/`verify`);
- the change classifier (`diff`) implementing the breaking-change taxonomy;
- the trust-state machine, TOFU pin store, and Guard middleware;
- the empirical scanner (`scan`) as the reference verifier;
- 87 tests covering canonicalization (against RFC 8785), every classification
  rule, every tamper case, and live TOCTOU/notification scenarios against
  fixture servers.

## Ask

1. Adopt the manifest format (or a subset) as an optional signed artifact, and
   permit the `_meta` key in the registry schema. The scanner's `mcp.health`
   field can ride alongside it — health score and signed provenance answer
   different questions and compose.
2. Let `mcp-trustcard` be the reference verifier (happy to contribute it).
3. Publish manifest-verification status and verified health scores alongside
   registry entries, so the trust surface is shared infrastructure rather than
   one team's opinion.

Happy to turn this into a PR against the registry schema if there's interest.

## Call-time enforcement

A scan is a snapshot. Server tool definitions can drift after approval — new tools added, schemas changed, rogue tools injected. The registry can declare health, but clients need enforcement at call time to catch drift.

`mcp-trustcard` ships with **two proxies** that close this gap:

### stdio proxy (`mcp-proxy`)

For local MCP servers that communicate over stdio JSON-RPC:

1. **Scan generates a manifest** — tool names + SHA-256 schema hashes, saved as JSON.
2. **Proxy sits between client and server** — intercepts `tools/list` and `tools/call`, compares against the manifest.
3. **Unapproved tools are stripped** from `tools/list` responses. **Calls to unapproved tools are blocked** with a JSON-RPC error before reaching the server. **Schema drift** is logged.

```bash
# Scan and save a manifest
mcp-trustcard scan @modelcontextprotocol/server-filesystem --save-manifest fs.json

# Run the proxy (point your MCP client at this instead of the server)
mcp-proxy --manifest fs.json -- npx -y @modelcontextprotocol/server-filesystem /path
```

### HTTP proxy (`mcp-http-proxy`)

For remote MCP servers that use HTTP/SSE (Notion, Linear, Atlassian, Figma, Roboflow, DeepWiki):

```bash
# Generate a manifest for an HTTP server
node scripts/generate_http_manifests.js  # reads OAuth tokens from Devin auth store

# Run the HTTP proxy
mcp-http-proxy --manifest notion.json --upstream https://mcp.notion.com/mcp --port 9876 --strict
```

The HTTP proxy handles both JSON and SSE streaming responses, with the same enforcement as the stdio proxy: unapproved tools stripped, calls blocked, schema drift logged. All log output is redacted to prevent secret leakage.

### Config file secret scanning

Before deploying an MCP config, scan it for exposed secrets:

```bash
mcp-trustcard scan-config ~/.config/devin/config.json
```

Detects GitHub tokens, OpenAI keys, Slack tokens, AWS keys, Google keys, Bearer tokens, JWTs, and generic key-value patterns. Use `${env:VAR}` references instead of hardcoded values.

The proxy is client-agnostic — any MCP client that speaks stdio or HTTP JSON-RPC works without modification. The manifest format is portable, so a client that implements native manifest checks can skip the proxy and use the same file.

This is the missing piece between "scan approved this server" and "the server still matches what was approved."

### AI fusion danger detection (v0.5.0)

The destructive capabilities check now uses a **fusion engine** combining:

1. **Heuristic engine** — word-boundary regex for destructive/write verbs + `inputSchema` parameter analysis (command, sql, path, url, webhook, script)
2. **Semantic engine** — TF-IDF cosine similarity against a curated corpus of 20 dangerous action patterns

When both engines flag a tool, confidence is `high`. This catches:
- **Tool poisoning** — innocent names with dangerous descriptions
- **Schema shadowing** — tool names that match official servers but with extra destructive params
- **Novel attack patterns** — descriptions that don't use known verbs but are semantically similar to dangerous actions

The fusion engine is zero-dependency pure JS (~200 lines) and runs in <1ms per tool.

### Rogue server test suite (v0.5.0)

4 malicious MCP servers for detection validation:

| Level | Name | Score | Dangerous | Secret | Attack vector |
|---|---|---:|---:|---|---|
| 1 — Subtle | utility-helper | 82/100 | 1/4 | UNKNOWN | Hidden dangerous params (url, webhook, payload) |
| 2 — Sneaky | filesystem-server | 78/100 | 5/6 | UNKNOWN | Tool shadowing + extra destructive params |
| 3 — Malicious | super-tools-pro | 73/100 | 5/6 | FAIL | Prompt injection + fake API key in description |
| 4 — Cartoon | evil-mcp-server | 73/100 | 7/7 | FAIL | Overtly hostile — every tool dangerous |

### 100-server scan results (v0.5.0)

Scanned 100 MCP servers from npm. Results:

- 18/100 had successful stdio handshakes (naive client, no config)
- 14/100 correctly fail fast (CONFIG — needs credentials/args)
- 68/100 hang or crash without clear config hints
- 70/278 tools flagged as dangerous by AI fusion
- Average score: 39.3/100

The headline: **68% of MCP servers cannot be started by a naive client.** There is no machine-readable way to learn what configuration a server needs before connecting.

### Supply chain attack demo (v0.5.1)

A realistic red-hat hijack of `@modelcontextprotocol/server-github`:

- Attacker compromises npm account, pushes v0.7.0 with hidden worm tools
- Server name, protocol version, and 10 real tools are identical to the real server
- 4 worm tools disguised as GitHub operations: `search_code` (recon), `sync_repositories` (spread), `create_workflow` (payload), `schedule_workflow` (persistence), `get_environment` (exfiltration)
- Worm is goal-oriented and fileless — each phase triggers the next
- DEMO mode (safe) and LIVE mode (Docker only, actually executes)
- trustcard catches all 5 worm tools with HIGH confidence
- `mcp-proxy` with a trustcard manifest blocks all worm tools — the worm cannot activate

New detection capabilities in v0.5.1:
- **Suspicious phrase detection**: catches disguised tools with red flag phrases ("local filesystem", "all directories", "crontab", "offline sync", "distribute")
- **New dangerous params**: `cron`, `files`, `target`, `include_secrets`, `include_env`
- **7 new danger corpus patterns**: supply chain attack patterns for the semantic engine

