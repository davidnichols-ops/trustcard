# Proposal: `mcp.health` — a standard health metadata field for MCP servers

## Problem

Clients cannot evaluate an MCP server before connecting. There is no machine-readable signal for:

- whether a server requires auth or configuration,
- which protocol versions it supports,
- whether it exposes destructive tools,
- its expected latency or reliability.

Today, an agent's only option is to connect and find out. `mcp-trustcard` probes this empirically — but empirical probing is slow, runs in the user's environment, and can't be done at selection time across hundreds of servers.

## Proposal

Add an optional `mcp.health` field to server manifests / registry entries. It is a **declared** trust card that clients can read statically and that tools like `mcp-trustcard` can **verify** empirically. Declared-vs-observed divergence is itself a signal.

### Schema

```jsonc
{
  "mcp.health": {
    "schemaVersion": "0.1",
    "protocolVersions": ["2025-06-18", "2024-11-05"],
    "requiresAuth": {
      "type": "env",            // "env" | "oauth" | "apiKey" | "none"
      "vars": ["GITHUB_PERSONAL_ACCESS_TOKEN"],
      "optional": false
    },
    "requiresArgs": ["path..."],          // CLI args the server needs to start
    "transport": ["stdio", "http", "sse"],
    "capabilities": {
      "tools": true,
      "resources": false,
      "prompts": false
    },
    "destructiveTools": "declared",       // "none" | "declared" | "unknown"
    "secretsInToolOutput": false,         // does any tool echo secrets?
    "latency": { "p50Ms": 800, "p95Ms": 2500 },
    "failureRate": 0.01,
    "lastVerified": "2026-07-14T12:00:00Z",
    "verifiedBy": "mcp-trustcard@0.1.0",
    "score": 86
  }
}
```

### Why this is better than status quo

| Today | With `mcp.health` |
|---|---|
| Client connects blind | Client reads the card at selection time |
| "Why didn't it start?" is a debugging session | `requiresAuth` / `requiresArgs` answer it instantly |
| Destructive tools discovered after first call | `destructiveTools` declared upfront |
| No way to compare servers | `score` + `lastVerified` give a comparable surface |
| Security review is manual | `secretsInToolOutput` + `verifiedBy` make it auditable |

### Verification, not trust

`mcp.health` is a **claim**, not a guarantee. `mcp-trustcard` (and any verifier) compares the claim against an empirical probe and reports drift:

```
Declared protocolVersions:  ["2025-06-18", "2024-11-05"]
Observed protocolVersion:   "2024-11-05"        ✓ within declared set

Declared requiresAuth:      env GITHUB_PERSONAL_ACCESS_TOKEN
Observed:                   handshake OK without token   ⚠ drift
```

Drift is published. Maintainers who keep their card honest get a verified badge; maintainers whose card diverges from reality get flagged. The incentive structure is what makes this work.

### Minimal viable field

If adopting the full schema is too heavy, the single highest-value field is:

```json
{ "mcp.health": { "requiresAuth": { "type": "env", "vars": ["X"] } } }
```

This alone would have let 4 of the 10 servers in our scan tell clients *why* they fail to handshake, instead of timing out silently.

## Ask

1. Adopt `mcp.health` (or a subset) as an optional field in the registry schema.
2. Let `mcp-trustcard` be the reference verifier.
3. Publish verified scores alongside registry entries so the ranking surface is shared infrastructure, not one team's opinion.

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
