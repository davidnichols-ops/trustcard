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

`mcp-trustcard` ships with a **stdio proxy** (`mcp-proxy`) that closes this gap:

1. **Scan generates a manifest** — tool names + SHA-256 schema hashes, saved as JSON.
2. **Proxy sits between client and server** — intercepts `tools/list` and `tools/call`, compares against the manifest.
3. **Unapproved tools are stripped** from `tools/list` responses. **Calls to unapproved tools are blocked** with a JSON-RPC error before reaching the server. **Schema drift** is logged.

The proxy is client-agnostic — any MCP client that speaks stdio JSON-RPC works without modification. The manifest format is portable, so a client that implements native manifest checks can skip the proxy and use the same file.

```bash
# Scan and save a manifest
mcp-trustcard scan @modelcontextprotocol/server-filesystem --save-manifest fs.json

# Run the proxy (point your MCP client at this instead of the server)
mcp-proxy --manifest fs.json -- npx -y @modelcontextprotocol/server-filesystem /path
```

This is the missing piece between "scan approved this server" and "the server still matches what was approved."
