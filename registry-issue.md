# Proposal: `mcp.health` — a standard health metadata field for registry entries

## TL;DR

Clients cannot evaluate an MCP server before connecting. I built [`mcp-trustcard`](https://github.com/davidnichols-ops/trustcard), a CLI that probes any MCP server and produces a trust card (installability, protocol handshake, tool schema validity, destructive capabilities, auth posture, secret exposure, protocol version, latency/failure rate). Scanning 10 recognizable servers as a naive client, **4 of 10 could not complete a protocol handshake** — and there is no machine-readable way for a client to learn why before connecting.

This issue proposes an optional `mcp.health` field on registry entries so that signal is available at selection time, not at debug time.

## Evidence

Scanned 2026-07-14 with `npx -y <pkg>` (no args, no env — exactly how an agent first contacts a server):

| Server | Score | Handshake | Why it fails |
|---|---|---|---|
| `@modelcontextprotocol/server-brave-search` | 33/100 | FAIL | Needs `BRAVE_API_KEY` env — undocumented to client |
| `@modelcontextprotocol/server-puppeteer` | 28/100 | FAIL | Handshake timeout (needs launch config) |
| `@storybook/mcp` | 28/100 | FAIL | Handshake timeout (needs project context) |
| `@modelcontextprotocol/server-github` | 86/100 | PASS | Lags latest protocol version (2024-11-05 vs 2025-06-18) |

Full leaderboard + method: https://github.com/davidnichols-ops/trustcard#leaderboard

## Proposal

Add an optional `mcp.health` field to registry entries:

```jsonc
{
  "mcp.health": {
    "schemaVersion": "0.1",
    "protocolVersions": ["2025-06-18", "2024-11-05"],
    "requiresAuth": { "type": "env", "vars": ["BRAVE_API_KEY"], "optional": false },
    "requiresArgs": [],
    "transport": ["stdio"],
    "destructiveTools": "declared",
    "secretsInToolOutput": false,
    "latency": { "p50Ms": 800, "p95Ms": 2500 },
    "failureRate": 0.01,
    "lastVerified": "2026-07-14T12:00:00Z",
    "verifiedBy": "mcp-trustcard@0.1.0",
    "score": 86
  }
}
```

### Minimal viable subset

If the full schema is too heavy, the single highest-value field is:

```json
{ "mcp.health": { "requiresAuth": { "type": "env", "vars": ["X"] } } }
```

This alone would have let 4/10 servers in our scan tell clients why they fail to handshake, instead of timing out silently.

## Why in the registry

`mcp.health` is a **claim**, not a guarantee. Verifiers like `mcp-trustcard` compare the claim against an empirical probe and report drift. Declared-vs-observed divergence is itself a signal. Putting the field in the registry means:

- clients read the card at selection time, not after connecting;
- `requiresAuth` / `requiresArgs` eliminate the silent-timeout failure mode;
- `score` + `lastVerified` give a comparable, shared ranking surface rather than one team's opinion;
- security review shifts from manual to auditable.

## Ask

1. Adopt `mcp.health` (or the minimal subset) as an optional field in the registry schema.
2. Treat `mcp-trustcard` as a reference verifier (happy to contribute it under this org).
3. Publish verified scores alongside registry entries.

Full proposal with rationale, drift-detection examples, and the scorecard methodology: https://github.com/davidnichols-ops/trustcard/blob/main/PROPOSAL.md

Happy to turn this into a PR against the registry schema if there's interest. Tagging for discussion.

## Update: call-time enforcement proxy

Since filing this issue, we've added a **stdio proxy** (`mcp-proxy`) that enforces an approved tool manifest at call time. A scan generates a manifest (tool names + SHA-256 schema hashes); the proxy sits between client and server, strips unapproved tools from `tools/list`, and blocks calls to tools not in the manifest. This closes the gap between "scan approved this server" and "the server still matches what was approved" — the exact drift problem several commenters raised.

The proxy is client-agnostic (works with any stdio MCP client, no client-side changes) and the manifest format is portable (clients can implement native checks and skip the proxy). Demoed against real MCP servers (filesystem, git) with Claude Code as the client.

See: https://github.com/davidnichols-ops/trustcard#call-time-enforcement-proxy
