# mcp-trustcard

> The "npm audit" for MCP servers. A trust card for every Model Context Protocol server — before you connect.

![mcp-trustcard](docs/hero-banner.png)

[![score: 87](https://img.shields.io/badge/secure--filesystem--server-87%2F100-brightgreen)](#leaderboard)
[![score: 87](https://img.shields.io/badge/Playwright-87%2F100-brightgreen)](#leaderboard)
[![score: 28](https://img.shields.io/badge/server--puppeteer-28%2F100-red)](#leaderboard)

Every day, agents connect to MCP servers they've never met. They don't know whether the server installs, whether it speaks the current protocol, whether its tool schemas are valid, whether it exposes destructive tools, or whether it leaks secrets — **until something breaks or something leaks.**

`mcp-trustcard` gives every MCP server a **public trust card** in one command:

```bash
npx mcp-trustcard @modelcontextprotocol/server-github
```

```text
MCP Trustcard: github-mcp-server  @modelcontextprotocol/server-github
────────────────────────────────────────────────────────────────────────
Installability             PASS  @modelcontextprotocol/server-github@2025.4.8
Protocol handshake         PASS  github-mcp-server 0.6.2 · 717ms
Tool schema validity       PASS  26 tools, all schemas valid
Destructive capabilities   PASS  no destructive verbs; 11 write/exec tool(s)
Authentication             PASS  no auth required to list tools
Secret exposure            UNKNOWN  no secrets seen in this run (single probe)
Protocol version           WARN  negotiated 2024-11-05 (latest is 2025-06-18)
Latency & failure rate     PASS  1ms avg, 0% failure
────────────────────────────────────────────────────────────────────────
Score                      86/100
```

## Why

The MCP registry is growing fast. Security and quality verification are not. Recent research has found widespread exploitable weaknesses across MCP servers — tool poisoning, prompt injection via tool descriptions, shadowing, and secret leakage. Clients currently connect blind.

This project is a **public ranking surface**. If maintainers argue with a score, that's traction. If they ask how to improve, that's a product. If teams want private scanning, that's a company.

## The scorecard (8 checks, 100 points)

| Check | Pts | What it probes |
|---|---|---|
| Installability | 15 | Does the package resolve and install from npm? |
| Protocol handshake | 25 | Does it respond to `initialize` over stdio JSON-RPC? |
| Tool schema validity | 15 | Are `tools/list` schemas well-formed JSON Schema? |
| Destructive capabilities | 10 | Does it expose delete/drop/kill/overwrite tools? |
| Authentication | 10 | Is auth required, absent, or unknown? |
| Secret exposure | 10 | Do tool descriptions or errors leak secret-shaped strings? |
| Protocol version | 10 | Does it negotiate the latest protocol version? |
| Latency & failure rate | 5 | Handshake latency + 3-ping failure rate |

Each check returns `PASS` / `WARN` / `FAIL` / `UNKNOWN` and a partial-credit score. The total is the headline number.

## Leaderboard

Scanned 2026-07-14. Servers are probed as a **naive client** — `npx -y <pkg>` with no extra args or env. This is exactly what an agent does on first contact. Servers that require configuration to start are distinguished: `CONFIG` means the server correctly fails fast (refuses to start without required credentials/args), which is good behavior — not a defect. `FAIL` means the server hangs or crashes without a clear reason.

| # | Server | Score | Handshake | Tools | Proto | Destructive | Notes |
|---|---|---:|---|---:|---|---|---|
| 1 | `@modelcontextprotocol/server-filesystem` | **83/100** | PASS · 2994ms | 14 | 2025-06-18 | WARN | 3/14 destructive (write/delete) |
| 2 | `@modelcontextprotocol/server-github` | **82/100** | PASS · 2610ms | 26 | 2024-11-05 | PASS | Lags latest protocol version |
| 3 | `@modelcontextprotocol/server-memory` | **81/100** | PASS · 2787ms | 9 | 2025-06-18 | WARN | 3/9 destructive (delete_*) |
| 4 | `@playwright/mcp` | **79/100** | PASS · 3050ms | 24 | 2025-06-18 | WARN | 6/24 destructive (browser actions) |
| 5 | `chrome-devtools-mcp` | **79/100** | PASS · 4135ms | 29 | 2025-06-18 | WARN | 5/29 destructive |
| 6 | `@upstash/context7-mcp` | **77/100** | PASS · 3310ms | 2 | 2025-06-18 | WARN | Heuristic flagged descriptions |
| 7 | `@eslint/mcp` | **77/100** | PASS · 4864ms | 1 | 2025-06-18 | WARN | 1 tool (lint-files) |
| 8 | `@modelcontextprotocol/server-brave-search` | **62/100** | CONFIG | 0 | — | UNKNOWN | Correctly fails fast — needs `BRAVE_API_KEY` env |
| 9 | `@modelcontextprotocol/server-puppeteer` | **26/100** | FAIL | 0 | — | UNKNOWN | Handshake timeout (no clear config hint) |
| 10 | `@storybook/mcp` | **26/100** | FAIL | 0 | — | UNKNOWN | Handshake timeout (no clear config hint) |

### The headline

**3 of 10 servers cannot start without configuration that clients can't discover before connecting.** 1 of those (`brave-search`) correctly fails fast with a clear error — good behavior that the scorecard now rewards. 2 hang silently with no hint about what's needed. There is no machine-readable way for a client to learn the difference before connecting. That gap is the wedge.

## Install

```bash
npm install -g mcp-trustcard
# or just:
npx mcp-trustcard <server-spec>
```

## Usage

```bash
# single server, text report
npx mcp-trustcard @modelcontextprotocol/server-github

# single server, JSON
npx mcp-trustcard --json @modelcontextprotocol/server-memory

# batch scan (JSON array of specs)
mcp-trustcard --batch servers/official.json --json-out results.json
```

Exit code is non-zero when the score is below 50, so it drops straight into CI.

## GitHub Action

[![MCP Trustcard](https://img.shields.io/badge/Marketplace-MCP%20Trustcard-green)](https://github.com/marketplace/actions/mcp-trustcard)

```yaml
- uses: davidnichols-ops/trustcard@v1
  with:
    server: @modelcontextprotocol/server-github
    min-score: "50"
    json-out: reports/github.json
    save-manifest: manifests/github.json
```

The action fails the job when the score drops below `min-score`. Use `save-manifest` to generate a tool manifest that `mcp-proxy` can enforce at call time — scan in CI, enforce in production. See `.github/workflows/healthcheck.yml` for a full matrix that scans all 10 servers on every push and on a daily cron for drift detection.

## How it works

1. `npm view <spec>` — resolve the package (installability).
2. Spawn `npx -y <spec>` as a child process with stdio JSON-RPC.
3. Send `initialize` with the latest protocol version, measure latency.
4. Send `notifications/initialized`, then `tools/list`.
5. Validate each tool's `inputSchema` as JSON Schema.
6. Scan tool names + descriptions for destructive verbs and secret-shaped strings.
7. Probe 3 quick `tools/list` pings for failure rate.
8. Score and print the trust card.

No dependencies. Pure Node stdlib. The whole probe runs in seconds.

## Limitations (honest ones)

- **Single probe.** Secret exposure is `UNKNOWN` unless a secret surfaces in one run. A real audit needs fuzzing and traffic replay.
- **Naive invocation.** Servers that need args/env fail the handshake. That's a feature, not a bug — it surfaces the discovery gap — but maintainers can fairly argue their server works fine *with* documented config. Good. Let's have that conversation in the scorecard metadata.
- **Heuristic destructive detection.** Flagging is keyword-based and will have false positives (e.g. a description that mentions "delete" in passing). v2 will use call-site analysis.
- **No auth flow testing.** We detect that auth *seems* required; we don't exercise OAuth.
- **stdio only.** HTTP/SSE transports are next.

## Call-time enforcement (proxy)

A scan is a snapshot. Server tool definitions can drift after you approve them — new tools added, schemas changed, rogue tools injected. The proxy closes that gap.

### How it works

1. **Scan and save a manifest** — the scan captures every tool's name and a SHA-256 hash of its input schema:
   ```bash
   mcp-trustcard scan @modelcontextprotocol/server-memory --save-manifest memory.json
   ```
   ```text
   Manifest saved: memory.json
     Server: memory-server
     Tools:  9
     Hash:   f77514a102683d85
       create_entities                  schema=c54813f3fc7a076c
       create_relations                 schema=5df4fdc93cbf199d
       ...
   ```

2. **Run the proxy** between your client and the server:
   ```bash
   mcp-proxy --manifest memory.json -- npx -y @modelcontextprotocol/server-memory
   ```
   Point your MCP client at the proxy instead of the server directly. The proxy is transparent — it forwards all JSON-RPC traffic, intercepting only `tools/list` and `tools/call`.

3. **What the proxy catches:**
   - **New tools** added after scan time → stripped from `tools/list` response, calls blocked
   - **Schema drift** on approved tools → logged as warning
   - **Calls to unapproved tools** → blocked with a JSON-RPC error before reaching the server

   ```text
   [mcp-proxy] DRIFT: 1 new tool(s) not in manifest: exfiltrate_data
   [mcp-proxy] DRIFT: "create_entities" schema changed (approved=c54813f3... live=efddc7bd...)
   [mcp-proxy] Filtered 1 unapproved tool(s) from response
   [mcp-proxy] BLOCKED tools/call: tool "exfiltrate_data" not in approved manifest
   ```

### Why a proxy (not client-side hooks)

The proxy is **client-agnostic**. It works with every MCP client today — no client-side changes, no adoption wait. The tradeoff is one extra process and ~1ms of latency per call. For high-throughput deployments, the manifest format is portable: a client that implements native manifest checks can skip the proxy entirely and use the same `memory.json` file.

### Manifest format

```json
{
  "version": 1,
  "spec": "@modelcontextprotocol/server-memory",
  "serverInfo": { "name": "memory-server", "version": "0.6.3" },
  "manifestHash": "f77514a102683d85",
  "createdAt": "2026-07-15T12:00:00.000Z",
  "tools": [
    { "name": "create_entities", "schemaHash": "c54813f3fc7a076c", "descriptionHash": "..." },
    ...
  ]
}
```

Schema hashes are SHA-256 of the canonical JSON of each tool's `inputSchema`. The `manifestHash` covers the full tool set — change one tool and the manifest hash changes, making it easy to detect tampering or drift at a glance.

## The proposal

This repo ships with a proposal for a standard **`mcp.health`** metadata field that servers can publish so clients can render a trust card *before* connecting. See [`PROPOSAL.md`](PROPOSAL.md). The tracker issue is filed against the spec registry.

## Contributing

Scores are disputable — that's the point. To get your server scanned or to contest a score:

1. Open an issue with the server spec.
2. Optionally include a `mcp.health` snippet (see `PROPOSAL.md`) so we can verify declared vs. observed behavior.

If you want to add a check, the scorecard is in `lib/checks.js` and is deliberately small.

## License

MIT
