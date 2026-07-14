# Social posts — ready to paste

Repo: https://github.com/davidnichols-ops/trustcard
Angle: "I scanned 10 MCP servers. Here's what clients currently cannot tell you before connecting."

---

## Hacker News

**Title:** I scanned 10 MCP servers — here's what agents can't know before connecting

**Text:**

Every agent that connects to an MCP server does it blind. It doesn't know whether the server installs, whether it speaks the current protocol, whether its tool schemas are valid, whether it exposes destructive tools, or whether it leaks secrets — until something breaks or something leaks.

I built mcp-trustcard, a CLI + GitHub Action that gives every MCP server a public trust card in one command:

    npx mcp-trustcard @modelcontextprotocol/server-github

It probes 8 things: installability, protocol handshake, tool schema validity, destructive capabilities, auth posture, secret exposure, protocol version, and latency/failure rate. Then it scores the server out of 100.

I scanned 10 recognizable servers as a naive client (npx -y <pkg>, no args, no env — exactly how an agent first contacts them). 4 of 10 could not complete a protocol handshake. There is no machine-readable way for a client to learn why before connecting. That's the gap.

Results: https://github.com/davidnichols-ops/trustcard#leaderboard

The point isn't that the scanner is perfect (it isn't — it's heuristic, single-probe, stdio-only). The point is that there is currently no public ranking surface for MCP server quality, and the registry doesn't expose the signals a client needs at selection time. I also filed a proposal for a standard `mcp.health` metadata field so servers can declare what they need and verifiers can check it.

If maintainers argue with their score, good — that's the conversation we need. If you want your server scanned, open an issue.

---

## Reddit (r/LocalLLaMA or r/MCP)

**Title:** I scanned 10 MCP servers and scored them. 4/10 can't even handshake without config clients can't see.

**Body:**

Built a tool called mcp-trustcard — basically "npm audit" but for MCP servers. It runs 8 checks (install, protocol handshake, tool schema validity, destructive tools, auth, secret exposure, protocol version, latency) and outputs a score out of 100.

Headline finding: scanned 10 well-known servers the way an agent actually invokes them (npx -y, no args/env). 4 of 10 timed out on the protocol handshake because they need env vars or args that the client has no way to discover upfront. One (server-github) is still on the older protocol version.

Leaderboard + method: https://github.com/davidnichols-ops/trustcard#leaderboard

It's heuristic and single-probe by design — v1 is about creating a public ranking surface, not being comprehensive. Also proposed a standard `mcp.health` metadata field for the registry so clients can read a trust card before connecting instead of debugging after.

Scores are disputable — that's the point. If a maintainer thinks their score is wrong, that's a thread I want to have in public. Open an issue to get your server added.

---

## X / Twitter

Thread:

1/ I scanned 10 MCP servers to see what agents can't know before connecting.

Built mcp-trustcard — "npm audit" for MCP. 8 checks, scores out of 100.

    npx mcp-trustcard @modelcontextprotocol/server-github

Result: 4/10 servers can't complete a protocol handshake when invoked the way an agent invokes them. 🧵

2/ The failures aren't bugs — they're servers that need env vars or args (BRAVE_API_KEY, project context, launch config). But there's no machine-readable way for a client to discover that *before* connecting. It just times out.

That's the gap. https://github.com/davidnichols-ops/trustcard

3/ Leaderboard:

87 — @playwright/mcp
87 — chrome-devtools-mcp
87 — server-filesystem
86 — server-github (lags latest protocol)
85 — server-memory
85 — @upstash/context7-mcp
85 — @eslint/mcp
33 — server-brave-search (needs API key)
28 — server-puppeteer (needs config)
28 — @storybook/mcp (needs project context)

4/ Also filed a proposal for a standard `mcp.health` metadata field so servers declare what they need (auth, args, protocol versions, destructive tools) and verifiers check it. Declared-vs-observed drift is itself a signal.

If maintainers argue with their score — good. That's the conversation we need.

---

## MCP Discord / community

**Channel:** #showcase or #security

I built **mcp-trustcard** — a CLI + GitHub Action that gives every MCP server a public trust card before an agent connects. One command:

```
npx mcp-trustcard @modelcontextprotocol/server-github
```

It probes installability, protocol handshake, tool schema validity, destructive capabilities, auth posture, secret exposure, protocol version, and latency — then scores the server /100.

I scanned 10 recognizable servers as a naive client. **4 of 10 couldn't complete a handshake** because they need env/args the client can't discover upfront. Full leaderboard: https://github.com/davidnichols-ops/trustcard#leaderboard

It's v1 — heuristic, single-probe, stdio-only — intentionally. The goal is a public ranking surface so we can have the "what should clients know before connecting" conversation in public instead of per-server.

Also proposed a standard `mcp.health` metadata field for the registry: https://github.com/davidnichols-ops/trustcard/blob/main/PROPOSAL.md

If you want your server scanned or you dispute a score, open an issue. Especially interested in maintainer feedback on the scorecard weights.
