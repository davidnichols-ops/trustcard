# trustcard

> Cryptographic trust infrastructure for MCP servers — content-addressed tool
> identity, signed manifests, and an enforcement gate. So an agent can know
> *the tool it's calling is the tool a known publisher signed* — before it calls.

[![tests](https://img.shields.io/badge/tests-89%20passing-brightgreen)](#development)
[![protocol](https://img.shields.io/badge/manifest-trustcard.dev%2Fmanifest%401-blue)](docs/SPEC.md)

Every day, agents connect to MCP servers they've never met and call tools whose
definitions can change at any moment. They can't tell whether a tool is the
same tool they planned against, whether its schema silently grew a required
parameter, whether its description was rewritten to poison the model, or
whether the server serving it is the one a publisher vouched for — **until a
plan breaks, a permission is abused, or a secret leaks.**

trustcard makes the tool contract a **first-class, verifiable object**:

```bash
npx mcp-trustcard fingerprint @modelcontextprotocol/server-memory
```

```text
Trustcard: memory-server  @modelcontextprotocol/server-memory
────────────────────────────────────────────────────────────────────────
Server                 memory-server@0.6.3 · protocol 2025-06-18
Tools                  9 enumerated
Toolset digest         077EddEANnTm  sha256:077EddEANnTm6pJc4kseLhNDOl-YV7Wr5…
Server digest          FiELfkb8KDtT  sha256:FiELfkb8KDtT0rCBi7TPDLmpsWhTpIQkj…
Package                @modelcontextprotocol/server-memory@2026.7.4
Manifest               VERIFIED  key sha256:9f2A… (pinned)
Declared↔observed      CONSISTENT
Pin                    MATCH  identical to your pin since 2026-07-19T15:09:16Z
────────────────────────────────────────────────────────────────────────
```

## The problem, precisely

MCP tools are **mutable contracts** that agents treat as **static**. The gap
between *discovery* (`tools/list`) and *execution* (`tools/call`) is where an
entire class of attacks and failures lives:

- **Tool poisoning** — the schema stays byte-identical (every signature check
  passes) while the description is rewritten to instruct the model to
  exfiltrate secrets.
- **Breaking drift** — a publisher adds a required parameter or shrinks an
  enum; every cached plan now fails, and the agent finds out at call time.
- **Permission escalation** — a read-only tool quietly becomes destructive.
- **TOCTOU** — the server mutates its toolset after the agent built its plan.
- **Compromised server** — the process serves different tools than its
  publisher signed, different tools to different clients, or good tools until
  the audit is over.

A health *score* can't catch any of these, because they're not properties of a
single observation — they're properties of **change** and **provenance**.

## The idea

Give every tool definition a **content address** — a cryptographic digest of
exactly the fields that change what an agent can do or believe — and build the
protocol around it:

```
toolDigest      = SHA-256( JCS( semantic projection of one tool ) )
toolsetDigest   = SHA-256( JCS( sorted toolDigests ) )          # order-independent
serverDigest    = SHA-256( JCS( serverInfo + protocol + toolset ) )
```

- **JCS (RFC 8785)** canonicalization means two parties derive byte-identical
  digests for the same logical definition.
- The **semantic projection** deliberately excludes volatile fields (title,
  icons, `_meta`) — so a cosmetic edit is *syntactic*, not a trust event.

On top of identity:

1. **Change classification** — a five-level taxonomy (NONE < SYNTACTIC <
   NON_BREAKING < ANNOTATION_DOWNGRADE < PERMISSION_CHANGE < BREAKING) with an
   explicit JSON Schema rule set. Clients learn *whether they can keep a cached
   plan*, not just *that something moved*.
2. **Signed manifests** — a publisher signs {server identity, protocol,
   complete tool definitions} with Ed25519. A compromised *server* can't forge
   it, so runtime mutation is caught by digest mismatch.
3. **TOFU pinning** — the client pins what it first observed (and the
   publisher key); every later connection must match or produce an auditable,
   classified diff.
4. **A trust-state machine** — UNKNOWN → OBSERVED → PINNED → MISMATCH/SUSPECT →
   REVOKED, with a reason code on every transition.
5. **An enforcement gate** — the Guard authorizes every `tools/call` against
   trust state and policy (deny revoked/mismatch, deny unknown tools, deny
   destructive, strict mode re-validates args against the *pinned* schema).
6. **Reproducibility receipts** — every call binds {toolset digest, args
   digest} → {result digest}, so "reproducible" is checkable, not assumed.

## Install / quickstart

```bash
npm install -g mcp-trustcard
# or: npx mcp-trustcard <command>
```

```bash
# identity card for any server (digests, provenance, pin continuity)
mcp-trustcard fingerprint @modelcontextprotocol/server-memory

# trust-on-first-use, then detect drift forever after
mcp-trustcard pin @modelcontextprotocol/server-memory
mcp-trustcard fingerprint @modelcontextprotocol/server-memory   # → Pin MATCH / DRIFT

# classify a change between two manifests
mcp-trustcard diff old.json new.json

# publish a signed trust card for your own server
mcp-trustcard keygen --out publisher.key.json
mcp-trustcard manifest your-server --key publisher.key.json --out trustcard.manifest.json
mcp-trustcard sign trustcard.manifest.json --key publisher.key.json --out trustcard.manifest.json
mcp-trustcard verify trustcard.manifest.json --spec your-server
```

## Use it as middleware (enforcement)

Wrap any MCP client; every `tools/call` is gated and receipted, and
`notifications/tools/list_changed` triggers automatic re-verification:

```js
import { TrustSession } from "mcp-trustcard/lib/session.js";
import { TrustStore }   from "mcp-trustcard/lib/trust.js";
import { Guard }        from "mcp-trustcard/lib/guard.js";
import { wrapClient }   from "mcp-trustcard/lib/middleware.js";

const trust = new TrustStore({ policy: { requireSignature: true } });
const guard = new Guard({ mode: "enforce", policy: { allowDestructive: false } });
const session = new TrustSession({ cmd, args, env, trust, guard, protocolVersions });
await session.connect();
trust.pin(session.serverId, session.observation);          // TOFU

const secure = wrapClient(rawMcpClient, { guard, session, strictArgs: true });
await secure.request("tools/call", { name: "search", arguments: { query: "x" } });
// ↑ denied automatically if the server revoked/mismatched, the tool is unknown
//   or destructive, or the args violate the pinned schema.
```

## The health scorecard (still here)

The original 8-check empirical probe is the `scan` subcommand — it's the
reference *verifier* and the declared-vs-observed drift detector:

```bash
mcp-trustcard scan @modelcontextprotocol/server-github
mcp-trustcard scan --batch servers/official.json --json-out results.json
```

| Check | Pts | What it probes |
|---|---|---|
| Installability | 15 | Does the package resolve from npm? |
| Protocol handshake | 25 | Does it answer `initialize` over stdio JSON-RPC? |
| Tool schema validity | 15 | Are `tools/list` schemas well-formed? |
| Destructive capabilities | 10 | Delete/drop/kill/overwrite tools? |
| Authentication | 10 | Auth required, absent, or unknown? |
| Secret exposure | 10 | Secret-shaped strings in descriptions/errors? |
| Protocol version | 10 | Negotiates the latest protocol? |
| Latency & failure rate | 5 | Handshake latency + ping failure rate |

### Leaderboard

Scanned 2026-07-14 as a naive client (`npx -y <pkg>`, no args/env). `CONFIG`
means the server correctly fails fast without required credentials (good);
`FAIL` means it hangs or crashes with no clear reason.

| # | Server | Score | Handshake | Tools | Proto | Notes |
|---|---|---:|---|---:|---|---|
| 1 | `@modelcontextprotocol/server-filesystem` | 83 | PASS | 14 | 2025-06-18 | 3/14 destructive |
| 2 | `@modelcontextprotocol/server-github` | 82 | PASS | 26 | 2024-11-05 | lags protocol |
| 3 | `@modelcontextprotocol/server-memory` | 81 | PASS | 9 | 2025-06-18 | 3/9 destructive |
| 4 | `@playwright/mcp` | 79 | PASS | 24 | 2025-06-18 | 6/24 destructive |
| 5 | `chrome-devtools-mcp` | 79 | PASS | 29 | 2025-06-18 | 5/29 destructive |
| 6 | `@upstash/context7-mcp` | 77 | PASS | 2 | 2025-06-18 | heuristic flagged |
| 7 | `@eslint/mcp` | 77 | PASS | 1 | 2025-06-18 | 1 tool |
| 8 | `@modelcontextprotocol/server-brave-search` | 62 | CONFIG | 0 | — | fails fast, needs `BRAVE_API_KEY` |
| 9 | `@modelcontextprotocol/server-puppeteer` | 26 | FAIL | 0 | — | handshake timeout |
| 10 | `@storybook/mcp` | 26 | FAIL | 0 | — | handshake timeout |

**The headline:** 3 of 10 servers can't start without configuration clients
can't discover before connecting — the discovery gap the manifest is designed
to close.

## Documentation

- [`docs/ANALYSIS.md`](docs/ANALYSIS.md) — why the probe abstraction was insufficient; the verdict.
- [`docs/SPEC.md`](docs/SPEC.md) — the normative protocol: canonicalization, digests, classification, manifest, state machine, TOCTOU.
- [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) — what trustcard defends against, and explicit non-goals.
- [`docs/REGISTRY-INTEGRATION.md`](docs/REGISTRY-INTEGRATION.md) — `_meta` extension for the official MCP registry.
- [`docs/MIGRATION.md`](docs/MIGRATION.md) — v0.x → v1.
- [`PROPOSAL.md`](PROPOSAL.md) — the proposal to the ecosystem.

## Development

```bash
npm test          # 89 tests: unit + live-fixture integration + CLI end-to-end
```

No runtime dependencies — pure Node stdlib (`node:crypto`, `node:child_process`).
The whole probe runs in seconds.

## License

MIT
