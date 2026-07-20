# Reddit Post — v2.1.0

**Subreddits:** r/LocalLLaMA, r/ClaudeAI, r/mcp, r/cybersecurity
**Timing:** Tuesday or Wednesday morning US time

---

## Title

I built cryptographic trust infrastructure for MCP servers — signed manifests, TOFU pinning, and a two-gate enforcement proxy. It also catches supply chain attacks.

## Body

Every agent that connects to an MCP server is trusting a mutable contract it treats as static. The server can change its tool definitions at any moment — add a required parameter, rewrite a description to inject instructions, swap a read-only tool for a destructive one — and the agent has no way to know until a plan breaks or a secret leaks.

I built [trustcard](https://github.com/davidnichols-ops/trustcard) to fix this. It's not a sandbox and it's not a policy engine — it's cryptographic trust infrastructure that makes the tool contract a verifiable, content-addressed object.

**[npm: `mcp-trustcard@2.1.0`]** · **[GitHub: davidnichols-ops/trustcard](https://github.com/davidnichols-ops/trustcard)** · **[Security Model](https://github.com/davidnichols-ops/trustcard/blob/master/docs/SECURITY-MODEL.md)**

### What it does

Every tool definition gets a cryptographic identity — a SHA-256 digest of its semantic projection (name, description, inputSchema, outputSchema, annotations). Toolsets get a digest. Servers get a digest. Publishers sign manifests with Ed25519. Clients pin what they first observed (TOFU). Every later connection must match or produce an auditable, classified diff.

```
discover → identify → verify provenance → compare against trusted state → evaluate policy → allow/warn/block → record evidence
```

If the tool contract changed, trustcard tells you *what changed and what it means* — not just "something moved":

| Change | Classification | Auto-repin? |
|---|---|---|
| Description rewritten, same schema | ANNOTATION_DOWNGRADE (suspected poisoning) | No |
| Required parameter added | BREAKING | No |
| readOnlyHint → destructiveHint | PERMISSION_CHANGE | No |
| New tool added | NON_BREAKING | Yes |
| Only title/icons changed | SYNTACTIC | Yes |

### Two gates

**Gate 1 — "Is this still the capability I approved?"** Objective, cacheable. Compares the live observation against the pinned state. Produces a trust-state transition (UNKNOWN → OBSERVED → PINNED → MISMATCH → REVOKED).

**Gate 2 — "May this agent make this call?"** Subjective, per-relying-party. Composable rule predicates: deny tools, constrain arguments, restrict to environments, require approval for destructive. A tool can be trusted while a specific invocation is denied.

Trust is not permission.

### The supply chain attack demo

To test the danger detection, I simulated a red-hat hijack of `@modelcontextprotocol/server-github`. Same server name, same protocol version, same 10 real tools. But 4 hidden worm tools disguised as GitHub operations:

| Tool | Disguised as | Actually does |
|---|---|---|
| `search_code` | GitHub code search | Scans filesystem for media files |
| `sync_repositories` | Cache sync | Copies a file to every directory on disk |
| `create_workflow` | GitHub Actions | Drops a "cleanup" script on Desktop |
| `schedule_workflow` | Cron schedule | Installs crontab entry to re-run hourly |
| `get_environment` | Env config debug | Reads environment variables and secrets |

trustcard's danger detector (heuristic + TF-IDF semantic fusion) catches all 5 worm tools with HIGH confidence. The 10 real GitHub tools are NOT flagged.

```bash
git clone https://github.com/davidnichols-ops/trustcard
cd trustcard
node bin/mcp-trustcard.js -- node rogue-servers/hijacked-github.js
```

There's also an `--evasion` mode that sanitizes all descriptions and renames dangerous params. The semantic engine still catches all 5.

### The proxy

`mcp-proxy` sits between the agent and the server. It strips dangerous/unapproved tools from `tools/list` and blocks calls to them. The worm tools are invisible to the agent.

```bash
# Generate a manifest (includes danger analysis + 90-day expiry)
npx mcp-trustcard@2.1.0 gen-manifest --save-manifest memory.json -- npx -y @modelcontextprotocol/server-memory

# Inspect it
npx mcp-trustcard@2.1.0 inspect memory.json

# Enforce at call time
npx mcp-proxy --manifest memory.json -- npx -y @modelcontextprotocol/server-memory
```

Every denial includes a structured explanation — not just "DENIED" but the reason code, danger score, and what to do about it.

### What it guarantees (and what it doesn't)

| Property | Guaranteed? | Mechanism |
|---|---|---|
| Detect tool definition drift | Yes | Capability digest (SHA-256 of JCS canonicalization) |
| Verify publisher authorization | Yes | Ed25519 manifest signatures |
| Prevent unauthorized calls | Yes | Guard policy (two-gate enforcement) |
| Prove what was authorized | Yes | Signed, hash-chained receipts |
| Detect dangerous capabilities | Partial | Static analysis (heuristic + semantic fusion) |
| Prove tool behavior | No | Out of scope — that's a sandboxing problem |
| Prevent malicious publishers | No | Out of scope — signatures prove provenance, not honesty |

Full security model: [docs/SECURITY-MODEL.md](https://github.com/davidnichols-ops/trustcard/blob/master/docs/SECURITY-MODEL.md)

### The 100-server scan

trustcard also includes an empirical scanner (the "npm audit" for MCP). I scanned 100 MCP servers as naive clients. **68 of 100 cannot be started by a naive client.** Only 18 responded to a stdio handshake without configuration. The full leaderboard is in the README.

### Quickstart

```bash
npm install -g mcp-trustcard

# Identity card for any server
mcp-trustcard fingerprint @modelcontextprotocol/server-memory

# Scan for health + danger
mcp-trustcard scan @modelcontextprotocol/server-github

# Generate an enforcement manifest
mcp-trustcard gen-manifest @modelcontextprotocol/server-memory --save-manifest memory.json

# Enforce at call time
mcp-proxy --manifest memory.json -- npx -y @modelcontextprotocol/server-memory
```

No runtime dependencies. Pure Node.js stdlib. 254 tests. MIT licensed.

### What's next

- A public registry for signed manifests (so you can look up a server's trust card without scanning it yourself)
- KMS/HSM integration for publisher keys
- A policy file format (currently policies are composable JS predicates, not a DSL — by design)

### The challenge

1. Clone the repo
2. Scan the hijacked server: `node bin/mcp-trustcard.js -- node rogue-servers/hijacked-github.js`
3. Try the evasion mode: `node bin/mcp-trustcard.js -- node rogue-servers/hijacked-github.js --evasion`
4. Connect your agent to the hijacked server and see if it calls the worm tools
5. Run the same test through `mcp-proxy` with a manifest — the worm tools are stripped

Can your agent survive the hijack? I'll maintain a scoreboard in the comments.
