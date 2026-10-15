# Bruce Lee — Reference MCP Server

A deterministic, hash-chained agent decision audit log exposed as an MCP server.
This is the **first reference well-behaved MCP server** in the trustcard repo —
it demonstrates the patterns that trustcard is designed to protect, while
providing a genuinely useful primitive for agent workflows.

## What It Does

Bruce Lee provides three tools for making agent reasoning **auditable,
reproducible, and tamper-evident**:

| Tool | Purpose | Read-only? |
|------|---------|------------|
| `record_decision` | Append a structured decision to a hash-chained audit log | No (local write) |
| `query_decisions` | Query the audit log by agent, kind, or time range | Yes |
| `server_identity` | Return capability descriptor, toolset digest, and log stats | Yes |

Every recorded decision is linked to the previous one via a SHA-256 digest
chain (`digest_n = hash(prev_{n-1}, ts, agent, action, rationale, kind, tags)`).
Modifying any entry breaks all subsequent digests — tamper-evident without a
central authority.

## Quick Start

```bash
# Run the server (stdio transport)
node examples/bruce-lee/server.js

# With a custom log path and debug logging
BRUCE_LEE_LOG_PATH=/tmp/audit.jsonl \
BRUCE_LEE_LOG_LEVEL=debug \
node examples/bruce-lee/server.js
```

### Scan it with trustcard

```bash
BRUCE_LEE_LOG_PATH=/tmp/audit.jsonl \
node bin/mcp-trustcard.js scan -- node examples/bruce-lee/server.js
```

Expected score: **87/100** (PASS on handshake, schema validity, destructive
capabilities, authentication, protocol version, latency).

### Generate a manifest

```bash
BRUCE_LEE_LOG_PATH=/tmp/audit.jsonl \
node bin/mcp-trustcard.js gen-manifest \
  --save-manifest bruce-lee.json \
  -- node examples/bruce-lee/server.js
```

### Deploy behind the proxy

```bash
BRUCE_LEE_LOG_PATH=/tmp/audit.jsonl \
node bin/mcp-proxy.js --manifest bruce-lee.json -- node examples/bruce-lee/server.js
```

## Architecture

```
  Agent (Claude, Devin, etc.)
    │
    │ JSON-RPC over stdio
    │
    ▼
  bruce-lee server.js
    │
    ├── initialize → protocolVersion + serverInfo + toolsetDigest binding
    ├── tools/list → 3 tools with honest annotations
    ├── tools/call
    │     ├── record_decision → validate → compute digest → append to JSONL
    │     ├── query_decisions  → validate → read + verify chain → filter
    │     └── server_identity  → return descriptor + log stats
    │
    └── audit log (append-only JSONL, hash-chained)
```

### Design Decisions

1. **Reuses trustcard's own crypto.** The hash chain uses `hashJson` from
   `lib/hash.js` (SHA-256 over RFC 8785 JCS canonical bytes). This keeps
   Bruce Lee's digests byte-compatible with trustcard's identity model —
   a tool's `toolDigest` and a decision's `digest` use the same algorithm.

2. **trustcard-aware handshake.** The server precomputes its `toolsetDigest`
   at startup and includes it in the `initialize` response `_meta` under
   `io.github.davidnichols-ops/trustcard`. This closes the TOCTOU window
   between discovery and execution — a trustcard client can verify the
   toolset hasn't drifted before making any calls.

3. **Honest annotations.** `record_decision` is `readOnlyHint: false` (it
   writes to a local log) but `destructiveHint: false` (it doesn't destroy
   anything). `query_decisions` and `server_identity` are `readOnlyHint: true`
   and `idempotentHint: true`. None are `openWorldHint: true`.

4. **Safe param names.** All parameter names (`agent`, `action`, `rationale`,
   `kind`, `tags`, `since`, `until`, `limit`) were chosen to avoid the
   trustcard danger detector's `DANGEROUS_PARAMS` list (`command`, `sql`,
   `path`, `url`, `data`, `code`, `payload`, etc.).

5. **Structured JSON-RPC error codes.** Every error path returns the correct
   code: -32700 (parse error), -32600 (invalid request), -32601 (method not
   found), -32602 (invalid params), -32603 (internal error). No generic
   "something went wrong" messages.

6. **Fail-closed on log corruption.** If the audit log's hash chain is broken
   (digest mismatch, broken prev pointer, malformed JSON), the server returns
   -32603 with a clear "audit log integrity failure" message. It never
   silently starts a new chain or returns partial data.

7. **Data minimization in queries.** `query_decisions` does not return the
   `rationale` field (which can be long and may contain sensitive reasoning).
   The caller gets the digest, which proves the rationale was recorded, without
   exposing it in bulk queries.

8. **Zero runtime dependencies.** Uses only Node.js stdlib + trustcard's own
   `lib/hash.js`, `lib/canon.js`, and `lib/identity.js`. Consistent with the
   repo's no-deps invariant.

### Observability

All logs go to **stderr** as structured JSON (stdout is the JSON-RPC transport):

```json
{"ts":"2026-07-31T15:46:05.626Z","level":"info","event":"server_starting","version":"1.0.0","logPath":"/tmp/audit.jsonl","toolsetDigest":"sha256:..."}
{"ts":"2026-07-31T15:46:05.940Z","level":"info","event":"decision_recorded","id":"dec_...","agent":"devin","action":"commit","kind":"decision","digest":"sha256:..."}
{"ts":"2026-07-31T15:46:05.940Z","level":"info","event":"decisions_queried","total":2,"matched":1,"agent":"devin"}
```

Log levels: `debug` (includes tool_call events), `info` (default), `warn`, `error`.

### Security Review

- **Input validation:** Every tool parameter is validated with explicit type,
  length, and enum checks. Validation is the single chokepoint before any
  state mutation.
- **Injection risks:** No string interpolation into file paths, commands, or
  SQL. The log path is set via environment variable, not user input. Tool
  descriptions contain no prompt-injection markers.
- **Privilege boundaries:** No authentication required (local stdio server).
  In production, deploy behind `mcp-proxy` with a manifest and Gate 2 policies.
- **Data handling:** Rationale is stored in the log but not returned in query
  results (data minimization). No secrets are handled. Logs are redaction-ready
  (structured JSON, no raw secret fields).
- **Trust assumptions:** The log file is trusted (local filesystem). If an
  attacker can modify the log file, they can break the chain — but the chain
  makes this **detectable**, not preventable. This is the same trust model as
  trustcard's receipts.

### Known Limitations

1. **No concurrent writers.** The append-only log uses `appendFileSync`, which
   is atomic for single appends but does not coordinate across multiple server
   instances writing to the same file. For multi-instance deployment, use a
   single log file per instance or add file locking.
2. **Timestamp-based ordering.** Decisions are ordered by insertion (file
   order), not by timestamp. Two decisions recorded in the same millisecond
   will have different digests (due to the random ID) but may have identical
   timestamps.
3. **No rationale in query results.** By design (data minimization), but means
   the caller cannot inspect reasoning without the digest + out-of-band
   verification. A future `get_decision` tool could return the full record by ID.
4. **No log rotation.** The JSONL file grows unbounded. For production, add
   log rotation or a retention policy.
5. **No signed receipts.** The hash chain is tamper-evident but not signed.
   Adding Ed25519 signing (like trustcard's receipt chain) would provide
   non-repudiation.

## Testing

```bash
# Bruce Lee tests only (42 tests)
node --test test/bruce-lee.test.js

# Full repo test suite (includes Bruce Lee)
node --test "test/*.test.js"
```

Test coverage:
- **Integration (11):** full MCP protocol, all 3 tools, persistence, defaults
- **Failure (13):** 3 intentional failure categories (validation, runtime, integration)
- **Edge cases (12):** empty queries, limit clamping, maxItems, empty strings, timestamps
- **Security (4):** no dangerous params, honest annotations, data minimization, no injection markers
- **Determinism (2):** digest computation, query ordering

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `BRUCE_LEE_LOG_PATH` | `$TMPDIR/bruce-lee/bruce-lee-decisions.jsonl` | Path to the append-only audit log. The default lives under the OS temp dir so demos don't drop untracked files into the repo; `*.jsonl` here is gitignored either way. |
| `BRUCE_LEE_LOG_LEVEL` | `info` | Log level: `debug`, `info`, `warn`, `error` |

## Versioning

- Server version: `1.0.0` (in `serverInfo.version`)
- Protocol version: `2025-06-18`
- Tool schema changes follow trustcard's diff taxonomy: NONE < SYNTACTIC <
  NON_BREAKING < ANNOTATION_DOWNGRADE < PERMISSION_CHANGE < BREAKING.
  Adding a new optional parameter is NON_BREAKING. Removing a parameter or
  adding a required one is BREAKING. Changing annotations is PERMISSION_CHANGE.
