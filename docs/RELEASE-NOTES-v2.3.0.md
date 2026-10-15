# trustcard v2.3.0 — Per-Agent Auth Scope Enforcement

**Released:** 2026-07-22
**Package:** `mcp-trustcard@2.3.0` on npm
**Tests:** 326 (283 existing + 43 new), all passing
**Dependencies:** Zero. Pure Node.js stdlib.

---

## What This Release Does

trustcard v2.3.0 closes the last major gap from the v2.2 threat model: **complex auth models**. MCP servers often require OAuth tokens to function, but the MCP protocol has no way to scope which tools an agent may call. v2.3.0 adds per-agent OAuth 2.1 auth scope enforcement at the proxy layer — the agent's bearer token is validated against per-tool `requiredScopes` before the call reaches the server.

This means:
- A read-only agent gets a token with `read:*` scopes → write tools are blocked
- A junior agent gets `tools:low-risk` → destructive tools require approval
- An external IdP (Auth0, Okta, Keycloak, GitHub) issues the token → trustcard introspects it via RFC 7662
- A local dev agent gets a HMAC-signed token from trustcard's built-in issuer → no external IdP needed

## Security Model

### What trustcard protects against

| Threat | Since | How |
|---|---|---|
| Tool poisoning (description rewritten to hide capability) | v1 | Content-addressed tool identity + JCS canonicalization. Description change = identity change = drift detected. |
| Supply chain swap (same name, different code) | v1 | Implementation identity (`npm-dist` digest) in the descriptor. `npm-dist` proves the tarball. |
| Silent capability drift (schema changed without notification) | v1 | `tools/list_changed` subscription + re-diff on every list. TOFU pinning binds the first-seen identity. |
| Destructive tool disguised as safe | v2.0 | Three-engine danger detection: heuristic verb/param analysis + semantic TF-IDF + prompt-injection markers. |
| Prompt injection in tool descriptions | v2.2 | Injection engine detects `<IMPORTANT>` tags, `[SYSTEM OVERRIDE]`, "ignore previous instructions", `~/.ssh/id_rsa`, exfiltration language, base64 blobs. Separate threat class from destructive actions. |
| Manifest tampering | v1 | Ed25519 signed manifests. Verify-before-trust. Fail closed on bad signature. |
| Key compromise | v2.0 | Old-key-signs-new-key rotation certificates with expiring rotation certs. Self-signed revocation certificates. |
| Stale manifests (frozen trust) | v2.1 | `expiresAt` field (default 90 days). Expired manifest blocks all calls until regenerated. |
| **Unauthorized tool access (agent calls tools outside its scope)** | **v2.3** | **Per-agent OAuth 2.1 scope enforcement. Token validated against `requiredScopes` per tool. Wildcard `*` and `prefix:*` supported.** |
| **Token replay across agents** | **v2.3** | **Token bound to subject + scopes. Proxy strips auth metadata before forwarding so server never sees the raw token.** |

### What trustcard does NOT protect against

- **A malicious server the operator explicitly trusted.** TOFU is trust-on-first-use. If the first connection is to a malicious server, the pin is poisoned. Mitigation: verify the fingerprint out-of-band on first use.
- **TOCTOU for non-cooperating servers.** If a server mutates its toolset without sending `tools/list_changed`, trustcard detects it on the next `tools/list` call but not between calls. Bounded by strict arg validation + receipts, not eliminated.
- **Compromised operator keys.** If the operator's Ed25519 key is stolen, the attacker can sign fraudulent manifests. Mitigation: key rotation + revocation certificates.
- **Side-channel attacks.** trustcard operates at the MCP protocol layer. It does not protect against timing attacks, memory dumps, or network-level attacks against the transport.
- **A token with overly broad scopes.** If the IdP issues `*` scopes to every agent, trustcard enforces that correctly — but the policy is meaningless. Scope design is the operator's responsibility.

### Trust boundary

```
Agent → [bearer token] → trustcard proxy → [stripped request] → MCP server
         ↑                                    ↑
    Gate 2: scope check              Gate 1: identity check
    (per-invocation)                 (per-session + per-list)
```

The trust boundary begins at the agent's token and ends at the server's tool execution. trustcard sits between them. Everything before the proxy is untrusted (agent, token). Everything after the proxy is trusted-but-verified (server, tools).

## What Changed

### New: `lib/auth.js`

- `DevIssuer` — HMAC-SHA256 JWT-like tokens for local dev. Signs `{subject, scopes, exp}` with a shared secret. No external IdP needed for development.
- `IdpIntrospector` — RFC 7662 OAuth 2.1 token introspection. Works with Auth0, Okta, Keycloak, GitHub. Caches introspection results until token expiry.
- `TokenValidator` — Combines both. Tries local dev-issuer first (fast, no network), falls back to IdP introspection. Returns `AuthToken` with subject, scopes, and validity.
- `scopeSatisfies(required, presented)` — Wildcard scope matching. `*` matches everything. `prefix:*` matches all scopes under a prefix. Exact match otherwise.
- `extractToken(request)` — Pulls bearer token from `_meta.auth.token` or `MCP_AUTH_TOKEN` env var.
- `stripAuth(request)` — Removes auth metadata from the request before forwarding to the server. The server never sees the raw token.

### Modified: `lib/manifest.js`

- `buildManifest` accepts `scopeOverrides` parameter. Tools can declare `requiredScopes` via server annotations (`_meta.requiredScopes`) or CLI (`--require-scopes`).
- `checkCall(manifest, toolName, args, authToken)` — now validates the caller's scopes against `requiredScopes` when auth is configured. Unscoped tools pass without a token (backward compatible).

### Modified: `lib/policy.js`

- New `requireScopes` Gate 2 rule. Per-tool or global scope requirements. Configurable verdict: `deny` or `require-approval`.
- `summarizeInvocation` now includes `subject` and `scopes` in the receipt.

### Modified: `bin/mcp-proxy.js`

New flags:
- `--auth-secret <hex>` — HMAC secret for dev-issuer tokens
- `--auth-introspect <url>` — RFC 7662 introspection endpoint URL
- `--auth-client-id` / `--auth-client-secret` — client credentials for introspection
- `--auth-token-env` — env var name to read the token from (default: `MCP_AUTH_TOKEN`)

The proxy extracts the token, validates it, strips auth metadata, then forwards the call. If validation fails, the call is blocked with a clear error.

### Modified: `bin/mcp-trustcard.js`

- `auth-issue --subject <name> --scopes <scopes> [--secret-file <path|->]` — issue a dev-mode token (secret also via `TRUSTCARD_AUTH_SECRET`; `--secret <hex>` works but exposes the key in the process list)
- `auth-verify --token <jwt> [--secret-file <path|->]` — verify a dev-mode token and print claims
- `gen-manifest --require-scopes <tool>=<scope1,scope2>` — repeatable flag to declare scope requirements (the older `tool:scope` form still parses)

## Quick Start

```bash
# Install
npm install -g mcp-trustcard

# Generate a manifest with scope requirements
node bin/mcp-trustcard.js gen-manifest --require-scopes "write_file=files:write" \
  --require-scopes "delete_file=files:delete,admin" \
  --save-manifest manifest.json -- npx @modelcontextprotocol/server-filesystem /tmp

# Issue a dev-mode token for a read-only agent
node bin/mcp-trustcard.js auth-issue --subject "reader-agent" \
  --scopes "files:read" --secret "$(openssl rand -hex 32)"

# Run the proxy with auth enforcement
MCP_AUTH_TOKEN="<token-from-above>" \
node bin/mcp-proxy.js --manifest manifest.json \
  --auth-secret "$(openssl rand -hex 32)" \
  -- npx @modelcontextprotocol/server-filesystem /tmp
```

## Test Coverage

326 tests total (43 new in v2.3.0):

- Scope matching: exact, wildcard `*`, prefix `prefix:*`, multi-require
- AuthToken validity: valid, expired, inactive, wrong issuer
- DevIssuer: roundtrip, wrong-secret, expired, no-expiry, malformed
- Token extraction: from `_meta`, from env var, precedence
- Auth metadata stripping: token removed before forwarding
- `checkCall` scope enforcement: no-token, sufficient, insufficient, wildcard, expired, multi-scope
- `buildManifest` scope overrides: CLI, server-declared, precedence
- `requireScopes` Gate 2 rule: deny, allow, wildcard, per-tool, global, require-approval
- `TokenValidator`: dev-issued, empty, unknown format

## Zero Dependencies

trustcard uses only the Node.js standard library. No `jsonwebtoken`, no `oauth`, no `jose`. HMAC-SHA256 via `node:crypto`. Ed25519 via `node:crypto`. HTTP introspection via `fetch()`. This is a security tool — supply chain attack surface must be zero.
