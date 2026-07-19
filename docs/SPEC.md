# Trustcard Protocol Specification v1

Status: draft. This document is the normative reference for the trustcard
manifest format, identity digests, change classification, trust-state machine,
and the client/server behaviors that close the discovery↔execution gap.

The key words **MUST**, **SHOULD**, and **MAY** are to be interpreted as in
RFC 2119.

---

## 1. Canonicalization

All digests are computed over the **RFC 8785 (JSON Canonicalization Scheme,
JCS)** byte serialization of a JSON value. JCS is chosen because:

- it is a published, implementation-independent standard with test vectors;
- it is deterministic for all JSON-representable values;
- it requires no schema — two parties canonicalize the same value identically.

Implementations **MUST** produce byte-identical output to RFC 8785. Numbers
**MUST** use the ECMAScript `Number::toString` shortest round-trip form with
`e+n` / `e-n` exponents and no leading zeros; object keys **MUST** be sorted
by UTF-16 code units; only the mandatory JSON string escapes are emitted.

The reference implementation is `lib/canon.js`.

## 2. Digests

A digest is `sha256:<base64url>` — the SHA-256 of the JCS bytes, base64url
encoded, prefixed with `sha256:`. This mirrors SRI/npm `integrity` syntax so
trustcard digests interoperate with existing supply-chain tooling.

```
digest(value) = "sha256:" + base64url(SHA256(JCS(value)))
```

## 3. Tool identity

### 3.1 The semantic projection

A tool definition has a **semantic projection**: the subset of fields that
change what an agent can do, or what it believes a tool does. The projection
contains exactly:

| field | why it is semantic |
|---|---|
| `name` | the call target |
| `description` | instructions to the model (poisoning vector) |
| `inputSchema` | the accepted-arguments contract |
| `outputSchema` | the structured-output contract |
| `annotations.{title,readOnlyHint,destructiveHint,idempotentHint,openWorldHint}` | behavioral permission hints |
| `execution` | dispatch semantics (e.g. `taskSupport`) |

All other fields — `title` (top-level), `icons`, `tags`, and arbitrary `_meta`
— are **volatile**: they **MUST NOT** appear in the projection. Changing only
volatile fields is a *syntactic* change and **MUST NOT** alter the digest.

### 3.2 Digests

```
toolDigest(tool)        = digest(projection(tool))
toolsetDigest(tools)    = digest({ toolset: sort([ toolDigest(t) for t in tools ]) })
serverDigest(binding)   = digest({
                            server: { name, version, title },
                            protocolVersion,
                            toolset: toolsetDigest(tools)
                          })
```

- `toolsetDigest` is **order-independent** (digests are sorted before hashing).
- `serverDigest` binds *who answered* (serverInfo), *which protocol was
  negotiated*, and *the exact toolset* into one value. Any drift in any of
  the three changes it.

## 4. Change classification

Given a pinned toolset and a newly observed toolset, the differ classifies the
transition into one of six ordered levels:

```
NONE  <  SYNTACTIC  <  NON_BREAKING  <  ANNOTATION_DOWNGRADE  <  PERMISSION_CHANGE  <  BREAKING
```

A transition is **compatible** (auto-repinnable) iff its level ≤ NON_BREAKING.

### 4.1 Syntactic

Only volatile fields changed. Semantic digests are identical.

### 4.2 Semantic, non-breaking

- a tool is **added**;
- an **optional** input property is added;
- an input domain is **widened** (type added to a union, enum grown, constraint
  relaxed, `additionalProperties` opened, constraint removed);
- a `required` entry is removed;
- an `outputSchema` is added.

### 4.3 Semantic, breaking

- a tool is **removed**;
- a **required** input property is added;
- an input domain is **narrowed**: type removed from a union, enum/const shrunk,
  `minimum/minLength/...` increased, `maximum/maxLength/...` decreased,
  `pattern`/`format`/`multipleOf`/`uniqueItems` added or tightened,
  `additionalProperties` closed, a composition keyword (`oneOf/anyOf/allOf/not/if`)
  introduced;
- the `outputSchema` is narrowed in a way that can invalidate prior consumers.

### 4.4 Permission change

- any of `readOnlyHint` / `destructiveHint` / `idempotentHint` / `openWorldHint`
  changes;
- `execution` (e.g. `taskSupport`) changes;
- the `outputSchema` is removed (structured output no longer guaranteed).

### 4.5 Annotation downgrade (suspected tool poisoning)

- the `description` is **materially rewritten** (token-set Jaccard < 0.6)
  **while the schemas are unchanged**. This is the signature of a tool-poisoning
  attack: the machine-checkable contract is untouched, but the instructions to
  the model are replaced. It is incompatible and **MUST NOT** be auto-repinned.

The reference implementation is `lib/diff.js`.

## 5. The manifest

A trustcard manifest is a signed JSON document binding a server's identity and
its complete tool definitions to a publisher key. Filename convention:
`trustcard.manifest.json`.

```jsonc
{
  "schema": "trustcard.dev/manifest@1",
  "server":    { "name": "...", "version": "..." },
  "protocol":  { "negotiated": "2025-06-18", "supported": ["2025-06-18"] },
  "tools":     [ /* complete tool definitions, as served by tools/list */ ],
  "toolsetDigest":  "sha256:...",
  "toolDigests":    { "<toolName>": "sha256:..." },
  "serverDigest":   "sha256:...",
  "publisher": { "keyId": "sha256:...", "publicKey": "<base64url spki>" },
  "issuedAt":  "2026-07-19T00:00:00Z",
  "expiresAt": null,
  "generator": "mcp-trustcard@1.0.0",
  "manifestDigest": "sha256:...",
  "signature": { "algorithm": "ed25519", "keyId": "sha256:...", "value": "<base64url>" }
}
```

### 5.1 Signing payload

The signing payload is the manifest with **both** `signature` and
`manifestDigest` removed, canonicalized with JCS. `manifestDigest` is defined
as `digest(payload)`, so neither it nor `signature` can be part of the payload.

```
manifestDigest = digest(manifest − {signature, manifestDigest})
signature.value = Ed25519_sign(secretKey, JCS(manifest − {signature, manifestDigest}))
```

### 5.2 Publisher keys

- Algorithm: **Ed25519** (small keys, fast verify, deterministic signatures,
  native to Node's `node:crypto` — no dependencies).
- `publicKey` is the base64url of the DER `spki` encoding.
- `keyId = digest(publicKey_bytes)` — the key is self-certifying; `keyId` is a
  pure function of the key bytes, so a claimed `keyId` that doesn't match the
  embedded `publicKey` is rejected.

### 5.3 Verification

A verifier **MUST** check, in order:

1. `schema` is a known version;
2. `publisher.keyId == digest(publisher.publicKey)`;
3. `manifestDigest == digest(payload)` (internal consistency);
4. `toolsetDigest == toolsetDigest(tools)`;
5. `serverDigest == serverDigest(server, protocol.negotiated, tools)`;
6. `Ed25519_verify(publisher.publicKey, signature.value, JCS(payload))`;
7. `expiresAt` is unset or in the future.

Any failure **MUST** fail verification. The reference implementation reports
*all* failures, not just the first.

## 6. Trust-state machine

Every server a client knows is in exactly one state:

```
                 observe()
   UNKNOWN ──────────────────► OBSERVED ── pin() ──► PINNED
                                                      │  │
                       compatible re-diff (≤NON_BREAKING)  │
                                                      ▼  ▼
                                              re-pin   incompatible diff
                                                      │
                        ┌─────────────────────────────┤
                        ▼                             ▼
                    MISMATCH ── approve() ──► PINNED   SUSPECT (unsigned-when-required)
                        │                             │
                        └──── policy denies ──────────┤
                                                      ▼
                                                   REVOKED   (terminal per session)
```

- **REVOKED** is terminal for the session: once a server changes its contract
  incompatibly or its provenance fails, the safe default is to stop routing
  calls until a human re-pins (`approve()` is the only exit).
- Every transition **MUST** emit an audit event `{ at, server, from, to, reason,
  detail }` with a stable machine-readable `reason` code (see
  `lib/trust.js#REASONS`).

## 7. Closing the discovery↔execution gap (TOCTOU)

Three mechanisms, in decreasing strength:

### 7.1 Handshake binding (cooperating servers)

A trustcard-aware server **SHOULD** attach a binding to its `initialize` result
under the `_meta` key `io.github.davidnichols-ops/trustcard`:

```jsonc
{ "_meta": { "io.github.davidnichols-ops/trustcard": {
    "schema": "trustcard.dev/manifest@1",
    "toolsetDigest": "sha256:...",
    "serverDigest": "sha256:...",
    "manifestDigest": "sha256:..."
} } }
```

The client recomputes the digests from its own `tools/list` and compares.
Mismatch ⇒ the server committed to one toolset and served another ⇒ SUSPECT.
This commits the server to a toolset *at handshake time*, before any call.

### 7.2 Change notification (stale-cache invalidation)

A server that sets `capabilities.tools.listChanged = true` and sends
`notifications/tools/list_changed` triggers the client to **immediately**
re-enumerate, re-diff against the pin, and re-evaluate trust. An incompatible
re-diff **MUST** move the server to MISMATCH and, per policy, REVOKED.

### 7.3 Per-call re-assertion (the residual window)

The window that remains is a server mutating between the last enumeration and
a call *without* sending a notification. Mitigations:

- the guard re-validates call arguments against the **pinned** inputSchema in
  strict mode (a server that silently widened/changed args fails the call);
- every call emits a receipt recording the digest under which it was made, so a
  later audit detects that the contract had drifted;
- a server that wants to be trusted for high-stakes calls **SHOULD** implement
  §7.1 so the window is bounded by the handshake.

## 8. Registry integration

The manifest is designed to live in the official MCP registry's extension
point: `server.json` `_meta` under a reverse-DNS key. See
`docs/REGISTRY-INTEGRATION.md`. The registry entry carries `{ manifestUrl,
manifestDigest, publisher.keyId }`; clients fetch the manifest, verify it
against the pinned publisher key, and check the digest — without the registry
needing to understand the format.

## 9. Reproducibility receipts

A receipt binds an exact contract version to a call:

```jsonc
{ "schema": "trustcard.dev/receipt@1",
  "at": "...", "server": {...}, "tool": "search",
  "toolDigest": "...", "toolsetDigest": "...", "serverDigest": "...",
  "protocolVersion": "...", "argumentsDigest": "...", "resultDigest": "..." }
```

Two calls are *reproducible* iff `toolsetDigest` and `argumentsDigest` match;
comparing `resultDigest` then measures whether the server is deterministic
under an identical contract — the only meaningful notion of reproducibility
when tools are mutable. See `lib/receipts.js`.
