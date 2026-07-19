# Registry integration

How trustcard manifests live in the official MCP registry without requiring
the registry to change anything.

## The extension point

The official `server.json` schema reserves `_meta` for publisher-provided
metadata under reverse-DNS keys. trustcard uses:

```
io.github.davidnichols-ops/trustcard
```

A registry entry that wants to publish a trust card adds:

```jsonc
{
  "$schema": "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json",
  "name": "io.example/knowledge-base",
  "version": "1.2.0",
  "packages": [ /* ... */ ],
  "_meta": {
    "io.github.davidnichols-ops/trustcard": {
      "schema": "trustcard.dev/registry@1",
      "manifestUrl": "https://example.com/.well-known/trustcard.manifest.json",
      "manifestDigest": "sha256:...",           // digest of the unsigned payload
      "publisher": { "keyId": "sha256:..." }   // the signing key clients should expect
    }
  }
}
```

Only three fields are required: where to fetch the manifest, its digest (so a
registry mirror or cache can't silently swap it), and the publisher `keyId`
(so a client knows which pinned key should have signed it). The full tool
definitions stay in the manifest itself — the registry entry stays small and
the registry does not need to parse or validate the format.

## Client flow

```
server.json (registry)
   │  _meta["io.github.davidnichols-ops/trustcard"]
   ▼
fetch manifestUrl ──► verify Ed25519 signature against pinned publisher key
   │                    (key continuity via the client's TOFU pin store)
   ▼
verify manifestDigest == digest(payload)   (registry mirror can't swap it)
   ▼
connect to server ──► observe tools/list ──► bindingConsistency(manifest, observed)
   │                                            declared toolset == live toolset?
   ▼
pin serverDigest in the client's pin store (TOFU)
   ▼
every later connection: re-observe, diff against pin, classify, enforce
```

## Why this shape

- **Decentralized.** No CA, no registry-operated key directory required on day
  one. Publisher keys are self-certifying (`keyId = hash(publicKey)`) and
  continuity comes from the client's pin store.
- **Registry-agnostic.** Works with the official registry, a private registry,
  or no registry at all (manifest can be fetched from a well-known URL or
  shipped in the npm package).
- **Fail-closed.** Every link in the chain — manifest integrity, signature,
  key continuity, declared↔observed consistency, pin continuity — fails closed
  and produces a specific reason.
- **Upgrade path.** If the official registry later operates a publisher key
  directory or signs entries itself, publisher keys can be *anchored* there.
  The manifest format and client verification do not change.

## Relationship to the earlier `mcp.health` proposal

`PROPOSAL.md` originally proposed an `mcp.health` field for *declared* health
metadata (requiresAuth, transport, latency). That remains useful and is kept —
but it is a **claim**, and v2 is what makes claims *checkable*. The trustcard
manifest supersedes the trust-relevant parts of `mcp.health` with signed,
content-addressed tool identity. The two compose: `mcp.health` answers "should
I connect and what config does it need?", the trustcard manifest answers "is
what I connected to the thing a known publisher signed?"

## Ask of the registry

1. Permit the `io.github.davidnichols-ops/trustcard` `_meta` key (it already
   conforms to the publisher-provided metadata rules).
2. Optionally surface `manifestDigest` verification status on registry pages
   ("this entry's manifest signature verifies and matches the served tools"),
   computed by running `mcp-trustcard fingerprint --manifest <url>` as a cron —
   the same drift-detection the existing leaderboard workflow already runs.
