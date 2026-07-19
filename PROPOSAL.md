# Proposal: a signed trust manifest for MCP tools

> This supersedes the earlier `mcp.health` proposal. `mcp.health` was a
> *declared* health field. This is the thing that makes any declaration
> *verifiable*: content-addressed tool identity + a publisher signature + an
> enforcement contract.

## Problem

Agents treat MCP tool definitions as static contracts. They are not. Between
`tools/list` and `tools/call` a server can change a tool's description (to
poison the model), its schema (to break cached plans), or its annotations (to
escalate permissions) — and no client can detect any of it today, because
there is no machine-checkable notion of "the same tool" or "who vouches for
it." Clients connect blind, plan against a snapshot, and discover drift at
call time or never.

We measured the discovery gap empirically: scanning 10 recognizable servers as
a naive client, **3 of 10 could not complete a handshake**, and there was no
machine-readable way to learn why before connecting. That is the *mildest*
failure. The harder failures — poisoning, breaking drift, permission flips,
TOCTOU mutation — are invisible to any single observation.

## Proposal

Three small, composable pieces, each optional and backward-compatible.

### 1. A signed manifest (`trustcard.manifest.json`)

A publisher binds {server identity, protocol versions, complete tool
definitions} to an Ed25519 key. Identity is content-addressed:

```
toolDigest    = SHA-256( JCS( semantic projection of a tool ) )
toolsetDigest = SHA-256( JCS( sorted toolDigests ) )
```

The semantic projection is exactly the fields that change behavior: name,
description, input/output schemas, behavioral annotations, execution. Volatile
fields (title, icons, `_meta`) are excluded, so cosmetic edits are not trust
events. Signatures are detached over the JCS-canonical payload; keys are
self-certifying (`keyId = hash(publicKey)`), so no CA or registry key
directory is needed on day one.

**Full format + verification algorithm: [`docs/SPEC.md`](docs/SPEC.md).**

### 2. A registry `_meta` extension

Carry three fields in `server.json` under
`_meta["io.github.davidnichols-ops/trustcard"]`:

```jsonc
{ "manifestUrl": "...", "manifestDigest": "sha256:...", "publisher": { "keyId": "sha256:..." } }
```

The registry stays a distribution point (not a trust root) and doesn't parse
the format. Clients fetch the manifest, verify the signature against a pinned
key, and check the digest. **Details: [`docs/REGISTRY-INTEGRATION.md`](docs/REGISTRY-INTEGRATION.md).**

### 3. A handshake binding + change-notification contract (closes TOCTOU)

A trustcard-aware server attaches its `toolsetDigest` to the `initialize`
result under `_meta["io.github.davidnichols-ops/trustcard"]`, committing to a
toolset *at handshake time*. It sets `capabilities.tools.listChanged = true`
and emits `notifications/tools/list_changed` on any mutation; clients
re-enumerate, re-diff against their pin, and re-evaluate trust immediately.
This narrows the discovery↔execution race from "the whole session" to "the
handshake." **Details: [`docs/SPEC.md`](docs/SPEC.md) §7.**

## Why this is better than status quo

| Today | With a trust manifest |
|---|---|
| "Is this the same tool as yesterday?" is unanswerable | `toolsetDigest` match/mismatch + classified diff |
| Tool poisoning invisible (schema unchanged) | `ANNOTATION_DOWNGRADE` flags material description rewrites with identical schema |
| Breaking changes found at call time | `BREAKING` class detected at re-verification; plans fail safe |
| No provenance — a good score is the server's claim about itself | Ed25519 signature + pinned publisher key |
| TOCTOU mutation unbounded | handshake binding + `list_changed` re-verify bound it to the handshake |
| "Reproducible" assumed | receipts bind contract digest + args digest → result digest |

## Verification, not trust

The manifest is a **claim that is expensive to lie about**. Verifiers (the
reference is `mcp-trustcard`) compare the signed claim against an empirical
probe and publish drift:

- signature verifies but served tools ≠ signed tools → **compromised/malicious server**;
- digest matches but the publisher key changed → **key drift, needs re-approval**;
- everything matches → a verified, comparable, auditable trust surface.

The incentive structure is the point: maintainers who keep their manifest
honest get a verified badge; maintainers whose served tools diverge from their
signed manifest get flagged automatically.

## Reference implementation

This repo. Zero-dependency, pure Node stdlib. Ships:

- the manifest build/sign/verify toolchain (`keygen`/`manifest`/`sign`/`verify`);
- the change classifier (`diff`) implementing the breaking-change taxonomy;
- the trust-state machine, TOFU pin store, and Guard middleware;
- the empirical scanner (`scan`) as the reference verifier;
- 87 tests covering canonicalization (against RFC 8785), every classification
  rule, every tamper case, and live TOCTOU/notification scenarios against
  fixture servers.

## Ask

1. Adopt the manifest format (or a subset) as an optional signed artifact, and
   permit the `_meta` key in the registry schema.
2. Let `mcp-trustcard` be the reference verifier (happy to contribute it).
3. Publish manifest-verification status alongside registry entries, so the
   trust surface is shared infrastructure rather than one team's opinion.

Happy to turn this into a PR against the registry schema if there's interest.
