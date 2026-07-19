# Proposal: a signed trust manifest for MCP registry entries

## TL;DR

Agents treat MCP tool definitions as static contracts, but servers can mutate
them at any moment — poisoning descriptions, adding required parameters, or
flipping permission annotations between `tools/list` and `tools/call`. No
client can detect this today, because there's no machine-checkable notion of
"the same tool" or "who vouches for it."

I built [`trustcard`](https://github.com/davidnichols-ops/trustcard), which
gives every tool definition a **content address** (SHA-256 over a JCS-canonical
semantic projection) and lets a publisher **sign** its toolset with Ed25519.
Clients pin what they first observe (TOFU) and every later connection must
match or produce a classified, auditable diff. This issue proposes carrying
the manifest in the registry via the existing `_meta` extension point — no
schema change required.

## Evidence

Two findings from scanning the ecosystem as a naive client (`npx -y <pkg>`, no
args/env — exactly how an agent first contacts a server):

1. **The discovery gap is real.** 3 of 10 recognizable servers couldn't
   complete a protocol handshake, and there was no machine-readable way to
   learn why before connecting. ([leaderboard + method](https://github.com/davidnichols-ops/trustcard#leaderboard))
2. **Health probing has a ceiling.** A score measures one observation. It
   cannot detect *change* (poisoning, breaking drift, permission flips) or
   establish *provenance* (is this the tool the publisher signed?) — the two
   things that actually hurt agents. That's why v2 is a protocol, not just a
   scanner.

## Proposal

Three composable, optional, backward-compatible pieces:

**1. A signed manifest** — `trustcard.manifest.json` binds {server identity,
protocol, complete tool definitions} to an Ed25519 key. Identity is
content-addressed; volatile fields (title/icons/`_meta`) are excluded so
cosmetic edits aren't trust events. Keys are self-certifying
(`keyId = hash(publicKey)`), so no CA is needed. [Format + verification →](https://github.com/davidnichols-ops/trustcard/blob/main/docs/SPEC.md)

**2. A registry `_meta` extension** — three fields under
`_meta["io.github.davidnichols-ops/trustcard"]`:

```jsonc
{ "manifestUrl": "...", "manifestDigest": "sha256:...", "publisher": { "keyId": "sha256:..." } }
```

The registry stays a distribution point, doesn't parse the format, and the
digest means a mirror/cache can't silently swap the manifest.
[Integration →](https://github.com/davidnichols-ops/trustcard/blob/main/docs/REGISTRY-INTEGRATION.md)

**3. A handshake binding + change-notification contract** — a trustcard-aware
server commits to a `toolsetDigest` in its `initialize` result and emits
`notifications/tools/list_changed` on mutation, so clients re-verify
immediately. This closes most of the discovery↔execution (TOCTOU) race for
cooperating servers. [TOCTOU analysis →](https://github.com/davidnichols-ops/trustcard/blob/main/docs/SPEC.md)

## Why in the registry

The manifest is a claim that's expensive to lie about. Verifiers compare the
signed claim to an empirical probe and publish drift — so the trust surface
becomes shared infrastructure, not one team's opinion:

- signature verifies but served tools ≠ signed tools → compromised/malicious server;
- publisher key changed → key drift, needs re-approval;
- all match → a verified, comparable trust card at selection time.

## Reference implementation

The repo above. Zero-dependency Node stdlib. Ships the full toolchain
(`keygen`/`manifest`/`sign`/`verify`/`diff`/`pin`), a trust-state machine,
TOFU pin store, an enforcement middleware (Guard), and 87 tests — including
RFC 8785 canonicalization vectors, every breaking-change rule, every tamper
case, and live TOCTOU/notification scenarios.

## Ask

1. Permit the `io.github.davidnichols-ops/trustcard` `_meta` key (it already
   conforms to the publisher-provided metadata rules).
2. Treat `trustcard` as a reference verifier (happy to contribute it).
3. Optionally surface manifest-verification status on registry pages.

Happy to open a PR against the registry schema if there's interest.
