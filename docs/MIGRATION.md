# Migration: v0.x → v1

v1 is a superset. Everything v0.x did still works; the subcommand structure is
new but the old invocations are preserved.

## What keeps working unchanged

```bash
npx mcp-trustcard @modelcontextprotocol/server-github      # → runs `scan`
npx mcp-trustcard scan <spec> --json
npx mcp-trustcard scan --batch servers/official.json --json-out results.json
```

- A bare spec with no subcommand still runs the health scorecard.
- Exit code is still non-zero when the score is below 50.
- The GitHub Action (`action.yml`) is unchanged — it calls `scan`.

## What's new

| Command | What it does |
|---|---|
| `fingerprint <spec>` | Full identity card: package integrity, observed digests, provenance, pin continuity |
| `manifest <spec>` | Probe a server and emit an unsigned manifest |
| `keygen` | Generate a publisher Ed25519 keypair |
| `sign <m.json> --key <k.json>` | Sign a manifest |
| `verify <signed.json> [--spec <pkg>]` | Verify signature/digests (+ live binding) |
| `diff <old.json> <new.json>` | Classify changes (BREAKING/PERMISSION/POISON/NON_BREAKING/SYNTACTIC) |
| `pin <spec>` / `unpin <key>` / `pins` | TOFU pin-store management |

## Library API

New modules under `lib/`:

```
canon.js       RFC 8785 JCS canonicalization
hash.js        sha256 digest helpers
identity.js    tool/server identity, semantic projection, digests
diff.js        syntactic-vs-semantic + breaking classification
trust.js       trust-state machine
provenance.js  manifest build/sign/verify (Ed25519)
pin.js         TOFU pin store (servers + publisher keys)
session.js     live connection with TOCTOU + list_changed handling
guard.js       per-call enforcement gate + receipts
middleware.js  wrapClient() for existing MCP clients
observe.js     probe → identity observation
fingerprint.js package + observed + provenance + pin → one card
receipts.js    reproducibility analysis
report.js      terminal rendering
```

The v0.x entry points `runHealthcheck` (`lib/checks.js`) and `McpStdioClient`
(`lib/client.js`) are unchanged; `client.js` gained a notification listener
(`client.on(method, fn)`) used by the session for `list_changed`.

## For server maintainers

To publish a trust card for your server:

```bash
npx mcp-trustcard keygen --out publisher.key.json   # once; guard the privateKey
npx mcp-trustcard manifest your-server --key publisher.key.json --out trustcard.manifest.json
npx mcp-trustcard sign trustcard.manifest.json --key publisher.key.json --out trustcard.manifest.json
```

Then reference it from your registry `server.json` `_meta` (see
`docs/REGISTRY-INTEGRATION.md`) or host it at a well-known URL.

To make your server *trustcard-aware* (closing the TOCTOU window for clients),
attach the binding to your `initialize` result — see `docs/SPEC.md` §7.1 — and
emit `notifications/tools/list_changed` whenever your toolset changes.

## For agent frameworks

Wrap your existing MCP client; every `tools/call` is then gated and receipted:

```js
import { TrustSession } from "mcp-trustcard/lib/session.js";
import { TrustStore } from "mcp-trustcard/lib/trust.js";
import { Guard } from "mcp-trustcard/lib/guard.js";
import { wrapClient } from "mcp-trustcard/lib/middleware.js";

const trust = new TrustStore({ policy: { requireSignature: true } });
const guard = new Guard({ mode: "enforce", policy: { allowDestructive: false } });
const session = new TrustSession({ cmd, args, env, trust, guard, protocolVersions });
await session.connect();
trust.pin(session.serverId, session.observation);   // TOFU

const secure = wrapClient(rawMcpClient, { guard, session, strictArgs: true });
await secure.request("tools/call", { name: "search", arguments: { query: "x" } });
```

---

# Migration: v1 → v2 (Capability Descriptor core)

v2 is **purely additive**. No v1 API, identity byte, pin, manifest, or test was
changed or removed. The descriptor core (`lib/descriptor.js`,
`lib/change.js`) is layered on top of v1; adopting it is opt-in.

## What keeps working unchanged

Everything. All 89 v1 tests pass unmodified. `interfaceDigest()` returns the
same bytes as `toolDigest()`, so every existing server pin, receipt, and diff
is still valid. v1 manifests still build, sign, and verify through
`provenance.js` untouched.

## The identity model change

| | v1 | v2 |
|---|---|---|
| Trust anchor | `serverDigest` (serverInfo + protocolVersion + toolset) | `descriptorDigest` (interface + implementation + provenance) |
| Interface identity | `toolDigest` (implicit) | `interfaceDigest` — same bytes, explicit name |
| Implementation identity | **none** (fetched but only printed) | typed `npm-dist` / `source` / `unresolved` |
| Change classification | single ladder | multi-axis vector + same simple `isCompatible` decision |
| Pin key | server name@version | descriptor content-address (server pins kept) |

## What changed, and what did NOT

- **Interface identity bytes: unchanged.** No migration of pins needed for the
  interface axis.
- **Implementation identity: new.** v1 has no M_id; existing pins simply have
  no implementation axis. When you re-observe with an implementation identity,
  it is recorded going forward (TOFU on the new axis), not back-filled.
- **serverDigest: retained for compatibility.** It folds in `protocolVersion`
  and `serverInfo.title`, which do not belong in a capability identity — the
  descriptor anchors on `interfaceDigest` instead. New code should pin
  descriptors; `serverDigest` remains so v1 pins keep resolving.
- **Manifests: unchanged format.** A v1 manifest can be *derived into* a bundle
  of descriptors (`manifestToDescriptors`) and back (`descriptorsToManifestTools`).

## Migrating pins

Server pins continue to work. To start pinning by descriptor instead:

```js
import { buildDescriptor, signDescriptor } from "mcp-trustcard/lib/descriptor.js";
const descriptor = signDescriptor(buildDescriptor({ tool, implementation, publisher }), privKey);
pinStore.pinDescriptor(descriptor);            // keyed by descriptorDigest
pinStore.getDescriptorPin(descriptor.descriptorDigest);
```

The two pin spaces (server-keyed and descriptor-keyed) coexist; neither
disturbs the other.

## Migrating manifests

No rewrite is required. A v1 manifest already embeds full tool definitions, so
it converts to descriptors losslessly:

```js
import { manifestToDescriptors } from "mcp-trustcard/lib/descriptor.js";
const bundle = manifestToDescriptors({ tools: manifest.tools, implementation, publisher });
// descriptorSetDigest(bundle) === manifest.toolsetDigest
```

## The new change vector

`diffToolsets()` is unchanged. `changeVector(prior, current)` adds the
implementation and provenance axes and splits permission into
EXPANSION/REDUCTION:

```js
import { changeVector } from "mcp-trustcard/lib/change.js";
const { vector, compatible } = changeVector(prior, current);
// vector.implementation === "REPLACED" catches I_id-same / M_id-changed
```

`isCompatible(diff)` still answers the v1 question; `isVectorCompatible(vector)`
answers the v2 one with the same boolean shape.

## New capabilities in v2 (all additive)

Beyond the descriptor core, v2 adds four pieces that were v1 non-goals. None
requires a migration — each activates only when you opt in.

**Gate 2 — invocation authorization** (`lib/policy.js`). v1's `Guard` only did
Gate 1 (is the capability still trusted?). v2 adds Gate 2: should *this*
invocation run? Pass an `InvocationPolicy` to the guard:

```js
import { InvocationPolicy, constrainArg } from "mcp-trustcard/lib/policy.js";
const guard = new Guard({ mode: "enforce", policy: { allowDestructive: true },
  invocationPolicy: new InvocationPolicy({ rules: [
    constrainArg("fetch_document", "id", (id) => /^doc-\d+$/.test(id)),
  ]}), relyingParty: "my-agent", environment: "prod" });
```

A trusted tool can still have an unauthorized invocation (confused-deputy
bound). `require-approval` throws the distinct `GuardApprovalRequired`. A guard
with no `invocationPolicy` behaves exactly like v1.

**Signed, chained receipts** (`lib/receipts.js`). Pass `receiptKey` (an Ed25519
private key, from `generatePublisherKeypair()`) to the guard and every receipt
is signed, hash-chained (`parentReceipt`), sequenced, and nonced. Verify with
`verifyReceiptSignature(receipt, publicKey)` and `verifyReceiptChain(list)`.
Without `receiptKey` the receipt is byte-for-byte the v1 unsigned receipt.

**Key rotation / revocation** (`lib/rotation.js`). To rotate a compromised
publisher key without a fresh TOFU moment, have the OLD key sign the new one:
`buildRotationCertificate({oldPrivateKey, newPublicKey, newKeyId})`, verified
by `verifyRotationCertificate`. Self-signed revocation via
`buildRevocationCertificate` / `verifyRevocationCertificate`.

**Change vector on the live path.** `TrustSession.refresh()` now returns
`{ diff, vector, ... }` — the 4-axis change vector rides along with the
interface diff. Construct the session with `implementation` and
`publisherKeyId` to populate the implementation/provenance axes.
