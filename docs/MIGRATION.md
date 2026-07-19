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
