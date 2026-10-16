---
name: trustcard-operations
description: Set up and operate Trustcard gates for MCP coding tools, explain tool denials, check manifest drift and expiry, renew unchanged contracts, and inspect local tool access. Use for Trustcard or MCP tool governance requests.
---

# Trustcard operations

Turn the user's requested MCP access into a working, verifiable gate without asking them to write scripts. Preserve the device's existing transport, credentials, runtime and policy. Use the installed Trustcard CLI or operations MCP; this skill contains instructions, not an independent security boundary.

## Prerequisite and discovery

This package requires **mcp-trustcard 3.2.0 or a later compatible release** for fleet commands, the console and `trustcard-ops`. Check the installed CLI's help and package version. Use a supported Node runtime (18 or later); inspect the actual executable instead of assuming a version-manager path works in background services.

Read the relevant client config and preserve existing entries. Never print environment values, bearer tokens, secret files or whole credential-bearing configs. Identify wrapped and direct connections separately. Start with:

```sh
mcp-trustcard status --config /absolute/path/client-config.json --json
mcp-trustcard console --config /absolute/path/client-config.json
```

Fleet operations accept JSON `mcpServers` or `servers` configs with supported stdio wrappers. They do not parse Codex/Grok TOML, infer remote gateway ownership, or prove runtime coverage. For client setup and HTTP endpoints read [references/clients.md](references/clients.md).

## Use the operations MCP when available

Configure `trustcard-ops --config /absolute/path/client-config.json` as a local stdio MCP server. Its config is fixed at startup; tools cannot select arbitrary executable paths or URLs.

- `tc_status`: local inventory and manifest policy. This does not contact upstreams.
- `tc_explain(server, tool)`: show the decision, required scopes and local override reason. Account for an expired manifest or audit bypass mode before explaining effective access.
- `tc_renew(server)`: preview renewal against live discovery.
- `tc_reapprove(server)`: preview reanalysis and policy migration.

Discovery starts the already-configured server and lists tools; it does not invoke its business tools. Writes are disabled unless the owner starts the operations server with `--allow-writes`. Applying a change also requires `apply: true`. Use that only for a change the user authorized. This process flag is a capability boundary, not proof of human approval.

## Resolve expiry and drift

For unchanged full contracts:

```sh
mcp-trustcard renew --config /absolute/path/client-config.json --within 14 --dry-run --json
mcp-trustcard renew --config /absolute/path/client-config.json --within 14 --json
```

Renewal preserves all policy decisions. Names, input/output schemas, descriptions, behavioral annotations, execution support and declared scopes must match. Legacy manifests without full contract digests need explicit reapproval. Signed publisher manifests belong to the provenance workflow and are refused here; never erase or retain a stale signature to force a renewal.

For recurring backend maintenance, `mcp-trustcard watch --config /absolute/path/client-config.json --within 14 --interval 21600` performs conservative renewal every six hours and emits JSON results. Use `--once` for a bounded service-manager run. It never reapproves drift or sends alerts; have the existing operations system monitor failures. Install recurring maintenance only within the user-authorized scope.

For a reviewed contract update:

```sh
mcp-trustcard reapprove --config /absolute/path/client-config.json --server example --dry-run --json
mcp-trustcard reapprove --config /absolute/path/client-config.json --server example --json
```

Inspect added, removed and changed tools, new blocks, and dropped overrides before application. Existing denials and required scopes remain. Reapproval can permit newly discovered tools that pass static analysis; do not describe it as an unchanged-contract renewal. Changed overrides are dropped. Unchanged legacy overrides can migrate based only on the legacy schema and description hashes; review that limited evidence explicitly. Never use `--allow-all` or automatic tool approval as a repair for a denial.

For an existing local HTTP gate:

```sh
mcp-trustcard reapprove /absolute/path/manifest.json --url http://127.0.0.1:PORT/mcp --dry-run --json
```

This CLI path supports endpoints accessible without custom authentication headers. Use the supported client integration or an operator-controlled authenticated workflow for protected endpoints; never place tokens in a URL or argv.

Every manifest replacement makes a backup and refuses a concurrent edit. Preserve file permissions and symlinks; symlink replacement is deliberately refused. Reload affected clients/proxies, then verify through the actual configured route. A successful file write alone does not establish that a running process loaded it.

## Cryptographic evidence and handoff

Distinguish:

- Local proxy policy and truncated legacy hashes: permission configuration, not publisher attestation.
- Full tool contract digest: content identity, not code identity or safe behavior.
- Publisher Ed25519 manifest verification: origin/key binding and freshness, within the installed verifier's limits.
- Signed call receipts: use **both** `verifyReceiptChain` and `verifyReceiptSignature` against the expected public key. Structural verification alone is insufficient. The HTTP proxy resumes an existing valid chain and refuses a corrupt or different-key chain. Use one writer per receipt file. Existing damaged history must remain preserved and identified.

The local console is read-only and shows only its selected JSON inventory. It does not perform fleet SSO, central policy signing, SIEM export or runtime sandboxing. Read [references/enterprise.md](references/enterprise.md) when asked to plan those integrations.

Finish with what changed, actual runtime/test results and exit status, backup/rollback locations, remaining direct routes, and known limits. Keep packages and marketplace descriptions aligned with features that exist. Preparing a listing or email does not authorize publishing, purchasing, or sending it.
