# Operations release candidate — 3.2.0-rc.1

Trustcard operations adds a reusable agent skill, four config-bound operations MCP tools, a local read-only console and policy-preserving fleet renewal/reapproval. It is a local release candidate, not a general enterprise production certification. The published 3.1.0 package may not include these commands; use the accompanying candidate tarball until a release is approved.

See [the skill](../skills/trustcard-operations/SKILL.md) for the operational workflow, [client integration](../skills/trustcard-operations/references/clients.md) for supported config/transport boundaries, and [enterprise integration](../skills/trustcard-operations/references/enterprise.md) for the planned control-plane architecture and acceptance gates.

## New commands

```
mcp-trustcard status --config client.json --json
mcp-trustcard renew --config client.json --within 14 --dry-run --json
mcp-trustcard reapprove --config client.json --server example --dry-run --json
mcp-trustcard reapprove manifest.json --url http://127.0.0.1:7778/mcp --dry-run --json
mcp-trustcard watch --config client.json --within 14 --once
mcp-trustcard watch --config client.json --within 14 --interval 21600
mcp-trustcard console --config client.json
trustcard-ops --config client.json
```

The console binds loopback and has no write API. It lists only the selected JSON config. Operations MCP writes require both owner startup flag `--allow-writes` and tool argument `apply:true`; that switch is not a human-approval protocol. Renewal previews start configured upstreams for discovery. They do not call the upstream's business tools.

The background watcher checks every six hours by default. It renews unchanged full contracts only and emits JSON results; drift and legacy/signature-bearing policies require explicit review. It does not perform automatic reapproval or deliver notifications. Supervise it with the host service manager and monitor non-success results.

## Behavior changes

- New enforcement manifests capture full semantic contract digests plus separately hashed declared scopes; v1 protocol identity bytes remain unchanged.
- Renewal refuses changed contracts, legacy manifests without full digests, and signature-bearing input. Publisher manifests use the separate provenance API.
- Explicit reapproval and legacy proxy auto-update preserve existing denials and scope requirements. Unchanged overrides migrate; changed overrides are dropped. New tools can be allowed by reapproval/auto-update after analysis: these modes are not unchanged-contract renewal.
- Proxy tools/list filtering now excludes denied and observed-drifted tools. Calls to tools observed as drifted are denied. This is discovery-dependent drift protection; it does not prove implementation identity or eliminate TOCTOU.
- HTTP gate binds `127.0.0.1` by default. Explicit `--host` is available for separately secured deployments. A configured HMAC secret alone still permits unscoped tools without a token.
- HTTP successful-call receipts bind the full authorization-policy digest and approved capability digest (when available), captured at the authorization decision rather than after a later policy update.
- HTTP signed receipt logs resume only after chain and signature checks with the expected current key. Invalid history or key mismatch stops startup. Preserve old history and use an explicitly identified new stream after an incident; never rewrite the log to make checks pass. One process must own each receipt file.
- Client environment `${NAME}` / `${env:NAME}` placeholders are resolved only from the discovery process environment; missing references fail before spawning and never reach the server as literal credential strings.
- JSON status now returns nonzero on invalid/expired/missing manifests, and numeric CLI options are validated.
- Fleet replacement preserves file permissions, makes a backup, rejects manifest symlinks, and refuses concurrent policy edits. Locks coordinate cooperating writers; no claim of a distributed transaction or protection against an uncooperative local administrator.

## Limits that remain

Fleet parsing is limited to supported JSON stdio wrappers. The HTTP CLI discovery path has no custom-auth-header option; TOML adapters, OAuth gateway mediation, Keychain/KMS custody, signed central policy rollout, tenant RBAC and a complete allow/deny event collector remain unimplemented. The console does not verify live process state or publisher signatures. Receipt signatures establish attribution, not that a tool behaved safely. Existing stdio process cleanup targets its direct child, not a guaranteed whole process tree. HTTP streaming/session hardening and a clean cross-platform matrix remain release gates for an enterprise production claim.
