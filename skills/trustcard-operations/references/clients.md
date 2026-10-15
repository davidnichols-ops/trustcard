# Client integration

Use the client's installed help/config schema as the authority. Do not copy another client's HTTP field names blindly. Back up each config before changing it; preserve env/header references without copying their values.

## JSON stdio clients

Devin, Cursor and Claude-style JSON configs commonly use `mcpServers`. Antigravity uses its own config location and supports `serverUrl` for HTTP. A supported local wrapper entry looks like:

```json
{
  "mcpServers": {
    "example": {
      "command": "/absolute/path/node",
      "args": ["/stable/runtime/bin/mcp-proxy.js", "--manifest", "/absolute/path/example.json", "--strict", "--", "/absolute/path/server", "arg"]
    }
  }
}
```

Keep the upstream's original args, cwd and environment. Fleet discovery resolves `${NAME}` and `${env:NAME}` references from its own process environment and refuses missing references before spawning. It does not borrow credentials from another client or secret store. A background renewal service must receive its authorized credential context separately. Use absolute manifest paths. Relative paths have client-dependent launch semantics and should be resolved against the actual client working directory before adoption. Never infer the launch directory from an unrelated agent session. Fleet config paths resolve relative manifest locations against the config directory; configurations with different client semantics must use absolute paths.

Generate a candidate manifest with `gen-manifest --save-manifest <candidate> -- <command> <args>`, inspect its decisions, then install the wrapper. Do not overwrite an existing policy with a fresh scan; use policy-preserving reapproval.

## HTTP clients

An HTTP gate is a separate process:

```sh
mcp-http-proxy --manifest /absolute/path/manifest.json --upstream http://127.0.0.1:UPSTREAM/mcp --port GATE --strict
```

Loopback is the default bind. Bind elsewhere only as a separately designed deployment with authentication, network restrictions and appropriate transport protection. The proxy's custom scoped HMAC authentication is not a general OAuth resource-server implementation. Local unscoped tools remain accessible without a token; configuring a secret alone does not make the endpoint fully authenticated.

Keep the same protocol/session route the client supports. Antigravity can point `serverUrl` at an existing gate. For Codex, inspect `codex mcp add --help` and `codex mcp list --json` and use its supported URL registration. Verify the persisted config, then reconnect the client. Do not claim a currently open chat reloaded its tool surface automatically.

`mcp-trustcard gate --config <file>` generates the manifest and previews (or with `--apply`, writes) the rewritten config entry: the URL points at the loopback `mcp-http-proxy` and an `_meta` marker records the manifest and upstream. Once applied, `status`, `renew` and `reapprove` treat the entry as gated — discovery runs against the recorded upstream, not the filtering proxy. Until `--apply` and the proxy process are both in place, the entry is ungated.

Remote OAuth connectors must retain their existing authentication flow; do not interpose the current local gate as a generic OAuth proxy.

## Background services

Use a stable installed release or immutable local snapshot. A live gate must not load code from a working tree that agents are editing. On macOS, launchd needs a real Node executable and explicit PATH; shell version-manager shims may fail outside an interactive session. Back up service definitions, test the candidate on another loopback port, switch, then verify health, initialization, list and one authorized read-only call. Preserve a rollback definition and old receipts. Do not overwrite a receipt key or a broken ledger to make a health check pass.
