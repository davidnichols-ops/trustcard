// Session: a live connection to one server with identity verification,
// TOCTOU handling, and trust-state evaluation layered on top of the raw
// JSON-RPC stdio client.
//
// Responsibilities:
//   1. negotiate protocol version (newest mutually supported);
//   2. enumerate tools and compute identity digests immediately;
//   3. if the server is trustcard-aware (attaches a binding in its initialize
//      result `_meta`), verify the binding against what we observe — closing
//      the discovery↔execution race for cooperating servers;
//   4. subscribe to `notifications/tools/list_changed` and, when it fires,
//      re-enumerate + re-diff + re-evaluate trust — this is the stale-cache
//      invalidation path;
//   5. expose call() which routes every tools/call through the Guard.
import { McpStdioClient } from "./client.js";
import { serverDigest, toolsetDigest, toolDigest, TRUSTCARD_META_KEY, handshakeBinding } from "./identity.js";
import { diffToolsets, isCompatible } from "./diff.js";
import { REASONS } from "./trust.js";

export class TrustSession {
  constructor({ cmd, args, env, trust, guard, protocolVersions, onEvent } = {}) {
    this.client = new McpStdioClient({ cmd, args, env });
    this.trust = trust;
    this.guard = guard;
    this.protocolVersions = protocolVersions;
    this.onEvent = onEvent ?? (() => {});
    this.observation = null;
    this.serverId = null;
    this.listChangedCount = 0;
  }

  async connect() {
    const versions = this.protocolVersions;
    let init = null;
    let lastErr = null;
    await this.client.start();
    for (const v of versions) {
      try {
        init = await this.client.request("initialize", {
          protocolVersion: v,
          capabilities: {},
          clientInfo: { name: "mcp-trustcard", version: "1.0.0" },
        }, 15_000);
        break;
      } catch (e) {
        lastErr = e;
      }
    }
    if (!init) throw new Error(`handshake failed for all protocol versions: ${lastErr?.message ?? "unknown"}`);
    this.client.notify("notifications/initialized", {});
    this.initResult = init;
    this.serverId = init.serverInfo ?? { name: "unknown", version: "unknown" };

    const res = await this.client.request("tools/list", {}, 10_000);
    const tools = Array.isArray(res?.tools) ? res.tools : [];
    this.observation = this._observe(tools, init.protocolVersion);

    // Verify a trustcard-aware server's handshake binding, if present.
    this.binding = init?._meta?.[TRUSTCARD_META_KEY] ?? null;
    if (this.binding) {
      const expected = handshakeBinding({ manifest: this.binding });
      const problems = [];
      if (this.binding.toolsetDigest && this.binding.toolsetDigest !== this.observation.toolsetDigest) {
        problems.push(`handshake binding toolsetDigest ${this.binding.toolsetDigest} ≠ observed ${this.observation.toolsetDigest}`);
      }
      this.bindingOk = problems.length === 0;
      if (!this.bindingOk) {
        this.trust?.suspect(this.serverId, REASONS.BREAKING_CHANGE, { binding: problems });
        this.onEvent({ type: "binding-mismatch", problems });
      }
    }

    // Stale-cache invalidation: server pushes list_changed → re-observe + re-diff.
    this.client.on("notifications/tools/list_changed", async () => {
      this.listChangedCount++;
      await this.refresh("list_changed");
    });

    return this.observation;
  }

  _observe(tools, protocolVersion) {
    return {
      tools,
      toolsetDigest: toolsetDigest(tools),
      serverDigest: serverDigest({ serverInfo: this.serverId, protocolVersion, tools }),
      toolDigests: Object.fromEntries(tools.map((t) => [t.name, toolDigest(t)])),
      protocolVersion,
      serverInfo: this.serverId,
      observedAt: new Date().toISOString(),
    };
  }

  // Re-enumerate tools and evaluate the diff against trust/pins.
  // This is the TOCTOU + stale-cache path: it runs on list_changed and can be
  // forced before sensitive calls.
  async refresh(reason = "manual") {
    const res = await this.client.request("tools/list", {}, 10_000);
    const tools = Array.isArray(res?.tools) ? res.tools : [];
    const prev = this.observation;
    const next = this._observe(tools, this.observation.protocolVersion);
    const diff = diffToolsets(prev.tools, next.tools);
    this.observation = next;
    const evalResult = this.trust?.evaluate(this.serverId, next, diff);
    const event = { type: "refresh", reason, diff: diff.summary, action: evalResult?.action };
    this.onEvent(event);
    if (evalResult?.action === "mismatch" && !isCompatible(diff)) {
      this.trust?.revoke(this.serverId, REASONS.BREAKING_CHANGE, { summary: diff.summary, via: reason });
    }
    return { diff, evaluation: evalResult, observation: next, previous: prev };
  }

  // Call a tool through the guard's policy gate.
  async call(name, args = {}, opts = {}) {
    if (this.guard) {
      await this.guard.authorizeCall({ session: this, tool: name, args, strict: opts.strict });
    }
    const result = await this.client.request("tools/call", { name, arguments: args }, opts.timeoutMs ?? 30_000);
    if (this.guard) this.guard.recordReceipt({ session: this, tool: name, args, result });
    return result;
  }

  async close() {
    await this.client.stop();
  }
}
