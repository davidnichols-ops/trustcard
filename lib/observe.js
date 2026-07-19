// Observe: probe a server and produce a full identity observation (the
// fingerprint). Reuses the healthcheck's spawn logic but focuses on identity:
// negotiated protocol version, serverInfo, and the complete tool definitions.
import { McpStdioClient, PROTOCOL_VERSIONS } from "./client.js";
import { serverDigest, toolsetDigest, toolDigest } from "./identity.js";

export async function observeServer({ cmd, args, env = {}, protocolVersions = PROTOCOL_VERSIONS, spawnTimeout = 45_000 }) {
  const client = new McpStdioClient({ cmd, args, env, spawnTimeout });
  const observation = {
    cmd: [cmd, ...args].join(" "),
    serverInfo: null,
    protocolVersion: null,
    tools: [],
    toolsetDigest: null,
    serverDigest: null,
    toolDigests: {},
    capabilities: null,
    handshakeBinding: null,
    observedAt: null,
    error: null,
  };
  try {
    await client.start();
    let init = null;
    let lastErr = null;
    for (const v of protocolVersions) {
      try {
        init = await client.request("initialize", {
          protocolVersion: v,
          capabilities: {},
          clientInfo: { name: "mcp-trustcard", version: "1.0.0" },
        }, 15_000);
        break;
      } catch (e) { lastErr = e; }
    }
    if (!init) throw new Error(lastErr?.message ?? "handshake failed");
    client.notify("notifications/initialized", {});
    observation.serverInfo = init.serverInfo ?? null;
    observation.protocolVersion = init.protocolVersion ?? null;
    observation.capabilities = init.capabilities ?? null;
    observation.handshakeBinding = init?._meta?.["io.github.davidnichols-ops/trustcard"] ?? null;

    const res = await client.request("tools/list", {}, 10_000);
    const tools = Array.isArray(res?.tools) ? res.tools : [];
    observation.tools = tools;
    observation.toolsetDigest = toolsetDigest(tools);
    observation.toolDigests = Object.fromEntries(tools.map((t) => [t.name, toolDigest(t)]));
    observation.serverDigest = serverDigest({ serverInfo: observation.serverInfo, protocolVersion: observation.protocolVersion, tools });
    observation.observedAt = new Date().toISOString();
  } catch (e) {
    observation.error = e.message ?? String(e);
    observation.stderr = client.stderr?.slice(-800);
  } finally {
    await client.stop();
  }
  return observation;
}
