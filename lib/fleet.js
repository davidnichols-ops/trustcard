// Fleet operations: find every trustcard-gated MCP server in a client config,
// re-attest it against the live server, and renew its manifest — atomically,
// with a backup, and without ever loosening a decision a human made.
//
// Zero deps. Config formats supported here: JSON with `mcpServers` (Devin,
// Antigravity, Claude, Cursor). TOML clients are handled by lib/adapters.
import { readFileSync, writeFileSync, renameSync, copyFileSync, existsSync } from "node:fs";
import { dirname, basename, join } from "node:path";
import { McpStdioClient, PROTOCOL_VERSIONS } from "./client.js";
import { renewManifest, buildManifest } from "./manifest.js";

const PROXY_RE = /(?:^|[\\/])(?:mcp-proxy(?:\.js)?|trustcard-proxy)$/;

// Parse a wrapped server entry: node <...>/mcp-proxy.js [flags] --manifest M -- cmd args...
export function parseWrappedServer(name, entry) {
  if (!entry || !Array.isArray(entry.args)) return null;
  const all = [entry.command, ...entry.args];
  const proxyIdx = all.findIndex((a) => typeof a === "string" && PROXY_RE.test(a));
  if (proxyIdx === -1) return null;
  const sep = all.indexOf("--", proxyIdx);
  if (sep === -1) return null;
  const flags = all.slice(proxyIdx + 1, sep);
  const mIdx = flags.indexOf("--manifest");
  const manifest = mIdx !== -1 ? flags[mIdx + 1] : null;
  const cwdIdx = flags.indexOf("--cwd");
  const [cmd, ...args] = all.slice(sep + 1);
  if (!cmd) return null;
  return { name, manifest, cmd, args, env: entry.env ?? {}, cwd: cwdIdx !== -1 ? flags[cwdIdx + 1] : undefined, flags };
}

export function readJsonConfig(path) {
  const raw = JSON.parse(readFileSync(path, "utf8"));
  const servers = raw.mcpServers ?? raw.servers ?? {};
  return { raw, servers };
}

export function listGated(configPath) {
  const { servers } = readJsonConfig(configPath);
  const gated = [];
  const ungated = [];
  for (const [name, entry] of Object.entries(servers)) {
    const w = parseWrappedServer(name, entry);
    if (w) gated.push(w);
    else ungated.push({ name, transport: entry.url || entry.serverUrl ? "http" : "stdio", url: entry.url ?? entry.serverUrl, command: entry.command });
  }
  return { gated, ungated };
}

// Spawn the real server, handshake, and return its live tools/list.
export async function listLiveTools({ cmd, args = [], env = {}, cwd, timeoutMs = 45_000 }) {
  const client = new McpStdioClient({ cmd, args, env, spawnTimeout: timeoutMs, cwd });
  try {
    await client.start();
    let init = null, lastErr = null;
    for (const v of PROTOCOL_VERSIONS) {
      try {
        init = await client.request("initialize", { protocolVersion: v, capabilities: {}, clientInfo: { name: "trustcard-renew", version: "1" } }, 15_000);
        break;
      } catch (e) { lastErr = e; }
    }
    if (!init) throw new Error(lastErr?.message ?? "handshake failed");
    client.notify("notifications/initialized", {});
    const tools = [];
    let cursor;
    do {
      const res = await client.request("tools/list", cursor ? { cursor } : {}, 15_000);
      if (Array.isArray(res?.tools)) tools.push(...res.tools);
      cursor = res?.nextCursor;
    } while (cursor);
    return { tools, serverInfo: init.serverInfo ?? null };
  } finally {
    await client.stop().catch(() => {});
  }
}

// Atomic write with a timestamped backup next to the original.
export function atomicWriteJson(path, obj, { backup = true } = {}) {
  if (backup && existsSync(path)) {
    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    copyFileSync(path, join(dirname(path), `.${basename(path)}.bak-${stamp}`));
  }
  const tmp = `${path}.tmp-${process.pid}`;
  writeFileSync(tmp, JSON.stringify(obj, null, 2) + "\n");
  renameSync(tmp, path);
}

export function manifestStatus(manifest, now = Date.now(), warnDays = 14) {
  if (!manifest.expiresAt) return { state: "no-expiry", daysLeft: null };
  const daysLeft = (Date.parse(manifest.expiresAt) - now) / 86_400_000;
  return { state: daysLeft < 0 ? "expired" : daysLeft < warnDays ? "expiring" : "ok", daysLeft: Math.round(daysLeft * 10) / 10 };
}

// Renew one wrapped server. Never writes on drift.
export async function renewServer(w, { days = 90, dryRun = false, onlyIfWithinDays = null, list = listLiveTools } = {}) {
  if (!w.manifest || !existsSync(w.manifest)) return { name: w.name, ok: false, action: "error", reason: `manifest not found: ${w.manifest}` };
  const manifest = JSON.parse(readFileSync(w.manifest, "utf8"));
  const status = manifestStatus(manifest);
  if (onlyIfWithinDays != null && status.daysLeft != null && status.daysLeft > onlyIfWithinDays) {
    return { name: w.name, ok: true, action: "skipped", reason: `${status.daysLeft}d left`, expiresAt: manifest.expiresAt };
  }
  let live;
  try { live = await list(w); }
  catch (e) { return { name: w.name, ok: false, action: "error", reason: `could not reach server: ${e.message}` }; }
  const r = renewManifest(manifest, live.tools, days);
  if (!r.renewed) return { name: w.name, ok: false, action: "drift", reason: r.reason, diff: r.diff };
  if (!dryRun) atomicWriteJson(w.manifest, r.manifest);
  return { name: w.name, ok: true, action: dryRun ? "would-renew" : "renewed", previousExpiresAt: manifest.expiresAt, expiresAt: r.manifest.expiresAt };
}

// Re-approve a drifted server. Rules (never loosen silently):
//   * danger analysis is re-run on the live toolset
//   * a manual override is carried forward ONLY if that tool's schema and
//     description hashes are unchanged; otherwise it is dropped and reported
//   * the previous manifest hash, server versions and full diff are recorded
export async function reapproveServer(w, { days = 90, dryRun = false, list = listLiveTools } = {}) {
  const old = JSON.parse(readFileSync(w.manifest, "utf8"));
  let live;
  try { live = await list(w); }
  catch (e) { return { name: w.name, ok: false, action: "error", reason: `could not reach server: ${e.message}` }; }
  const oldByName = new Map(old.tools.map((t) => [t.name, t]));
  const probe = buildManifest(live.tools, live.serverInfo, old.spec, null, days);
  const carried = [], dropped = [];
  for (const t of probe.tools) {
    const prev = oldByName.get(t.name);
    if (!prev?.manualOverride) continue;
    if (prev.schemaHash === t.schemaHash && prev.descriptionHash === t.descriptionHash) carried.push(t.name);
    else dropped.push(t.name);
  }
  const next = buildManifest(live.tools, live.serverInfo, old.spec, carried, days);
  const r = renewManifest(old, live.tools, days);
  next.reapproval = {
    at: new Date().toISOString(),
    previousManifestHash: old.manifestHash,
    previousServerInfo: old.serverInfo ?? null,
    diff: r.diff,
    overridesCarried: carried,
    overridesDropped: dropped,
    newlyBlocked: next.tools.filter((t) => !t.allowed && oldByName.get(t.name)?.allowed !== false).map((t) => t.name),
    newlyAllowed: next.tools.filter((t) => t.allowed && oldByName.get(t.name)?.allowed === false).map((t) => t.name),
  };
  if (Array.isArray(old.renewals)) next.renewals = old.renewals;
  if (!dryRun) atomicWriteJson(w.manifest, next);
  return { name: w.name, ok: true, action: dryRun ? "would-reapprove" : "reapproved", expiresAt: next.expiresAt, reapproval: next.reapproval };
}
