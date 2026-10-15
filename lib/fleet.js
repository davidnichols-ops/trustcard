// Fleet operations: find every trustcard-gated MCP server in a client config,
// re-attest it against the live server, and renew its manifest — atomically,
// with a backup, and without ever loosening a decision a human made.
//
// Zero deps. Config formats supported here: JSON with `mcpServers` (Devin,
// Antigravity, Claude, Cursor). TOML clients are handled by lib/adapters.
import { readFileSync, writeFileSync, renameSync, copyFileSync, existsSync, statSync, lstatSync, chmodSync, unlinkSync, openSync, closeSync, fsyncSync } from "node:fs";
import { dirname, basename, join, resolve } from "node:path";
import { randomUUID } from "node:crypto";
import { McpStdioClient, PROTOCOL_VERSIONS } from "./client.js";
import { McpHttpClient } from "./client-http.js";
import { renewManifest, buildManifest, assertProxyManifest, diffManifest, computeManifestHash } from "./manifest.js";
import { TRUSTCARD_VERSION } from "./version.js";

const PROXY_RE = /(?:^|[\\/])(?:mcp-proxy(?:\.js)?|trustcard-proxy)$/;
export const TRUSTCARD_HTTP_GATE_KEY = "io.github.davidnichols-ops/trustcard";

// Parse a wrapped server entry: node <...>/mcp-proxy.js [flags] --manifest M -- cmd args...
export function parseWrappedServer(name, entry) {
  if (!entry || !Array.isArray(entry.args)) return null;
  const all = [entry.command, ...entry.args];
  const proxyIdx = all.findIndex((a) => typeof a === "string" && PROXY_RE.test(a));
  if (proxyIdx === -1) return null;
  // A filename mentioned in another program's arguments is not a wrapper.
  if (!(proxyIdx === 0 || (proxyIdx === 1 && /(?:^|[\\/])node(?:\.exe)?$/.test(entry.command)))) return null;
  if (!all.every((a) => typeof a === "string")) return null;
  const sep = all.indexOf("--", proxyIdx);
  if (sep === -1) return null;
  const flags = all.slice(proxyIdx + 1, sep);
  const mIdx = flags.indexOf("--manifest");
  const manifest = mIdx !== -1 ? flags[mIdx + 1] : null;
  if (!manifest || manifest.startsWith("--") || flags.filter((f) => f === "--manifest").length !== 1) return null;
  const cwdIdx = flags.indexOf("--cwd");
  const [cmd, ...args] = all.slice(sep + 1);
  if (!cmd) return null;
  return { name, manifest, cmd, args, env: entry.env ?? {}, cwd: cwdIdx !== -1 ? flags[cwdIdx + 1] : entry.cwd, flags };
}

// Parse a gated HTTP entry: the config points at a local mcp-http-proxy
// (loopback url) and carries the manifest + upstream under the trustcard
// _meta marker — written by `mcp-trustcard gate --apply`. Discovery for
// renew/reapprove must hit the UPSTREAM, not the proxy: the proxy filters
// tools/list to the approved set, so probing it can never see drift.
export function parseHttpGated(name, entry, configDir) {
  const url = entry?.url ?? entry?.serverUrl;
  const meta = entry?._meta?.[TRUSTCARD_HTTP_GATE_KEY];
  if (!url || !meta || typeof meta !== "object") return null;
  if (typeof meta.manifest !== "string" || !meta.manifest) return null;
  if (typeof meta.upstream !== "string" || !/^https?:\/\//i.test(meta.upstream)) return null;
  if (!/^https?:\/\/(?:localhost|127\.|::1|\[::1\])/i.test(url)) return null;
  return {
    name,
    manifest: meta.manifest,
    url: meta.upstream,            // discovery target = real server, not the filter
    proxyUrl: url,
    headers: entry.headers ?? {},
    // marker may pin the discovery transport; config "transport"/"type" fields
    // like "sse" also map. Anything else falls back to streamable-http.
    transport: ["sse", "streamable-http"].includes(meta.transport) ? meta.transport
      : entry.transport === "sse" || entry.type === "sse" ? "sse" : "streamable-http",
    env: {},
  };
}

export function readJsonConfig(path) {
  const raw = JSON.parse(readFileSync(path, "utf8"));
  const servers = raw.mcpServers ?? raw.servers ?? {};
  if (!servers || typeof servers !== "object" || Array.isArray(servers)) throw new Error("MCP servers must be an object");
  return { raw, servers };
}

export function listGated(configPath) {
  const { servers } = readJsonConfig(configPath);
  const gated = [];
  const ungated = [];
  const configDir = dirname(configPath);
  for (const [name, entry] of Object.entries(servers)) {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) throw new Error(`invalid server entry: ${name}`);
    const w = parseWrappedServer(name, entry);
    if (w) {
      // Client configs resolve relative files in their own directory.
      w.manifest = w.manifest ? resolve(configDir, w.manifest) : null;
      gated.push(w);
      continue;
    }
    const hg = parseHttpGated(name, entry, configDir);
    if (hg) {
      hg.manifest = resolve(configDir, hg.manifest);
      gated.push(hg);
      continue;
    }
    ungated.push({ name, transport: entry.url || entry.serverUrl ? "http" : "stdio", url: entry.url ?? entry.serverUrl, command: entry.command, headers: entry.headers });
  }
  return { gated, ungated };
}

// Spawn the real server, handshake, and return its live tools/list.
export async function listLiveTools({ cmd, args = [], env = {}, cwd, url, headers = {}, transport, timeoutMs = 45_000, maxPages = 100 }) {
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) throw new Error("timeout must be positive and finite");
  const resolveEnvRefs = (value) => value.replace(/\$\{(?:env:)?([A-Za-z_][A-Za-z0-9_]*)\}/g, (_, variable) => {
    if (process.env[variable] == null || process.env[variable] === "") throw new Error(`missing environment reference: ${variable}; run discovery in the client's credential context`);
    return process.env[variable];
  });
  const resolvedEnv = {};
  for (const [name, value] of Object.entries(env)) {
    if (typeof value !== "string") throw new Error(`environment value must be a string: ${name}`);
    resolvedEnv[name] = resolveEnvRefs(value);
  }
  // Config headers (Authorization etc.) carry the same ${VAR} references.
  const resolvedHeaders = {};
  for (const [name, value] of Object.entries(headers)) {
    if (typeof value !== "string") throw new Error(`header value must be a string: ${name}`);
    resolvedHeaders[name] = resolveEnvRefs(value);
  }
  const client = url ? new McpHttpClient({ url, headers: resolvedHeaders, transport, timeout: timeoutMs })
    : new McpStdioClient({ cmd, args, env: resolvedEnv, spawnTimeout: timeoutMs, cwd });
  const deadline = Date.now() + timeoutMs;
  const budget = () => {
    const remaining = deadline - Date.now();
    if (remaining <= 0) throw new Error("tool discovery deadline exceeded");
    return Math.min(remaining, 15_000);
  };
  try {
    await client.start();
    let init = null, lastErr = null;
    for (const v of PROTOCOL_VERSIONS) {
      try {
        init = await client.request("initialize", { protocolVersion: v, capabilities: {}, clientInfo: { name: "trustcard-renew", version: TRUSTCARD_VERSION } }, budget());
        break;
      } catch (e) { lastErr = e; }
    }
    if (!init) throw new Error(lastErr?.message ?? "handshake failed");
    await client.notify("notifications/initialized", {}, budget());
    const tools = [];
    const cursors = new Set(), names = new Set();
    let cursor;
    let pages = 0;
    do {
      if (++pages > maxPages) throw new Error("tool pagination limit exceeded");
      const res = await client.request("tools/list", cursor ? { cursor } : {}, budget());
      if (!Array.isArray(res?.tools)) throw new Error("invalid tools/list response");
      for (const tool of res.tools) {
        if (!tool || typeof tool.name !== "string" || !tool.name || names.has(tool.name)) throw new Error("invalid or duplicate tool name");
        names.add(tool.name);
        tools.push(tool);
      }
      cursor = res?.nextCursor;
      if (cursor != null && (typeof cursor !== "string" || !cursor || cursors.has(cursor))) throw new Error("invalid or repeated pagination cursor");
      if (cursor) cursors.add(cursor);
    } while (cursor);
    return { tools, serverInfo: init.serverInfo ?? null };
  } finally {
    await client.stop().catch(() => {});
  }
}

// Atomic write with a timestamped backup next to the original.
export function atomicWriteJson(path, obj, { backup = true, expected } = {}) {
  const lock = `${path}.lock`;
  const fd = openSync(lock, "wx", 0o600);
  const tmp = `${path}.tmp-${randomUUID()}`;
  try {
  if (existsSync(path) && lstatSync(path).isSymbolicLink()) throw new Error("refusing to replace a manifest symlink");
  if (expected !== undefined && readFileSync(path, "utf8") !== expected) throw new Error("manifest changed during discovery; retry after reviewing it");
  const mode = existsSync(path) ? statSync(path).mode & 0o777 : 0o600;
  if (backup && existsSync(path)) {
    const stamp = `${new Date().toISOString().replace(/[:.]/g, "-")}-${randomUUID()}`;
    copyFileSync(path, join(dirname(path), `.${basename(path)}.bak-${stamp}`));
  }
  writeFileSync(tmp, JSON.stringify(obj, null, 2) + "\n", { flag: "wx", mode });
  chmodSync(tmp, mode);
  const tempFd = openSync(tmp, "r");
  try { fsyncSync(tempFd); } finally { closeSync(tempFd); }
  renameSync(tmp, path);
  } finally {
    if (existsSync(tmp)) unlinkSync(tmp);
    closeSync(fd);
    unlinkSync(lock);
  }
}

export function manifestStatus(manifest, now = Date.now(), warnDays = 14) {
  if (!manifest.expiresAt) return { state: "no-expiry", daysLeft: null };
  const daysLeft = (Date.parse(manifest.expiresAt) - now) / 86_400_000;
  if (!Number.isFinite(daysLeft)) return { state: "invalid-expiry", daysLeft: null };
  return { state: daysLeft <= 0 ? "expired" : daysLeft < warnDays ? "expiring" : "ok", daysLeft: Math.round(daysLeft * 10) / 10 };
}

// Renew one wrapped server. Never writes on drift.
export async function renewServer(w, { days = 90, dryRun = false, onlyIfWithinDays = null, list = listLiveTools } = {}) {
  if (!w.manifest || !existsSync(w.manifest)) return { name: w.name, ok: false, action: "error", reason: `manifest not found: ${w.manifest}` };
  const original = readFileSync(w.manifest, "utf8");
  const manifest = JSON.parse(original);
  assertProxyManifest(manifest);
  const status = manifestStatus(manifest);
  if (onlyIfWithinDays != null && status.daysLeft != null && status.daysLeft > onlyIfWithinDays) {
    return { name: w.name, ok: true, action: "skipped", reason: `${status.daysLeft}d left`, expiresAt: manifest.expiresAt };
  }
  let live;
  try { live = await list(w); }
  catch (e) { return { name: w.name, ok: false, action: "error", reason: `could not reach server: ${e.message}` }; }
  const r = renewManifest(manifest, live.tools, days);
  // Distinguish refusal kinds honestly: a legacy-format manifest that never
  // recorded contract digests is not "drift" — the server did not change, the
  // manifest format predates the full contract. Same for signed manifests,
  // which need re-signing, not reapproval-free renewal.
  if (!r.renewed) {
    const action = r.code === "legacy-format" ? "legacy-format"
      : r.code === "signed" ? "signed-manifest"
      : "drift";
    return { name: w.name, ok: false, action, reason: r.reason, diff: r.diff };
  }
  if (!dryRun) atomicWriteJson(w.manifest, r.manifest, { expected: original });
  return { name: w.name, ok: true, action: dryRun ? "would-renew" : "renewed", previousExpiresAt: manifest.expiresAt, expiresAt: r.manifest.expiresAt };
}

// Re-approve a drifted server. Rules (never loosen silently):
//   * danger analysis is re-run on the live toolset
//   * a manual override is carried forward ONLY if that tool's schema and
//     description hashes are unchanged; otherwise it is dropped and reported
//   * the previous manifest hash, server versions and full diff are recorded
export async function reapproveServer(w, { days = 90, dryRun = false, list = listLiveTools } = {}) {
  if (!Number.isFinite(days) || days <= 0) throw new Error("expiry must be a positive finite number of days");
  const original = readFileSync(w.manifest, "utf8");
  const old = JSON.parse(original);
  if (old.signature || old.manifestDigest) return { name: w.name, ok: false, action: "error", reason: "signed manifests require explicit re-signing; reapproval refused" };
  assertProxyManifest(old);
  let live;
  try { live = await list(w); }
  catch (e) { return { name: w.name, ok: false, action: "error", reason: `could not reach server: ${e.message}` }; }
  const oldByName = new Map(old.tools.map((t) => [t.name, t]));
  const probe = buildManifest(live.tools, live.serverInfo, old.spec, null, days);
  const carried = [], dropped = [];
  for (const t of probe.tools) {
    const prev = oldByName.get(t.name);
    if (!prev?.manualOverride) continue;
    if (prev.schemaHash === t.schemaHash && prev.descriptionHash === t.descriptionHash &&
        (!prev.contractDigest || prev.contractDigest === t.contractDigest) &&
        (!prev.declaredScopesHash || prev.declaredScopesHash === t.declaredScopesHash)) carried.push(t.name);
    else dropped.push(t.name);
  }
  const next = buildManifest(live.tools, live.serverInfo, old.spec, carried, days);
  for (const t of next.tools) {
    const prev = oldByName.get(t.name);
    // Reanalysis may tighten policy. It must never erase an operator denial
    // or scopes, even when a tool's contract changed.
    if (prev?.allowed === false) t.allowed = false;
    const scopes = [...new Set([...(prev?.requiredScopes ?? []), ...(t.requiredScopes ?? [])])];
    if (scopes.length) t.requiredScopes = scopes;
    if (prev?.overrideReason && carried.includes(t.name)) t.overrideReason = prev.overrideReason;
  }
  next.summary.allowedTools = next.tools.filter((t) => t.allowed).length;
  next.manifestHash = computeManifestHash(next.tools);
  const r = { diff: diffManifest(old, live.tools) };
  next.reapproval = {
    at: new Date().toISOString(),
    previousManifestHash: old.manifestHash,
    previousServerInfo: old.serverInfo ?? null,
    diff: r.diff,
    overridesCarried: carried,
    overridesDropped: dropped,
    newlyBlocked: next.tools.filter((t) => !t.allowed && oldByName.get(t.name)?.allowed !== false).map((t) => t.name),
    newlyAllowed: next.tools.filter((t) => t.allowed && oldByName.get(t.name)?.allowed !== true).map((t) => t.name),
  };
  if (Array.isArray(old.renewals)) next.renewals = old.renewals;
  if (!dryRun) atomicWriteJson(w.manifest, next, { expected: original });
  return { name: w.name, ok: true, action: dryRun ? "would-reapprove" : "reapproved", expiresAt: next.expiresAt, reapproval: next.reapproval };
}
