// Manifest generation and validation for call-time enforcement.
// A manifest captures the approved tool set at scan time:
//   - tool name
//   - schema hash (SHA-256 of canonical JSON of inputSchema)
//   - description hash (for drift detection)
//   - danger analysis (from the AI fusion engine)
//   - allowed flag (dangerous tools are blocked by default)
//
// At call time, the proxy compares live tools/list against the manifest
// and blocks tools/call for tools not in the manifest, with drifted schemas,
// or marked as dangerous (allowed=false).
import { createHash } from "node:crypto";
import { analyzeTool } from "./danger-detector.js";

// Canonical JSON: sorted keys, no whitespace — stable hash input.
function canonicalJson(obj) {
  if (obj === null || obj === undefined) return "null";
  if (typeof obj !== "object") return JSON.stringify(obj);
  if (Array.isArray(obj)) return `[${obj.map(canonicalJson).join(",")}]`;
  const keys = Object.keys(obj).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`).join(",")}}`;
}

function hash(obj) {
  return createHash("sha256").update(canonicalJson(obj)).digest("hex").slice(0, 16);
}

// Default manifest expiry: 90 days. Forces re-generation (and re-analysis
// by the danger detector) periodically. Override with expiresInDays.
const DEFAULT_EXPIRY_DAYS = 90;

function isoDaysFromNow(days) {
  const d = new Date();
  d.setDate(d.getDate() + days);
  return d.toISOString();
}

// Build a manifest from a tools/list response.
// Dangerous tools (as identified by the AI fusion engine) are marked
// allowed=false so the proxy blocks calls to them.
//
// allowTools: a Set or array of tool names to explicitly allow even if the
// danger detector flags them. Each override records the reason and sets
// allowed=true. This is for tools that have been reviewed by a human and
// have their own safety constraints (e.g. an allowlisted command executor).
//
// expiresInDays: override the default 90-day expiry. Set to null for no
// expiry (not recommended — a manifest should be re-generated periodically
// so the danger analysis stays fresh).
export function buildManifest(tools, serverInfo = null, spec = null, allowTools = null, expiresInDays = DEFAULT_EXPIRY_DAYS) {
  const allowSet = allowTools instanceof Set ? allowTools
    : Array.isArray(allowTools) ? new Set(allowTools)
    : new Set();
  const entries = tools.map((t) => {
    const analysis = analyzeTool(t);
    const overridden = allowSet.has(t.name);
    return {
      name: t.name,
      schemaHash: hash(t.inputSchema ?? {}),
      descriptionHash: hash(t.description ?? ""),
      dangerous: analysis.isDangerous,
      dangerScore: Math.round(analysis.score * 100) / 100,
      dangerConfidence: analysis.confidence,
      allowed: overridden ? true : !analysis.isDangerous,
      ...(overridden ? { manualOverride: true, overrideReason: "explicitly allowed via --allow-tool" } : {}),
    };
  });
  const manifestHash = hash(entries.map((e) => `${e.name}:${e.schemaHash}:${e.allowed}`));
  const dangerousCount = entries.filter((e) => e.dangerous && !e.manualOverride).length;
  const overriddenCount = entries.filter((e) => e.manualOverride).length;
  const now = new Date().toISOString();
  return {
    version: 1,
    spec,
    serverInfo,
    manifestHash,
    createdAt: now,
    expiresAt: expiresInDays != null ? isoDaysFromNow(expiresInDays) : null,
    summary: {
      totalTools: entries.length,
      allowedTools: entries.length - dangerousCount,
      dangerousTools: dangerousCount,
      overriddenTools: overriddenCount,
    },
    tools: entries,
  };
}

// Compare a live tools/list against a manifest.
// Returns { added, removed, drifted, ok }
export function diffManifest(manifest, liveTools) {
  const manifestByName = new Map(manifest.tools.map((t) => [t.name, t]));
  const liveByName = new Map(liveTools.map((t) => [t.name, t]));

  const added = [];
  const removed = [];
  const drifted = [];

  for (const [name, live] of liveByName) {
    const approved = manifestByName.get(name);
    if (!approved) {
      added.push(name);
    } else {
      const liveSchemaHash = hash(live.inputSchema ?? {});
      if (liveSchemaHash !== approved.schemaHash) {
        drifted.push({ name, approved: approved.schemaHash, live: liveSchemaHash });
      }
    }
  }
  for (const name of manifestByName.keys()) {
    if (!liveByName.has(name)) removed.push(name);
  }

  return {
    added,
    removed,
    drifted,
    ok: added.length === 0 && removed.length === 0 && drifted.length === 0,
  };
}

// Check if a specific tool call is allowed by the manifest.
// Returns { allowed, reason }
export function checkCall(manifest, toolName, args = {}) {
  // Manifest freshness: an expired manifest blocks all calls.
  if (manifest.expiresAt && Date.parse(manifest.expiresAt) < Date.now()) {
    return {
      allowed: false,
      reason: `manifest expired at ${manifest.expiresAt} — regenerate with: mcp-trustcard gen-manifest --save-manifest <file> -- <server-cmd>`,
    };
  }
  const entry = manifest.tools.find((t) => t.name === toolName);
  if (!entry) {
    return { allowed: false, reason: `tool "${toolName}" not in approved manifest` };
  }
  if (entry.allowed === false) {
    return {
      allowed: false,
      reason: `tool "${toolName}" blocked by manifest (dangerous: score=${entry.dangerScore}, confidence=${entry.dangerConfidence})`,
    };
  }
  return { allowed: true, reason: null };
}

export { hash, canonicalJson };
