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
import { scopeSatisfies } from "./auth.js";
import { toolDigest } from "./identity.js";

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
  return new Date(Date.now() + days * 86_400_000).toISOString();
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
export function buildManifest(tools, serverInfo = null, spec = null, allowTools = null, expiresInDays = DEFAULT_EXPIRY_DAYS, scopeOverrides = null) {
  const allowSet = allowTools instanceof Set ? allowTools
    : Array.isArray(allowTools) ? new Set(allowTools)
    : new Set();
  const scopeOverrideMap = scopeOverrides instanceof Map ? scopeOverrides
    : scopeOverrides && typeof scopeOverrides === "object" ? new Map(Object.entries(scopeOverrides))
    : new Map();
  const entries = tools.map((t) => {
    const analysis = analyzeTool(t);
    const overridden = allowSet.has(t.name);
    // Extract requiredScopes from the tool definition.
    // Sources (in priority order):
    //   1. scopeOverrides map (explicit --require-scopes CLI flag)
    //   2. tool.annotations._meta.requiredScopes (server-declared)
    //   3. tool._meta.requiredScopes (alternate location)
    //   4. none (tool is unscoped — any valid token can call it)
    const requiredScopes = scopeOverrideMap.get(t.name)
      ?? t.annotations?._meta?.requiredScopes
      ?? t._meta?.requiredScopes
      ?? [];
    const scopeList = Array.isArray(requiredScopes) ? requiredScopes
      : typeof requiredScopes === "string" ? [requiredScopes]
      : [];
    return {
      name: t.name,
      schemaHash: hash(t.inputSchema ?? {}),
      descriptionHash: hash(t.description ?? ""),
      contractDigest: toolDigest(t),
      declaredScopesHash: hash(t.annotations?._meta?.requiredScopes ?? t._meta?.requiredScopes ?? []),
      dangerous: analysis.isDangerous,
      dangerScore: Math.round(analysis.score * 100) / 100,
      dangerConfidence: analysis.confidence,
      allowed: overridden ? true : !analysis.isDangerous,
      ...(scopeList.length > 0 ? { requiredScopes: scopeList } : {}),
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
      if (liveSchemaHash !== approved.schemaHash ||
          hash(live.description ?? "") !== approved.descriptionHash ||
          (approved.contractDigest && toolDigest(live) !== approved.contractDigest) ||
          (approved.declaredScopesHash && hash(live.annotations?._meta?.requiredScopes ?? live._meta?.requiredScopes ?? []) !== approved.declaredScopesHash)) {
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

export function assertProxyManifest(manifest) {
  if (manifest?.version !== 1 || !Array.isArray(manifest.tools)) throw new Error("unsupported proxy manifest schema");
  if (manifest.signature || manifest.manifestDigest) throw new Error("signature-bearing manifests need the provenance verifier, not the proxy fleet API");
  if (manifest.expiresAt != null && !Number.isFinite(Date.parse(manifest.expiresAt))) throw new Error("invalid manifest expiry");
  const names = new Set();
  for (const t of manifest.tools) {
    if (!t || typeof t.name !== "string" || !t.name || names.has(t.name) || typeof t.allowed !== "boolean" ||
        !/^[a-f0-9]{16}$/.test(t.schemaHash) || !/^[a-f0-9]{16}$/.test(t.descriptionHash) ||
        (t.requiredScopes != null && (!Array.isArray(t.requiredScopes) || t.requiredScopes.some((s) => typeof s !== "string" || !s)))) {
      throw new Error("invalid proxy manifest tool entry");
    }
    names.add(t.name);
  }
}

// Used by both explicit fleet reapproval and legacy auto-update mode. A fresh
// detector result cannot erase the operator's existing restrictions.
export function preserveProxyPolicy(old, next) {
  assertProxyManifest(old);
  const previous = new Map(old.tools.map((t) => [t.name, t]));
  for (const t of next.tools) {
    const p = previous.get(t.name);
    if (!p) continue;
    const unchanged = p.schemaHash === t.schemaHash && p.descriptionHash === t.descriptionHash &&
      (!p.contractDigest || p.contractDigest === t.contractDigest) &&
      (!p.declaredScopesHash || p.declaredScopesHash === t.declaredScopesHash);
    if (p.manualOverride && unchanged) {
      t.manualOverride = true; t.overrideReason = p.overrideReason;
      t.allowed = p.allowed;
    }
    if (p.allowed === false) t.allowed = false;
    const scopes = [...new Set([...(p.requiredScopes ?? []), ...(t.requiredScopes ?? [])])];
    if (scopes.length) t.requiredScopes = scopes;
  }
  next.summary.allowedTools = next.tools.filter((t) => t.allowed).length;
  next.summary.overriddenTools = next.tools.filter((t) => t.manualOverride).length;
  next.summary.dangerousTools = next.tools.filter((t) => t.dangerous && !t.manualOverride).length;
  next.manifestHash = hash(next.tools.map((t) => `${t.name}:${t.schemaHash}:${t.allowed}`));
  return next;
}

// Re-attest a manifest against a live tools/list and extend its expiry.
//
// Renewal is deliberately conservative: it only succeeds when the live toolset
// is byte-for-byte the same contract the human approved — same tool names,
// same schema hashes AND same description hashes (a changed description is the
// classic tool-poisoning vector, so it must force a fresh review). Allow/deny
// decisions and manual overrides are carried forward verbatim; renewal never
// re-runs the danger detector in a way that could silently flip a decision.
//
// Returns { renewed: true, manifest, diff } or { renewed: false, diff, reason }.
export function renewManifest(manifest, liveTools, expiresInDays = DEFAULT_EXPIRY_DAYS, now = new Date()) {
  if (!Number.isFinite(expiresInDays) || expiresInDays <= 0) throw new Error("expiry must be a positive finite number of days");
  // A publisher signature cannot survive edits without the signing key.
  if (manifest.signature || manifest.manifestDigest) return { renewed: false, reason: "signed manifests require explicit re-signing; renewal refused", diff: null };
  if (manifest.tools.some((t) => !t.contractDigest)) return { renewed: false, reason: "legacy manifest lacks full contract digests; explicit reapproval required", diff: diffManifest(manifest, liveTools) };
  assertProxyManifest(manifest);
  const diff = diffManifest(manifest, liveTools);
  const byName = new Map(manifest.tools.map((t) => [t.name, t]));
  const descriptionDrift = [];
  for (const live of liveTools) {
    const approved = byName.get(live.name);
    if (!approved) continue;
    const liveDesc = hash(live.description ?? "");
    if (approved.descriptionHash && liveDesc !== approved.descriptionHash) {
      descriptionDrift.push({ name: live.name, approved: approved.descriptionHash, live: liveDesc });
    }
  }
  const fullDiff = { ...diff, descriptionDrift, ok: diff.ok && descriptionDrift.length === 0 };
  if (!fullDiff.ok) {
    const parts = [];
    if (diff.added.length) parts.push(`added: ${diff.added.join(", ")}`);
    if (diff.removed.length) parts.push(`removed: ${diff.removed.join(", ")}`);
    if (diff.drifted.length) parts.push(`schema changed: ${diff.drifted.map((d) => d.name).join(", ")}`);
    if (descriptionDrift.length) parts.push(`description changed: ${descriptionDrift.map((d) => d.name).join(", ")}`);
    return { renewed: false, diff: fullDiff, reason: `live toolset differs from approved manifest (${parts.join("; ")})` };
  }
  const nowIso = now.toISOString();
  let expiresAt = null;
  if (expiresInDays != null) {
    expiresAt = new Date(now.getTime() + expiresInDays * 86_400_000).toISOString();
  }
  const renewals = Array.isArray(manifest.renewals) ? manifest.renewals : [];
  return {
    renewed: true,
    diff: fullDiff,
    manifest: {
      ...manifest,
      expiresAt,
      renewedAt: nowIso,
      renewals: [...renewals, { at: nowIso, previousExpiresAt: manifest.expiresAt ?? null, manifestHash: manifest.manifestHash }].slice(-20),
    },
  };
}

// Check if a specific tool call is allowed by the manifest.
// Returns { allowed, reason }
export function checkCall(manifest, toolName, args = {}, authToken = null) {
  if (!Array.isArray(manifest?.tools)) return { allowed: false, reason: "invalid manifest tools" };
  // Manifest freshness: an expired manifest blocks all calls.
  if (manifest.expiresAt && (!Number.isFinite(Date.parse(manifest.expiresAt)) || Date.parse(manifest.expiresAt) <= Date.now())) {
    return {
      allowed: false,
      reason: `manifest expired at ${manifest.expiresAt} — regenerate with: mcp-trustcard gen-manifest --save-manifest <file> -- <server-cmd>`,
    };
  }
  const entry = manifest.tools.find((t) => t.name === toolName);
  if (!entry) {
    return { allowed: false, reason: `tool "${toolName}" not in approved manifest` };
  }
  if (entry.allowed !== true) {
    return {
      allowed: false,
      reason: `tool "${toolName}" blocked by manifest (dangerous: score=${entry.dangerScore}, confidence=${entry.dangerConfidence})`,
    };
  }
  // Scope check: if the tool declares requiredScopes, the caller must present
  // a valid token with sufficient scopes. A null authToken means no auth
  // enforcement is configured — unscoped tools still pass, scoped tools don't.
  if (entry.requiredScopes && entry.requiredScopes.length > 0) {
    if (!authToken) {
      return {
        allowed: false,
        reason: `tool "${toolName}" requires scopes [${entry.requiredScopes.join(", ")}] but no auth token was provided`,
      };
    }
    if (!authToken.isValid) {
      return {
        allowed: false,
        reason: `tool "${toolName}" requires scopes [${entry.requiredScopes.join(", ")}] but token is ${authToken.isExpired ? "expired" : "inactive"}`,
      };
    }
    if (!scopeSatisfies(authToken.scopes, entry.requiredScopes)) {
      const missing = entry.requiredScopes.filter((s) => !authToken.scopes.includes(s) && !authToken.scopes.includes("*") && !authToken.scopes.some((g) => g.endsWith(":*") && s.startsWith(g.slice(0, -1))));
      return {
        allowed: false,
        reason: `tool "${toolName}" requires scopes [${entry.requiredScopes.join(", ")}] but token for "${authToken.subject}" has [${authToken.scopes.join(", ")}] (missing: ${missing.join(", ")})`,
      };
    }
  }
  return { allowed: true, reason: null };
}

export { hash, canonicalJson };
