// Change vector: a structured, multi-axis classification of what changed.
//
// v1's diff.js produces a single ordered level (NONE < SYNTACTIC < ... <
// BREAKING) over the *interface* only. That ordering is correct and is kept —
// but it cannot represent the two changes the substrate analysis flagged:
//
//   * implementation replacement  — I_id unchanged, M_id changed (compromised
//     or redeployed code behind a stable contract);
//   * provenance change           — publisher key rotated or publisher swapped.
//
// changeVector() classifies a transition across independent axes. Each axis is
// ordered by consequence; the trust decision is the policy-weighted maximum.
// isVectorCompatible() is the simple boolean that preserves v1's
// "can this be auto-accepted?" contract without forcing callers to understand
// the full taxonomy.
//
// This module is additive: it consumes diff.js output and descriptor identity,
// and does not modify the existing interface classification.
import { diffToolsets, CHANGE_LEVEL } from "./diff.js";
import { implementationsEqual } from "./descriptor.js";

// Ordered severity per axis. Higher = less acceptable.
export const AXIS_LEVEL = {
  interface: { NONE: 0, SYNTACTIC: 1, NON_BREAKING: 2, ANNOTATION_DOWNGRADE: 3, BREAKING: 4 },
  permission: { NONE: 0, REDUCTION: 1, EXPANSION: 2 },
  implementation: { NONE: 0, UNRESOLVED: 1, REPLACED: 2 },
  provenance: { NONE: 0, KEY_ROTATION: 1, PUBLISHER_CHANGE: 2 },
};

// Compare permission-relevant annotations directly to classify direction.
// An increase in what a tool *might* do is an EXPANSION; a decrease, REDUCTION.
// v1 folds all of this into a single PERMISSION_CHANGE level; splitting
// direction is the one change that produces a different trust consequence.
const PERMISSION_KEYS = ["readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"];
function permissionAxisLevel(oldTools, newTools) {
  let level = "NONE";
  const oldByName = new Map((oldTools ?? []).map((t) => [t.name, t]));
  for (const newT of newTools ?? []) {
    const oldT = oldByName.get(newT.name);
    if (!oldT) continue;
    const oa = oldT.annotations ?? {};
    const na = newT.annotations ?? {};
    const executionChanged = JSON.stringify(oldT.execution ?? null) !== JSON.stringify(newT.execution ?? null);
    // Losing a safety hint, or gaining a danger hint, widens the blast radius.
    const widens =
      (oa.readOnlyHint === true && na.readOnlyHint !== true) ||
      (oa.destructiveHint !== true && na.destructiveHint === true) ||
      (oa.idempotentHint === true && na.idempotentHint !== true) ||
      (oa.openWorldHint === false && na.openWorldHint !== false) ||
      executionChanged;
    // Gaining a safety hint, or dropping a danger hint, narrows it.
    const narrows =
      (oa.readOnlyHint !== true && na.readOnlyHint === true) ||
      (oa.destructiveHint === true && na.destructiveHint !== true);
    if (widens) {
      level = "EXPANSION";
    } else if ((narrows || PERMISSION_KEYS.some((k) => (oa[k] !== undefined) !== (na[k] !== undefined))) && level === "NONE") {
      level = "REDUCTION";
    }
  }
  return level;
}

// Compute the structured change vector between a prior and current state.
//   prior / current: { tools, implementation, publisherKeyId }
// `implementation` is a descriptor implementation identity (or null).
// `publisherKeyId` distinguishes provenance movement from interface movement.
export function changeVector(prior, current) {
  const interfaceDiff = diffToolsets(prior?.tools ?? [], current?.tools ?? []);

  // permission axis: direction-aware split of v1's PERMISSION_CHANGE.
  const permissionLevel = permissionAxisLevel(prior?.tools, current?.tools);

  // interface axis: v1's level, but with pure permission-annotation moves
  // excluded — those are governed by the permission axis (which knows
  // direction), not double-counted here. If the ONLY change is a permission
  // annotation, the interface itself (schema/structure/semantics) did not move.
  let interfaceLevel = interfaceDiff.overall;
  if (interfaceLevel === "PERMISSION_CHANGE") {
    const nonPermissionChange = interfaceDiff.toolDiffs?.some((d) =>
      d.level !== "NONE" &&
      (d.findings ?? []).some((f) => f.kind !== "annotation-permission" && f.kind !== "execution-changed")
    );
    if (!nonPermissionChange) interfaceLevel = "NONE";
  }

  // implementation axis: the case v1 cannot represent.
  let implementationLevel = "NONE";
  const oi = prior?.implementation ?? null;
  const ni = current?.implementation ?? null;
  const oUnresolved = !oi || oi.kind === "unresolved";
  const nUnresolved = !ni || ni.kind === "unresolved";
  if (oUnresolved && nUnresolved) {
    implementationLevel = "NONE"; // nothing to compare; no claim either way.
  } else if (oUnresolved !== nUnresolved) {
    implementationLevel = "UNRESOLVED"; // one side lost/gained artifact identity.
  } else if (!implementationsEqual(oi, ni)) {
    implementationLevel = "REPLACED"; // same interface, different code.
  }

  // provenance axis.
  let provenanceLevel = "NONE";
  const ok = prior?.publisherKeyId ?? null;
  const nk = current?.publisherKeyId ?? null;
  if (ok && nk && ok !== nk) provenanceLevel = "KEY_ROTATION";
  else if (ok && !nk) provenanceLevel = "PUBLISHER_CHANGE";
  else if (!ok && nk) provenanceLevel = "NONE"; // gaining provenance is not a break.

  const vector = {
    interface: interfaceLevel,
    permission: permissionLevel,
    implementation: implementationLevel,
    provenance: provenanceLevel,
  };
  return {
    vector,
    interfaceDiff, // full v1 detail for callers that want findings/summary
    compatible: isVectorCompatible(vector),
    summary: summarizeVector(vector),
  };
}

// The simple compatibility decision, preserved from v1's isCompatible().
// A change is auto-acceptable only if EVERY axis stays within its safe band.
export function isVectorCompatible(vector) {
  const ifaceOk = CHANGE_LEVEL[vector.interface] <= CHANGE_LEVEL.NON_BREAKING;
  const permOk = vector.permission === "NONE" || vector.permission === "REDUCTION";
  const implOk = vector.implementation === "NONE"; // any implementation movement blocks auto-accept
  const provOk = vector.provenance === "NONE";      // key rotation requires re-approval
  return ifaceOk && permOk && implOk && provOk;
}

function summarizeVector(vector) {
  const parts = [];
  if (vector.interface !== "NONE") parts.push(`interface:${vector.interface}`);
  if (vector.permission !== "NONE") parts.push(`permission:${vector.permission}`);
  if (vector.implementation !== "NONE") parts.push(`implementation:${vector.implementation}`);
  if (vector.provenance !== "NONE") parts.push(`provenance:${vector.provenance}`);
  return parts.length === 0 ? "no change" : parts.join(", ");
}
