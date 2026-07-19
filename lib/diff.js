// Diff: given a pinned toolset and an observed toolset, classify every change
// as SYNTACTIC (cosmetic only) or SEMANTIC, and every semantic change as
// BREAKING, PERMISSION_CHANGE, ANNOTATION_DOWNGRADE, or NON_BREAKING.
//
// The classification contract (what "breaking" means for a tool contract):
//   - a tool disappearing                                        → BREAKING
//   - a new *required* input parameter                            → BREAKING
//   - an input parameter's type/domain narrowing                  → BREAKING
//     (type removed from union, enum/const shrink, new constraints,
//      min/max tightened, pattern/format added, additionalProperties closed)
//   - output schema narrowing that can invalidate prior consumers → BREAKING
//   - readOnly/destructive/openWorld/execution drift              → PERMISSION_CHANGE
//   - description materially rewritten with schema unchanged      → ANNOTATION_DOWNGRADE
//     (classic tool-poisoning surface: same signature, new instructions)
//   - new *optional* input, widened domain, added tool            → NON_BREAKING
import { toolProjection, toolDigest, volatileFields } from "./identity.js";
import { jsonEqual } from "./canon.js";

export const CHANGE_LEVEL = {
  NONE: 0,
  SYNTACTIC: 1,
  NON_BREAKING: 2,
  ANNOTATION_DOWNGRADE: 3,
  PERMISSION_CHANGE: 4,
  BREAKING: 5,
};

const LEVEL_NAME = Object.fromEntries(Object.entries(CHANGE_LEVEL).map(([k, v]) => [v, k]));

function maxLevel(a, b) {
  return CHANGE_LEVEL[a] >= CHANGE_LEVEL[b] ? a : b;
}

// --- JSON Schema domain comparison -----------------------------------------
// We don't attempt full logical subsumption (undecidable in general); we use a
// conservative syntactic rule set. When in doubt, we report SUSPECT_DOMAIN
// (treated as NON_BREAKING-but-noteworthy) rather than claiming safety.

const CONSTRAINT_KEYS = [
  "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum",
  "minLength", "maxLength", "minItems", "maxItems",
  "minProperties", "maxProperties", "pattern", "format",
  "multipleOf", "uniqueItems", "contains", "propertyNames",
];

function asTypeSet(schema) {
  if (!schema || typeof schema !== "object") return null;
  if (schema.type === undefined) return null;
  return new Set(Array.isArray(schema.type) ? schema.type : [schema.type]);
}

function classifyConstraintTightening(key, oldV, newV) {
  // Returns true when going oldV -> newV *narrows* the accepted domain.
  switch (key) {
    case "minimum": case "minLength": case "minItems": case "minProperties":
      return newV > oldV;
    case "maximum": case "maxLength": case "maxItems": case "maxProperties":
      return newV < oldV;
    case "exclusiveMinimum": return newV > oldV || (oldV === false && newV !== false);
    case "exclusiveMaximum": return newV < oldV || (oldV === false && newV !== false);
    case "uniqueItems": return oldV === false && newV === true;
    default:
      return true; // pattern/format/multipleOf/contains/propertyNames changed → assume narrowing
  }
}

function diffEnum(oldE, newE) {
  const oldSet = new Set((oldE ?? []).map((x) => JSON.stringify(x)));
  const newSet = new Set((newE ?? []).map((x) => JSON.stringify(x)));
  const removed = [...oldSet].filter((x) => !newSet.has(x));
  const added = [...newSet].filter((x) => !oldSet.has(x));
  return { removed: removed.map(JSON.parse), added: added.map(JSON.parse) };
}

// Compare two schemas that describe the *same* input slot.
// Returns { level, findings[] }.
function diffSchema(oldS, newS, path) {
  const findings = [];
  let level = "NONE";

  const note = (lvl, kind, detail) => {
    level = maxLevel(level, lvl);
    findings.push({ level: lvl, kind, path, detail });
  };

  if (jsonEqual(oldS, newS)) return { level, findings };
  if (!oldS || !newS || typeof oldS !== "object" || typeof newS !== "object") {
    note("SUSPECT_DOMAIN", "schema-replaced", "schema replaced wholesale");
    return { level, findings };
  }

  // type unions
  const oldT = asTypeSet(oldS);
  const newT = asTypeSet(newS);
  if (oldT && newT) {
    for (const t of oldT) if (!newT.has(t)) note("BREAKING", "type-removed", `type "${t}" removed from union`);
    for (const t of newT) if (!oldT.has(t)) note("NON_BREAKING", "type-added", `type "${t}" added to union`);
  } else if (oldT && !newT) {
    note("NON_BREAKING", "type-relaxed", "type constraint removed entirely");
  } else if (!oldT && newT) {
    note("BREAKING", "type-constrained", `type constraint added: ${[...newT].join("|")}`);
  }

  // const / enum
  if (oldS.const !== undefined || newS.const !== undefined) {
    if (!jsonEqual(oldS.const, newS.const)) {
      note("BREAKING", "const-changed", `const ${JSON.stringify(oldS.const)} → ${JSON.stringify(newS.const)}`);
    }
  }
  if (oldS.enum || newS.enum) {
    const { removed, added } = diffEnum(oldS.enum, newS.enum);
    if (removed.length) note("BREAKING", "enum-shrunk", `enum values removed: ${removed.map((v) => JSON.stringify(v)).join(", ")}`);
    if (added.length) note("NON_BREAKING", "enum-grown", `enum values added: ${added.map((v) => JSON.stringify(v)).join(", ")}`);
  }

  // scalar constraints
  for (const key of CONSTRAINT_KEYS) {
    const had = oldS[key] !== undefined;
    const has = newS[key] !== undefined;
    if (had && has && !jsonEqual(oldS[key], newS[key])) {
      const narrowed = classifyConstraintTightening(key, oldS[key], newS[key]);
      note(narrowed ? "BREAKING" : "NON_BREAKING", narrowed ? "constraint-tightened" : "constraint-relaxed",
        `${key}: ${JSON.stringify(oldS[key])} → ${JSON.stringify(newS[key])}`);
    } else if (!had && has) {
      note("BREAKING", "constraint-added", `${key} := ${JSON.stringify(newS[key])} (new restriction)`);
    } else if (had && !has) {
      note("NON_BREAKING", "constraint-removed", `${key} removed`);
    }
  }

  // required set (object schemas)
  const oldReq = new Set(oldS.required ?? []);
  const newReq = new Set(newS.required ?? []);
  for (const r of newReq) if (!oldReq.has(r)) note("BREAKING", "required-added", `"${r}" is now required`);
  for (const r of oldReq) if (!newReq.has(r)) note("NON_BREAKING", "required-removed", `"${r}" no longer required`);

  // properties
  const oldProps = oldS.properties ?? {};
  const newProps = newS.properties ?? {};
  for (const p of Object.keys(oldProps)) {
    if (!(p in newProps)) {
      note(oldReq.has(p) ? "BREAKING" : "NON_BREAKING", "property-removed",
        `property "${p}" removed${oldReq.has(p) ? " (was required)" : ""}`);
    } else {
      const sub = diffSchema(oldProps[p], newProps[p], `${path}.${p}`);
      for (const f of sub.findings) findings.push(f);
      level = maxLevel(level, sub.level);
    }
  }
  for (const p of Object.keys(newProps)) {
    if (!(p in oldProps)) {
      note(newReq.has(p) ? "BREAKING" : "NON_BREAKING", "property-added",
        `property "${p}" added${newReq.has(p) ? " (required — breaks existing callers)" : " (optional)"}`);
    }
  }

  // additionalProperties closing
  const oldAP = oldS.additionalProperties;
  const newAP = newS.additionalProperties;
  if ((oldAP === undefined || oldAP === true) && newAP === false) {
    note("BREAKING", "additional-properties-closed", "additionalProperties: true/∅ → false");
  } else if (oldAP === false && (newAP === undefined || newAP === true)) {
    note("NON_BREAKING", "additional-properties-opened", "additionalProperties: false → true/∅");
  }

  // composition keywords newly introduced (oneOf/anyOf/allOf/not/if)
  for (const comp of ["oneOf", "anyOf", "allOf", "not", "if"]) {
    if (oldS[comp] === undefined && newS[comp] !== undefined) {
      note("BREAKING", "composition-added", `"${comp}" introduced — restricts accepted inputs`);
    } else if (oldS[comp] !== undefined && !jsonEqual(oldS[comp], newS[comp])) {
      note("SUSPECT_DOMAIN", "composition-changed", `"${comp}" changed — manual review required`);
    }
  }

  return { level, findings };
}

// --- description materiality ------------------------------------------------
// A description rewrite is the primary tool-poisoning vector: the schema stays
// identical (so every naive check passes) while the instructions to the model
// change. We flag it when the token sets diverge materially.
function descriptionMateriality(oldD = "", newD = "") {
  const tok = (s) => new Set(String(s).toLowerCase().split(/[^a-z0-9]+/).filter((t) => t.length > 2));
  const a = tok(oldD);
  const b = tok(newD);
  if (a.size === 0 && b.size === 0) return { material: false, jaccard: 1 };
  const inter = [...a].filter((t) => b.has(t)).length;
  const union = new Set([...a, ...b]).size;
  const jaccard = union === 0 ? 1 : inter / union;
  return { material: jaccard < 0.6, jaccard };
}

const PERMISSION_ANNOTATIONS = ["readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"];

// --- tool-level diff ---------------------------------------------------------
function diffTool(oldT, newT) {
  const findings = [];
  let level = "NONE";

  // Syntactic-only: projections identical, volatile surface differs.
  if (jsonEqual(toolProjection(oldT), toolProjection(newT))) {
    const changedVolatile = [...new Set([...volatileFields(oldT), ...volatileFields(newT)])]
      .filter((k) => !jsonEqual(oldT[k], newT[k]));
    if (changedVolatile.length > 0) {
      return {
        tool: newT.name ?? oldT.name,
        level: "SYNTACTIC",
        findings: [{ level: "SYNTACTIC", kind: "volatile-fields", detail: `cosmetic fields changed: ${changedVolatile.join(", ")}` }],
      };
    }
    return { tool: newT.name ?? oldT.name, level: "NONE", findings: [] };
  }

  const note = (lvl, kind, detail) => {
    level = maxLevel(level, lvl);
    findings.push({ level: lvl, kind, detail });
  };

  // inputSchema
  if (!jsonEqual(oldT.inputSchema, newT.inputSchema)) {
    const s = diffSchema(oldT.inputSchema ?? {}, newT.inputSchema ?? {}, "inputSchema");
    for (const f of s.findings) findings.push(f);
    level = maxLevel(level, s.level);
  }

  // outputSchema — narrowing breaks consumers that validate structured content
  if (!jsonEqual(oldT.outputSchema, newT.outputSchema)) {
    if (oldT.outputSchema && !newT.outputSchema) {
      note("PERMISSION_CHANGE", "output-schema-removed", "outputSchema removed — structured output no longer guaranteed");
    } else if (!oldT.outputSchema && newT.outputSchema) {
      note("NON_BREAKING", "output-schema-added", "outputSchema added");
    } else {
      const s = diffSchema(oldT.outputSchema, newT.outputSchema, "outputSchema");
      for (const f of s.findings) findings.push({ ...f, kind: `output:${f.kind}` });
      level = maxLevel(level, s.level === "BREAKING" ? "BREAKING" : s.level);
    }
  }

  // permission-relevant annotations
  const oldA = oldT.annotations ?? {};
  const newA = newT.annotations ?? {};
  for (const k of PERMISSION_ANNOTATIONS) {
    if (!jsonEqual(oldA[k], newA[k])) {
      note("PERMISSION_CHANGE", "annotation-permission", `annotations.${k}: ${JSON.stringify(oldA[k])} → ${JSON.stringify(newA[k])}`);
    }
  }

  // execution semantics (e.g. taskSupport)
  if (!jsonEqual(oldT.execution, newT.execution)) {
    note("PERMISSION_CHANGE", "execution-changed", `execution: ${JSON.stringify(oldT.execution)} → ${JSON.stringify(newT.execution)}`);
  }

  // description poisoning surface
  if (oldT.description !== newT.description) {
    const m = descriptionMateriality(oldT.description, newT.description);
    const schemaUnchanged = jsonEqual(oldT.inputSchema, newT.inputSchema) && jsonEqual(oldT.outputSchema, newT.outputSchema);
    if (m.material && schemaUnchanged) {
      note("ANNOTATION_DOWNGRADE", "description-rewrite",
        `description materially rewritten (jaccard=${m.jaccard.toFixed(2)}) with unchanged schema — possible tool poisoning`);
    } else if (m.material) {
      note("NON_BREAKING", "description-changed", `description materially rewritten (jaccard=${m.jaccard.toFixed(2)})`);
    } else {
      note("NONE", "description-touched", "description edited (immaterial)");
    }
  }

  return { tool: newT.name ?? oldT.name, level, findings };
}

// --- toolset-level diff ------------------------------------------------------
export function diffToolsets(oldTools, newTools) {
  const oldByName = new Map((oldTools ?? []).map((t) => [t.name, t]));
  const newByName = new Map((newTools ?? []).map((t) => [t.name, t]));

  const toolDiffs = [];
  const added = [];
  const removed = [];
  let overall = "NONE";

  for (const [name, newT] of newByName) {
    if (!oldByName.has(name)) {
      added.push(name);
      overall = maxLevel(overall, "NON_BREAKING");
      toolDiffs.push({ tool: name, level: "NON_BREAKING", kind: "added", findings: [{ level: "NON_BREAKING", kind: "tool-added", detail: `new tool "${name}"` }] });
    }
  }
  for (const [name] of oldByName) {
    if (!newByName.has(name)) {
      removed.push(name);
      overall = maxLevel(overall, "BREAKING");
      toolDiffs.push({ tool: name, level: "BREAKING", kind: "removed", findings: [{ level: "BREAKING", kind: "tool-removed", detail: `tool "${name}" removed — any cached plan referencing it now fails` }] });
    }
  }
  for (const [name, oldT] of oldByName) {
    const newT = newByName.get(name);
    if (!newT) continue;
    const d = diffTool(oldT, newT);
    if (d.level !== "NONE") {
      toolDiffs.push(d);
      overall = maxLevel(overall, d.level);
    }
  }

  const syntacticOnly = overall === "SYNTACTIC" || overall === "NONE";
  return {
    overall,
    overallName: LEVEL_NAME[CHANGE_LEVEL[overall]],
    syntacticOnly,
    added,
    removed,
    changed: toolDiffs.filter((d) => d.kind !== "added" && d.kind !== "removed" && d.level !== "NONE"),
    toolDiffs,
    summary: summarize({ overall, added, removed, changed: toolDiffs }),
  };
}

function summarize({ overall, added, removed, changed }) {
  if (overall === "NONE") return "tool definitions identical (digest match)";
  if (overall === "SYNTACTIC") return "cosmetic changes only (title/icons/meta) — semantic digests unchanged";
  const parts = [];
  if (removed.length) parts.push(`${removed.length} removed`);
  if (added.length) parts.push(`${added.length} added`);
  const breaking = changed.filter((c) => c.level === "BREAKING").length;
  const perm = changed.filter((c) => c.level === "PERMISSION_CHANGE").length;
  const poison = changed.filter((c) => c.level === "ANNOTATION_DOWNGRADE").length;
  if (breaking) parts.push(`${breaking} breaking`);
  if (perm) parts.push(`${perm} permission change(s)`);
  if (poison) parts.push(`${poison} possible poisoning`);
  return `${LEVEL_NAME[CHANGE_LEVEL[overall]]}: ${parts.join(", ") || "modified"}`;
}

// Is a transition from pinned → observed admissible without re-approval?
export function isCompatible(diff) {
  return CHANGE_LEVEL[diff.overall] <= CHANGE_LEVEL.NON_BREAKING;
}
