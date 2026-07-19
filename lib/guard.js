// Guard: the enforcement point. Every decision the rest of the system makes
// (identity, diff classification, trust state, provenance) is only as good as
// the thing that *stops the call*. Guard is that thing.
//
// It wraps a TrustSession and applies policy to every tools/call:
//   - server must not be REVOKED / MISMATCH (unless overridden)
//   - tool must exist in the *verified* toolset (deny unknown tools)
//   - destructive tools require explicit policy allowance
//   - strict mode validates call arguments against the pinned inputSchema
//     (catches a server that widened/changed args without telling anyone)
//   - every call can emit a reproducibility receipt
//
// Modes: "enforce" (deny + throw), "audit" (allow + event), "off".
import { hashJson } from "./hash.js";
import { canon } from "./canon.js";
import { SignedReceiptChain } from "./receipts.js";
import { interfaceDigest } from "./descriptor.js";

export class GuardDenial extends Error {
  constructor(reason, detail = {}) {
    super(`trustcard guard denied call: ${reason}`);
    this.name = "GuardDenial";
    this.reason = reason;
    this.detail = detail;
  }
}

// require-approval needs a distinct error so callers can route it to a human
// instead of treating it as a hard denial.
export class GuardApprovalRequired extends Error {
  constructor(reason, detail = {}) {
    super(`trustcard guard: call requires approval: ${reason}`);
    this.name = "GuardApprovalRequired";
    this.reason = reason;
    this.detail = detail;
  }
}

export class Guard {
  constructor({ mode = "enforce", policy = {}, onEvent, receiptSink, invocationPolicy = null, relyingParty = null, environment = null, receiptKey = null, receiptChain = null } = {}) {
    this.mode = mode;
    this.policy = {
      allowDestructive: false,     // destructiveHint tools need explicit opt-in
      allowUnknownTools: false,    // tools not in the verified set are denied
      allowedTools: null,          // null = all verified tools; array = allowlist
      requirePinned: true,         // server must be PINNED (not just OBSERVED)
      maxCallsPerTool: null,       // optional rate ceiling
      ...policy,
    };
    this.onEvent = onEvent ?? (() => {});
    this.receiptSink = receiptSink ?? null;
    this.callCounts = new Map();
    // v2 (additive): Gate 2 invocation authorization + identity for receipts.
    this.invocationPolicy = invocationPolicy ?? null;
    this.relyingParty = relyingParty;
    this.environment = environment;
    this.receiptChain = receiptChain ?? (receiptKey ? new SignedReceiptChain({ privateKey: receiptKey, relyingParty }) : null);
  }

  _decide(allow, reason, detail) {
    const event = { type: allow ? "guard-allow" : "guard-deny", reason, detail, at: new Date().toISOString() };
    this.onEvent(event);
    if (!allow && this.mode === "enforce") throw new GuardDenial(reason, detail);
    return allow;
  }

  _decideApproval(reason, detail) {
    const event = { type: "guard-require-approval", reason, detail, at: new Date().toISOString() };
    this.onEvent(event);
    if (this.mode === "enforce") throw new GuardApprovalRequired(reason, detail);
    return false; // audit/off modes: report, don't throw
  }

  // The per-call authorization gate. `session` is a TrustSession.
  async authorizeCall({ session, tool, args, strict = false }) {
    const state = session.trust?.get(session.serverId)?.state ?? "UNKNOWN";

    if (state === "REVOKED") {
      return this._decide(false, "server-revoked", { server: session.serverId, tool });
    }
    if (state === "MISMATCH") {
      return this._decide(false, "server-mismatch", { server: session.serverId, tool });
    }
    if (this.policy.requirePinned && state !== "PINNED") {
      return this._decide(false, "server-not-pinned", { server: session.serverId, state, tool });
    }

    const observed = session.observation;
    const toolDef = observed?.tools?.find((t) => t.name === tool);
    if (!toolDef) {
      return this._decide(this.policy.allowUnknownTools, "unknown-tool", { tool });
    }
    if (Array.isArray(this.policy.allowedTools) && !this.policy.allowedTools.includes(tool)) {
      return this._decide(false, "tool-not-allowlisted", { tool });
    }

    const destructive = toolDef.annotations?.destructiveHint === true && toolDef.annotations?.readOnlyHint !== true;
    if (destructive && !this.policy.allowDestructive) {
      return this._decide(false, "destructive-tool", { tool });
    }

    if (this.policy.maxCallsPerTool != null) {
      const n = this.callCounts.get(tool) ?? 0;
      if (n >= this.policy.maxCallsPerTool) {
        return this._decide(false, "rate-ceiling", { tool, max: this.policy.maxCallsPerTool });
      }
    }

    if (strict) {
      const problem = validateArgs(toolDef.inputSchema, args);
      if (problem) return this._decide(false, "args-violate-schema", { tool, problem });
    }

    // Gate 2 (v2): per-invocation authorization. Gate 1 (above) established that
    // the capability is still the trusted one; Gate 2 decides whether THIS
    // invocation — these args, this environment, this relying party — is allowed.
    // The tool can be trusted while the specific invocation is not authorized.
    if (this.invocationPolicy) {
      const decision = this.invocationPolicy.authorize({
        relyingParty: this.relyingParty,
        tool,
        args,
        environment: this.environment,
        capabilityDigest: interfaceDigest(toolDef),
        destructive,
      });
      if (decision.verdict === "deny") {
        return this._decide(false, decision.reason, { tool, rule: decision.rule });
      }
      if (decision.verdict === "require-approval") {
        return this._decideApproval(decision.reason, { tool, rule: decision.rule });
      }
    }

    this.callCounts.set(tool, (this.callCounts.get(tool) ?? 0) + 1);
    return this._decide(true, "ok", { tool, state });
  }

  // Reproducibility receipt: binds the exact contract version to the call.
  // v1 fields are preserved byte-for-byte; when the guard has a receiptChain
  // (a signing key), the receipt is additionally signed, chained to the previous
  // receipt, and given a sequence number + nonce — turning a log line into
  // verifiable, replay-resistant evidence.
  recordReceipt({ session, tool, args, result }) {
    const toolDef = session.observation?.tools?.find((t) => t.name === tool);
    const base = {
      schema: "trustcard.dev/receipt@1",
      at: new Date().toISOString(),
      server: session.serverId,
      tool,
      toolDigest: session.observation?.toolDigests?.[tool] ?? null,
      toolsetDigest: session.observation?.toolsetDigest ?? null,
      serverDigest: session.observation?.serverDigest ?? null,
      protocolVersion: session.observation?.protocolVersion ?? null,
      argumentsDigest: hashJson(args ?? {}),
      resultDigest: result !== undefined ? hashJson(result) : null,
      annotations: toolDef?.annotations ?? null,
      // v2 (additive): the observed capability identity at call time, so
      // declared↔observed drift is detectable in hindsight.
      capabilityDigest: toolDef ? interfaceDigest(toolDef) : null,
      relyingParty: this.relyingParty ?? null,
      environment: this.environment ?? null,
    };
    const receipt = this.receiptChain ? this.receiptChain.append(base) : base;
    this.onEvent({ type: "receipt", receipt });
    this.receiptSink?.(receipt);
    return receipt;
  }
}

// Minimal inputSchema validation for strict mode — covers the common JSON
// Schema surface used by MCP tools (type, required, properties, enum, const,
// additionalProperties:false). Not a full validator; deliberately conservative.
export function validateArgs(schema, args, path = "args") {
  if (!schema || typeof schema !== "object") return null;
  if (schema.type === "object" || schema.properties) {
    if (typeof args !== "object" || args === null || Array.isArray(args)) return `${path}: expected object`;
    for (const r of schema.required ?? []) {
      if (!(r in args)) return `${path}: missing required "${r}"`;
    }
    if (schema.additionalProperties === false) {
      for (const k of Object.keys(args)) {
        if (!(schema.properties && k in schema.properties)) return `${path}: unexpected property "${k}"`;
      }
    }
    for (const [k, sub] of Object.entries(schema.properties ?? {})) {
      if (k in args) {
        const p = validateArgs(sub, args[k], `${path}.${k}`);
        if (p) return p;
      }
    }
    return null;
  }
  if (schema.const !== undefined && canon(args) !== canon(schema.const)) return `${path}: must equal ${JSON.stringify(schema.const)}`;
  if (schema.enum && !schema.enum.some((e) => canon(e) === canon(args))) return `${path}: not in enum`;
  if (schema.type) {
    const types = Array.isArray(schema.type) ? schema.type : [schema.type];
    const ok = types.some((t) => {
      switch (t) {
        case "string": return typeof args === "string";
        case "number": return typeof args === "number";
        case "integer": return typeof args === "number" && Number.isInteger(args);
        case "boolean": return typeof args === "boolean";
        case "null": return args === null;
        case "array": return Array.isArray(args);
        case "object": return typeof args === "object" && args !== null && !Array.isArray(args);
        default: return true;
      }
    });
    if (!ok) return `${path}: expected ${types.join("|")}`;
  }
  if (schema.type === "array" && schema.items && Array.isArray(args)) {
    for (let i = 0; i < args.length; i++) {
      const p = validateArgs(schema.items, args[i], `${path}[${i}]`);
      if (p) return p;
    }
  }
  if (typeof args === "string") {
    if (schema.minLength != null && args.length < schema.minLength) return `${path}: shorter than minLength`;
    if (schema.maxLength != null && args.length > schema.maxLength) return `${path}: longer than maxLength`;
    if (schema.pattern && !(new RegExp(schema.pattern).test(args))) return `${path}: pattern mismatch`;
  }
  if (typeof args === "number") {
    if (schema.minimum != null && args < schema.minimum) return `${path}: below minimum`;
    if (schema.maximum != null && args > schema.maximum) return `${path}: above maximum`;
  }
  return null;
}
