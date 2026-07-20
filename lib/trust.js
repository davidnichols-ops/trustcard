// Trust state machine.
//
// Every server a client talks to is in exactly one state, and every
// transition is an auditable event with a machine-readable reason code.
//
//                 observe()
//   UNKNOWN ────────────────────► OBSERVED
//                                    │ pin()/policy ok
//                                    ▼
//   ┌────────── list_changed ───► PINNED ──────── compatible re-diff ───► PINNED (re-pinned)
//   │ re-diff                     │   │
//   │                             │   └─ incompatible diff ──► MISMATCH ── policy denies ──► REVOKED
//   │                             │                            │
//   └─────────────────────────────┘                            └─ approve() ──► PINNED
//   unsigned-when-required ──► SUSPECT ── policy ──► PINNED | REVOKED
//   bad signature / key drift / deny policy ──► REVOKED (terminal per session)
//
// REVOKED is terminal for the session: once a server has demonstrated it will
// change its contract under you (or its provenance fails), the safe default is
// to stop routing calls to it until a human re-pins.

import { CHANGE_LEVEL } from "./diff.js";

export const TRUST_STATES = ["UNKNOWN", "OBSERVED", "PINNED", "MISMATCH", "SUSPECT", "REVOKED"];

// Human-facing trust level projection. The internal state machine has six
// states; these project onto four levels for UIs and high-level APIs.
// The state machine is unchanged — this is a derived view, not a replacement.
export const TRUST_LEVELS = ["TRUSTED", "VERIFIED", "OBSERVED", "UNTRUSTED", "REVOKED"];

export function trustLevel(state) {
  switch (state) {
    case "PINNED":   return "TRUSTED";
    case "OBSERVED": return "OBSERVED";
    case "SUSPECT":  return "OBSERVED";
    case "UNKNOWN":  return "OBSERVED";
    case "MISMATCH": return "UNTRUSTED";
    case "REVOKED":  return "REVOKED";
    default:         return "OBSERVED";
  }
}

// Why a transition happened — stable codes for audit logs and CI.
export const REASONS = {
  FIRST_OBSERVATION: "FIRST_OBSERVATION",
  PIN_CREATED: "PIN_CREATED",
  DIGEST_MATCH: "DIGEST_MATCH",
  COMPATIBLE_REPIN: "COMPATIBLE_REPIN",
  TOOL_ADDED: "TOOL_ADDED",
  BREAKING_CHANGE: "BREAKING_CHANGE",
  PERMISSION_CHANGE: "PERMISSION_CHANGE",
  ANNOTATION_DOWNGRADE: "ANNOTATION_DOWNGRADE",
  SIGNATURE_MISSING: "SIGNATURE_MISSING",
  SIGNATURE_INVALID: "SIGNATURE_INVALID",
  PUBLISHER_KEY_DRIFT: "PUBLISHER_KEY_DRIFT",
  PUBLISHER_UNPINNED: "PUBLISHER_UNPINNED",
  LIST_CHANGED: "LIST_CHANGED",
  POLICY_DENY: "POLICY_DENY",
  MANUAL_APPROVAL: "MANUAL_APPROVAL",
  MANUAL_REVOKE: "MANUAL_REVOKE",
};

const TERMINAL = new Set(["REVOKED"]);

export class TrustStore {
  constructor({ policy = {}, onEvent } = {}) {
    this.policy = {
      requireSignature: false,
      allowAutoRepin: true,       // auto re-pin on compatible (non-breaking) changes
      allowNewTools: true,        // auto-accept added tools
      ...policy,
    };
    this.onEvent = onEvent ?? (() => {});
    this.servers = new Map(); // serverKey -> record
  }

  _key(serverId) {
    return typeof serverId === "string" ? serverId : `${serverId?.name ?? "?"}@${serverId?.version ?? "?"}`;
  }

  get(serverId) {
    return this.servers.get(this._key(serverId)) ?? { state: "UNKNOWN", history: [] };
  }

  _transition(serverId, to, reason, detail = {}) {
    const key = this._key(serverId);
    const rec = this.servers.get(key) ?? { state: "UNKNOWN", history: [] };
    if (TERMINAL.has(rec.state) && reason !== REASONS.MANUAL_APPROVAL) {
      // REVOKED is sticky: refuse to leave it silently.
      return rec;
    }
    const event = {
      at: new Date().toISOString(),
      server: key,
      from: rec.state,
      to,
      reason,
      detail,
    };
    rec.state = to;
    rec.history.push(event);
    this.servers.set(key, rec);
    this.onEvent(event);
    return rec;
  }

  observe(serverId, observation) {
    const rec = this.get(serverId);
    if (rec.state === "UNKNOWN") {
      this._transition(serverId, "OBSERVED", REASONS.FIRST_OBSERVATION, {
        serverDigest: observation.serverDigest,
      });
    }
    const r = this.servers.get(this._key(serverId));
    r.lastObservation = observation;
    return r;
  }

  pin(serverId, observation, publisher = null) {
    // pin() implies an observation — tolerate being called without a prior
    // observe() so callers can go straight from connect() to pin().
    if (!this.servers.has(this._key(serverId))) {
      this.observe(serverId, observation);
    }
    const rec = this.servers.get(this._key(serverId));
    rec.pin = {
      serverDigest: observation.serverDigest,
      toolsetDigest: observation.toolsetDigest,
      toolDigests: observation.toolDigests ?? {},
      tools: observation.tools,
      protocolVersion: observation.protocolVersion,
      pinnedAt: new Date().toISOString(),
      publisher,
    };
    this._transition(serverId, "PINNED", REASONS.PIN_CREATED, { serverDigest: observation.serverDigest });
    return this.get(serverId);
  }

  // Evaluate a fresh observation against the pin. Returns { action, diff, rec }.
  evaluate(serverId, observation, diff) {
    const key = this._key(serverId);
    const rec = this.servers.get(key);
    if (!rec?.pin) return { action: "unpinned", diff, rec };

    if (diff.overall === "NONE") {
      this._transition(serverId, "PINNED", REASONS.DIGEST_MATCH, {});
      return { action: "ok", diff, rec: this.get(serverId) };
    }

    if (diff.overall === "SYNTACTIC") {
      // Cosmetic drift — never a trust event, but worth an audit line.
      this._transition(serverId, "PINNED", REASONS.DIGEST_MATCH, { syntacticOnly: true });
      return { action: "ok", diff, rec: this.get(serverId) };
    }

    const level = CHANGE_LEVEL[diff.overall];
    if (level <= CHANGE_LEVEL.NON_BREAKING) {
      const onlyAdded = diff.removed.length === 0 && diff.changed.every((c) => c.level === "NON_BREAKING");
      if (onlyAdded && !this.policy.allowNewTools && diff.added.length > 0) {
        this._transition(serverId, "MISMATCH", REASONS.TOOL_ADDED, { added: diff.added });
        return { action: "mismatch", diff, rec: this.get(serverId) };
      }
      if (this.policy.allowAutoRepin) {
        rec.pin = {
          ...rec.pin,
          serverDigest: observation.serverDigest,
          toolsetDigest: observation.toolsetDigest,
          toolDigests: observation.toolDigests ?? rec.pin.toolDigests,
          tools: observation.tools,
          repinnedAt: new Date().toISOString(),
        };
        this._transition(serverId, "PINNED", REASONS.COMPATIBLE_REPIN, { summary: diff.summary });
        return { action: "repinned", diff, rec: this.get(serverId) };
      }
      return { action: "ok", diff, rec: this.get(serverId) };
    }

    // Incompatible change: breaking, permission, or suspected poisoning.
    const reason =
      diff.overall === "BREAKING" ? REASONS.BREAKING_CHANGE
      : diff.overall === "PERMISSION_CHANGE" ? REASONS.PERMISSION_CHANGE
      : REASONS.ANNOTATION_DOWNGRADE;
    this._transition(serverId, "MISMATCH", reason, { summary: diff.summary });
    return { action: "mismatch", diff, rec: this.get(serverId) };
  }

  suspect(serverId, reason, detail = {}) {
    this._transition(serverId, "SUSPECT", reason, detail);
    return this.get(serverId);
  }

  revoke(serverId, reason, detail = {}) {
    this._transition(serverId, "REVOKED", reason, detail);
    return this.get(serverId);
  }

  approve(serverId) {
    const rec = this.servers.get(this._key(serverId));
    if (!rec) return this.get(serverId);
    rec.state = "UNKNOWN"; // manual reset out of any state incl. REVOKED
    this._transition(serverId, "OBSERVED", REASONS.MANUAL_APPROVAL, {});
    if (rec.lastObservation) this.pin(serverId, rec.lastObservation, rec.pin?.publisher ?? null);
    return this.get(serverId);
  }
}
