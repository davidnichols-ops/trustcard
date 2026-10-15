#!/usr/bin/env node
// Bruce Lee — a reference well-behaved MCP server.
//
// Provides a deterministic, hash-chained audit log for agent decisions.
// Demonstrates: proper input validation, structured JSON-RPC error codes,
// observability via structured stderr logs, trustcard-aware handshake
// (toolsetDigest binding), safe failure handling, and zero runtime deps.
//
// Transport: stdio, newline-delimited JSON-RPC.
// Protocol:  2025-06-18
//
// Usage:
//   node examples/bruce-lee/server.js
//   BRUCE_LEE_LOG_PATH=/tmp/audit.jsonl node examples/bruce-lee/server.js
//
// Environment:
//   BRUCE_LEE_LOG_PATH  — path to the append-only audit log
//                         (default: a per-user path under the OS temp dir so
//                         demos never write untracked artifacts into the repo)
//   BRUCE_LEE_LOG_LEVEL — log level: "debug" | "info" | "warn" | "error" (default: "info")

import { createHash } from "node:crypto";
import { appendFileSync, existsSync, readFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

// --- trustcard crypto (reuse the repo's own JCS + SHA-256) -------------------
// This keeps Bruce Lee's digests byte-compatible with trustcard's identity model.
import { hashJson } from "../../lib/hash.js";
import { canon } from "../../lib/canon.js";
import { toolsetDigest, TRUSTCARD_META_KEY, MANIFEST_SCHEMA_VERSION } from "../../lib/identity.js";

// --- Constants ---------------------------------------------------------------
const SERVER_NAME = "bruce-lee";
const SERVER_VERSION = "1.0.0";
const PROTOCOL_VERSION = "2025-06-18";
const LOG_PATH = process.env.BRUCE_LEE_LOG_PATH
  ?? join(tmpdir(), "bruce-lee", "bruce-lee-decisions.jsonl");
const LOG_LEVEL = process.env.BRUCE_LEE_LOG_LEVEL ?? "info";

const LEVELS = { debug: 10, info: 20, warn: 30, error: 40 };

// JSON-RPC error codes (per spec)
const ERR_PARSE = -32700;
const ERR_INVALID_REQUEST = -32600;
const ERR_METHOD_NOT_FOUND = -32601;
const ERR_INVALID_PARAMS = -32602;
const ERR_INTERNAL = -32603;

// Valid decision kinds
const VALID_KINDS = ["decision", "observation", "escalation", "veto"];

// --- Structured logging to stderr --------------------------------------------
// Never stdout — stdout is the JSON-RPC transport. Logs are JSON objects with
// ts, level, event, and arbitrary context fields. Redaction is not needed
// because Bruce Lee never handles secrets, but the structure is here for it.
function log(level, event, fields = {}) {
  if (LEVELS[level] < LEVELS[LOG_LEVEL]) return;
  const entry = { ts: new Date().toISOString(), level, event, ...fields };
  process.stderr.write(JSON.stringify(entry) + "\n");
}

// --- Tool definitions --------------------------------------------------------
// Annotations are set honestly: record_decision writes to a local log (not
// destructive, not read-only), query_decisions and server_identity are
// read-only and idempotent. None are open-world.
const TOOLS = [
  {
    name: "record_decision",
    description:
      "Record a structured agent decision to an append-only, hash-chained audit log. " +
      "Returns a receipt containing the decision digest and the previous decision's digest, " +
      "forming a tamper-evident chain. Use this to make agent reasoning auditable and reproducible.",
    inputSchema: {
      type: "object",
      properties: {
        agent: {
          type: "string",
          minLength: 1,
          maxLength: 200,
          description: "Identifier of the agent making the decision (e.g. 'devin', 'claude-3', 'human:david').",
        },
        action: {
          type: "string",
          minLength: 1,
          maxLength: 200,
          description: "The action being decided on (e.g. 'commit', 'deploy', 'merge', 'escalate').",
        },
        rationale: {
          type: "string",
          minLength: 1,
          maxLength: 4000,
          description: "Why the decision was made. This is the auditable reasoning trail.",
        },
        kind: {
          type: "string",
          enum: VALID_KINDS,
          description: "Decision category. 'decision' = chose an action, 'observation' = noted a fact, 'escalation' = sent to human, 'veto' = blocked an action.",
        },
        tags: {
          type: "array",
          items: { type: "string", maxLength: 100 },
          maxItems: 20,
          description: "Optional free-form tags for querying and grouping decisions.",
        },
      },
      required: ["agent", "action", "rationale"],
    },
    annotations: {
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: false,
      title: "Record Decision",
    },
  },
  {
    name: "query_decisions",
    description:
      "Query the audit log for recorded decisions. Filters by agent, kind, or time range. " +
      "Returns matching decisions with their digests and chain pointers. Read-only and deterministic — " +
      "the same query always returns the same results (modulo new appends).",
    inputSchema: {
      type: "object",
      properties: {
        agent: {
          type: "string",
          description: "Filter to decisions by this agent only.",
        },
        kind: {
          type: "string",
          enum: VALID_KINDS,
          description: "Filter to decisions of this kind only.",
        },
        since: {
          type: "string",
          description: "ISO 8601 timestamp — only decisions at or after this time.",
        },
        until: {
          type: "string",
          description: "ISO 8601 timestamp — only decisions before this time.",
        },
        limit: {
          type: "integer",
          minimum: 1,
          maximum: 1000,
          description: "Maximum number of decisions to return (default 100, max 1000).",
        },
      },
    },
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
      title: "Query Decisions",
    },
  },
  {
    name: "server_identity",
    description:
      "Return this server's capability descriptor: name, version, protocol version, toolset digest, " +
      "tool count, and audit log statistics. Use this to verify you are talking to the correct Bruce Lee " +
      "instance and that the toolset has not drifted.",
    inputSchema: {
      type: "object",
      properties: {},
    },
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
      title: "Server Identity",
    },
  },
];

// Precompute the toolset digest at startup. This is the trustcard-aware binding:
// the server commits to its exact toolset at handshake time, closing the TOCTOU
// window between discovery and execution.
const TOOLSET_DIGEST = toolsetDigest(TOOLS);

// --- Audit log ---------------------------------------------------------------
// Append-only JSONL. Each line is a decision record. The chain works like this:
//   digest_n = hashJson({ prev: digest_{n-1}, ts, agent, action, rationale, kind, tags })
// The first decision has prev: null. Modifying any entry breaks all subsequent
// digests — tamper-evident without a central authority.

function computeDigest(record) {
  return hashJson({
    prev: record.prev,
    ts: record.ts,
    agent: record.agent,
    action: record.action,
    rationale: record.rationale,
    kind: record.kind,
    tags: record.tags ?? [],
  });
}

// Read the entire log, validating the hash chain. Returns { records, lastDigest }.
// Fail-closed: if any record's digest doesn't match, throw with a clear error.
function readLog(path) {
  if (!existsSync(path)) return { records: [], lastDigest: null };
  const raw = readFileSync(path, "utf8");
  const lines = raw.split("\n").filter((l) => l.trim().length > 0);
  const records = [];
  let expectedPrev = null;
  for (let i = 0; i < lines.length; i++) {
    let rec;
    try {
      rec = JSON.parse(lines[i]);
    } catch {
      throw new LogIntegrityError(`line ${i + 1}: malformed JSON`);
    }
    if (rec.prev !== expectedPrev) {
      throw new LogIntegrityError(
        `line ${i + 1}: chain broken — expected prev=${expectedPrev}, got prev=${rec.prev}`
      );
    }
    const recomputed = computeDigest(rec);
    if (recomputed !== rec.digest) {
      throw new LogIntegrityError(
        `line ${i + 1}: digest mismatch — expected ${recomputed}, got ${rec.digest}`
      );
    }
    records.push(rec);
    expectedPrev = rec.digest;
  }
  return { records, lastDigest: expectedPrev };
}

// Append a single record atomically. Creates the parent directory if needed.
function appendRecord(path, record) {
  const dir = dirname(path);
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  appendFileSync(path, JSON.stringify(record) + "\n");
}

// Custom error class so the RPC layer can distinguish integrity failures from
// generic internal errors. Integrity failures are -32603 (internal error) but
// with a specific message that operators can grep for.
class LogIntegrityError extends Error {
  constructor(message) {
    super(`audit log integrity failure: ${message}`);
    this.name = "LogIntegrityError";
  }
}

// --- Input validation --------------------------------------------------------
// Returns { ok: true, value } or { ok: false, error: { code, message } }.
// This is the single validation chokepoint — every tool call passes through it.

function validateRecordDecision(params) {
  if (!params || typeof params !== "object") {
    return fail(ERR_INVALID_PARAMS, "params must be an object");
  }
  const { agent, action, rationale, kind, tags } = params;

  if (typeof agent !== "string" || agent.length < 1 || agent.length > 200) {
    return fail(ERR_INVALID_PARAMS, "agent must be a string of 1-200 characters");
  }
  if (typeof action !== "string" || action.length < 1 || action.length > 200) {
    return fail(ERR_INVALID_PARAMS, "action must be a string of 1-200 characters");
  }
  if (typeof rationale !== "string" || rationale.length < 1 || rationale.length > 4000) {
    return fail(ERR_INVALID_PARAMS, "rationale must be a string of 1-4000 characters");
  }
  if (kind !== undefined) {
    if (typeof kind !== "string" || !VALID_KINDS.includes(kind)) {
      return fail(ERR_INVALID_PARAMS, `kind must be one of: ${VALID_KINDS.join(", ")}`);
    }
  }
  if (tags !== undefined) {
    if (!Array.isArray(tags) || tags.length > 20) {
      return fail(ERR_INVALID_PARAMS, "tags must be an array of at most 20 strings");
    }
    for (const t of tags) {
      if (typeof t !== "string" || t.length > 100) {
        return fail(ERR_INVALID_PARAMS, "each tag must be a string of at most 100 characters");
      }
    }
  }
  return { ok: true, value: { agent, action, rationale, kind: kind ?? "decision", tags: tags ?? [] } };
}

function validateQueryDecisions(params) {
  if (params === undefined || params === null) return { ok: true, value: {} };
  if (typeof params !== "object" || Array.isArray(params)) {
    return fail(ERR_INVALID_PARAMS, "params must be an object");
  }
  const { agent, kind, since, until, limit } = params;

  if (agent !== undefined && (typeof agent !== "string" || agent.length < 1)) {
    return fail(ERR_INVALID_PARAMS, "agent filter must be a non-empty string");
  }
  if (kind !== undefined) {
    if (typeof kind !== "string" || !VALID_KINDS.includes(kind)) {
      return fail(ERR_INVALID_PARAMS, `kind must be one of: ${VALID_KINDS.join(", ")}`);
    }
  }
  if (since !== undefined) {
    if (typeof since !== "string" || isNaN(Date.parse(since))) {
      return fail(ERR_INVALID_PARAMS, "since must be a valid ISO 8601 timestamp");
    }
  }
  if (until !== undefined) {
    if (typeof until !== "string" || isNaN(Date.parse(until))) {
      return fail(ERR_INVALID_PARAMS, "until must be a valid ISO 8601 timestamp");
    }
  }
  if (limit !== undefined) {
    if (typeof limit !== "number" || !Number.isInteger(limit) || limit < 1 || limit > 1000) {
      return fail(ERR_INVALID_PARAMS, "limit must be an integer between 1 and 1000");
    }
  }
  return { ok: true, value: { agent, kind, since, until, limit: limit ?? 100 } };
}

function fail(code, message) {
  return { ok: false, error: { code, message } };
}

// --- Tool handlers -----------------------------------------------------------

function handleRecordDecision(params) {
  const v = validateRecordDecision(params);
  if (!v.ok) return v;

  const { agent, action, rationale, kind, tags } = v.value;

  let lastDigest;
  try {
    ({ lastDigest } = readLog(LOG_PATH));
  } catch (e) {
    log("error", "log_read_failed", { error: e.message });
    return fail(ERR_INTERNAL, e.message);
  }

  const ts = new Date().toISOString();
  const record = {
    id: `dec_${ts.replace(/[^0-9]/g, "")}_${randomId()}`,
    prev: lastDigest,
    ts,
    agent,
    action,
    rationale,
    kind,
    tags,
  };
  record.digest = computeDigest(record);

  try {
    appendRecord(LOG_PATH, record);
  } catch (e) {
    log("error", "log_append_failed", { error: e.message });
    return fail(ERR_INTERNAL, `failed to write audit log: ${e.message}`);
  }

  log("info", "decision_recorded", { id: record.id, agent, action, kind, digest: record.digest });

  // Return a receipt — the subset of fields that prove the chain link.
  const receipt = {
    id: record.id,
    digest: record.digest,
    previousDigest: record.prev,
    timestamp: record.ts,
    agent,
    action,
    kind,
  };
  return { ok: true, result: receipt };
}

function handleQueryDecisions(params) {
  const v = validateQueryDecisions(params);
  if (!v.ok) return v;

  const { agent, kind, since, until, limit } = v.value;

  let records;
  try {
    ({ records } = readLog(LOG_PATH));
  } catch (e) {
    log("error", "log_read_failed", { error: e.message });
    return fail(ERR_INTERNAL, e.message);
  }

  // Apply filters
  let filtered = records;
  if (agent) filtered = filtered.filter((r) => r.agent === agent);
  if (kind) filtered = filtered.filter((r) => r.kind === kind);
  if (since) {
    const sinceMs = Date.parse(since);
    filtered = filtered.filter((r) => Date.parse(r.ts) >= sinceMs);
  }
  if (until) {
    const untilMs = Date.parse(until);
    filtered = filtered.filter((r) => Date.parse(r.ts) < untilMs);
  }
  filtered = filtered.slice(-limit);

  log("info", "decisions_queried", { total: records.length, matched: filtered.length, agent, kind });

  // Return a compact projection — no rationale in query results by default
  // (rationale can be long; the caller can fetch by id if needed).
  const results = filtered.map((r) => ({
    id: r.id,
    digest: r.digest,
    previousDigest: r.prev,
    timestamp: r.ts,
    agent: r.agent,
    action: r.action,
    kind: r.kind,
    tags: r.tags,
  }));

  return { ok: true, result: { count: results.length, decisions: results } };
}

function handleServerIdentity() {
  let stats;
  try {
    const { records, lastDigest } = readLog(LOG_PATH);
    stats = { decisionCount: records.length, lastDecisionDigest: lastDigest };
  } catch (e) {
    stats = { decisionCount: 0, lastDecisionDigest: null, error: e.message };
  }

  const identity = {
    name: SERVER_NAME,
    version: SERVER_VERSION,
    protocolVersion: PROTOCOL_VERSION,
    toolsetDigest: TOOLSET_DIGEST,
    toolCount: TOOLS.length,
    tools: TOOLS.map((t) => t.name),
    logPath: LOG_PATH,
    ...stats,
  };

  return { ok: true, result: identity };
}

// --- Tool dispatch -----------------------------------------------------------
const HANDLERS = {
  record_decision: handleRecordDecision,
  query_decisions: handleQueryDecisions,
  server_identity: () => handleServerIdentity(),
};

// --- JSON-RPC protocol -------------------------------------------------------
function send(msg) {
  process.stdout.write(JSON.stringify(msg) + "\n");
}

function makeError(id, code, message) {
  return { jsonrpc: "2.0", id: id ?? null, error: { code, message } };
}

function makeResult(id, result) {
  return { jsonrpc: "2.0", id, result };
}

function handle(msg) {
  // Validate JSON-RPC envelope
  if (!msg || typeof msg !== "object" || msg.jsonrpc !== "2.0") {
    return makeError(msg?.id, ERR_INVALID_REQUEST, "invalid JSON-RPC 2.0 envelope");
  }

  const { id, method, params } = msg;

  // --- initialize ---
  if (method === "initialize") {
    const result = {
      protocolVersion: PROTOCOL_VERSION,
      capabilities: { tools: { listChanged: false } },
      serverInfo: { name: SERVER_NAME, version: SERVER_VERSION },
      // trustcard-aware binding: commit to the toolset digest at handshake.
      // A trustcard client verifies this matches the manifest, closing the
      // TOCTOU window between discovery and execution.
      _meta: {
        [TRUSTCARD_META_KEY]: {
          schema: MANIFEST_SCHEMA_VERSION,
          toolsetDigest: TOOLSET_DIGEST,
        },
      },
    };
    return makeResult(id, result);
  }

  // --- notifications/initialized (no response) ---
  if (method === "notifications/initialized") {
    log("info", "client_initialized");
    return null;
  }

  // --- tools/list ---
  if (method === "tools/list") {
    return makeResult(id, { tools: TOOLS });
  }

  // --- tools/call ---
  if (method === "tools/call") {
    const toolName = params?.name;
    const toolArgs = params?.arguments ?? {};

    if (!HANDLERS[toolName]) {
      return makeError(id, ERR_METHOD_NOT_FOUND, `unknown tool: ${toolName}`);
    }

    log("debug", "tool_call", { tool: toolName, id });

    const handler = HANDLERS[toolName];
    let res;
    try {
      res = handler(toolArgs);
    } catch (e) {
      log("error", "tool_exception", { tool: toolName, error: e.message, stack: e.stack });
      return makeError(id, ERR_INTERNAL, `internal error in ${toolName}: ${e.message}`);
    }

    if (!res.ok) {
      return makeError(id, res.error.code, res.error.message);
    }

    // MCP tools/call returns content blocks, not raw JSON.
    return makeResult(id, {
      content: [{ type: "text", text: JSON.stringify(res.result, null, 2) }],
      isError: false,
    });
  }

  // --- ping ---
  if (method === "ping") {
    return makeResult(id, {});
  }

  // Unknown method
  return makeError(id, ERR_METHOD_NOT_FOUND, `method not found: ${method}`);
}

// --- Random ID generation (no deps) -----------------------------------------
function randomId() {
  return createHash("sha256").update(`${Date.now()}-${Math.random()}`).digest("hex").slice(0, 8);
}

// --- Main loop ---------------------------------------------------------------
log("info", "server_starting", { version: SERVER_VERSION, logPath: LOG_PATH, toolsetDigest: TOOLSET_DIGEST });

let buffer = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  buffer += chunk;
  let idx;
  while ((idx = buffer.indexOf("\n")) >= 0) {
    const line = buffer.slice(0, idx).trim();
    buffer = buffer.slice(idx + 1);
    if (!line) continue;
    let msg;
    try {
      msg = JSON.parse(line);
    } catch {
      send(makeError(null, ERR_PARSE, "parse error: malformed JSON"));
      continue;
    }
    const response = handle(msg);
    if (response !== null) send(response);
  }
});

// Exit when the parent closes stdin — never outlive the client.
process.stdin.on("end", () => {
  log("info", "server_stopping");
  process.exit(0);
});

// Catch uncaught errors — fail gracefully, never crash silently.
process.on("uncaughtException", (e) => {
  log("error", "uncaught_exception", { error: e.message, stack: e.stack });
});
