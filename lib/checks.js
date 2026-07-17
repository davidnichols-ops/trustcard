// Scorecard checks for an MCP server spec.
// Each check returns { status: "PASS"|"WARN"|"FAIL"|"UNKNOWN", detail, score, max }.
import { exec as execCb } from "node:child_process";
import { promisify } from "node:util";
import { McpStdioClient, PROTOCOL_VERSIONS } from "./client.js";

const exec = promisify(execCb);

const LATEST_PROTOCOL = PROTOCOL_VERSIONS[0];

// --- heuristics -------------------------------------------------------------
// Destructive verbs are matched as whole words (word-boundary regex), not
// substrings. This prevents false positives like "browser_navigate" matching
// "remove" inside "removeDuplicates" or "get_item_props" matching "reset".
// We match against the tool name (snake_case split) and description.
const DESTRUCTIVE_VERBS = [
  "delete", "remove", "drop", "kill", "destroy", "truncate",
  "overwrite", "purge", "wipe", "force", "reset", "uninstall", "disable",
  "checkout", "push", "merge", "fork", "revert", "rollback",
  "format", "reboot", "shutdown", "eject", "detach", "evict",
  "clear", "clean", "flush", "abort",
];
const WRITE_VERBS = [
  "write", "create", "update", "insert", "upsert", "push", "post", "put",
  "execute", "exec", "run", "send", "submit", "apply", "set", "install",
  "deploy", "merge", "commit", "edit", "modify", "patch",
];

// Build a word-boundary regex for a verb that also handles snake_case.
// "delete" matches "delete_file", "deleteFile", "DELETE_FILE", but NOT
// "undelete" or "deletegate" (delegate misspelling).
function verbRegex(verb) {
  // Match the verb at a word boundary, or after an underscore (snake_case)
  return new RegExp(`(^|[^a-z])${verb}([^a-z]|$)`, "i");
}

// Pre-compile regexes for performance
const DESTRUCTIVE_REGEXES = DESTRUCTIVE_VERBS.map(verbRegex);
const WRITE_REGEXES = WRITE_VERBS.map(verbRegex);
const AUTH_HINTS = [
  "token", "api key", "apikey", "api-key", "personal access", "password",
  "secret", "credential", "oauth", "bearer", "authorization", "login",
  "authenticate", "auth", "env var", "environment variable", "requires",
];
const CONFIG_HINTS = [
  "api key", "apikey", "api-key", "token", "personal access", "password",
  "secret", "credential", "oauth", "bearer", "authorization",
  "env var", "environment variable", "missing", "required", "not set",
  "not provided", "must be set", "is required", "no api key", "no token",
  "config", "configuration", "--help", "usage:", "arguments required",
  "connection string", "database url", "db url", "dsn",
];
const SECRET_PATTERNS = [
  /sk-[A-Za-z0-9]{16,}/, // openai
  /gh[pousr]_[A-Za-z0-9]{16,}/, // github
  /AKIA[0-9A-Z]{12,}/, // aws
  /xox[baprs]-[A-Za-z0-9-]{10,}/, // slack
  /AIza[0-9A-Za-z_-]{20,}/, // google
  /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/, // jwt
  /[A-Za-z0-9_-]{32,}$/, // generic high-entropy tail
];

// Additional patterns for config file scanning — env vars and inline secrets
const CONFIG_SECRET_PATTERNS = [
  ...SECRET_PATTERNS,
  /(?:token|key|secret|password|passwd|credential|api_key|apikey)["\s]*[:=]\s*["']?([A-Za-z0-9_\-\.]{20,})["']?/gi, // key-value pairs
  /Bearer\s+[A-Za-z0-9_.-]{20,}/gi, // bearer tokens
  /x-api-key["\s]*[:=]\s*["']?([A-Za-z0-9_\-]{16,})["']?/gi, // x-api-key headers
];

// Scan a config file (JSON or text) for secrets.
// Returns array of findings: { pattern, sample, key, line }
export function scanConfigForSecrets(configText, configPath = null) {
  const findings = [];
  const lines = configText.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const pattern of CONFIG_SECRET_PATTERNS) {
      // Reset regex lastIndex for global patterns
      pattern.lastIndex = 0;
      const match = pattern.exec(line);
      if (match) {
        // Extract the key name if possible (for JSON key-value pairs)
        const keyMatch = line.match(/["']?([A-Za-z_][A-Za-z0-9_]*)["']?\s*[:=]/);
        const key = keyMatch ? keyMatch[1] : "unknown";
        // Redact the secret in the sample
        const sample = line.trim().slice(0, 80).replace(match[0], match[0].slice(0, 10) + "***REDACTED***");
        findings.push({
          pattern: pattern.source.slice(0, 40),
          sample,
          key,
          line: i + 1,
          configPath,
        });
      }
    }
  }
  return findings;
}

function findDestructive(tools) {
  const hits = [];
  for (const t of tools) {
    const text = `${t.name} ${t.description ?? ""}`;
    for (let i = 0; i < DESTRUCTIVE_REGEXES.length; i++) {
      if (DESTRUCTIVE_REGEXES[i].test(text)) {
        hits.push({ name: t.name, verb: DESTRUCTIVE_VERBS[i] });
        break;
      }
    }
  }
  return hits;
}

function findWrite(tools) {
  const hits = [];
  for (const t of tools) {
    const text = `${t.name} ${t.description ?? ""}`;
    for (let i = 0; i < WRITE_REGEXES.length; i++) {
      if (WRITE_REGEXES[i].test(text)) {
        hits.push({ name: t.name, verb: WRITE_VERBS[i] });
        break;
      }
    }
  }
  return hits;
}

function scanSecrets(texts) {
  for (const t of texts ?? []) {
    if (!t) continue;
    for (const p of SECRET_PATTERNS) {
      if (p.test(t)) return { leaked: true, pattern: p.source, sample: t.slice(0, 80) };
    }
  }
  return { leaked: false };
}

function validateToolSchema(tools) {
  const issues = [];
  if (!Array.isArray(tools)) return { valid: false, issues: ["tools/list did not return an array"] };
  for (const t of tools) {
    if (!t.name || typeof t.name !== "string") issues.push(`tool missing name: ${JSON.stringify(t).slice(0, 60)}`);
    if (t.inputSchema && typeof t.inputSchema === "object") {
      const s = t.inputSchema;
      if (s.type && s.type !== "object") issues.push(`${t.name}: inputSchema.type is "${s.type}", expected "object"`);
      if (!s.properties && !s.allOf && !s.anyOf && !s.$ref) issues.push(`${t.name}: inputSchema has no properties`);
    } else if (t.inputSchema === undefined) {
      // allowed — tool takes no args
    } else {
      issues.push(`${t.name}: inputSchema is not an object`);
    }
  }
  return { valid: issues.length === 0, issues };
}

// --- parameter-based danger analysis ----------------------------------------
// A tool's name may be benign ("read_file") but its parameters can make it
// dangerous (e.g. a "path" param that accepts arbitrary filesystem paths,
// an "sql" param that accepts DROP TABLE, a "command" param that runs shell).
// We analyze inputSchema.properties to detect these patterns.

// Parameter names that indicate dangerous capabilities, mapped to risk level.
const DANGEROUS_PARAM_NAMES = {
  // Filesystem access — can read sensitive files (~/.ssh, /etc/passwd)
  path: { risk: "filesystem", level: "medium", reason: "arbitrary filesystem path" },
  filepath: { risk: "filesystem", level: "medium", reason: "arbitrary filesystem path" },
  file_path: { risk: "filesystem", level: "medium", reason: "arbitrary filesystem path" },
  filename: { risk: "filesystem", level: "low", reason: "filesystem filename" },
  directory: { risk: "filesystem", level: "medium", reason: "arbitrary directory path" },
  dir: { risk: "filesystem", level: "medium", reason: "arbitrary directory path" },
  // Shell/command execution — can run arbitrary commands
  command: { risk: "shell", level: "high", reason: "arbitrary shell command" },
  cmd: { risk: "shell", level: "high", reason: "arbitrary shell command" },
  script: { risk: "shell", level: "high", reason: "arbitrary script execution" },
  code: { risk: "shell", level: "high", reason: "arbitrary code execution" },
  // SQL — can DROP TABLE, DELETE, etc.
  sql: { risk: "sql", level: "high", reason: "raw SQL query" },
  query: { risk: "sql", level: "medium", reason: "query parameter (may be SQL or search)" },
  // URLs — can make outbound requests to arbitrary hosts (SSRF)
  url: { risk: "network", level: "medium", reason: "arbitrary URL (SSRF risk)" },
  uri: { risk: "network", level: "medium", reason: "arbitrary URI (SSRF risk)" },
  endpoint: { risk: "network", level: "medium", reason: "arbitrary endpoint" },
  // Webhooks / callbacks — can exfiltrate data
  webhook: { risk: "exfil", level: "high", reason: "webhook URL (data exfiltration risk)" },
  callback_url: { risk: "exfil", level: "high", reason: "callback URL (data exfiltration risk)" },
};

// Parameter descriptions that hint at dangerous capabilities
const DANGEROUS_DESC_PATTERNS = [
  { pattern: /arbitrary.*path|any.*file|absolute.*path/i, risk: "filesystem", level: "high", reason: "description mentions arbitrary file access" },
  { pattern: /shell|bash|terminal|subprocess|system\(/i, risk: "shell", level: "high", reason: "description mentions shell/system access" },
  { pattern: /raw.*sql|execute.*query|drop|delete.*from/i, risk: "sql", level: "high", reason: "description mentions raw SQL or destructive queries" },
  { pattern: /arbitrary.*url|any.*host|external.*url/i, risk: "network", level: "high", reason: "description mentions arbitrary URL access" },
];

// Analyze a single tool's inputSchema for dangerous parameters.
function analyzeToolDanger(tool) {
  const findings = [];
  const schema = tool.inputSchema;
  if (!schema || typeof schema !== "object") return findings;

  const props = schema.properties || {};
  for (const [paramName, paramSchema] of Object.entries(props)) {
    if (typeof paramSchema !== "object") continue;

    // Check parameter name against known dangerous names
    const lowerName = paramName.toLowerCase();
    if (DANGEROUS_PARAM_NAMES[lowerName]) {
      const info = DANGEROUS_PARAM_NAMES[lowerName];
      findings.push({
        tool: tool.name,
        param: paramName,
        risk: info.risk,
        level: info.level,
        reason: info.reason,
      });
    }

    // Check parameter description for dangerous patterns
    const desc = paramSchema.description || "";
    for (const p of DANGEROUS_DESC_PATTERNS) {
      if (p.pattern.test(desc)) {
        findings.push({
          tool: tool.name,
          param: paramName,
          risk: p.risk,
          level: p.level,
          reason: p.reason,
        });
        break; // one match per param is enough
      }
    }

    // Check if a string param has no constraints (no enum, no pattern, no maxLength)
    // This means it accepts arbitrary input — more dangerous for path/sql/command params
    if (paramSchema.type === "string" && !paramSchema.enum && !paramSchema.pattern && !paramSchema.maxLength) {
      // Only flag if the param name is already suspicious
      if (DANGEROUS_PARAM_NAMES[lowerName]) {
        // Already flagged above — upgrade to high if unconstrained
        const existing = findings.find((f) => f.param === paramName);
        if (existing && existing.level !== "high") {
          existing.level = "high";
          existing.reason += " (unconstrained — no enum/pattern/maxLength)";
        }
      }
    }
  }
  return findings;
}

// Analyze all tools for parameter-based dangers.
function findDangerousParams(tools) {
  const allFindings = [];
  for (const t of tools) {
    allFindings.push(...analyzeToolDanger(t));
  }
  return allFindings;
}

// --- npm installability -----------------------------------------------------
async function checkInstallability(spec) {
  // Try to find a working npm — the mise-managed npm may be broken
  const npmCandidates = [
    "npm",
    "/opt/homebrew/bin/npm",
    "/usr/local/bin/npm",
  ];
  let npmBin = "npm";
  for (const candidate of npmCandidates) {
    try {
      await exec(`${candidate} --version`, { timeout: 5_000, env: process.env });
      npmBin = candidate;
      break;
    } catch {
      // try next candidate
    }
  }

  try {
    const { stdout } = await exec(`${npmBin} view ${JSON.stringify(spec)} name version description.bin --json`, {
      timeout: 30_000, env: process.env,
    });
    const info = JSON.parse(stdout);
    return {
      status: "PASS",
      detail: `${info.name}@${info.version}`,
      score: 15, max: 15,
      meta: { name: info.name, version: info.version, description: info.description, bin: info.bin },
    };
  } catch (e) {
    return {
      status: "FAIL",
      detail: `npm view failed: ${(e.message || "").slice(0, 120)}`,
      score: 0, max: 15,
    };
  }
}

// --- the full probe ---------------------------------------------------------
// spec can be:
//   - a string (npm package spec) — runs checkInstallability, spawns via npx
//   - an object { cmd, args, spec? } — local command, skips installability check
export async function runHealthcheck(spec, opts = {}) {
  const isLocal = typeof spec === "object" && spec !== null;
  const specStr = isLocal ? (spec.spec ?? `${spec.cmd} ${(spec.args ?? []).join(" ")}`) : spec;
  const report = {
    spec: specStr,
    checks: {},
    score: 0,
    max: 100,
    tools: [],
    serverInfo: null,
    protocolVersion: null,
    latencyMs: null,
    failureRate: null,
    runAt: new Date().toISOString(),
  };

  // 1. installability (npm packages only — local commands skip this check)
  let install = { status: "UNKNOWN", detail: "local command — installability check skipped", score: 10, max: 15 };
  let cmd, args, cwd;
  if (isLocal) {
    cmd = spec.cmd;
    args = spec.args ?? [];
    cwd = spec.cwd;
  } else {
    install = await checkInstallability(spec);
    cmd = "npx";
    args = ["-y", spec];
  }
  report.checks.installability = install;

  // 2. protocol handshake + tools
  const client = new McpStdioClient({ cmd, args, env: opts.env ?? {}, spawnTimeout: 45_000, cwd });
  const t0 = Date.now();
  let handshakeOk = false;
  let initResult = null;
  let handshakeErr = null;
  try {
    await client.start();
    initResult = await client.request("initialize", {
      protocolVersion: LATEST_PROTOCOL,
      capabilities: {},
      clientInfo: { name: "mcp-trustcard", version: "0.1.0" },
    }, 15_000);
    handshakeOk = true;
    client.notify("notifications/initialized", {});
    report.latencyMs = Date.now() - t0;
    report.serverInfo = initResult?.serverInfo ?? null;
    report.protocolVersion = initResult?.protocolVersion ?? null;
  } catch (e) {
    handshakeErr = e.message || String(e);
  }

  if (handshakeOk) {
    const lat = report.latencyMs;
    const hStatus = lat < 1500 ? "PASS" : lat < 3000 ? "PASS" : "WARN";
    const hScore = lat < 1500 ? 25 : lat < 3000 ? 21 : 17;
    report.checks.handshake = {
      status: hStatus,
      detail: `${report.serverInfo?.name ?? "server"} ${report.serverInfo?.version ?? ""} · ${lat}ms`,
      score: hScore, max: 25,
    };
  } else {
    // capture stderr for config/auth analysis
    report.stderr = client.stderr.slice(-800);
    const failText = `${report.stderr} ${handshakeErr ?? ""}`.toLowerCase();
    const configHit = CONFIG_HINTS.find((h) => failText.includes(h));
    if (configHit) {
      // Server correctly refused to start without required config/credentials.
      // This is fail-fast behavior — better than starting silently broken.
      // Give partial credit: the server is well-behaved, just needs config
      // that a naive probe doesn't provide.
      report.checks.handshake = {
        status: "CONFIG_REQUIRED",
        detail: `correctly fails fast without config ("${configHit}"): ${handshakeErr.slice(0, 100)}`,
        score: 15, max: 25,
      };
      report.configRequired = true;
    } else {
      report.checks.handshake = {
        status: "FAIL",
        detail: handshakeErr.slice(0, 160),
        score: 0, max: 25,
      };
    }
  }

  // 3. tools/list + schema validity
  let tools = [];
  if (handshakeOk) {
    try {
      const res = await client.request("tools/list", {}, 10_000);
      tools = Array.isArray(res?.tools) ? res.tools : (Array.isArray(res) ? res : []);
      report.tools = tools.map((t) => ({ name: t.name, description: (t.description ?? "").slice(0, 140) }));
    } catch (e) {
      report.checks.schema = {
        status: "FAIL", detail: `tools/list failed: ${(e.message || "").slice(0, 120)}`,
        score: 0, max: 15,
      };
    }
  }

  if (tools.length > 0 && !report.checks.schema) {
    const v = validateToolSchema(tools);
    report.checks.schema = v.valid
      ? { status: "PASS", detail: `${tools.length} tools, all schemas valid`, score: 15, max: 15 }
      : { status: "WARN", detail: `${v.issues.length} schema issue(s): ${v.issues.slice(0, 2).join("; ")}`, score: 8, max: 15 };
  } else if (handshakeOk && !report.checks.schema) {
    report.checks.schema = { status: "UNKNOWN", detail: "no tools exposed or tools/list unsupported", score: 5, max: 15 };
  } else if (!handshakeOk && !report.checks.schema) {
    const cfgScore = report.configRequired ? 7 : 0;
    const cfgDetail = report.configRequired
      ? "cannot enumerate — config required to start"
      : "handshake failed; could not enumerate tools";
    report.checks.schema = { status: "UNKNOWN", detail: cfgDetail, score: cfgScore, max: 15 };
  }

  // 4. destructive capabilities (verb-based + parameter-based)
  if (tools.length > 0) {
    const dest = findDestructive(tools);
    const writes = findWrite(tools);
    const dangerousParams = findDangerousParams(tools);
    const ratio = dest.length / tools.length;

    // Combine verb-based and parameter-based findings
    const highRiskParams = dangerousParams.filter((p) => p.level === "high");
    const mediumRiskParams = dangerousParams.filter((p) => p.level === "medium");

    if (dest.length > 0) {
      const dScore = ratio > 0.3 ? 3 : ratio > 0.15 ? 5 : 7;
      // Further penalize if high-risk params found
      const paramPenalty = highRiskParams.length > 0 ? 2 : 0;
      report.checks.destructive = {
        status: "WARN",
        detail: `${dest.length}/${tools.length} destructive tool(s): ${dest.slice(0, 3).map((d) => d.name).join(", ")}${dest.length > 3 ? "…" : ""}${dangerousParams.length > 0 ? `; ${dangerousParams.length} dangerous param(s)` : ""}`,
        score: Math.max(0, dScore - paramPenalty), max: 10,
      };
    } else if (highRiskParams.length > 0) {
      // No destructive verbs, but dangerous parameters detected
      report.checks.destructive = {
        status: "WARN",
        detail: `${highRiskParams.length} high-risk param(s): ${highRiskParams.slice(0, 3).map((p) => `${p.tool}.${p.param} (${p.risk})`).join(", ")}${highRiskParams.length > 3 ? "…" : ""}`,
        score: 5, max: 10,
      };
    } else if (writes.length > 0 || mediumRiskParams.length > 0) {
      const detailParts = [];
      if (writes.length > 0) detailParts.push(`${writes.length} write/exec tool(s)`);
      if (mediumRiskParams.length > 0) detailParts.push(`${mediumRiskParams.length} medium-risk param(s)`);
      report.checks.destructive = {
        status: "PASS",
        detail: `no destructive verbs; ${detailParts.join(", ")}`,
        score: 8, max: 10,
      };
    } else {
      report.checks.destructive = { status: "PASS", detail: "read-only toolset, no dangerous params", score: 10, max: 10 };
    }

    // Store dangerous params in report for downstream consumers
    if (dangerousParams.length > 0) {
      report.dangerousParams = dangerousParams;
    }
  } else {
    const cfgScore = report.configRequired ? 5 : 3;
    const cfgDetail = report.configRequired
      ? "cannot enumerate — config required to start"
      : "no tools enumerated";
    report.checks.destructive = { status: "UNKNOWN", detail: cfgDetail, score: cfgScore, max: 10 };
  }

  // 5. authentication
  const descText = `${install.meta?.description ?? ""} ${client.stderr ?? ""} ${(initResult?.serverInfo?.name ?? "")} ${isLocal ? specStr : ""}`.toLowerCase();
  const authHit = AUTH_HINTS.find((h) => descText.includes(h));
  if (authHit || report.configRequired) {
    report.checks.authentication = {
      status: "REQUIRED",
      detail: report.configRequired
        ? `server correctly requires config/credentials to start`
        : `auth hint detected ("${authHit}")`,
      score: 10, max: 10,
    };
  } else if (handshakeOk && tools.length > 0) {
    report.checks.authentication = {
      status: "PASS",
      detail: "no auth required to list tools",
      score: 7, max: 10,
    };
  } else {
    report.checks.authentication = { status: "UNKNOWN", detail: "could not determine auth posture", score: 5, max: 10 };
  }

  // 6. secret exposure
  const texts = [
    ...(tools.map((t) => t.description ?? "")),
    client.stderr,
    handshakeErr ?? "",
  ];
  const sec = scanSecrets(texts);
  if (sec.leaked) {
    report.checks.secretExposure = {
      status: "FAIL", detail: `possible secret in output: ${sec.sample}`,
      score: 0, max: 10,
    };
  } else if (tools.length > 0 || handshakeOk) {
    report.checks.secretExposure = { status: "UNKNOWN", detail: "no secrets seen in this run (single probe)", score: 5, max: 10 };
  } else {
    report.checks.secretExposure = { status: "UNKNOWN", detail: "no data to scan", score: 3, max: 10 };
  }

  // 7. protocol version
  if (report.protocolVersion === LATEST_PROTOCOL) {
    report.checks.protocol = { status: "PASS", detail: `negotiated ${report.protocolVersion} (latest)`, score: 10, max: 10 };
  } else if (report.protocolVersion) {
    report.checks.protocol = { status: "WARN", detail: `negotiated ${report.protocolVersion} (latest is ${LATEST_PROTOCOL})`, score: 6, max: 10 };
  } else {
    const cfgScore = report.configRequired ? 5 : 0;
    const cfgDetail = report.configRequired
      ? "cannot negotiate — config required to start"
      : "no protocol version negotiated";
    report.checks.protocol = { status: "UNKNOWN", detail: cfgDetail, score: cfgScore, max: 10 };
  }

  // 8. latency & failure rate (3 quick pings)
  if (handshakeOk) {
    let ok = 0;
    let totalLat = 0;
    const pings = 3;
    for (let i = 0; i < pings; i++) {
      try {
        const a = Date.now();
        await client.request("tools/list", {}, 8_000);
        totalLat += Date.now() - a;
        ok++;
      } catch {}
    }
    report.failureRate = (pings - ok) / pings;
    report.avgLatencyMs = ok ? Math.round(totalLat / ok) : null;
    if (report.failureRate === 0 && report.avgLatencyMs < 500) {
      report.checks.latency = { status: "PASS", detail: `${report.avgLatencyMs}ms avg, 0% failure`, score: 5, max: 5 };
    } else if (report.failureRate === 0) {
      report.checks.latency = { status: "WARN", detail: `${report.avgLatencyMs}ms avg, 0% failure`, score: 3, max: 5 };
    } else {
      report.checks.latency = { status: "FAIL", detail: `${Math.round(report.failureRate * 100)}% failure across ${pings} pings`, score: 1, max: 5 };
    }
  } else {
    const cfgScore = report.configRequired ? 2 : 0;
    const cfgDetail = report.configRequired
      ? "cannot measure — config required to start"
      : "no handshake";
    report.checks.latency = { status: "UNKNOWN", detail: cfgDetail, score: cfgScore, max: 5 };
  }

  await client.stop();

  // total score
  report.score = Object.values(report.checks).reduce((s, c) => s + (c.score || 0), 0);
  report.max = Object.values(report.checks).reduce((s, c) => s + (c.max || 0), 0);
  return report;
}
