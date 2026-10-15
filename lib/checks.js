// Scorecard checks for an MCP server spec.
// Each check returns { status: "PASS"|"WARN"|"FAIL"|"UNKNOWN", detail, score, max }.
// UNKNOWN means "could not assess" — it never earns score credit and never
// renders as a green PASS badge.
import { McpStdioClient, PROTOCOL_VERSIONS } from "./client.js";
import { McpHttpClient } from "./client-http.js";
import { analyzeAllTools, analyzeTool } from "./danger-detector.js";
import { npmView, probeBin, isNpmSpec, NPX_BIN_CANDIDATES } from "./npm.js";
import { TRUSTCARD_VERSION } from "./version.js";

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

/**
 * Classify the specific failure mode from stderr/handshake error text.
 * Used for declaration-vs-observation analysis to distinguish:
 * - missing env var
 * - missing argument
 * - authentication failure
 * - runtime crash
 * - transport failure
 * - timeout
 * - unknown
 */
function classifyFailure(failText) {
  // Check for environment variable specific hints
  if (/env(?:ironment)?\s*(?:var(?:iable)?)?|set\s+\w+_\w+|_\w+\s+env/i.test(failText)) {
    return 'missing_env_var';
  }
  // Check for API key / token / credential specific hints
  if (/api.?key|token|credential|secret|password|auth/i.test(failText)) {
    return 'missing_auth';
  }
  // Check for argument/flag specific hints
  if (/--\w+|argument|flag|usage:|command.?line/i.test(failText)) {
    return 'missing_argument';
  }
  // Check for connection/transport errors
  if (/econnrefused|econnreset|timeout|timed.?out|connection.?refused|connection.?reset|unreachable/i.test(failText)) {
    return 'transport_failure';
  }
  // Check for crash/error/exception
  if (/error|exception|crash|fatal|segfault|panic|throw/i.test(failText)) {
    return 'runtime_crash';
  }
  // Check for not found / missing module
  if (/not.?found|cannot.?find|module.?not.?found|enoent/i.test(failText)) {
    return 'package_not_found';
  }
  return 'unknown';
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
  // The spec is validated and passed to npm as an argv element — it never
  // reaches a shell, so command substitutions and backticks stay literal.
  if (!isNpmSpec(spec)) {
    return {
      status: "FAIL",
      detail: `invalid npm package spec (expected [scope/]name[@version]): ${String(spec).slice(0, 80)}`,
      score: 0, max: 15,
      meta: { invalidSpec: true },
    };
  }
  try {
    const info = await npmView(spec, ["name", "version", "description", "bin", "deprecated"]);
    const hasBin = info.bin && Object.keys(info.bin).length > 0;
    const isDeprecated = info.deprecated;

    if (isDeprecated) {
      return {
        status: "WARN",
        detail: `${info.name}@${info.version} (DEPRECATED: ${info.deprecated})`,
        score: 10, max: 15,
        meta: { name: info.name, version: info.version, description: info.description, bin: info.bin, deprecated: info.deprecated },
      };
    }

    if (!hasBin) {
      return {
        status: "WARN",
        detail: `${info.name}@${info.version} (no bin — may be a library or HTTP server, not stdio-runnable)`,
        score: 10, max: 15,
        meta: { name: info.name, version: info.version, description: info.description, bin: info.bin, noBin: true },
      };
    }

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
  const isRemote = typeof spec === "string" && /^https?:\/\//i.test(spec);
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

  if (isRemote) {
    return runRemoteHealthcheck(spec, opts, report);
  }

  // 1. installability (npm packages only — local commands skip this check)
  // UNKNOWN carries zero credit: a skipped check is not affirmative evidence.
  let install = { status: "UNKNOWN", detail: "local command — installability check skipped", score: 0, max: 15 };
  let cmd, args, cwd;
  let skipHandshake = false;
  if (isLocal) {
    cmd = spec.cmd;
    args = spec.args ?? [];
    cwd = spec.cwd;
  } else {
    install = await checkInstallability(spec);
    // If the package has no bin, npx can't run it — skip handshake
    if (install.meta?.noBin) {
      skipHandshake = true;
      report.configRequired = true;
      report.configReason = "no bin field — package is a library or HTTP server, not stdio-runnable via npx";
    }
    if (install.meta?.invalidSpec) {
      // An invalid spec must never reach npx — it could be re-read as an
      // npx flag even though it can't reach a shell.
      skipHandshake = true;
      report.invalidSpec = true;
      report.configReason = null;
    }
    cmd = await probeBin(NPX_BIN_CANDIDATES);
    args = ["-y", spec];
  }
  report.checks.installability = install;

  // 2. protocol handshake + tools
  // Local specs may carry their own env (config-driven scans); merge with any
  // env supplied as an option — opts wins on key conflicts.
  const childEnv = { ...(isLocal ? spec.env ?? {} : {}), ...(opts.env ?? {}) };
  const client = new McpStdioClient({ cmd, args, env: childEnv, spawnTimeout: 45_000, cwd });
  const t0 = Date.now();
  let handshakeOk = false;
  let initResult = null;
  let handshakeErr = null;

  if (skipHandshake) {
    if (report.invalidSpec) {
      // Invalid spec: refused to invoke npx at all — this is a hard FAIL, not
      // a "needs config" situation.
      report.checks.handshake = {
        status: "FAIL",
        detail: "refused to spawn — spec is not a valid npm package name",
        score: 0, max: 25,
      };
    } else {
      // Package has no bin — can't run via npx. Mark as CONFIG (known issue).
      report.checks.handshake = {
        status: "CONFIG",
        detail: report.configReason,
        score: 12, max: 25,
      };
    }
  } else {
  try {
    await client.start();
    initResult = await client.request("initialize", {
      protocolVersion: LATEST_PROTOCOL,
      capabilities: {},
      clientInfo: { name: "mcp-trustcard", version: TRUSTCARD_VERSION },
    }, 15_000);
    handshakeOk = true;
    client.notify("notifications/initialized", {});
    report.latencyMs = Date.now() - t0;
    report.serverInfo = initResult?.serverInfo ?? null;
    report.protocolVersion = initResult?.protocolVersion ?? null;
    report.capabilities = initResult?.capabilities ?? null;
  } catch (e) {
    handshakeErr = e.message || String(e);
  }
  } // end else (not skipHandshake)

  if (handshakeOk) {
    const lat = report.latencyMs;
    const hStatus = lat < 1500 ? "PASS" : lat < 3000 ? "PASS" : "WARN";
    const hScore = lat < 1500 ? 25 : lat < 3000 ? 21 : 17;
    report.checks.handshake = {
      status: hStatus,
      detail: `${report.serverInfo?.name ?? "server"} ${report.serverInfo?.version ?? ""} · ${lat}ms`,
      score: hScore, max: 25,
    };
  } else if (!skipHandshake) {
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
      // Classify the specific failure mode for declaration-vs-observation analysis
      report.failureMode = classifyFailure(failText);
    } else {
      report.checks.handshake = {
        status: "FAIL",
        detail: handshakeErr.slice(0, 160),
        score: 0, max: 25,
      };
      report.failureMode = classifyFailure(failText);
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
    report.checks.schema = { status: "UNKNOWN", detail: "no tools exposed or tools/list unsupported", score: 0, max: 15 };
  } else if (!handshakeOk && !report.checks.schema) {
    const cfgDetail = report.configRequired
      ? "cannot enumerate — config required to start"
      : "handshake failed; could not enumerate tools";
    report.checks.schema = { status: "UNKNOWN", detail: cfgDetail, score: 0, max: 15 };
  }

  // 4. destructive capabilities (fusion: heuristic + semantic AI)
  if (tools.length > 0) {
    const analysis = analyzeAllTools(tools);
    const dangerous = analysis.dangerous;
    const highConf = analysis.highConfidenceCount;
    const ratio = dangerous.length / tools.length;

    if (dangerous.length > 0) {
      const detailParts = [
        `${dangerous.length}/${tools.length} dangerous tool(s)`,
      ];
      if (highConf > 0) detailParts.push(`${highConf} high-confidence (AI+heuristic)`);
      // Show top reasons from the most dangerous tool
      if (dangerous[0]?.reasons?.length > 0) {
        detailParts.push(dangerous[0].reasons.slice(0, 2).join("; "));
      }
      // High-confidence detections or a high dangerous-tool ratio are a hard
      // FAIL — capability to delete/exec is not a "warn", it is the primary
      // thing this scorecard exists to surface. Lower-signal hits stay WARN.
      if (highConf > 0 || ratio > 0.3) {
        report.checks.destructive = {
          status: "FAIL",
          detail: detailParts.join("; "),
          score: 0, max: 10,
        };
      } else {
        report.checks.destructive = {
          status: "WARN",
          detail: detailParts.join("; "),
          score: ratio > 0.15 ? 2 : 4, max: 10,
        };
      }
    } else {
      // Check if any tools have write verbs but weren't flagged as dangerous
      const writes = findWrite(tools);
      if (writes.length > 0) {
        report.checks.destructive = {
          status: "PASS",
          detail: `no dangerous tools detected (AI fusion); ${writes.length} write/exec tool(s)`,
          score: 8, max: 10,
        };
      } else {
        report.checks.destructive = {
          status: "PASS",
          detail: "no dangerous tools detected (AI fusion + heuristic)",
          score: 10, max: 10,
        };
      }
    }

    // Store full analysis for downstream consumers
    report.dangerAnalysis = analysis;
    report.dangerousParams = analysis.tools
      .filter(t => t.analysis.heuristic.dangerousParams.length > 0)
      .flatMap(t => t.analysis.heuristic.dangerousParams.map(p => ({
        tool: t.name, param: p,
      })));
  } else {
    const cfgDetail = report.configRequired
      ? "cannot enumerate — config required to start"
      : "no tools enumerated";
    report.checks.destructive = { status: "UNKNOWN", detail: cfgDetail, score: 0, max: 10 };
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
    // We observed an unauthenticated tools/list — that is a finding, not a
    // clean bill of health. Anyone who can reach the server can enumerate and
    // call every tool. WARN, not a green PASS.
    report.checks.authentication = {
      status: "WARN",
      detail: "no auth required to enumerate and call tools — any caller with transport access can invoke them",
      score: 3, max: 10,
    };
  } else {
    report.checks.authentication = { status: "UNKNOWN", detail: "could not determine auth posture", score: 0, max: 10 };
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
    report.checks.secretExposure = { status: "UNKNOWN", detail: "no secrets seen in this run (single probe)", score: 0, max: 10 };
  } else {
    report.checks.secretExposure = { status: "UNKNOWN", detail: "no data to scan", score: 0, max: 10 };
  }

  // 7. protocol version
  if (report.protocolVersion === LATEST_PROTOCOL) {
    report.checks.protocol = { status: "PASS", detail: `negotiated ${report.protocolVersion} (latest)`, score: 10, max: 10 };
  } else if (report.protocolVersion) {
    report.checks.protocol = { status: "WARN", detail: `negotiated ${report.protocolVersion} (latest is ${LATEST_PROTOCOL})`, score: 6, max: 10 };
  } else {
    const cfgDetail = report.configRequired
      ? "cannot negotiate — config required to start"
      : "no protocol version negotiated";
    report.checks.protocol = { status: "UNKNOWN", detail: cfgDetail, score: 0, max: 10 };
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
    const cfgDetail = report.configRequired
      ? "cannot measure — config required to start"
      : "no handshake";
    report.checks.latency = { status: "UNKNOWN", detail: cfgDetail, score: 0, max: 5 };
  }

  await client.stop();

  // total score
  report.score = Object.values(report.checks).reduce((s, c) => s + (c.score || 0), 0);
  report.max = Object.values(report.checks).reduce((s, c) => s + (c.max || 0), 0);
  return report;
}

// --- remote (HTTP/SSE) healthcheck -------------------------------------------
// Scans a remote MCP server via the streamable-http or SSE transport.
// Reuses the same check structure as the stdio healthcheck but skips
// installability (remote servers don't need npm installation).
async function runRemoteHealthcheck(url, opts, report) {
  const transport = opts.transport || "streamable-http";
  const headers = opts.headers || {};

  // 1. installability — N/A for remote servers. SKIPPED, not PASS: nothing
  // was verified, so no credit is earned.
  report.checks.installability = {
    status: "SKIPPED",
    detail: "remote server — no installation required",
    score: 0,
    max: 15,
  };

  // 2. protocol handshake + tools
  const client = new McpHttpClient({ url, transport, headers, timeout: 30_000 });
  const t0 = Date.now();
  let handshakeOk = false;
  let initResult = null;
  let handshakeErr = null;

  try {
    await client.start();

    for (const v of PROTOCOL_VERSIONS) {
      try {
        initResult = await client.request("initialize", {
          protocolVersion: v,
          capabilities: {},
          clientInfo: { name: "mcp-trustcard", version: TRUSTCARD_VERSION },
        }, 15_000);
        handshakeOk = true;
        break;
      } catch (e) {
        handshakeErr = e;
      }
    }

    if (handshakeOk) {
      await client.notify("notifications/initialized", {});
      report.checks.handshake = {
        status: "PASS",
        detail: `negotiated ${initResult.protocolVersion}`,
        score: 25,
        max: 25,
      };
      report.serverInfo = initResult.serverInfo ?? null;
      report.protocolVersion = initResult.protocolVersion ?? null;
      report.capabilities = initResult.capabilities ?? null;

      // 3. tools/list + schema validation
      let tools = [];
      try {
        const res = await client.request("tools/list", {}, 10_000);
        tools = Array.isArray(res?.tools) ? res.tools : [];
      } catch (e) {
        // some servers don't support tools/list
      }
      report.tools = tools;

      if (tools.length > 0) {
        const v = validateToolSchema(tools);
        report.checks.schema = v.valid
          ? { status: "PASS", detail: `${tools.length} tools, all schemas valid`, score: 15, max: 15 }
          : { status: "WARN", detail: `${v.errors.length} schema issues: ${v.errors.slice(0, 2).join("; ")}`, score: 8, max: 15 };
      } else {
        report.checks.schema = { status: "UNKNOWN", detail: "no tools exposed or tools/list unsupported", score: 0, max: 15 };
      }

      // 4. destructive capabilities
      if (tools.length > 0) {
        const danger = analyzeAllTools(tools);
        const dangerous = danger.dangerous || [];
        const highConf = danger.highConfidenceCount ?? 0;
        const ratio = dangerous.length / tools.length;
        if (dangerous.length === 0) {
          report.checks.destructive = { status: "PASS", detail: "no destructive tools detected", score: 10, max: 10 };
        } else {
          const names = dangerous.slice(0, 3).map(d => d.name).join(", ");
          const detail = `${dangerous.length}/${tools.length} potentially destructive: ${names}${highConf > 0 ? ` (${highConf} high-confidence)` : ""}`;
          if (highConf > 0 || ratio > 0.3) {
            report.checks.destructive = { status: "FAIL", detail, score: 0, max: 10 };
          } else {
            report.checks.destructive = { status: "WARN", detail, score: 4, max: 10 };
          }
        }
      } else {
        report.checks.destructive = { status: "UNKNOWN", detail: "no tools to analyze", score: 0, max: 10 };
      }

      // 5. authentication posture
      const descText = `${initResult.serverInfo?.name ?? ""} ${client.stderr}`.toLowerCase();
      const hasAuthHint = AUTH_HINTS.some(h => descText.includes(h));
      const needsHeaders = (url && headers && Object.keys(headers).length > 0);
      if (hasAuthHint || needsHeaders) {
        report.checks.authentication = { status: "PASS", detail: "auth detected/configured", score: 10, max: 10 };
      } else {
        // Open endpoint observed serving tools without credentials — a
        // finding, not a clean PASS.
        report.checks.authentication = { status: "WARN", detail: "no auth required (open endpoint) — any caller can invoke tools", score: 3, max: 10 };
      }

      // 6. secret exposure (check tool descriptions for secrets)
      if (tools.length > 0) {
        const secretResult = scanSecrets(tools.flatMap(t => [t.description, JSON.stringify(t.inputSchema)].filter(Boolean)));
        if (!secretResult.leaked) {
          report.checks.secretExposure = { status: "PASS", detail: "no secrets detected in tool output", score: 10, max: 10 };
        } else {
          report.checks.secretExposure = { status: "FAIL", detail: `potential secret: ${secretResult.pattern?.slice(0, 40)}`, score: 0, max: 10 };
        }
      } else {
        report.checks.secretExposure = { status: "UNKNOWN", detail: "no tools to scan", score: 0, max: 10 };
      }

      // 7. protocol version
      const pv = initResult.protocolVersion;
      if (pv === LATEST_PROTOCOL) {
        report.checks.protocol = { status: "PASS", detail: `latest (${pv})`, score: 10, max: 10 };
      } else if (pv) {
        report.checks.protocol = { status: "WARN", detail: `lags latest (${pv} vs ${LATEST_PROTOCOL})`, score: 6, max: 10 };
      } else {
        report.checks.protocol = { status: "UNKNOWN", detail: "no protocol version reported", score: 0, max: 10 };
      }

      // 8. latency
      const elapsed = Date.now() - t0;
      report.latencyMs = elapsed;
      if (elapsed < 2000) {
        report.checks.latency = { status: "PASS", detail: `${elapsed}ms`, score: 5, max: 5 };
      } else if (elapsed < 5000) {
        report.checks.latency = { status: "WARN", detail: `${elapsed}ms`, score: 3, max: 5 };
      } else {
        report.checks.latency = { status: "FAIL", detail: `${elapsed}ms`, score: 1, max: 5 };
      }

    } else {
      // Handshake failed
      const errDetail = handshakeErr?.message ?? "unknown error";
      const isConfig = CONFIG_HINTS.some(h => errDetail.toLowerCase().includes(h));
      report.checks.handshake = {
        status: isConfig ? "CONFIG" : "FAIL",
        detail: errDetail.slice(0, 200),
        score: isConfig ? 12 : 0,
        max: 25,
      };
      report.checks.schema = { status: "UNKNOWN", detail: "handshake failed", score: 0, max: 15 };
      report.checks.destructive = { status: "UNKNOWN", detail: "handshake failed", score: 0, max: 10 };
      report.checks.authentication = { status: "UNKNOWN", detail: "handshake failed", score: 0, max: 10 };
      report.checks.secretExposure = { status: "UNKNOWN", detail: "handshake failed", score: 0, max: 10 };
      report.checks.protocol = { status: "UNKNOWN", detail: "handshake failed", score: 0, max: 10 };
      report.checks.latency = { status: "UNKNOWN", detail: "handshake failed", score: 0, max: 5 };
    }
  } catch (e) {
    report.checks.handshake = { status: "FAIL", detail: e.message?.slice(0, 200), score: 0, max: 25 };
    report.checks.schema = { status: "UNKNOWN", detail: "connection error", score: 0, max: 15 };
    report.checks.destructive = { status: "UNKNOWN", detail: "connection error", score: 0, max: 10 };
    report.checks.authentication = { status: "UNKNOWN", detail: "connection error", score: 0, max: 10 };
    report.checks.secretExposure = { status: "UNKNOWN", detail: "connection error", score: 0, max: 10 };
    report.checks.protocol = { status: "UNKNOWN", detail: "connection error", score: 0, max: 10 };
    report.checks.latency = { status: "UNKNOWN", detail: "connection error", score: 0, max: 5 };
  } finally {
    await client.stop();
  }

  report.score = Object.values(report.checks).reduce((s, c) => s + (c.score || 0), 0);
  report.max = Object.values(report.checks).reduce((s, c) => s + (c.max || 0), 0);
  return report;
}
