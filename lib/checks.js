// Scorecard checks for an MCP server spec.
// Each check returns { status: "PASS"|"WARN"|"FAIL"|"UNKNOWN", detail, score, max }.
import { exec as execCb } from "node:child_process";
import { promisify } from "node:util";
import { McpStdioClient, PROTOCOL_VERSIONS } from "./client.js";

const exec = promisify(execCb);

const LATEST_PROTOCOL = PROTOCOL_VERSIONS[0];

// --- heuristics -------------------------------------------------------------
const DESTRUCTIVE_VERBS = [
  "delete", "remove", "drop", "rm", "kill", "destroy", "truncate",
  "overwrite", "purge", "wipe", "force", "reset", "uninstall", "disable",
];
const WRITE_VERBS = [
  "write", "create", "update", "insert", "upsert", "push", "post", "put",
  "execute", "exec", "run", "send", "submit", "apply", "set", "install",
  "deploy", "merge", "commit", "edit", "modify", "patch",
];
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

function findDestructive(tools) {
  const hits = [];
  for (const t of tools) {
    const text = `${t.name} ${t.description ?? ""}`.toLowerCase();
    for (const v of DESTRUCTIVE_VERBS) {
      if (text.includes(v)) { hits.push({ name: t.name, verb: v }); break; }
    }
  }
  return hits;
}

function findWrite(tools) {
  const hits = [];
  for (const t of tools) {
    const text = `${t.name} ${t.description ?? ""}`.toLowerCase();
    for (const v of WRITE_VERBS) {
      if (text.includes(v)) { hits.push({ name: t.name, verb: v }); break; }
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

// --- npm installability -----------------------------------------------------
async function checkInstallability(spec) {
  try {
    const { stdout } = await exec(`npm view ${JSON.stringify(spec)} name version description.bin --json`, {
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
export async function runHealthcheck(spec, opts = {}) {
  const report = {
    spec,
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

  // 1. installability
  const install = await checkInstallability(spec);
  report.checks.installability = install;

  // Resolve the executable command. Prefer the package's own bin; fall back to npx.
  let cmd = "npx";
  let args = ["-y", spec];
  if (install.meta?.bin && typeof install.meta.bin === "object") {
    const firstBin = Object.values(install.meta.bin)[0];
    // still use npx to run the package bin without a global install
    args = ["-y", spec];
    cmd = "npx";
  }

  // 2. protocol handshake + tools
  const client = new McpStdioClient({ cmd, args, env: opts.env ?? {}, spawnTimeout: 45_000 });
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

  // 4. destructive capabilities
  if (tools.length > 0) {
    const dest = findDestructive(tools);
    const writes = findWrite(tools);
    const ratio = dest.length / tools.length;
    if (dest.length > 0) {
      const dScore = ratio > 0.3 ? 3 : ratio > 0.15 ? 5 : 7;
      report.checks.destructive = {
        status: "WARN",
        detail: `${dest.length}/${tools.length} destructive tool(s): ${dest.slice(0, 3).map((d) => d.name).join(", ")}${dest.length > 3 ? "…" : ""}`,
        score: dScore, max: 10,
      };
    } else if (writes.length > 0) {
      report.checks.destructive = {
        status: "PASS",
        detail: `no destructive verbs; ${writes.length} write/exec tool(s)`,
        score: 8, max: 10,
      };
    } else {
      report.checks.destructive = { status: "PASS", detail: "read-only toolset", score: 10, max: 10 };
    }
  } else {
    const cfgScore = report.configRequired ? 5 : 3;
    const cfgDetail = report.configRequired
      ? "cannot enumerate — config required to start"
      : "no tools enumerated";
    report.checks.destructive = { status: "UNKNOWN", detail: cfgDetail, score: cfgScore, max: 10 };
  }

  // 5. authentication
  const descText = `${install.meta?.description ?? ""} ${client.stderr ?? ""} ${(initResult?.serverInfo?.name ?? "")}`.toLowerCase();
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
