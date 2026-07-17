#!/usr/bin/env node
// mcp-trustcard — the "npm audit" for MCP servers.
import { runHealthcheck } from "../lib/checks.js";
import { scanConfigForSecrets } from "../lib/checks.js";
import { buildManifest } from "../lib/manifest.js";
import { McpStdioClient, PROTOCOL_VERSIONS } from "../lib/client.js";
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { exec as execCb } from "node:child_process";
import { promisify } from "node:util";

const exec = promisify(execCb);

function usage() {
  console.log(`mcp-trustcard — a trust card for any MCP server

Usage:
  mcp-trustcard <npm-package-or-spec>
  mcp-trustcard -- <cmd> [args...]          # scan a local command (non-npm)
  mcp-trustcard --batch <servers.json> [--json-out results.json]
  mcp-trustcard --json <spec>              # machine-readable single report
  mcp-trustcard scan <spec> --save-manifest <file>   # scan + save tool manifest
  mcp-trustcard scan -- <cmd> [args...] --save-manifest <file>  # local cmd manifest
  mcp-trustcard scan-config <config.json>   # scan MCP config for exposed secrets

Examples:
  npx mcp-trustcard @modelcontextprotocol/server-github
  mcp-trustcard --env-file .env -- uv run maos mcp serve  # inject env vars
  mcp-trustcard --batch servers/official.json --json-out results.json
  mcp-trustcard scan @modelcontextprotocol/server-memory --save-manifest memory.json
  mcp-trustcard scan -- uv run maos mcp serve --save-manifest maos.json
  mcp-proxy --manifest memory.json -- npx -y @modelcontextprotocol/server-memory

Options:
  --batch <file>      JSON array of specs { spec, env? } or { cmd, args, env? } to scan
  --json-out <file>   write batch results as JSON
  --json              emit single report as JSON instead of text
  --save-manifest <file>  save approved tool manifest (for proxy enforcement)
  --env-file <file>   load env vars from a .env file (KEY=value lines) and inject into the scanned server
  --cwd <dir>         working directory for local command (use with -- <cmd>)
  --no-color          disable ANSI colors
  -h, --help          show this help
`);
}

// Parse a .env file and return a map of KEY -> value
function parseEnvFile(path) {
  const text = readFileSync(path, "utf8");
  const env = {};
  for (const line of text.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const eqIdx = trimmed.indexOf("=");
    if (eqIdx === -1) continue;
    const key = trimmed.slice(0, eqIdx).trim();
    let val = trimmed.slice(eqIdx + 1).trim();
    // Strip surrounding quotes
    if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
      val = val.slice(1, -1);
    }
    env[key] = val;
  }
  return env;
}

// Parse a -- separator from args, returning everything after it as cmd + args.
// Returns { cmd, args } or null if no -- separator found.
function parseLocalCommand(argList) {
  const dashIdx = argList.indexOf("--");
  if (dashIdx === -1 || !argList[dashIdx + 1]) return null;
  return {
    cmd: argList[dashIdx + 1],
    args: argList.slice(dashIdx + 2),
  };
}

// Generate a tool manifest by connecting to the server, listing tools,
// and hashing their schemas. Used by the proxy for call-time enforcement.
// spec can be a string (npm) or { cmd, args, spec? } (local command).
async function generateManifest(spec, outFile, env = {}) {
  const isLocal = typeof spec === "object" && spec !== null;
  let cmd, args, specStr, cwd;

  if (isLocal) {
    cmd = spec.cmd;
    args = spec.args ?? [];
    specStr = spec.spec ?? `${cmd} ${args.join(" ")}`;
    cwd = spec.cwd;
  } else {
    // Try to find a working npm — the mise-managed npm may be broken
    const npmCandidates = ["npm", "/opt/homebrew/bin/npm", "/usr/local/bin/npm"];
    let npmBin = "npm";
    for (const candidate of npmCandidates) {
      try {
        await exec(`${candidate} --version`, { timeout: 5_000, env: process.env });
        npmBin = candidate;
        break;
      } catch {}
    }
    const { stdout } = await exec(`${npmBin} view ${JSON.stringify(spec)} name version bin --json`, {
      timeout: 30_000, env: process.env,
    });
    JSON.parse(stdout); // verify it resolves
    cmd = "npx";
    args = ["-y", spec];
    specStr = spec;
  }

  const client = new McpStdioClient({
    cmd, args,
    env,
    spawnTimeout: 45_000,
    cwd,
  });

  try {
    await client.start();
    const init = await client.request("initialize", {
      protocolVersion: PROTOCOL_VERSIONS[0],
      capabilities: {},
      clientInfo: { name: "mcp-trustcard", version: "0.3.0" },
    }, 15_000);
    client.notify("notifications/initialized", {});

    const res = await client.request("tools/list", {}, 10_000);
    const tools = Array.isArray(res?.tools) ? res.tools : [];

    const manifest = buildManifest(tools, init?.serverInfo ?? null, specStr);
    writeFileSync(outFile, JSON.stringify(manifest, null, 2));

    console.log(`Manifest saved: ${outFile}`);
    console.log(`  Server: ${manifest.serverInfo?.name ?? specStr}`);
    console.log(`  Tools:  ${manifest.tools.length}`);
    console.log(`  Hash:   ${manifest.manifestHash}`);
    for (const t of manifest.tools) {
      console.log(`    ${t.name.padEnd(32)} schema=${t.schemaHash}`);
    }
    return manifest;
  } finally {
    await client.stop();
  }
}

const args = process.argv.slice(2);
const noColor = args.includes("--no-color");
const c = (code, s) => (noColor ? s : `\x1b[${code}m${s}\x1b[0m`);
const green = (s) => c("32", s);
const yellow = (s) => c("33", s);
const red = (s) => c("31", s);
const blue = (s) => c("34", s);
const dim = (s) => c("2", s);
const bold = (s) => c("1", s);

function badge(status) {
  if (status === "PASS") return green("PASS");
  if (status === "WARN") return yellow("WARN");
  if (status === "CONFIG_REQUIRED") return blue("CONFIG");
  if (status === "REQUIRED") return blue("REQUIRED");
  if (status === "FAIL") return red("FAIL");
  return dim("UNKNOWN");
}

function printReport(r) {
  const name = r.serverInfo?.name ?? r.spec.split("/").pop();
  console.log("");
  console.log(`${bold("MCP Trustcard")}: ${bold(name)}  ${dim(r.spec)}`);
  console.log(dim("─".repeat(56)));
  const labels = {
    installability: "Installability",
    handshake: "Protocol handshake",
    schema: "Tool schema validity",
    destructive: "Destructive capabilities",
    authentication: "Authentication",
    secretExposure: "Secret exposure",
    protocol: "Protocol version",
    latency: "Latency & failure rate",
  };
  for (const key of Object.keys(labels)) {
    const chk = r.checks[key];
    if (!chk) continue;
    console.log(`${labels[key].padEnd(26)} ${badge(chk.status)}  ${dim(chk.detail ?? "")}`);
  }
  console.log(dim("─".repeat(56)));
  const scoreColor = r.score >= 75 ? green : r.score >= 50 ? yellow : red;
  console.log(`${"Score".padEnd(26)} ${scoreColor(bold(`${r.score}/${r.max}`))}`);
  if (r.tools?.length) console.log(`${dim(`Tools (${r.tools.length}):`)} ${r.tools.slice(0, 8).map((t) => t.name).join(", ")}${r.tools.length > 8 ? "…" : ""}`);
  console.log("");
}

async function main() {
  if (args.includes("-h") || args.includes("--help")) return usage();

  // Parse --cwd <dir>
  const cwdIdx = args.indexOf("--cwd");
  const cwd = cwdIdx !== -1 && args[cwdIdx + 1] ? args[cwdIdx + 1] : undefined;

  // Parse --env-file <file>
  const envFileIdx = args.indexOf("--env-file");
  let injectedEnv = {};
  if (envFileIdx !== -1 && args[envFileIdx + 1]) {
    const envFile = args[envFileIdx + 1];
    if (!existsSync(envFile)) {
      console.error(`--env-file: file not found: ${envFile}`);
      process.exit(2);
    }
    injectedEnv = parseEnvFile(envFile);
    process.stderr.write(`Loaded ${Object.keys(injectedEnv).length} env var(s) from ${envFile}\n`);
  }

  // scan-config subcommand: scan an MCP config file for exposed secrets
  if (args[0] === "scan-config") {
    const configArg = args[1];
    if (!configArg || !existsSync(configArg)) {
      console.error("scan-config: missing <config-file> or file not found");
      console.error("Usage: mcp-trustcard scan-config <path-to-config.json>");
      process.exit(2);
    }
    const configText = readFileSync(configArg, "utf8");
    const findings = scanConfigForSecrets(configText, configArg);
    if (findings.length === 0) {
      console.log(`${green("PASS")} No secrets detected in ${configArg}`);
      process.exit(0);
    } else {
      console.log(`${red("FAIL")} ${findings.length} potential secret(s) found in ${configArg}:`);
      for (const f of findings) {
        console.log(`  ${yellow("line " + f.line)} key=${bold(f.key)} pattern=${f.pattern}`);
        console.log(`    ${dim(f.sample)}`);
      }
      process.exit(1);
    }
  }

  // scan subcommand: generate a tool manifest for proxy enforcement
  if (args[0] === "scan") {
    let scanArgs = args.slice(1);
    const manifestIdx = scanArgs.indexOf("--save-manifest");
    const outFile = manifestIdx !== -1 ? scanArgs[manifestIdx + 1] : null;
    if (!outFile) { console.error("scan: missing --save-manifest <file>"); process.exit(2); }

    // Strip --save-manifest and --cwd and their values from scanArgs so they don't leak into the command
    if (manifestIdx !== -1) {
      scanArgs = scanArgs.filter((_, i) => i !== manifestIdx && i !== manifestIdx + 1);
    }
    const scanCwdIdx = scanArgs.indexOf("--cwd");
    if (scanCwdIdx !== -1) {
      scanArgs = scanArgs.filter((_, i) => i !== scanCwdIdx && i !== scanCwdIdx + 1);
    }

    // Check for -- <cmd> [args...] syntax
    const local = parseLocalCommand(scanArgs);
    if (local) {
      if (cwd) local.cwd = cwd;
      await generateManifest(local, outFile, injectedEnv);
      return;
    }

    // Otherwise: npm spec
    const spec = scanArgs.find((a) => !a.startsWith("-") && a !== "scan");
    if (!spec) { console.error("scan: missing <spec> or -- <cmd> [args...]"); process.exit(2); }
    await generateManifest(spec, outFile, injectedEnv);
    return;
  }

  const batchIdx = args.indexOf("--batch");
  const jsonOutIdx = args.indexOf("--json-out");
  const jsonFlag = args.includes("--json");

  if (batchIdx !== -1) {
    const file = args[batchIdx + 1];
    if (!file || !existsSync(file)) { console.error("missing --batch file"); process.exit(2); }
    const list = JSON.parse(readFileSync(file, "utf8"));
    const results = [];
    for (const entry of list) {
      let spec, env;
      if (typeof entry === "string") {
        spec = entry;
      } else if (entry.cmd) {
        spec = { cmd: entry.cmd, args: entry.args ?? [], spec: entry.spec };
        env = entry.env;
      } else {
        spec = entry.spec;
        env = entry.env;
      }
      const label = typeof spec === "object" ? `${spec.cmd} ${(spec.args ?? []).join(" ")}` : spec;
      process.stderr.write(`scanning ${label}...\n`);
      const r = await runHealthcheck(spec, { env });
      results.push(r);
      printReport(r);
    }
    if (jsonOutIdx !== -1) {
      writeFileSync(args[jsonOutIdx + 1], JSON.stringify(results, null, 2));
    }
    // summary table
    console.log(bold("\nSummary"));
    console.log("─".repeat(64));
    for (const r of results) {
      const name = (r.serverInfo?.name ?? r.spec.split("/").pop()).slice(0, 22);
      const sc = `${r.score}/${r.max}`;
      const scStr = r.score >= 75 ? green(sc) : r.score >= 50 ? yellow(sc) : red(sc);
      console.log(`${name.padEnd(24)} ${scStr.padEnd(10)} ${dim(r.spec)}`);
    }
    console.log("─".repeat(64));
    return;
  }

  // Check for -- <cmd> [args...] syntax (local command scan)
  const local = parseLocalCommand(args);
  if (local) {
    if (cwd) local.cwd = cwd;
    const r = await runHealthcheck(local, { env: injectedEnv });
    if (jsonFlag) console.log(JSON.stringify(r, null, 2));
    else printReport(r);
    process.exit(r.score >= 50 ? 0 : 1);
  }

  const spec = args.find((a) => !a.startsWith("-") && a !== (envFileIdx !== -1 ? args[envFileIdx + 1] : null));
  if (!spec) return usage();
  const r = await runHealthcheck(spec, { env: injectedEnv });
  if (jsonFlag) console.log(JSON.stringify(r, null, 2));
  else printReport(r);
  process.exit(r.score >= 50 ? 0 : 1);
}

main().catch((e) => { console.error("fatal:", e); process.exit(1); });
