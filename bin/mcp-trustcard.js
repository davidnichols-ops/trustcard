#!/usr/bin/env node
// mcp-trustcard — cryptographic trust infrastructure for MCP servers.
//
// Subcommands:
//   scan        empirical health scorecard (parallel batch, scan-config, CI modes)
//   gen-manifest  build a proxy-enforcement manifest (lib/manifest.js)
//   fingerprint full identity card: digests, provenance, pin continuity
//   manifest    build an unsigned crypto manifest from a live probe (lib/provenance.js)
//   keygen      generate a publisher Ed25519 keypair
//   sign        sign a manifest with a publisher key
//   verify      verify a signed manifest (+ optionally against a live probe)
//   diff        classify changes between two manifests/fingerprints
//   pin         trust-on-first-use: pin a server's observed identity
//   unpin       remove a server pin
//   pins        list the pin store
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { exec as execCb } from "node:child_process";
import { promisify } from "node:util";
import { runHealthcheck, scanConfigForSecrets } from "../lib/checks.js";
import { buildManifest as buildProxyManifest } from "../lib/manifest.js";
import { McpStdioClient, PROTOCOL_VERSIONS } from "../lib/client.js";
import { fingerprint } from "../lib/fingerprint.js";
import { observeServer } from "../lib/observe.js";
import { buildManifest, signManifest, verifyManifest, generatePublisherKeypair, bindingConsistency } from "../lib/provenance.js";
import { diffToolsets, CHANGE_LEVEL } from "../lib/diff.js";
import { PinStore } from "../lib/pin.js";
import { printFingerprint, printDiff } from "../lib/report.js";

const exec = promisify(execCb);

const argv = process.argv.slice(2);
const noColor = argv.includes("--no-color") || !process.stdout.isTTY;
const c = (code, s) => (noColor ? s : `\x1b[${code}m${s}\x1b[0m`);
const green = (s) => c("32", s);
const yellow = (s) => c("33", s);
const red = (s) => c("31", s);
const blue = (s) => c("34", s);
const dim = (s) => c("2", s);
const bold = (s) => c("1", s);

function flag(name) { return argv.includes(name); }
function opt(name, fallback = undefined) {
  const i = argv.indexOf(name);
  return i !== -1 ? argv[i + 1] : fallback;
}
function positional(skip = 1) {
  const VALUE_FLAGS = new Set(["--manifest", "--out", "--key", "--pins", "--spec", "--json-out", "--batch", "--env-file", "--cwd", "--save-manifest", "--threshold", "--parallel", "--timeout"]);
  const out = [];
  for (let i = skip; i < argv.length; i++) {
    const a = argv[i];
    if (VALUE_FLAGS.has(a)) { i++; continue; }
    if (a.startsWith("-")) continue;
    out.push(a);
  }
  return out;
}

function usage() {
  console.log(`mcp-trustcard — cryptographic trust infrastructure for MCP servers

Identity & provenance:
  mcp-trustcard fingerprint <spec> [--manifest m.json] [--json]
  mcp-trustcard manifest <spec> [--key pub.key.json] [--out m.json]
  mcp-trustcard keygen [--out publisher.key.json]
  mcp-trustcard sign <manifest.json> --key publisher.key.json [--out signed.json]
  mcp-trustcard verify <signed.json> [--spec <pkg>]
  mcp-trustcard diff <old.json> <new.json> [--verbose]

Continuity (TOFU pinning):
  mcp-trustcard pin <spec>          # trust-on-first-use
  mcp-trustcard unpin <serverKey>
  mcp-trustcard pins [--json]

Health scorecard (scanner):
  mcp-trustcard scan <spec> [--json]
  mcp-trustcard scan -- <cmd> [args...]        # scan a local command (non-npm)
  mcp-trustcard scan --batch servers.json [--json-out results.json] [--parallel n]
  mcp-trustcard scan-config <config.json>      # scan an MCP config for exposed secrets
  mcp-trustcard gen-manifest <spec> --save-manifest <file>   # proxy-enforcement manifest
  mcp-trustcard gen-manifest -- <cmd> [args...] --save-manifest <file> [--allow-tool <name>...]
  mcp-trustcard <spec>                         # shorthand for scan

Options: --json  --no-color  --pins <path>  --env-file <f>  --cwd <dir>
         --strict  --threshold <n>  --parallel <n>  -h/--help`);
}

function loadJson(path) { return JSON.parse(readFileSync(path, "utf8")); }

function badge(status) {
  if (status === "PASS") return green("PASS");
  if (status === "WARN") return yellow("WARN");
  if (status === "CONFIG_REQUIRED") return blue("CONFIG");
  if (status === "REQUIRED") return blue("REQUIRED");
  if (status === "FAIL") return red("FAIL");
  return dim("UNKNOWN");
}

function printHealth(r) {
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
  const name = r.serverInfo?.name ?? r.spec.split("/").pop();
  console.log("");
  console.log(`${bold("MCP Trustcard")}: ${bold(name)}  ${dim(r.spec)}`);
  console.log(dim("─".repeat(56)));
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
    if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
      val = val.slice(1, -1);
    }
    env[key] = val;
  }
  return env;
}

// Parse a -- separator from args, returning everything after it as cmd + args.
function parseLocalCommand(argList) {
  const dashIdx = argList.indexOf("--");
  if (dashIdx === -1 || !argList[dashIdx + 1]) return null;
  return { cmd: argList[dashIdx + 1], args: argList.slice(dashIdx + 2) };
}

// Resolve --env-file and --cwd once per invocation.
function runtimeOpts() {
  const cwd = opt("--cwd");
  const envFile = opt("--env-file");
  let injectedEnv = {};
  if (envFile) {
    if (!existsSync(envFile)) { console.error(`--env-file: file not found: ${envFile}`); process.exit(2); }
    injectedEnv = parseEnvFile(envFile);
    process.stderr.write(`Loaded ${Object.keys(injectedEnv).length} env var(s) from ${envFile}\n`);
  }
  return { cwd, injectedEnv };
}

// CI gating shared by single + batch scans.
function applyCi(results) {
  const strict = flag("--strict");
  const thresholdIdx = argv.indexOf("--threshold");
  const threshold = thresholdIdx !== -1 ? parseInt(argv[thresholdIdx + 1]) || 50 : 50;
  if (strict) {
    const failures = results.filter((r) => Object.values(r.checks).some((c) => c.status === "FAIL"));
    if (failures.length > 0) {
      console.error(red(`\n${failures.length} server(s) have FAIL checks — CI strict mode`));
      process.exit(1);
    }
  }
  const belowThreshold = results.filter((r) => r.score < threshold);
  if (belowThreshold.length > 0 && thresholdIdx !== -1) {
    console.error(red(`\n${belowThreshold.length} server(s) below threshold ${threshold} — CI threshold mode`));
    process.exit(1);
  }
  // default: exit non-zero if any server scores below the pass bar
  process.exit(results.every((r) => r.score >= 50) ? 0 : 1);
}

async function cmdScan() {
  const { cwd, injectedEnv } = runtimeOpts();
  const jsonOut = opt("--json-out");
  const batchIdx = argv.indexOf("--batch");

  async function scanOne(entry) {
    let spec, env;
    if (typeof entry === "string") spec = entry;
    else if (entry.cmd) { spec = { cmd: entry.cmd, args: entry.args ?? [], spec: entry.spec }; env = entry.env; }
    else { spec = entry.spec; env = entry.env; }
    if (typeof spec === "object" && cwd) spec.cwd = spec.cwd ?? cwd;
    const label = typeof spec === "object" ? `${spec.cmd} ${(spec.args ?? []).join(" ")}` : spec;
    process.stderr.write(`scanning ${label}...\n`);
    return runHealthcheck(spec, { env: { ...injectedEnv, ...(env ?? {}) } });
  }

  if (batchIdx !== -1) {
    const file = argv[batchIdx + 1];
    if (!file || !existsSync(file)) { console.error("missing --batch file"); process.exit(2); }
    const list = loadJson(file);
    const parallelIdx = argv.indexOf("--parallel");
    const parallel = parallelIdx !== -1 ? parseInt(argv[parallelIdx + 1]) || 5 : 1;
    const results = [];

    if (parallel > 1) {
      const queue = [...list];
      const workers = [];
      for (let w = 0; w < parallel; w++) {
        workers.push((async () => {
          while (queue.length > 0) {
            const entry = queue.shift();
            if (!entry) break;
            const r = await scanOne(entry);
            results.push(r);
            printHealth(r);
          }
        })());
      }
      await Promise.all(workers);
    } else {
      for (const entry of list) {
        const r = await scanOne(entry);
        results.push(r);
        printHealth(r);
      }
    }

    if (jsonOut) writeFileSync(jsonOut, JSON.stringify(results, null, 2));
    // summary table
    console.log(bold("\nSummary"));
    console.log("─".repeat(64));
    for (const r of results) {
      const name = (r.serverInfo?.name ?? String(r.spec).split("/").pop()).slice(0, 22);
      const sc = `${r.score}/${r.max}`;
      const scStr = r.score >= 75 ? green(sc) : r.score >= 50 ? yellow(sc) : red(sc);
      console.log(`${name.padEnd(24)} ${scStr.padEnd(10)} ${dim(String(r.spec))}`);
    }
    console.log("─".repeat(64));
    applyCi(results);
    return;
  }

  // local command via `-- <cmd> [args...]`
  const local = parseLocalCommand(argv.slice(1));
  if (local) {
    if (cwd) local.cwd = cwd;
    const r = await runHealthcheck(local, { env: injectedEnv });
    if (flag("--json")) console.log(JSON.stringify(r, null, 2));
    else printHealth(r);
    applyCi([r]);
    return;
  }

  const pos = positional(1);
  const spec = pos[0];
  if (!spec) { usage(); process.exit(2); }
  const r = await runHealthcheck(spec, { env: injectedEnv });
  if (flag("--json")) console.log(JSON.stringify(r, null, 2));
  else printHealth(r);
  applyCi([r]);
}

// scan-config: scan an MCP config file for exposed secrets.
function cmdScanConfig() {
  const configArg = positional(1)[0];
  if (!configArg || !existsSync(configArg)) {
    console.error("scan-config: missing <config-file> or file not found");
    console.error("Usage: mcp-trustcard scan-config <path-to-config.json>");
    process.exit(2);
  }
  const findings = scanConfigForSecrets(readFileSync(configArg, "utf8"), configArg);
  if (findings.length === 0) {
    console.log(`${green("PASS")} No secrets detected in ${configArg}`);
    process.exit(0);
  }
  console.log(`${red("FAIL")} ${findings.length} potential secret(s) found in ${configArg}:`);
  for (const f of findings) {
    console.log(`  ${yellow("line " + f.line)} key=${bold(f.key)} pattern=${f.pattern}`);
    console.log(`    ${dim(f.sample)}`);
  }
  process.exit(1);
}

// gen-manifest: build a proxy-enforcement manifest (lib/manifest.js) by listing tools.
async function cmdGenManifest() {
  const { cwd, injectedEnv } = runtimeOpts();
  const outFile = opt("--save-manifest") ?? opt("--out");
  if (!outFile) { console.error("gen-manifest: missing --save-manifest <file>"); process.exit(2); }

  // Collect --allow-tool overrides (can be repeated).
  const allowTools = [];
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--allow-tool" && argv[i + 1]) {
      allowTools.push(argv[i + 1]);
      i++;
    }
  }

  const local = parseLocalCommand(argv.slice(1));
  let cmd, args, specStr, scwd;
  if (local) {
    cmd = local.cmd; args = local.args; specStr = `${cmd} ${args.join(" ")}`; scwd = cwd;
  } else {
    const spec = positional(1)[0];
    if (!spec) { console.error("gen-manifest: missing <spec> or -- <cmd> [args...]"); process.exit(2); }
    const npmCandidates = ["npm", "/opt/homebrew/bin/npm", "/usr/local/bin/npm"];
    let npmBin = "npm";
    for (const candidate of npmCandidates) {
      try { await exec(`${candidate} --version`, { timeout: 5_000, env: process.env }); npmBin = candidate; break; } catch {}
    }
    const { stdout } = await exec(`${npmBin} view ${JSON.stringify(spec)} name version bin --json`, { timeout: 30_000, env: process.env });
    JSON.parse(stdout); // verify it resolves
    cmd = "npx"; args = ["-y", spec]; specStr = spec;
  }

  const client = new McpStdioClient({ cmd, args, env: injectedEnv, spawnTimeout: 45_000, cwd: scwd });
  try {
    await client.start();
    // Try all protocol versions — servers may not support the newest.
    let init = null;
    let lastErr = null;
    for (const v of PROTOCOL_VERSIONS) {
      try {
        init = await client.request("initialize", {
          protocolVersion: v,
          capabilities: {},
          clientInfo: { name: "mcp-trustcard", version: "2.0.0" },
        }, 15_000);
        break;
      } catch (e) { lastErr = e; }
    }
    if (!init) throw new Error(lastErr?.message ?? "handshake failed");
    client.notify("notifications/initialized", {});
    const res = await client.request("tools/list", {}, 10_000);
    const tools = Array.isArray(res?.tools) ? res.tools : [];
    const manifest = buildProxyManifest(tools, init?.serverInfo ?? null, specStr, allowTools);
    writeFileSync(outFile, JSON.stringify(manifest, null, 2));
    console.log(`Manifest saved: ${outFile}`);
    console.log(`  Server: ${manifest.serverInfo?.name ?? specStr}`);
    console.log(`  Tools:  ${manifest.tools.length}`);
    console.log(`  Hash:   ${manifest.manifestHash}`);
    if (allowTools.length > 0) {
      console.log(`  Overrides: ${allowTools.join(", ")}`);
    }
    for (const t of manifest.tools) {
      const flag = t.manualOverride ? " [override]" : "";
      console.log(`    ${t.name.padEnd(32)} schema=${t.schemaHash}${flag}`);
    }
  } finally {
    await client.stop();
  }
}

async function cmdFingerprint() {
  const spec = positional(1)[0];
  if (!spec) { usage(); process.exit(2); }
  const pins = new PinStore(opt("--pins"));
  const card = await fingerprint(spec, { manifestPath: opt("--manifest"), pinStore: pins });
  if (flag("--json")) console.log(JSON.stringify(card, null, 2));
  else printFingerprint(card, c);
  const failed = card.observation?.error || (card.provenance && !card.provenance.ok) || (card.binding && !card.binding.consistent) || card.drift?.status === "drifted";
  process.exit(failed ? 1 : 0);
}

async function cmdManifest() {
  const spec = positional(1)[0];
  if (!spec) { usage(); process.exit(2); }
  const obs = await observeServer({ cmd: "npx", args: ["-y", spec], env: {} });
  if (obs.error) { console.error(red(`probe failed: ${obs.error}`)); process.exit(1); }
  const keyPath = opt("--key");
  let publisher;
  if (keyPath) {
    const k = loadJson(keyPath);
    publisher = { keyId: k.keyId, publicKey: k.publicKey };
  } else {
    publisher = { keyId: "unpublished", publicKey: "" };
  }
  const manifest = buildManifest({ serverInfo: obs.serverInfo, protocolVersion: obs.protocolVersion, tools: obs.tools, publisher });
  const out = opt("--out");
  if (out) writeFileSync(out, JSON.stringify(manifest, null, 2) + "\n");
  else console.log(JSON.stringify(manifest, null, 2));
}

async function cmdKeygen() {
  const kp = generatePublisherKeypair();
  const out = opt("--out");
  const doc = {
    schema: "trustcard.dev/publisher-key@1",
    keyId: kp.keyId,
    publicKey: kp.publicKey,
    privateKey: kp.privateKey,
    createdAt: new Date().toISOString(),
    warning: "The privateKey field signs manifests. Split this file: publicKey+keyId are publishable; privateKey belongs in a secret store.",
  };
  if (out) {
    writeFileSync(out, JSON.stringify(doc, null, 2) + "\n", { mode: 0o600 });
    console.log(`${green("✓")} publisher key written to ${out}`);
    console.log(`  keyId: ${kp.keyId}`);
  } else {
    console.log(JSON.stringify(doc, null, 2));
  }
}

async function cmdSign() {
  const manifestPath = positional(1)[0];
  const keyPath = opt("--key");
  if (!manifestPath || !keyPath) { console.error("sign requires <manifest.json> --key <publisher.key.json>"); process.exit(2); }
  const manifest = loadJson(manifestPath);
  const key = loadJson(keyPath);
  const signed = signManifest(manifest, key.privateKey);
  const out = opt("--out");
  if (out) writeFileSync(out, JSON.stringify(signed, null, 2) + "\n");
  else console.log(JSON.stringify(signed, null, 2));
  console.error(`${green("✓")} signed with ${signed.signature.keyId}`);
}

async function cmdVerify() {
  const manifestPath = positional(1)[0];
  if (!manifestPath) { usage(); process.exit(2); }
  const manifest = loadJson(manifestPath);
  const result = verifyManifest(manifest);
  const spec = opt("--spec");
  let binding = null;
  if (spec && result.ok) {
    const obs = await observeServer({ cmd: "npx", args: ["-y", spec], env: {} });
    binding = obs.error ? { consistent: false, problems: [obs.error] } : bindingConsistency(manifest, obs);
  }
  if (flag("--json")) {
    console.log(JSON.stringify({ ...result, binding }, null, 2));
  } else {
    console.log("");
    console.log(`${bold("Manifest verification")}: ${manifestPath}`);
    console.log(dim("─".repeat(72)));
    console.log(`${"Signature + digests".padEnd(26)} ${result.ok ? green("VERIFIED") : red("INVALID")}  ${result.keyId ? dim("key " + result.keyId.slice(0, 20) + "…") : ""}`);
    for (const e of result.errors) console.log(`${"".padEnd(26)} ${red("✗")} ${dim(e)}`);
    if (binding) {
      console.log(`${"Live binding".padEnd(26)} ${binding.consistent ? green("CONSISTENT") : red("DRIFT")}  ${dim(spec ?? "")}`);
      for (const p of binding.problems) console.log(`${"".padEnd(26)} ${red("✗")} ${dim(p)}`);
    }
    console.log("");
  }
  process.exit(result.ok && (!binding || binding.consistent) ? 0 : 1);
}

async function cmdDiff() {
  const [oldPath, newPath] = positional(1);
  if (!oldPath || !newPath) { console.error("diff requires <old.json> <new.json>"); process.exit(2); }
  const oldDoc = loadJson(oldPath);
  const newDoc = loadJson(newPath);
  const toolsOf = (d) => d.tools ?? d.observation?.tools ?? (Array.isArray(d) ? d : []);
  const diff = diffToolsets(toolsOf(oldDoc), toolsOf(newDoc));
  if (flag("--json")) console.log(JSON.stringify(diff, null, 2));
  else printDiff(diff, c, { verbose: flag("--verbose") });
  process.exit(CHANGE_LEVEL[diff.overall] >= CHANGE_LEVEL.PERMISSION_CHANGE ? 1 : 0);
}

async function cmdPin() {
  const spec = positional(1)[0];
  if (!spec) { usage(); process.exit(2); }
  const pins = new PinStore(opt("--pins"));
  const obs = await observeServer({ cmd: "npx", args: ["-y", spec], env: {} });
  if (obs.error) { console.error(red(`probe failed: ${obs.error}`)); process.exit(1); }
  const key = pins.serverKey(obs.serverInfo ?? spec);
  pins.pinServer(key, obs);
  console.log(`${green("✓")} pinned ${bold(key)}`);
  console.log(`  toolset: ${obs.toolsetDigest}`);
  console.log(`  server:  ${obs.serverDigest}`);
  console.log(`  tools:   ${obs.tools.length}`);
  console.log(dim(`  store:   ${pins.path}`));
}

async function cmdUnpin() {
  const key = positional(1)[0];
  if (!key) { usage(); process.exit(2); }
  const pins = new PinStore(opt("--pins"));
  pins.removeServerPin(key);
  console.log(`${green("✓")} removed pin ${key}`);
}

async function cmdPins() {
  const pins = new PinStore(opt("--pins"));
  const data = pins.list();
  if (flag("--json")) { console.log(JSON.stringify(data, null, 2)); return; }
  console.log("");
  console.log(`${bold("Trustcard pins")}  ${dim(pins.path)}`);
  console.log(dim("─".repeat(72)));
  for (const [k, v] of Object.entries(data.servers)) {
    console.log(`${bold(k)}`);
    console.log(`  toolset ${dim(v.toolsetDigest)}`);
    console.log(`  pinned  ${dim(v.firstPinnedAt)}  repins: ${v.repinCount}`);
  }
  for (const [k, v] of Object.entries(data.publishers)) {
    console.log(`publisher ${dim(k)}  first seen ${v.firstSeen}`);
  }
  if (Object.keys(data.servers).length === 0 && Object.keys(data.publishers).length === 0) {
    console.log(dim("  (empty — pin a server with `mcp-trustcard pin <spec>`)"));
  }
  console.log("");
}

async function main() {
  const cmd = argv[0];
  if (!cmd || cmd === "-h" || cmd === "--help" || cmd === "help") return usage();
  switch (cmd) {
    case "scan": return cmdScan();
    case "scan-config": return cmdScanConfig();
    case "gen-manifest": return cmdGenManifest();
    case "fingerprint": return cmdFingerprint();
    case "manifest": return cmdManifest();
    case "keygen": return cmdKeygen();
    case "sign": return cmdSign();
    case "verify": return cmdVerify();
    case "diff": return cmdDiff();
    case "pin": return cmdPin();
    case "unpin": return cmdUnpin();
    case "pins": return cmdPins();
    default:
      if (!cmd.startsWith("-")) return cmdScan();
      usage();
      process.exit(2);
  }
}

main().catch((e) => { console.error("fatal:", e.message ?? e); process.exit(1); });
