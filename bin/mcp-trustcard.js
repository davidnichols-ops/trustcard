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
import { runHealthcheck, scanConfigForSecrets } from "../lib/checks.js";
import { buildManifest as buildProxyManifest, manifestHashStatus } from "../lib/manifest.js";
import { McpStdioClient, PROTOCOL_VERSIONS } from "../lib/client.js";
import { fingerprint } from "../lib/fingerprint.js";
import { observeServer } from "../lib/observe.js";
import { buildManifest, signManifest, verifyManifest, generatePublisherKeypair, bindingConsistency, isProxyManifest, normalizeTrustedKey, publisherFromSecret } from "../lib/provenance.js";
import { hashManifestPayload } from "../lib/hash.js";
import { MANIFEST_SCHEMA_VERSION, toolsetDigest, serverDigest } from "../lib/identity.js";
import { buildDescriptor, signDescriptor, verifyDescriptor } from "../lib/descriptor.js";
import { changeVector } from "../lib/change.js";
import { diffToolsets, CHANGE_LEVEL } from "../lib/diff.js";
import { PinStore } from "../lib/pin.js";
import { printFingerprint, printDiff } from "../lib/report.js";
import { EvidenceStore } from "../lib/evidence-store.js";
import { EVIDENCE_LAYERS } from "../lib/evidence-predicates.js";
import { BehaviorEngine, SandboxRuntime, InputGenerator, OutputComparator, RegressionCorpus, ReferenceObservation } from "../lib/behavior.js";
import { resolve as resolvePath, dirname, isAbsolute, basename, join } from "node:path";
import { fileURLToPath } from "node:url";
import { npmView, isNpmSpec, assertNpmSpec } from "../lib/npm.js";
import { TRUSTCARD_VERSION } from "../lib/version.js";

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
// Collect every occurrence of a repeatable value-taking flag.
function optsAll(name) {
  const out = [];
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === name && argv[i + 1] !== undefined) { out.push(argv[i + 1]); i++; }
  }
  return out;
}
function positional(skip = 1) {
  const VALUE_FLAGS = new Set(["--interval", "--config", "--url", "--within", "--port", "--manifest", "--out", "--key", "--pins", "--spec", "--json-out", "--batch", "--env-file", "--cwd", "--save-manifest", "--threshold", "--parallel", "--timeout", "--subject", "--predicate", "--since", "--until", "--layer", "--evidence-dir", "--server", "--corpus", "--seed", "--probe", "--tool", "--implementation", "--namespace", "--expires-in", "--claims", "--publisher-name", "--publisher-key", "--scopes", "--secret", "--secret-file", "--auth-secret", "--auth-secret-file", "--allow-tool", "--require-scopes", "--manifest-dir", "--transport", "--header"]);
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

Fleet operations (JSON client configs):
  mcp-trustcard status --config <file> [--json]
  mcp-trustcard gate --config <file> [--server <name>] [--port <n>] [--apply] [--json]
                        (preview by default; --apply writes manifests and
                        rewrites config entries — HTTP needs mcp-http-proxy running)
  mcp-trustcard renew --config <file> [--server <name>] [--within <days>] [--dry-run] [--json]
  mcp-trustcard reapprove --config <file> [--server <name>] [--dry-run] [--json]
  mcp-trustcard reapprove <manifest.json> --url <endpoint> [--dry-run] [--json]
  mcp-trustcard console --config <file> [--port <port>]
  mcp-trustcard watch --config <file> [--within 14] [--interval 21600] [--once]

Identity & provenance:
  mcp-trustcard fingerprint <spec> [--manifest m.json] [--json]
  mcp-trustcard manifest <spec> [--key pub.key.json] [--expires-in <days>|--no-expiry] [--out m.json]
                        (builds an UNSIGNED provenance manifest; --key embeds the publisher's
                        public identity only — it does NOT sign; use "sign" for that)
  mcp-trustcard keygen [--out publisher.key.json]
  mcp-trustcard sign <manifest.json> --key publisher.key.json [--out signed.json]
                        (embeds publisher identity derived from --key; refuses proxy manifests)
  mcp-trustcard verify <signed.json> [--spec <pkg>] [--publisher-key <key-or-file>] [--pins <path>]
                        (a valid signature alone proves self-asserted provenance;
                        --publisher-key/--pins anchor the publisher key out-of-band)
  mcp-trustcard diff <old.json> <new.json> [--verbose]

Capability descriptor (protocol-neutral):
  mcp-trustcard descriptor build <tool-or-manifest.json> --key pub.key.json [--tool <name>] [--out desc.json]
  mcp-trustcard descriptor sign <desc.json> --key publisher.key.json [--out signed.json]
  mcp-trustcard descriptor verify <desc.json> [--json]
  mcp-trustcard descriptor diff <old.json> <new.json> [--json]
  mcp-trustcard descriptor pin <desc.json> [--pins path]

Behavioral verification:
  mcp-trustcard behavior <manifest.json> [--server <spec>] [--corpus <dir>] [--json]
                        [--seed <n>] [--timeout <ms>] [--probe <id>] [--verbose]
  mcp-trustcard behavior diff <reference.json> <target.json>

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
  mcp-trustcard gen-manifest -- <cmd> [args...] --save-manifest <file> [--allow-tool <name>...] [--require-scopes <tool>=<s1,s2>] [--expires-in <days>|--no-expiry]
  mcp-trustcard inspect <file>                 # inspect a manifest or pin store
  mcp-trustcard auth-issue --subject <id> --scopes <s1,s2> --secret-file <path|->   # issue a dev-mode token
  mcp-trustcard auth-verify <token> --secret-file <path|->   # verify a dev-mode token
                        (secrets: prefer --secret-file or TRUSTCARD_AUTH_SECRET over --secret argv)
  mcp-trustcard <spec>                         # shorthand for scan

Evidence substrate (observatory):
  mcp-trustcard evidence query --subject <name> [--predicate <p>] [--layer <n>] [--json]
  mcp-trustcard evidence history --subject <name> [--since <date>]
  mcp-trustcard evidence stats [--json]
  mcp-trustcard evidence verify                 # integrity check all evidence
  mcp-trustcard evidence export [--since <date>] [--json-out <file>]
  mcp-trustcard evidence contradictions --subject <name>

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
  if (status === "SKIPPED") return dim("SKIPPED");
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

  // Collect --require-scopes overrides (repeatable). Documented form:
  //   --require-scopes read_file=read:files,write:disk   (tool=scope,scope,...)
  //   --require-scopes "*=read:files"                     (wildcard: all tools)
  // The older colon form (tool:scope,scope) is still accepted. A tool name that
  // does not match an enumerated tool is an error — overrides must never be
  // silently dropped.
  const scopeOverrides = {};
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--require-scopes" && argv[i + 1]) {
      const spec = argv[i + 1];
      let sepIdx = spec.indexOf("=");
      if (sepIdx === -1) sepIdx = spec.indexOf(":");
      if (sepIdx <= 0) { console.error(`--require-scopes: expected <tool>=<scope1,scope2,...>, got "${spec}"`); process.exit(2); }
      const tool = spec.slice(0, sepIdx).trim();
      const scopes = spec.slice(sepIdx + 1).split(",").map((s) => s.trim()).filter(Boolean);
      if (scopes.length === 0) { console.error(`--require-scopes: "${spec}" declares no scopes`); process.exit(2); }
      scopeOverrides[tool] = scopes;
      i++;
    }
  }

  // Expiry override: --expires-in <days> (default 90). --no-expiry disables.
  const expiresFlag = opt("--expires-in");
  const expiresInDays = expiresFlag === "none" || argv.includes("--no-expiry")
    ? null
    : expiresFlag ? parseInt(expiresFlag, 10) : 90;

  const local = parseLocalCommand(argv.slice(1));
  let cmd, args, specStr, scwd;

  // Check for HTTP URL spec (remote server).
  const posSpec = positional(1)[0];
  const isRemote = posSpec && /^https?:\/\//i.test(posSpec);

  if (isRemote) {
    specStr = posSpec;
  } else if (local) {
    cmd = local.cmd; args = local.args; specStr = `${cmd} ${args.join(" ")}`; scwd = cwd;
  } else {
    const spec = posSpec;
    if (!spec) { console.error("gen-manifest: missing <spec> or -- <cmd> [args...]"); process.exit(2); }
    // Spec is validated and passed to npm/npx as an argv element — never a
    // shell string — so substitutions/backticks in it stay literal.
    try { assertNpmSpec(spec); }
    catch (e) { console.error(`gen-manifest: ${e.message}`); process.exit(2); }
    try {
      await npmView(spec, ["name", "version", "bin"]);
    } catch (e) {
      console.error(`gen-manifest: package spec does not resolve in the npm registry: ${e.message?.slice(0, 120)}`);
      process.exit(2);
    }
    cmd = "npx"; args = ["-y", spec]; specStr = spec;
  }

  // For remote HTTP servers, use McpHttpClient; otherwise stdio.
  let client;
  if (isRemote) {
    const { McpHttpClient } = await import("../lib/client-http.js");
    client = new McpHttpClient({ url: posSpec, transport: "streamable-http", timeout: 30_000 });
  } else {
    client = new McpStdioClient({ cmd, args, env: injectedEnv, spawnTimeout: 45_000, cwd: scwd });
  }
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
          clientInfo: { name: "mcp-trustcard", version: TRUSTCARD_VERSION },
        }, 15_000);
        break;
      } catch (e) { lastErr = e; }
    }
    if (!init) throw new Error(lastErr?.message ?? "handshake failed");
    client.notify("notifications/initialized", {});
    const res = await client.request("tools/list", {}, 10_000);
    const tools = Array.isArray(res?.tools) ? res.tools : [];
    // Overrides that name a tool the server doesn't expose are operator
    // errors (typos, stale scripts). They silently did nothing before; that is
    // how permission gates get quietly bypassed, so reject them loudly.
    const toolNames = new Set(tools.map((t) => t.name));
    const unknownScopeTools = Object.keys(scopeOverrides).filter((n) => n !== "*" && !toolNames.has(n));
    const unknownAllowTools = allowTools.filter((n) => !toolNames.has(n));
    if (unknownScopeTools.length || unknownAllowTools.length) {
      if (unknownScopeTools.length) console.error(`gen-manifest: --require-scopes references tool(s) the server does not expose: ${unknownScopeTools.join(", ")}`);
      if (unknownAllowTools.length) console.error(`gen-manifest: --allow-tool references tool(s) the server does not expose: ${unknownAllowTools.join(", ")}`);
      console.error(`  enumerated tools: ${[...toolNames].join(", ") || "(none)"}`);
      process.exit(2);
    }
    // Expand wildcard scope overrides to all tools
    const finalScopeOverrides = {};
    if (scopeOverrides["*"]) {
      for (const t of tools) {
        finalScopeOverrides[t.name] = scopeOverrides["*"];
      }
    }
    Object.assign(finalScopeOverrides, scopeOverrides);
    delete finalScopeOverrides["*"];
    const manifest = buildProxyManifest(tools, init?.serverInfo ?? null, specStr, allowTools, expiresInDays,
      Object.keys(finalScopeOverrides).length > 0 ? finalScopeOverrides : null);
    writeFileSync(outFile, JSON.stringify(manifest, null, 2));
    console.log(`Manifest saved: ${outFile}`);
    console.log(`  Server: ${manifest.serverInfo?.name ?? specStr}`);
    console.log(`  Tools:  ${manifest.tools.length}`);
    console.log(`  Hash:   ${manifest.manifestHash}`);
    console.log(`  Expires: ${manifest.expiresAt ?? "never"}`);
    if (allowTools.length > 0) {
      console.log(`  Overrides: ${allowTools.join(", ")}`);
    }
    const scopedCount = manifest.tools.filter((t) => t.requiredScopes?.length > 0).length;
    if (scopedCount > 0) {
      console.log(`  Scoped tools: ${scopedCount}`);
    }
    for (const t of manifest.tools) {
      const flags = [];
      if (t.manualOverride) flags.push("override");
      if (t.requiredScopes?.length) flags.push(`scopes=[${t.requiredScopes.join(",")}]`);
      const flagStr = flags.length > 0 ? ` [${flags.join(", ")}]` : "";
      console.log(`    ${t.name.padEnd(32)} schema=${t.schemaHash}${flagStr}`);
    }
  } finally {
    await client.stop();
  }
}

async function cmdFingerprint() {
  const { cwd, injectedEnv } = runtimeOpts();
  const local = parseLocalCommand(argv.slice(1));
  const posSpec = positional(1)[0];
  const pins = new PinStore(opt("--pins"));

  let card;
  if (local) {
    // Local command via `-- <cmd> [args...]`
    const specStr = `${local.cmd} ${local.args.join(" ")}`;
    card = await fingerprint(specStr, {
      manifestPath: opt("--manifest"),
      pinStore: pins,
      localCmd: { cmd: local.cmd, args: local.args, cwd: cwd || undefined, env: injectedEnv },
    });
  } else {
    const spec = posSpec;
    if (!spec) { usage(); process.exit(2); }
    card = await fingerprint(spec, { manifestPath: opt("--manifest"), pinStore: pins });
  }

  if (flag("--json")) console.log(JSON.stringify(card, null, 2));
  else printFingerprint(card, c);
  const failed = card.observation?.error || (card.provenance && !card.provenance.ok) || (card.binding && !card.binding.consistent) || card.drift?.status === "drifted";
  process.exit(failed ? 1 : 0);
}

async function cmdManifest() {
  const { cwd, injectedEnv } = runtimeOpts();
  const local = parseLocalCommand(argv.slice(1));
  const posSpec = positional(1)[0];

  let obs;
  if (local) {
    obs = await observeServer({ cmd: local.cmd, args: local.args, env: injectedEnv, cwd: cwd || undefined });
  } else {
    const spec = posSpec;
    if (!spec) { usage(); process.exit(2); }
    obs = await observeServer({ cmd: "npx", args: ["-y", spec], env: injectedEnv });
  }
  if (obs.error) { console.error(red(`probe failed: ${obs.error}`)); process.exit(1); }
  const keyPath = opt("--key");
  let publisher;
  if (keyPath) {
    const k = loadJson(keyPath);
    // --key embeds the publisher's PUBLIC identity in the manifest. It does not
    // sign anything — signing is a separate step (`mcp-trustcard sign`).
    if (!k?.keyId || !k?.publicKey) {
      console.error(`manifest: --key ${keyPath} must contain keyId and publicKey (a public key file, or the full keygen output)`);
      process.exit(2);
    }
    publisher = { keyId: k.keyId, publicKey: k.publicKey };
  } else {
    publisher = { keyId: "unpublished", publicKey: "" };
  }
  // Provenance manifests expire by default (90 days, same as proxy policy):
  // a signed toolset should be re-attested periodically, not trusted forever.
  // --expires-in <days> overrides; --no-expiry emits expiresAt: null.
  const expiresFlag = opt("--expires-in");
  const expiresInDays = expiresFlag === "none" || argv.includes("--no-expiry")
    ? null
    : expiresFlag !== undefined ? parseInt(expiresFlag, 10) : 90;
  if (expiresInDays !== null && (!Number.isFinite(expiresInDays) || expiresInDays <= 0)) {
    console.error(`manifest: --expires-in must be a positive number of days (or --no-expiry)`);
    process.exit(2);
  }
  const expiresAt = expiresInDays != null ? new Date(Date.now() + expiresInDays * 86_400_000).toISOString() : null;
  const manifest = buildManifest({ serverInfo: obs.serverInfo, protocolVersion: obs.protocolVersion, tools: obs.tools, publisher, expiresAt });
  const out = opt("--out");
  if (out) writeFileSync(out, JSON.stringify(manifest, null, 2) + "\n");
  else console.log(JSON.stringify(manifest, null, 2));
  // Confirmation goes to stderr: stdout stays pure JSON for piping.
  console.error(`${green("✓")} unsigned manifest built${out ? ` → ${out}` : ""} — ${manifest.tools.length} tool(s), expires ${manifest.expiresAt ?? "never"}`);
  console.error(dim(`  publisher identity ${publisher.keyId === "unpublished" ? "not embedded (pass --key <publisher key file>)" : `embedded as ${publisher.keyId}`} — manifest is NOT signed; run \`mcp-trustcard sign\` with the publisher private key`));
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
  let manifest, key;
  try { manifest = loadJson(manifestPath); } catch (e) { console.error(`sign: cannot read manifest: ${e.message}`); process.exit(2); }
  try { key = loadJson(keyPath); } catch (e) { console.error(`sign: cannot read key file: ${e.message}`); process.exit(2); }
  if (!key?.privateKey) { console.error(`sign: --key ${keyPath} has no privateKey (generate one with \`mcp-trustcard keygen\`)`); process.exit(2); }
  // Fail fast on the wrong document class: a proxy manifest is call-time
  // policy, not provenance, and signing it is meaningless.
  if (isProxyManifest(manifest)) {
    console.error(`sign: ${manifestPath} is a proxy-enforcement manifest (gen-manifest format)`);
    console.error(`      proxy manifests are local call-time policy and are never signed.`);
    console.error(`      to produce a signable provenance manifest: \`mcp-trustcard manifest <spec> --key <publisher-key.json> --out m.json\``);
    process.exit(2);
  }
  // If the key file also declares a publicKey/keyId, it must agree with the
  // private key — a mismatched key file is malformed input, not a signing choice.
  try {
    const derived = publisherFromSecret(key.privateKey);
    if (key.publicKey && key.publicKey !== derived.publicKey) {
      console.error(`sign: key file's publicKey does not match its privateKey — malformed key file`);
      process.exit(2);
    }
    if (key.keyId && key.keyId !== derived.keyId) {
      console.error(`sign: key file's keyId does not match its privateKey — malformed key file`);
      process.exit(2);
    }
  } catch (e) {
    console.error(`sign: --key ${keyPath} does not contain a valid Ed25519 private key: ${e.message}`);
    process.exit(2);
  }
  let signed;
  try {
    signed = signManifest(manifest, key.privateKey);
  } catch (e) {
    console.error(`sign: ${e.message}`);
    process.exit(2);
  }
  // Never report success for a manifest we cannot verify — self-check the
  // signed output before declaring it good.
  const check = verifyManifest(signed);
  if (!check.ok) {
    console.error(`sign: produced an unverifiable manifest — refusing to report success:`);
    for (const e of check.errors) console.error(`  ${red("✗")} ${e}`);
    process.exit(1);
  }
  const out = opt("--out");
  if (out) writeFileSync(out, JSON.stringify(signed, null, 2) + "\n");
  else console.log(JSON.stringify(signed, null, 2));
  console.error(`${green("✓")} signed with ${signed.signature.keyId} (publisher identity embedded from the signing key)`);
}

// Resolve a --publisher-key value into a trust anchor: an existing JSON file
// ({keyId, publicKey} — e.g. keygen output or a public-only split), a literal
// "sha256:..." keyId, or a base64url spki public key.
function publisherAnchorFrom(value) {
  if (!value) return null;
  if (existsSync(value)) {
    let doc;
    try { doc = loadJson(value); } catch (e) { console.error(`verify: cannot read --publisher-key file ${value}: ${e.message}`); process.exit(2); }
    const anchor = normalizeTrustedKey(doc);
    if (!anchor) { console.error(`verify: --publisher-key file ${value} contains no keyId or publicKey`); process.exit(2); }
    return anchor;
  }
  return normalizeTrustedKey(value);
}

async function cmdVerify() {
  const manifestPath = positional(1)[0];
  if (!manifestPath) { usage(); process.exit(2); }
  const manifest = loadJson(manifestPath);

  // Out-of-band trust anchors. Cryptographic validity alone proves only that
  // *someone* signed the manifest; anchoring decides whether that someone is
  // the publisher you trust.
  const trustedKeys = [];
  for (const v of optsAll("--publisher-key")) {
    const a = publisherAnchorFrom(v);
    if (!a) { console.error(`verify: --publisher-key "${v}" is not a keyId, public key, or key file`); process.exit(2); }
    trustedKeys.push(a);
  }
  const pinsPath = opt("--pins");
  if (pinsPath !== undefined) {
    const pins = new PinStore(pinsPath);
    const publishers = pins.list()?.publishers ?? {};
    for (const [keyId, p] of Object.entries(publishers)) {
      if (p?.publicKey) trustedKeys.push({ keyId, publicKey: p.publicKey });
    }
    if (Object.keys(publishers).length === 0) {
      console.error(`verify: --pins ${pinsPath} contains no publisher pins — nothing to anchor trust to`);
      process.exit(2);
    }
  }

  const result = verifyManifest(manifest, { trustedKeys });
  const spec = opt("--spec");
  let binding = null;
  if (spec && result.ok) {
    const obs = await observeServer({ cmd: "npx", args: ["-y", spec], env: {} });
    binding = obs.error ? { consistent: false, problems: [obs.error] } : bindingConsistency(manifest, obs);
  }
  const anchorSupplied = trustedKeys.length > 0;
  if (flag("--json")) {
    console.log(JSON.stringify({ ...result, binding }, null, 2));
  } else {
    console.log("");
    console.log(`${bold("Manifest verification")}: ${manifestPath}`);
    console.log(dim("─".repeat(72)));
    console.log(`${"Signature + digests".padEnd(26)} ${result.ok ? green("VERIFIED") : red("INVALID")}  ${result.keyId ? dim("key " + result.keyId.slice(0, 20) + "…") : ""}`);
    for (const e of result.errors) console.log(`${"".padEnd(26)} ${red("✗")} ${dim(e)}`);
    const t = result.trust;
    if (t?.anchored) {
      console.log(`${"Publisher trust".padEnd(26)} ${green("ANCHORED")}  ${dim(t.detail)}`);
    } else if (anchorSupplied) {
      console.log(`${"Publisher trust".padEnd(26)} ${red("UNTRUSTED")}  ${dim(t?.detail ?? "")}`);
    } else {
      console.log(`${"Publisher trust".padEnd(26)} ${yellow("SELF-ASSERTED")}  ${dim(t?.detail ?? "")}`);
    }
    if (binding) {
      console.log(`${"Live binding".padEnd(26)} ${binding.consistent ? green("CONSISTENT") : red("DRIFT")}  ${dim(spec ?? "")}`);
      for (const p of binding.problems) console.log(`${"".padEnd(26)} ${red("✗")} ${dim(p)}`);
    }
    console.log("");
  }
  const failed = !result.ok || (anchorSupplied && !result.trust.anchored) || (binding && !binding.consistent);
  process.exit(failed ? 1 : 0);
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
  const { cwd, injectedEnv } = runtimeOpts();
  const local = parseLocalCommand(argv.slice(1));
  const posSpec = positional(1)[0];
  const pins = new PinStore(opt("--pins"));

  let obs;
  if (local) {
    obs = await observeServer({ cmd: local.cmd, args: local.args, env: injectedEnv, cwd: cwd || undefined });
  } else {
    const spec = posSpec;
    if (!spec) { usage(); process.exit(2); }
    obs = await observeServer({ cmd: "npx", args: ["-y", spec], env: injectedEnv });
  }
  if (obs.error) { console.error(red(`probe failed: ${obs.error}`)); process.exit(1); }
  // Bind the pin to the route the operator configured (spec or command line),
  // not just the server's self-reported name@version — an impostor can copy a
  // self-report, and two unnamed servers must not collapse into "?@?".
  const origin = local ? `${local.cmd} ${local.args.join(" ")}`.trim() : String(posSpec);
  const serverId = { ...(obs.serverInfo ?? {}), origin };
  const key = pins.serverKey(serverId);
  pins.pinServer(serverId, obs);
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

// Read an auth secret without putting it on the command line.
// Order: --secret-file <path> ("-" = stdin), then --secret <hex> (argv —
// visible to every local process via `ps`; use only for throwaway dev keys),
// then TRUSTCARD_AUTH_SECRET.
async function resolveAuthSecret(cmdName) {
  const file = opt("--secret-file");
  if (file != null) {
    const value = file === "-"
      ? await new Promise((resolve, reject) => {
          const chunks = [];
          process.stdin.on("data", (c) => chunks.push(c));
          process.stdin.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
          process.stdin.on("error", reject);
        })
      : readFileSync(file, "utf8");
    const secret = value.trim();
    if (!secret) { console.error(`${cmdName}: --secret-file ${file} is empty`); process.exit(2); }
    return secret;
  }
  const argvSecret = opt("--secret");
  if (argvSecret) {
    process.stderr.write(`warn: --secret exposes the key in the process list; prefer --secret-file or TRUSTCARD_AUTH_SECRET\n`);
    return argvSecret;
  }
  const envSecret = process.env.TRUSTCARD_AUTH_SECRET;
  if (envSecret) return envSecret;
  console.error(`${cmdName}: missing secret — use --secret-file <path|-> or set TRUSTCARD_AUTH_SECRET (--secret works but leaks via argv)`);
  process.exit(2);
}

// auth-issue: issue a dev-mode token (HMAC-signed JWT-like).
// Usage: mcp-trustcard auth-issue --subject <agent-id> --scopes <scope1,scope2,...> [--secret-file <path|->] [--expires-in <seconds>]
async function cmdAuthIssue() {
  const { DevIssuer } = await import("../lib/auth.js");
  const subject = opt("--subject") ?? positional(1)[0];
  if (!subject) { console.error("auth-issue: missing --subject <agent-id>"); process.exit(2); }
  const scopesStr = opt("--scopes") ?? "";
  const scopes = scopesStr.split(",").map((s) => s.trim()).filter(Boolean);
  const secret = await resolveAuthSecret("auth-issue");
  const expiresIn = parseInt(opt("--expires-in") ?? "3600", 10);

  const issuer = new DevIssuer({ secret });
  const token = issuer.issue({ subject, scopes, expiresInSeconds: expiresIn });

  // Print the token and a decoded summary
  console.log(token);
  if (!flag("--quiet")) {
    const decoded = issuer.verify(token);
    console.error(`  subject: ${decoded.subject}`);
    console.error(`  scopes:  ${decoded.scopes.join(", ")}`);
    console.error(`  expires: ${decoded.expiresAt ?? "never"}`);
    console.error(`  issuer:  ${decoded.issuer}`);
  }
}

// auth-verify: verify a dev-mode token and print its claims.
// Usage: mcp-trustcard auth-verify <token> [--secret-file <path|->]
async function cmdAuthVerify() {
  const { DevIssuer } = await import("../lib/auth.js");
  const token = positional(1)[0];
  if (!token) { console.error("auth-verify: missing <token>"); process.exit(2); }
  const secret = await resolveAuthSecret("auth-verify");

  const issuer = new DevIssuer({ secret });
  const decoded = issuer.verify(token);
  if (!decoded) {
    console.error("auth-verify: token is invalid (bad signature or malformed)");
    process.exit(1);
  }
  if (decoded.isExpired) {
    console.error(`auth-verify: token expired at ${decoded.expiresAt}`);
    process.exit(1);
  }
  if (flag("--json")) {
    console.log(JSON.stringify({
      subject: decoded.subject,
      scopes: decoded.scopes,
      expiresAt: decoded.expiresAt,
      issuer: decoded.issuer,
      active: decoded.isValid,
    }, null, 2));
  } else {
    console.log(`subject: ${decoded.subject}`);
    console.log(`scopes:  ${decoded.scopes.join(", ")}`);
    console.log(`expires: ${decoded.expiresAt ?? "never"}`);
    console.log(`issuer:  ${decoded.issuer}`);
    console.log(`active:  ${decoded.isValid}`);
  }
}

// inspect: human-readable summary of a manifest or pin store.
// Works on both proxy manifests (lib/manifest.js) and signed manifests
// (lib/provenance.js). Detects which format by looking for `signature`.
async function cmdInspect() {
  const file = positional(1)[0];
  if (!file) { console.error("inspect: missing <file>"); process.exit(2); }

  let data;
  try {
    data = JSON.parse(readFileSync(file, "utf8"));
  } catch (e) {
    console.error(`inspect: cannot read ${file}: ${e.message}`);
    process.exit(1);
  }

  const isSigned = !!data.signature;
  const isProxy = data.version === 1 && Array.isArray(data.tools) && !data.signature;
  const isProvenance = !isSigned && !isProxy && data.schema === MANIFEST_SCHEMA_VERSION;
  const isPinStore = data.schema === "trustcard.dev/pins@1";

  if (isSigned) {
    const ok = inspectSignedManifest(data, file);
    if (!ok) process.exit(1);
    return;
  }
  if (isProvenance) {
    const ok = inspectProvenanceManifest(data, file);
    if (!ok) process.exit(1);
    return;
  }
  if (isProxy) {
    const ok = inspectProxyManifest(data, file);
    if (!ok) process.exit(1);
    return;
  }
  if (isPinStore) return inspectPinStore(data, file);

  console.error(`inspect: unrecognized file format (no signature, no version=1 tools, no pins schema)`);
  process.exit(1);
}

// An unsigned provenance manifest (the `manifest` command's output before
// `sign` is run). Exit nonzero when any recorded digest fails to recompute.
function inspectProvenanceManifest(m, file) {
  console.log(`Trustcard Provenance Manifest (unsigned): ${file}`);
  console.log("─".repeat(60));
  console.log(`  Schema:     ${m.schema}`);
  console.log(`  Server:     ${m.server?.name ?? "?"} ${m.server?.version ?? ""}`);
  console.log(`  Publisher:  ${m.publisher?.keyId ?? "none"}`);
  console.log(`  Identity:   ${m.manifestDigest}`);
  console.log(`  Signed:     no — sign with \`mcp-trustcard sign ${file} --key publisher.key.json\``);
  console.log(`  Issued:     ${m.issuedAt ?? "?"}`);
  console.log(`  Expires:    ${m.expiresAt ?? "never"}`);
  const errors = [];
  if (m.manifestDigest && m.manifestDigest !== hashManifestPayload(m)) {
    errors.push(`manifestDigest mismatch — payload hashes to ${hashManifestPayload(m)}`);
  }
  if (m.toolsetDigest && m.toolsetDigest !== toolsetDigest(m.tools)) {
    errors.push("toolsetDigest mismatch");
  }
  const recomputedServer = serverDigest({ serverInfo: m.server, protocolVersion: m.protocol?.negotiated, tools: m.tools });
  if (m.serverDigest && m.serverDigest !== recomputedServer) errors.push("serverDigest mismatch");
  if (!m.manifestDigest) errors.push("missing manifestDigest");
  if (m.expiresAt && Date.parse(m.expiresAt) < Date.now()) errors.push(`expired at ${m.expiresAt}`);
  if (errors.length === 0) {
    console.log(`  Digests:    all recorded digests recompute cleanly`);
  } else {
    console.log(`  Digests:    INVALID`);
    for (const e of errors) console.log(`    - ${e}`);
  }
  console.log(`  Tools:      ${m.tools?.length ?? 0}`);
  return errors.length === 0;
}

function inspectProxyManifest(m, file) {
  console.log(`Trustcard Proxy Manifest: ${file}`);
  console.log("─".repeat(60));
  console.log(`  Server:     ${m.serverInfo?.name ?? "?"} ${m.serverInfo?.version ?? ""}`);
  console.log(`  Spec:       ${m.spec ?? "?"}`);
  console.log(`  Hash:       ${m.manifestHash}`);
  console.log(`  Created:    ${m.createdAt}`);
  console.log(`  Expires:    ${m.expiresAt ?? "never"}${m.expiresAt && Date.parse(m.expiresAt) < Date.now() ? " (EXPIRED)" : ""}`);
  const hs = manifestHashStatus(m);
  console.log(`  Integrity:  ${hs.ok ? (hs.format === "legacy-v1" ? `OK (legacy hash — scopes/contract not covered)` : `OK (policy hash covers decisions, scopes, contracts)`) : `MISMATCH — ${hs.detail}`}`);
  console.log(`  Tools:      ${m.summary.totalTools} total, ${m.summary.allowedTools} allowed, ${m.summary.dangerousTools} dangerous${m.summary.overriddenTools ? `, ${m.summary.overriddenTools} overridden` : ""}`);
  console.log("");
  console.log("  Tools:");
  for (const t of m.tools) {
    const status = t.manualOverride ? "[override]" : t.allowed ? "[allowed]" : "[blocked]";
    const danger = t.dangerScore > 0 ? ` danger=${t.dangerScore}(${t.dangerConfidence})` : "";
    console.log(`    ${t.name.padEnd(36)} ${status}${danger}`);
  }
  return hs.ok;
}

function inspectSignedManifest(m, file) {
  const v = verifyManifest(m);
  console.log(`Trustcard Signed Manifest: ${file}`);
  console.log("─".repeat(60));
  console.log(`  Schema:     ${m.schema}`);
  console.log(`  Server:     ${m.server?.name ?? "?"} ${m.server?.version ?? ""}`);
  console.log(`  Publisher:  ${m.publisher?.keyId ?? "?"}`);
  console.log(`  Identity:   ${m.manifestDigest}`);
  console.log(`  Signed:     ${m.signature ? `yes (${m.signature.algorithm}, keyId=${m.signature.keyId})` : "no"}`);
  console.log(`  Issued:     ${m.issuedAt ?? "?"}`);
  console.log(`  Expires:    ${m.expiresAt ?? "never"}${m.expiresAt && Date.parse(m.expiresAt) < Date.now() ? " (EXPIRED)" : ""}`);
  console.log(`  Verified:   ${v.ok ? "yes" : "NO"}`);
  if (!v.ok) {
    console.log(`  Errors:`);
    for (const e of v.errors) console.log(`    - ${e}`);
  }
  console.log(`  Tools:      ${m.tools?.length ?? 0}`);
  if (m.tools) {
    console.log("");
    console.log("  Tools:");
    for (const t of m.tools) {
      console.log(`    ${t.name.padEnd(36)} schema=${(m.toolDigests?.[t.name] ?? "?").slice(0, 16)}`);
    }
  }
  return v.ok;
}

function inspectPinStore(data, file) {
  const servers = Object.keys(data.servers ?? {});
  const publishers = Object.keys(data.publishers ?? {});
  const descriptors = Object.keys(data.descriptors ?? {});
  console.log(`Trustcard Pin Store: ${file}`);
  console.log("─".repeat(60));
  console.log(`  Schema:      ${data.schema}`);
  console.log(`  Server pins: ${servers.length}`);
  console.log(`  Publisher pins: ${publishers.length}`);
  console.log(`  Descriptor pins: ${descriptors.length}`);
  if (data.corrupt) console.log(`  ⚠ CORRUPT — file was unreadable, started empty`);
  if (servers.length > 0) {
    console.log("");
    console.log("  Server pins:");
    for (const k of servers) {
      const p = data.servers[k];
      console.log(`    ${k.padEnd(36)} pinned=${p.firstPinnedAt ?? "?"} repins=${p.repinCount ?? 0}`);
    }
  }
  if (publishers.length > 0) {
    console.log("");
    console.log("  Publisher pins:");
    for (const k of publishers) {
      const p = data.publishers[k];
      console.log(`    ${k.slice(0, 24).padEnd(28)} firstSeen=${p.firstSeen ?? "?"} source=${p.source ?? "?"}`);
    }
  }
}

// ─── Evidence substrate commands ──────────────────────────────────

function evidenceDir() {
  return opt("--evidence-dir") || "data/evidence";
}

async function cmdEvidence() {
  const sub = argv[1];
  if (!sub) {
    console.log("Usage: mcp-trustcard evidence <query|history|stats|verify|export|contradictions>");
    process.exit(2);
  }

  const dir = evidenceDir();
  const store = new EvidenceStore(dir);

  switch (sub) {
    case "query": {
      const subject = opt("--subject");
      const predicate = opt("--predicate");
      const layer = opt("--layer") !== undefined ? parseInt(opt("--layer"), 10) : undefined;
      const since = opt("--since");
      const until = opt("--until");
      const asJson = flag("--json");

      const filters = {};
      if (subject) filters.subject = subject;
      if (predicate) filters.predicate = predicate;
      if (layer !== undefined && !isNaN(layer)) filters.layer = layer;
      if (since) filters.since = since;
      if (until) filters.until = until;

      const records = store.query(filters);

      if (asJson) {
        console.log(JSON.stringify(records, null, 2));
      } else {
        if (records.length === 0) {
          console.log(dim("No evidence records found."));
          return;
        }
        console.log(bold(`Evidence records (${records.length}):`));
        for (const r of records) {
          const layerName = EVIDENCE_LAYERS[r.claim.layer] ?? "?";
          const val = r.claim.value === null ? dim("null") : JSON.stringify(r.claim.value);
          console.log(
            `  ${r.timestamp}  ${blue(layerName.padEnd(10))}  ${r.claim.predicate.padEnd(35)}  ${val.slice(0, 60)}  conf=${r.claim.confidence}`
          );
        }
      }
      break;
    }

    case "history": {
      const subject = opt("--subject");
      if (!subject) {
        console.error("--subject is required for history");
        process.exit(2);
      }
      const since = opt("--since");
      const records = store.query({ subject, since });

      if (records.length === 0) {
        console.log(dim(`No evidence history for "${subject}".`));
        return;
      }

      console.log(bold(`Evidence history for "${subject}" (${records.length} records):`));
      let lastDate = "";
      for (const r of records) {
        const date = r.timestamp.slice(0, 10);
        const time = r.timestamp.slice(11, 19);
        if (date !== lastDate) {
          console.log(dim(`\n  ${date}`));
          lastDate = date;
        }
        const layerName = EVIDENCE_LAYERS[r.claim.layer] ?? "?";
        const val = r.claim.value === null ? dim("null (observation failed)") : JSON.stringify(r.claim.value);
        console.log(`    ${time}  ${blue(layerName.padEnd(10))}  ${r.claim.predicate.padEnd(35)}  ${val.slice(0, 80)}`);
        if (r.claim.payload?.error) {
          console.log(dim(`              error: ${r.claim.payload.error}`));
        }
      }
      break;
    }

    case "stats": {
      const stats = store.stats();
      const asJson = flag("--json");

      if (asJson) {
        console.log(JSON.stringify(stats, null, 2));
        return;
      }

      if (stats.totalRecords === 0) {
        console.log(dim("Evidence store is empty."));
        return;
      }

      console.log(bold("Evidence Store Statistics"));
      console.log(`  Total records:  ${stats.totalRecords}`);
      console.log(`  Total files:    ${stats.totalFiles}`);
      console.log(`  Subjects:       ${stats.bySubject}`);
      console.log("");
      console.log(bold("  By layer:"));
      for (const [layer, count] of Object.entries(stats.byLayer).sort((a, b) => a[0] - b[0])) {
        console.log(`    Layer ${layer} (${EVIDENCE_LAYERS[layer] ?? "?"}):  ${count}`);
      }
      console.log("");
      console.log(bold("  By predicate (top 10):"));
      const sortedPreds = Object.entries(stats.byPredicate).sort((a, b) => b[1] - a[1]).slice(0, 10);
      for (const [pred, count] of sortedPreds) {
        console.log(`    ${pred.padEnd(40)}  ${count}`);
      }
      console.log("");
      console.log(bold("  By observer:"));
      for (const [obs, count] of Object.entries(stats.byObserver)) {
        console.log(`    ${obs.padEnd(25)}  ${count}`);
      }
      break;
    }

    case "verify": {
      console.log(bold("Verifying evidence store integrity..."));
      const result = store.verify();
      if (result.verified) {
        console.log(green(`  OK — ${result.totalRecords} records verified, no errors.`));
      } else {
        console.log(red(`  FAIL — ${result.errors.length} error(s), ${result.duplicates.length} duplicate(s).`));
        for (const err of result.errors.slice(0, 10)) {
          console.log(red(`    ${err.file}:${err.line}  ${err.error}`));
        }
        if (result.duplicates.length > 0) {
          console.log(red(`  Duplicates:`));
          for (const dup of result.duplicates.slice(0, 10)) {
            console.log(red(`    ${dup.id}  at ${dup.file}:${dup.line}`));
          }
        }
        process.exit(1);
      }
      break;
    }

    case "export": {
      const since = opt("--since");
      const until = opt("--until");
      const outFile = opt("--json-out");

      const filters = {};
      if (since) filters.since = since;
      if (until) filters.until = until;

      const records = store.export(filters);
      const json = JSON.stringify({
        exportedAt: new Date().toISOString(),
        recordCount: records.length,
        records,
      }, null, 2);

      if (outFile) {
        writeFileSync(outFile, json);
        console.log(green(`Exported ${records.length} records to ${outFile}`));
      } else {
        console.log(json);
      }
      break;
    }

    case "contradictions": {
      const subject = opt("--subject");
      if (!subject) {
        console.error("--subject is required for contradictions");
        process.exit(2);
      }

      const contradictions = store.contradictions(subject);
      const preds = Object.keys(contradictions);

      if (preds.length === 0) {
        console.log(green(`No contradictions found for "${subject}".`));
        return;
      }

      console.log(yellow(`Contradictions for "${subject}":`));
      for (const [pred, recs] of Object.entries(contradictions)) {
        console.log(yellow(`\n  ${pred}:`));
        for (const r of recs) {
          const val = r.claim.value === null ? dim("null") : JSON.stringify(r.claim.value);
          console.log(`    ${r.timestamp}  value=${val}  conf=${r.claim.confidence}  method=${r.observer.method}`);
        }
      }
      break;
    }

    default:
      console.error(`Unknown evidence subcommand: "${sub}"`);
      console.log("Usage: mcp-trustcard evidence <query|history|stats|verify|export|contradictions>");
      process.exit(2);
  }
}

function behaviorFindingKey(f) {
  return `${f.tool}:${f.probe?.id}:${f.divergenceClass}:${f.mechanism}:${JSON.stringify(f.evidence).slice(0, 120)}`;
}

async function cmdBehaviorDiff(refPath, targetPath) {
  if (!existsSync(refPath)) { console.error(`behavior diff: reference not found: ${refPath}`); process.exit(2); }
  if (!existsSync(targetPath)) { console.error(`behavior diff: target not found: ${targetPath}`); process.exit(2); }
  const refReport = loadJson(refPath);
  const targetReport = loadJson(targetPath);

  const refById = new Map((refReport.findings ?? []).map((f) => [behaviorFindingKey(f), f]));
  const targetById = new Map((targetReport.findings ?? []).map((f) => [behaviorFindingKey(f), f]));

  const added = (targetReport.findings ?? []).filter((f) => !refById.has(behaviorFindingKey(f)));
  const removed = (refReport.findings ?? []).filter((f) => !targetById.has(behaviorFindingKey(f)));

  const sameToolset = refReport.target?.toolsetDigest === targetReport.target?.toolsetDigest;
  const diff = {
    referenceSummary: refReport.summary ?? "unknown",
    targetSummary: targetReport.summary ?? "unknown",
    toolsetDigestMatch: sameToolset,
    referenceToolsetDigest: refReport.target?.toolsetDigest ?? null,
    targetToolsetDigest: targetReport.target?.toolsetDigest ?? null,
    added: added.map((f) => ({ severity: f.severity, divergenceClass: f.divergenceClass, mechanism: f.mechanism, tool: f.tool, probe: f.probe?.id, evidence: f.evidence })),
    removed: removed.map((f) => ({ severity: f.severity, divergenceClass: f.divergenceClass, mechanism: f.mechanism, tool: f.tool, probe: f.probe?.id })),
  };

  if (flag("--json")) {
    console.log(JSON.stringify(diff, null, 2));
  } else {
    console.log(`Behavior diff: ${refPath} -> ${targetPath}`);
    console.log(`Reference summary: ${diff.referenceSummary}`);
    console.log(`Target summary:      ${diff.targetSummary}`);
    console.log(`Toolset digest match: ${sameToolset}`);
    console.log(`---`);
    console.log(`Added findings (${added.length}):`);
    for (const f of added) console.log(`  [${f.severity}] ${f.divergenceClass} (${f.mechanism}) on ${f.tool}:${f.probe?.id}`);
    console.log(`Removed findings (${removed.length}):`);
    for (const f of removed) console.log(`  [${f.severity}] ${f.divergenceClass} (${f.mechanism}) on ${f.tool}:${f.probe?.id}`);
  }
  process.exit(diff.targetSummary === "pass" && sameToolset ? 0 : 1);
}

async function cmdBehavior() {
  if (argv[1] === "diff") return cmdBehaviorDiff(argv[2], argv[3]);
  const { cwd, injectedEnv } = runtimeOpts();
  const json = flag("--json");
  const manifestPath = positional(1)[0];
  if (!manifestPath) { console.error("behavior: missing <manifest.json>"); usage(); process.exit(2); }
  let manifest;
  try { manifest = loadJson(manifestPath); } catch (e) { console.error(`behavior: cannot read ${manifestPath}: ${e.message}`); process.exit(2); }

  // Resolve the target server spec. The manifest may contain it directly, or
  // the caller may override with --server or the `-- <cmd> [args...]` form.
  let server = manifest.server ?? (manifest.cmd ? manifest : null);
  const serverSpec = opt("--server");
  if (serverSpec) {
    server = { cmd: "npx", args: ["-y", serverSpec] };
  }
  const local = parseLocalCommand(argv.slice(1));
  if (local) {
    server = { cmd: local.cmd, args: local.args };
    if (cwd) server.cwd = cwd;
  }
  if (!server || !server.cmd) {
    console.error("behavior: manifest must include a 'server' object with 'cmd', or use --server / -- <cmd>");
    process.exit(2);
  }

  const spawnTimeout = parseInt(opt("--timeout") ?? "30000", 10);
  const callTimeout = Math.min(spawnTimeout, 30000);
  const seed = parseInt(opt("--seed") ?? "0", 10);
  const probeId = opt("--probe");
  const corpusDir = opt("--corpus");
  const verbose = flag("--verbose");

  const baseDir = cwd ? resolvePath(cwd) : process.cwd();
  // Only resolve args that look like filesystem paths — flags (-y), package
  // specs (@scope/pkg) and other literals must pass through verbatim. The
  // runtime runs the child with a temp cwd, so relative paths still need
  // pinning to baseDir; everything else is handed to the process untouched.
  const resolvedArgs = (server.args ?? []).map((a) => {
    if (typeof a !== "string" || a.startsWith("-") || isAbsolute(a)) return a;
    const looksPath = a.startsWith("./") || a.startsWith("../") || a.startsWith("~") || existsSync(resolvePath(baseDir, a));
    return looksPath ? resolvePath(baseDir, a) : a;
  });
  const runtime = new SandboxRuntime({
    cmd: server.cmd,
    args: resolvedArgs,
    env: { ...injectedEnv, ...(server.env ?? {}) },
    cwd: cwd ? resolvePath(cwd) : undefined,
    spawnTimeout,
    callTimeout,
    detached: server.detached ?? false,
  });

  // Load a saved reference observation if the manifest points to one.
  let reference = null;
  if (manifest.reference) {
    const refPath = typeof manifest.reference === "string" ? manifest.reference : manifest.reference.path;
    if (!existsSync(refPath)) { console.error(`behavior: reference not found: ${refPath}`); process.exit(2); }
    const refJson = loadJson(refPath);
    reference = new ReferenceObservation(refJson);
  }

  const probeFilter = probeId ? (p) => p.id === probeId || p.type === probeId : null;
  const inputGenerator = new InputGenerator({ seed, probesPerTool: 10 });
  const outputComparator = new OutputComparator();
  const corpus = corpusDir ? new RegressionCorpus({ dir: corpusDir }) : null;
  const engine = new BehaviorEngine({ runtime, inputGenerator, outputComparator, reference, corpus, probeFilter });

  const report = await engine.run();

  if (verbose && !json) {
    for (const obs of report.observations) {
      console.error(`probe ${obs.probe?.id} elapsed=${obs.elapsedMs}ms ok=${obs.ok}`);
    }
  }

  if (json) {
    console.log(JSON.stringify(report.toJSON(), null, 2));
  } else {
    console.log(report.toHuman());
    if (corpusDir) console.log(`Corpus written to: ${corpusDir}`);
  }
  process.exit(report.summary === "pass" ? 0 : 1);
}

async function cmdDescriptor() {
  const sub = argv[1];
  switch (sub) {
    case "build": return cmdDescriptorBuild();
    case "sign": return cmdDescriptorSign();
    case "verify": return cmdDescriptorVerify();
    case "diff": return cmdDescriptorDiff();
    case "pin": return cmdDescriptorPin();
    default:
      console.error("Unknown descriptor subcommand");
      usage();
      process.exit(2);
  }
}

function parseOptionalJsonArg(arg, label) {
  if (!arg) return null;
  let value;
  if (existsSync(arg)) {
    try { value = loadJson(arg); } catch (e) { console.error(`${label}: failed to read ${arg}: ${e.message}`); process.exit(2); }
  } else {
    try { value = JSON.parse(arg); } catch (e) { console.error(`${label}: expected JSON or existing file, got "${arg}"`); process.exit(2); }
  }
  return value;
}

async function cmdDescriptorBuild() {
  const filePath = positional(2)[0];
  if (!filePath) { console.error("descriptor build requires <tool-or-manifest.json>"); usage(); process.exit(2); }
  const keyPath = opt("--key");
  if (!keyPath) { console.error("descriptor build requires --key <publisher.key.json>"); process.exit(2); }

  let key;
  try { key = loadJson(keyPath); } catch (e) { console.error(`key: ${e.message}`); process.exit(2); }
  if (!key?.keyId || !key?.publicKey) { console.error("key file must contain keyId and publicKey"); process.exit(2); }

  let raw;
  try { raw = loadJson(filePath); } catch (e) { console.error(`descriptor build: ${e.message}`); process.exit(2); }

  let tool;
  if (raw && Array.isArray(raw.tools) && raw.tools.length > 0) {
    const toolName = opt("--tool");
    if (!toolName) { console.error("manifest contains multiple tools; select one with --tool <name>"); process.exit(2); }
    tool = raw.tools.find((t) => t?.name === toolName);
    if (!tool) { console.error(`tool "${toolName}" not found in manifest`); process.exit(2); }
  } else {
    tool = raw;
  }

  if (!tool || typeof tool !== "object" || !tool.name) { console.error("descriptor build: input is not a valid tool definition"); process.exit(2); }

  const namespace = opt("--namespace") ?? tool.name;
  const implementation = parseOptionalJsonArg(opt("--implementation"), "--implementation");
  const claims = parseOptionalJsonArg(opt("--claims"), "--claims");

  let expiresAt = null;
  const expiresIn = opt("--expires-in");
  if (expiresIn) {
    const days = Number(expiresIn);
    if (!Number.isFinite(days) || days <= 0) { console.error("--expires-in must be a positive number of days"); process.exit(2); }
    expiresAt = new Date(Date.now() + days * 86400000).toISOString();
  }

  const publisher = {
    keyId: key.keyId,
    publicKey: key.publicKey,
    publisher: opt("--publisher-name") ?? key.keyId,
  };

  const descriptor = buildDescriptor({ tool, namespace, implementation, publisher, expiresAt, claims });

  const out = opt("--out");
  if (out) writeFileSync(out, JSON.stringify(descriptor, null, 2) + "\n");

  if (flag("--json")) {
    if (!out) console.log(JSON.stringify(descriptor, null, 2));
  } else {
    console.log(`${green("✓")} descriptor built for ${bold(tool.name)}`);
    console.log(`  descriptorDigest: ${dim(descriptor.descriptorDigest)}`);
    console.log(`  interfaceDigest:  ${dim(descriptor.capability.interfaceDigest)}`);
    console.log(`  implementation:   ${dim(descriptor.implementation.kind)}`);
    console.log(`  namespace:        ${dim(namespace)}`);
    console.log(`  issuedAt:         ${dim(descriptor.issuedAt)}${expiresAt ? `  expiresAt: ${dim(expiresAt)}` : ""}`);
    if (out) console.log(`  written to:       ${dim(out)}`);
  }
}

async function cmdDescriptorSign() {
  const descPath = positional(2)[0];
  const keyPath = opt("--key");
  if (!descPath || !keyPath) { console.error("descriptor sign requires <desc.json> --key <publisher.key.json>"); process.exit(2); }
  let descriptor, key;
  try { descriptor = loadJson(descPath); } catch (e) { console.error(`descriptor sign: ${e.message}`); process.exit(2); }
  try { key = loadJson(keyPath); } catch (e) { console.error(`key: ${e.message}`); process.exit(2); }
  if (!key?.privateKey) { console.error("key file must contain privateKey"); process.exit(2); }
  const signed = signDescriptor(descriptor, key.privateKey);
  const out = opt("--out");
  if (out) writeFileSync(out, JSON.stringify(signed, null, 2) + "\n");
  if (flag("--json")) {
    if (!out) console.log(JSON.stringify(signed, null, 2));
  } else {
    console.log(`${green("✓")} signed descriptor with ${signed.signature.keyId}`);
    if (out) console.log(`  written to: ${dim(out)}`);
  }
}

async function cmdDescriptorVerify() {
  const descPath = positional(2)[0];
  if (!descPath) { console.error("descriptor verify requires <desc.json>"); process.exit(2); }
  let descriptor;
  try { descriptor = loadJson(descPath); } catch (e) { console.error(`descriptor verify: ${e.message}`); process.exit(2); }
  const result = verifyDescriptor(descriptor);
  if (flag("--json")) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    console.log("");
    console.log(`${bold("Descriptor verification")}: ${descPath}`);
    console.log(dim("─".repeat(72)));
    console.log(`${"Schema + signature".padEnd(26)} ${result.ok ? green("VERIFIED") : red("INVALID")}`);
    for (const e of result.errors) console.log(`${"".padEnd(26)} ${red("✗")} ${dim(e)}`);
    console.log("");
  }
  process.exit(result.ok ? 0 : 1);
}

function descriptorDiffInput(descriptor) {
  if (!descriptor?.capability?.interface) { console.error("descriptor diff: input is not a valid descriptor"); process.exit(2); }
  return {
    tools: [descriptor.capability.interface],
    implementation: descriptor.implementation ?? { kind: "unresolved" },
    publisherKeyId: descriptor.provenance?.keyId ?? null,
  };
}

async function cmdDescriptorDiff() {
  const [oldPath, newPath] = positional(2);
  if (!oldPath || !newPath) { console.error("descriptor diff requires <old.json> <new.json>"); process.exit(2); }
  let oldDesc, newDesc;
  try { oldDesc = loadJson(oldPath); } catch (e) { console.error(`descriptor diff: ${e.message}`); process.exit(2); }
  try { newDesc = loadJson(newPath); } catch (e) { console.error(`descriptor diff: ${e.message}`); process.exit(2); }
  const prior = descriptorDiffInput(oldDesc);
  const current = descriptorDiffInput(newDesc);
  const { vector, compatible, summary, interfaceDiff } = changeVector(prior, current);
  if (flag("--json")) {
    console.log(JSON.stringify({ vector, compatible, summary, interfaceDiff }, null, 2));
  } else {
    console.log(`${bold("Descriptor diff")}: ${oldPath} → ${newPath}`);
    console.log(dim("─".repeat(72)));
    console.log(`  interface:      ${vector.interface}`);
    console.log(`  permission:     ${vector.permission}`);
    console.log(`  implementation: ${vector.implementation}`);
    console.log(`  provenance:     ${vector.provenance}`);
    console.log(`  compatible:     ${compatible ? green("yes") : red("no")}`);
    console.log(`  summary:        ${dim(summary)}`);
    console.log("");
  }
  process.exit(compatible ? 0 : 1);
}

async function cmdDescriptorPin() {
  const descPath = positional(2)[0];
  if (!descPath) { console.error("descriptor pin requires <desc.json>"); process.exit(2); }
  let descriptor;
  try { descriptor = loadJson(descPath); } catch (e) { console.error(`descriptor pin: ${e.message}`); process.exit(2); }
  if (!descriptor?.descriptorDigest) { console.error("descriptor pin: input is missing descriptorDigest"); process.exit(2); }
  const pins = new PinStore(opt("--pins"));
  const pin = pins.pinDescriptor(descriptor);
  console.log(`${green("✓")} pinned descriptor ${bold(descriptor.descriptorDigest)}`);
  console.log(`  namespace: ${pin.namespace ?? "(none)"}`);
  console.log(`  interface: ${pin.interfaceDigest ?? "(none)"}`);
  console.log(`  store:     ${dim(pins.path)}`);
}

// renew: re-attest gated servers and extend manifest expiry if nothing changed.
//   mcp-trustcard renew --config <client-config.json> [--within <days>] [--expires-in <days>] [--dry-run] [--json]
//   mcp-trustcard renew <manifest.json> [--expires-in <days>] [--dry-run] -- <server-cmd> [args...]
async function cmdRenew(reapprove = false) {
  const fleet = await import("../lib/fleet.js");
  const days = opt("--expires-in") != null ? Number(opt("--expires-in")) : 90;
  // Default renewal window is 14 days — matching watch/renewalPass. Pass
  // --within 0 to only touch already-expired manifests, or a larger window to
  // renew further ahead of expiry.
  const within = opt("--within") != null ? Number(opt("--within")) : 14;
  if (!Number.isFinite(days) || days <= 0 || !Number.isFinite(within) || within < 0) { console.error("expiry must be positive and --within nonnegative (finite days)"); process.exitCode = 2; return; }
  const dryRun = argv.includes("--dry-run");
  const asJson = argv.includes("--json");
  const configPath = opt("--config");
  let targets;
  if (configPath) {
    targets = fleet.listGated(configPath).gated;
    const only = opt("--server");
    if (only) targets = targets.filter((t) => t.name === only);
  } else {
    const manifestPath = positional(1)[0];
    const local = parseLocalCommand(argv.slice(1));
    const url = opt("--url");
    if (!manifestPath || (!local && !url)) { console.error("renew: need --config <file> or <manifest.json> -- <server-cmd>"); process.exit(2); }
    targets = [{ name: basename(manifestPath, ".json"), manifest: manifestPath, cmd: local?.cmd, args: local?.args, url, env: runtimeOpts().injectedEnv, cwd: opt("--cwd") }];
  }
  if (!targets.length) { console.error("no matching gated servers"); process.exitCode = 2; return; }
  const results = [];
  for (const t of targets) {
    try { results.push(await (reapprove ? fleet.reapproveServer : fleet.renewServer)(t, { days, dryRun, onlyIfWithinDays: within })); }
    catch (e) { results.push({ name: t.name, ok: false, action: "error", reason: e.message }); }
  }
  if (asJson) console.log(JSON.stringify({ results }, null, 2));
  else for (const r of results) {
    // ✓ = applied, ◌ = dry-run preview (nothing written), · = skipped, ✗ = failed
    const mark = !r.ok ? "✗"
      : r.action === "skipped" ? "·"
      : r.action?.startsWith("would-") ? "◌"
      : "✓";
    console.log(`${mark} ${r.name.padEnd(22)} ${r.action.padEnd(20)} ${r.expiresAt ?? r.reason ?? ""}`);
  }
  if (results.some((r) => !r.ok)) process.exitCode = 1;
}

// gate: preview or apply manifest gating for servers in a client config.
//   mcp-trustcard gate --config <file> [--server <name>] [--port <n>]
//                      [--expires-in <days>] [--manifest-dir <dir>]
//                      [--transport streamable-http|sse] [--apply] [--json]
//
// Stdio entries are wrapped in mcp-proxy; HTTP/SSE entries get a generated
// manifest plus a rewritten config entry pointing at a local mcp-http-proxy.
// PREVIEW IS THE DEFAULT — nothing is written until --apply. Gating HTTP
// traffic additionally requires the operator to run the printed mcp-http-proxy
// command; until both steps are done the entry is UNGATED.
async function cmdGate() {
  const fleet = await import("../lib/fleet.js");
  const configPath = opt("--config");
  if (!configPath || !existsSync(configPath)) { console.error("gate: missing --config <client-config.json>"); process.exit(2); }
  const apply = flag("--apply");
  const asJson = flag("--json");
  const port = opt("--port") != null ? parseInt(opt("--port"), 10) : 9876;
  const days = opt("--expires-in") != null ? Number(opt("--expires-in")) : 90;
  if (!Number.isFinite(days) || days <= 0) { console.error("gate: --expires-in must be a positive number of days"); process.exit(2); }
  if (!Number.isFinite(port) || port <= 0 || port > 65535) { console.error("gate: --port must be a valid TCP port"); process.exit(2); }

  const { raw, servers } = fleet.readJsonConfig(configPath);
  const configDir = dirname(resolvePath(configPath));
  const { ungated } = fleet.listGated(configPath);
  const ungatedNames = new Set(ungated.map((u) => u.name));
  const only = opt("--server");
  if (only && servers[only] && !ungatedNames.has(only)) { console.error(`gate: "${only}" is already gated`); process.exitCode = 2; return; }
  if (only && !servers[only]) { console.error(`gate: no configured server named "${only}"`); process.exit(2); }
  const names = Object.keys(servers).filter((n) => ungatedNames.has(n) && (!only || n === only));
  if (!names.length) { console.log(dim("Nothing to gate — every configured server is already wrapped.")); return; }

  const manifestDir = opt("--manifest-dir") ?? join(configDir, "trustcard-manifests");
  const proxyJs = join(dirname(fileURLToPath(import.meta.url)), "mcp-proxy.js");
  const httpProxyJs = join(dirname(fileURLToPath(import.meta.url)), "mcp-http-proxy.js");
  const plans = [];
  for (const name of names) {
    const entry = servers[name];
    const url = entry.url ?? entry.serverUrl;
    const transport = url ? (opt("--transport") ?? "streamable-http") : null;
    const manifestPath = join(manifestDir, `${name.replace(/[^\w.-]/g, "_")}.manifest.json`);
    let live;
    try {
      live = await fleet.listLiveTools(url
        ? { url, headers: entry.headers ?? {}, transport }
        : { cmd: entry.command, args: entry.args ?? [], env: entry.env ?? {}, cwd: entry.cwd });
    } catch (e) {
      plans.push({ name, ok: false, error: `discovery failed: ${e.message}` });
      continue;
    }
    const specStr = url ?? `${entry.command} ${(entry.args ?? []).join(" ")}`.trim();
    const manifest = buildProxyManifest(live.tools, live.serverInfo ?? null, specStr, null, days);
    let nextEntry, proxyCommand;
    if (url) {
      if (!/^https?:\/\//i.test(url)) { plans.push({ name, ok: false, error: `not an http(s) url: ${url}` }); continue; }
      let upstreamPath = "";
      try { upstreamPath = new URL(url).pathname; } catch { upstreamPath = ""; }
      const urlKey = entry.serverUrl != null ? "serverUrl" : "url";
      const meta = {
        ...(entry._meta ?? {}),
        [fleet.TRUSTCARD_HTTP_GATE_KEY]: {
          manifest: manifestPath,
          upstream: url,
          proxy: "mcp-http-proxy",
          gatedAt: new Date().toISOString(),
        },
      };
      nextEntry = { ...entry, [urlKey]: `http://127.0.0.1:${port}${upstreamPath}`, _meta: meta };
      proxyCommand = `${process.execPath} ${httpProxyJs} --manifest ${manifestPath} --upstream ${url} --port ${port}`;
    } else {
      nextEntry = {
        ...entry,
        command: process.execPath,
        args: [proxyJs, "--manifest", manifestPath, "--", entry.command, ...(entry.args ?? [])],
      };
      proxyCommand = null; // the wrapper is the config entry itself
    }
    plans.push({ name, ok: true, tools: live.tools.length, manifestPath, manifest, nextEntry, proxyCommand });
  }

  const failed = plans.filter((p) => !p.ok);
  const planned = plans.filter((p) => p.ok);

  if (asJson) {
    console.log(JSON.stringify({
      applied: apply,
      config: configPath,
      servers: plans.map((p) => p.ok
        ? { name: p.name, tools: p.tools, manifestPath: p.manifestPath, entry: p.nextEntry, proxyCommand: p.proxyCommand }
        : { name: p.name, error: p.error }),
    }, null, 2));
  } else {
    console.log(bold(apply ? "Applying gates:" : "Gate preview (nothing written — pass --apply to write):"));
    for (const p of plans) {
      if (!p.ok) { console.log(`  ✗ ${p.name.padEnd(22)} ${p.error}`); continue; }
      console.log(`  ${apply ? "✓" : "◌"} ${p.name.padEnd(22)} ${p.tools} tool(s) → ${p.manifestPath}`);
      console.log(`    config entry: ${dim(JSON.stringify(p.nextEntry))}`);
      if (p.proxyCommand) console.log(`    run proxy:    ${dim(p.proxyCommand)}`);
    }
    if (planned.length && !apply) {
      console.log(dim("\n  --apply writes the manifest(s) and rewrites the config entries above."));
      console.log(dim("  For HTTP servers the printed mcp-http-proxy command must ALSO be running;"));
      console.log(dim("  until then the entry is ungated (the proxy refuses to start without its manifest)."));
    }
    if (planned.length && apply && planned.some((p) => p.proxyCommand)) {
      console.log(dim("\n  HTTP gates require the printed mcp-http-proxy process to be running."));
      console.log(dim("  `status`/`renew`/`reapprove` discover the upstream recorded in _meta."));
    }
  }

  if (apply && planned.length) {
    const { mkdirSync } = await import("node:fs");
    mkdirSync(manifestDir, { recursive: true });
    const serversKey = raw.mcpServers ? "mcpServers" : "servers";
    for (const p of planned) {
      fleet.atomicWriteJson(p.manifestPath, p.manifest);
      raw[serversKey][p.name] = p.nextEntry;
    }
    fleet.atomicWriteJson(configPath, raw);
    if (!asJson) console.log(green(`\nApplied: ${planned.length} gate(s) written; config updated (backup alongside).`));
  }
  if (failed.length) process.exitCode = 1;
}

// status: what is gated, what isn't, and when gates expire.
//   mcp-trustcard status --config <client-config.json> [--json]
async function cmdStatus() {
  const fleet = await import("../lib/fleet.js");
  const configPath = opt("--config");
  if (!configPath) { console.error("status: missing --config <client-config.json>"); process.exit(2); }
  const { gated, ungated } = fleet.listGated(configPath);
  const rows = gated.map((g) => {
    if (!g.manifest || !existsSync(g.manifest)) return { name: g.name, gated: true, state: "missing-manifest" };
    let m;
    try { m = JSON.parse(readFileSync(g.manifest, "utf8")); if (!Array.isArray(m.tools)) throw new Error("missing tools"); }
    catch (e) { return { name: g.name, gated: true, state: "invalid-manifest", reason: e.message }; }
    const s = fleet.manifestStatus(m);
    return { name: g.name, gated: true, httpGated: !!g.proxyUrl, proxyUrl: g.proxyUrl, ...s, expiresAt: m.expiresAt, tools: m.tools.length, blocked: m.tools.filter((t) => !t.allowed).length, overrides: m.tools.filter((t) => t.manualOverride).length, signaturePresent: !!m.signature, signatureVerified: false };
  });
  const out = { config: configPath, gated: rows, ungated };
  if (rows.some((r) => ["expired", "missing-manifest", "invalid-manifest", "invalid-expiry"].includes(r.state))) process.exitCode = 1;
  if (argv.includes("--json")) { console.log(JSON.stringify(out, null, 2)); return; }
  for (const r of rows) console.log(`  ${r.state === "ok" ? "✓" : r.state === "expiring" ? "!" : "✗"} ${r.name.padEnd(22)} ${String(r.state).padEnd(10)} ${r.daysLeft ?? ""}d  tools=${r.tools ?? "?"} blocked=${r.blocked ?? "?"} overrides=${r.overrides ?? "?"}${r.httpGated ? " (http-gated)" : ""}`);
  for (const u of ungated) console.log(`  - ${u.name.padEnd(22)} UNGATED (${u.transport})${u.transport === "http" ? " — gate with: mcp-trustcard gate --config <this file> --server " + u.name : ""}`);
  if (rows.some((r) => r.state === "expired" || r.state === "missing-manifest")) process.exitCode = 1;
}

async function main() {
  const cmd = argv[0];
  if (!cmd || cmd === "-h" || cmd === "--help" || cmd === "help") return usage();
  switch (cmd) {
    case "scan": return cmdScan();
    case "scan-config": return cmdScanConfig();
    case "gen-manifest": return cmdGenManifest();
    case "renew": return cmdRenew();
    case "reapprove": return cmdRenew(true);
    case "status": return cmdStatus();
    case "gate": return cmdGate();
    case "watch": {
      const configPath = opt("--config");
      if (!configPath) throw new Error("watch: --config <JSON file> required");
      const { watchFleet } = await import("../lib/renewal.js");
      return watchFleet(configPath, { intervalSeconds: opt("--interval") != null ? Number(opt("--interval")) : 21600, within: opt("--within") != null ? Number(opt("--within")) : 14, days: opt("--expires-in") != null ? Number(opt("--expires-in")) : 90, once: flag("--once") });
    }
    case "console": {
      const configPath = opt("--config");
      if (!configPath) throw new Error("console: --config <JSON file> required");
      const { startConsole } = await import("../lib/console.js");
      const server = await startConsole({ configPath, port: opt("--port") != null ? Number(opt("--port")) : 0 });
      console.log(`Trustcard console: http://127.0.0.1:${server.address().port}`);
      return;
    }
    case "inspect": return cmdInspect();
    case "fingerprint": return cmdFingerprint();
    case "manifest": return cmdManifest();
    case "keygen": return cmdKeygen();
    case "sign": return cmdSign();
    case "verify": return cmdVerify();
    case "diff": return cmdDiff();
    case "pin": return cmdPin();
    case "unpin": return cmdUnpin();
    case "pins": return cmdPins();
    case "auth-issue": return cmdAuthIssue();
    case "auth-verify": return cmdAuthVerify();
    case "evidence": return cmdEvidence();
    case "behavior": return cmdBehavior();
    case "descriptor": return cmdDescriptor();
    default: {
      // Bare-argument shorthand for `scan <spec>` is intentional and
      // documented, but only for things that could actually be a spec —
      // otherwise a mistyped subcommand would silently trigger a package
      // download and spawn. Unknown words that look like command typos fail
      // closed; non-spec garbage fails closed too.
      if (cmd.startsWith("-")) { usage(); process.exit(2); }
      if (/^https?:\/\//i.test(cmd)) return cmdScan();
      if (!isNpmSpec(cmd)) {
        console.error(`unknown command: ${JSON.stringify(cmd)}`);
        console.error("run `mcp-trustcard --help` for the command list");
        process.exit(2);
      }
      const near = nearestCommand(cmd);
      if (near) {
        console.error(`unknown command "${cmd}" — did you mean \`${near}\`?`);
        console.error(`(to scan an npm package literally named "${cmd}", run: mcp-trustcard scan ${cmd})`);
        process.exit(2);
      }
      process.stderr.write(dim(`interpreting "${cmd}" as an npm package spec — \`mcp-trustcard scan ${cmd}\` is the explicit form\n`));
      argv.unshift("scan"); // positional(1) expects argv[0] to be the command name
      return cmdScan();
    }
  }
}

// Edit distance ≤ 2 against the command table catches the classic typo case
// (`verfy`, `staus`, `descripto`) without eating real package names.
const SUBCOMMANDS = [
  "scan", "scan-config", "gen-manifest", "renew", "reapprove", "status",
  "watch", "console", "inspect", "fingerprint", "manifest", "keygen", "sign",
  "verify", "diff", "pin", "unpin", "pins", "auth-issue", "auth-verify",
  "evidence", "behavior", "descriptor", "gate",
];
function nearestCommand(word) {
  if (word.length < 3 || word.includes("/") || word.includes("@") || word.includes(".")) return null;
  const dist = (a, b) => {
    const m = a.length, n = b.length;
    const prev = Array.from({ length: n + 1 }, (_, j) => j);
    for (let i = 1; i <= m; i++) {
      const cur = [i];
      for (let j = 1; j <= n; j++) {
        cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
      }
      prev.splice(0, prev.length, ...cur);
    }
    return prev[n];
  };
  let best = null, bestD = Infinity;
  for (const c of SUBCOMMANDS) {
    const d = dist(word, c);
    if (d < bestD) { bestD = d; best = c; }
  }
  return bestD <= 2 ? best : null;
}

main().catch((e) => { console.error("fatal:", e.message ?? e); process.exit(1); });
