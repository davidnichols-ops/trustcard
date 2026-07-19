#!/usr/bin/env node
// mcp-trustcard — cryptographic trust infrastructure for MCP servers.
//
// Subcommands:
//   scan        empirical health scorecard (the original trust card)
//   fingerprint full identity card: digests, provenance, pin continuity
//   manifest    build an unsigned manifest from a live probe
//   keygen      generate a publisher Ed25519 keypair
//   sign        sign a manifest with a publisher key
//   verify      verify a signed manifest (+ optionally against a live probe)
//   diff        classify changes between two manifests/fingerprints
//   pin         trust-on-first-use: pin a server's observed identity
//   unpin       remove a server pin
//   pins        list the pin store
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { runHealthcheck } from "../lib/checks.js";
import { fingerprint } from "../lib/fingerprint.js";
import { observeServer } from "../lib/observe.js";
import { buildManifest, signManifest, verifyManifest, generatePublisherKeypair, bindingConsistency } from "../lib/provenance.js";
import { diffToolsets, CHANGE_LEVEL } from "../lib/diff.js";
import { PinStore } from "../lib/pin.js";
import { printFingerprint, printDiff } from "../lib/report.js";

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
  const VALUE_FLAGS = new Set(["--manifest", "--out", "--key", "--pins", "--spec", "--json-out", "--batch"]);
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

Health scorecard (original):
  mcp-trustcard scan <spec> [--json]
  mcp-trustcard scan --batch servers.json [--json-out results.json]
  mcp-trustcard <spec>              # shorthand for scan

Options: --json  --no-color  --pins <path>  -h/--help`);
}

function loadJson(path) { return JSON.parse(readFileSync(path, "utf8")); }

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
    const st = chk.status === "PASS" ? green("PASS")
      : chk.status === "WARN" ? yellow("WARN")
      : chk.status === "FAIL" ? red("FAIL")
      : chk.status === "CONFIG_REQUIRED" || chk.status === "REQUIRED" ? blue(chk.status === "CONFIG_REQUIRED" ? "CONFIG" : "REQUIRED")
      : dim("UNKNOWN");
    console.log(`${labels[key].padEnd(26)} ${st}  ${dim(chk.detail ?? "")}`);
  }
  console.log(dim("─".repeat(56)));
  const scoreColor = r.score >= 75 ? green : r.score >= 50 ? yellow : red;
  console.log(`${"Score".padEnd(26)} ${scoreColor(bold(`${r.score}/${r.max}`))}`);
  if (r.tools?.length) console.log(`${dim(`Tools (${r.tools.length}):`)} ${r.tools.slice(0, 8).map((t) => t.name).join(", ")}${r.tools.length > 8 ? "…" : ""}`);
  console.log("");
}

async function cmdScan() {
  const batchIdx = argv.indexOf("--batch");
  const jsonOut = opt("--json-out");
  if (batchIdx !== -1) {
    const file = argv[batchIdx + 1];
    if (!file || !existsSync(file)) { console.error("missing --batch file"); process.exit(2); }
    const list = loadJson(file);
    const results = [];
    for (const entry of list) {
      const spec = typeof entry === "string" ? entry : entry.spec;
      const env = typeof entry === "object" ? entry.env : undefined;
      process.stderr.write(`scanning ${spec}...\n`);
      const r = await runHealthcheck(spec, { env });
      results.push(r);
      printHealth(r);
    }
    if (jsonOut) writeFileSync(jsonOut, JSON.stringify(results, null, 2));
    return;
  }
  const pos = positional(argv[0] === "scan" ? 1 : 0);
  const spec = pos[0];
  if (!spec) { usage(); process.exit(2); }
  const r = await runHealthcheck(spec);
  if (flag("--json")) console.log(JSON.stringify(r, null, 2));
  else printHealth(r);
  process.exit(r.score >= 50 ? 0 : 1);
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
