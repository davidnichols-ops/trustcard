// npm/npx helpers — argv-only child execution, never a shell.
//
// Every invocation uses execFile with an argument array: the package spec is a
// single argv element, never interpolated into a shell string. Specs are also
// validated against npm's registry-spec grammar before any child process runs,
// so a hostile spec cannot be re-interpreted as an npm/npx flag (e.g.
// "--registry=evil.example") or reach a shell.
import { execFile as execFileCb } from "node:child_process";
import { promisify } from "node:util";

const execFile = promisify(execFileCb);

export const NPM_BIN_CANDIDATES = ["npm", "/opt/homebrew/bin/npm", "/usr/local/bin/npm"];
export const NPX_BIN_CANDIDATES = ["npx", "/opt/homebrew/bin/npx", "/usr/local/bin/npx"];

// Registry-style npm spec: [scope/]name[@version|tag|range].
// Deliberately narrower than npm's full spec grammar — no git URLs, no
// tarballs, no file: paths, no whitespace or shell metacharacters. Those forms
// never reach npx through this CLI (local commands use the `-- cmd args` form).
const NPM_NAME = "[a-z0-9][a-z0-9._~-]*";
const NPM_SPEC_RE = new RegExp(
  `^(?:@${NPM_NAME}/)?${NPM_NAME}(?:@[a-z0-9^~<>=*x|][a-z0-9._~|^*<>=x,-]*)?$`,
  "i",
);

export function isNpmSpec(spec) {
  return typeof spec === "string" && spec.length > 0 && spec.length <= 214 && NPM_SPEC_RE.test(spec);
}

export function assertNpmSpec(spec) {
  if (!isNpmSpec(spec)) {
    const shown = typeof spec === "string" ? JSON.stringify(spec.slice(0, 80)) : String(spec);
    throw new Error(`invalid npm package spec ${shown} — expected [scope/]name[@version-or-tag]`);
  }
}

// First candidate that answers `bin --version` within the timeout.
export async function probeBin(candidates = NPM_BIN_CANDIDATES, { timeoutMs = 5_000, env = process.env } = {}) {
  for (const candidate of candidates) {
    try {
      await execFile(candidate, ["--version"], { timeout: timeoutMs, env });
      return candidate;
    } catch {
      // try the next candidate
    }
  }
  return candidates[0];
}

// `npm view <spec> <fields...> --json` — argv form, spec validated first.
export async function npmView(spec, fields, { timeoutMs = 30_000, env = process.env, npmBin } = {}) {
  assertNpmSpec(spec);
  const bin = npmBin ?? await probeBin(NPM_BIN_CANDIDATES, { env });
  const { stdout } = await execFile(bin, ["view", spec, ...fields, "--json"], { timeout: timeoutMs, env });
  return JSON.parse(stdout);
}
