---
name: testing-trustcard-behavior
description: End-to-end verification of the trustcard behavioral verification engine (lib/behavior.js and the mcp-trustcard behavior CLI).
---

# Testing the trustcard behavioral verification engine

Use this skill when you need to verify the `lib/behavior.js` engine or the `mcp-trustcard behavior` CLI subcommands on the `devin/behavior-engine` branch.

## Devin Secrets Needed

None. All commands run locally with Node >=18 and the in-repo fixture server.

## One-time environment

- Repo root: `/home/ubuntu/repos/trustcard` (or the current repo root).
- Branch: `devin/behavior-engine`.
- Node >=18, npm installed, no external dependencies required (`package.json` has none).
- `npm test` must pass before claiming behavioral tests are valid.

## Commands

Run the full suite:

```bash
npm test
```

Run the behavioral CLI against the benign fixture (process-substitution manifest):

```bash
node bin/mcp-trustcard.js behavior \
  <(echo '{"server":{"cmd":"node","args":["test/fixtures/behavior-mem-server.js"]}}') \
  --corpus /tmp/tc-corpus/benign --json > /tmp/tc-benign.json
# Expected: exit 0, report.summary === "pass"
```

Run the behavioral CLI against the malicious same-contract fixture:

```bash
node bin/mcp-trustcard.js behavior \
  <(echo '{"server":{"cmd":"node","args":["test/fixtures/behavior-mem-server.js"],"env":{"TRUSTCARD_EVIL":"1"}}}') \
  --corpus /tmp/tc-corpus/evil --json > /tmp/tc-evil.json
# Expected: exit 1, report.summary === "fail",
# findings include prompt_injection, exfiltration_instruction,
# unexpected_tool_behavior, unexpected_network_attempt, all high severity.
```

Diff the two reports:

```bash
node bin/mcp-trustcard.js behavior diff \
  /tmp/tc-benign.json /tmp/tc-evil.json --json > /tmp/tc-diff.json
# Expected: exit 1, toolsetDigestMatch === true,
# added findings contain the four classes above.
```

Isolate a single probe (use `--probe <tool>:<type>:<index>`):

```bash
node bin/mcp-trustcard.js behavior \
  <(echo '{"server":{"cmd":"node","args":["test/fixtures/behavior-mem-server.js"]}}') \
  --probe greet:valid:0 --json
# Expected: exit 0, probesTotal === 1, probesPassed === 1, summary === "pass".
```

## Process-cleanup check

After any fixture-invoking command, verify no orphan `behavior-mem-server` processes remain. Avoid matching the pgrep command itself by using a regex character class:

```bash
pgrep -af "[b]ehavior-mem-server" || true
```

If any PIDs are listed, `kill -9` them and report it as a cleanup bug.

## What success looks like

- `npm test` exits 0 with `# pass` matching the expected test count (currently 626).
- Benign fixture: exit 0, `Summary: pass`, no high/critical findings.
- Evil fixture: exit 1, `Summary: fail`, exactly the four high-severity classes above.
- Diff: toolset digest match, four added findings.
- `--probe`: runs exactly one probe and finishes quickly.
- No orphaned `node behavior-mem-server.js` processes after any run.

## Common pitfalls

- Bare `node --test` (without `test/*.test.js`) can hang on fixture servers; always use the `npm test` glob from `package.json`.
- When checking for orphans, a naive `pgrep -af "behavior-mem-server"` matches the shell command itself; use the `[b]...` trick.
- The `--probe` filter accepts an exact probe id or a probe type; use `tool:type:index` to isolate one probe.
- The manifest `server.env` is the correct way to pass `TRUSTCARD_EVIL=1`; setting it in the caller's environment is not enough because `SandboxRuntime` defaults to `inheritEnv: false`.
