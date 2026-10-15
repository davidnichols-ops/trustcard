# Behavioral verification for MCP servers

> **Current as of trustcard v3.0.3.** For the long-term vision, see
> [`ROADMAP-2Y.md`](ROADMAP-2Y.md).

`mcp-trustcard behavior` executes a server as a process-isolated stdio child —
fresh working directory and minimal environment, **not** an OS sandbox (the
child can still reach the network and filesystem). It fires deterministic
seeded probes, and compares what the server actually does against a
reference observation or its own runtime expectations.

It answers a question the static trust substrate cannot: **does the running
code honor the contract it signed?** Two servers can have byte-identical
tool lists and still diverge at runtime. This layer catches observable
divergence, produces structured evidence, and writes replayable regression
artifacts.

## What behavioral verification proves and does not prove

### Proves

- The server starts, handshakes, lists tools, and responds to calls within
  configured timeouts.
- Tool outputs conform to the declared schema for valid and boundary inputs.
- Secret-like values sent into a tool are not echoed back in the response or
  stderr.
- Prompt-injection markers and exfiltration URLs are not *newly minted* in tool
  outputs (echoing the input is expected and scored separately).
- Unexpected stderr network/filesystem/process events are observed.
- Output shape, error behavior, and side-effect signals are stable relative to
  a reference observation.

### Does not prove

- **No actual containment.** The Node stdio sandbox sets a clean `cwd`, limits
  environment variables, captures stdout/stderr, and kills the process tree,
  but it does not block network, filesystem, or process spawn at the OS level.
  Capability labels are truthful: `network: "not-observed"` means the harness
  watches for evidence; it does not mean egress is impossible.
- **No absence of bugs.** Probes are seeded and deterministic but finite. A
  server can pass every probe and still fail on real inputs.
- **No universal runtime proof.** The harness records the process layer. Hidden
  side effects that leave no trace in stdout/stderr/exit are not detected.
- **No guarantee the reference is good.** A reference observation only captures
  what the reference server did. If the reference itself is malicious, the
  comparison is meaningless.

## Trust model

1. The server's static identity is still computed by `lib/identity.js`.
   `toolsetDigest` and `serverDigest` are unchanged from the established
   substrate.
2. A reference observation is a captured `BehaviorReport` converted to an
   `ReferenceObservation`. It stores identity, server info, tool metadata, and
   per-probe observations keyed by probe id.
3. Probes are generated deterministically from a seed, so rerunning the same
   server with the same seed produces the same inputs.
4. The `OutputComparator` is split into **fact** and **heuristic**:
   - *Fact:* protocol errors, JSON-RPC parse errors, schema mismatch,
     timeout, crash, canary leakage, stderr network/filesystem/process events.
   - *Heuristic:* prompt-injection marker drift, new URLs in output, output
     text drift relative to reference.
5. A finding's `confidence` reflects the strength of the evidence, not a
   guarantee of exploitability.

## Harness semantics

`SandboxRuntime` (`lib/behavior.js`) launches the server as an MCP stdio child.
(The class name predates the honest-labeling pass — it is a **process harness**,
not an OS sandbox; it does not restrict network, filesystem, or subprocesses.)

- `cwd` is a fresh temp directory by default, or a caller-provided directory.
- Environment is minimal (`PATH` plus `HOME`/`TMPDIR`/`TEMP` mapped to the
  harness `cwd`). Use `inheritEnv: true` only when the server genuinely needs
  the caller's environment.
- `detached: true` runs the child in its own process group and kills the
  whole group on stop.
- `spawnTimeout` bounds the MCP handshake; `callTimeout` bounds each tool call.
- Stdout is parsed as JSON-RPC. Stderr is accumulated and sliced per-call so
  each observation carries only the delta since the previous call.
- On stop, stdin is closed, `SIGTERM` is sent, a 50 ms grace period passes,
  then `SIGKILL` is sent.

Capability labels on every report:

- `network: "not-observed"` — the harness did not observe raw network calls;
  it only sees URLs in stdout/stderr.
- `filesystem: "cwd-isolated"` — the server starts in a fresh directory;
  writes outside it are not blocked.
- `subprocesses: "stderr-only"` — child process events are inferred from
  stderr text, not syscall interception.

## Probe categories

`InputGenerator` builds a small, deterministic corpus per tool:

| Category | Purpose |
|---|---|
| `valid` | Normal, schema-following call. |
| `boundary` | Edge values: empty string, minLength/maxLength, numeric limits, empty arrays. |
| `malformed_missing_required` | Omit required properties and observe error behavior. |
| `malformed_wrong_type` | Pass wrong types and observe error behavior. |
| `long_string` | Very long strings to detect truncation or instability. |
| `unicode` | Unicode, zero-width characters, bidirectional markers. |
| `path_like` | Filesystem-looking paths (e.g. `/etc/passwd`). |
| `url_like` | URL-looking strings. |
| `prompt_injection` | Strings containing injection markers. |
| `secret_canary` | Only for schemas with a secret-like property; inserts `TC-CANARY-...` and checks for leakage. |

Probe count is controlled by `probesPerTool`. The generator is seeded by a
PRNG derived from SHA-256 of the seed, so the same seed always emits the same
probes.

## Findings and divergence classes

Each `BehaviorFinding` has:

- `id`, `server`, `tool`, `probe`
- `divergenceClass`, `mechanism`, `severity`, `confidence`
- `evidence`, `suggestedFixes`, `reproducibility` (seed, runtime metadata,
  reference/target toolset digests), `timestamp`

Divergence classes:

| Class | Typical trigger |
|---|---|
| `schema_violation` | Non-ok response to a valid probe, or ok response to a malformed one. |
| `output_shape_drift` | Output shape differs from the reference for the same probe. |
| `unexpected_tool_behavior` | Canary leakage, output text drift, side-effect mismatch. |
| `prompt_injection` | New injection markers appear in output that were not in input. |
| `exfiltration_instruction` | A URL appears in output that was not in input. |
| `unexpected_network_attempt` | Stderr contains an external-fetch or HTTP network event. |
| `unexpected_filesystem_attempt` | Stderr contains a filesystem write/read event. |
| `process_spawn_attempt` | Stderr contains a child-process spawn event. |
| `nondeterministic_behavior` | Same seed produces different outputs across runs. |
| `timeout` | Tool call exceeded `callTimeout`. |
| `crash` | Child process exited unexpectedly. |
| `state_transition_drift` | Stateful server state differs from reference after a sequence. |
| `unauthorized_side_effect` | Reference recorded a side effect that target does not, or vice versa. |

Severity rolls up into the report summary: any `critical` or `high` finding
makes the report `fail`; `medium` findings make it `warn`; otherwise `pass`.

## Deterministic replay

The `RegressionCorpus` writes one artifact per finding:

```json
{
  "reportId": "...",
  "finding": { ... },
  "probe": { "id": "...", "tool": "...", "args": { ... } },
  "serverIdentity": { "toolsetDigest": "sha256:...", "tools": [...] },
  "referenceObservation": { ... },
  "targetObservation": { ... },
  "recordedAt": "..."
}
```

Because the probe, seed, server identity, and reference observation are all
captured, a regression can be replayed by re-running the same server with the
same probe id and comparing the new observation to the recorded one.

## Differential verification

`mcp-trustcard behavior diff <reference.json> <target.json>` compares two
behavior reports and lists:

- `toolsetDigestMatch`: whether the static contract is identical.
- `added` findings: present in the target but not the reference.
- `removed` findings: present in the reference but not the target.

This is the core acceptance test: a server whose `toolsetDigest` matches the
reference can still have `added` high-severity behavioral findings, proving
that static identity does not imply behavioral trust.

## CLI usage

```text
mcp-trustcard behavior <manifest.json>
  [--server <npx-spec>] [--corpus <dir>] [--json]
  [--seed <n>] [--timeout <ms>] [--probe <id>] [--verbose]
  [-- <cmd> [args...]]

mcp-trustcard behavior diff <reference-report.json> <target-report.json>
```

Manifest `server` field:

```json
{
  "server": {
    "cmd": "node",
    "args": ["server.js"],
    "env": { "FOO": "bar" }
  },
  "reference": "reference-observation.json"
}
```

Options:

- `--server <spec>`: shortcut that builds `npx -y <spec>`.
- `--corpus <dir>`: directory for regression artifacts.
- `--seed <n>`: seed for deterministic probes (default `0`).
- `--timeout <ms>`: spawn and call timeout (default `30000`).
- `--probe <id>`: run only the probe whose id or type matches.
- `--json`: emit the report as JSON.
- `--verbose`: print per-probe timing.
- `-- <cmd> [args...]`: run a local command instead of the manifest server.

Exit codes: `0` for `pass`, `1` for `warn`/`fail` or missing arguments.

## Design notes

- The module is additive: it does not modify `toolDigest`, `toolsetDigest`,
  `serverDigest`, manifest signing, or the trust state machine.
- It adds zero runtime dependencies; only Node stdlib is used.
- The reference observation is a snapshot, not a contract. Differential
  verification is only as strong as the reference run it compares against.
- Canary leakage detection is scoped to secret-like parameters. A non-secret
  string field that echoes an injected canary is reported at `low` severity to
  avoid false positives; a secret-like field that leaks is `high`.

## Relationship to evidence and roadmap

Behavior reports are the raw material for the evidence substrate
(`lib/evidence.js`, `lib/evidence-store.js`). Each finding is a candidate
observation that can be stored as a content-addressed, signed evidence record.

The first roadmap gate after v3.0.3 is **behavior → evidence bridge**
(`ROADMAP-2Y.md` Gate Y1-H1): running `mcp-trustcard behavior` with an optional
`--evidence-dir` should append evidence records per finding and make them
queryable with `mcp-trustcard evidence query --subject <server>`.

Other near-term work includes HTTP/SSE transport parity for the behavioral
harness, a real-world reference corpus, and an observatory scheduler. Deep
containment (OS-level namespaces, TEE attestation, syscall tracing) is an
explicit Y2 goal and must remain optional and truthfully labeled.
