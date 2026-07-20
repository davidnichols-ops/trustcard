# Changelog

## [2.2.1] — 2026-07-19

Patch release fixing two issues found in the v2.2.0 comparison report
(same 104-server census, same Colab environment, reproducible).

### Fixed

- **`create_directory` false positive (residual)** — v2.2.0's `silently`
  injection pattern over-matched "succeeds silently" in the official
  `@modelcontextprotocol/server-filesystem` description. "Succeed silently"
  and "fail silently" are standard API idioms meaning "idempotent, no error
  if already exists" — not secrecy instructions. Fix: `secretly`/`covertly`/
  `stealthily` are always suspicious (no benign use). `silently`/`quietly`
  are only suspicious when paired with a covert-action verb (`read silently`,
  `exfiltrate silently`). The safe-tool-pattern override now applies correctly
  to `create_directory`.
- **Unbracketed injection language missed** — v2.2.0 only matched
  `<IMPORTANT>` and `[SYSTEM OVERRIDE]` syntax. The sentinel-malicious server
  uses "IMPORTANT SYSTEM UPDATE" and "URGENT SECURITY NOTICE" without brackets
  — 6/8 tools were missed. Fix: added patterns for unbracketed system-message
  mimics: `(IMPORTANT|CRITICAL|URGENT) (SYSTEM|SECURITY|ADMIN|SAFETY)
  (UPDATE|NOTICE|REQUIREMENT|WARNING|ALERT|...)`. Benign "important" in
  normal context ("this is an important tool") does NOT match — the pattern
  requires the system/security/admin noun qualifier.

### Tests

- 283 (273 + 10 new): `succeed silently` / `fail silently` benign,
  `read silently` / `exfiltrate silently` flagged, `secretly` always flagged,
  unbracketed `IMPORTANT SYSTEM UPDATE` / `URGENT SECURITY NOTICE` /
  `CRITICAL SYSTEM REQUIREMENT` flagged, benign `important` not flagged.

## [2.2.0] — 2026-07-19

Adds a prompt-injection detector and fixes two false positives found in an
external MCP Census + Trustcard Evaluation Report (104 servers, 57 live,
1,218 tools, 5 rogue servers, 5 real-world tool-poisoning PoCs).

### Added

- **Prompt-injection detector** (third engine in the fusion) — scans tool
  descriptions for injection markers: `<IMPORTANT>` tags, `[SYSTEM OVERRIDE]`
  brackets, "ignore previous instructions", "do not tell the user", sensitive
  file paths (`~/.ssh/id_rsa`), secrecy instructions, base64 blobs,
  exfiltration language, system prompt extraction attempts. This is a separate
  threat class from destructive actions — a tool can have a benign schema
  ("add two numbers") with a weaponized description. Catches both real-world
  PoCs that v2.1 missed: malicious-demo-mcp-server (SSH key exfil via
  `<IMPORTANT>` block) and sentinel-malicious (`[SYSTEM OVERRIDE]`).

### Fixed

- **`sequentialthinking` false positive** — flagged on the verb "clear" in a
  thinking tool's description ("clear previous thinking to start fresh").
  This silently zeroed out the only tool the server exposes. Fix: context-aware
  verb scoring. `clear`/`reset`/`flush`/`clean`/`abort`/`disable` are only
  destructive when paired with destructive nouns (files, data, cache,
  database). Without a destructive noun, they're benign cognitive operations.
  Also whitelisted as a safe tool pattern.
- **`create_directory` false positive** — flagged because "create" is a write
  verb and the semantic engine matched "create write file disk storage". Fix:
  safe tool pattern whitelist (`create_directory`, `mkdir`, `sequentialthinking`).
  Override applies in the fusion layer unless the injection detector flags the
  description (a poisoned `create_directory` is still dangerous).

### Tests

- 273 (254 + 19 new): 6 false-positive / context-aware tests, 10 injection
  detector tests, 3 full-fusion tests with injection.

## [2.1.0] — 2026-07-19

Pre-freeze security model hardening. Clarity over capability — adds the
documentation and features needed for an external security engineer to
understand exactly what trustcard guarantees in one afternoon.

### Added

- **`docs/SECURITY-MODEL.md`** — guarantees table (20 rows: property,
  guaranteed?, mechanism, code location), two-gate model explained, trust-level
  projection (6 internal states → 4 human-facing levels), manifest freshness
  rules, schema versioning migration contract (5 rules), explicit non-goals.
- **Manifest expiration** — proxy manifests now carry `expiresAt` (default
  90 days). `checkCall` blocks all calls when expired, with a regeneration
  hint. `--expires-in <days>` and `--no-expiry` flags on `gen-manifest`.
- **Trust level projection** (`lib/trust.js`) — `trustLevel(state)` maps the
  6 internal states to 4 human-facing levels: TRUSTED / OBSERVED / UNTRUSTED
  / REVOKED. Internal state machine unchanged; this is a derived view for UIs.
- **`inspect` command** — `trustcard inspect <file>` works on proxy manifests,
  signed manifests, and pin stores. Shows expiry status, danger scores,
  overrides, verification errors.
- **Block explanations** (`bin/mcp-proxy.js`) — `explainDenial()` produces
  structured `data` in JSON-RPC error responses. Three denial types:
  `MANIFEST_EXPIRED`, `TOOL_NOT_APPROVED`, `DANGEROUS_TOOL`. Each includes
  explanation, metadata, and an action.
- **`--allow-tool` flag** on `gen-manifest` — explicitly mark a dangerous tool
  as allowed. Override recorded as `manualOverride: true` in the manifest.
- **Reference deployment** (`examples/production-agent/`) — architecture
  diagram, component descriptions, deployment steps, explicit non-goals.

### Tests

- 254 (243 + 11 new in `test/security-model.test.js`): trust level projection,
  manifest expiration, block explanation structure.

## [2.0.0] — 2026-07-19

Major release. Adds the v2 enforcement surface, closes two release-blocking
findings from a pre-release adversarial audit, **and unifies the two
development lines**. See [`docs/AUDIT-REPORT-v2.md`](docs/AUDIT-REPORT-v2.md).

**v2.0.0 is both the strongest MCP scanner and the first real capability-trust
substrate for agentic tools.** It merges the crypto/protocol line (descriptors,
Gate 2, receipts, rotation) with the scanner/proxy line (v0.4.0–v0.5.4: AI-fusion
danger detection, stdio + HTTP/SSE enforcement proxies, config secret scanning,
100-server leaderboard) into one tool. The scanner tells you *whether a server
looks healthy*; the protocol proves *the tool you called is the tool a publisher
signed*. Neither alone is sufficient — v2.0.0 is the union.

### Merged (scanner / proxy line, v0.4.0–v0.5.4)

- **AI-fusion danger detection** — heuristic (verb + parameter analysis) fused
  with a semantic engine (TF-IDF cosine similarity over a dangerous-actions
  corpus). Catches tool poisoning, schema shadowing, and novel attack patterns.
- **Call-time enforcement proxies** — `mcp-proxy` (stdio) and `mcp-http-proxy`
  (HTTP/SSE) enforce an approved tool manifest at call time, client-agnostic.
- **Config-file secret scanning** (`scan-config`) and proxy log **redaction**.
- **100-server leaderboard**, rogue-server test suite, and a supply-chain attack
  demo. CLI: parallel batch scanning, `--env-file`, local-command, `--strict`,
  `--threshold`. The unified CLI adds these to the crypto subcommands; the proxy
  manifest generator is `gen-manifest` (distinct from the crypto `manifest`).

### Added

- **Capability descriptors** — a protocol-neutral, publisher-signed projection
  of any tool source (MCP, OpenAPI, function-calling) into one canonical
  contract. Trust no longer depends on MCP-specific JSON shape. (`lib/descriptor.js`,
  `docs/DESCRIPTOR.md`)
- **Gate 2 invocation policy** — per-call argument re-validation against the
  *approved* descriptor's schema plus an optional per-tool arg policy, scoped per
  agent. Complements Gate 1 ("is this the tool we approved?"). (`lib/policy.js`)
- **Signed, chained receipts** — receipts are Ed25519-signed and hash-chained so
  history is tamper-evident and unforgeable end-to-end. (`lib/receipts.js`)
- **Publisher key rotation & revocation** — the old key signs an expiring
  rotation certificate to hand off trust; a revocation certificate retires a key
  permanently (no expiry, by design). (`lib/rotation.js`)

### Security (audit findings, fixed)

- **Receipt-chain verification now recomputes `receiptDigest`** for every receipt
  instead of trusting the embedded value. Previously a tampered receipt *body*
  that kept its chain fields passed verification. (Finding 1)
- **Rotation certificates now enforce `expiresAt`.** Previously a rotation cert
  could be replayed indefinitely, letting a stolen old key keep authorizing
  rotations. Revocation deliberately has no expiry. (Finding 2)

### Verification

- `npm test` → **243 tests, 243 pass, 0 fail** across the unified suite (crypto
  protocol + scanner/proxy), including the adversarial suite
  (`test/adversarial.test.js`, `test/audit-probes.test.js`) that executes the
  THREAT-MODEL attacks as real tests.
- Clean-install verified: `npm pack` → fresh install imports all v2 entry points.

### Docs

- SPEC: §12.1 what a signed receipt proves (and does not); §13.1 rotation expiry.
- THREAT-MODEL: v2 attack table (#12–#19).
- README: v2 features, updated test counts, doc links.

## [1.0.0]

v1: content-addressed tool identity, signed manifests, TOFU pinning, a
trust-state machine, an enforcement gate, and reproducibility receipts.
