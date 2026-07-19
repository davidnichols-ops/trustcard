# Changelog

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
