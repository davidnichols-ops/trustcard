# OpenHands Session Context — trustcard v2 hardening audit

This file gives a Devin CLI agent the context of 5 OpenHands sessions
(conversation IDs `045ac8f0`, `274ce0d2`, `df33bd98`, `75607f0a`, `a91e5092`)
that worked on trustcard from 2026-07-19. The sessions ran Kimi K3 via
OpenRouter against this repo and produced the v2 critical path plus the
release-hardening audit. A final 2026-07-19 session (Kimi K3) finished the
audit report, threat-model/README/CHANGELOG updates, and the v2.0.0 version
bump, and committed the result.

> **STATUS (as of the v2.0.0 commit): the audit is COMMITTED and RELEASED.**
> Do not redo it. The findings below are fixed; the suite is 164/164;
> `package.json` is `2.0.0`. What remains is listed in "Open follow-ups".

Read this BEFORE touching the repo. The AGENTS.md file has the architecture
map and invariants; this file has the session-derived state.

## What the sessions were asked to do

> Turn trustcard from a useful prototype into a defensible protocol-level
> infrastructure project. Analyze the current implementation, the MCP
> ecosystem, tool-definition drift, server identity, trust boundaries,
> caching, versioning, and the failure modes of agents operating against
> mutable tools. Determine whether the current Trustcard abstraction is
> fundamentally sufficient. Then design and implement the strongest version
> of the system you can.

The user then pushed through three phases: (1) adversarial architecture
analysis, (2) v2 capability descriptor implementation, (3) one-shot
completion of the v2 critical path, and finally (4) a release hardening
audit with executable attack simulations.

## What landed in git (committed, on `master`)

Last 4 commits at HEAD `5e4d212`:

| Commit | What |
|---|---|
| `5e4d212` | v2 enforcement: Gate 2 invocation policy, signed chained receipts, key rotation |
| `2484294` | v2: protocol-neutral Capability Descriptor core (additive over v1) |
| `6c95076` | docs: TRUST-SUBSTRATE — what a general agentic trust layer should become |
| `8eb727c` | trustcard v1: cryptographic trust infrastructure for MCP tools |

Test count at HEAD: **147/147 passing**. Tree clean at HEAD.

## What was committed in the v2.0.0 release commit

The previously-uncommitted audit work is now committed. The release commit
includes:

```
 M README.md
 M docs/SPEC.md
 M docs/THREAT-MODEL.md
 M lib/receipts.js
 M lib/rotation.js
 M package.json            (version 1.0.0 → 2.0.0)
 M AGENTS.md               (164-test count + pointer to this file)
?? test/adversarial.test.js
?? test/audit-probes.test.js
?? docs/AUDIT-REPORT-v2.md
?? CHANGELOG.md
```

Test count at the release commit: **164/164 passing** (147 prior + 17 new).

### Committed audit changes — what they were

These are the **release hardening audit** deliverables from the last session
(`045ac8f0`, user message `71c767de`). The user asked for "v2.0 Release
Hardening Audit" and the agent produced:

1. **`lib/receipts.js`** — `verifyReceiptChain()` now RECOMPUTES each
   receipt's digest from the payload and requires it to match the embedded
   field. Before, an attacker could tamper the body and keep the original
   digest; the parentReceipt links would still line up. Now content forgery
   is detected. This is a real security fix.

2. **`lib/rotation.js`** — rotation/revocation cert verification hardened
   (exact change small, ~9 lines).

3. **`test/adversarial.test.js`** (NEW, ~A1–A6 attacks) — executable attack
   simulations. Every test attempts an attack and asserts the control holds.
   A PASS means the attack was REJECTED. Where the control is weak, the test
   documents the gap explicitly (release-blocking). Covers: forged descriptor
   signatures, receipt chain tampering, key rotation attacks, etc.

4. **`test/audit-probes.test.js`** (NEW) — pins the *classification* of
   MCP-specific changes so the release report can state precisely which
   changes are informational / authorization-relevant / trust-breaking.
   Covers: description rewrite → ANNOTATION_DOWNGRADE, permission expansion,
   implementation swap with identical interface, publisher key change.

5. **`docs/SPEC.md`, `docs/THREAT-MODEL.md`, `README.md`** — documentation
   accuracy fixes (removes overclaims per the audit's task #8).

### The audit task list — final status

```
1. Trust boundary map (table: trusted/verified/assumed/forged/compromised per boundary)  [DONE — AUDIT-REPORT §5]
2. Gate separation audit — stress-test (relyingParty, capability, environment) cache key   [OPEN — see follow-ups]
3. Policy engine audit — determinism, ordering, defaults, deny-on-uncertainty              [OPEN — see follow-ups]
4. Receipt system audit — modify/delete/reorder/replay/fork + verification semantics       [DONE, committed]
5. Key lifecycle audit — compromised old/new key, revocation replay/ordering               [DONE: rotation expiry + revocation permanence]
6. Descriptor identity audit — which changes are trust-breaking (MCP-specific)             [DONE, audit-probes.test.js]
7. Agent attack simulation — attacks 1-6 as executable code                                 [DONE, adversarial.test.js]
8. Documentation accuracy audit — remove overclaims                                         [DONE, docs/ + README.md]
9. Compatibility audit — v1 API/receipt/guard parity                                        [OPEN — see follow-ups]
10. Release checklist — clean install, changelog, report, version bump                      [DONE]
Deliverables: audit report, threat model update, fixes, release recommendation              [DONE]
```

## What is DONE (do not redo)

- Audit findings #1 (receipt-chain forgery) and #2 (rotation replay) are
  **fixed and pinned** by regression tests.
- Audit report written: `docs/AUDIT-REPORT-v2.md`.
- THREAT-MODEL v2 attack table (#12–#19) added; SPEC §12.1 (receipt semantics)
  and §13.1 (rotation expiry) documented.
- README updated (v2 features, 164-test count, doc links); CHANGELOG.md created.
- `package.json` bumped to `2.0.0`; clean install verified (24-file pack, all v2
  entry points import); CLI smoke-tested.
- Release checklist items done: clean install ✅, changelog ✅, report ✅.
  (No `examples/` dir exists — the CLI *is* the example surface.)

## Open follow-ups (genuine, not yet done)

These were scoped but **not executed** as dedicated adversarial tests. They are
hardening beyond the release-blocking findings — good next-session work, none of
them currently known to be broken:

- **Gate-2 cache-key stress** — adversarially probe the `(relyingParty,
  capability, environment)` decision-cache key in `lib/policy.js`: can two
  relying parties share a decision they shouldn't? can environment drift yield a
  stale allow? (A4 covers cross-agent scoping; a dedicated cache-key probe is
  still open.)
- **Policy-engine determinism** — prove `policy.js` is order-independent across
  rule reordering and denies on uncertainty (no matching rule → deny, not allow).
- **v1 compatibility/parity** — assert v1 still produces byte-identical
  receipts/digests/pins (`interfaceDigest()` must stay byte-equal to
  `toolDigest()`; invariant #6 in AGENTS.md). Existing v1 tests pass, but an
  explicit parity pin is not yet written.
- **`npm publish` of 2.0.0** — a human action; intentionally not done by the
  agent.

## Workflow rules (unchanged)

- **Verify before committing**: `npm test` must pass. Current bar: 164/164. The
  glob `"test/*.test.js"` is required (see AGENTS.md) — bare `node --test` hangs
  on fixture servers.
- **Commit style**: conventional commits, no AI attribution, no co-author
  trailers. See `git log --oneline`.
- **The v2 design is done.** v1 was right about *what* to pin but wrong about
  *at what level*; v2 generalizes to a 4-axis change vector
  (interface/permission/implementation/provenance) via `lib/change.js` and
  `lib/descriptor.js`. Do not redesign — harden the open follow-ups above.

## Key files to read (in order)

1. `AGENTS.md` — architecture map, invariants, commands
2. `docs/ANALYSIS.md` — why the probe abstraction was insufficient
3. `docs/TRUST-SUBSTRATE.md` — the v2 architecture (written by the sessions)
4. `docs/THREAT-MODEL.md` — threat model (updated in uncommitted work)
5. `lib/change.js` — the 4-axis change vector (v2 core)
6. `lib/descriptor.js` — protocol-neutral capability descriptor (v2 core)
7. `lib/policy.js` — Gate 2 invocation policy (audit target #2, #3)
8. `lib/receipts.js` — receipt chain (forgery fix, committed)
9. `test/adversarial.test.js` — the attack simulations (committed)
10. `test/audit-probes.test.js` — the classification probes (committed)
11. `docs/AUDIT-REPORT-v2.md` — the formal audit report (committed)

## Environment

- Repo: `/Users/david/Projects/trustcard`
- Node 22.23.1 (mise-managed)
- No deps, no build step, ESM, `node:test` + `node:assert`
- Test: `npm test` (164/164 passing at the release commit)
- `package.json` version: `2.0.0`. HEAD: the v2.0.0 release commit (working
  tree clean after it).
