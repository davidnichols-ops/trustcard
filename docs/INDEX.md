# trustcard documentation index

This is the entry point for the trustcard documentation. It maps each document to
its purpose and audience.

## Start here

| Document | Why read it |
|---|---|
| [`README.md`](../README.md) | High-level overview, quickstart, CLI commands, and what trustcard does not claim. |
| [`AGENTS.md`](../AGENTS.md) | **Repository knowledge for future Devin sessions:** architecture map, invariants, test commands, and agent-facing conventions. Read this before editing code. |
| [`SECURITY-MODEL.md`](SECURITY-MODEL.md) | The guarantees table: what is proven, what is partially mitigated, and what is out of scope. |

## Normative / protocol

| Document | Why read it |
|---|---|
| [`SPEC.md`](SPEC.md) | Normative v1 protocol specification: canonicalization, digests, identity, change classification, trust-state machine, and wire formats. v3 extensions (behavior, evidence) are described where they intersect the protocol. |
| [`DESCRIPTOR.md`](DESCRIPTOR.md) | The protocol-neutral capability descriptor: interface identity, implementation identity, provenance, and change vectors. |
| [`REGISTRY-INTEGRATION.md`](REGISTRY-INTEGRATION.md) | How manifests live in the official MCP registry without requiring registry changes. |

## Runtime verification

| Document | Why read it |
|---|---|
| [`BEHAVIOR.md`](BEHAVIOR.md) | Behavioral verification: sandbox semantics, probe categories, divergence classes, regression corpus, and CLI usage. |
| [`THREAT-MODEL.md`](THREAT-MODEL.md) | Attack scenarios and controls, including v2/v3 additions. |

## Operational

- [Operations release candidate](OPERATIONS.md): fleet commands, local console, reusable skill and explicit deployment limits.

| Document | Why read it |
|---|---|
| [`MIGRATION.md`](MIGRATION.md) | Moving from v0.x → v3, v1 → v3, and v2 → v3. |
| [`KNOWN-LIMITATIONS.md`](KNOWN-LIMITATIONS.md) | Honest residual gaps: probe-bounded behavior, harness vs sandbox, pattern-based detection, evidence locality, rate limits, TOCTOU. |

## Vision and planning

| Document | Why read it |
|---|---|
| [`ROADMAP-2Y.md`](ROADMAP-2Y.md) | Two-year dependency-gate plan: behavior→evidence bridge, observatory, HTTP/SSE parity, non-MCP adapter, OS/TEE/syscall containment, delegation, standards track, and ecosystem sample10,000. |

## Design history (still useful, may reference earlier versions)

These documents capture the reasoning that produced the current architecture.
They are accurate as design records but may describe pre-v3 decisions or
phased work that is now complete. Refer to the documents above for the current
implementation.

| Document | Notes |
|---|---|
| [`ANALYSIS.md`](ANALYSIS.md) | Why the health-probe abstraction was insufficient and what the protocol model replaces it with. |
| [`TRUST-SUBSTRATE.md`](TRUST-SUBSTRATE.md) | First-principles investigation into a protocol-neutral trust substrate. Some early proposals (e.g., folding namespace into identity) were deliberately not implemented; see `DESCRIPTOR.md` for corrections. |
| [`AUDIT-REPORT-v2.md`](AUDIT-REPORT-v2.md) | v2 adversarial architecture audit. |
| `PHASE-*.md` | Phase-by-phase implementation notes from earlier work. `PHASE-3-IMPLEMENTATION.md` is the most recent, but current code may have diverged. |

## Research artifacts and external notes

The remaining `docs/*.md` files (e.g., `reddit-post-*`, `mcp_requirements_registry_proposal.md`, `issue-1445-closing-comment.md`, etc.) are research artifacts, external feedback, and investigation notes. They are preserved for historical context but are not the current operational documentation.

## How to keep this index useful

When adding a new top-level doc, update this index and add a status note if the
doc is historical, experimental, or roadmap-only. When a roadmap gate lands,
move the relevant doc from "Vision" to "Runtime verification" or "Normative" as
appropriate.
