# Trustcard as a General Trust Substrate

A first-principles investigation into what the smallest universal trust object
for an executable capability should be, whether Trustcard v1's abstraction
survives generalization beyond MCP, and what the system should become.

This document attacks v1's assumptions. Where v1 breaks, it says so and
proposes the smallest model that survives.

---

## 1. Executive verdict

**v1 is correct about *what* must be pinned, and wrong about *at what level of
abstraction*.**

The core insight — content-addressed identity of a capability's *contract*,
signed provenance, TOFU continuity, and an enforcement gate — is right and
generalizes. But v1 conflates four things that must be separated to become a
substrate:

1. **The interface** (what you call and what it means) — this is what v1 pins
   well. Keep it.
2. **The implementation** (the code/binary/process that runs) — v1 *assumes*
   the observed server *is* the manifest's subject, but never separately
   identifies the implementation. A capability and the code that provides it
   are different objects with different lifecycles and different compromise
   modes. v1 has no implementation identity.
3. **The trust decision** — v1 treats trust as a property of a *server* (`this
   server is PINNED`). Trust is not a property of a server; it is a *decision*
   made by a *relying party* about a *specific binding* of
   interface+implementation+provenance, under a *policy*, in a *context*. v1's
   state machine is a per-server cache of one relying party's decisions and
   cannot express "trusted for read, denied for write" or "trusted by A, not B."
4. **The invocation** — v1 gates calls, but the *trust object* is the static
   toolset. The dangerous unit is often not the tool but the *(capability,
   arguments, intent)* triple. v1 validates args against schema; it has no
   model of *invocation authorization* as distinct from *capability trust*.

**The single highest-leverage next move** is to refactor v1's identity core
into a **capability descriptor** — a minimal, protocol-neutral, signed object
binding an interface identity to an implementation identity and provenance —
and to split the trust decision from the identity of the thing trusted. Do
this *before* building any registry, graph, or runtime. Everything else in
this document is contingent on getting that object right.

**Recommendation (Part XIII): Option C** — a protocol-neutral trust layer with
MCP as the reference implementation. Not a runtime (Option D), not yet a
universal standard (Option E).

---

## 2. The fundamental trust object

### 2.1 What exactly is being trusted?

Not the tool. Not the server. Not the publisher. What a relying party actually
needs to trust is a **claim that an invocation will behave as expected**. That
claim decomposes into:

- an **interface** — the contract: name, inputs, outputs, behavioral contract,
  declared permission boundary. This is stable, pinnable, and the thing an
  agent plans against.
- an **implementation** — the code that executes. This is what actually runs
  and what can be malicious or compromised.
- a **provenance** — who vouches for the binding of interface to
  implementation.

v1 pins the interface and *infers* the implementation from "the process I
spawned answered `tools/list`." That inference is the weakest link in v1: it
conflates the contract with whatever process happened to answer.

### 2.2 Tool vs. capability

- A **tool** is a concrete, named, callable unit exposed by a specific server
  or runtime (`search` on `memory-server`).
- A **capability** is the abstract function a relying party wants ("semantic
  search over a knowledge graph"), independent of who provides it.

The distinction matters because **trust should attach to the capability's
interface + provenance, not to the tool's network location.** Two servers can
provide the same capability; one server can provide many; the *same* capability
can be re-implemented. If trust attaches to the tool-on-this-server, then every
legitimate re-hosting or re-implementation is a false trust break, and every
malicious re-hosting is indistinguishable from a legitimate one.

**Conclusion:** the trust object is the **capability**, identified by its
interface, bound to an implementation and a publisher. "Tool" and "server" are
*providers* of capabilities, not the thing trusted.

### 2.3 The nine questions, answered

1. **What is trusted?** A specific (interface, implementation, provenance)
   binding, for a class of invocations, by a relying party.
2. **Tool vs. capability:** trust the capability; the tool is one provider.
3. **Is capability identity independent of implementation?** The *interface
   identity* is. The *trust decision* is not — it must include the
   implementation identity, because a good interface can be served by bad code.
4. **Can one capability have multiple implementations?** Yes, and this is
   common (multiple SDKs, re-hosts, forks). The model must support N
   implementations per interface without N unrelated trust decisions.
5. **Does the execution environment belong in the identity?** Not in the
   *capability* identity (a capability is the same capability on your machine
   or mine). But the environment belongs in the *trust decision* and the
   *receipt*, because the same capability is riskier in a prod environment with
   real credentials than in a sandbox.
6. **Does the caller's identity belong in the trust decision?** Yes —
   absolutely. Trust is a relationship; the relying party is one of its poles.
   v1 has an implicit single relying party ("this client"), which is why it
   can't express per-agent or per-org policy.
7. **Does the argument set belong in the trust object?** Not in the *capability
   identity* (that's fixed). But arguments belong in *invocation authorization*
   and the *receipt* — because `delete(path="/tmp/x")` and
   `delete(path="/")` are the same capability with wildly different risk.
8. **Artifact, action, or relationship?** Trust is a **relationship** between
   an actor and an (artifact, action) pair, mediated by context and policy. It
   is not an intrinsic property of the artifact. (Proven in Part III.)
9. **Trusted in one context, denied in another?** Yes, necessarily. Any model
   that can't express this is not a trust model, it's an allowlist.

### 2.4 The minimal sufficient object

The smallest object that captures all of this:

> **A Capability Descriptor** = a signed statement binding:
> an **interface identity** (what it does / its contract),
> an **implementation identity** (the code that provides it),
> a **provenance** (who vouches, with what key),
> and an optional **validity window** (issuance/expiry).

Everything else — trust state, policy, invocation authorization, receipts — is
a *decision or record about* descriptors, not part of the descriptor. Keeping
the descriptor minimal and the decisions external is what makes it a substrate
rather than a monolith.

This refines the prompt's proposed chain. The chain `Capability → Identity →
Manifest → Provenance → TrustState → Policy → ExecutionGate → Receipt` has the
right *flow*, but it wrongly nests Identity, Provenance, and Manifest as stages
of one object. Correctly: the **descriptor is the atom**; TrustState, Policy,
and Receipt are *separate subsystems that reference* descriptors.

---

## 3. Formal model

### 3.1 Entities

```
RelyingParty   R      — an agent, org, or runtime making trust decisions
Publisher      P      — asserts a binding; holds a signing key
Key            K      — an Ed25519 keypair; K_id = H(K_pub)
Interface      I      — the contract (semantic projection). I_id = H(JCS(proj(I)))
Implementation M      — the code/binary. M_id = H(canonical(M))  (e.g. SRI/npm integrity,
                        container digest, or H(source_commit) for reproducible builds)
Capability     C      — (I) plus a stable name/namespace: C_id = H(name ‖ I_id)
Descriptor     D      — signed { C_id, I_id, M_id, P, K_id, issuedAt, expiresAt }
Environment    E      — runtime context (host, sandbox, creds present, network)
Invocation     X      — (R, C, args, intent, E, t)
Policy         Π      — a function: (D, X, trustGraph) → {allow, deny, require-approval}
TrustDecision  T      — R's recorded decision about a D under a Π
Receipt        Q      — a signed record that X happened under D with outcome
```

### 3.2 The three separations that make it a substrate

**Separation 1 — identity from trust.** `I_id`, `M_id`, `C_id` are pure
functions of content. They exist whether or not anyone trusts anything. Trust
is *never* in the identifier.

**Separation 2 — descriptor from decision.** `D` is objective and portable: any
party can verify the same signature and get the same `C_id/I_id/M_id`. `T` is
subjective and local: it is *R's* decision and is meaningless to another
relying party except as one signal.

**Separation 3 — capability trust from invocation authorization.** Deciding "I
trust capability C from publisher P" is a different act from "I authorize *this*
invocation of C with *these* args in *this* environment." v1 collapses these;
the substrate must not.

### 3.3 Trust as a relationship (formal)

A trust decision is a tuple:

```
T = ( R, D, scope, Π, verdict, t )
```

where `scope` constrains *which invocations* the decision covers:

```
scope = { argumentConstraint, environmentConstraint, validityWindow }
```

- `argumentConstraint` — e.g. "read-only", "path under /data", "no network".
- `environmentConstraint` — e.g. "only in sandbox", "only in dev", "no prod creds".
- `validityWindow` — decision expiry, independent of descriptor expiry.

This single construct — **scoped trust decision** — is what v1 lacks and what
makes the difference between "a pin store" and "a trust substrate." v1's PINNED
is the degenerate case `scope = {}` (unscoped). Real policy is scoping.

### 3.4 Why this is minimal

You cannot remove any element without losing a real capability:

- Drop `I_id` → you can't detect interface drift (v1's whole point).
- Drop `M_id` → you can't distinguish a re-host from a re-implementation, and a
  compromised implementation serving a good interface is invisible.
- Drop `P`/`K_id` → no provenance; nothing to pin continuity to.
- Drop `R` → trust becomes a global boolean; can't express "trusted by A, not B."
- Drop `scope` → can't express "read ok, write no" or "dev ok, prod no."
- Drop `E` from the invocation/receipt → can't reason about environment risk.

And you need nothing more to express every scenario in the prompt. Anything
beyond this (graphs, registries, runtimes) is *derivable* from these atoms.

---

## 4. Generalization beyond MCP (Part II)

For each domain: the capability, identity, provenance, what can change, the
trust boundary, the enforcement point, the manifest analog, what a receipt must
prove, the TOCTOU shape, and what v1 carries over unchanged.

### 4.1 Summary matrix

| Domain | Capability | Identity (I_id) | Implementation (M_id) | Provenance | Enforcement point | TOCTOU shape |
|---|---|---|---|---|---|---|
| MCP tool | `tools/call` target | semantic projection of tool def | server package `dist.integrity` | publisher manifest sig | client middleware | discovery↔call mutation |
| REST/GraphQL API | an operation/route | canonicalized OpenAPI/GraphQL op | deployed service build | operator sig / mTLS / OIDC | egress proxy / client SDK | spec↔deployed drift |
| Local executable | a binary/script invocation | canonical argv-interface + help/man | `H(binary)` (SRI) | package sig (sigstore/apt) | exec wrapper / `execve` hook | post-install swap |
| Agent skill | the skill (prompt or code) | canonical skill body | the loaded artifact bytes | author sig / repo commit | agent runtime skill loader | load↔invoke edit |
| Browser action | `navigate/click/submit/purchase` | action schema + target origin+selector | the page/app build | site TLS + (weak) publisher | the browser-driver gate | DOM mutate↔click |
| LLM tool call | the model's chosen call | the callee's interface identity | callee implementation | callee provenance | the tool-call dispatcher | plan↔dispatch mutation |
| Plugin | extension entry points | canonical declared API surface | plugin package integrity | marketplace/dev sig | host plugin loader/sandbox | review↔load swap |
| Agent→agent | a delegated task/contract | the delegation contract | the sub-agent build/model | delegator→delegatee attestation | the delegation gate | delegatee drift post-delegate |

### 4.2 What generalizes unchanged, what doesn't

**Unchanged (the substrate):**
- **Canonical identity.** JCS + digest works on any JSON-representable
  contract. For non-JSON contracts (GraphQL SDL, protobuf, argv), you need a
  canonical form per contract language — but the *principle* (a canonical
  projection, digested) is identical.
- **Semantic projection.** Every domain has "fields that change behavior" vs
  "fields that are presentation." The projection is domain-specific, the
  split is universal.
- **Signed descriptor + TOFU continuity + fail-closed.** Identical.
- **Enforcement gate + receipts.** The *shape* is identical; only the
  interception point changes (middleware, proxy, exec hook, loader, driver).

**Does not generalize unchanged:**
- **The semantic projection content.** It is MCP-tool-specific today. Each
  domain needs its own projection. This is the main per-domain work.
- **Implementation identity.** v1 has no real `M_id`. For APIs it's the
  deployed build; for executables it's `H(binary)`; for skills it's the loaded
  bytes; for browser actions it's barely definable (the page is mutable by
  nature). This is the hardest generalization and the reason v1 can't claim to
  be a substrate yet.
- **TOCTOU closure.** v1 closes it for cooperating MCP servers. For APIs and
  browser actions there is no `list_changed` equivalent and no handshake
  binding; the residual window is much larger and honesty about it is
  essential.

### 4.3 The two hard domains

**Browser automation** is where the model strains most. A web page's
"capability" (`purchase`) has no stable interface identity — the DOM is a
presentation layer, not a contract. The best achievable identity is `(origin,
action schema, selector/stability fingerprint)`, and even that drifts
constantly and legitimately. Here Trustcard can offer *provenance of the site*
(TLS) and *policy on the action* (deny `purchase` without approval), but the
"content-addressed interface" guarantee is weak. **Honest conclusion: browser
is a policy-enforcement domain, not an identity-pinning domain.**

**Agent→agent delegation** is where receipts and provenance matter most and
where v1 has nothing. The "capability" is a delegated contract; the
"implementation" is another agent whose model+prompt is its M_id. This domain
is the strongest argument for chained receipts (Part VIII) and for the trust
graph (Part X), and it is the primary research frontier.

### 4.4 The general capability trust model

Across all eight domains, the invariant is:

> A relying party trusts an invocation iff it can (a) identify the capability's
> interface, (b) identify the implementation, (c) verify provenance binding
> interface↔implementation, and (d) evaluate a scoped policy over the specific
> invocation — and it records a receipt so the decision is auditable.

Where any of (a)–(c) is weak (browser), the substrate degrades gracefully to
(d) policy + receipt. That graceful degradation — from "cryptographic identity"
down to "policy + audit" — is a *feature* of separating identity from
enforcement, and it is only possible because the model does not require every
domain to achieve the strongest identity guarantee.

---

## 5. Trust is not a property (Part III)

### 5.1 The proposition is correct

Trust is not intrinsic to an artifact. The examples in the prompt — trusted by
A not B, allowed in dev not prod, allowed for read not write, trusted from
publisher X not Y — are not edge cases; they are the *normal* case. Any system
that stores "this server is trusted" as a bare fact about the server has
already lost, because it has baked in one relying party, one scope, and one
context.

v1 makes exactly this mistake structurally: `TrustStore` maps `serverId →
state`. The state is a property of the server. There is no relying party, no
scope, no environment. It works because v1 has an implicit single R and an
implicit unscoped policy. That is a fine v1 simplification and an unacceptable
substrate assumption.

### 5.2 Trust is a decision, cached

The right model: **trust is not stored; decisions are cached.** A relying
party evaluates a policy over a descriptor and an invocation scope and
*records the outcome*. The record is a cache keyed by `(R, C_id, scope)` — and
it must be invalidated when any input changes: the descriptor (interface,
implementation, provenance), the scope, or the policy.

This reframing matters because it makes the state machine *a cache of
decisions*, not *the truth*. v1 treats the state as truth.

### 5.3 Is v1's state machine sufficient? No — and yes.

v1: `UNKNOWN → OBSERVED → PINNED → MATCH/MISMATCH → SUSPECT → REVOKED`.

**What it gets right:** it models *continuity over time* (the essential thing a
probe can't), makes REVOKED sticky, and fails closed. Keep all of that.

**What it cannot express:**
1. **Scope.** One boolean-ish state per server. Can't say "trusted for read."
2. **Relying party.** One implicit R.
3. **Provenance state vs. interface state.** v1 conflates "the interface
   changed" (MISMATCH) with "the provenance is wrong" (SUSPECT) and "the key
   drifted" (no state at all). These have different consequences.
4. **Validity.** No expiry on the decision itself.

### 5.4 The minimum sufficient state model

Do **not** add states for every concept. The insight: *continuity* (did the
thing change?) and *authorization* (may this invocation proceed?) are separate
axes. Keep the continuity machine small and push scope into the decision.

**Continuity state (per `(R, C_id)` binding) — essentially v1's, generalized:**

```
UNSEEN → OBSERVED → ESTABLISHED ⇄ DRIFTED
                       ↓   ↑          ↓
                    (re-establish)   ↓
                       ↓             ↓
                    REVOKED ←────────┘   (sticky, per R)
```

- `ESTABLISHED` replaces PINNED (a pin is how you establish continuity).
- `DRIFTED` replaces MISMATCH and means "an identity input changed"
  (interface, implementation, or provenance). It does not pre-judge *which*
  changed — that's in the diff, not the state.
- `SUSPECT` is removed as a state and becomes a *verdict flag* on a decision
  ("observed without required provenance"). Keeping it as a state double-counts
  with DRIFTED.
- `REVOKED` stays sticky and per-relying-party.

**Authorization (per invocation) — not a state, a function:**

```
authorize(R, X) = Π( descriptorFor(X.C), X.args, X.E, continuityState(R, X.C) )
                ∈ { allow, deny, require-approval }
```

This is the crucial move: **scope and environment live in `authorize()`, not in
the state machine.** The state machine answers "is this still the thing I
established?"; `authorize()` answers "given that, may this specific invocation
run?" Two questions, two mechanisms, neither bloated.

This is the minimum. It adds exactly one concept to v1 (scope-aware
authorization as separate from continuity) and removes one (SUSPECT-as-state).
Net complexity is flat; expressive power is what makes it a substrate.

---

## 6. Identity architecture (Part IV)

### 6.1 What belongs in canonical identity

Identity should capture **what a relying party's plan depends on.** Include:

- **Interface:** name/namespace, input contract, output contract, declared
  behavioral/permission boundary, failure modes. (v1's projection, plus
  failure modes.)
- **Nothing about presentation** (title, icons, docs formatting, `_meta`).
- **Nothing about location** (URL, host, PID) — location is not identity.

### 6.2 The identity hierarchy

Separate identities, separately digested, composed by the descriptor:

```
InterfaceId      I_id  = H(canonical interface projection)     ← v1 has this
PermissionId     Perm_id = H(canonical declared permission set) ← v1 folds into I_id
ImplementationId M_id  = H(canonical implementation)           ← v1 lacks this
PublisherId      P_id  = K_id = H(K_pub)                       ← v1 has this
EnvironmentId    E_id  = H(canonical env descriptor)           ← decision/receipt only
InvocationId     X_id  = H(C_id ‖ args ‖ E_id ‖ t)             ← receipt only
```

**Should PermissionId be separate from InterfaceId?** v1 folds annotations into
the tool digest. The substrate should *optionally* surface the permission
boundary as its own digest, because permission changes deserve their own
policy lane (Part VI) and their own "did *only* the permission boundary move?"
query. But it is a *view over* the interface projection, not a new primitive —
compute it from the same projection. Don't double the identity surface.

**Should identity be hierarchical?** Yes: `C_id = H(namespace ‖ I_id)`, and the
descriptor binds `C_id → M_id → P_id`. The hierarchy lets you ask "same
interface, different implementation?" and "same implementation, different
publisher?" — the two questions v1 cannot ask.

### 6.3 The six hard cases

1. **Two schemas, same semantic capability.** E.g. `{"type":"string",
   "enum":["a","b"]}` vs `{"enum":["a","b"]}`. Canonicalization alone won't
   unify these; you need a *normalization* pass in the projection (strip
   defaults, normalize type-unions, sort enums). v1 does not normalize; it
   only projects. **Substrate should add a normalization layer before
   digesting**, or semantic-equivalent interfaces get different identities.
   This is a real v1 gap.
2. **Schema unchanged, behavior changed.** Invisible to interface identity.
   This is what `M_id` is for — if the implementation changed, `M_id` moves.
   If neither changed but runtime behavior did (server-side state), no static
   identity can catch it; that's behavioral attestation, an open problem (§18).
3. **Description changes, behavior doesn't.** v1 treats a *material*
   description rewrite as ANNOTATION_DOWNGRADE (suspected poisoning). That is
   correct for LLM-consuming descriptions, because the description *is* part of
   the behavior surface for a model. Keep it, but recognize it is
   **agent-specific**: for a non-LLM caller, description is presentation and
   should be volatile. The projection must be parameterized by caller class.
4. **Behavior changes, manifest doesn't.** The declared↔observed binding check
   (v1's `bindingConsistency`) catches this: signed manifest says X, observed
   interface says Y → mismatch. Only works if the client re-observes. This is
   why receipts must record the *observed* identity at call time.
5. **Can a manifest fully describe a capability?** No. A manifest can describe
   the *contract* and the *declared* boundary, never the actual runtime
   behavior. The descriptor is a claim about behavior, not a proof of it. The
   system must be designed so that an honest-but-incomplete manifest is still
   useful (identity + provenance + continuity) and a dishonest manifest is
   *detectable* (declared≠observed). Never claim completeness.
6. **Separate identities per concern?** Yes, as above — but lazily. Compute
   sub-identities as *views* of one projection rather than independent objects,
   so they can't disagree with each other.

### 6.4 The identity architecture, stated

One canonical projection per contract language → a family of derived digests
(interface, permission-view) → a descriptor binding interface to implementation
to publisher → environment and invocation identities computed only at
decision/receipt time. Identity is **content-addressed, hierarchical, and
lazy** — you digest exactly what you need to compare, and nothing about
location or presentation.

---

## 7. Manifest architecture (Part V)

v1's manifest is a server manifest: it binds *one server's* toolset to a key.
The substrate needs a **capability descriptor** that is protocol-neutral. The
question is what belongs in the universal core versus a protocol extension.

### 7.1 The minimal universal core

The smallest descriptor that is still useful across every domain in §4:

```jsonc
{
  "schema": "trustcard.dev/descriptor@1",
  "capability": {
    "namespace": "io.example/search",       // stable, human-meaningful
    "interfaceDigest": "sha256:...",         // I_id — the contract
    "interface": { /* protocol-neutral projection */ }
  },
  "implementation": {
    "digest": "sha256:...",                  // M_id — SRI / container / build hash
    "kind": "npm|oci|binary|source|service"  // how to interpret M_id
  },
  "provenance": {
    "publisher": "io.example",
    "keyId": "sha256:...",
    "signature": { "algorithm": "ed25519", "value": "..." }
  },
  "issuedAt": "...", "expiresAt": null
}
```

That is the whole core. It answers: *what is the contract, what code provides
it, who vouches, is it current.* Everything else is extension.

**Why this is minimal:** remove `interfaceDigest` and you can't detect drift;
remove `implementation.digest` and you can't distinguish re-host from
re-implementation; remove `provenance` and there's nothing to pin; remove
validity and you can't expire. Each field is load-bearing in at least one
domain from §4.

### 7.2 The extended descriptor

Add, as optional blocks, only what changes a policy or trust decision:

```jsonc
{
  "security": {
    "declaredPermissions": ["net:example.com", "fs:read:/data"],
    "sideEffects": "none|read|write|irreversible",
    "credentialAccess": false
  },
  "behavioralContract": {
    "invariants": ["idempotent"],
    "failureModes": ["rate-limited", "partial-result"]
  },
  "trust": {
    "requiredSigners": 1,
    "transparencyLog": "rekor:...",
    "revocation": "trustcard.dev/revocation@1#..."
  },
  "runtime": {
    "requiresEnv": ["DATABASE_URL"],
    "isolation": "sandbox-required"
  }
}
```

### 7.3 The tradeoff

**Minimal core:** maximal interoperability, minimal signature surface, easy to
implement correctly, but says nothing about permissions or behavior beyond the
raw contract. **Extended:** enables real policy ("deny `sideEffects:
irreversible` without approval", "require transparency-log inclusion") but adds
signature surface, more ways to be wrong, and more per-domain interpretation.

**Resolution:** the core is mandatory and sufficient for identity + provenance
+ continuity (the thing only cryptography can give you). The extension blocks
are *optional claims* that policy *may* consume. Critically, **the extended
blocks are claims, not guarantees** — a malicious publisher can lie in
`declaredPermissions`. So policy should treat the extended block as *advisory
input to a decision*, never as the decision. The substrate's hard guarantee
lives only in the minimal core. This is the same discipline as v1's "don't
trust annotations from untrusted servers," generalized.

### 7.4 What goes in protocol extensions

Anything transport- or domain-specific stays out of the universal descriptor:

- MCP: the `_meta` handshake binding, `listChanged` semantics.
- APIs: the OpenAPI/GraphQL projection rules, the egress-proxy interception.
- Executables: how `M_id` maps to a package manager's integrity field.

The descriptor carries `implementation.kind` precisely so each domain can
define its own `M_id` derivation without polluting the core. **One universal
envelope, many domain payloads.**

---

## 8. Trust state model (Part VI recap)

Covered in §5.4. Restated for the deliverable structure: the substrate keeps a
**small continuity machine** (`UNSEEN→OBSERVED→ESTABLISHED⇄DRIFTED→REVOKED`,
sticky, per relying-party) and moves **scope and environment into a separate
`authorize()` function**. Trust is a cached decision, not a stored property.
This is the one conceptual change v1 needs to become a substrate; everything
else in v1's state handling is kept.

---

## 9. Change taxonomy (Part VI)

### 9.1 Critique of v1's taxonomy

```
NONE < SYNTACTIC < NON_BREAKING < ANNOTATION_DOWNGRADE < PERMISSION_CHANGE < BREAKING
```

**Strengths:** it is a *total order by consequence*, which is exactly right for
an auto-repin decision ("compatible iff ≤ NON_BREAKING"). Most taxonomies are
unordered bags of categories that force the consumer to decide; v1's ordering
*is* the decision. Keep the ordering.

**Weaknesses when generalized:**
1. It only reasons about the **interface**. It has no axis for
   *implementation* change (M_id moved but I_id didn't — a re-deploy or a
   compromise) or *provenance* change (key rotated, publisher changed).
2. `PERMISSION_CHANGE` conflates **expansion** (scarier) and **reduction**
   (usually fine). Losing `readOnlyHint` (expansion of what it might do) is not
   the same as gaining it.
3. `ANNOTATION_DOWNGRADE` is agent-specific (description = behavior for an
   LLM). Correct, but it's a *domain* category wearing a universal label.

### 9.2 The principled lattice

Change happens on **independent axes**, and each axis has its own severity.
Do not flatten them into one order — a change can be non-breaking on the
interface axis *and* a provenance break on the provenance axis simultaneously.
The decision is the **max severity across axes, per policy weight.**

Axes (each ordered, each with its own consequence):

| Axis | Ordered levels | Consequence driver |
|---|---|---|
| **Interface** | NONE → SYNTACTIC → NON_BREAKING → BREAKING | can a cached plan still run? |
| **Permission** | NONE → REDUCTION → EXPANSION | did the blast radius grow? |
| **Implementation** | NONE → REBUILD(same M_id class) → REPLACED(new M_id) | is it the same code? |
| **Provenance** | NONE → KEY_ROTATION(signed-over) → PUBLISHER_CHANGE | is it the same voucher? |
| **Description** (agent callers) | NONE → EDIT → MATERIAL_REWRITE | poisoning signal |

Rules that make each category earn its place:

- **Interface BREAKING** ⇒ invalidate cached plans, require re-plan. (v1 rule,
  unchanged.)
- **Permission EXPANSION** ⇒ never auto-repin; require re-approval.
  **REDUCTION** ⇒ compatible. Splitting these is the one change that produces a
  *different decision*, so it earns a category.
- **Implementation REPLACED with unchanged interface** ⇒ this is the
  compromised-server case; it is *not* "no change." It must surface as
  DRIFTED-on-implementation, which v1 cannot even represent. This is the
  taxonomy's most important addition.
- **Provenance KEY_ROTATION** ⇒ acceptable *only* if old key signs new
  (continuity), else treat as PUBLISHER_CHANGE. **PUBLISHER_CHANGE** ⇒ full
  re-establishment; prior pins do not transfer.
- **Description MATERIAL_REWRITE** ⇒ for LLM callers, poisoning-suspect; for
  non-LLM callers, SYNTACTIC. The category is caller-class-dependent.

**What was deliberately NOT added:** "side-effect change," "dependency change,"
"runtime change" are not new axes — they are *causes* that manifest on the
implementation or permission axis. A dependency swap moves M_id
(Implementation). A new side effect moves the permission boundary (Permission).
Adding them as axes would double-count. Each category must produce a distinct
consequence; these don't.

### 9.3 The taxonomy, stated

A change is a vector over five ordered axes; the trust consequence is the
policy-weighted maximum. This replaces v1's single ladder with a small lattice
that is no more complex to compute but can represent the two changes v1 is
blind to (implementation replacement with a stable interface, and provenance
rotation). The auto-repin rule generalizes from "≤ NON_BREAKING" to "no axis
exceeds its compatible threshold."

---

## 10. Enforcement architecture (Part VII)

### 10.1 What each enforcement point can and cannot do

| Point | Can enforce | Cannot enforce |
|---|---|---|
| Before discovery | which sources/servers may be consulted at all | anything about unknown capabilities |
| During handshake | protocol version, capability negotiation, digest commitment (v1 §7.1 binding) | tool semantics (none seen yet) |
| During enumeration | identity computation, descriptor verification, drift detection | future mutation (TOCTOU) |
| **Before invocation** | **continuity + per-invocation authorization — the last point where denial prevents all harm** | what the code does after the call starts |
| During invocation | streaming limits, kill-switch, response filtering | side effects already in flight |
| After invocation | receipts, anomaly detection, revocation input | nothing — purely detective |
| Network layer | domain/IP allowlists, TLS, egress proxying | tool-call semantics (opaque in stdio; shallow in HTTP) |
| OS layer | sandboxing, seccomp, FS/credential isolation | nothing semantic — zero awareness of "which capability" |

Three conclusions:

1. **The pre-invocation gate is irreplaceable.** It is the only point that can
   make a *semantic* decision *before* harm. v1 correctly puts the Guard there.
2. **The gate alone is insufficient.** It can be wrong (policy bug), bypassed
   (a code path that skips middleware), or blind (args it can't parse). So the
   gate must be backed by OS/network **containment** that bounds the blast
   radius of any call the gate wrongly allowed — and by **receipts** that make
   the failure detectable and attributable after the fact.
3. **No layer substitutes for another.** Semantic gates can't sandbox;
   sandboxes can't understand "purchase"; receipts can't prevent. The substrate
   mandates defense-in-depth: **gate → containment → receipt.** v1 has gate and
   receipt; containment is out of its scope and must be documented as the
   operator's responsibility, not silently assumed.

### 10.2 The confused deputy

The MCP client/middleware holds ambient authority — API tokens, filesystem
access, credentials the *tool* never sees. A malicious or compromised server
(or a poisoned description) can induce the agent to invoke *trusted* tools in
ways that abuse the *client's* authority: the tool is fine, the call is valid,
the composition is an attack.

v1's defense is argument validation against schema — which cannot catch this,
because the dangerous call is schema-valid. The honest assessment: **v1 has no
defense against the confused deputy beyond containment, because intent is not
observable at the middleware.** The middleware sees calls, not the plan that
produced them.

What *can* be done, in order of feasibility:

- **Least-privilege credential scoping.** Don't let tools ride the client's
  ambient credentials; issue per-capability scoped tokens so a deputy invoked
  maliciously can only exercise the authority that capability legitimately
  needs. (Operator/runtime responsibility; Trustcard should *specify* it.)
- **Invocation policy on arguments.** Deny classes of (capability, arg-pattern)
  regardless of tool trust — e.g. "no `fs:write` outside /data", "no purchase
  over $X without approval." This is the substrate's job (§10.3).
- **Receipts.** Make the abuse attributable and auditable after the fact.

### 10.3 Capability trust + invocation policy as separate layers

Yes — this separation is mandatory, and it is the same separation §5.4 derived
from the state-machine side. The architecture is **two gates in series**:

```
Invocation X
  │
  ▼
Gate 1 — CONTINUITY: is observedIdentity(X.C) still == establishedIdentity(R, X.C)?
  │        (v1's Guard, generalized: interface + implementation + provenance axes)
  ▼
Gate 2 — AUTHORIZATION: Π(descriptor, X.args, X.E, decisionScope) → allow/deny/require-approval
  │        (the new layer: argument constraints, environment constraints, intent-shaped rules)
  ▼
Execution → Receipt
```

The two gates answer different questions and must not be merged:

- Gate 1 is **objective and cacheable** — same answer for everyone who pinned
  the same identity. It detects *change*.
- Gate 2 is **subjective and per-invocation** — it depends on the relying
  party's policy, the arguments, and the environment. It detects *danger*.

"Tool is trusted; this invocation is not authorized" is exactly Gate 1 pass /
Gate 2 deny. v1 can express Gate 1 fully and Gate 2 only as schema validation.
**Building Gate 2 as a real policy layer is the second-highest-leverage next
move** (after the descriptor refactor), because it is what converts Trustcard
from "detect drift" into "enforce policy."

### 10.4 Intent

The prompt's chain starts with `Intent → Trust Evaluation`. Intent is real but
**unobservable below the agent**: the agent's planner holds it; the middleware
cannot. Two honest options: (a) the agent *declares* intent as a structured
annotation on each call (self-reported — useful for audit, useless against a
compromised agent), or (b) policy constrains the *space* of invocations so that
even unintended calls stay within bounds (robust, and equivalent to Gate 2).
The substrate adopts (b) as the guarantee and (a) as receipt metadata. It never
claims to verify intent.

---

## 11. Receipt architecture (Part VIII)

### 11.1 What a receipt must prove

A receipt is evidence that a specific decision and execution happened. It must
let a later auditor answer: *who invoked what, under which established
identity, authorized by which decision, in which environment, with what outcome
— and can I verify none of that record was altered?*

Minimal cryptographically useful receipt:

```jsonc
{
  "schema": "trustcard.dev/receipt@1",
  "invocationId": "sha256:...",        // H(C_id ‖ argsDigest ‖ E_id ‖ t ‖ nonce)
  "capability": { "id": "...", "interfaceDigest": "...", "implementationDigest": "..." },
  "observedIdentity": "sha256:...",    // what the gate actually saw at call time
  "decision": { "state": "ESTABLISHED", "pinDigest": "...", "policyId": "..." },
  "argsDigest": "sha256:...",          // args themselves stay local (privacy)
  "environment": "dev|prod|sandbox:...",
  "timestamp": "...", "nonce": "...", "seq": 41,
  "outcome": "allowed|denied|error|executed",
  "parentReceipt": "sha256:...|null",  // delegation chain link
  "signature": { "algorithm": "ed25519", "keyId": "...", "value": "..." }
}
```

### 11.2 Design decisions

- **Signed by the relying party's key.** v1's receipts are unsigned local
  JSONL — fine for local debugging, worthless as evidence. A receipt an
  auditor can't verify is a log line, not a receipt. The agent/runtime signs;
  the capability provider *may* countersign (two-party receipt — stronger, but
  optional since it needs server cooperation).
- **Args by digest, not value.** Receipts must not become a secret leak.
  Arguments are stored locally; the receipt carries `argsDigest`, and selective
  disclosure = revealing the preimage to a specific auditor. This gives
  auditability without surveillance.
- **Nonce + monotonic `seq` per signer** — defeats replay and makes gaps
  (deleted receipts) detectable.
- **`parentReceipt` for delegation.** When agent A authorizes agent B, B's
  receipts link back to A's authorizing receipt. A hash chain of receipts *is*
  the delegation audit trail.
- **`observedIdentity` recorded at call time** — this is what makes
  declared↔observed drift detectable in hindsight (§6.3 case 4).

### 11.3 Could receipts become the event log of agentic systems?

Yes — and this is the strongest *strategic* argument for the substrate. If
every agent runtime emitted signed, chained, content-addressed receipts, the
composition of those receipts across agents is exactly a transparency log of
agentic action: replayable, auditable, attributable. Three conditions, in order
of difficulty: (1) receipts must be signed and chained — specified here;
(2) agent runtimes must actually emit them — adoption problem, not design
problem; (3) an ecosystem place to anchor them (transparency log or ledger) —
deliberately left open (§14). Trustcard should *specify* the receipt format and
emit it from its own middleware, and should not try to own the log.

---

## 12. Threat model (Part IX) — 20 attacks

Defense classes: **[v1]** exists today · **[S]** substrate design here ·
**[op]** operator/runtime responsibility · **[NG]** honest non-goal.

| # | Attack | Assumption exploited | Defense today | Residual weakness | Mitigation → owner |
|---|---|---|---|---|---|
| 1 | Tool poisoning (malicious description) | model consumes descriptions as behavior | poisoning heuristics; `requireProvenance` | new obfuscation beats heuristics | signed manifests + Gate-2 policy on effects **[S]**; prompt-hardening **[NG]** |
| 2 | Manifest substitution | client accepts wrong manifest | key pinning; `bindingConsistency` | none for pinned; first-use is TOFU | transparency log **[S/op]** |
| 3 | Publisher key compromise | key == publisher | key-drift detection (deny) | detects, doesn't prevent; rotation UX is the attack window | transparency log + old-key-signed rotation **[S]** |
| 4 | TOCTOU (mutate between discovery and call) | gap between observe and use | re-enumeration + list_changed + handshake binding | silent mutation between check and call on non-cooperating server | receipts + containment **[S/op]**; full closure only w/ binding **[NG to eliminate]** |
| 5 | Silent mutation, no notification | server needn't notify | periodic `validateOnCall` re-enum | window between validations | same as #4 |
| 6 | Capability aliasing (same capability, many names) | trust attaches to name | namespace in `C_id` | cross-server aliases resolve to different `C_id` → re-TOFU friction or over-broad pinning | alias mapping as *signed descriptor claim* **[S]** |
| 7 | Semantic-equivalence attack (different schema, same effect) | digest is syntactic-class | projection removes presentation | normalization gaps (enum order, type-union forms) → false drift or false match | normalization layer **[S, §6.3.1]** |
| 8 | Schema confusion (validator ≠ executor interpretation) | one canonical meaning | JCS is deterministic | JSON Schema itself has ambiguous corners (e.g. `additionalProperties` merges) | restrict schemas to a well-defined subset **[S]** |
| 9 | Permission laundering (powerful cap behind benign one) | gate checks the called cap only | none | a "format" tool that shells out | declared↔observed binding + containment **[S/op]**; full dataflow **[NG]** |
| 10 | Confused deputy | client ambient authority | arg validation (insufficient) | trusted tool, malicious composition | Gate-2 arg policy + scoped creds + receipts **[S/op, §10.2]** |
| 11 | Agent impersonation | receipts/decisions name an agent | none (v1 has no agent identity) | unsigned receipts forgeable by anyone | relying-party key signs receipts **[S, §11]** |
| 12 | Receipt forgery | log lines == evidence | unsigned JSONL | trivially forgeable/editable | signed, chained receipts **[S]** |
| 13 | Receipt replay | valid receipt re-presented | none | replayed receipt as fake evidence | nonce + monotonic seq + timestamp **[S]** |
| 14 | Revocation race | revocation slower than use | fail-closed on drift | REVOKED is local; no distribution | short validity windows + optional transparency **[S]**; instant global revoke **[NG]** |
| 15 | Compromised middleware | the gate is honest | none — Guard is the TCB | a malicious Guard denies/permits at will | keep TCB minimal/auditable; remote attestation **[NG]**; containment as backstop **[op]** |
| 16 | Malicious registry | registry is neutral | v1 is registry-agnostic | a registry can censor/reorder/substitute | content-addressed descriptors + sigs verified client-side; registry is transport only **[S]** |
| 17 | Dependency substitution | M_id covers the top artifact only | none (v1 has no M_id) | swapped transitive dep, same top-level hash if built loosely | M_id = full lockfile/SBOM digest **[S]** |
| 18 | Environment compromise | E is as declared | receipts record `environment` label | label is self-reported | attested environment identity **[NG]**; containment **[op]** |
| 19 | Prompt injection → legit tool misuse | tool calls follow model intent | poisoning heuristics at the margin | this is an LLM-alignment attack, not a tool attack | Gate-2 bounds damage **[S]**; prevention **[NG]** |
| 20 | Trusted tool malicious within declared interface | contract == behavior | none — undetectable by identity | the cap does exactly what the manifest says, maliciously | containment + receipts + provenance reputation **[op]**; **[NG] to prevent** |

### 12.1 The five most instructive

**#15 — Compromised middleware is the ceiling on every claim.** Every guarantee
in this document terminates at "the Guard evaluated correctly." A compromised
Guard is a compromised everything. The only honest answers: keep the TCB
small enough to audit (v1's zero-dependency, single-responsibility modules are
exactly right — *do not* grow them carelessly), and make containment the
backstop so a lying gate can't silently grant OS-level power. Trustcard should
never claim to solve its own compromise.

**#20 — The within-contract malicious tool is a true non-goal.** If a
capability does precisely what its signed descriptor says, and what it says is
malicious, no identity or provenance system can help. The defenses are
reputation (provenance history), containment, and receipts for attribution.
Stating this plainly is what separates a credible design from security theater.

**#3 — Key compromise is mostly a UX attack.** Cryptography detects a new key
instantly (v1's key-drift does). The real attack is social: "yes, we rotated
our key, please re-pin." Old-key-signs-new-key rotation turns the social attack
back into a cryptographic verification; without it, every rotation is a TOFU
moment. This is cheap to specify and high-value.

**#4/#5 — TOCTOU is bounded, not eliminated, and that's fine.** v1 already
states this. The substrate adds: the *receipt* records the observed identity at
call time, so even when the window is exploited, the exploit is attributable
and the drift is detectable after the fact. Detective closure where preventive
closure is impossible.

**#7 — Semantic-equivalence attacks target the projection, not the crypto.**
The digests are sound; the attack is making two semantically identical
contracts digest differently (to force re-TOFU and fatigue users into
over-pinning) or two different contracts digest the same (to launder a change).
The fix is a rigorous normalization subset, not more hashing.

### 12.2 Honest non-goals (unchanged in spirit from v1, generalized)

Sandboxing/containment; LLM prompt-injection prevention; within-contract
malicious behavior; behavioral attestation of runtime; the middleware's own
compromise; instant global revocation. The substrate *reduces* these risks via
containment backstops, receipts, and transparency, but must never claim to
eliminate them.

---

## 13. Trust graph analysis (Part X)

A flat pin store answers one question: "have I, R, established this exact
identity before?" Two questions it *cannot* answer motivate the graph:

- **"Why was this execution trusted?"** — requires walking: invocation →
  capability → descriptor → publisher key → (relying party's delegation).
- **"What is the blast radius if this key is compromised?"** — requires the
  reverse edges: key → all descriptors it signed → all capabilities → all
  relying parties that established them.

The graph is a *derived view*, not a new primitive. Nodes are exactly the §3
entities; edges are claims that already exist as signed objects (a descriptor
*is* a `signs`/`defines` edge; a receipt *is* an `invokes` edge; a revocation
*is* a `revokes` edge). Nothing new needs to be trusted — the graph is built by
collecting descriptors and receipts you already verify.

**Verdict: worth it, but later.** The blast-radius query is the single most
valuable thing a pin store can't do, and it becomes essential the moment there
is more than one publisher key (i.e., as soon as the substrate is real). But it
requires no new trust machinery — only indexing verified artifacts. Build the
descriptor and receipt formats so they *are* the edges (content-addressed,
cross-referencing), and the graph becomes a query layer anyone can construct.
Do not build a graph *service*; make the data graph-shaped and let services
emerge. Priority: after the descriptor refactor, alongside receipts.

---

## 14. Registry analysis (Part XI)

### 14.1 Does Trustcard need a registry?

No — and it must never *require* one. Every guarantee in the core (identity,
provenance, continuity, fail-closed) is verifiable client-side from the
descriptor alone. A registry that is load-bearing is a central point of
failure, censorship, and capture. The protocol is registry-agnostic by design.

### 14.2 What a registry is good for

Discovery and distribution, not trust:

- finding descriptors by namespace;
- distributing **revocations** faster than local drift detection;
- a **transparency log** making key rotation and manifest history public and
  non-repudiable (mitigates #2, #3, #14);
- caching content-addressed artifacts (descriptors are addressed by digest, so
  any registry/mirror/CDN serves them without becoming trusted).

### 14.3 Composable trust roots

Trust composes as **delegation chains verified locally**, not as hierarchy
imposed by a registry:

```
Local trust (my pins)            — always authoritative for me
  ↓ delegates
Organization trust (org policy signs which publishers/keys it accepts)
  ↓ delegates
Publisher trust (publisher key signs capability descriptors)
  ↓ (optionally anchors in)
Registry/transparency (public, verifiable append-only history)
```

Each layer is a relying party making scoped decisions about the next, using the
*same* decision machinery (§5.4). An org is just an R whose decisions are
distributed to its agents as policy. The registry is not a trust root — it is a
bulletin board whose contents are only believed after client-side signature
verification. This is the sigstore/certificate-transparency lesson applied to
capabilities: **transparency distributes evidence; it never replaces
verification.**

**Recommendation:** stay registry-agnostic in the core spec; *define* one
optional transparency-log profile so interop exists when people want it. Do not
build or operate a registry.

---

## 15. Protocol design (Part XII)

The prompt's lifecycle, classified:

```
DISCOVER ─ protocol primitive (per-domain transport)
IDENTIFY ─ protocol primitive (canonical projection + digest)      ← CORE
ATTEST   ─ protocol primitive (descriptor issuance/signing)        ← CORE
VERIFY   ─ protocol primitive (signature + binding check)          ← CORE
AUTHORIZE─ policy decision (relying-party Π; not wire protocol)    ← LOCAL
EXECUTE  ─ out of scope (the capability's own protocol)
RECEIPT  ─ protocol primitive (signed, chained record)             ← CORE
MONITOR  ─ implementation detail (re-observation cadence, list_changed)
REVOKE   ─ protocol primitive (signed revocation + distribution)   ← CORE
```

### 15.1 The smallest useful core

Five primitives. Everything else is policy, transport, or implementation:

1. **IDENTIFY** — `C_id / I_id / M_id` from a canonical projection.
2. **ATTEST** — issue a descriptor binding `C_id → M_id → P`, signed by `K`.
3. **VERIFY** — check signature + `bindingConsistency` (declared == observed).
4. **RECEIPT** — record a signed, chained invocation record.
5. **REVOKE** — issue/distribute a signed revocation of a descriptor or key.

**AUTHORIZE is deliberately *not* a protocol primitive.** It is local policy;
putting it on the wire would force a global policy language and destroy the
per-relying-party model. The protocol carries *evidence* (descriptors,
receipts, revocations); decisions stay local. This is the load-bearing design
choice: **Trustcard is an evidence protocol, not an authorization protocol.**

### 15.2 Why this survives across MCP, APIs, local tools, skills

IDENTIFY/ATTEST/VERIFY/RECEIPT/REVOKE are all statements *about* content, not
*over* a transport. Each domain supplies only: (a) a canonical projection for
its contract language, (b) an `implementation.kind` for its M_id, (c) an
enforcement point for its gate. The five primitives and the descriptor/receipt
formats are identical everywhere. That is what "protocol-neutral" concretely
means.

---

## 16. Strategic options (Part XIII)

| | A. MCP-only standard | B. Generic signed manifest | C. Protocol-neutral layer, MCP reference | D. Agent security runtime | E. Universal capability attestation standard |
|---|---|---|---|---|---|
| Technical scope | narrow | medium | medium-large | very large | huge |
| Adoption difficulty | low-med (rides MCP) | med | med | high (runtime lock-in) | very high (needs consortium) |
| Competitive landscape | MCP scanners/linters | sigstore/in-toto adjacent | thin — few do identity+gate+receipt | crowded (agent frameworks) | W3C/IETF-style, slow |
| Strategic defensibility | weak (feature of MCP) | weak-med (sigstore overlap) | **strong** (the gate + receipt + taxonomy is the moat) | med | strong if achieved, unlikely |
| Implementation complexity | low | med | med | high | very high |
| Likely users | MCP devs | package/tool publishers | agent-platform & tool builders | enterprises w/ agent fleets | standards bodies |
| Standards path | MCP `_meta` | standalone schema | MCP `_meta` ref-impl + neutral core | product, not standard | IETF/W3C |
| Overreach risk | low | med (reinvents sigstore) | **low-med** | high | very high |

**Why not the others:** A caps the insight at one protocol and gets absorbed as
an MCP feature. B collides head-on with sigstore/in-toto, which already sign
artifacts — Trustcard's distinct value is not signing, it's *semantic identity
+ change taxonomy + the gate + receipts*, which sigstore doesn't do. D is a
product, requires owning the runtime, and forfeits neutrality. E is the
destination, not the next step — attempted now it dies in committee.

**Why C wins:** it keeps everything that made v1 right, names MCP as the
*reference implementation* (real users, real tests, real `_meta` integration),
and extracts the protocol-neutral core (descriptor, taxonomy, gate, receipt) so
other domains can adopt without MCP. It is the largest step that does not
require either runtime lock-in or a standards consortium.

---

## 17. Recommended direction + roadmap (Part XIV)

Priority = Security Value × Generality × Adoption Leverage ÷ Complexity.

### 17.1 Immediate (the single highest-leverage move)

**Refactor v1's identity core into the protocol-neutral Capability Descriptor.**

Concretely, in this repo:

1. Split `identity.js`: interface digest (I_id) stays; add a first-class
   `implementation` identity (M_id) — for npm MCP servers, `dist.integrity`;
   leave a `kind` enum for oci/binary/source/service.
2. Generalize `provenance.js` manifests from *server* manifests to *capability
   descriptors* (§7.1 core). Server manifest = a bundle of descriptors.
3. Add the **normalization layer** before digesting (§6.3.1) — strip defaults,
   normalize type-unions, sort enums — with tests for semantic-equivalence.
4. Split the taxonomy (§9): add Implementation and Provenance axes; split
   PERMISSION_CHANGE into EXPANSION/REDUCTION. Keep the ordered-consequence
   decision rule per axis.

This is small, pure-refactor, fully testable, and it converts v1 from "an MCP
thing" into "a substrate with an MCP adapter." Everything else depends on it.

### 17.2 Near-term (after the descriptor lands)

5. **Gate 2 — invocation policy** (§10.3): a scoped decision store keyed
   `(R, C_id, scope)` and an `authorize()` that evaluates arg/environment
   constraints. This is what makes it *enforcement*, not just detection.
6. **Signed, chained receipts** (§11) emitted from `middleware.js`, with
   `parentReceipt` for delegation.
7. **Old-key-signs-new-key rotation** + a revocation primitive (§12.1, §15.1).
8. **One transparency-log profile** (optional, §14.3) — a spec, not a service.
9. **A second adapter** (a local-executable gate: `execve` wrapper pinning
   `H(binary)`) to prove protocol-neutrality with a non-MCP domain.

### 17.3 Long-term / research

- Trust-graph query layer over accumulated descriptors+receipts (§13).
- Behavioral attestation (§18) — the within-contract gap.
- Multi-agent delegation receipts at ecosystem scale.
- Standards-track submission of the descriptor + receipt formats (E), only
  after C has real multi-domain adoption.

**Do not build now:** a registry service, a graph service, a runtime, a
universal standard. Each is either premature or someone else's job.

---

## 18. Open research questions

1. **Behavioral attestation.** Can a capability prove anything about runtime
   behavior beyond its contract (deterministic replay, proof-carrying
   execution, TEE attestation)? This is the only thing that touches attack #20,
   and it is genuinely open.
2. **Semantic normalization completeness.** Is there a canonical subset of JSON
   Schema / OpenAPI / GraphQL SDL for which semantic equivalence is decidable
   and the normalization is confluent? Needed to close #7/#8 rigorously.
3. **Environment identity.** How to make `E_id` attested rather than
   self-reported (#18) without dragging in a whole remote-attestation stack.
4. **Delegation semantics.** When agent A authorizes agent B with a scoped
   decision, how is scope *attenuated* (never widened) across a delegation
   chain, and how do chained receipts prove attenuation held?
5. **Alias resolution without a trusted oracle.** #6 needs a way to learn
   "these two names are the same capability" from signed claims alone, without
   a registry that could lie about aliasing.
6. **Policy portability.** AUTHORIZE is local by design — but can scoped
   *decisions* be shared between relying parties as signed, attenuable
   credentials (Biscuit/macaroon-style) without re-introducing a global policy
   language?

---

## Appendix A — What survives from v1, unchanged

JCS canonicalization; semantic projection as the identity basis; the
ordered-by-consequence change decision rule; signed Ed25519 provenance; TOFU +
fail-closed continuity; the pre-invocation gate as the enforcement point;
receipts; the explicit honest non-goals. The substrate is a *generalization and
separation* of v1's correct parts — descriptor/decision, continuity/authorization,
interface/implementation — not a replacement.

## Appendix B — Where v1 breaks (the load-bearing critiques, collected)

1. Trust stored as a property of a server, not a scoped decision by a relying
   party. (§5)
2. No implementation identity — conflates the contract with whatever answered
   `tools/list`. (§2, §6)
3. Taxonomy blind to implementation replacement and provenance rotation; folds
   permission expansion and reduction into one bucket. (§9)
4. No normalization — semantic-equivalent contracts digest differently. (§6.3)
5. Receipts unsigned, unchained — evidence value ~zero. (§11)
6. Invocation authorization absent — gate validates schema, not policy. (§10)
7. Single implicit relying party — can't express per-agent/org trust. (§5)

Each is fixable by the refactor in §17.1–17.2 without discarding v1's core.
