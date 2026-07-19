import { test } from "node:test";
import assert from "node:assert/strict";
import {
  InvocationPolicy,
  ScopedDecisions,
  denyTools,
  requireApprovalForDestructive,
  restrictToolToEnvironments,
  constrainArg,
  forbidArg,
} from "../lib/policy.js";
import { Guard, GuardApprovalRequired } from "../lib/guard.js";
import { TrustStore } from "../lib/trust.js";
import { toolsetDigest, serverDigest, toolDigest } from "../lib/identity.js";
import { TOOL_SEARCH, TOOL_FETCH } from "./helpers.js";

const SID = { name: "fake-server", version: "1.0.0" };
const DESTRUCTIVE = { name: "delete_all", description: "Delete.", inputSchema: { type: "object", properties: { path: { type: "string" } } }, annotations: { readOnlyHint: false, destructiveHint: true } };

function makeSession(tools) {
  const trust = new TrustStore();
  const observation = {
    tools,
    toolsetDigest: toolsetDigest(tools),
    serverDigest: serverDigest({ serverInfo: SID, protocolVersion: "2025-06-18", tools }),
    toolDigests: Object.fromEntries(tools.map((t) => [t.name, toolDigest(t)])),
    protocolVersion: "2025-06-18",
  };
  trust.observe(SID, observation);
  trust.pin(SID, observation);
  return { serverId: SID, trust, observation };
}

// --- rule predicates ---------------------------------------------------------
test("denyTools denies named tools, allows others", () => {
  const p = new InvocationPolicy({ rules: [denyTools(["delete_all"])] });
  assert.equal(p.authorize({ tool: "delete_all" }).verdict, "deny");
  assert.equal(p.authorize({ tool: "search" }).verdict, "allow");
});

test("requireApprovalForDestructive gates destructive invocations", () => {
  const p = new InvocationPolicy({ rules: [requireApprovalForDestructive()] });
  assert.equal(p.authorize({ tool: "delete_all", destructive: true }).verdict, "require-approval");
  assert.equal(p.authorize({ tool: "search", destructive: false }).verdict, "allow");
});

test("restrictToolToEnvironments denies outside allowed envs", () => {
  const p = new InvocationPolicy({ rules: [restrictToolToEnvironments("delete_all", ["dev"])] });
  assert.equal(p.authorize({ tool: "delete_all", environment: "prod" }).verdict, "deny");
  assert.equal(p.authorize({ tool: "delete_all", environment: "dev" }).verdict, "allow");
  assert.equal(p.authorize({ tool: "search", environment: "prod" }).verdict, "allow");
});

test("constrainArg enforces an argument predicate (confused-deputy bound)", () => {
  // the classic confused-deputy bound: delete is only allowed under /data
  const p = new InvocationPolicy({ rules: [constrainArg("delete_all", "path", (p) => typeof p === "string" && p.startsWith("/data"))] });
  assert.equal(p.authorize({ tool: "delete_all", args: { path: "/data/x" } }).verdict, "allow");
  assert.equal(p.authorize({ tool: "delete_all", args: { path: "/" } }).verdict, "deny");
});

test("forbidArg denies when a forbidden argument is present", () => {
  const p = new InvocationPolicy({ rules: [forbidArg("search", "admin_override")] });
  assert.equal(p.authorize({ tool: "search", args: { query: "x", admin_override: true } }).verdict, "deny");
  assert.equal(p.authorize({ tool: "search", args: { query: "x" } }).verdict, "allow");
});

test("first matching rule wins; a throwing predicate never widens access", () => {
  const p = new InvocationPolicy({
    rules: [
      { name: "throws", when: () => { throw new Error("boom"); }, verdict: "deny" },
      denyTools(["delete_all"]),
    ],
  });
  // throwing rule is skipped (not a match), so delete_all is denied by the next rule
  assert.equal(p.authorize({ tool: "delete_all" }).verdict, "deny");
  // and search falls through to default allow
  assert.equal(p.authorize({ tool: "search" }).verdict, "allow");
});

// --- Gate 2 in the Guard ------------------------------------------------------
test("Gate 2: trusted tool, unauthorized invocation → denied at the guard", async () => {
  // The tool IS trusted (server PINNED). But this invocation is out of policy.
  const policy = new InvocationPolicy({ rules: [constrainArg("delete_all", "path", (p) => p.startsWith("/data"))] });
  const guard = new Guard({ mode: "enforce", policy: { allowDestructive: true }, invocationPolicy: policy });
  const session = makeSession([DESTRUCTIVE]);
  // in-scope invocation allowed
  assert.equal(await guard.authorizeCall({ session, tool: "delete_all", args: { path: "/data/a" } }), true);
  // out-of-scope invocation denied even though the tool itself is trusted
  await assert.rejects(() => guard.authorizeCall({ session, tool: "delete_all", args: { path: "/" } }), /arg-out-of-policy-scope/);
});

test("Gate 2: require-approval throws a distinct, routable error", async () => {
  const policy = new InvocationPolicy({ rules: [requireApprovalForDestructive()] });
  const guard = new Guard({ mode: "enforce", policy: { allowDestructive: true }, invocationPolicy: policy });
  const session = makeSession([DESTRUCTIVE]);
  await assert.rejects(
    () => guard.authorizeCall({ session, tool: "delete_all", args: { path: "/data" } }),
    (e) => {
      assert.ok(e instanceof GuardApprovalRequired);
      assert.equal(e.name, "GuardApprovalRequired");
      return true;
    }
  );
});

test("Gate 2 is optional: a guard without a policy behaves exactly like v1", async () => {
  const guard = new Guard({ mode: "enforce", policy: { allowDestructive: true } });
  const session = makeSession([DESTRUCTIVE]);
  assert.equal(await guard.authorizeCall({ session, tool: "delete_all", args: { path: "/" } }), true);
});

// --- scoped decisions ---------------------------------------------------------
test("ScopedDecisions: per-relying-party, per-environment decisions", () => {
  const d = new ScopedDecisions();
  d.record({ relyingParty: "agent-a", capability: "sha256:cap1", environment: "dev", verdict: "allow" });
  d.record({ relyingParty: "agent-a", capability: "sha256:cap1", environment: "prod", verdict: "deny" });
  assert.equal(d.lookup({ relyingParty: "agent-a", capability: "sha256:cap1", environment: "dev" }).verdict, "allow");
  assert.equal(d.lookup({ relyingParty: "agent-a", capability: "sha256:cap1", environment: "prod" }).verdict, "deny");
  // a different relying party has no decision (trust is not global)
  assert.equal(d.lookup({ relyingParty: "agent-b", capability: "sha256:cap1", environment: "dev" }), null);
});

test("ScopedDecisions: wildcard environment fallback + clear", () => {
  const d = new ScopedDecisions();
  d.record({ relyingParty: "a", capability: "c", environment: "*", verdict: "require-approval" });
  assert.equal(d.lookup({ relyingParty: "a", capability: "c", environment: "anything" }).verdict, "require-approval");
  d.clear({ relyingParty: "a", capability: "c", environment: "*" });
  assert.equal(d.lookup({ relyingParty: "a", capability: "c" }), null);
});
