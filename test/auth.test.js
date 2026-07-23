import { test } from "node:test";
import assert from "node:assert/strict";
import {
  scopeSatisfies,
  AuthToken,
  DevIssuer,
  extractToken,
  stripAuth,
  TokenValidator,
} from "../lib/auth.js";
import { buildManifest, checkCall } from "../lib/manifest.js";
import { requireScopes, InvocationPolicy } from "../lib/policy.js";

// --- scopeSatisfies ---------------------------------------------------------

test("scopeSatisfies: exact match", () => {
  assert.ok(scopeSatisfies(["read:files"], "read:files"));
  assert.ok(!scopeSatisfies(["read:files"], "write:files"));
});

test("scopeSatisfies: wildcard * matches everything", () => {
  assert.ok(scopeSatisfies(["*"], "read:files"));
  assert.ok(scopeSatisfies(["*"], "admin"));
  assert.ok(scopeSatisfies(["*"], ["read:files", "write:db"]));
});

test("scopeSatisfies: prefix wildcard read:* matches read:files", () => {
  assert.ok(scopeSatisfies(["read:*"], "read:files"));
  assert.ok(scopeSatisfies(["read:*"], "read:db"));
  assert.ok(!scopeSatisfies(["read:*"], "write:files"));
});

test("scopeSatisfies: multiple required scopes all must be present", () => {
  assert.ok(scopeSatisfies(["read:files", "write:db"], ["read:files", "write:db"]));
  assert.ok(!scopeSatisfies(["read:files"], ["read:files", "write:db"]));
  assert.ok(scopeSatisfies(["read:*", "write:*"], ["read:files", "write:db"]));
});

test("scopeSatisfies: empty required always satisfied", () => {
  assert.ok(scopeSatisfies([], []));
  assert.ok(scopeSatisfies(["read:files"], []));
});

// --- AuthToken --------------------------------------------------------------

test("AuthToken: valid token is valid", () => {
  const t = new AuthToken({ subject: "agent-1", scopes: ["read:files"], active: true });
  assert.ok(t.isValid);
  assert.ok(t.canCall(["read:files"]));
  assert.ok(!t.canCall(["write:files"]));
});

test("AuthToken: expired token is invalid", () => {
  const t = new AuthToken({
    subject: "agent-1",
    scopes: ["read:files"],
    active: true,
    expiresAt: new Date(Date.now() - 1000).toISOString(),
  });
  assert.ok(!t.isValid);
  assert.ok(t.isExpired);
  assert.ok(!t.canCall(["read:files"]));
});

test("AuthToken: inactive token is invalid", () => {
  const t = new AuthToken({ subject: "agent-1", scopes: ["read:files"], active: false });
  assert.ok(!t.isValid);
  assert.ok(!t.canCall(["read:files"]));
});

// --- DevIssuer --------------------------------------------------------------

test("DevIssuer: issue and verify roundtrip", () => {
  const issuer = new DevIssuer({ secret: "test-secret-hex" });
  const token = issuer.issue({ subject: "agent-1", scopes: ["read:files", "write:db"] });
  const decoded = issuer.verify(token);
  assert.ok(decoded);
  assert.equal(decoded.subject, "agent-1");
  assert.deepEqual(decoded.scopes, ["read:files", "write:db"]);
  assert.ok(decoded.isValid);
});

test("DevIssuer: wrong secret fails verification", () => {
  const issuer1 = new DevIssuer({ secret: "secret-1" });
  const issuer2 = new DevIssuer({ secret: "secret-2" });
  const token = issuer1.issue({ subject: "agent-1", scopes: ["read:files"] });
  const decoded = issuer2.verify(token);
  assert.equal(decoded, null);
});

test("DevIssuer: expired token is invalid", () => {
  const issuer = new DevIssuer({ secret: "test-secret" });
  const token = issuer.issue({ subject: "agent-1", scopes: ["read:files"], expiresInSeconds: -1 });
  const decoded = issuer.verify(token);
  assert.ok(decoded);
  assert.ok(!decoded.isValid);
  assert.ok(decoded.isExpired);
});

test("DevIssuer: no expiry token never expires", () => {
  const issuer = new DevIssuer({ secret: "test-secret" });
  const token = issuer.issue({ subject: "agent-1", scopes: ["read:files"], expiresInSeconds: 0 });
  const decoded = issuer.verify(token);
  assert.ok(decoded);
  assert.ok(decoded.isValid);
  assert.equal(decoded.expiresAt, null);
});

test("DevIssuer: malformed token returns null", () => {
  const issuer = new DevIssuer({ secret: "test-secret" });
  assert.equal(issuer.verify("not-a-token"), null);
  assert.equal(issuer.verify("a.b"), null);
  assert.equal(issuer.verify("a.b.c.d"), null);
});

// --- extractToken / stripAuth -----------------------------------------------

test("extractToken: from _meta.auth.token", () => {
  const req = { params: { _meta: { auth: { token: "abc123" } } } };
  assert.equal(extractToken(req), "abc123");
});

test("extractToken: from _meta.authorization Bearer", () => {
  const req = { params: { _meta: { authorization: "Bearer abc123" } } };
  assert.equal(extractToken(req), "abc123");
});

test("extractToken: from environment variable", () => {
  process.env.MCP_AUTH_TOKEN_TEST = "env-token";
  const req = { params: {} };
  assert.equal(extractToken(req, "MCP_AUTH_TOKEN_TEST"), "env-token");
  delete process.env.MCP_AUTH_TOKEN_TEST;
});

test("extractToken: returns null when no token present", () => {
  const req = { params: {} };
  assert.equal(extractToken(req, "NONEXISTENT_VAR"), null);
});

test("extractToken: _meta.auth.token takes precedence over env", () => {
  process.env.MCP_AUTH_TOKEN_PREC = "env-token";
  const req = { params: { _meta: { auth: { token: "meta-token" } } } };
  assert.equal(extractToken(req, "MCP_AUTH_TOKEN_PREC"), "meta-token");
  delete process.env.MCP_AUTH_TOKEN_PREC;
});

test("stripAuth: removes auth fields from _meta", () => {
  const req = { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "foo", _meta: { auth: { token: "secret" }, other: "keep" } } };
  const cleaned = stripAuth(req);
  assert.equal(cleaned.params._meta.auth, undefined);
  assert.equal(cleaned.params._meta.other, "keep");
});

test("stripAuth: no _meta returns request unchanged", () => {
  const req = { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "foo" } };
  const cleaned = stripAuth(req);
  assert.deepEqual(cleaned, req);
});

// --- Manifest scope enforcement (checkCall) ---------------------------------

test("checkCall: unscoped tool passes without token", () => {
  const manifest = {
    expiresAt: null,
    tools: [{ name: "read_file", allowed: true }],
  };
  const check = checkCall(manifest, "read_file", {}, null);
  assert.ok(check.allowed);
});

test("checkCall: scoped tool blocked without token", () => {
  const manifest = {
    expiresAt: null,
    tools: [{ name: "delete_file", allowed: true, requiredScopes: ["write:files"] }],
  };
  const check = checkCall(manifest, "delete_file", {}, null);
  assert.ok(!check.allowed);
  assert.match(check.reason, /requires scopes.*write:files.*no auth token/);
});

test("checkCall: scoped tool passes with sufficient token", () => {
  const manifest = {
    expiresAt: null,
    tools: [{ name: "delete_file", allowed: true, requiredScopes: ["write:files"] }],
  };
  const token = new AuthToken({ subject: "agent-1", scopes: ["write:files"], active: true });
  const check = checkCall(manifest, "delete_file", {}, token);
  assert.ok(check.allowed);
});

test("checkCall: scoped tool blocked with insufficient token", () => {
  const manifest = {
    expiresAt: null,
    tools: [{ name: "delete_file", allowed: true, requiredScopes: ["write:files"] }],
  };
  const token = new AuthToken({ subject: "agent-1", scopes: ["read:files"], active: true });
  const check = checkCall(manifest, "delete_file", {}, token);
  assert.ok(!check.allowed);
  assert.match(check.reason, /missing.*write:files/);
});

test("checkCall: wildcard scope satisfies required scope", () => {
  const manifest = {
    expiresAt: null,
    tools: [{ name: "delete_file", allowed: true, requiredScopes: ["write:files"] }],
  };
  const token = new AuthToken({ subject: "agent-1", scopes: ["write:*"], active: true });
  const check = checkCall(manifest, "delete_file", {}, token);
  assert.ok(check.allowed);
});

test("checkCall: * scope satisfies any required scope", () => {
  const manifest = {
    expiresAt: null,
    tools: [{ name: "admin_op", allowed: true, requiredScopes: ["admin", "superuser"] }],
  };
  const token = new AuthToken({ subject: "agent-1", scopes: ["*"], active: true });
  const check = checkCall(manifest, "admin_op", {}, token);
  assert.ok(check.allowed);
});

test("checkCall: expired token blocked on scoped tool", () => {
  const manifest = {
    expiresAt: null,
    tools: [{ name: "delete_file", allowed: true, requiredScopes: ["write:files"] }],
  };
  const token = new AuthToken({
    subject: "agent-1",
    scopes: ["write:files"],
    active: true,
    expiresAt: new Date(Date.now() - 1000).toISOString(),
  });
  const check = checkCall(manifest, "delete_file", {}, token);
  assert.ok(!check.allowed);
  assert.match(check.reason, /expired/);
});

test("checkCall: multiple required scopes all must be present", () => {
  const manifest = {
    expiresAt: null,
    tools: [{ name: "dangerous_op", allowed: true, requiredScopes: ["read:files", "write:db"] }],
  };
  const token = new AuthToken({ subject: "agent-1", scopes: ["read:files"], active: true });
  const check = checkCall(manifest, "dangerous_op", {}, token);
  assert.ok(!check.allowed);
  assert.match(check.reason, /missing.*write:db/);
});

// --- buildManifest with scopeOverrides --------------------------------------

test("buildManifest: scopeOverrides add requiredScopes to tools", () => {
  const tools = [
    { name: "read_file", description: "Read a file", inputSchema: {} },
    { name: "delete_file", description: "Delete a file", inputSchema: {} },
  ];
  const manifest = buildManifest(tools, null, null, null, 90, { delete_file: ["write:files"] });
  const deleteEntry = manifest.tools.find((t) => t.name === "delete_file");
  const readEntry = manifest.tools.find((t) => t.name === "read_file");
  assert.deepEqual(deleteEntry.requiredScopes, ["write:files"]);
  assert.equal(readEntry.requiredScopes, undefined);
});

test("buildManifest: server-declared scopes from annotations._meta", () => {
  const tools = [
    {
      name: "admin_op",
      description: "Admin operation",
      inputSchema: {},
      annotations: { _meta: { requiredScopes: ["admin"] } },
    },
  ];
  const manifest = buildManifest(tools);
  assert.deepEqual(manifest.tools[0].requiredScopes, ["admin"]);
});

test("buildManifest: scopeOverrides take precedence over server-declared", () => {
  const tools = [
    {
      name: "op",
      description: "An operation",
      inputSchema: {},
      annotations: { _meta: { requiredScopes: ["read"] } },
    },
  ];
  const manifest = buildManifest(tools, null, null, null, 90, { op: ["write"] });
  assert.deepEqual(manifest.tools[0].requiredScopes, ["write"]);
});

// --- Gate 2 requireScopes rule ----------------------------------------------

test("requireScopes: denies when no token present", () => {
  const rule = requireScopes(["write:files"], { tool: "delete_file" });
  const result = rule.when({ tool: "delete_file", authToken: null });
  assert.ok(result); // rule fires → deny
});

test("requireScopes: denies when token lacks scope", () => {
  const rule = requireScopes(["write:files"], { tool: "delete_file" });
  const token = new AuthToken({ subject: "a", scopes: ["read:files"], active: true });
  const result = rule.when({ tool: "delete_file", authToken: token });
  assert.ok(result); // rule fires → deny
});

test("requireScopes: allows when token has scope", () => {
  const rule = requireScopes(["write:files"], { tool: "delete_file" });
  const token = new AuthToken({ subject: "a", scopes: ["write:files"], active: true });
  const result = rule.when({ tool: "delete_file", authToken: token });
  assert.ok(!result); // rule does not fire → allow
});

test("requireScopes: wildcard scope satisfies", () => {
  const rule = requireScopes(["write:files"]);
  const token = new AuthToken({ subject: "a", scopes: ["write:*"], active: true });
  const result = rule.when({ tool: "any_tool", authToken: token });
  assert.ok(!result);
});

test("requireScopes: only applies to specified tool", () => {
  const rule = requireScopes(["write:files"], { tool: "delete_file" });
  const result = rule.when({ tool: "read_file", authToken: null });
  assert.ok(!result); // different tool → rule doesn't fire
});

test("requireScopes: applies to all tools when no tool specified", () => {
  const rule = requireScopes(["read"]);
  const result = rule.when({ tool: "any_tool", authToken: null });
  assert.ok(result); // fires for any tool
});

test("InvocationPolicy: requireScopes rule blocks call", () => {
  const policy = new InvocationPolicy({
    rules: [requireScopes(["write:files"], { tool: "delete_file" })],
  });
  const decision = policy.authorize({ tool: "delete_file", authToken: null });
  assert.equal(decision.verdict, "deny");
  assert.equal(decision.reason, "insufficient-scopes");
});

test("InvocationPolicy: requireScopes rule allows call with valid token", () => {
  const policy = new InvocationPolicy({
    rules: [requireScopes(["write:files"], { tool: "delete_file" })],
  });
  const token = new AuthToken({ subject: "a", scopes: ["write:files"], active: true });
  const decision = policy.authorize({ tool: "delete_file", authToken: token });
  assert.equal(decision.verdict, "allow");
});

test("InvocationPolicy: requireScopes with require-approval verdict", () => {
  const policy = new InvocationPolicy({
    rules: [requireScopes(["admin"], { verdict: "require-approval" })],
  });
  const decision = policy.authorize({ tool: "any", authToken: null });
  assert.equal(decision.verdict, "require-approval");
});

// --- TokenValidator ---------------------------------------------------------

test("TokenValidator: validates dev-issued tokens", async () => {
  const issuer = new DevIssuer({ secret: "shared-secret" });
  const validator = new TokenValidator({ devIssuer: issuer });
  const token = issuer.issue({ subject: "agent-1", scopes: ["read:files"] });
  const decoded = await validator.validate(token);
  assert.ok(decoded);
  assert.equal(decoded.subject, "agent-1");
  assert.ok(decoded.isValid);
});

test("TokenValidator: returns null for empty token", async () => {
  const validator = new TokenValidator({ devIssuer: new DevIssuer({ secret: "s" }) });
  const result = await validator.validate(null);
  assert.equal(result, null);
});

test("TokenValidator: returns null for unknown token format", async () => {
  const validator = new TokenValidator({ devIssuer: new DevIssuer({ secret: "s" }) });
  const result = await validator.validate("garbage-token");
  assert.equal(result, null);
});
