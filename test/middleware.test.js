// Middleware + receipts: wrapping a raw client and reproducibility analysis.
import { test } from "node:test";
import assert from "node:assert/strict";
import { wrapClient } from "../lib/middleware.js";
import { Guard, GuardDenial } from "../lib/guard.js";
import { TrustStore } from "../lib/trust.js";
import { reproducibilityReport } from "../lib/receipts.js";
import { toolsetDigest, serverDigest, toolDigest } from "../lib/identity.js";
import { hashJson } from "../lib/hash.js";
import { TOOL_SEARCH, clone } from "./helpers.js";

const SID = { name: "fake-server", version: "1.0.0" };

function makeSession(tools) {
  const trust = new TrustStore();
  const observation = {
    tools,
    toolsetDigest: toolsetDigest(tools),
    serverDigest: serverDigest({ serverInfo: SID, protocolVersion: "2025-06-18", tools }),
    toolDigests: Object.fromEntries(tools.map((t) => [t.name, toolDigest(t)])),
    protocolVersion: "2025-06-18",
  };
  trust.pin(SID, observation);
  return { serverId: SID, trust, observation, refresh: async () => ({ refreshed: true }) };
}

test("wrapClient gates tools/call and emits a receipt", async () => {
  const calls = [];
  const raw = {
    async request(method, params) {
      calls.push({ method, params });
      if (method === "tools/call") return { content: [{ type: "text", text: "ok" }] };
      return {};
    },
  };
  const receipts = [];
  const guard = new Guard({ mode: "enforce", receiptSink: (r) => receipts.push(r) });
  const session = makeSession([TOOL_SEARCH]);
  const secure = wrapClient(raw, { guard, session });
  const res = await secure.request("tools/call", { name: "search", arguments: { query: "x" } });
  assert.equal(res.content[0].text, "ok");
  assert.equal(receipts.length, 1);
  // and a denied call never reaches the raw client
  const before = calls.length;
  await assert.rejects(() => secure.request("tools/call", { name: "nonexistent", arguments: {} }), GuardDenial);
  assert.equal(calls.length, before);
});

test("wrapClient passes through non-tool methods untouched", async () => {
  const raw = { async request(method) { return { echoed: method }; } };
  const secure = wrapClient(raw, { guard: new Guard(), session: makeSession([TOOL_SEARCH]) });
  const res = await secure.request("resources/list", {});
  assert.equal(res.echoed, "resources/list");
});

test("reproducibilityReport: identical contract+args, diverging results flagged", () => {
  const td = toolsetDigest([TOOL_SEARCH]);
  const mk = (result) => ({
    tool: "search",
    toolsetDigest: td,
    argumentsDigest: hashJson({ query: "x" }),
    resultDigest: hashJson(result),
  });
  const rows = reproducibilityReport([mk({ a: 1 }), mk({ a: 1 }), mk({ a: 2 })]);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].calls, 3);
  assert.equal(rows[0].distinctResults, 2);
  assert.equal(rows[0].reproducible, false);
});

test("reproducibilityReport: different contract versions are separate groups", () => {
  const mk = (toolset, result) => ({
    tool: "search",
    toolsetDigest: toolset,
    argumentsDigest: hashJson({ query: "x" }),
    resultDigest: hashJson(result),
  });
  const rows = reproducibilityReport([mk("sha256:v1", { a: 1 }), mk("sha256:v2", { a: 1 })]);
  assert.equal(rows.length, 2);
  assert.ok(rows.every((r) => r.reproducible));
});
