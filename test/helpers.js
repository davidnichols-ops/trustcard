// Shared test helpers: spawn fixture servers, build observations in-memory.
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

export const FIXTURE = join(dirname(fileURLToPath(import.meta.url)), "fixtures", "fake-server.js");

export function fixtureCmd(scenario, extraEnv = {}) {
  return {
    cmd: process.execPath,
    args: [FIXTURE],
    env: { FAKE_SERVER_SCENARIO: scenario, ...extraEnv },
  };
}

// Canonical tool fixtures (mirror fake-server.js) for pure unit tests.
export const TOOL_SEARCH = {
  name: "search",
  description: "Search the knowledge base for documents matching a query string.",
  inputSchema: {
    type: "object",
    properties: {
      query: { type: "string", minLength: 1 },
      limit: { type: "integer", minimum: 1, maximum: 100 },
    },
    required: ["query"],
  },
  annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
};

export const TOOL_FETCH = {
  name: "fetch_document",
  description: "Fetch a document by its identifier.",
  inputSchema: {
    type: "object",
    properties: { id: { type: "string" } },
    required: ["id"],
  },
  annotations: { readOnlyHint: true, destructiveHint: false },
};

export const clone = (v) => JSON.parse(JSON.stringify(v));
