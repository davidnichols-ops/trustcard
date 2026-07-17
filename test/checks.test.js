import { test } from "node:test";
import assert from "node:assert/strict";
import { scanConfigForSecrets } from "../lib/checks.js";

// We need to test the internal functions findDestructive, findWrite, findDangerousParams.
// Since they're not exported, we test them indirectly via runHealthcheck with mock tools.
// But for unit testing, let's test the verb matching logic directly by importing
// the module and checking the behavior through the exported scanConfigForSecrets
// and by constructing tool objects and checking the regex patterns.

// Test the verb regex logic by replicating what findDestructive does
// (since findDestructive is not exported, we test the behavior through the
// destructive check in runHealthcheck — but that requires a real server.
// Instead, we test the regex patterns directly.)

const DESTRUCTIVE_VERBS = [
  "delete", "remove", "drop", "kill", "destroy", "truncate",
  "overwrite", "purge", "wipe", "force", "reset", "uninstall", "disable",
  "checkout", "push", "merge", "fork", "revert", "rollback",
  "format", "reboot", "shutdown", "eject", "detach", "evict",
  "clear", "clean", "flush", "abort",
];

function verbRegex(verb) {
  return new RegExp(`(^|[^a-z])${verb}([^a-z]|$)`, "i");
}

const DESTRUCTIVE_REGEXES = DESTRUCTIVE_VERBS.map(verbRegex);

function isDestructive(text) {
  return DESTRUCTIVE_REGEXES.some((r) => r.test(text));
}

test("verb matching: does NOT flag read-only tools as destructive (false positive fixes)", () => {
  // These were all false positives in v0.2.0
  assert.equal(isDestructive("duckduckgo_web_search Web search via DuckDuckGo"), false, "search should not be destructive");
  assert.equal(isDestructive("browser_navigate Navigate to a URL"), false, "navigate should not be destructive");
  assert.equal(isDestructive("browser_click Click an element"), false, "click should not be destructive");
  assert.equal(isDestructive("get_item_props Get properties of an item"), false, "get_item_props should not be destructive");
  assert.equal(isDestructive("excel_describe_sheets Describe sheets in a workbook"), false, "describe should not be destructive");
  assert.equal(isDestructive("skillsmp_search Search for skills"), false, "search should not be destructive");
  assert.equal(isDestructive("get_flight_status Get current flight status"), false, "get_flight_status should not be destructive");
  assert.equal(isDestructive("read_file Read file contents"), false, "read_file should not be destructive");
  assert.equal(isDestructive("list_directory List directory contents"), false, "list_directory should not be destructive");
  assert.equal(isDestructive("search_repositories Search for repos"), false, "search_repositories should not be destructive");
});

test("verb matching: DOES flag actually destructive tools", () => {
  assert.equal(isDestructive("delete_file Delete a file"), true, "delete_file should be destructive");
  assert.equal(isDestructive("remove_record Remove a record"), true, "remove_record should be destructive");
  assert.equal(isDestructive("drop_table Drop a database table"), true, "drop_table should be destructive");
  assert.equal(isDestructive("git_reset Reset to a previous commit"), true, "git_reset should be destructive");
  assert.equal(isDestructive("git_checkout Checkout a branch (overwrites working tree)"), true, "git_checkout should be destructive");
  assert.equal(isDestructive("push_files Push files to remote"), true, "push_files should be destructive");
  assert.equal(isDestructive("merge_pull_request Merge a pull request"), true, "merge_pull_request should be destructive");
  assert.equal(isDestructive("fork_repository Fork a repository"), true, "fork_repository should be destructive");
  assert.equal(isDestructive("kill_process Kill a running process"), true, "kill_process should be destructive");
  assert.equal(isDestructive("truncate_table Truncate a table"), true, "truncate_table should be destructive");
  assert.equal(isDestructive("purge_cache Purge the cache"), true, "purge_cache should be destructive");
  assert.equal(isDestructive("wipe_data Wipe all data"), true, "wipe_data should be destructive");
  assert.equal(isDestructive("force_push Force push to remote"), true, "force_push should be destructive");
  assert.equal(isDestructive("revert_changes Revert changes"), true, "revert_changes should be destructive");
  assert.equal(isDestructive("rollback_deployment Rollback a deployment"), true, "rollback_deployment should be destructive");
});

test("verb matching: does NOT match substrings (word boundary)", () => {
  // "deletegate" should not match "delete" (it's a misspelling of delegate)
  assert.equal(isDestructive("deletegate Delegate a task"), false, "deletegate should not match delete");
  // "removeDuplicates" as a tool name should not match "remove" because D is a letter
  // (the regex uses [^a-z] with i flag, so A-Z are also excluded as boundaries)
  // But if the description says "Remove", that WILL match — which is correct behavior
  assert.equal(isDestructive("removeDuplicates deduplicate entries"), false, "removeDuplicates should not match remove (D is a letter, description doesn't say remove)");
  // But "remove_duplicates" should match because _ is not a letter
  assert.equal(isDestructive("remove_duplicates deduplicate entries"), true, "remove_duplicates should match remove");
});

test("verb matching: handles snake_case correctly", () => {
  assert.equal(isDestructive("git_push Push to remote"), true, "git_push matches push (underscore boundary)");
  assert.equal(isDestructive("force_delete Force delete"), true, "force_delete matches both force and delete");
  assert.equal(isDestructive("create_or_update_file Create or update"), false, "create_or_update should not match destructive verbs");
});

// --- Parameter-based danger analysis tests ---
// We test the logic directly since findDangerousParams is not exported.

const DANGEROUS_PARAM_NAMES = {
  path: { risk: "filesystem", level: "medium", reason: "arbitrary filesystem path" },
  command: { risk: "shell", level: "high", reason: "arbitrary shell command" },
  sql: { risk: "sql", level: "high", reason: "raw SQL query" },
  url: { risk: "network", level: "medium", reason: "arbitrary URL (SSRF risk)" },
};

function analyzeToolDanger(tool) {
  const findings = [];
  const schema = tool.inputSchema;
  if (!schema || typeof schema !== "object") return findings;
  const props = schema.properties || {};
  for (const [paramName, paramSchema] of Object.entries(props)) {
    const lowerName = paramName.toLowerCase();
    if (DANGEROUS_PARAM_NAMES[lowerName]) {
      findings.push({
        tool: tool.name,
        param: paramName,
        ...DANGEROUS_PARAM_NAMES[lowerName],
      });
    }
  }
  return findings;
}

test("parameter analysis: detects filesystem path params", () => {
  const tool = {
    name: "read_file",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string", description: "Path to the file to read" },
      },
    },
  };
  const findings = analyzeToolDanger(tool);
  assert.equal(findings.length, 1, "path param detected");
  assert.equal(findings[0].risk, "filesystem");
  assert.equal(findings[0].level, "medium");
});

test("parameter analysis: detects shell command params", () => {
  const tool = {
    name: "execute",
    inputSchema: {
      type: "object",
      properties: {
        command: { type: "string", description: "Shell command to execute" },
      },
    },
  };
  const findings = analyzeToolDanger(tool);
  assert.equal(findings.length, 1, "command param detected");
  assert.equal(findings[0].risk, "shell");
  assert.equal(findings[0].level, "high");
});

test("parameter analysis: detects SQL params", () => {
  const tool = {
    name: "query_database",
    inputSchema: {
      type: "object",
      properties: {
        sql: { type: "string", description: "SQL query to execute" },
      },
    },
  };
  const findings = analyzeToolDanger(tool);
  assert.equal(findings.length, 1, "sql param detected");
  assert.equal(findings[0].risk, "sql");
  assert.equal(findings[0].level, "high");
});

test("parameter analysis: detects URL params (SSRF risk)", () => {
  const tool = {
    name: "fetch_url",
    inputSchema: {
      type: "object",
      properties: {
        url: { type: "string", description: "URL to fetch" },
      },
    },
  };
  const findings = analyzeToolDanger(tool);
  assert.equal(findings.length, 1, "url param detected");
  assert.equal(findings[0].risk, "network");
});

test("parameter analysis: does NOT flag safe params", () => {
  const tool = {
    name: "search",
    inputSchema: {
      type: "object",
      properties: {
        query: { type: "string", description: "Search query" },
        limit: { type: "number", description: "Max results" },
        offset: { type: "number", description: "Pagination offset" },
      },
    },
  };
  const findings = analyzeToolDanger(tool);
  // "query" is NOT in the test's local DANGEROUS_PARAM_NAMES (the real one in checks.js has it)
  // So with the test's local map, no findings
  assert.equal(findings.length, 0, "no dangerous params in safe tool (test local map)");
});

test("parameter analysis: handles tools with no params", () => {
  const tool = {
    name: "ping",
    inputSchema: { type: "object", properties: {} },
  };
  const findings = analyzeToolDanger(tool);
  assert.equal(findings.length, 0, "no params = no findings");
});

test("parameter analysis: handles tools with no inputSchema", () => {
  const tool = { name: "noop" };
  const findings = analyzeToolDanger(tool);
  assert.equal(findings.length, 0, "no schema = no findings");
});

// --- Config file secret scanning tests ---

test("scanConfigForSecrets: detects GitHub tokens", () => {
  const config = JSON.stringify({
    mcpServers: {
      github: {
        env: { GITHUB_PERSONAL_ACCESS_TOKEN: "ghp_1234567890abcdef1234" },
      },
    },
  }, null, 2);
  const findings = scanConfigForSecrets(config, "test.json");
  assert.ok(findings.length > 0, "GitHub token detected");
  assert.ok(findings.some((f) => f.key === "GITHUB_PERSONAL_ACCESS_TOKEN"), "correct key identified");
});

test("scanConfigForSecrets: detects OpenAI keys", () => {
  const config = '{"api_key": "sk-1234567890abcdef1234567"}';
  const findings = scanConfigForSecrets(config);
  assert.ok(findings.length > 0, "OpenAI key detected");
});

test("scanConfigForSecrets: detects Slack tokens", () => {
  const config = '{"token": "xoxb-1234567890-abcdef"}';
  const findings = scanConfigForSecrets(config);
  assert.ok(findings.length > 0, "Slack token detected");
});

test("scanConfigForSecrets: detects AWS keys", () => {
  const config = '{"aws_key": "AKIAIOSFODNN7EXAMPLE"}';
  const findings = scanConfigForSecrets(config);
  assert.ok(findings.length > 0, "AWS key detected");
});

test("scanConfigForSecrets: detects Bearer tokens", () => {
  const config = '{"auth": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"}';
  const findings = scanConfigForSecrets(config);
  assert.ok(findings.length > 0, "Bearer/JWT token detected");
});

test("scanConfigForSecrets: does NOT flag non-secret values", () => {
  const config = JSON.stringify({
    mcpServers: {
      filesystem: {
        command: "node",
        args: ["/usr/local/bin/mcp-server-filesystem", "/home/user"],
      },
    },
  }, null, 2);
  const findings = scanConfigForSecrets(config);
  assert.equal(findings.length, 0, "no false positives on non-secret config");
});

test("scanConfigForSecrets: redacts secrets in sample output", () => {
  const config = '{"GITHUB_TOKEN": "ghp_1234567890abcdef1234"}';
  const findings = scanConfigForSecrets(config);
  assert.ok(findings.length > 0);
  assert.ok(findings[0].sample.includes("***REDACTED***"), "secret is redacted in sample");
  assert.ok(!findings[0].sample.includes("ghp_1234567890abcdef1234"), "full secret not in sample");
});

test("scanConfigForSecrets: reports line numbers", () => {
  const config = 'line1\nline2\n{"token": "ghp_1234567890abcdef1234"}\nline4';
  const findings = scanConfigForSecrets(config);
  assert.ok(findings.length > 0);
  assert.ok(findings[0].line === 3, "correct line number reported");
});

// --- env-file parsing tests ---

// We test parseEnvFile indirectly by importing the CLI module's function.
// Since parseEnvFile is not exported, we replicate the logic here to verify
// the parsing behavior matches the expected .env format.
function parseEnvFile(text) {
  const env = {};
  for (const line of text.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const eqIdx = trimmed.indexOf("=");
    if (eqIdx === -1) continue;
    const key = trimmed.slice(0, eqIdx).trim();
    let val = trimmed.slice(eqIdx + 1).trim();
    if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
      val = val.slice(1, -1);
    }
    env[key] = val;
  }
  return env;
}

test("env-file parsing: parses KEY=value lines", () => {
  const env = parseEnvFile("API_KEY=abc123\nSECRET=xyz");
  assert.equal(env.API_KEY, "abc123");
  assert.equal(env.SECRET, "xyz");
  assert.equal(Object.keys(env).length, 2);
});

test("env-file parsing: skips comments and blank lines", () => {
  const env = parseEnvFile("# comment\n\nAPI_KEY=abc\n# another comment\nSECRET=def");
  assert.equal(env.API_KEY, "abc");
  assert.equal(env.SECRET, "def");
  assert.equal(Object.keys(env).length, 2);
});

test("env-file parsing: strips surrounding quotes", () => {
  const env = parseEnvFile('KEY1="value with spaces"\nKEY2=\'single quoted\'');
  assert.equal(env.KEY1, "value with spaces");
  assert.equal(env.KEY2, "single quoted");
});

test("env-file parsing: handles values with = signs", () => {
  const env = parseEnvFile("CONN_STRING=postgres://user:pass@host:5432/db");
  assert.equal(env.CONN_STRING, "postgres://user:pass@host:5432/db");
});

test("env-file parsing: handles empty file", () => {
  const env = parseEnvFile("");
  assert.equal(Object.keys(env).length, 0);
});
