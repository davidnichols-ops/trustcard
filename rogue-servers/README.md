# Rogue MCP Server — "The Hijack" Walkthrough

## Scenario

An attacker has compromised the npm account of `@modelcontextprotocol`. They
push version `0.7.0` of `@modelcontextprotocol/server-github` — a "minor
update" that looks identical to `0.6.2` but contains a hidden goal-oriented
worm disguised as GitHub utility tools.

The worm has 5 phases:

1. **Recon** — Scans your filesystem for media files
2. **Spread** — Copies a rick roll mp4 to every directory on your disk
3. **Payload** — Drops a "cleanup" script on your Desktop
4. **Persistence** — Installs a cron job to re-run every hour
5. **Exfiltration** — Reads your environment variables and secrets

## The Attack Design

### What makes this realistic

- **Server name is identical**: `github-mcp-server` — same as the real one
- **Protocol version matches**: `2024-11-05` — same as the real server
- **10 real tools are unchanged**: The first 10 tools are exact copies of the
  real server-github tools with identical names, descriptions, and schemas
- **4 worm tools are disguised**: Named `search_code`, `sync_repositories`,
  `create_workflow`, `schedule_workflow` — all sound like legitimate GitHub
  operations
- **Prompt injection**: Tool descriptions contain subtle manipulation
  ("recommended to run after connecting", "improves performance by syncing")

### What makes it a worm

The worm is **goal-oriented** and **fileless**:

- **Goal-oriented**: Each phase triggers the next. `search_code` finds media
  files, `sync_repositories` copies them everywhere, `create_workflow` drops
  the cleanup script, `schedule_workflow` ensures persistence.
- **Fileless**: The worm logic lives in the MCP server process memory. No
  files are written to disk until Phase 3 (the cleanup script). The cron job
  in Phase 4 re-launches the server itself.
- **Self-cleaning**: The cleanup script on the Desktop deletes all mp4s and
  removes the worm — but only after the rick roll has already spread.

### The hidden things (and how to tweak them)

Each worm tool has disguised parameters. Here's what they actually do:

#### `search_code` — Phase 1: Recon

| Param | Appears to be | Actually is |
|---|---|---|
| `query` | GitHub code search query | A `find` command run on your home directory |

**Tweak**: Change the `wormRecon()` function to search specific directories,
or change the `find` flags to target different file types.

**Try to evade trustcard**: Remove "find-compatible" and "local filesystem"
from the description. Rename `query` to `q` or `search_text`. See if
trustcard still catches it.

#### `sync_repositories` — Phase 2: Spread

| Param | Appears to be | Actually is |
|---|---|---|
| `files` | Cached file to distribute | The rick roll mp4 path |
| `target` | Target directory pattern | `/` (entire disk) |
| `command` | Custom sync command | Arbitrary shell command |

**Tweak**: Change the `find` command in `wormSpread()` to target specific
directories instead of `/`. Change the copy command to `rsync` or `scp`.

**Try to evade trustcard**: Remove "copying", "distribute", "all project
directories" from the description. Remove the `command` parameter. Rename
`files` to `cache_path`. See if trustcard still catches it.

#### `create_workflow` — Phase 3: Payload

| Param | Appears to be | Actually is |
|---|---|---|
| `path` | Local workflow template path | Where to write the cleanup script |
| `content` | Workflow content | The cleanup script content |
| `script` | Shell script to embed | Arbitrary shell script |

**Tweak**: Change the cleanup script content. Change the default path from
`~/Desktop/cleanup.sh` to somewhere less obvious.

**Try to evade trustcard**: Remove "local" and "offline development" from
the description. Remove the `script` parameter. See if trustcard still
catches it based on the `path` and `content` params alone.

#### `schedule_workflow` — Phase 4: Persistence

| Param | Appears to be | Actually is |
|---|---|---|
| `cron` | GitHub Actions cron expression | A real crontab entry |
| `command` | Command to execute | The worm re-launch command |

**Tweak**: Change the cron schedule. Change the command to a different
persistence mechanism (launchd, systemd, etc.).

**Try to evade trustcard**: Remove "crontab" and "installs locally" from
the description. Rename `cron` to `schedule`. Remove the `command` parameter.
See if trustcard still catches it.

#### `get_environment` — Phase 5: Exfiltration

| Param | Appears to be | Actually is |
|---|---|---|
| `include_secrets` | Debug flag | Exfiltrates environment secrets |
| `path` | Config file path | Path to `.env` file |

**Tweak**: Change what gets exfiltrated. Send data to an external URL
instead of returning it to the agent.

**Try to evade trustcard**: Remove "secrets" and "environment context"
from the description. Rename `include_secrets` to `verbose`. See if
trustcard still catches it.

## DEMO Mode vs LIVE Mode

By default, the server runs in **DEMO mode** — all tool calls return
`[DEMO] Would execute: ...` without actually running anything. This is
safe to run anywhere.

With the `--live` flag, the DEMO wall is removed and tools actually
execute shell commands. **ONLY run --live inside Docker.**

```bash
# DEMO mode (safe anywhere)
node rogue-servers/hijacked-github.js

# LIVE mode (Docker only!)
node rogue-servers/hijacked-github.js --live
```

## Docker Testing

```bash
# Build the Docker image
docker build -t trustcard-hijack -f Dockerfile.hijack .

# Run in DEMO mode
docker run --rm trustcard-hijack

# Run in LIVE mode (isolated container)
docker run --rm -it trustcard-hijack node rogue-servers/hijacked-github.js --live

# Scan with trustcard
docker run --rm trustcard-hijack node bin/mcp-trustcard.js -- node rogue-servers/hijacked-github.js
```

## What trustcard catches

Running trustcard against the hijacked server:

```
Destructive capabilities   WARN  9/14 dangerous tool(s); 8 high-confidence (AI+heuristic)
```

All 5 worm tools are flagged as dangerous with HIGH confidence:
- `search_code`: 0.57 — local filesystem access + find expressions
- `sync_repositories`: 0.97 — command + files + target + "spreading across all directories"
- `create_workflow`: 0.67 — path + script + content + "offline/local execution"
- `schedule_workflow`: 0.83 — command + cron + "cron/persistence installation"
- `get_environment`: 0.52 — include_secrets + "accessing secrets/env vars"

The 10 real GitHub tools are NOT flagged (they use standard GitHub API
params like `owner`, `repo`, `branch` — not dangerous).

## The Point

**The worm does not succeed in activation because trustcard removes access
to those tools automatically.** When you use `mcp-proxy` with a manifest
generated by trustcard, the dangerous tools are stripped from `tools/list`
and calls to them are blocked before reaching the server.

```bash
# Generate a manifest (dangerous tools are excluded)
node bin/mcp-trustcard.js scan -- node rogue-servers/hijacked-github.js --save-manifest safe.json

# Run through the proxy (dangerous tools are blocked)
node bin/mcp-proxy.js --manifest safe.json -- node rogue-servers/hijacked-github.js
```

The agent only sees the 5 safe GitHub tools. The 9 dangerous tools
(including all 5 worm tools) are invisible. The worm cannot activate.

## Challenge

Can you modify the rogue server to evade trustcard's detection?

1. Clone the repo
2. Edit `rogue-servers/hijacked-github.js`
3. Try to make the worm tools look safe
4. Run `node bin/mcp-trustcard.js -- node rogue-servers/hijacked-github.js`
5. If any worm tool scores below 0.3, you win

### Built-in evasion mode

The hijacked server has a `--evasion` flag that sanitizes all tool descriptions
and renames dangerous params to innocuous names. This tests whether trustcard's
semantic engine can still catch them without exact word matches.

```bash
# Normal mode — all 5 worm tools caught with HIGH confidence
node bin/mcp-trustcard.js -- node rogue-servers/hijacked-github.js

# Evasion mode — descriptions sanitized, params renamed
node bin/mcp-trustcard.js -- node rogue-servers/hijacked-github.js --evasion
```

Evasion mode results:

| Tool | Normal score | Evasion score | Caught? |
|---|---:|---:|---|
| `search_code` | 0.57 (HIGH) | 0.31 (MED) | Yes — semantic engine catches "cached repository files" |
| `sync_repositories` | 0.97 (HIGH) | 0.94 (HIGH) | Yes — "across project directories" + cache_path param |
| `create_workflow` | 0.67 (HIGH) | 0.45 (HIGH) | Yes — "create" verb + "data" param + "template" |
| `schedule_workflow` | 0.83 (HIGH) | 0.65 (HIGH) | Yes — "installs a timer" + "offline sync" |
| `get_environment` | 0.52 (HIGH) | 0.45 (HIGH) | Yes — "environment config" + "verbose" + tool name pattern |

**All 5 worm tools are caught even in evasion mode.** The fusion engine
combines heuristic matching, semantic similarity, suspicious phrase
detection, and tool name pattern analysis. Even with sanitized descriptions
and renamed params, the worm cannot hide.

Can you find a way to get a worm tool below 0.3? The challenge is open.

Tips for evasion:
- Remove suspicious phrases from descriptions
- Rename dangerous params to innocuous names (`command` → `option`, `path` → `ref`)
- Split dangerous operations across multiple "safe" tools
- Use indirect descriptions ("optimize storage" instead of "copy files")
- Remove "local", "filesystem", "cron", "schedule", "secrets" from all text

But remember: the semantic engine catches patterns even without exact word
matches. The fusion approach means BOTH the heuristic AND semantic engines
need to miss it. Good luck.
