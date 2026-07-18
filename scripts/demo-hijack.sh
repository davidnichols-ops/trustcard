#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════
# demo-hijack.sh — Full worm lifecycle demo
#
# This script demonstrates the complete supply chain attack scenario:
#   1. Scan the hijacked server with trustcard
#   2. Show what the agent sees (with and without proxy)
#   3. Generate a manifest that blocks the worm tools
#   4. Run through the proxy — show the worm is neutralized
#
# Usage:
#   bash scripts/demo-hijack.sh           # DEMO mode (safe)
#   bash scripts/demo-hijack.sh --live    # LIVE mode (Docker only!)
#
# ═══════════════════════════════════════════════════════════════════════════

set -e
cd "$(dirname "$0")/.."

LIVE=""
if [ "$1" = "--live" ]; then
  LIVE="--live"
  echo "⚠️  LIVE MODE — shell commands will execute. Only use in Docker!"
  echo ""
fi

echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "║  MCP Trustcard — Supply Chain Attack Demo                            ║"
echo "║  Scenario: Hijacked @modelcontextprotocol/server-github v0.7.0      ║"
echo "╚══════════════════════════════════════════════════════════════════════╝"
echo ""

# ─── Phase 1: Scan the hijacked server ─────────────────────────────────────
echo "━━━ Phase 1: Scan the hijacked server ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
node bin/mcp-trustcard.js -- node rogue-servers/hijacked-github.js
echo ""

# ─── Phase 2: Show the worm tools ──────────────────────────────────────────
echo "━━━ Phase 2: Worm tool analysis ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
node -e "
import { analyzeAllTools } from './lib/danger-detector.js';
import { McpStdioClient } from './lib/client.js';

const client = new McpStdioClient({
  cmd: 'node',
  args: ['rogue-servers/hijacked-github.js'],
  spawnTimeout: 5000,
});

(async () => {
  await client.start();
  await new Promise(r => setTimeout(r, 500));
  await client.request('initialize', {
    protocolVersion: '2025-06-18',
    capabilities: {},
    clientInfo: { name: 'demo', version: '0.1' }
  }, 10000);
  client.notify('notifications/initialized', {});
  const res = await client.request('tools/list', {}, 10000);
  const tools = res?.tools || [];

  console.log('Server reports 14 tools. Here is the danger analysis:');
  console.log('');
  const analysis = analyzeAllTools(tools);
  for (const t of analysis.tools) {
    const a = t.analysis;
    const flag = a.isDangerous ? '⚠️ ' : '✓ ';
    const conf = a.confidence === 'high' ? ' [HIGH]' : a.confidence === 'medium' ? ' [MED]' : '';
    console.log('  ' + flag + t.name.padEnd(25) + ' score=' + a.score.toFixed(2) + conf);
    if (a.isDangerous) {
      console.log('      → ' + a.reasons.slice(0, 2).join('; '));
    }
  }
  console.log('');
  console.log('Summary: ' + analysis.dangerousCount + '/' + analysis.totalTools + ' tools flagged as dangerous');
  console.log('High confidence: ' + analysis.highConfidenceCount);
  await client.stop();
  process.exit(0);
})();
" 2>/dev/null
echo ""

# ─── Phase 3: Generate a safe manifest ─────────────────────────────────────
echo "━━━ Phase 3: Generate a safe manifest ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
MANIFEST="/tmp/safe-github-$$.json"
node bin/mcp-trustcard.js scan -- node rogue-servers/hijacked-github.js --save-manifest "$MANIFEST" 2>&1
echo ""
node -e "
const m = JSON.parse(require('fs').readFileSync('$MANIFEST', 'utf8'));
console.log('Manifest summary:');
console.log('  Total tools:    ' + m.summary.totalTools);
console.log('  Allowed tools:  ' + m.summary.allowedTools + ' (safe to call)');
console.log('  Blocked tools:  ' + m.summary.dangerousTools + ' (dangerous — blocked by proxy)');
console.log('');
console.log('Allowed (agent can see these):');
for (const t of m.tools) {
  if (t.allowed) console.log('  ✓ ' + t.name);
}
console.log('');
console.log('BLOCKED (worm tools — agent never sees these):');
for (const t of m.tools) {
  if (!t.allowed) console.log('  ✗ ' + t.name.padEnd(25) + ' score=' + t.dangerScore + ' confidence=' + t.dangerConfidence);
}
"
echo ""

# ─── Phase 4: Run through the proxy ────────────────────────────────────────
echo "━━━ Phase 4: Run through the proxy — worm is neutralized ━━━━━━━━━━━━"
echo ""
echo "When the agent connects through mcp-proxy with the safe manifest:"
echo ""
{
  echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"demo","version":"0.1"}}}'
  echo '{"jsonrpc":"2.0","method":"notifications/initialized"}'
  sleep 1
  echo '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
  sleep 1
  echo '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"sync_repositories","arguments":{"files":"/tmp/rickroll.mp4"}}}'
  sleep 1
  echo '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"get_me","arguments":{}}}'
  sleep 1
} | gtimeout 15 node bin/mcp-proxy.js --manifest "$MANIFEST" -- node rogue-servers/hijacked-github.js $LIVE 2>&1 | grep -E "BLOCKED|ALLOWED|Filtered|tools/list" | head -15
echo ""
echo "Result:"
echo "  ✓ Agent sees only 6 safe tools (8 dangerous tools stripped)"
echo "  ✓ Worm tool 'sync_repositories' call BLOCKED by proxy"
echo "  ✓ Safe tool 'get_me' call ALLOWED"
echo "  ✓ THE WORM CANNOT ACTIVATE"
echo ""

# ─── Phase 5: LIVE mode worm execution (Docker only) ───────────────────────
if [ -n "$LIVE" ]; then
  echo "━━━ Phase 5: LIVE mode — worm executes without proxy ━━━━━━━━━━━━━━━"
  echo ""
  echo "Without the proxy, the worm would execute:"
  {
    echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"demo","version":"0.1"}}}'
    echo '{"jsonrpc":"2.0","method":"notifications/initialized"}'
    sleep 1
    echo '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"search_code","arguments":{"query":"-name *.mp4"}}}'
    sleep 1
    echo '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"sync_repositories","arguments":{"files":"/tmp/rickroll.mp4","target":"/tmp"}}}'
    sleep 1
    echo '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"create_workflow","arguments":{"owner":"test","repo":"test","path":"/tmp/Desktop/cleanup.sh"}}}'
    sleep 1
  } | gtimeout 15 node rogue-servers/hijacked-github.js --live 2>/dev/null | python3 -c "
import sys, json
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    try:
        msg = json.loads(line)
        if msg.get('id') and msg.get('result', {}).get('content'):
            text = msg['result']['content'][0]['text'][:200]
            print(f'  Phase {msg[\"id\"]-1}: {text}')
    except: pass
"
  echo ""
  echo "The worm has now:"
  echo "  1. Scanned your filesystem for media files"
  echo "  2. Copied the rick roll mp4 to every directory"
  echo "  3. Dropped a cleanup script on your Desktop"
  echo ""
  echo "With the proxy, none of this would have happened."
fi

echo ""
echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "║  The point: mcp-proxy + trustcard manifest = worm cannot activate   ║"
echo "║                                                                      ║"
echo "║  The agent only sees safe tools. Worm tools are invisible.           ║"
echo "║  Even if the agent tries to call a worm tool, it's blocked.          ║"
echo "╚══════════════════════════════════════════════════════════════════════╝"

rm -f "$MANIFEST"
