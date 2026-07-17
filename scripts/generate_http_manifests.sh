#!/bin/bash
# Generate manifests for HTTP-based MCP servers by connecting to each upstream
# and calling tools/list. Requires OAuth tokens (for notion/linear/atlassian)
# or API keys (for roboflow). DeepWiki and Figma may work without auth for
# tools/list.
#
# Usage: ./scripts/generate_http_manifests.sh
# Output: ~/.config/devin/manifests/{server}.json

set -euo pipefail

MANIFEST_DIR="$HOME/.config/devin/manifests"
mkdir -p "$MANIFEST_DIR"

# Helper: call tools/list on an HTTP MCP server and save manifest
# Args: <name> <url> [extra-headers-json]
generate_manifest() {
  local name="$1"
  local url="$2"
  local headers="${3:-{}}"
  local outfile="$MANIFEST_DIR/$name.json"

  echo "Generating manifest for $name ($url)..."

  # Send initialize + tools/list in a single session
  local init_response
  init_response=$(curl -s -X POST "$url" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json, text/event-stream" \
    $(echo "$headers" | python3 -c "
import json, sys
h = json.load(sys.stdin)
for k, v in h.items():
    print(f'-H \"{k}: {v}\"')
" 2>/dev/null) \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"mcp-trustcard","version":"0.4.0"}}}' \
    2>/dev/null || echo "")

  if [ -z "$init_response" ]; then
    echo "  FAILED: no response from initialize (may need OAuth login)"
    return 1
  fi

  # Check if we got an auth error
  if echo "$init_response" | grep -qi "auth\|unauthorized\|401\|403"; then
    echo "  SKIPPED: requires authentication (run 'devin mcp login $name' first)"
    return 1
  fi

  # Now call tools/list
  local tools_response
  tools_response=$(curl -s -X POST "$url" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json, text/event-stream" \
    $(echo "$headers" | python3 -c "
import json, sys
h = json.load(sys.stdin)
for k, v in h.items():
    print(f'-H \"{k}: {v}\"')
" 2>/dev/null) \
    -d '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' \
    2>/dev/null || echo "")

  if [ -z "$tools_response" ]; then
    echo "  FAILED: no response from tools/list"
    return 1
  fi

  # Extract tools and build manifest using node
  echo "$tools_response" | node -e "
    const { buildManifest } = require('./lib/manifest.js');
    let buf = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', d => buf += d);
    process.stdin.on('end', () => {
      try {
        const msg = JSON.parse(buf);
        const tools = msg.result?.tools || [];
        if (tools.length === 0) {
          console.error('  NO TOOLS found in response');
          process.exit(1);
        }
        const manifest = buildManifest(tools, msg.result?.serverInfo, '$url');
        const fs = require('fs');
        fs.writeFileSync('$outfile', JSON.stringify(manifest, null, 2));
        console.log('  Manifest saved: $outfile');
        console.log('  Tools: ' + manifest.tools.length);
        console.log('  Hash: ' + manifest.manifestHash);
      } catch (e) {
        console.error('  ERROR parsing response: ' + e.message);
        process.exit(1);
      }
    });
  " 2>&1 || echo "  FAILED to generate manifest"
}

# DeepWiki — no auth required for public repos
generate_manifest "deepwiki" "https://mcp.deepwiki.com/mcp" '{}' || true

# Figma — may require OAuth
generate_manifest "figma" "https://mcp.figma.com/mcp" '{}' || true

# Roboflow — requires API key
if [ -n "${ROBOFLOW_API_KEY:-}" ]; then
  generate_manifest "roboflow" "https://mcp.roboflow.com/mcp" "{\"x-api-key\":\"$ROBOFLOW_API_KEY\",\"Accept\":\"application/json, text/event-stream\"}" || true
else
  echo "roboflow: SKIPPED (ROBOFLOW_API_KEY not set)"
fi

# Notion, Linear, Atlassian — require OAuth (run 'devin mcp login <name>' first)
for srv in notion linear atlassian; do
  case $srv in
    notion) url="https://mcp.notion.com/mcp" ;;
    linear) url="https://mcp.linear.app/mcp" ;;
    atlassian) url="https://mcp.atlassian.com/v1/mcp" ;;
  esac
  echo "$srv: attempting manifest generation (may need OAuth)..."
  generate_manifest "$srv" "$url" '{}' || echo "  $srv: SKIPPED (requires OAuth — run 'devin mcp login $srv')"
done

echo ""
echo "Done. Manifests in $MANIFEST_DIR:"
ls -la "$MANIFEST_DIR"/*.json 2>/dev/null | awk '{print "  " $NF}'
