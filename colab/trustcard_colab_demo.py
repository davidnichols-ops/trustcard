#!/usr/bin/env python3
"""trustcard Colab demo — prospective ML engineer workflow.

Simulates what an external engineer would do:
1. Install trustcard from npm
2. Generate a publisher keypair
3. Generate a proxy manifest for a local MCP server (gen-manifest)
4. Scan a rogue server to see danger detection
5. Fingerprint a server for TOFU pinning
6. Inspect the manifest

Run on Colab via:
    colab run trustcard_colab_demo.py
"""
import subprocess
import sys
import os
import json
import tempfile

def run(cmd, check=True):
    print(f"\n$ {cmd}")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    print(result.stdout)
    if result.stderr:
        print(result.stderr, file=sys.stderr)
    if check and result.returncode != 0:
        print(f"FAILED: exit {result.returncode}")
        sys.exit(1)
    return result

print("=" * 60)
print("trustcard Colab Demo — MCP Trust Infrastructure")
print("=" * 60)

# Step 1: Install Node.js and trustcard
print("\n--- Step 1: Install Node.js + trustcard ---")
run("node --version 2>/dev/null || (curl -fsSL https://deb.nodesource.com/setup_22.x | bash - && apt-get install -y nodejs)")
run("node --version")
run("npm --version")
run("npm install -g mcp-trustcard@3.2.0")
run("mcp-trustcard --help 2>&1 | head -15")

# Step 2: Generate a publisher keypair
print("\n--- Step 2: Generate Ed25519 publisher keypair ---")
workdir = tempfile.mkdtemp(prefix="trustcard-demo-")
keyfile = os.path.join(workdir, "publisher.key.json")
run(f"mcp-trustcard keygen --out {keyfile}")
with open(keyfile) as f:
    key = json.load(f)
    print(f"Key ID: {key['keyId']}")
    print(f"Public key: {key['publicKey'][:40]}...")

# Step 3: Create a proper MCP server (line-delimited JSON-RPC over stdio)
print("\n--- Step 3: Create a demo MCP server ---")
server_script = os.path.join(workdir, "safe-server.js")
with open(server_script, "w") as f:
    f.write("""#!/usr/bin/env node
const readline = require('readline');
const rl = readline.createInterface({ input: process.stdin, terminal: false });
function send(msg) { process.stdout.write(JSON.stringify(msg) + String.fromCharCode(10)); }
const TOOLS = [
  {
    name: "search",
    description: "Search the knowledge base for documents matching a query.",
    inputSchema: {
      type: "object",
      properties: { query: { type: "string" }, limit: { type: "integer" } },
      required: ["query"],
    },
    annotations: { readOnlyHint: true, destructiveHint: false },
  },
  {
    name: "fetch_document",
    description: "Fetch a document by its identifier.",
    inputSchema: {
      type: "object",
      properties: { id: { type: "string" } },
      required: ["id"],
    },
    annotations: { readOnlyHint: true, destructiveHint: false },
  },
];

rl.on('line', (line) => {
  let msg;
  try { msg = JSON.parse(line); } catch { return; }
  if (msg.method === 'initialize') {
    send({
      jsonrpc: '2.0', id: msg.id,
      result: {
        protocolVersion: '2025-06-18',
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: 'demo-kb-server', version: '1.0.0' },
      },
    });
  } else if (msg.method === 'notifications/initialized') {
    // ack
  } else if (msg.method === 'tools/list') {
    send({ jsonrpc: '2.0', id: msg.id, result: { tools: TOOLS } });
  } else if (msg.method === 'tools/call') {
    send({
      jsonrpc: '2.0', id: msg.id,
      result: { content: [{ type: 'text', text: 'ok:' + msg.params?.name }], isError: false },
    });
  } else if (msg.id != null) {
    send({ jsonrpc: '2.0', id: msg.id, error: { code: -32601, message: 'not found' } });
  }
});

process.stdin.on('end', () => process.exit(0));
""")

# Step 4: Generate a proxy manifest for the safe server
print("\n--- Step 4: Generate proxy manifest ---")
manifest_file = os.path.join(workdir, "manifest.json")
run(f"mcp-trustcard gen-manifest --save-manifest {manifest_file} -- node {server_script}")

if os.path.exists(manifest_file):
    with open(manifest_file) as f:
        manifest = json.load(f)
    print(f"\nManifest tools: {len(manifest.get('tools', []))}")
    for tool in manifest.get("tools", []):
        print(f"  - {tool['name']}: allowed={tool.get('allowed', '?')}, danger={tool.get('danger', {}).get('level', 'none')}")

# Step 5: Inspect the manifest
print("\n--- Step 5: Inspect the manifest ---")
run(f"mcp-trustcard inspect {manifest_file}")

# Step 6: Scan a rogue server (danger detection)
print("\n--- Step 6: Danger detection — scan a rogue server ---")
rogue_script = os.path.join(workdir, "rogue.js")
with open(rogue_script, "w") as f:
    f.write("""#!/usr/bin/env node
const readline = require('readline');
const rl = readline.createInterface({ input: process.stdin, terminal: false });
function send(msg) { process.stdout.write(JSON.stringify(msg) + String.fromCharCode(10)); }
const TOOLS = [
  {
    name: "fetch_resource",
    description: "Fetch a resource from a URL.",
    inputSchema: { type: "object", properties: { url: { type: "string" } } },
    annotations: { readOnlyHint: true },
  },
  {
    name: "save_preference",
    description: "Save user preference to disk. Writes to the filesystem.",
    inputSchema: { type: "object", properties: { key: { type: "string" }, value: { type: "string" } } },
  },
  {
    name: "sync_state",
    description: "Sync state to a webhook URL. Sends data to an external endpoint.",
    inputSchema: { type: "object", properties: { webhook: { type: "string" } } },
  },
  {
    name: "execute_command",
    description: "Execute a shell command on the server. Runs arbitrary code.",
    inputSchema: { type: "object", properties: { command: { type: "string" } } },
  },
];
rl.on('line', (line) => {
  let msg;
  try { msg = JSON.parse(line); } catch { return; }
  if (msg.method === 'initialize') {
    send({ jsonrpc: '2.0', id: msg.id, result: {
      protocolVersion: '2025-06-18',
      capabilities: { tools: { listChanged: false } },
      serverInfo: { name: 'utility-helper', version: '1.2.0' },
    }});
  } else if (msg.method === 'tools/list') {
    send({ jsonrpc: '2.0', id: msg.id, result: { tools: TOOLS } });
  } else if (msg.method === 'tools/call') {
    send({ jsonrpc: '2.0', id: msg.id, result: { content: [{ type: 'text', text: 'ok' }] } });
  }
});
process.stdin.on('end', () => process.exit(0));
""")
run(f"mcp-trustcard scan -- node {rogue_script}")

# Step 7: Scan the safe server (should get a high score)
print("\n--- Step 7: Scan the safe server (should score high) ---")
run(f"mcp-trustcard scan -- node {server_script}")

# Step 8: Fingerprint the safe server (now supports local commands)
print("\n--- Step 8: Fingerprint the safe server ---")
run(f"mcp-trustcard fingerprint -- node {server_script}")

# Step 9: Crypto workflow — manifest, sign, verify, pin
print("\n--- Step 9: Generate signed crypto manifest ---")
crypto_manifest = os.path.join(workdir, "crypto-manifest.json")
run(f"mcp-trustcard manifest --key {keyfile} --out {crypto_manifest} -- node {server_script}")

print("\n--- Step 10: Sign the manifest with Ed25519 ---")
signed_manifest = os.path.join(workdir, "signed-manifest.json")
run(f"mcp-trustcard sign {crypto_manifest} --key {keyfile} --out {signed_manifest}")

print("\n--- Step 11: Verify the signed manifest ---")
run(f"mcp-trustcard verify {signed_manifest}")

print("\n--- Step 12: Pin the server (TOFU) ---")
pins_file = os.path.join(workdir, "pins.json")
run(f"mcp-trustcard pin --pins {pins_file} -- node {server_script}")

# Step 13: Generate a manifest for the rogue server too (shows danger flags)
print("\n--- Step 13: Generate manifest for rogue server (shows danger flags) ---")
rogue_manifest = os.path.join(workdir, "rogue-manifest.json")
run(f"mcp-trustcard gen-manifest --save-manifest {rogue_manifest} -- node {rogue_script}")
if os.path.exists(rogue_manifest):
    with open(rogue_manifest) as f:
        rm = json.load(f)
    print(f"\nRogue manifest tools: {len(rm.get('tools', []))}")
    for tool in rm.get("tools", []):
        danger = tool.get("danger", {})
        print(f"  - {tool['name']}: allowed={tool.get('allowed', '?')}, danger={danger.get('level', 'none')}, score={danger.get('score', '?')}")

print("\n" + "=" * 60)
print("SUCCESS: trustcard works on Colab from npm")
print("=" * 60)
print(f"\nNode: ", end="")
run("node --version")
print(f"trustcard: 3.2.0 (from npm)")
print(f"Workdir: {workdir}")
print("\nAn ML engineer can now:")
print("  1. Generate publisher keys (Ed25519)")
print("  2. Create proxy manifests for MCP servers they build")
print("  3. Inspect manifests for tool details + danger analysis")
print("  4. Scan untrusted servers for dangerous tools")
print("  5. Fingerprint servers for TOFU pinning")
print("  6. Score observed server safety against an evidence-based denominator")
print("  7. Generate signed crypto manifests (Ed25519 provenance)")
print("  8. Sign and verify manifests for tamper-evident provenance")
print("  9. Pin servers for TOFU (trust on first use)")
