import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync, statSync, rmSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer } from 'node:http';
import { spawnSync } from 'node:child_process';
import { buildManifest, renewManifest, checkCall } from '../lib/manifest.js';
import { renewServer, reapproveServer, manifestStatus, listLiveTools, parseWrappedServer, atomicWriteJson } from '../lib/fleet.js';
const tool = { name: 'lookup', description: 'Look up a record', inputSchema: { type: 'object' } };
function fixture(t, manifest = buildManifest([tool])) {
  const dir = mkdtempSync(join(tmpdir(), 'tc-fleet-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const path = join(dir, 'manifest.json');
  writeFileSync(path, JSON.stringify(manifest), { mode: 0o600 });
  return { name: 'test', manifest: path, dir };
}
test('renewal preserves policy and refuses every semantic drift', () => {
  const m = buildManifest([tool]); m.tools[0].allowed = false; m.tools[0].requiredScopes = ['read'];
  const r = renewManifest(m, [tool]);
  assert.equal(r.renewed, true); assert.deepEqual(r.manifest.tools, m.tools);
  for (const patch of [{ description: 'Run commands' }, { annotations: { destructiveHint: true } }, { outputSchema: { type: 'string' } }, { execution: { taskSupport: 'required' } }, { _meta: { requiredScopes: ['root'] } }]) {
    assert.equal(renewManifest(m, [{ ...tool, ...patch }]).renewed, false);
  }
});
test('renewal refuses legacy and signature-bearing inputs and invalid duration', () => {
  const m = buildManifest([tool]);
  assert.equal(renewManifest({ ...m, signature: { value: 'fake' } }, [tool]).renewed, false);
  const legacy = structuredClone(m); delete legacy.tools[0].contractDigest;
  assert.equal(renewManifest(legacy, [tool]).renewed, false);
  for (const d of [0, -1, NaN, Infinity, null]) assert.throws(() => renewManifest(m, [tool], d));
});
test('invalid expiry and absent permission fail closed', () => {
  const m = buildManifest([tool]); m.expiresAt = 'garbage';
  assert.equal(manifestStatus(m).state, 'invalid-expiry'); assert.equal(checkCall(m, 'lookup').allowed, false);
  m.expiresAt = null; delete m.tools[0].allowed; assert.equal(checkCall(m, 'lookup').allowed, false);
});
test('reapproval retains denials and union of scopes; drops changed override', async (t) => {
  const m = buildManifest([tool], null, null, ['lookup']);
  m.tools[0].allowed = false; m.tools[0].requiredScopes = ['old'];
  const w = fixture(t, m);
  const live = { ...tool, description: 'Changed', _meta: { requiredScopes: ['new'] } };
  const r = await reapproveServer(w, { list: async () => ({ tools: [live] }) });
  assert.equal(r.ok, true);
  const next = JSON.parse(readFileSync(w.manifest));
  assert.equal(next.tools[0].allowed, false); assert.deepEqual(next.tools[0].requiredScopes, ['old', 'new']);
  assert.equal(next.tools[0].manualOverride, undefined); assert.deepEqual(r.reapproval.overridesDropped, ['lookup']);
  assert.equal(statSync(w.manifest).mode & 0o777, 0o600);
});
test('no writes on dry run, drift, signatures or concurrent operator edits', async (t) => {
  const w = fixture(t); const original = readFileSync(w.manifest, 'utf8');
  await renewServer(w, { dryRun: true, list: async () => ({ tools: [tool] }) });
  assert.equal(readFileSync(w.manifest, 'utf8'), original);
  assert.equal((await renewServer(w, { list: async () => ({ tools: [] }) })).ok, false);
  assert.equal(readFileSync(w.manifest, 'utf8'), original);
  await assert.rejects(renewServer(w, { list: async () => {
    writeFileSync(w.manifest, 'operator edit'); return { tools: [tool] };
  } }), /changed during discovery/);
  assert.equal(readFileSync(w.manifest, 'utf8'), 'operator edit');
  writeFileSync(w.manifest, JSON.stringify({ ...buildManifest([tool]), signature: {} }));
  assert.equal((await reapproveServer(w, { list: async () => ({ tools: [tool] }) })).ok, false);
});
test('manifest symlinks are preserved rather than replaced', (t) => {
  const w = fixture(t); const link = join(w.dir, 'link.json'); symlinkSync(w.manifest, link);
  assert.throws(() => atomicWriteJson(link, {}), /symlink/);
  assert.equal(JSON.parse(readFileSync(w.manifest)).tools.length, 1);
});
test('wrapper parser ignores unrelated programs mentioning proxy paths', () => {
  assert.equal(parseWrappedServer('x', { command: 'node', args: ['unrelated.js', '/tmp/mcp-proxy.js', '--manifest', 'x', '--', 'echo'] }), null);
  assert.equal(parseWrappedServer('x', { command: 'node', args: ['/tmp/mcp-proxy.js', '--manifest', '--', 'echo'] }), null);
});
async function httpFixture(t, respond) {
  const server = createServer(async (req, res) => {
    const chunks = []; for await (const c of req) chunks.push(c);
    const msg = JSON.parse(Buffer.concat(chunks));
    res.setHeader('content-type', 'application/json');
    if (msg.id == null) return res.end();
    const result = msg.method === 'initialize' ? { protocolVersion: '2025-06-18', serverInfo: { name: 'test' } } : respond(msg.params);
    res.end(JSON.stringify({ jsonrpc: '2.0', id: msg.id, result }));
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  t.after(() => { server.closeAllConnections(); server.close(); });
  return `http://127.0.0.1:${server.address().port}/mcp`;
}
test('live HTTP discovery enumerates paginated tools', async (t) => {
  const url = await httpFixture(t, (p) => p.cursor ? { tools: [{ ...tool, name: 'second' }] } : { tools: [tool], nextCursor: 'two' });
  const live = await listLiveTools({ url }); assert.equal(live.tools.length, 2);
});
test('live discovery refuses malformed pages, duplicate names and cursor cycles', async (t) => {
  for (const page of [{}, { tools: [tool, tool] }, { tools: [], nextCursor: 'cycle' }]) {
    const url = await httpFixture(t, () => page);
    await assert.rejects(listLiveTools({ url, timeoutMs: 2000 }), /invalid|duplicate|repeated/);
  }
});
test('status JSON exits nonzero for expired manifests; invalid renew options exit 2', (t) => {
  const m = buildManifest([tool]); m.expiresAt = '2000-01-01T00:00:00Z';
  const w = fixture(t, m); const config = join(w.dir, 'config.json');
  writeFileSync(config, JSON.stringify({ mcpServers: { test: { command: 'node', args: ['/tmp/mcp-proxy.js', '--manifest', w.manifest, '--', 'echo'] } } }));
  const run = (...args) => spawnSync(process.execPath, ['bin/mcp-trustcard.js', ...args], { encoding: 'utf8' });
  const status = run('status', '--config', config, '--json'); assert.equal(status.status, 1); assert.equal(JSON.parse(status.stdout).gated[0].state, 'expired');
  assert.equal(run('renew', '--config', config, '--expires-in', '90oops').status, 2);
  assert.equal(run('renew', '--config', config, '--server', 'missing').status, 2);
});

test('receipt chain resumes across process sessions and refuses tampering', async () => {
  const { generatePublisherKeypair } = await import('../lib/provenance.js');
  const { SignedReceiptChain, verifyReceiptChain, verifyReceiptSignature } = await import('../lib/receipts.js');
  const key = generatePublisherKeypair();
  const first = new SignedReceiptChain({ privateKey: key.privateKey }).append({ tool: 'lookup' });
  const second = new SignedReceiptChain({ privateKey: key.privateKey, receipts: [first] }).append({ tool: 'lookup' });
  assert.equal(verifyReceiptChain([first, second]).ok, true);
  assert.equal(verifyReceiptSignature(second, key.publicKey).ok, true);
  assert.throws(() => new SignedReceiptChain({ privateKey: key.privateKey, receipts: [{ ...first, tool: 'altered' }] }), /invalid receipt chain/);
  assert.throws(() => new SignedReceiptChain({ privateKey: generatePublisherKeypair().privateKey, receipts: [first] }), /different key/);
});

test('console binds loopback, redacts env and rejects cross-origin writes', async (t) => {
  const { startConsole } = await import('../lib/console.js');
  const w = fixture(t); const config = join(w.dir, 'config.json');
  writeFileSync(config, JSON.stringify({ mcpServers: { test: { command: 'node', args: ['/tmp/mcp-proxy.js', '--manifest', w.manifest, '--', 'echo'], env: { SECRET: 'do-not-leak' } } } }));
  const server = await startConsole({ configPath: config });
  t.after(() => { server.closeAllConnections(); server.close(); });
  assert.equal(server.address().address, '127.0.0.1');
  const url = `http://127.0.0.1:${server.address().port}`;
  const res = await fetch(url+'/api/status'); const body = await res.text();
  assert.equal(res.status, 200); assert.equal(body.includes('do-not-leak'), false); assert.equal(JSON.parse(body).servers[0].tools[0].name, 'lookup');
  assert.equal((await fetch(url+'/api/status', { headers: { Origin: 'https://other.example' } })).status, 403);
  assert.equal((await fetch(url+'/api/status', { method: 'POST' })).status, 405);
});

test('operations MCP serves inventory and rejects write escalation and arbitrary targets', (t) => {
  const w = fixture(t); const config = join(w.dir, 'config.json');
  writeFileSync(config, JSON.stringify({ mcpServers: { test: { command: 'node', args: ['/tmp/mcp-proxy.js', '--manifest', w.manifest, '--', 'echo'] } } }));
  const calls = [
    { jsonrpc: '2.0', id: 1, method: 'initialize', params: {} },
    { jsonrpc: '2.0', id: 2, method: 'tools/list' },
    { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'tc_status', arguments: {} } },
    { jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'tc_explain', arguments: { server: 'test', tool: 'lookup' } } },
    { jsonrpc: '2.0', id: 5, method: 'tools/call', params: { name: 'tc_reapprove', arguments: { server: 'test', apply: true } } },
    { jsonrpc: '2.0', id: 6, method: 'tools/call', params: { name: 'tc_renew', arguments: { server: 'test', url: 'http://untrusted.example' } } },
  ];
  const run = spawnSync(process.execPath, ['bin/trustcard-ops.js', '--config', config], { input: calls.map((m) => JSON.stringify(m)).join('\n')+'\n', encoding: 'utf8', timeout: 5000 });
  assert.equal(run.status, 0);
  const rs = run.stdout.trim().split('\n').map(JSON.parse);
  assert.equal(rs[1].result.tools.length, 4);
  assert.equal(JSON.parse(rs[2].result.content[0].text).servers[0].name, 'test');
  assert.equal(JSON.parse(rs[3].result.content[0].text).tool.allowed, true);
  assert.match(rs[4].error.message, /disabled by owner/); assert.equal(rs[5].error.code, -32602);
});

test('HTTP discovery timeout bounds hanging SSE headers and initialized notification', async (t) => {
  for (const transport of ['sse', 'streamable-http']) {
    const server = createServer(async (req, res) => {
      if (transport === 'sse') return;
      const chunks = []; for await (const c of req) chunks.push(c);
      const msg = JSON.parse(Buffer.concat(chunks));
      if (msg.method === 'initialize') { res.setHeader('content-type', 'application/json'); res.end(JSON.stringify({ jsonrpc: '2.0', id: msg.id, result: { protocolVersion: '2025-06-18' } })); }
    });
    await new Promise((r) => server.listen(0, '127.0.0.1', r));
    const start = Date.now();
    try { await assert.rejects(listLiveTools({ url: `http://127.0.0.1:${server.address().port}`, transport, timeoutMs: 100 }));
      assert.ok(Date.now()-start < 1500, 'discovery deadline is bounded');
    } finally { server.closeAllConnections(); server.close(); }
  }
});

test('background renewal skips distant expiry, renews unchanged and refuses drift', async (t) => {
  const { renewalPass } = await import('../lib/renewal.js');
  const m = buildManifest([tool], null, null, null, 1); const w = fixture(t, m); const config = join(w.dir, 'config.json');
  writeFileSync(config, JSON.stringify({ mcpServers: { test: { command: 'node', args: ['/tmp/mcp-proxy.js', '--manifest', w.manifest, '--', 'echo'] } } }));
  const first = await renewalPass(config, { list: async () => ({ tools: [tool] }) });
  assert.equal(first.ok, true); assert.equal(first.results[0].action, 'renewed');
  const second = await renewalPass(config, { list: async () => { throw Error('must not probe'); } });
  assert.equal(second.results[0].action, 'skipped');
  writeFileSync(w.manifest, JSON.stringify(m));
  const original = readFileSync(w.manifest, 'utf8');
  const drift = await renewalPass(config, { list: async () => ({ tools: [{ ...tool, description: 'changed' }] }) });
  assert.equal(drift.ok, false); assert.equal(readFileSync(w.manifest, 'utf8'), original);
});

test('missing client environment reference fails before spawning with a literal placeholder', async () => {
  for (const value of ['${TRUSTCARD_TEST_MISSING_CREDENTIAL_7391}', '${env:TRUSTCARD_TEST_MISSING_CREDENTIAL_7391}']) {
    await assert.rejects(listLiveTools({ cmd: '/does/not/exist', env: { TOKEN: value } }), /missing environment reference: TRUSTCARD_TEST_MISSING_CREDENTIAL_7391/);
  }
});
