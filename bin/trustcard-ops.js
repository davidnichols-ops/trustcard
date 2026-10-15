#!/usr/bin/env node
// Operations MCP: config selected by owner at startup; tool inputs cannot
// choose executables, file paths, URLs or arbitrary configurations.
import { createInterface } from 'node:readline';
import { listGated, renewServer, reapproveServer } from '../lib/fleet.js';
import { fleetSnapshot } from '../lib/console.js';
const argv = process.argv.slice(2);
const i = argv.indexOf('--config');
if (i < 0 || !argv[i+1]) { console.error('trustcard-ops --config <JSON client config> [--allow-writes]'); process.exit(2); }
const configPath = argv[i+1];
const allowWrites = argv.includes('--allow-writes');
fleetSnapshot(configPath);
const schema = (properties, required = []) => ({ type: 'object', properties, required, additionalProperties: false });
const serverField = { type: 'string', minLength: 1 };
const tools = [
  { name: 'tc_status', description: 'Read local configured gate inventory, policy decisions, scope requirements and expiry. Does not probe runtime or verify publisher signatures.', inputSchema: schema({}), annotations: { readOnlyHint: true, destructiveHint: false } },
  { name: 'tc_explain', description: 'Explain a configured tool decision from the local manifest. Does not grant access or test the upstream server.', inputSchema: schema({ server: serverField, tool: serverField }, ['server','tool']), annotations: { readOnlyHint: true, destructiveHint: false } },
  ...['renew', 'reapprove'].map((op) => ({ name: `tc_${op}`, description: `${op === 'renew' ? 'Check the full live contract and extend an unchanged manifest' : 'Reanalyze live tools while preserving denials and scopes'}. Starts the configured upstream server for discovery. Preview by default; apply requires apply=true and owner-enabled --allow-writes. Existing client processes must reload policy after application.`, inputSchema: schema({ server: serverField, apply: { type: 'boolean', default: false }, days: { type: 'number', exclusiveMinimum: 0, default: 90 } }, ['server']), annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: true } })),
];
async function handle(msg) {
  if (!msg || msg.jsonrpc !== '2.0' || typeof msg.method !== 'string' || Array.isArray(msg)) throw Object.assign(new Error('invalid request'), { code: -32600 });
  if (msg.id == null) return undefined;
  if (msg.method === 'initialize') return { protocolVersion: '2025-06-18', capabilities: { tools: { listChanged: false } }, serverInfo: { name: 'trustcard-operations', version: '3.2.0-rc.1' } };
  if (msg.method === 'ping') return {};
  if (msg.method === 'tools/list') return { tools };
  if (msg.method !== 'tools/call') throw Object.assign(new Error('method not found'), { code: -32601 });
  const name = msg.params?.name, args = msg.params?.arguments ?? {};
  const definition = tools.find((t) => t.name === name);
  if (!definition) throw Object.assign(new Error('unknown tool'), { code: -32601 });
  const fields = definition.inputSchema.properties;
  if (!args || typeof args !== 'object' || Array.isArray(args) || Object.keys(args).some((k) => !(k in fields)) || definition.inputSchema.required.some((k) => typeof args[k] !== 'string' || !args[k])) throw Object.assign(new Error('invalid arguments'), { code: -32602 });
  let value;
  if (name === 'tc_status') value = fleetSnapshot(configPath);
  else if (name === 'tc_explain') {
    const server = fleetSnapshot(configPath).servers.find((s) => s.name === args.server);
    const tool = server?.tools.find((t) => t.name === args.tool);
    if (!tool) throw Object.assign(new Error('unknown configured server or tool'), { code: -32602 });
    value = { server: server.name, state: server.state, tool, signatureVerified: false };
  } else {
    if (args.apply != null && typeof args.apply !== 'boolean') throw Object.assign(new Error('apply must be boolean'), { code: -32602 });
    if (args.days != null && (!Number.isFinite(args.days) || args.days <= 0)) throw Object.assign(new Error('days must be positive and finite'), { code: -32602 });
    if (args.apply && !allowWrites) throw Object.assign(new Error('write operations disabled by owner; restart with --allow-writes to enable'), { code: -32602 });
    const target = listGated(configPath).gated.find((t) => t.name === args.server);
    if (!target) throw Object.assign(new Error('unknown configured gated server'), { code: -32602 });
    value = await (name === 'tc_renew' ? renewServer : reapproveServer)(target, { days: args.days ?? 90, dryRun: !args.apply });
  }
  return { content: [{ type: 'text', text: JSON.stringify(value, null, 2) }], isError: value.ok === false };
}
const input = createInterface({ input: process.stdin });
// Sequential dispatch prevents two operations from overwriting one policy.
for await (const line of input) {
  if (!line.trim()) continue;
  let msg;
  try { msg = JSON.parse(line); }
  catch { process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'invalid JSON' } })+'\n'); continue; }
  try {
    const result = await handle(msg);
    if (result !== undefined) process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: msg.id, result })+'\n');
  } catch (e) {
    if (msg?.id != null) process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: msg.id, error: { code: e.code ?? -32603, message: e.message } })+'\n');
  }
}
