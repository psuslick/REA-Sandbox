'use strict';
/**
 * REA MCP read-only gateway. Runs INSIDE disposable Windows Sandbox only.
 * Tunnel client speaks MCP/JSON-RPC stdio to this process, not to REA directly.
 * This is an advisory application-layer boundary, not a substitute for VM/firewall isolation.
 */
const { spawn } = require('node:child_process');
const readline = require('node:readline');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');

const ALLOW = new Set([
  'binary_session', 'open_binary', 'close_binary', 'binary_overview',
  'list_segments', 'list_strings', 'search_strings', 'list_procedures',
  'search_procedures', 'procedure_info', 'procedure_address',
  'procedure_assembly', 'procedure_pseudo_code', 'procedure_callees',
  'procedure_callers', 'procedure_references', 'xrefs',
  'read_bytes', 'analyze_function', 'get_call_graph'
]);
const MAX_LINE = 12 * 1024 * 1024; // do not accept unbounded JSON from tunnel.
const MAX_ARGS_BYTES = 128 * 1024;
const target = process.env.REA_GUARD_TARGET || 'C:\\App\\samples\\Intel_HST_f59fdc8a-40f4-48f3-baa6-51b9a27e64b1_3.exe';
const rea = process.env.REA_GUARD_REA;

if (process.platform === 'win32') {
  const must = 'c:\\app\\samples\\intel_hst_f59fdc8a-40f4-48f3-baa6-51b9a27e64b1_3.exe';
  if (path.win32.normalize(target).toLowerCase() !== must) throw new Error('Guard target must equal the pinned guest-local sample path.');
  if (os.userInfo().username.toLowerCase() !== 'wdagutilityaccount') throw new Error('Refusing to run outside Windows Sandbox.');
  const real = fs.realpathSync.native(target).replace(/^\\\\\?\\/, '').toLowerCase();
  if (path.win32.normalize(real) !== must) throw new Error('Target is redirected; refused.');
  const hash = require('node:crypto').createHash('sha256').update(fs.readFileSync(target)).digest('hex');
  if (hash !== 'dd3ff68bc5c326691e787a8967807a144535fcb334e315c42053bf68ac9df25b') throw new Error('Pinned sample hash mismatch');
}

// Direct Node entrypoint; never execute a command shell or resolve from host PATH.
let executable, args;
if (process.platform === 'win32') {
  const root = 'C:\\App\\rea-runtime\\node_modules\\rea-agents';
  const meta = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  if (meta.name !== 'rea-agents' || meta.version !== '6.10.1') throw new Error('Unexpected REA package');
  const bin = typeof meta.bin === 'string' ? meta.bin : meta.bin?.rea;
  if (typeof bin !== 'string') throw new Error('REA package has no CLI entrypoint');
  const entry = fs.realpathSync.native(path.resolve(root, bin));
  if (!entry.toLowerCase().startsWith(root.toLowerCase() + '\\')) throw new Error('REA CLI entrypoint outside package');
  executable = process.execPath;
  args = [entry, 'mcp'];
} else {
  // Test fixture only. Production launcher refuses non-Windows hosts.
  if (!rea || process.env.REA_GUARD_TEST !== '1') throw new Error('Not Windows Sandbox');
  executable = process.execPath;
  args = [rea, 'mcp'];
}
const childEnv = Object.fromEntries(Object.entries(process.env).filter(([key]) => !/^(CONTROL_PLANE_|OPENAI_|CLOUDFLARED_|MCP_|TUNNEL_CLIENT_|HARPOON_)/i.test(key)));
for (const key of Object.keys(process.env)) { if (/^(CONTROL_PLANE_|OPENAI_|CLOUDFLARED_|MCP_|TUNNEL_CLIENT_|HARPOON_)/i.test(key)) delete process.env[key]; }
const child = spawn(executable, args, { stdio: ['pipe', 'pipe', 'inherit'], env: childEnv, windowsHide: true });
child.on('error', err => { process.stderr.write('REA gateway child error: ' + err.message + '\n'); process.exit(2); });
child.on('exit', code => { process.stderr.write('REA subprocess exited: ' + code + '\n'); process.exit(code === null ? 2 : code); });
child.stdin.on('error', () => { process.exit(2); });

function reply(id, code, message) {
  if (id !== undefined) process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id, error: { code, message } }) + '\n');
}
function safePathFields(value, parent = '') {
  if (!value || typeof value !== 'object') return true;
  for (const [key, v] of Object.entries(value)) {
    const k = key.toLowerCase();
    // No file loading, writing, execution or remote URLs in other analysis requests.
    if (/(?:path|file|filename|directory|command|executable|script|url|uri|destination|process_id|pid|target|artifact|snapshot|registration|config|provider_id)$/i.test(k)) return false;
    if (v && typeof v === 'object' && !safePathFields(v, k)) return false;
  }
  return true;
}
function scrubRequest(msg) {
  if (msg.method === 'tools/call') {
    const p = msg.params;
    if (!p || typeof p !== 'object' || typeof p.name !== 'string' || !ALLOW.has(p.name)) return 'Tool not approved by REA VM policy';
    const a = p.arguments === undefined ? {} : p.arguments;
    if (!a || typeof a !== 'object' || Array.isArray(a) || Buffer.byteLength(JSON.stringify(a)) > MAX_ARGS_BYTES) return 'Invalid or excessive tool arguments';
    if (p.name === 'binary_session') {
      if (Object.keys(a).length) return 'binary_session arguments blocked';
    } else if (p.name === 'open_binary') {
      // Refuse snapshots and cross-provider selection. Enforce a single immutable target name.
      if (Object.keys(a).some(k => !['path', 'provider_id'].includes(k))) return 'Unapproved open_binary argument';
      if (a.path !== undefined && (typeof a.path !== 'string' || path.win32.normalize(a.path).toLowerCase() !== path.win32.normalize(target).toLowerCase())) return 'Only guest-local pinned Intel executable may be opened';
      if (a.provider_id !== undefined && a.provider_id !== 'ghidra') return 'Only Ghidra provider permitted';
      msg.params.arguments = { path: target, provider_id: 'ghidra' };
    } else if (p.name === 'close_binary') {
      // close_binary also accepts snapshot_path (writes evidence); ban all arguments.
      if (Object.keys(a).length) return 'close_binary arguments blocked';
    } else if (!safePathFields(a)) return 'Unexpected filesystem, command or URL argument blocked';
  }
  return null;
}
const pending = new Map();
const inbound = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
inbound.on('line', line => {
  if (Buffer.byteLength(line) > MAX_LINE) return; // drop oversized input
  let msg;
  try { msg = JSON.parse(line); } catch { return; }
  if (!msg || typeof msg !== 'object' || Array.isArray(msg) || msg.jsonrpc !== '2.0' || typeof msg.method !== 'string') return;
  if (msg.method) {
    const methods = new Set(['initialize', 'ping', 'tools/list', 'tools/call', 'notifications/initialized', 'notifications/cancelled']);
    if (!methods.has(msg.method)) return reply(msg.id, -32601, 'MCP method blocked by REA VM policy');
    let reason;
    try { reason = scrubRequest(msg); } catch { reason = 'Malformed or excessively nested arguments'; }
    if (reason) return reply(msg.id, -32602, reason);
    if (msg.id !== undefined) {
      if (pending.size >= 64 || pending.has(JSON.stringify(msg.id))) return reply(msg.id, -32600, 'Duplicate or excessive pending requests');
      pending.set(JSON.stringify(msg.id), msg.method);
    }
  }
  child.stdin.write(JSON.stringify(msg) + '\n');
});
inbound.on('close', () => child.stdin.end());
const outbound = readline.createInterface({ input: child.stdout, crlfDelay: Infinity });
outbound.on('line', line => {
  if (Buffer.byteLength(line) > MAX_LINE) { process.stderr.write('REA output exceeded gateway limit.\n'); return; }
  let msg;
  try { msg = JSON.parse(line); } catch { process.stderr.write('Dropped non-JSON child stdout.\n'); return; }
  if (!msg || typeof msg !== 'object' || msg.method || msg.id === undefined || !pending.has(JSON.stringify(msg.id))) return;
  if (msg.id !== undefined && pending.has(JSON.stringify(msg.id))) {
    const method = pending.get(JSON.stringify(msg.id));
    pending.delete(JSON.stringify(msg.id));
    if (method === 'tools/list' && msg.result && Array.isArray(msg.result.tools)) {
      msg.result.tools = msg.result.tools.filter(t => t && ALLOW.has(t.name));
    }
    if (method === 'initialize' && msg.result && msg.result.capabilities) {
      delete msg.result.capabilities.resources;
      delete msg.result.capabilities.prompts;
      delete msg.result.capabilities.logging;
    }
  }
  process.stdout.write(JSON.stringify(msg) + '\n');
});
