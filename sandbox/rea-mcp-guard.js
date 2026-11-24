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
const {createScope,schemas} = require('./rea-source-scope');
const localNames = new Set(schemas.map(x=>x.name));
const win = process.platform === 'win32';
const root = win ? 'C:\\SandboxBootstrap\\reaSourceInspection' : process.env.REA_TEST_SOURCE_ROOT;
const staging = win ? 'C:\\App\\source-samples' : process.env.REA_TEST_STAGE_ROOT;
const scope = createScope(root, staging);
let pinnedAvailable = !win;

// Discovery is independent of authorization. Unknown and effectful operations
// remain visible but fail closed. These are audited argument contracts, not a
// name-prefix trust rule or reliance on upstream readOnlyHint annotations.
const SESSION = new Set(`binary_overview list_segments list_strings search_strings list_procedures search_procedures procedure_info procedure_address procedure_assembly procedure_pseudo_code procedure_callees procedure_callers procedure_references xrefs read_bytes analyze_function get_call_graph list_names address_name address_to_file_offset current_address current_document current_procedure list_documents list_bookmarks find_xrefs_to_name get_navigation_context inspect_address_context inspect_native_instruction inspect_native_api inspect_native_data_type resolve_containing_procedure resolve_native_call_targets read_function_instructions search_bytes trace_call_path trace_native_values batch_decompile decompile_all inspect_native_load_image get_objc_classes get_objc_protocols analyze_swift_types`.split(/\s+/));
// File-backed built-in static parsers. Do not add parsers that follow external
// paths, invoke arbitrary programs, mount images, or load target code here.
const BINARY_PARSERS = new Set(`inspect_pe_imports inspect_pe_certificates inspect_pe_load_config inspect_pe_resources inspect_native_exports inspect_binary_hardening inspect_go_binary inspect_rust_binary inspect_elf_notes inspect_elf_dependencies inspect_elf_unwind_ranges inspect_managed_artifact inspect_managed_members inspect_managed_native_boundaries inspect_byte_entropy inspect_native_initializers`.split(/\s+/));
const PACKAGE_PARSERS = new Map([['inspect_nuget_nupkg',['.nupkg']],['inspect_python_pyc',['.pyc']],['inspect_erlang_beam',['.beam']],['inspect_il2cpp_metadata',['.dat']]]);
const EVIDENCE = new Set(['inspect_analysis_settings','list_unknowns','get_evidence_bundle']);
const COMPARE = new Set(['compare_artifacts','compare_functions','compare_application_versions','compare_javascript_export_shapes','compare_wasm_interfaces']);
const advertised = new Set();
function policy(name) {
  if(localNames.has(name)) return 'scoped source inspection';
  if(['binary_session','open_binary','close_binary'].includes(name)) return 'restricted session lifecycle';
  if(SESSION.has(name)) return 'active-target static analysis';
  if(BINARY_PARSERS.has(name)||PACKAGE_PARSERS.has(name)) return 'scoped static file parser';
  if(EVIDENCE.has(name)||COMPARE.has(name)||name==='inspect_analysis_view') return 'in-memory evidence read';
  return 'blocked: operation not authorized in static-only mode';
}
const MAX_LINE = 12 * 1024 * 1024; // do not accept unbounded JSON from tunnel.
const MAX_ARGS_BYTES = 128 * 1024;
const target = process.env.REA_GUARD_TARGET || 'C:\\App\\samples\\Intel_HST_f59fdc8a-40f4-48f3-baa6-51b9a27e64b1_3.exe';
const rea = process.env.REA_GUARD_REA;

if (process.platform === 'win32') {
  const must = 'c:\\app\\samples\\intel_hst_f59fdc8a-40f4-48f3-baa6-51b9a27e64b1_3.exe';
  if (path.win32.normalize(target).toLowerCase() !== must) throw new Error('Guard target must equal the pinned guest-local sample path.');
  if (os.userInfo().username.toLowerCase() !== 'wdagutilityaccount') throw new Error('Refusing to run outside Windows Sandbox.');
  if (fs.existsSync(target)) {
  const real = fs.realpathSync.native(target).replace(/^\\\\\?\\/, '').toLowerCase();
  if (path.win32.normalize(real) !== must) throw new Error('Target is redirected; refused.');
  const hash = require('node:crypto').createHash('sha256').update(fs.readFileSync(target)).digest('hex');
  if (hash !== 'dd3ff68bc5c326691e787a8967807a144535fcb334e315c42053bf68ac9df25b') throw new Error('Pinned sample hash mismatch');
  pinnedAvailable = true;
  }
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
childEnv.REA_MCP_OUTPUT_SCHEMA_PROFILE = 'off';
const child = spawn(executable, args, { stdio: ['pipe', 'pipe', 'inherit'], env: childEnv, windowsHide: true });
child.on('error', err => { process.stderr.write('REA gateway child error: ' + err.message + '\n'); process.exit(2); });
child.on('exit', code => { process.stderr.write('REA subprocess exited: ' + code + '\n'); process.exit(code === null ? 2 : code); });
child.stdin.on('error', () => { process.exit(2); });

function reply(id, code, message) {
  if (id !== undefined) process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id, error: { code, message } }) + '\n');
}
// Reject unrecognized option keys, including nested documents, provider overrides,
// and path aliases. Text selectors are not interpreted as filenames here.
const SESSION_KEYS = new Set(`address addresses start_address end_address procedure procedures pattern mode case_sensitive detail direction length depth max_depth max_nodes max_results limit offset count size analysis name symbol query needle encoding bytes hex value type kind selector target_address source_address goal_address start end include_thunks include_external include_assembly include_pseudocode include_references include_strings include_cfg include_native_api max_instructions max_bytes max_functions page_size page_offset`.split(/\s+/));
const PARSER_KEYS = new Set(`detail architecture type_names member_names offset limit count max_results max_items max_strings min_length max_length include_strings include_methods include_fields include_resources include_symbols`.split(/\s+/));
function scalar(v) {return typeof v==='string' && v.length<=16384 && !v.includes('\0') || typeof v==='boolean' || typeof v==='number'&&Number.isFinite(v);}
function flat(a, keys) {return Object.entries(a).every(([k,v])=>keys.has(k)&&(scalar(v)||Array.isArray(v)&&v.length<=256&&v.every(scalar)));}
function exact(a, keys) {return Object.keys(a).every(k=>keys.includes(k));}
function retainedRef(a) {return a && typeof a==='object' && !Array.isArray(a) && exact(a,['kind','evidence_id']) && a.kind==='retained-evidence' && typeof a.evidence_id==='string' && /^[a-zA-Z0-9_.:-]{1,160}$/.test(a.evidence_id);}
function retainedView(a) {
  return exact(a,['source','view']) && retainedRef(a.source) && a.view && typeof a.view==='object' && !Array.isArray(a.view) && flat(a.view,new Set(['kind','collection','offset','limit','page','facet','item','index','field','address','procedure','start_line','line_count']));
}
function scrubRequest(msg) {
  if (msg.method === 'tools/call') {
    const p = msg.params;
    if(msg.id===undefined) return 'Tool invocation requires a request ID';
    if (!p || typeof p !== 'object' || Array.isArray(p) || !exact(p,['name','arguments','_meta']) || typeof p.name !== 'string' || policy(p.name).startsWith('blocked:')) return 'Tool not approved by REA VM policy';
    const a = p.arguments === undefined ? {} : p.arguments;
    if (!a || typeof a !== 'object' || Array.isArray(a) || Buffer.byteLength(JSON.stringify(a)) > MAX_ARGS_BYTES) return 'Invalid or excessive tool arguments';
    if (localNames.has(p.name)) return null;
    if (p.name === 'binary_session') {
      if (!exact(a,['detail','refresh_candidates']) || a.detail!==undefined&&!['summary','complete'].includes(a.detail) || a.refresh_candidates!==undefined&&typeof a.refresh_candidates!=='boolean') return 'binary_session arguments blocked';
    } else if (p.name === 'open_binary') {
      // Never hand caller-controlled paths directly to Ghidra.
      if (Object.keys(a).some(k => !['path', 'provider_id'].includes(k))) return 'Unapproved open_binary argument';
      if (a.provider_id !== undefined && a.provider_id !== 'ghidra') return 'Only Ghidra provider permitted';
      if (a.path === undefined || a.path === target) {
        if (!pinnedAvailable) return 'No legacy Intel sample; supply a relative inspection path';
        msg.params.arguments = {path:target,provider_id:'ghidra'};
      } else {
        try {
          const staged=scope.stage(a.path);
          msg.params.arguments={path:staged.path,provider_id:'ghidra'};
          process.stderr.write('Static analysis input SHA-256: '+staged.sha256+'\n');
        } catch(e) { return 'Inspection binary refused: '+e.message; }
      }
    } else if (p.name === 'close_binary') {
      // close_binary also accepts snapshot_path (writes evidence); ban all arguments.
      if (Object.keys(a).length) return 'close_binary arguments blocked';
     } else if (BINARY_PARSERS.has(p.name)||PACKAGE_PARSERS.has(p.name)) {
      if(typeof a.path!=='string') return 'Explicit relative inspection path required';
      const {path:rel,...options}=a;
      if(!flat(options,PARSER_KEYS)) return 'Unapproved static parser option';
      try {
        const staged=BINARY_PARSERS.has(p.name)?scope.stage(rel):scope.stagePackage(rel,PACKAGE_PARSERS.get(p.name));
        msg.params.arguments={...options,path:staged.path};
        process.stderr.write('Static parser input SHA-256: '+staged.sha256+'\n');
      } catch(e) {return 'Inspection artifact refused: '+e.message;}
    } else if (SESSION.has(p.name)) {
      if(!flat(a,SESSION_KEYS)) return 'Unexpected active-target argument blocked';
      if(a.analysis!==undefined && a.analysis!=='independent_fresh' && a.analysis!=='call_destination') return 'Unapproved analysis mode';
    } else if (p.name==='inspect_analysis_view') {
      if(!retainedView(a)) return 'Only retained in-memory evidence views are permitted';
    } else if (COMPARE.has(p.name)) {
      if(!exact(a,['left','right','detail'])||!retainedRef(a.left)||!retainedRef(a.right)||a.detail!==undefined&&!['summary','complete'].includes(a.detail)) return 'Comparison requires two retained in-memory evidence references';
    } else if (EVIDENCE.has(p.name)) {
      if(!flat(a,new Set(['detail','offset','limit','status','evidence_id']))) return 'Unapproved evidence argument';
    } else return 'Operation blocked by static-only policy';
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
    if (msg.id !== undefined && (pending.size >= 64 || pending.has(JSON.stringify(msg.id)))) return reply(msg.id,-32600,'Duplicate or excessive pending requests');
    let reason;
    try { reason = scrubRequest(msg); } catch { reason = 'Malformed or excessively nested arguments'; }
    if (reason) return reply(msg.id, -32602, reason);
    if (msg.method === 'tools/call' && localNames.has(msg.params.name)) {
      if (msg.id === undefined) return;
      try {
        const f={list_source_files:scope.list,read_source_file:scope.read,hash_source_file:scope.digest}[msg.params.name];
        const result=f(msg.params.arguments || {});
        process.stdout.write(JSON.stringify({jsonrpc:'2.0',id:msg.id,result:{content:[{type:'text',text:JSON.stringify(result)}]}})+'\n');
      } catch(e) {reply(msg.id,-32602,'Source inspection refused: '+e.message);}
      return;
    }
    if (msg.id !== undefined) {
      if (pending.size >= 64 || pending.has(JSON.stringify(msg.id))) return reply(msg.id, -32600, 'Duplicate or excessive pending requests');
      pending.set(JSON.stringify(msg.id), {method:msg.method,firstPage:!msg.params?.cursor});
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
    const {method,firstPage} = pending.get(JSON.stringify(msg.id));
    pending.delete(JSON.stringify(msg.id));
    if (method === 'tools/list' && msg.result && Array.isArray(msg.result.tools)) {
      // Preserve every upstream tool and its input schema. The gateway annotates
      // authorization status; it never treats an advertised name as permission.
      if(firstPage) advertised.clear();
      for(const t of msg.result.tools) {
        if(!t || typeof t.name!=='string') continue;
        advertised.add(t.name);
        delete t.outputSchema; // optional MCP field; keep catalog compact
        t.description='[REA Sandbox: '+policy(t.name)+'] '+(t.description||'');
        if(t.name==='open_binary'||BINARY_PARSERS.has(t.name)||PACKAGE_PARSERS.has(t.name)) {
          t.description+=' Supply a path relative to reaSourceInspection; gateway stages a guest-local copy.';
          if(t.inputSchema?.properties?.path) t.inputSchema.properties.path={type:'string',description:'Relative path within reaSourceInspection'};
        }
      }
      if(firstPage) msg.result.tools.push(...schemas.filter(t=>!advertised.has(t.name)));
      if(!msg.result.nextCursor) process.stderr.write('REA catalog: '+advertised.size+' upstream tools; '+schemas.length+' local tools; operation policy enforced separately.\n');
    }
    if (method === 'initialize' && msg.result && msg.result.capabilities) {
      delete msg.result.capabilities.resources;
      delete msg.result.capabilities.prompts;
      delete msg.result.capabilities.logging;
    }
  }
  process.stdout.write(JSON.stringify(msg) + '\n');
});
