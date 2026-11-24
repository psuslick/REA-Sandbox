'use strict';
// Offline guest preflight and mock-test harness. No network or secret required.
const {spawn} = require('node:child_process');
const readline = require('node:readline');
const path = require('node:path');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const crypto = require('node:crypto');
const mock = process.env.REA_GUARD_TEST === '1' && process.platform !== 'win32';
if (!mock && process.platform !== 'win32') throw new Error('Guest only');
let fixture;
if(mock){
 fixture=fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()),'rea-scope-test-'));
 const root=path.join(fixture,'source'), stage=path.join(fixture,'staging');
 fs.mkdirSync(root);fs.mkdirSync(stage);fs.mkdirSync(path.join(root,'repo'));
 fs.writeFileSync(path.join(root,'repo','main.cs'),'line one\nline two\nline three');
 fs.writeFileSync(path.join(fixture,'outside.txt'),'not authorized');
 fs.symlinkSync(path.join(fixture,'outside.txt'),path.join(root,'escape.txt'));
 fs.symlinkSync(fixture,path.join(root,'escape-dir'));
 fs.linkSync(path.join(fixture,'outside.txt'),path.join(root,'hardlink.txt'));
 const pe=Buffer.alloc(128);pe.write('MZ');pe.writeUInt32LE(64,60);pe.writeUInt32LE(0x4550,64);
 fs.writeFileSync(path.join(root,'repo','sample.exe'),pe);
 fs.writeFileSync(path.join(root,'repo','not.exe'),'not a PE');
 fs.writeFileSync(path.join(root,'repo','sample.nupkg'),'mock package, never parsed');
 process.env.REA_TEST_SOURCE_ROOT=root;process.env.REA_TEST_STAGE_ROOT=stage;
}
const child = spawn(process.execPath,[path.join(__dirname,'rea-mcp-guard.js')],{stdio:['pipe','pipe','inherit'],windowsHide:true,env:process.env});
const rl = readline.createInterface({input:child.stdout,crlfDelay:Infinity});
let id=0; const waiting=new Map();
function fail(err) { for (const p of waiting.values()) {clearTimeout(p.timer);p.reject(err);} waiting.clear(); }
child.on('error',fail);child.on('exit',(code)=>fail(new Error('Guard exited: '+code)));child.stdin.on('error',fail);
rl.on('line',line=>{try{const m=JSON.parse(line);const p=waiting.get(m.id);if(p){clearTimeout(p.timer);waiting.delete(m.id);p.resolve(m);}}catch(e){fail(e);}});
function request(method,params,timeout=30000){return new Promise((resolve,reject)=>{const n=++id;const timer=setTimeout(()=>{waiting.delete(n);reject(new Error('Timeout: '+method));},timeout);waiting.set(n,{resolve,reject,timer});child.stdin.write(JSON.stringify({jsonrpc:'2.0',id:n,method,params})+'\n');});}
function ok(m){assert(!m.error, JSON.stringify(m.error));assert(m.result, 'Missing result');assert(!m.result.isError,JSON.stringify(m.result).slice(0,2000));return m.result;}
async function main(){
 const init=ok(await request('initialize',{protocolVersion:'2025-03-26',capabilities:{},clientInfo:{name:'REA offline smoke',version:'0.12.0'}}));assert(init.protocolVersion);
 child.stdin.write(JSON.stringify({jsonrpc:'2.0',method:'notifications/initialized'})+'\n');
 const tools=[];let cursor;const seenCursors=new Set();
 do {const page=ok(await request('tools/list',cursor?{cursor}:{}));assert(Array.isArray(page.tools));tools.push(...page.tools);cursor=page.nextCursor;if(cursor){assert(!seenCursors.has(cursor),'Repeated catalog cursor');seenCursors.add(cursor);assert(seenCursors.size<100,'Too many catalog pages');}}while(cursor);
 const names=tools.map(t=>t.name);
 if(mock){const expected=require('../CAPABILITIES.json').tools;assert.deepEqual([...names].sort(),expected.map(t=>t.name).sort());for(const t of expected){if(t.origin==='local')continue;const actual=tools.find(x=>x.name===t.name);assert.equal(actual.description.includes('blocked:'),t.authorization==='blocked','Manifest policy drift: '+t.name);}}
 assert.equal(new Set(names).size,names.length,'Duplicate tools');assert.equal(names.length,266,'Expected pinned REA 263 + 3 local tools');
 for(const name of ['open_binary','close_binary','binary_session','list_source_files','read_source_file','hash_source_file'])assert(names.includes(name),'Missing required tool: '+name);
 for(const name of ['inspect_pe_imports','inspect_managed_members','inspect_nuget_nupkg','start_frida_session','capture_browser_scenario','extract_artifact'])assert(names.includes(name),'Hidden tool: '+name);
 assert(tools.find(t=>t.name==='start_frida_session').description.includes('blocked:'));
 assert(tools.find(t=>t.name==='inspect_pe_imports').description.includes('scoped static file parser'));
 for(const name of ['start_frida_session','capture_browser_scenario','export_evidence_bundle','extract_artifact','mock_unreviewed_0'])assert((await request('tools/call',{name,arguments:{}})).error,'Disallowed call accepted: '+name);
 const call=(name,args)=>request('tools/call',{name,arguments:args},120000);
 assert((await call('run_command',{})).error,'Disallowed tool accepted');
 assert((await call('open_binary',{path:'C:\\Windows\\System32\\cmd.exe'})).error,'Wrong sample accepted');
 assert((await call('open_binary',{provider_id:'ida'})).error,'Wrong provider accepted');
 assert((await call('close_binary',{snapshot_path:'C:\\REA-Exchange\\out'})).error,'Snapshot accepted');
 assert((await call('binary_session',{expected_server_path:'C:\\Windows'})).error,'Session path accepted');
 ok(await call('binary_session',{detail:'summary',refresh_candidates:false}));
 assert((await call('inspect_pe_imports',{path:'../outside.txt'})).error,'Parser traversal accepted');
 assert((await call('inspect_pe_imports',{path:'repo/sample.exe',candidate_path:'C:\\Windows'})).error,'Second path accepted');
 assert((await call('inspect_analysis_view',{source:{kind:'file',path:'C:\\Windows'},view:{kind:'native-context'}})).error,'External evidence accepted');
 assert((await call('inspect_analysis_view',{source:{kind:'retained-evidence',evidence_id:'id',path:'outside'},view:{kind:'native-context'}})).error,'Nested path accepted');
 assert((await request('resources/list',{})).error,'Resources accepted');
 const data = m=>JSON.parse(ok(m).content[0].text);
 const rootList=data(await call('list_source_files',{})); assert(Array.isArray(rootList.entries));
 for(const bad of ['..','../outside.txt','..\\outside.txt','C:\\Windows','\\\\server\\share','/etc/passwd','repo/main.cs:secret','repo/../main.cs','repo/CON','repo/main.cs.']) {
  assert((await call('read_source_file',{path:bad})).error,'Escaped path: '+bad);
  assert((await call('hash_source_file',{path:bad})).error,'Escaped hash: '+bad);
 }
 assert((await call('list_source_files',{path:'..'})).error,'Parent listing allowed');
 assert((await call('list_source_files',{path:'',limit:999999})).error,'Unbounded listing');
 assert((await call('read_source_file',{path:'anything',destination:'out'})).error,'Unexpected argument');
 assert((await call('list_strings',{document:'C:\\Windows\\System32\\cmd.exe'})).error,'Document override allowed');
 if(mock){
  assert(rootList.entries.some(x=>x.name==='repo'&&x.type==='directory'));
  assert(rootList.entries.some(x=>x.name==='escape.txt'&&x.type==='blocked'));
  assert(rootList.entries.some(x=>x.name==='hardlink.txt'&&x.type==='blocked'));
  const page=data(await call('list_source_files',{path:'repo',limit:1}));assert.equal(page.next_offset,1);
  const read=data(await call('read_source_file',{path:'repo/main.cs',start_line:2,line_count:1}));assert.equal(read.text,'line two');assert.equal(read.next_line,3);
  const sha=crypto.createHash('sha256').update('line one\nline two\nline three').digest('hex');assert.equal(read.sha256,sha);
  assert.equal(data(await call('hash_source_file',{path:'repo/main.cs'})).sha256,sha);
  for(const bad of ['escape.txt','escape-dir/outside.txt','hardlink.txt'])assert((await call('read_source_file',{path:bad})).error,'Link accepted: '+bad);
  assert((await call('open_binary',{path:'repo/not.exe'})).error,'Invalid header accepted');
  assert((await call('open_binary',{path:'repo/main.cs'})).error,'Source opened as binary');
  ok(await call('inspect_pe_imports',{path:'repo/sample.exe'}));
  ok(await call('inspect_managed_members',{path:'repo/sample.exe',type_names:['Example.Parser'],detail:'summary'}));
  ok(await call('inspect_nuget_nupkg',{path:'repo/sample.nupkg'}));
  ok(await call('inspect_analysis_view',{source:{kind:'retained-evidence',evidence_id:'abc'},view:{kind:'managed-members',collection:'methods',offset:0,limit:20}}));
  ok(await call('compare_functions',{left:{kind:'retained-evidence',evidence_id:'abc'},right:{kind:'retained-evidence',evidence_id:'def'}}));
  assert((await call('compare_functions',{left:{kind:'evidence-file',path:'C:\\Windows'},right:{kind:'retained-evidence',evidence_id:'def'}})).error);
  ok(await call('open_binary',{path:'repo/sample.exe'}));ok(await call('list_names',{}));ok(await call('binary_session',{}));ok(await call('close_binary',{}));
 }
 const pin='C:\\App\\samples\\Intel_HST_f59fdc8a-40f4-48f3-baa6-51b9a27e64b1_3.exe';
 if(mock||fs.existsSync(pin)){ok(await call('open_binary',{}));ok(await call('binary_session',{}));ok(await call('close_binary',{}));}
 else {assert((await call('open_binary',{})).error);ok(await call('binary_session',{}));console.log('INFO: no legacy Intel sample; live Ghidra open test skipped.');}
 console.log('PASS: full tools/list ('+names.length+' tools), scoped directory/read/hash and parser policy, traversal and execution denials, optional pinned static open/session/close. No sample executed.');
}
main().catch(e=>{console.error('MCP smoke failure: '+e.message);process.exitCode=1;}).finally(()=>{child.stdin.end();rl.close();const timer=setTimeout(()=>child.kill(),3000);timer.unref();child.on('exit',()=>{clearTimeout(timer);if(fixture)fs.rmSync(fixture,{recursive:true,force:true});});});
