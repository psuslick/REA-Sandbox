'use strict';
// Offline guest preflight and mock-test harness. No network or secret required.
const {spawn} = require('node:child_process');
const readline = require('node:readline');
const path = require('node:path');
const assert = require('node:assert/strict');
const mock = process.env.REA_GUARD_TEST === '1' && process.platform !== 'win32';
if (!mock && process.platform !== 'win32') throw new Error('Guest only');
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
 const tools=ok(await request('tools/list',{})).tools;assert(Array.isArray(tools));const names=tools.map(t=>t.name);
 for(const name of ['open_binary','close_binary','binary_session'])assert(names.includes(name),'Missing required tool: '+name);
 assert(!names.includes('execute')&&!names.includes('run_command'),'Unexpected tools');
 const call=(name,args)=>request('tools/call',{name,arguments:args},120000);
 assert((await call('run_command',{})).error,'Disallowed tool accepted');
 assert((await call('open_binary',{path:'C:\\Windows\\System32\\cmd.exe'})).error,'Wrong sample accepted');
 assert((await call('open_binary',{provider_id:'ida'})).error,'Wrong provider accepted');
 assert((await call('close_binary',{snapshot_path:'C:\\REA-Exchange\\out'})).error,'Snapshot accepted');
 assert((await call('binary_session',{expected_server_path:'C:\\Windows'})).error,'Session path accepted');
 assert((await request('resources/list',{})).error,'Resources accepted');
 ok(await call('open_binary',{}));ok(await call('binary_session',{}));ok(await call('close_binary',{}));
 console.log('PASS: initialize, filtered tools/list ('+names.length+' tools), policy denials, pinned static open/session/close. No sample executed.');
}
main().catch(e=>{console.error('MCP smoke failure: '+e.message);process.exitCode=1;}).finally(()=>{child.stdin.end();rl.close();const timer=setTimeout(()=>child.kill(),3000);timer.unref();child.on('exit',()=>clearTimeout(timer));});
