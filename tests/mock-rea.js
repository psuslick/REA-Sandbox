'use strict';
const fs=require('node:fs');const path=require('node:path');const readline=require('node:readline');const assert=require('node:assert/strict');
assert(!process.env.CONTROL_PLANE_API_KEY);assert(!process.env.OPENAI_API_KEY);assert(!process.env.CLOUDFLARED_TOKEN);
const names=require('../CAPABILITIES.json').tools.filter(x=>x.origin==='upstream').map(x=>x.name);
let opened=false;
function staged(a){assert(a.path.startsWith(process.env.REA_TEST_STAGE_ROOT+path.sep));assert(fs.existsSync(a.path));}
readline.createInterface({input:process.stdin}).on('line',l=>{
const m=JSON.parse(l);if(m.id===undefined)return;let result={};
if(m.method==='initialize')result={protocolVersion:'2025-03-26',capabilities:{tools:{},resources:{},prompts:{}}};
else if(m.method==='tools/list'){const second=m.params?.cursor==='next';result={tools:names.slice(second?100:0,second?263:100).map(name=>({name,description:'fixture',inputSchema:{type:'object',properties:{path:{type:'string'}}},outputSchema:{type:'object'}})),...(!second?{nextCursor:'next'}:{})};}
else if(m.method==='tools/call'){const {name,arguments:a}=m.params;
if(name==='open_binary'){if(!a.path.includes('Intel_HST')){staged(a);assert.equal(fs.readFileSync(a.path).subarray(0,2).toString(),'MZ');}assert.equal(a.provider_id,'ghidra');opened=true;}
else if(name==='binary_session'){assert(Object.keys(a).every(k=>['detail','refresh_candidates'].includes(k)));}
else if(name==='close_binary'){assert(opened);opened=false;}
else if(['inspect_pe_imports','inspect_managed_members','inspect_nuget_nupkg'].includes(name)){staged(a);assert(!('candidate_path' in a));}
else if(['list_names','list_strings'].includes(name)){assert(opened);assert(!('document' in a));}
else if(name==='compare_functions'){assert.equal(a.left.kind,'retained-evidence');assert.equal(a.right.kind,'retained-evidence');}
else if(name==='inspect_analysis_view'){assert.equal(a.source.kind,'retained-evidence');assert(!('path' in a.source));}
else throw Error('blocked call reached child: '+name);result={content:[{type:'text',text:'ok'}]};}
process.stdout.write(JSON.stringify({jsonrpc:'2.0',id:m.id,result})+'\n');});
