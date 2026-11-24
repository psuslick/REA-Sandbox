'use strict';
// Only the fixed, explicitly authorized read-only mapping is exposed. No shell,
// archive extraction, network, source evaluation, or host writes.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { TextDecoder } = require('node:util');
const MAX_BINARY = 128 * 1024 * 1024;
const MAX_TEXT = 2 * 1024 * 1024;
const MAX_DIR = 20000;
function createScope(root, staging) {
  const win = process.platform === 'win32';
  const canon = s => (win ? s.replace(/^\\\\\?\\/, '').toLowerCase() : s);
  const real = p => fs.realpathSync.native(p);
  const equal = (a,b) => canon(a) === canon(b);
  function safeName(s) {
    return typeof s === 'string' && s.length > 0 && s.length <= 255 &&
      s !== '.' && s !== '..' && !/[<>:"/\\|?*\x00-\x1f\x7f]/.test(s) &&
      !/[. ]$/.test(s) && !/^(?:con|prn|aux|nul|com[0-9¹²³]|lpt[0-9¹²³]|conin\$|conout\$)(?:\.|$)/i.test(s);
  }
  function parts(rel, allowRoot) {
    if (typeof rel !== 'string' || rel.length > 2048) throw Error('Expected a relative source path');
    if (!rel && allowRoot) return [];
    const p = rel.split(/[\\/]/);
    if (!p.every(safeName)) throw Error('Invalid source path (absolute paths, traversal and device names forbidden)');
    return p;
  }
  function checked(p, kind) {
    const st = fs.lstatSync(p);
    if (st.isSymbolicLink() || !equal(real(p),p) || (kind === 'dir' ? !st.isDirectory() : !st.isFile() || st.nlink > 1)) throw Error('Redirected, linked or unsupported entry');
    return st;
  }
  function resolve(rel, kind) {
    const seg = parts(rel, kind === 'dir');
    checked(root,'dir');
    let p = root;
    for (let i=0;i<seg.length;i++) { p=path.join(p,seg[i]); checked(p,i===seg.length-1?kind:'dir'); }
    return p;
  }
  function bytes(rel,max) {
    const p = resolve(rel,'file');
    const fd = fs.openSync(p,fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
    try {
      const st = fs.fstatSync(fd);
      if (!st.isFile() || st.nlink > 1 || st.size > max) throw Error('Unsupported file or size limit exceeded');
      const before=checked(p,'file');
      if (before.ino !== st.ino || before.dev !== st.dev || before.size !== st.size) throw Error('File changed during open');
      const data = Buffer.alloc(st.size); let n=0;
      while(n<data.length) { const got=fs.readSync(fd,data,n,data.length-n,null); if(!got) throw Error('File shortened during read'); n+=got; }
      const after=fs.fstatSync(fd); const current=checked(p,'file');
      if (after.size !== st.size || after.mtimeMs !== st.mtimeMs || current.ino!==st.ino || current.dev!==st.dev || current.mtimeMs!==st.mtimeMs) throw Error('File changed during read');
      return data;
    } finally { fs.closeSync(fd); }
  }
  const hash = b => crypto.createHash('sha256').update(b).digest('hex');
  function integer(n,d,min,max) { if(n===undefined)return d; if(!Number.isSafeInteger(n)||n<min||n>max) throw Error('Invalid pagination'); return n; }
  function exact(a, allowed) { if(Object.keys(a).some(k=>!allowed.includes(k))) throw Error('Unexpected source tool argument'); }
  function list(a) {
    exact(a,['path','offset','limit']); const rel=a.path===undefined?'':a.path;
    const p=resolve(rel,'dir'); const offset=integer(a.offset,0,0,MAX_DIR); const limit=integer(a.limit,100,1,200);
    const names=[]; const dir=fs.opendirSync(p);
    try { let item; while((item=dir.readSync())!==null) { if(names.length>=MAX_DIR)throw Error('Directory entry limit exceeded'); names.push(item.name); } } finally {dir.closeSync();}
    names.sort(); const entries=names.slice(offset,offset+limit).map(name=>{
      if(!safeName(name))return {name,type:'blocked'};
      try {const f=path.join(p,name); const st=fs.lstatSync(f); if(st.isSymbolicLink())return {name,type:'blocked'}; if(st.isDirectory()){checked(f,'dir');return {name,type:'directory'};} checked(f,'file');return {name,type:'file',size:st.size};}catch{return {name,type:'blocked'};}
    });
    return {path:rel,entries,total:names.length,next_offset:offset+limit<names.length?offset+limit:null};
  }
  function read(a) {
    exact(a,['path','start_line','line_count']); const b=bytes(a.path,MAX_TEXT);
    const text=new TextDecoder('utf-8',{fatal:true}).decode(b);
    if(text.includes('\0'))throw Error('Not a UTF-8 source text file');
    const lines=text.split(/\r\n|\n|\r/); const start=integer(a.start_line,1,1,Math.max(1,lines.length)); const count=integer(a.line_count,100,1,400);
    let used=0, end=start-1; const content=[];
    for(const line of lines.slice(start-1,start-1+count)){const size=Buffer.byteLength(line)+1;if(used+size>64000)break;used+=size;content.push(line);end++;}
    if(!content.length)throw Error('Single line exceeds 64 KB response limit');
    return {path:a.path,sha256:hash(b),total_lines:lines.length,start_line:start,end_line:end,next_line:end<lines.length?end+1:null,text:content.join('\n')};
  }
  function digest(a) {exact(a,['path']);const b=bytes(a.path,MAX_BINARY);return {path:a.path,size:b.length,sha256:hash(b)};}
  let stagedBytes=0, stagedCount=0;
  function stage(rel) {
    const seg=parts(rel,false);const ext=path.extname(seg.at(-1)).toLowerCase();
    if(!['.exe','.dll','.sys','.ocx','.cpl','.efi','.bin','.elf','.so','.dylib'].includes(ext))throw Error('Only supported binary filename extensions may be opened');
    const b=bytes(rel,MAX_BINARY);
    // Only conventional executable headers; reject scripts, containers and raw data.
    const mz=b.length>=64 && b[0]===0x4d && b[1]===0x5a;
    const pe=mz?b.readUInt32LE(0x3c):0;
    const validPE=mz && pe>=64 && pe+24<=b.length && b.readUInt32LE(pe)===0x4550;
    const elf=b.length>=16 && b.subarray(0,4).equals(Buffer.from([0x7f,0x45,0x4c,0x46]));
    const mach=b.length>=32 && [0xfeedface,0xcefaedfe,0xfeedfacf,0xcffaedfe,0xcafebabe,0xbebafeca,0xcafebabf,0xbfbafeca].includes(b.readUInt32BE(0));
    if(!validPE&&!elf&&!mach)throw Error('Unsupported executable header');
    return stageBytes(rel,ext,b);
  }
  function stagePackage(rel,extensions) {
    const seg=parts(rel,false);const ext=path.extname(seg.at(-1)).toLowerCase();
    if(!extensions.includes(ext))throw Error('File extension not authorized for this parser');
    return stageBytes(rel,ext,bytes(rel,MAX_BINARY));
  }
  function stageBytes(rel,ext,b) {
    if(stagedCount>=64 || stagedBytes+b.length>1024*1024*1024)throw Error('Guest staging quota reached; restart sandbox');
    const sha=hash(b); checked(staging,'dir'); const dir=fs.mkdtempSync(path.join(staging,'sample-')); const out=path.join(dir,'target'+ext);
    stagedCount++; stagedBytes+=b.length;
    fs.writeFileSync(out,b,{flag:'wx',mode:0o600}); if(hash(fs.readFileSync(out))!==sha)throw Error('Guest staged hash mismatch');
    return {path:out,sha256:sha,source:rel};
  }
  return {list,read,digest,stage,stagePackage};
}
const schemas=[
  {name:'list_source_files',description:'List one directory within the approved reaSourceInspection root, paginated. Paths are relative; empty path lists the root.',inputSchema:{type:'object',properties:{path:{type:'string'},offset:{type:'integer'},limit:{type:'integer'}},additionalProperties:false}},
  {name:'read_source_file',description:'Read UTF-8 source lines in the approved reaSourceInspection folder. Returns line numbers and SHA-256; never executes code.',inputSchema:{type:'object',properties:{path:{type:'string'},start_line:{type:'integer'},line_count:{type:'integer'}},required:['path'],additionalProperties:false}},
  {name:'hash_source_file',description:'Calculate SHA-256 of a file within the approved reaSourceInspection folder.',inputSchema:{type:'object',properties:{path:{type:'string'}},required:['path'],additionalProperties:false}}
];
module.exports={createScope,schemas};
