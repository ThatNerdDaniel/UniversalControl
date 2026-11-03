import fs from 'node:fs';import path from 'node:path';import zlib from 'node:zlib';import {sha} from './release-policy.mjs';
const text=b=>new TextDecoder('utf8',{fatal:true}).decode(b);
function field(b){const n=b.indexOf(0);if(n<0)return text(b);if(b.subarray(n).some(v=>v!==0))throw Error('Invalid tar text padding');return text(b.subarray(0,n));}
function octal(b){const s=text(b).replace(/\0/g,'').trim();if(!/^[0-7]+$/.test(s))throw Error('Unsupported tar integer');return parseInt(s,8);}
export function inspectArchive(bytes,m){
 if(!Buffer.isBuffer(bytes)||bytes.length!==m.archiveBytes||sha(bytes)!==m.archiveSha256)throw Error('Archive digest/size rejected');const raw=zlib.gunzipSync(bytes,{maxOutputLength:67108864}),entries=[],seen=new Set();let offset=0,ended=false;
 while(offset+512<=raw.length){const h=raw.subarray(offset,offset+512);if(h.every(v=>v===0)){if(raw.length-offset<1024||raw.subarray(offset).some(v=>v!==0))throw Error('Invalid tar ending');ended=true;break;}
  const checksum=octal(h.subarray(148,156));let sum=0;for(let i=0;i<512;i++)sum+=i>=148&&i<156?32:h[i];if(sum!==checksum)throw Error('Tar checksum rejected');
  const type=String.fromCharCode(h[156]);if(!['0','\0','5'].includes(type))throw Error('Tar links/extensions rejected');const prefix=field(h.subarray(345,500)),name=(prefix?prefix+'/':'')+field(h.subarray(0,100));
  if(!name.startsWith('package/')||name.includes('\\')||name.includes(':')||/[\x00-\x1f\x7f]/.test(name))throw Error('Unsafe archive path');const relative=name.slice(8).replace(/\/$/,'');const parts=relative.split('/');
  if(!relative||relative.length>240||parts.length>12||parts.some(p=>!p||p==='.'||p==='..'||!/^[A-Za-z0-9._-]+$/.test(p)||/[. ]$/.test(p)||/^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(p)))throw Error('Unsafe archive path');const identity=relative.toLowerCase();if(seen.has(identity))throw Error('Duplicate archive path');seen.add(identity);
  const size=octal(h.subarray(124,136));if(size>16777216||type==='5'&&size!==0||offset+512+size>raw.length||entries.length>=512)throw Error('Excessive/truncated archive');const data=raw.subarray(offset+512,offset+512+size);entries.push({relative,directory:type==='5',data,sha256:sha(data)});offset+=512+Math.ceil(size/512)*512;
 }if(!ended)throw Error('Missing tar ending');
 const pkg=entries.find(e=>e.relative==='package.json'&&!e.directory);if(!pkg)throw Error('Package manifest missing');const p=JSON.parse(text(pkg.data));if(p.name!=='@universalcontrol/agent'||p.version!==m.version||p.bin?.universalcontrol!=='bin/universalcontrol.mjs'||!entries.some(e=>e.relative==='bin/universalcontrol.mjs'&&!e.directory))throw Error('Package identity/entry rejected');return entries;
}
export function extractVerified(entries,directory){
 if(fs.existsSync(directory))throw Error('Staging directory exists');fs.mkdirSync(directory);for(const e of entries){const target=path.join(directory,...e.relative.split('/'));let cursor=directory;for(const component of e.relative.split('/').slice(0,-1)){cursor=path.join(cursor,component);if(fs.existsSync(cursor)){if(fs.lstatSync(cursor).isSymbolicLink()||!fs.statSync(cursor).isDirectory())throw Error('Unsafe staging parent');}else fs.mkdirSync(cursor);}
  if(e.directory){if(fs.existsSync(target)){if(!fs.statSync(target).isDirectory()||fs.lstatSync(target).isSymbolicLink())throw Error('Archive directory conflict');}else fs.mkdirSync(target);}else fs.writeFileSync(target,e.data,{flag:'wx'});
 }return entries.filter(e=>!e.directory).map(e=>({path:e.relative,sha256:e.sha256}));
}
export function verifyInstalled(directory,files){const expected=new Set(files.map(e=>e.path));function walk(dir){for(const e of fs.readdirSync(dir,{withFileTypes:true})){const p=path.join(dir,e.name);if(e.isSymbolicLink())throw Error('Installed reparse point rejected');if(e.isDirectory())walk(p);else if(!expected.has(path.relative(directory,p).replaceAll('\\','/')))throw Error('Unmanifested installed file');}}walk(directory);for(const e of files){const target=path.join(directory,...e.path.split('/'));if(fs.lstatSync(target).isSymbolicLink()||sha(fs.readFileSync(target))!==e.sha256)throw Error('Installed file changed');}return true;}
