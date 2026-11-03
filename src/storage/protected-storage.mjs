import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

function windowsData(action,input) {
  const result=spawnSync('powershell.exe',['-NoLogo','-NoProfile','-NonInteractive','-File',fileURLToPath(new URL('./protected-data.ps1',import.meta.url))],
    {input:JSON.stringify({action,payload:Buffer.from(input).toString('base64')}),encoding:'utf8',windowsHide:true,timeout:15000,maxBuffer:1048576});
  if(result.error||result.status!==0)throw Error('CurrentUser protected storage unavailable; no plaintext fallback');
  const raw=result.stdout.trim();if(!/^[A-Za-z0-9+/]+={0,2}$/.test(raw))throw Error('Invalid protected-data response');return Buffer.from(raw,'base64');
}
export const windowsProtection={protect:b=>windowsData('protect',b),unprotect:b=>windowsData('unprotect',b)};
export function safePath(root,relative) {
  if(!path.isAbsolute(root)||typeof relative!=='string'||path.isAbsolute(relative))throw Error('Explicit private-root/relative path required');
  const target=path.resolve(root,relative),part=path.relative(root,target);
  if(part==='..'||part.startsWith('..'+path.sep)||path.isAbsolute(part))throw Error('Private path escaped root');
  let current=path.parse(target).root;
  for(const item of target.slice(current.length).split(path.sep).filter(Boolean)){current=path.join(current,item);if(fs.existsSync(current)&&fs.lstatSync(current).isSymbolicLink())throw Error('Private state reparse point rejected');}
  return target;
}
export function writeProtected(root,relative,kind,value,protection=windowsProtection,{replace=false}={}) {
  const target=safePath(root,relative),plain=Buffer.from(JSON.stringify({v:1,kind,value}));
  const cipher=protection.protect(plain);
  if(!Buffer.isBuffer(cipher)||!cipher.length||cipher.equals(plain))throw Error('Protected storage did not encrypt');
  const encoded=JSON.stringify({v:1,protection:'DPAPI-CurrentUser',ciphertext:cipher.toString('base64')});
  fs.mkdirSync(path.dirname(target),{recursive:true});
  if(!replace){fs.writeFileSync(target,encoded,{flag:'wx'});return;}
  const stage=target+'.stage-'+crypto.randomUUID();
  try{fs.writeFileSync(stage,encoded,{flag:'wx'});fs.renameSync(stage,target);}finally{if(fs.existsSync(stage))fs.unlinkSync(stage);}
}
export function readProtected(root,relative,kind,protection=windowsProtection) {
  const target=safePath(root,relative);if(fs.statSync(target).size>1048576)throw Error('Protected record too large');
  const record=JSON.parse(fs.readFileSync(target,'utf8'));
  if(record.v!==1||record.protection!=='DPAPI-CurrentUser'||typeof record.ciphertext!=='string')throw Error('Invalid protected record');
  const decoded=JSON.parse(protection.unprotect(Buffer.from(record.ciphertext,'base64')).toString('utf8'));
  if(decoded.v!==1||decoded.kind!==kind)throw Error('Protected credential purpose mismatch');return decoded.value;
}
export function protectionPreflight(protection=windowsProtection) {
  const probe=crypto.randomBytes(32),encrypted=protection.protect(probe);
  if(!Buffer.isBuffer(encrypted)||encrypted.equals(probe)||!protection.unprotect(encrypted).equals(probe))throw Error('CurrentUser protection preflight failed');
}
