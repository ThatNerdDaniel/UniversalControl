import {spawnSync} from 'node:child_process';import {fileURLToPath} from 'node:url';import {PairingFailure} from './pairing-code.mjs';
export function validateDisplayResult(raw){
 const flags=['shown','nativeVisible','onScreen','foreground'];
 if(!raw||raw.v!==2||typeof raw.ok!=='boolean'||flags.some(k=>typeof raw[k]!=='boolean')||!['closed','expired','failed'].includes(raw.closeReason)||!Number.isInteger(raw.session)||raw.session<0||raw.ok&&raw.session<1||!Number.isSafeInteger(raw.elapsedMs)||raw.elapsedMs<0||raw.elapsedMs>901000||!Number.isSafeInteger(raw.shownElapsedMs)||raw.shownElapsedMs< -1||raw.shownElapsedMs>901000||!['INPUT','ASSEMBLY','NATIVE_SETUP','DESKTOP_CHECK','BUILD_FORM','SHOW_DIALOG','SHOWN'].includes(raw.phase)||!raw.bounds||Array.isArray(raw.bounds)||Object.keys(raw.bounds).sort().join()!=='height,left,top,width'||!['left','top','width','height'].every(k=>Number.isInteger(raw.bounds[k])&&Math.abs(raw.bounds[k])<=100000))throw new PairingFailure('PRIVATE_DISPLAY_UNAVAILABLE');
 const result=Object.fromEntries(['phase','session','elapsedMs','shownElapsedMs','closeReason','bounds',...flags].map(k=>[k,raw[k]]));
 if(!raw.ok||!raw.shown||!raw.nativeVisible||!raw.onScreen||raw.closeReason==='failed')throw new PairingFailure('PRIVATE_DISPLAY_UNAVAILABLE');
 return result;
}
export function privateCodeDisplay({expiresAt,spawnProcess=spawnSync,clock=Date.now}={}){return async code=>{
 const now=clock();if(typeof code!=='string'||code.length>8192||!Number.isSafeInteger(expiresAt)||expiresAt<=now||expiresAt>now+900000)throw new PairingFailure('PRIVATE_DISPLAY_UNAVAILABLE');
 const started=clock();let r;try{r=spawnProcess('powershell.exe',['-NoLogo','-NoProfile','-NonInteractive','-STA','-File',fileURLToPath(new URL('./private-code-display.ps1',import.meta.url))],{input:JSON.stringify({code,expiresAt}),encoding:'utf8',windowsHide:false,timeout:Math.max(1000,expiresAt-now+1000),maxBuffer:8192});}catch{throw new PairingFailure('PRIVATE_DISPLAY_UNAVAILABLE');}
 if(r.error||r.status!==0)throw new PairingFailure('PRIVATE_DISPLAY_UNAVAILABLE');let raw;try{raw=JSON.parse(r.stdout);}catch{throw new PairingFailure('PRIVATE_DISPLAY_UNAVAILABLE');}
 return {...validateDisplayResult(raw),childElapsedMs:Math.max(0,clock()-started),codeExpired:clock()>=expiresAt};
};}
