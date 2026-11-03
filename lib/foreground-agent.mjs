// Existing foreground lifecycle reused with owner-configured target validation.
import fs from 'node:fs';import path from 'node:path';import {once} from 'node:events';import {windowsProtection,readProtected,safePath} from '../src/storage/protected-storage.mjs';
const release={releaseId:'generic-owned-agent'};
const text=(root,file)=>fs.readFileSync(safePath(root,file),'utf8');
const sleep=(ms,signal)=>new Promise(resolve=>{if(signal?.aborted)return resolve();const done=()=>{clearTimeout(timer);signal?.removeEventListener('abort',done);resolve();},timer=setTimeout(done,ms);signal?.addEventListener('abort',done,{once:true});});
function agentProfile(p){if(!p||p.v!==1||p.enabled!==true||p.role!=='agent'||!path.isAbsolute(p.root)||!path.isAbsolute(p.workingDirectory)||!/^[A-Z0-9-]{1,64}$/.test(p.device)||typeof p.host!=='string'||!p.host||p.host.length>253||/[\s/@\\?#]/.test(p.host)||!Number.isInteger(p.port)||p.port<1||p.port>65535||!/^[A-Za-z0-9.-]{1,253}$/.test(p.tlsName))throw Error('Saved owner target invalid');return p;}
export async function foregroundAgent(profile,{signal,protection=windowsProtection,connect,createCore,validate,wait=sleep,onStatus=()=>{},onControl}={}){
  profile=agentProfile(profile);if(!signal)throw Error('Foreground lifetime signal required');
  onStatus('RELEASE: '+release.releaseId);
  const key=readProtected(profile.root,'agent/identity.dpapi','agent-key',protection),cert=text(profile.root,'agent/certificate.pem'),ca=text(profile.root,'agent/controller-trust.pem');
  const core=createCore(profile.workingDirectory);let session,delay=1000;
  const stop=()=>session?.close();signal.addEventListener('abort',stop);
  try{
    while(!signal.aborted){
      try{
        const ticketPath=safePath(profile.root,'agent/enrollment.dpapi');const token=fs.existsSync(ticketPath)?readProtected(profile.root,'agent/enrollment.dpapi','enrollment-ticket',protection):undefined;
        session=connect({host:profile.host,port:profile.port,servername:profile.tlsName,cert,key,ca,device:profile.device,token,
          execute:(method,args)=>{if(process.env.UNIVERSALCONTROL_MANAGED_WIRE==='1'&&['__uc_update_offer','__uc_update_status','__uc_update_drain','__uc_update_resume'].includes(method)){if(typeof onControl!=='function')throw Error('Managed control disabled');return onControl(method,args);}validate(method,{device:profile.device,...args},[profile.device]);return core.call(method,args);}});
        const ended=once(session,'closed').catch(()=>{});
        session.on('pairing',()=>onStatus('PAIRING REQUEST SENT; waiting for one owner whole-machine confirmation.'));
        let handshake;
        try{await Promise.race([session.ready,new Promise((_,reject)=>{handshake=setTimeout(()=>{session.close();reject(Error('Connection/pairing timed out'));},65000);})]);}finally{clearTimeout(handshake);}
        if(signal.aborted)break;
        if(fs.existsSync(ticketPath))fs.unlinkSync(ticketPath);
        delay=1000;onStatus('CONNECTED: '+profile.device+'; this PowerShell window is the link. Ctrl+C disconnects.');
        await ended;
      }catch(e){if(!signal.aborted)onStatus('DISCONNECTED: '+e.message);session?.close();}
      await core.clearProcesses?.(); // Confirm owned-child termination before reconnect.
      if(!signal.aborted){onStatus('RECONNECTING with saved identity; no new pairing grant.');await wait(delay,signal);delay=Math.min(delay*2,30000);}
    }
  }finally{signal.removeEventListener('abort',stop);session?.close();try{await core.close();onStatus('DISCONNECTED: foreground agent stopped.');}catch(e){onStatus('DISCONNECTED: owned cleanup unconfirmed; no automatic retry.');throw e;}}
}
