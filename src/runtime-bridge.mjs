import {bounded} from './supervisor.mjs';
// Production IPC protocol with injectable application I/O for isolated tests.
export class RuntimeBridge {
 constructor({nonce,archiveSha256,application,send,readyMs=15000}){this.nonce=nonce;this.hash=archiveSha256;this.app=application;this.send=send;this.readyMs=readyMs;this.closed=false;this.activated=false;this.readyConfirmed=false;this.stopTask=null;}
 async start(){if(this.closed)return;await this.app.start();if(this.closed)return;await new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(Error('Runtime application did not connect')),this.readyMs);this.cancelReady=()=>{clearTimeout(timer);resolve();};this.app.ready.then(()=>{clearTimeout(timer);resolve();},e=>{clearTimeout(timer);reject(e);});});if(this.closed)return;const health=await this.app.health();if(this.closed)return;if(health.healthy!==true||health.connected!==true)throw Error('Runtime health/reconnect not confirmed');this.readyConfirmed=true;this.send({kind:'ready',nonce:this.nonce,archiveSha256:this.hash,wireProtocol:1,health});}
 async stop(){if(this.stopTask)return this.stopTask;this.closed=true;this.cancelReady?.();this.stopTask=Promise.resolve().then(()=>this.app.stop());return this.stopTask;}
 async handle(m){if(!m||m.nonce!==this.nonce||this.closed)return;if(m.kind==='stop'){await this.stop();return;}if(m.kind==='resume'){if(this.activated)await this.app.activate();return;}
  if(!['drain','activate','status','device-status','device-offer','peers'].includes(m.kind))return;
  try{let result;if(m.kind==='activate'){if(!this.readyConfirmed)throw Error('Not ready');await this.app.activate();this.activated=true;result={activated:true};}else if(m.kind==='drain')result=await this.app.drain();else if(m.kind==='status')result={...(await this.app.health()),activated:this.activated};else result=await this.app.deviceControl(m.kind,m);
   if(!this.closed)this.send({kind:'reply',nonce:this.nonce,id:m.id,result});
  }catch{if(!this.closed)this.send({kind:'reply',nonce:this.nonce,id:m.id,error:'Managed operation unavailable; no automatic mutation replay'});}
 }
}
