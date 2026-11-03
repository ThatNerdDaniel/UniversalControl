// Owner-specific configuration is injected; nothing runs on import.
import crypto from 'node:crypto';import {invitationLifetime,PairingFailure,exact,ownerOrigin,rsaKey,fingerprint,pss,bytes,digest,sealInvitation} from './pairing-code.mjs';
export class GenericAdmission {
 constructor({registry,ownerKey,ownerDevice,origin,privateKey,allowedDevices,clock=Date.now,maxInvitations=2,bootstrapFor,bootstrapCurrent=b=>Date.parse(new crypto.X509Certificate(b.certificate).validTo)>clock()+7*86400000}){
  registry.owner(ownerKey);registry.active(ownerDevice,registry.record(ownerDevice)?.fingerprint);if(!Array.isArray(allowedDevices)||allowedDevices.some(d=>!/^[A-Z0-9-]{1,64}$/.test(d))||!Number.isInteger(maxInvitations)||maxInvitations<1||maxInvitations>32||registry.maxEnrollmentMs!==invitationLifetime)throw new PairingFailure('EXPLICIT_OWNER_POLICY_REQUIRED');
  this.registry=registry;this.ownerKey=ownerKey;this.ownerDevice=ownerDevice;this.origin=ownerOrigin(origin);this.privateKey=privateKey;this.publicKey=crypto.createPublicKey(privateKey).export({type:'spki',format:'pem'});rsaKey(this.publicKey);this.allowed=allowedDevices;this.clock=clock;this.limit=maxInvitations;this.notified=new Set();this.started=clock();this.calls=0;this.closed=false;
  this.bootstrapFor=bootstrapFor;this.bootstrapCurrent=bootstrapCurrent;this.issuing=new Map();registry.db.exec('CREATE TABLE IF NOT EXISTS generic_invite(codeHash TEXT PRIMARY KEY,tokenHash TEXT,device TEXT UNIQUE,issuedAt INTEGER,expiresAt INTEGER,requestHash TEXT,fingerprint TEXT);CREATE TABLE IF NOT EXISTS generic_bootstrap(id TEXT PRIMARY KEY,plan TEXT,phase TEXT,reply TEXT)');
 }
 check(){if(this.closed)throw new PairingFailure('PAIRING_CLOSED');}
 async issue({device,approval=false,displayPrivate,ttl=invitationLifetime}){
  this.check();this.registry.owner(this.ownerKey);this.registry.active(this.ownerDevice,this.registry.record(this.ownerDevice)?.fingerprint);
  if(approval!==true||typeof displayPrivate!=='function'||!this.allowed.includes(device)||device===this.ownerDevice||this.registry.record(device)||!Number.isInteger(ttl)||ttl<1000||ttl>invitationLifetime)throw new PairingFailure('OWNER_APPROVAL_REQUIRED');
  const db=this.registry.db;db.prepare('DELETE FROM generic_invite WHERE expiresAt<=? AND requestHash IS NULL').run(this.clock());if(db.prepare('SELECT count(*) n FROM generic_invite').get().n>=this.limit||db.prepare('SELECT 1 FROM generic_invite WHERE device=?').get(device))throw new PairingFailure('PAIRING_WINDOW_ALREADY_EXISTS');
  const token=crypto.randomBytes(32).toString('hex'),issuedAt=this.clock(),expiresAt=issuedAt+ttl,body={v:2,purpose:'uc-pair-invitation-v2',origin:this.origin,device,controllerKey:this.publicKey,controllerPin:fingerprint(this.publicKey),token,issuedAt,expiresAt},code=sealInvitation(body,this.privateKey);
  db.prepare('INSERT INTO generic_invite VALUES(?,?,?,?,?,NULL,NULL)').run(digest(Buffer.from(code)),digest(Buffer.from(token)),device,issuedAt,expiresAt);
  try{await displayPrivate(code,{device,expiresAt});}catch{throw new PairingFailure('PRIVATE_CODE_DISPLAY_FAILED');}
  // Never return code/token through ordinary CLI, tool results or telemetry.
  return {issued:true,device,expiresAt};
 }
 admit(wire){
  try{
   this.check();if(this.clock()-this.started>=60000){this.started=this.clock();this.calls=0;}if(++this.calls>60)throw new PairingFailure('PAIRING_RATE_LIMITED');if(typeof wire!=='string'||Buffer.byteLength(wire)>16384)throw Error();const e=JSON.parse(wire);exact(e,['token','body','signature']);const b=e.body;exact(b,['v','purpose','origin','device','codeHash','publicKey','nonce','issuedAt']);
   if(b.v!==2||b.purpose!=='uc-pair-request-v2'||b.origin!==this.origin||!this.allowed.includes(b.device)||!/^[a-f0-9]{64}$/.test(b.codeHash)||!/^[a-f0-9]{64}$/.test(e.token)||!/^[a-f0-9]{64}$/.test(b.nonce)||!Number.isSafeInteger(b.issuedAt)||b.issuedAt>this.clock()+30000||typeof e.signature!=='string'||e.signature.length>1024)throw Error();
   const db=this.registry.db,invite=db.prepare('SELECT * FROM generic_invite WHERE codeHash=?').get(b.codeHash);if(!invite||invite.device!==b.device||invite.expiresAt<=this.clock()||b.issuedAt<invite.issuedAt-30000||invite.tokenHash!==digest(Buffer.from(e.token)))throw Error();
   const pub=rsaKey(b.publicKey);if(!crypto.verify('sha256',bytes(b),pss(pub),Buffer.from(e.signature,'base64url')))throw Error();const id=digest(bytes(b)),fp=fingerprint(b.publicKey),main=this.registry.active(this.ownerDevice,this.registry.record(this.ownerDevice)?.fingerprint);
   if(invite.requestHash&&(invite.requestHash!==id||invite.fingerprint!==fp))throw Error();
   if(!invite.requestHash){if(this.registry.record(b.device))throw Error();if(db.prepare('UPDATE generic_invite SET requestHash=?,fingerprint=? WHERE codeHash=? AND requestHash IS NULL').run(id,fp,b.codeHash).changes!==1)throw Error();}
   const peer=this.reconcile(db.prepare('SELECT * FROM generic_invite WHERE codeHash=?').get(b.codeHash),fp);
   return {id,device:b.device,fingerprint:fp,state:peer.state,expiresAt:invite.expiresAt};
  }catch(e){if(e instanceof PairingFailure&&e.code==='PAIRING_RATE_LIMITED')throw e;throw new PairingFailure('PAIRING_REQUEST_DENIED');}
 }
 reconcile(invite,fp){
  this.check();const main=this.registry.active(this.ownerDevice,this.registry.record(this.ownerDevice)?.fingerprint);
  if(!invite?.requestHash||invite.fingerprint!==fp)throw Error('Bound request required');
  let peer=this.registry.record(invite.device);
  if(peer&&(peer.fingerprint!==fp||peer.subject!==main.subject||peer.client!==main.client||['revoked','denied'].includes(peer.state)))throw Error('Existing peer decision differs');
  if(peer?.state==='approved')return peer;
  if(invite.expiresAt<=this.clock())throw Error('Original invitation expired');
  if(peer?.state==='invited'){this.registry.resetUnapproved(this.ownerKey,invite.device);peer=null;}
  if(!peer){
   const token=this.registry.open(this.ownerKey,{device:invite.device,fingerprint:fp,subject:main.subject,client:main.client,ttl:invite.expiresAt-this.clock()});
   const result=this.registry.request({device:invite.device,fingerprint:fp,token});
   this.notified.add(result.request);peer=this.registry.record(invite.device);
  }
  if(peer?.state!=='pending'||peer.expires<=this.clock())throw Error('No live pending request');
  if(!this.notified.has(peer.request)){this.notified.add(peer.request);this.registry.emit('pairing',{device:invite.device,fingerprint:fp,request:peer.request,scope:'whole_machine'});}
  return peer;
 }
 async status(proof){
  try{this.check();exact(proof,['body','signature']);const b=proof.body;exact(b,['v','purpose','origin','device','id','publicKey','issuedAt']);if(b.v!==2||b.purpose!=='uc-pair-status-v2'||b.origin!==this.origin||!/^[a-f0-9]{64}$/.test(b.id)||!Number.isSafeInteger(b.issuedAt)||Math.abs(this.clock()-b.issuedAt)>30000||typeof proof.signature!=='string'||proof.signature.length>1024)throw Error();const invite=this.registry.db.prepare('SELECT * FROM generic_invite WHERE requestHash=? AND device=?').get(b.id,b.device);if(!invite)throw new PairingFailure('PAIRING_REQUEST_UNKNOWN');if(fingerprint(b.publicKey)!==invite.fingerprint||!crypto.verify('sha256',bytes(b),pss(rsaKey(b.publicKey)),Buffer.from(proof.signature,'base64url')))throw Error();
   const peer=this.reconcile(invite,invite.fingerprint);
   if(peer.state!=='approved'){if(peer.state!=='pending'||invite.expiresAt<=this.clock())throw Error();return {id:b.id,device:b.device,fingerprint:invite.fingerprint,state:'pending',expiresAt:invite.expiresAt};}
   this.registry.active(b.device,invite.fingerprint);if(this.issuing.has(b.id))return await this.issuing.get(b.id);
   const work=this.approvedBootstrap(b,invite);this.issuing.set(b.id,work);try{return await work;}finally{this.issuing.delete(b.id);}
  }catch(e){if(e.code==='PAIRING_REQUEST_UNKNOWN')throw e;throw new PairingFailure('PAIRING_STATUS_DENIED');}
 }
 async approvedBootstrap(b,invite){
  this.check();const db=this.registry.db,prior=db.prepare('SELECT * FROM generic_bootstrap WHERE id=?').get(b.id);if(prior?.reply){const cached=JSON.parse(prior.reply);if(this.bootstrapCurrent(cached.body.bootstrap)){this.registry.active(b.device,invite.fingerprint);return cached;}}
  if(typeof this.bootstrapFor!=='function')throw new PairingFailure('OWNER_BOOTSTRAP_NOT_CONFIGURED');let plan;
  if(prior?.phase==='ISSUING')plan=JSON.parse(prior.plan);else{const generation=prior?JSON.parse(prior.plan).generation+1:1,now=Math.floor(this.clock()/1000)*1000;plan={generation,serial:'1'+digest(Buffer.from(b.id+':'+generation)).slice(1,32),notBefore:now-300000,notAfter:now+90*86400000};db.prepare('INSERT INTO generic_bootstrap VALUES(?,?,?,NULL) ON CONFLICT(id) DO UPDATE SET plan=excluded.plan,phase=excluded.phase,reply=NULL').run(b.id,JSON.stringify(plan),'ISSUING');}
  const bootstrap=await this.bootstrapFor({device:b.device,publicKey:b.publicKey,fingerprint:invite.fingerprint,id:b.id,plan});this.check();this.registry.active(b.device,invite.fingerprint);
  const body={v:2,purpose:'uc-pair-approved-v2',origin:this.origin,id:b.id,device:b.device,fingerprint:invite.fingerprint,bootstrap},reply={body,signature:crypto.sign('sha256',bytes(body),pss(this.privateKey)).toString('base64url')};db.prepare("UPDATE generic_bootstrap SET phase='ISSUED',reply=? WHERE id=?").run(JSON.stringify(reply),b.id);return reply;
 }
 close(){this.closed=true;}
}
