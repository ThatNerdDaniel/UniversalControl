// Generic invitation/proof codec. No built-in owner endpoint, pin or credential.
import crypto from 'node:crypto';import {inspect} from 'node:util';
export const invitationLifetime=15*60*1000;
export const bytes=x=>Buffer.from(JSON.stringify(x));
export const digest=x=>crypto.createHash('sha256').update(x).digest('hex');
export const fingerprint=key=>digest(crypto.createPublicKey(key).export({type:'spki',format:'der'}));
export const pss=key=>({key,padding:crypto.constants.RSA_PKCS1_PSS_PADDING,saltLength:32});
const privateInvitations=new WeakMap();
export class PairingFailure extends Error{constructor(code){super(code);this.name='PairingFailure';this.code=code;}}
export function exact(x,fields){if(!x||Object.keys(x).sort().join()!==[...fields].sort().join())throw new PairingFailure('INVALID_PAIRING_DATA');}
export function ownerOrigin(value){try{const url=new URL(value);if(url.protocol!=='https:'||url.origin!==value||url.username||url.password||!url.hostname)throw Error();return value;}catch{throw new PairingFailure('INVALID_OWNER_ORIGIN');}}
export function rsaKey(pem){try{if(typeof pem!=='string'||pem.length>4096)throw Error();const key=crypto.createPublicKey(pem);if(key.asymmetricKeyType!=='rsa'||key.asymmetricKeyDetails.modulusLength!==3072)throw Error();return key;}catch{throw new PairingFailure('INVALID_OWNER_KEY');}}
export function sealInvitation(body,privateKey){return 'uc2.'+bytes({body,signature:crypto.sign('sha256',bytes(body),pss(privateKey)).toString('base64url')}).toString('base64url');}
export function decodeInvitation(code,{device,clock=Date.now}={}){
 try{
  if(typeof code!=='string'||code.length>8192||!/^uc2\.[A-Za-z0-9_-]+$/.test(code))throw Error();const encoded=code.slice(4),raw=Buffer.from(encoded,'base64url');if(raw.toString('base64url')!==encoded)throw Error();const e=JSON.parse(raw);exact(e,['body','signature']);const b=e.body;
  exact(b,['v','purpose','origin','device','controllerKey','controllerPin','token','issuedAt','expiresAt']);const key=rsaKey(b.controllerKey);
  if(b.v!==2||b.purpose!=='uc-pair-invitation-v2'||b.origin!==ownerOrigin(b.origin)||!/^[A-Z0-9-]{1,64}$/.test(b.device)||device!==undefined&&b.device!==device||b.controllerPin!==fingerprint(b.controllerKey)||!/^[a-f0-9]{64}$/.test(b.token)||!Number.isSafeInteger(b.issuedAt)||!Number.isSafeInteger(b.expiresAt)||b.issuedAt>clock()+30000||b.expiresAt<=clock()||b.expiresAt<=b.issuedAt||b.expiresAt-b.issuedAt>invitationLifetime||typeof e.signature!=='string'||e.signature.length>1024||!crypto.verify('sha256',bytes(b),pss(key),Buffer.from(e.signature,'base64url')))throw Error();
  const invitation={origin:b.origin,device:b.device,controllerKey:b.controllerKey,controllerPin:b.controllerPin,issuedAt:b.issuedAt,expiresAt:b.expiresAt};
  Object.defineProperty(invitation,inspect.custom,{value:()=>({type:'OwnerInvitation',secret:'[REDACTED]'})});privateInvitations.set(invitation,{token:b.token,codeHash:digest(Buffer.from(code))});return Object.freeze(invitation);
 }catch{throw new PairingFailure('INVALID_OR_EXPIRED_PAIRING_CODE');}
}
export function makeAdmission(invitation,{privateKey,clock=Date.now,nonce=crypto.randomBytes(32).toString('hex')}={}){
 try{const secret=privateInvitations.get(invitation);if(!secret)throw Error();const body={v:2,purpose:'uc-pair-request-v2',origin:invitation.origin,device:invitation.device,codeHash:secret.codeHash,publicKey:crypto.createPublicKey(privateKey).export({type:'spki',format:'pem'}),nonce,issuedAt:clock()};
  const raw={token:secret.token,body,signature:crypto.sign('sha256',bytes(body),pss(privateKey)).toString('base64url')};
  // Only the transport serializer has deliberate access to the bearer value.
  return Object.freeze({id:digest(bytes(body)),origin:invitation.origin,device:invitation.device,fingerprint:fingerprint(body.publicKey),wire:()=>JSON.stringify(raw),toJSON:()=>({id:digest(bytes(body)),secret:'[REDACTED]'}),[inspect.custom]:()=>({type:'PairingRequest',secret:'[REDACTED]'})});
 }catch{throw new PairingFailure('PAIRING_PROOF_UNAVAILABLE');}
}
export function makeStatusProof({origin,device,id,privateKey,clock=Date.now}){try{const body={v:2,purpose:'uc-pair-status-v2',origin:ownerOrigin(origin),device,id,publicKey:crypto.createPublicKey(privateKey).export({type:'spki',format:'pem'}),issuedAt:clock()};return {body,signature:crypto.sign('sha256',bytes(body),pss(privateKey)).toString('base64url')};}catch{throw new PairingFailure('PAIRING_PROOF_UNAVAILABLE');}}
