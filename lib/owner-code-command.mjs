// Separate owner process only; never exposed as a public issuance route.
import fs from 'node:fs';import os from 'node:os';
import {safePath,readProtected,windowsProtection} from '../src/storage/protected-storage.mjs';
import {PeerRegistry} from './generic-peer-registry.mjs';import {GenericAdmission} from './generic-admission.mjs';import {privateCodeDisplay} from './private-code-display.mjs';import {invitationLifetime,PairingFailure} from './pairing-code.mjs';
export async function issueOwnerCode({root,device,approval=false,protection=windowsProtection,spawnProcess,clock=Date.now}){
 if(approval!==true)throw new PairingFailure('OWNER_APPROVAL_REQUIRED');
 const profile=JSON.parse(fs.readFileSync(safePath(root,'controller/profile.json')));
 if(profile.device!==os.hostname().toUpperCase()||profile.genericPairing?.v!==2||profile.genericPairing?.enabled!==true||profile.genericPairing?.invitationLifetime!==invitationLifetime)throw new PairingFailure('REVIEWED_GENERIC_OWNER_POLICY_REQUIRED');
 const ownerKey=readProtected(root,'controller/owner-key.dpapi','owner-key',protection),privateKey=readProtected(root,'controller/ca-key.dpapi','ca-key',protection),registry=new PeerRegistry({filename:safePath(root,'controller/peers.sqlite'),maxEnrollmentMs:invitationLifetime,clock});
 let admission,display;
 try {
  admission=new GenericAdmission({registry,ownerKey,ownerDevice:profile.device,origin:profile.issuer,privateKey,allowedDevices:profile.allowedDevices??[profile.device],clock});
  const result=await admission.issue({device,approval:true,displayPrivate:async(code,{expiresAt})=>{display=await privateCodeDisplay({expiresAt,spawnProcess,clock})(code);}});
  return {...result,display:{shownVerified:display.shown&&display.nativeVisible&&display.onScreen,closed:true,closeReason:display.closeReason,codeExpired:clock()>=result.expiresAt}};
 }finally{admission?.close();registry.close();}
}
