import crypto from 'node:crypto';
export const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
export const version=v=>{if(typeof v!=='string'||!/^\d{1,6}\.\d{1,6}\.\d{1,6}$/.test(v))throw Error('Invalid version');return v.split('.').map(Number);};
export function compare(a,b){const x=version(a),y=version(b);for(let i=0;i<3;i++)if(x[i]!==y[i])return Math.sign(x[i]-y[i]);return 0;}
const keys=['kind','fleet','sequence','version','releaseId','archiveSha256','archiveBytes','wireProtocol','minLauncher','minNode','compatibility'];
export function validateManifest(m,policy){
 if(!m||Array.isArray(m)||Object.keys(m).sort().join(',')!==[...keys].sort().join(',')||m.kind!=='uc-runtime-v1'||m.fleet!==policy.fleet||!Number.isSafeInteger(m.sequence)||m.sequence<1||!/^[a-f0-9]{64}$/.test(m.archiveSha256)||!Number.isSafeInteger(m.archiveBytes)||m.archiveBytes<1||m.archiveBytes>8388608||!/^[a-zA-Z0-9.-]{1,100}$/.test(m.releaseId??''))throw Error('Invalid release manifest');
 version(m.version);version(m.minNode);if(m.wireProtocol!==1||policy.wireProtocol!==1||m.compatibility!=='additive-v1'||m.minLauncher!==1||policy.launcherVersion!==1||compare(policy.nodeVersion,m.minNode)<0)throw Error('Incompatible runtime/launcher; owner setup required');return m;
}
export function verifyEnvelope(envelope,policy){
 if(!envelope||Object.keys(envelope).sort().join(',')!=='manifest,signature'||typeof envelope.signature!=='string'||!/^[A-Za-z0-9_-]{80,100}$/.test(envelope.signature))throw Error('Unsigned or malformed release');
 const m=validateManifest(envelope.manifest,policy),key=crypto.createPublicKey(policy.publicKey);if(key.asymmetricKeyType!=='ed25519'||!crypto.verify(null,Buffer.from(JSON.stringify(m)),key,Buffer.from(envelope.signature,'base64url')))throw Error('Release signature rejected');return m;
}
export function signForReview(manifest,privateKey){if(crypto.createPrivateKey(privateKey).asymmetricKeyType!=='ed25519')throw Error('Ed25519 required');return {manifest,signature:crypto.sign(null,Buffer.from(JSON.stringify(manifest)),privateKey).toString('base64url')};}
export function enrollmentUpdateTrust(policy){const key=crypto.createPublicKey(policy.publicKey);if(key.asymmetricKeyType!=='ed25519'||typeof policy.fleet!=='string'||!policy.fleet)throw Error('Invalid update trust');return {v:1,fleet:policy.fleet,publicKey:key.export({type:'spki',format:'pem'}),launcherVersion:1,wireProtocol:1};}
