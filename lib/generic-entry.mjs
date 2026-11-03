// Generic UI draft only. Not wired into or included in any approved package.
// No controller address, pin, discovery, key generation, files or network here.
import {emitKeypressEvents} from 'node:readline';
export async function hiddenPairingInput({input,output,signal,maxLength=8192}){
 if(!input?.isTTY||!output?.isTTY||typeof input.setRawMode!=='function')throw Error('Interactive terminal required; pairing was not started');
 if(signal?.aborted)throw Error('Pairing cancelled');
 const previousRaw=Boolean(input.isRaw),paused=input.isPaused?.()??false;
 return new Promise((resolve,reject)=>{let text='',done=false;
  const finish=(error,value)=>{if(done)return;done=true;input.off('keypress',key);input.off('end',ended);input.off('close',ended);input.off('error',failed);signal?.removeEventListener('abort',cancelled);input.setRawMode(previousRaw);if(paused)input.pause();text='';output.write('\n');error?reject(error):resolve(value);};
  const cancelled=()=>finish(Error('Pairing cancelled')),ended=()=>finish(Error('Pairing input closed')),failed=()=>finish(Error('Pairing input unavailable'));
  const key=(value,k={})=>{if(k.ctrl&&['c','d'].includes(k.name)||k.name==='escape')return cancelled();if(k.name==='return'||k.name==='enter'){const code=text.trim();return code?finish(null,code):finish(Error('No pairing code supplied; pairing was not started'));}if(k.name==='backspace'){text=text.slice(0,-1);return;}if(k.ctrl||k.meta)return;if(typeof value==='string'){if(/[^\x20-\x7e]/.test(value)||text.length+value.length>maxLength)return finish(Error('Invalid pairing input'));text+=value;}};
  emitKeypressEvents(input);input.on('keypress',key);input.once('end',ended);input.once('close',ended);input.once('error',failed);signal?.addEventListener('abort',cancelled,{once:true});
  try{input.setRawMode(true);output.write('Pairing code (hidden): ');input.resume();}catch{failed();}
 });
}
export async function genericEntry({savedProfile,readCode,validateCode,enroll,reconnect}){
 if(savedProfile)return reconnect(savedProfile);
 // Validation must be local and must complete before enroll can discover an
 // owner endpoint, generate a key, install target state or send a request.
 const code=await readCode();if(typeof code!=='string'||!code.trim())throw Error('No pairing code supplied');const invitation=await validateCode(code);if(!invitation)throw Error('Invalid owner invitation');return enroll(invitation);
}
