#!/usr/bin/env node
import path from 'node:path';import os from 'node:os';import {pathToFileURL} from 'node:url';
export async function genericCli({argv=process.argv.slice(2),input=process.stdin,output=process.stdout,signal,protection,root=process.env.LOCALAPPDATA&&path.join(process.env.LOCALAPPDATA,'UniversalControl'),workingDirectory=os.homedir(),http,connectSaved,getDevice=()=>os.hostname().toUpperCase()}={}){
 const [major,minor]=process.versions.node.split('.').map(Number);if(major<22||major===22&&minor<13)throw Error('NODE_22_13_REQUIRED');if(!root)throw Error('OWNER_LOCAL_STATE_REQUIRED');
 const [{GenericState},{integratedInstaller},{interactiveSavedRunner}]=await Promise.all([import('./generic-state.mjs'),import('./integrated-installer.mjs'),import('./saved-runner.mjs')]);const state=new GenericState({root,workingDirectory,protection}),life=new AbortController(),stop=()=>life.abort();if(signal?.aborted)life.abort();signal?.addEventListener('abort',stop,{once:true});process.once('SIGINT',stop);process.once('SIGTERM',stop);
 try{return await integratedInstaller({argv,input,output,signal:life.signal,state,getDevice,http,connectSaved:connectSaved??(saved=>interactiveSavedRunner({root:saved.root,input,output,signal:life.signal}))});}finally{signal?.removeEventListener('abort',stop);process.off('SIGINT',stop);process.off('SIGTERM',stop);}
}
if(process.argv[1]&&pathToFileURL(path.resolve(process.argv[1])).href===import.meta.url)genericCli().catch(()=>{console.error('UC_SETUP_STOPPED: local state retained; no automatic re-pairing.');process.exitCode=1;});
