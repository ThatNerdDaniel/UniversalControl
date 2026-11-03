#!/usr/bin/env node
import {genericCli} from '../lib/generic-cli.mjs';
if(process.argv.length===3&&process.argv[2]==='--version')console.log('0.10.2');else genericCli().catch(()=>{console.error('UC_SETUP_STOPPED: local state retained; no automatic re-pairing.');process.exitCode=1;});
