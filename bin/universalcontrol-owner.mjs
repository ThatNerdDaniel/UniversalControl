#!/usr/bin/env node
import {ownerCli} from '../lib/owner-cli.mjs';
ownerCli().catch(()=>{console.error('OWNER_CODE_NOT_ISSUED');process.exitCode=1;});
