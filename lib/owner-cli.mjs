#!/usr/bin/env node
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {issueOwnerCode} from './owner-code-command.mjs';
// Separate owner-only operation; the generic target installer accepts no args.
export async function ownerCli({argv = process.argv.slice(2),
  root = process.env.LOCALAPPDATA && path.join(process.env.LOCALAPPDATA, 'UniversalControl'),
  issue = issueOwnerCode, output = process.stdout} = {}) {
  if (argv.length !== 3 || argv[0] !== 'code' || argv[2] !== '--approve' || !/^[A-Z0-9-]{1,64}$/.test(argv[1])) throw Error('OWNER_CODE_CONFIRMATION_REQUIRED');
  if (!root) throw Error('OWNER_LOCAL_STATE_REQUIRED');
  const result = await issue({root, device: argv[1], approval: true});
  const display=result.display?{shownVerified:result.display.shownVerified===true,closed:result.display.closed===true,closeReason:['closed','expired'].includes(result.display.closeReason)?result.display.closeReason:'unknown',codeExpired:result.display.codeExpired===true}:undefined;
  output.write(JSON.stringify({display,issued: result.issued === true, device: argv[1], expiresAt: result.expiresAt}) + '\n');
  return {issued: result.issued === true};
}
if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) ownerCli().catch(() => {
  console.error('OWNER_CODE_NOT_ISSUED: private display unavailable or owner policy not approved.'); process.exitCode = 1;
});
