import test from 'node:test';
import assert from 'node:assert/strict';
import {genericAgentApplication} from '../lib/generic-agent-application.mjs';
import {PairingFailure} from '../lib/pairing-code.mjs';
const tick = () => new Promise(r => setImmediate(r));
async function fixture({cleanupFailure, refresh = async () => ({key: 'fixture-new-key'}), fallback = () => ({key: 'fixture-local-key'})} = {}) {
  const signal = new AbortController();
  let native, core, calls = 0, connects = 0, fallbackCalls = 0, cleanup = 0;
  class Core {
    constructor() { this.processes = {sessions: new Map()}; this.desktop = {helper: () => ({ok: true})}; core = this; }
    call() { calls++; return {ok: true}; }
  }
  const foregroundAgent = async (profile, options) => {
    native = options; options.createCore('/fixture'); options.connect({device: profile.device});
    options.onStatus('CONNECTED: TARGET');
    await new Promise(r => options.signal.addEventListener('abort', r, {once: true}));
    cleanup++; if (cleanupFailure) throw cleanupFailure;
  };
  const state = {root: '/fixture', read: () => ({device: 'TARGET'}), currentTransport: () => { fallbackCalls++; return fallback(); }};
  const app = await genericAgentApplication({packageDirectory: '/fixture', state, signal: signal.signal,
    refresh, modules: [{foregroundAgent}, {Core}, {connectMutualTls: p => { connects++; return p; }}, {validate() {}}]});
  return {app, signal, get native() { return native; }, get core() { return core; },
    get calls() { return calls; }, get connects() { return connects; }, get fallbackCalls() { return fallbackCalls; }, get cleanup() { return cleanup; }};
}
test('saved app has no action access until managed activation; drain and owned close are enforced', async () => {
  const f = await fixture();
  await f.app.start(); await f.app.ready;
  await assert.rejects(f.core.call('file_read', {}), /UPDATING_NOT_EXECUTED/);
  await f.app.activate(); await f.core.call('file_read', {}); assert.equal(f.calls, 1);
  assert.deepEqual(await f.app.drain(), {drained: true});
  await assert.rejects(f.core.call('file_read', {}), /UPDATING_NOT_EXECUTED/);
  await f.native.onControl('__uc_update_resume'); await f.core.call('file_read', {});
  await f.app.stop(); await f.app.stop();
  assert.equal(f.cleanup, 1); assert.equal(f.app.health().healthy, false);
});
test('explicit owner denial, bad bootstrap or TLS rejection cannot fall back to saved certificate', async () => {
  for (const code of ['OWNER_DENIED', 'OWNER_TLS_REJECTED', 'SIGNED_OWNER_BOOTSTRAP_REJECTED']) {
    const f = await fixture({refresh: async () => { throw new PairingFailure(code); }});
    await assert.rejects(f.app.start(), new RegExp(code));
    assert.equal(f.fallbackCalls, 0); assert.equal(f.connects, 0); await f.app.stop();
  }
});
test('temporary owner outage permits only locally verified nonexpired credentials', async () => {
  const refresh = async () => { throw new PairingFailure('OWNER_CONNECTION_UNAVAILABLE'); };
  const f = await fixture({refresh}); await f.app.start(); assert.equal(f.fallbackCalls, 1); assert.equal(f.connects, 1); await f.app.stop();
  const expired = await fixture({refresh, fallback: () => { throw new PairingFailure('SIGNED_OWNER_BOOTSTRAP_REJECTED'); }});
  await assert.rejects(expired.app.start(), /SIGNED_OWNER_BOOTSTRAP_REJECTED/);
  assert.equal(expired.connects, 0); await expired.app.stop();
});
test('reconnect refresh owner revocation closes owned session and action gate without invitation replay', async () => {
  let count = 0;
  const f = await fixture({refresh: async () => { if (++count > 1) throw new PairingFailure('OWNER_DENIED'); return {key: 'fixture'}; }});
  await f.app.start(); await f.app.activate();
  f.native.onStatus('DISCONNECTED: TARGET'); await tick(); await tick();
  assert.equal(f.native.signal.aborted, true); assert.equal(f.fallbackCalls, 0);
  await assert.rejects(f.core.call('file_read', {}), /UPDATING_NOT_EXECUTED/);
  assert.equal(f.app.health().connected, false); await f.app.stop();
});
test('outer console abort disconnects and awaits owned agent cleanup', async () => {
  const f = await fixture(); await f.app.start(); f.signal.abort(); await f.app.stop();
  assert.equal(f.native.signal.aborted, true); assert.equal(f.cleanup, 1);
});

test('application stop propagates uncoded original owned cleanup failure',async()=>{const original=Error('Fixture uncoded close failure'),f=await fixture({cleanupFailure:original});await f.app.start();await assert.rejects(f.app.stop(),e=>e===original);assert.equal(f.cleanup,1);assert.equal(f.app.health().connected,false);});
