import {foregroundAgent as genericForegroundAgent} from './foreground-agent.mjs';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {DrainGate, coreIsBusy} from '../src/drain-gate.mjs';
import {refreshSavedCredentials} from './integrated-installer.mjs';

// Only a temporary connection failure permits still-valid pinned local TLS.
const temporary = error => error?.code === 'OWNER_CONNECTION_UNAVAILABLE';
export async function genericAgentApplication({packageDirectory, state, signal,
  onControl, onConnected = () => {}, onStatus = () => {}, modules,
  refresh = refreshSavedCredentials, protection}) {
  const load = name => import(pathToFileURL(path.join(packageDirectory, 'src', name)));
  const [{foregroundAgent}, {Core}, {connectMutualTls}, {validate}] = modules ??
    await Promise.all([Promise.resolve({foregroundAgent: genericForegroundAgent}),
      load('core.mjs'), load('transport.mjs'), load('controller.mjs')]);
  const profile = state.read(state.root, 'agent/profile.json');
  let task, core, connected = false, tls, refreshing, timer, stopping = false, stopTask;
  const life = new AbortController();
  let resolveReady, rejectReady;
  const ready = new Promise((a, b) => { resolveReady = a; rejectReady = b; });
  ready.catch(() => {});
  const gate = new DrainGate({busy: () => Boolean(refreshing) || Boolean(core && coreIsBusy(core)),
    interactive: () => { try { return core.desktop.helper({action: 'check'}).ok === true; } catch { return false; } }});
  gate.accepting = false;
  const update = () => {
    if (refreshing) return refreshing;
    refreshing = Promise.resolve().then(() => refresh({state, signal: life.signal}))
      .then(value => { if (!stopping) tls = value; return value; })
      .finally(() => { refreshing = null; });
    return refreshing;
  };
  const refreshOrFail = async () => {
    try { return await update(); }
    catch (error) {
      if (temporary(error) && !life.signal.aborted) {
        // Checks certificate dates, signed receipt, device key and owner pin.
        try { tls = state.currentTransport(); return tls; }
        catch (invalidLocalCertificate) { error = invalidLocalCertificate; }
      }
      tls = null; gate.close(); life.abort(); rejectReady(error); throw error;
    }
  };
  const refreshAfterDisconnect = () => {
    void refreshOrFail().catch(() => onStatus('Saved identity unavailable; no automatic re-pairing.'));
  };
  const stopSignal = () => life.abort();
  signal.addEventListener('abort', stopSignal, {once: true});
  return {
    ready,
    async start() {
      if (signal.aborted) throw Error('Owner closed');
      await refreshOrFail();
      if (life.signal.aborted) throw Error('Owner closed');
      task = foregroundAgent(profile, {signal: life.signal, protection, validate,
        connect: params => {
          if (!tls) throw Error('Saved credentials unavailable');
          return connectMutualTls({...params, ...tls});
        },
        createCore: root => {
          core = new Core(root, {wholeMachine: true});
          const original = core.call.bind(core);
          core.call = (method, args) => gate.call(() => original(method, args));
          return core;
        },
        onStatus: text => {
          onStatus(text);
          if (text.startsWith('CONNECTED:')) { connected = true; resolveReady(); onConnected(profile.device); }
          if (text.startsWith('DISCONNECTED:')) { connected = false; if (!stopping) refreshAfterDisconnect(); }
        },
        onControl: async (method, args) => {
          if (method === '__uc_update_drain') return gate.drain(10000);
          if (method === '__uc_update_resume') { gate.resume(); return {resumed: true}; }
          return onControl(method, args);
        }});
      task.catch(rejectReady);
      task.then(() => { connected = false; if (!stopping) rejectReady(Error('Owned agent ended unexpectedly')); }, () => { connected = false; });
      timer = setInterval(() => { if (!stopping && !refreshing) refreshAfterDisconnect(); }, 3600000);
      timer.unref();
    },
    health: () => ({healthy: connected, connected, role: 'agent'}),
    activate: async () => { gate.resume(); },
    drain: () => gate.drain(10000),
    stop() {
      if (stopTask) return stopTask;
      stopping = true; gate.close(); connected = false; clearInterval(timer); life.abort();
      stopTask = Promise.allSettled([task, refreshing].filter(Boolean)).then(results => {
        signal.removeEventListener('abort', stopSignal);
        if (task && results[0]?.status === 'rejected') throw results[0].reason;
      });
      return stopTask;
    }
  };
}
