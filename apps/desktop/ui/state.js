// The window's one shared state, and the calls every view makes through it. A view never talks to the
// shell directly: that way the busy bar, the cancel button and error reporting work for all of them.
import { invoke, listen, newCallId } from './lib/bridge.js';
import { adoptInfo } from './lib/availability.js';

export const state = {
  info: null,
  tools: [],
  datasets: [],
  current: null,
  running: false,
  settings: null,
  call: null,
  progress: null,
};

// every call the window has started and not yet seen finish, by id. `state.call` is the oldest of them:
// the shell serves one request at a time, so that is the one holding the engine.
const calls = new Map();
function begin(id, label) {
  calls.set(id, { id, label, since: performance.now() });
  state.call = calls.values().next().value ?? null;
  notify();
}
function end(id) {
  calls.delete(id);
  state.call = calls.values().next().value ?? null;
}

export function isBusy() {
  return calls.size > 0;
}

const subscribers = new Set();
export function onChange(fn) {
  subscribers.add(fn);
  return () => subscribers.delete(fn);
}
export function notify() {
  for (const fn of subscribers) fn(state);
}

export function currentDataset() {
  return state.datasets.find((d) => d.handle === state.current) ?? null;
}

export async function refresh() {
  const s = await invoke('engine_state');
  state.running = s.running;
  state.datasets = s.datasets;
  state.settings = s.settings;
  if (!state.datasets.some((d) => d.handle === state.current)) {
    state.current = state.datasets.length ? state.datasets[state.datasets.length - 1].handle : null;
  }
  notify();
}

export async function loadInfo() {
  const callId = newCallId('info');
  begin(callId, '启动引擎');
  try {
    state.info = adoptInfo(state.info, await invoke('engine_info', { callId }));
    state.tools = state.info.tools ?? [];
  } finally {
    end(callId);
  }
  await refresh();
  return state.info;
}

/**
 * Call one engine tool for the current (or given) input set. Resolves to the shell's reply
 * {ok, data, elapsed_ms, started_engine}; a failure is data.error, never a thrown exception.
 */
export async function call(tool, args = {}, options = {}) {
  const handle = options.handle === undefined ? state.current : options.handle;
  const callId = newCallId(tool);
  begin(callId, options.label ?? tool);
  try {
    return await invoke('engine_call', {
      request: { call_id: callId, tool, handle, args, deadline_ms: options.deadline_ms ?? null },
    });
  } finally {
    end(callId);
    await refresh();
  }
}

export async function openInputs(paths) {
  const callId = newCallId('open');
  begin(callId, '打开输入');
  try {
    return await invoke('open_inputs', { callId, paths });
  } finally {
    end(callId);
    await refresh();
  }
}

export async function closeInputs(handle) {
  const callId = newCallId('close');
  try {
    return await invoke('close_inputs', { callId, handle });
  } finally {
    await refresh();
  }
}

export async function exportQuery(request, label = '导出') {
  const callId = newCallId('export');
  state.progress = { done: 0, total: 0 };
  begin(callId, label);
  try {
    return await invoke('export_query', { request: { ...request, call_id: callId } });
  } finally {
    end(callId);
    state.progress = null;
    await refresh();
  }
}

export async function runDiff(request) {
  const callId = newCallId('diff');
  state.progress = { done: 0, total: 0 };
  begin(callId, '比较两个输入集');
  try {
    return await invoke('diff_run', { request: { ...request, call_id: callId } });
  } finally {
    end(callId);
    state.progress = null;
    await refresh();
  }
}

export function diffPage(query) {
  return invoke('diff_page', { query });
}

export async function diffSmali(request) {
  const callId = newCallId('smali-diff');
  begin(callId, 'smali 对比');
  try {
    return await invoke('diff_smali', { request: { ...request, call_id: callId } });
  } finally {
    end(callId);
    await refresh();
  }
}

/** Cancel whatever the shell says is holding the engine (not whatever this window last started). */
export async function cancelCurrent() {
  const shell = await invoke('engine_state');
  if (!shell.busy) return false;
  return invoke('engine_cancel', { callId: shell.busy.call_id });
}

export async function startProgressListener() {
  await listen('progress', (payload) => {
    if (state.call && payload.call_id === state.call.id) {
      state.progress = { done: payload.done, total: payload.total };
      notify();
    }
  });
}

export function toast(message, kind = 'info') {
  const holder = document.getElementById('toasts');
  const el = document.createElement('div');
  el.className = `toast ${kind === 'bad' ? 'bad' : ''}`;
  el.textContent = message;
  holder.append(el);
  setTimeout(() => el.remove(), kind === 'bad' ? 9000 : 4500);
}
