// Start-up, navigation, and the status bar. Which views are available is decided by what the engine
// lists (tools/list), not by this file.
import { h, replace } from './lib/dom.js';
import { millis } from './lib/format.js';
import { baseName } from './lib/format.js';
import { viewAvailability } from './lib/availability.js';
import { cancelCurrent, currentDataset, loadInfo, onChange, refresh, startProgressListener, state, toast } from './state.js';
import { view as inputs } from './views/inputs.js';
import { view as query } from './views/query.js';
import { view as browse } from './views/browse.js';
import { view as manifest } from './views/manifest.js';
import { view as diff } from './views/diff.js';
import { view as engine } from './views/engine.js';

const views = [inputs, query, browse, manifest, diff, engine];
const panes = new Map();
let active = null;

function renderNav() {
  const nav = document.getElementById('nav');
  replace(nav, views.map((view) => {
    const { available, missing } = viewAvailability(state.info, state.tools, view.needs);
    const disabled = !available;
    return h('button', {
      type: 'button',
      dataset: { view: view.id },
      'aria-current': active === view.id ? 'page' : undefined,
      disabled,
      title: disabled ? `引擎没有列出：${missing.join(', ')}` : view.title,
      onclick: () => select(view.id),
    }, view.title);
  }));
}

async function select(id) {
  active = id;
  for (const [key, pane] of panes) pane.hidden = key !== id;
  renderNav();
  await views.find((v) => v.id === id).show();
}

function renderTop() {
  const chip = document.getElementById('engine-chip');
  const started = state.info?.start;
  if (!state.info) {
    chip.textContent = '引擎：检测中';
    chip.dataset.state = 'unknown';
  } else if (started && !started.ok) {
    chip.textContent = '引擎：无法启动';
    chip.dataset.state = 'bad';
  } else {
    chip.textContent = `引擎：${state.running ? '运行中' : '待命'} · ${state.info.version?.engine_version ?? '?'}`;
    chip.dataset.state = 'ok';
  }
  const select = document.getElementById('current-set');
  replace(select, state.datasets.length
    ? state.datasets.map((d) => h('option', { value: d.handle, selected: d.handle === state.current },
      `#${d.handle} ${d.inputs.map(baseName).join(' + ')}${d.live ? '' : '（待重新打开）'}`))
    : h('option', { value: '' }, '（未打开输入）'));
}

let ticker = null;
function renderStatus() {
  const text = document.getElementById('busy-text');
  const cancel = document.getElementById('cancel-button');
  const progress = document.getElementById('busy-progress');
  if (state.call) {
    const elapsed = performance.now() - state.call.since;
    text.textContent = `执行中：${state.call.label} · ${millis(elapsed)}`;
    text.className = 'busy';
    cancel.hidden = false;
    if (state.progress && state.progress.total > 0) {
      progress.hidden = false;
      progress.max = state.progress.total;
      progress.value = state.progress.done;
    } else {
      progress.hidden = true;
    }
    if (!ticker) ticker = setInterval(renderStatus, 250);
  } else {
    text.textContent = '空闲';
    text.className = 'idle';
    cancel.hidden = true;
    progress.hidden = true;
    if (ticker) {
      clearInterval(ticker);
      ticker = null;
    }
  }
  const dataset = currentDataset();
  document.getElementById('status-note').textContent = dataset
    ? `当前输入集 #${dataset.handle}${dataset.live ? '' : '（引擎需要重新打开它）'}`
    : '没有打开的输入集';
}

async function main() {
  const main = document.getElementById('main');
  for (const view of views) {
    const pane = h('section', { class: 'view', id: `view-${view.id}`, hidden: true });
    view.build(pane);
    main.append(pane);
    panes.set(view.id, pane);
  }
  document.getElementById('cancel-button').addEventListener('click', async () => {
    const asked = await cancelCurrent();
    if (!asked) toast('没有正在执行的请求可取消');
  });
  document.getElementById('current-set').addEventListener('change', (event) => {
    state.current = event.target.value === '' ? null : Number(event.target.value);
    renderTop();
    renderStatus();
  });
  onChange(() => {
    renderTop();
    renderStatus();
    renderNav();
  });
  await startProgressListener();
  renderNav();
  await loadInfo();
  await refresh();
  renderNav();
  // with no engine there is nothing to open: show why, on the page that explains it
  await select(state.info?.start?.ok === false ? 'engine' : 'inputs');
}

main().catch((error) => {
  console.error(error);
  toast(`工作台启动失败：${error?.message ?? error}`, 'bad');
});
