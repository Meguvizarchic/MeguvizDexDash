// Opening inputs, and what the engine says about their provenance and coverage.
import { h, replace } from '../lib/dom.js';
import { bytes, baseName, millis, number, shortId } from '../lib/format.js';
import { invoke } from '../lib/bridge.js';
import { call, closeInputs, openInputs, refresh, state, toast, notify } from '../state.js';
import { errorBox, kv, pill, resultTable } from '../widgets.js';

const SOURCES_SQL = 'SELECT file_id, entry_name, dex_version, byte_len, checksum, signature_hex, string_count, type_count, '
  + 'method_count, class_count FROM dex_files ORDER BY file_id';

let root;
let pathsBox;
let errorHolder;
let listHolder;
const sources = new Map(); // handle -> {reply}

async function open() {
  const paths = pathsBox.value.split(/\r?\n/u).map((p) => p.trim()).filter(Boolean);
  replace(errorHolder);
  if (!paths.length) {
    replace(errorHolder, errorBox({ code: 'INVALID_ARGUMENT', message: '先给出至少一个输入路径。' }));
    return;
  }
  const reply = await openInputs(paths);
  if (!reply.ok) {
    replace(errorHolder, errorBox(reply.data.error));
    return;
  }
  state.current = reply.data.handle;
  pathsBox.value = '';
  toast(`已打开输入集 #${reply.data.handle}（${millis(reply.elapsed_ms)}）`);
  await loadSources(reply.data.handle);
  render();
}

async function pick() {
  const picked = await invoke('pick_inputs');
  if (picked.length) pathsBox.value = [pathsBox.value.trim(), ...picked].filter(Boolean).join('\n');
}

async function loadSources(handle) {
  const reply = await call('query', { sql: [SOURCES_SQL], limit: 200 }, { handle, label: '读取 DEX 来源' });
  sources.set(handle, reply);
}

function datasetCard(dataset) {
  const s = dataset.summary ?? {};
  const manifest = s.snapshot_manifest ?? {};
  const isCurrent = dataset.handle === state.current;
  const diagnostics = Array.isArray(s.diagnostics) ? s.diagnostics : [];
  const members = sources.get(dataset.handle);
  return h('section', { class: 'panel dataset', dataset: { handle: dataset.handle, current: String(isCurrent) } },
    h('div', { class: 'row' },
      h('strong', {}, `输入集 #${dataset.handle}`),
      dataset.live ? pill('引擎已打开', 'ok') : pill('待重新打开', 'warn'),
      isCurrent ? pill('当前', 'ok') : null,
      pill(s.profile ? `${s.profile}（未准入）` : '未准入', 'warn'),
      h('span', { class: 'spacer' }),
      h('button', { type: 'button', onclick: () => { state.current = dataset.handle; notify(); render(); }, disabled: isCurrent }, '设为当前'),
      h('button', { type: 'button', onclick: async () => { await loadSources(dataset.handle); render(); } }, '刷新来源'),
      h('button', { type: 'button', class: 'danger', onclick: async () => {
        const reply = await closeInputs(dataset.handle);
        if (!reply.ok) toast(reply.data.error.message, 'bad');
        sources.delete(dataset.handle);
        render();
      } }, '关闭')),
    h('h3', {}, '输入'),
    h('ul', {}, dataset.inputs.map((input) => h('li', { title: input }, baseName(input), h('span', { class: 'note' }, `  ${input}`)))),
    h('h3', {}, '快照与覆盖'),
    kv([
      ['snapshot_id', shortId(s.snapshot_id, 28)],
      ['scope_id', shortId(s.scope_id, 28)],
      ['输入字节', s.input_bytes !== undefined ? `${number(s.input_bytes)}（${bytes(s.input_bytes)}）` : null],
      ['DEX 个数', s.dex_count],
      ['含 DEX', s.has_dex === undefined ? null : (s.has_dex ? '是' : '否（只有归档成员，查询与 decode 会明确拒绝）')],
      ['SQL 方言', s.sql_dialect],
      ['准备耗时', s.prepare_ms !== undefined ? millis(s.prepare_ms) : null],
    ]),
    h('h3', {}, '来源（每个输入的内容身份）'),
    h('div', { class: 'scroll' },
      h('table', { class: 'grid' },
        h('thead', {}, h('tr', {}, ['序号', '类型', '字节', 'content_id (sha256)', 'occurrence_id'].map((t) => h('th', {}, t)))),
        h('tbody', {}, (manifest.sources ?? []).map((src) => h('tr', {},
          h('td', { class: 'num' }, src.input_ordinal),
          h('td', {}, src.input_kind),
          h('td', { class: 'num' }, number(src.byte_length)),
          h('td', { class: 'text', title: src.content_id }, src.content_id),
          h('td', { class: 'text', title: src.occurrence_id }, shortId(src.occurrence_id, 36))))))),
    h('p', { class: 'note' }, `捕获策略 ${manifest.capture_policy ?? '—'}；${manifest.scope ?? ''}`),
    h('h3', {}, 'DEX 成员'),
    diagnostics.length
      ? h('ul', { class: 'state-warn' }, diagnostics.map((d) => h('li', {}, typeof d === 'string' ? d : JSON.stringify(d))))
      : h('p', { class: 'note' }, '引擎没有报告诊断信息。'),
    !members ? h('p', { class: 'note' }, '尚未读取。')
      : !members.ok ? errorBox(members.data.error)
        : membersTable(members.data.statements[0]));
}

function membersTable(statement) {
  if (!statement.rows.length) return h('p', { class: 'note' }, '这个输入集没有 DEX 成员（引擎确认结果已完整）。');
  return resultTable(statement);
}

function render() {
  replace(listHolder, state.datasets.length
    ? state.datasets.map(datasetCard)
    : h('p', { class: 'note' }, '还没有打开任何输入。文件只在本机读取，不会上传。'));
}

export const view = {
  id: 'inputs',
  title: '输入与来源',
  needs: ['open_dataset'],
  build(el) {
    root = el;
    pathsBox = h('textarea', {
      id: 'input-paths',
      rows: 3,
      placeholder: '每行一个路径：DEX / APK / JAR / ZIP',
      'aria-label': '输入路径',
    });
    errorHolder = h('div', { id: 'open-error' });
    listHolder = h('div', { id: 'dataset-list' });
    root.append(
      h('h2', {}, '输入与来源'),
      h('div', { class: 'panel' },
        pathsBox,
        h('div', { class: 'row' },
          h('button', { type: 'button', id: 'pick-inputs', onclick: pick }, '选择文件…'),
          h('button', { type: 'button', id: 'open-inputs', class: 'primary', onclick: open }, '打开'),
          h('span', { class: 'note' }, '只在本机读取；不上传任何文件。多个输入打开成一个输入集时，查询看到的是它们合在一起的快照。')),
        errorHolder),
      listHolder);
  },
  async show() {
    await refresh();
    render();
  },
};
