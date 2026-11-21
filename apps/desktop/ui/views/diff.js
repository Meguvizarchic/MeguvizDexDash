// Comparing two input sets. Both sides are loaded completely or the comparison fails; the list says
// what each status can and cannot prove, and one method pair can be compared exactly, line by line.
import { h, replace } from '../lib/dom.js';
import { STATUS_LABEL, isAgreement, statusLabel, withContext } from '../lib/diff.js';
import { baseName, number, shortId } from '../lib/format.js';
import { diffPage, diffSmali, runDiff, state } from '../state.js';
import { errorBox, kv, pill } from '../widgets.js';

const PAGE = 100;
let sideA;
let sideB;
let prefixBox;
let resultHolder;
let listHolder;
let detailHolder;
let diffId = null;
let filter = { kind: '', status: 'differences', contains: '' };

function datasetOptions(select, selected) {
  replace(select, state.datasets.map((d) => h('option', { value: d.handle, selected: d.handle === selected },
    `#${d.handle} ${d.inputs.map(baseName).join(' + ')}`)));
}

function sidePanel(label, side) {
  return h('div', { class: 'panel', dataset: { side: label } },
    h('div', { class: 'row' }, h('strong', {}, `输入集 ${label}`), pill(`#${side.handle}`), pill('已完整加载', 'ok')),
    kv([
      ['已加载', `${number(side.classes_loaded)} 个类、${number(side.methods_loaded)} 个方法`],
      ['snapshot', side.snapshot_ids.map((id) => shortId(id, 30)).join(', ')],
      ['内容 sha256', side.content_ids.join(', ')],
      ['DEX 成员', Object.entries(side.dex_members).map(([id, name]) => `#${id} ${name}`).join('，')],
    ]));
}

function summaryPanel(summary) {
  const row = (title, counts) => h('tr', {}, h('th', {}, title),
    h('td', {}, Object.entries(counts).map(([status, n]) => h('span', { class: isAgreement(status) ? 'pill ok' : 'pill warn', title: status }, `${statusLabel(status)} ${number(n)}`)).flatMap((e) => [e, ' '])));
  return h('div', { class: 'panel', id: 'diff-summary' },
    h('div', { class: 'row' }, h('strong', {}, `差异 ${number(summary.differences)} 项`), h('span', { class: 'note' }, `共 ${number(summary.entries)} 个条目（两边都已完整加载）`)),
    h('table', { class: 'grid' }, h('tbody', {}, row('类', summary.classes), row('方法', summary.methods))),
    h('p', { class: 'note' }, '方法按引擎给出的操作码序列比较。“操作码序列相同”不等于方法相同：常量、引用和跳转目标没有比较，要证明相同请点开一对方法做 smali 对比。重复定义按出现次数保留，没有 code item（抽象/native）与空方法体分开。'));
}

async function loadList(offset = 0) {
  if (diffId === null) return;
  const reply = await diffPage({ diff_id: diffId, kind: filter.kind, status: filter.status, contains: filter.contains, offset, limit: PAGE });
  if (!reply.ok) return replace(listHolder, errorBox(reply.data.error));
  const d = reply.data;
  replace(listHolder,
    h('div', { class: 'scroll' },
      h('table', { class: 'grid', id: 'diff-table' },
        h('thead', {}, h('tr', {}, ['', '键', '状态', 'A', 'B', '说明'].map((t) => h('th', {}, t)))),
        h('tbody', {}, d.entries.map((e) => h('tr', {
          class: 'pick', dataset: { key: e.key, status: e.status },
          onclick: () => showEntry(e),
        },
        h('td', {}, e.kind === 'class' ? '类' : '方法'),
        h('td', { class: 'text', title: e.key }, e.key),
        h('td', {}, h('span', { class: isAgreement(e.status) ? 'pill ok' : 'pill warn' }, statusLabel(e.status))),
        h('td', { class: 'num' }, e.a.length), h('td', { class: 'num' }, e.b.length),
        h('td', {}, e.notes.join('；'))))))),
    h('div', { class: 'row pager' },
      h('button', { type: 'button', disabled: offset === 0, onclick: () => loadList(Math.max(0, offset - PAGE)) }, '上一页'),
      h('button', { type: 'button', disabled: d.next_offset === null, onclick: () => loadList(d.next_offset) }, '下一页'),
      h('span', { class: d.next_offset === null ? 'state-ok' : 'state-warn' },
        d.total === 0 ? '没有符合条件的条目（两边已完整加载，这是确认过的空）'
          : `第 ${offset + 1}–${offset + d.entries.length} 项，共 ${number(d.total)} 项${d.next_offset === null ? '，已是最后一页' : '，后面还有未显示的项'}`)));
}

function occurrences(title, list) {
  return h('div', {}, h('strong', {}, title),
    list.length ? h('ul', {}, list.map((o) => h('li', {}, `DEX #${o.file_id}（${o.entry ?? '?'}）· 索引 ${o.index} · ${JSON.stringify(o.detail)}`)))
      : h('p', { class: 'note' }, '没有'));
}

async function showEntry(entry) {
  const canCompare = entry.kind === 'method' && entry.a.length > 0 && entry.b.length > 0;
  replace(detailHolder, h('div', { class: 'panel', id: 'diff-detail' },
    h('div', { class: 'row' }, h('strong', {}, entry.key), pill(statusLabel(entry.status), isAgreement(entry.status) ? 'ok' : 'warn')),
    entry.notes.length ? h('p', { class: 'note' }, entry.notes.join('；')) : null,
    h('div', { class: 'xref' }, occurrences('A', entry.a), occurrences('B', entry.b)),
    canCompare
      ? h('div', { class: 'row' },
        h('button', { type: 'button', id: 'compare-smali', class: 'primary', onclick: () => compareSmali(entry) }, '对比 smali（精确）'),
        entry.a.length > 1 || entry.b.length > 1 ? h('span', { class: 'note' }, '有多个出现位置时对比第一个。') : null)
      : null,
    h('div', { id: 'smali-diff' })));
}

async function compareSmali(entry) {
  const holder = document.getElementById('smali-diff');
  replace(holder, h('p', { class: 'note' }, '读取两边的 smali…'));
  const reply = await diffSmali({
    handle_a: Number(sideA.value), file_id_a: entry.a[0].file_id, method_idx_a: entry.a[0].index,
    handle_b: Number(sideB.value), file_id_b: entry.b[0].file_id, method_idx_b: entry.b[0].index,
    deadline_ms: 120_000,
  });
  if (!reply.ok) return replace(holder, errorBox(reply.data.error));
  const d = reply.data;
  if (d.too_different) return replace(holder, h('p', { class: 'state-warn' }, d.note));
  replace(holder,
    h('p', { class: d.identical ? 'state-ok' : 'state-warn', id: 'smali-diff-state' },
      d.identical ? `两边的 smali 完全相同（${number(d.lines_a)} 行）` : `不同：+${d.added} 行，-${d.removed} 行（A ${number(d.lines_a)} 行，B ${number(d.lines_b)} 行）`),
    d.identical ? null : h('pre', { class: 'code' }, withContext(d.lines).map((line) => (line.op === 'gap'
      ? h('div', { class: 'diff-line gap' }, `… ${line.skipped} 行相同 …`)
      : h('div', { class: `diff-line ${line.op === '+' ? 'add' : line.op === '-' ? 'del' : ''}` }, `${line.op} ${line.text}`)))));
}

async function compare() {
  const a = Number(sideA.value);
  const b = Number(sideB.value);
  replace(resultHolder, h('p', { class: 'note' }, '两边都完整加载后才比较…'));
  replace(listHolder);
  replace(detailHolder);
  const reply = await runDiff({ handle_a: a, handle_b: b, prefix: prefixBox.value.trim(), deadline_ms: 180_000 });
  if (!reply.ok) {
    diffId = null;
    return replace(resultHolder, errorBox(reply.data.error));
  }
  diffId = reply.data.diff_id;
  filter = { ...filter, status: 'differences' };
  replace(resultHolder, h('div', { class: 'xref' }, sidePanel('A', reply.data.sides[0]), sidePanel('B', reply.data.sides[1])), summaryPanel(reply.data.summary),
    filterBar());
  await loadList(0);
}

function filterBar() {
  const kind = h('select', { id: 'diff-kind' }, [['', '类和方法'], ['class', '只看类'], ['method', '只看方法']].map(([v, t]) => h('option', { value: v }, t)));
  const status = h('select', { id: 'diff-status' }, [['differences', '所有差异'], ['', '全部条目'], ...Object.entries(STATUS_LABEL).map(([v, t]) => [v, t])].map(([v, t]) => h('option', { value: v, selected: v === filter.status }, t)));
  const contains = h('input', { type: 'text', id: 'diff-contains', placeholder: '键包含…' });
  const apply = () => { filter = { kind: kind.value, status: status.value, contains: contains.value }; loadList(0); };
  return h('div', { class: 'row' }, kind, status, contains, h('button', { type: 'button', id: 'diff-apply', onclick: apply }, '筛选'));
}

export const view = {
  id: 'diff',
  title: '差异',
  needs: ['query', 'decode'],
  build(root) {
    sideA = h('select', { id: 'diff-a', 'aria-label': '输入集 A' });
    sideB = h('select', { id: 'diff-b', 'aria-label': '输入集 B' });
    prefixBox = h('input', { type: 'text', id: 'diff-prefix', class: 'grow', placeholder: '只比较此前缀的类（例如 Lorg/example/；留空为全部）' });
    resultHolder = h('div', { id: 'diff-result' });
    listHolder = h('div', { id: 'diff-list' });
    detailHolder = h('div', { id: 'diff-detail-holder' });
    root.append(
      h('h2', {}, '差异'),
      h('div', { class: 'panel' },
        h('div', { class: 'row' }, h('label', {}, 'A ', sideA), h('label', {}, 'B ', sideB), prefixBox,
          h('button', { type: 'button', id: 'run-diff', class: 'primary', onclick: compare }, '比较')),
        h('p', { class: 'note' }, '两边都要先在“输入与来源”页打开。比较只在两边的类与方法都被完整读完时进行（引擎一次最多分页 10 万行，更大的输入请用类前缀缩小范围）；读不完整会报错，不会给出“没有差异”。')),
      resultHolder, listHolder, detailHolder);
  },
  show() {
    const handles = state.datasets.map((d) => d.handle);
    const a = handles.includes(Number(sideA.value)) ? Number(sideA.value) : handles[handles.length - 2] ?? handles[0];
    const b = handles.includes(Number(sideB.value)) ? Number(sideB.value) : handles[handles.length - 1];
    datasetOptions(sideA, a);
    datasetOptions(sideB, b);
  },
};
