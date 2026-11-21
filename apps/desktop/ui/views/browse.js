// Classes, methods, smali and cross-references. Every fact on this page is an engine answer; the page
// only chooses which question to ask next.
import { h, replace } from '../lib/dom.js';
import { containsPattern, like, quote } from '../lib/sql.js';
import { number } from '../lib/format.js';
import { previousOffset } from '../lib/pager.js';
import { directiveLength, tokenizeLine } from '../lib/smali.js';
import { rowObject } from '../lib/cells.js';
import { call, currentDataset, toast } from '../state.js';
import { errorBox, pagerBar, resultTable } from '../widgets.js';

const CLASS_PAGE = 100;
const SMALI_LINES = 300;
let searchBox;
let classHolder;
let methodHolder;
let smaliHolder;
let xrefHolder;
let modeSelect;
let selectedClass = null;
let method = null; // {descriptor, file_id, method_idx, offsets: [byte offsets of the pages shown]}

function needDataset(into) {
  if (currentDataset()) return true;
  replace(into, errorBox({ code: 'UNKNOWN_HANDLE', message: '先在“输入与来源”页打开一个输入集。' }));
  return false;
}

async function searchClasses(offset = 0) {
  if (!needDataset(classHolder)) return;
  const text = searchBox.value.trim();
  const where = text ? ` WHERE ${like('descriptor', containsPattern(text))}` : '';
  const sql = `SELECT descriptor, file_id, access_flags FROM classes${where} ORDER BY descriptor, file_id`;
  const reply = await call('query', { sql: [sql], limit: CLASS_PAGE, offset }, { label: '搜索类', deadline_ms: 120_000 });
  if (!reply.ok) return replace(classHolder, errorBox(reply.data.error));
  const st = reply.data.statements[0];
  replace(classHolder,
    resultTable(st, {
      onRow: (row, i, tr) => {
        classHolder.querySelectorAll('tr.selected').forEach((r) => r.classList.remove('selected'));
        tr.classList.add('selected');
        selectClass(st.rows[i][0].value, Number(st.rows[i][1].value));
      },
    }),
    pagerBar({ offset: st.offset ?? offset, limit: CLASS_PAGE, rows: st.rows.length, nextOffset: st.next_offset, truncated: st.truncated },
      { onPrev: () => searchClasses(previousOffset(offset, CLASS_PAGE)), onNext: () => searchClasses(st.next_offset) }));
}

async function selectClass(descriptor, fileId) {
  selectedClass = { descriptor, fileId };
  replace(methodHolder, h('p', { class: 'note' }, `读取 ${descriptor} 的方法…`));
  const sql = 'SELECT file_id, method_idx, name, descriptor, access_flags, opcode_count FROM methods '
    + `WHERE class_descriptor = ${quote(descriptor)} ORDER BY file_id, method_idx`;
  const reply = await call('query', { sql: [sql], limit: 1000 }, { label: `方法：${descriptor}`, deadline_ms: 120_000 });
  if (!reply.ok) return replace(methodHolder, errorBox(reply.data.error));
  const st = reply.data.statements[0];
  replace(methodHolder,
    h('div', { class: 'row' }, h('strong', {}, descriptor), h('span', { class: 'note' }, `DEX #${fileId}；${st.rows.length} 个方法${st.next_offset === null ? '（完整）' : '（未完整加载）'}`)),
    h('p', { class: 'note' }, 'access_flags 为 ∅ 的行是只在这个 DEX 里被引用、没有在这里定义的方法（引擎的 methods 关系同时列出定义与引用）。'),
    resultTable(st, {
      onRow: (row) => {
        const m = rowObject(st.columns, row);
        openMethod({ descriptor: m.descriptor, file_id: Number(m.file_id), method_idx: Number(m.method_idx) });
      },
    }));
}

async function openMethod(target, offset = 0, trail = []) {
  method = { ...target, trail };
  replace(smaliHolder, h('p', { class: 'note' }, `读取 smali：${target.descriptor}…`));
  const mode = modeSelect.value;
  const args = { file_id: target.file_id, method_idx: target.method_idx, mode, max_lines: SMALI_LINES };
  if (offset) args.offset = offset;
  const reply = await call('decode', args, { label: `smali：${target.descriptor}`, deadline_ms: 120_000 });
  if (!reply.ok) return replace(smaliHolder, errorBox(reply.data.error));
  const m = reply.data.methods[0];
  const lines = String(m.smali ?? '').split('\n');
  if (lines[lines.length - 1] === '') lines.pop();
  const body = h('pre', { class: 'smali', id: 'smali-text', dataset: { descriptor: target.descriptor } });
  for (const line of lines) {
    const dirLen = directiveLength(line);
    if (dirLen) body.append(h('span', { class: 'dir' }, line.slice(0, dirLen)));
    for (const token of tokenizeLine(dirLen ? line.slice(dirLen) : line)) body.append(tokenNode(token));
    body.append('\n');
  }
  const more = m.next_offset !== null && m.next_offset !== undefined;
  replace(smaliHolder,
    h('div', { class: 'row' },
      h('strong', {}, m.declaration ?? target.descriptor),
      h('span', { class: 'note' }, `DEX #${m.file_id}，method_idx ${m.method_idx}，${m.registers ?? '?'} 个寄存器，${m.try_count ?? 0} 个 try，${number(m.code_units ?? 0)} 个代码单元`)),
    h('div', { class: 'row' },
      h('button', { type: 'button', id: 'smali-prev', disabled: trail.length === 0, onclick: () => {
        const previous = trail[trail.length - 1];
        openMethod(target, previous, trail.slice(0, -1));
      } }, '上一页'),
      h('button', { type: 'button', id: 'smali-next', disabled: !more, onclick: () => openMethod(target, m.next_offset, [...trail, offset]) }, '下一页'),
      h('span', { class: more ? 'state-warn' : 'state-ok', id: 'smali-state' },
        more ? `已显示第 ${m.start_line ?? 0}–${m.end_line ?? '?'} 行（共 ${m.total_lines ?? '?'} 行）；后面还有未加载的部分`
          : `已显示到末尾（共 ${m.total_lines ?? lines.length} 行，${number(m.total_bytes ?? 0)} 字节）`),
      m.omitted && Object.keys(m.omitted).length
        ? h('span', { class: 'note' }, `文本省略：${JSON.stringify(m.omitted)}`) : null),
    body);
  xrefHolder.dataset.ready = 'true';
  replace(xrefHolder, xrefPanel(target));
}

function tokenNode(token) {
  switch (token.kind) {
    case 'method':
    case 'field':
    case 'type':
      return h('span', {
        class: 'ref', title: token.desc, dataset: { kind: token.kind, desc: token.desc },
        onclick: () => follow(token),
      }, token.text);
    case 'label': return h('span', { class: 'lbl' }, token.text);
    case 'str': return h('span', { class: 'str' }, token.text);
    default: return document.createTextNode(token.text);
  }
}

async function follow(token) {
  if (token.kind === 'method') return navigateMethod(token.desc);
  const owner = token.desc.slice(0, token.desc.indexOf(';') + 1);
  const reply = await call('query', { sql: [`SELECT descriptor, file_id FROM classes WHERE descriptor = ${quote(owner)} ORDER BY file_id`], limit: 5 }, { label: `查找类 ${owner}` });
  if (!reply.ok) return toast(reply.data.error.message, 'bad');
  const rows = reply.data.statements[0].rows;
  if (!rows.length) return toast(`${owner} 不在已打开的输入里（外部引用，没有可显示的定义）`);
  return selectClass(rows[0][0].value, Number(rows[0][1].value));
}

async function navigateMethod(desc) {
  const reply = await call('query', {
    // only definitions: a row with no access flags merely references the method from that DEX and has no code
    sql: [`SELECT file_id, method_idx FROM methods WHERE descriptor = ${quote(desc)} AND access_flags IS NOT NULL ORDER BY file_id, method_idx`], limit: 10,
  }, { label: `查找方法 ${desc}`, deadline_ms: 120_000 });
  if (!reply.ok) return toast(reply.data.error.message, 'bad');
  const rows = reply.data.statements[0].rows;
  if (!rows.length) return toast(`${desc} 在已打开的输入里没有定义（外部引用，没有可显示的代码）`);
  const sameFile = rows.find((r) => method && Number(r[0].value) === method.file_id) ?? rows[0];
  if (rows.length > 1) toast(`${desc} 在 ${rows.length} 个 DEX 里有定义，显示 DEX #${sameFile[0].value} 的那个`);
  return openMethod({ descriptor: desc, file_id: Number(sameFile[0].value), method_idx: Number(sameFile[1].value) });
}

function xrefPanel(target) {
  const callers = h('div', { id: 'xref-callers' }, h('p', { class: 'note' }, '尚未加载。'));
  const callees = h('div', { id: 'xref-callees' }, h('p', { class: 'note' }, '尚未加载。'));
  return h('div', {},
    h('h3', {}, '交叉引用'),
    h('p', { class: 'note' }, '只包含 DEX 里显式编码的调用点。反射、动态加载和 invoke-custom 的实际目标是未知的，不在这里，也不能理解成“没有人调用”。'),
    h('div', { class: 'xref' },
      h('div', {},
        h('div', { class: 'row' }, h('strong', {}, '调用者'),
          h('button', { type: 'button', id: 'load-callers', onclick: () => loadCallers(target, callers) }, '加载')),
        callers),
      h('div', {},
        h('div', { class: 'row' }, h('strong', {}, '被调用'),
          h('button', { type: 'button', id: 'load-callees', onclick: () => loadCallees(target, callees) }, '加载')),
        callees)));
}

async function loadCallers(target, holder) {
  replace(holder, h('p', { class: 'note' }, '查找调用者…'));
  const sql = `SELECT DISTINCT method, file_id, method_idx FROM method_calls WHERE callee = ${quote(target.descriptor)} ORDER BY method, file_id`;
  const reply = await call('query', { sql: [sql], limit: 200 }, { label: `调用者：${target.descriptor}`, deadline_ms: 180_000 });
  if (!reply.ok) return replace(holder, errorBox(reply.data.error));
  const st = reply.data.statements[0];
  replace(holder, h('p', { class: st.next_offset === null ? 'state-ok' : 'state-warn' },
    st.rows.length === 0 ? '没有显式编码的调用点指向它（引擎确认结果已完整）'
      : `${st.rows.length} 个调用者${st.next_offset === null ? '（完整）' : '，后面还有未加载的'}`),
  st.rows.length ? resultTable(st, { onRow: (row) => openMethod({ descriptor: row[0].value, file_id: Number(row[1].value), method_idx: Number(row[2].value) }) }) : null);
}

async function loadCallees(target, holder) {
  replace(holder, h('p', { class: 'note' }, '查找被调用的方法…'));
  const sql = `SELECT DISTINCT callee FROM method_calls WHERE file_id = ${target.file_id} AND method_idx = ${target.method_idx} ORDER BY callee`;
  const reply = await call('query', { sql: [sql], limit: 200 }, { label: `被调用：${target.descriptor}`, deadline_ms: 180_000 });
  if (!reply.ok) return replace(holder, errorBox(reply.data.error));
  const st = reply.data.statements[0];
  replace(holder, h('p', { class: st.next_offset === null ? 'state-ok' : 'state-warn' },
    st.rows.length === 0 ? '这个方法没有显式编码的调用（引擎确认结果已完整）'
      : `${st.rows.length} 个被调用的方法${st.next_offset === null ? '（完整）' : '，后面还有未加载的'}`),
  st.rows.length ? resultTable(st, { onRow: (row) => navigateMethod(row[0].value) }) : null);
}

export const view = {
  id: 'browse',
  title: '类与 Smali',
  needs: ['query', 'decode'],
  build(root) {
    searchBox = h('input', { type: 'text', id: 'class-search', class: 'grow', placeholder: '类名包含…（例如 newpipe/App）' });
    searchBox.addEventListener('keydown', (event) => { if (event.key === 'Enter') searchClasses(0); });
    modeSelect = h('select', { id: 'smali-mode', 'aria-label': 'smali 模式' },
      h('option', { value: 'smali' }, 'smali 全文'),
      h('option', { value: 'context' }, '带行号的骨架'),
      h('option', { value: 'summary' }, '仅元数据'));
    modeSelect.addEventListener('change', () => { if (method) openMethod(method); });
    classHolder = h('div', { id: 'class-list' }, h('p', { class: 'note' }, '搜索类名，或直接点搜索列出全部。'));
    methodHolder = h('div', { id: 'method-list' }, h('p', { class: 'note' }, '选择一个类。'));
    smaliHolder = h('div', { id: 'smali-holder' }, h('p', { class: 'note' }, '选择一个方法。'));
    xrefHolder = h('div', { id: 'xref-holder' });
    root.append(
      h('h2', {}, '类与 Smali'),
      h('div', { class: 'split' },
        h('div', { class: 'panel' },
          h('div', { class: 'row' }, searchBox, h('button', { type: 'button', id: 'search-classes', class: 'primary', onclick: () => searchClasses(0) }, '搜索')),
          classHolder),
        h('div', { class: 'panel' }, methodHolder)),
      h('div', { class: 'panel' },
        h('div', { class: 'row' }, h('strong', {}, 'Smali'), modeSelect),
        smaliHolder),
      h('div', { class: 'panel' }, xrefHolder));
  },
  show() {},
};
