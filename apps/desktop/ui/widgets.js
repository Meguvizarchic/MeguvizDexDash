// Pieces several views share: an error, a typed result table, a key/value list, a pager.
import { h } from './lib/dom.js';
import { cellKind, cellTitle, shortText } from './lib/cells.js';
import { describeError } from './lib/errors.js';
import { describePage } from './lib/pager.js';

export function errorBox(error) {
  const e = describeError(error);
  return h('div', { class: 'error-box', role: 'alert', dataset: { code: e.code } },
    h('div', {}, h('span', { class: 'code' }, e.code), ' ', e.message),
    e.hint ? h('div', { class: 'note' }, e.hint) : null,
    h('details', {},
      h('summary', {}, '详情'),
      h('pre', {}, JSON.stringify(e.details, null, 2))));
}

/** A table for one result statement: columns with their types, typed cells, NULL shown as ∅. */
export function resultTable(statement, { onRow, selected } = {}) {
  const columns = statement.columns ?? [];
  const head = h('tr', {}, columns.map((c) =>
    h('th', { title: `${c.name}: ${c.data_type}${c.nullable ? ', nullable' : ''}` }, c.name, ' ',
      h('span', { class: 'type' }, c.data_type))));
  const body = (statement.rows ?? []).map((row, index) => {
    const tr = h('tr', { class: onRow ? 'pick' : '', dataset: { row: index } },
      row.map((cell) => h('td', { class: cellKind(cell), title: cellTitle(cell) }, shortText(cell))));
    if (selected === index) tr.classList.add('selected');
    if (onRow) tr.addEventListener('click', () => onRow(row, index, tr));
    return tr;
  });
  return h('div', { class: 'scroll' }, h('table', { class: 'grid' }, h('thead', {}, head), h('tbody', {}, body)));
}

export function kv(pairs) {
  const dl = h('dl', { class: 'kv' });
  for (const [key, value] of pairs) {
    if (value === undefined || value === null || value === '') continue;
    dl.append(h('dt', {}, key), h('dd', {}, value));
  }
  return dl;
}

export function pill(text, kind = '') {
  return h('span', { class: `pill ${kind}` }, text);
}

/** The line under a paged result and its previous/next buttons. */
export function pagerBar({ offset, limit, rows, nextOffset, truncated }, { onPrev, onNext, busy }) {
  const info = describePage({ offset, rows, nextOffset, truncated });
  return h('div', { class: 'row pager' },
    h('button', { type: 'button', onclick: onPrev, disabled: busy || offset <= 0, dataset: { act: 'prev' } }, '上一页'),
    h('button', { type: 'button', onclick: onNext, disabled: busy || (nextOffset === null || nextOffset === undefined), dataset: { act: 'next' } }, '下一页'),
    h('span', { class: info.complete ? 'state-ok' : 'state-warn', dataset: { complete: String(info.complete) } }, info.text),
    h('span', { class: 'note' }, `每页 ${limit} 行`));
}
