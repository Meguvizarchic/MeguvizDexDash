// Free SQL over the current input set: typed paging, an honest "is this the whole result" line,
// cancel, and a complete export.
import { h, replace } from '../lib/dom.js';
import { hasOrderBy, oneStatement } from '../lib/sql.js';
import { millis, number } from '../lib/format.js';
import { previousOffset } from '../lib/pager.js';
import { invoke } from '../lib/bridge.js';
import { call, currentDataset, exportQuery, isBusy, state, toast } from '../state.js';
import { errorBox, kv, pagerBar, resultTable } from '../widgets.js';

const DEFAULT_SQL = 'SELECT descriptor, access_flags FROM classes ORDER BY descriptor';
let root;
let sqlBox;
let limitSelect;
let resultHolder;
let tablesHolder;
let exportHolder;
let exportPath;
let exportFormat;
let page = { offset: 0, sql: '' };
let tablesLoaded = false;

async function run(offset = 0) {
  const sql = oneStatement(sqlBox.value);
  if (!sql) return;
  if (!currentDataset()) {
    replace(resultHolder, errorBox({ code: 'UNKNOWN_HANDLE', message: '先在“输入与来源”页打开一个输入集。' }));
    return;
  }
  const limit = Number(limitSelect.value);
  page = { offset, sql };
  replace(resultHolder, h('p', { class: 'note' }, '执行中…'));
  const reply = await call('query', { sql: [sql], limit, offset }, { label: `查询：${sql.replace(/\s+/gu, ' ').slice(0, 60)}`, deadline_ms: 120_000 });
  if (!reply.ok) {
    replace(resultHolder, errorBox(reply.data.error));
    return;
  }
  const statement = reply.data.statements[0];
  const more = statement.next_offset !== null && statement.next_offset !== undefined;
  replace(resultHolder,
    resultTable(statement),
    pagerBar(
      { offset: statement.offset ?? offset, limit, rows: statement.rows.length, nextOffset: statement.next_offset, truncated: statement.truncated },
      {
        busy: false,
        onPrev: () => run(previousOffset(offset, limit)),
        onNext: () => run(statement.next_offset),
      }),
    more && !hasOrderBy(sql)
      ? h('p', { class: 'state-warn' }, '这条语句没有 ORDER BY：每一页都会重新执行，翻页时行的顺序没有保证。加上确定的 ORDER BY。')
      : null,
    h('p', { class: 'note' }, `用时 ${millis(reply.elapsed_ms)}${reply.started_engine ? '（含重新启动引擎与重新打开输入）' : ''}；${statement.columns.length} 列`));
}

async function loadTables() {
  const reply = await call('list_tables', {}, { handle: null, label: '读取关系列表' });
  if (!reply.ok) {
    replace(tablesHolder, errorBox(reply.data.error));
    return;
  }
  tablesLoaded = true;
  replace(tablesHolder, reply.data.tables.map((t) => h('div', {},
    h('button', {
      type: 'button',
      class: 'link',
      title: `${t.column_count} 列`,
      dataset: { table: t.name },
      onclick: async () => {
        sqlBox.value = `SELECT * FROM ${t.name} LIMIT 100`;
        const described = await call('describe_table', { name: t.name }, { handle: null, label: `描述 ${t.name}` });
        if (described.ok) toast(`${t.name}: ${described.data.columns.map((c) => c.name).join(', ')}`);
      },
    }, t.name))));
}

async function pickSave() {
  const name = `mdd-query.${exportFormat.value}`;
  const chosen = await invoke('pick_save_path', { fileName: name });
  if (chosen) exportPath.value = chosen;
}

async function doExport() {
  const sql = oneStatement(sqlBox.value);
  if (!sql || !currentDataset()) {
    toast('先打开输入集并写好查询。', 'bad');
    return;
  }
  if (!exportPath.value.trim()) {
    const dir = await invoke('suggest_export_dir');
    const sep = dir.includes('\\') ? '\\' : '/';
    exportPath.value = `${dir}${sep}mdd-query.${exportFormat.value}`;
  }
  replace(exportHolder, h('p', { class: 'note' }, '导出中…（可在底部取消；取消后不留残缺文件）'));
  const reply = await exportQuery({
    handle: state.current,
    sql,
    format: exportFormat.value,
    path: exportPath.value.trim(),
    page_rows: 1000,
    deadline_ms: 120_000,
  });
  if (!reply.ok) {
    replace(exportHolder, errorBox(reply.data.error));
    return;
  }
  const r = reply.data;
  replace(exportHolder, h('div', { class: 'panel', id: 'export-report' },
    h('strong', { class: 'state-ok' }, `已完整导出 ${number(r.rows)} 行`),
    kv([
      ['文件', r.path],
      ['格式', r.format],
      ['字节', number(r.bytes)],
      ['页数', r.pages],
      ['列', r.columns.join(', ')],
      ['快照', r.snapshot_ids.join(', ')],
      ['用时', millis(r.elapsed_ms)],
    ]),
    h('p', { class: 'note' }, '行数已与导出前的 count(*) 核对一致；不一致时文件会被删除而不是留下。')));
}

export const view = {
  id: 'query',
  title: '查询',
  needs: ['query', 'list_tables', 'describe_table'],
  build(el) {
    root = el;
    sqlBox = h('textarea', { id: 'sql', rows: 5, spellcheck: 'false', 'aria-label': 'SQL' });
    sqlBox.value = DEFAULT_SQL;
    sqlBox.addEventListener('keydown', (event) => {
      if (event.key === 'Enter' && (event.ctrlKey || event.metaKey)) {
        event.preventDefault();
        run(0);
      }
    });
    limitSelect = h('select', { id: 'limit', 'aria-label': '每页行数' },
      [50, 100, 200, 500, 1000].map((n) => h('option', { value: n, selected: n === 200 }, `${n} 行/页`)));
    resultHolder = h('div', { id: 'query-result' });
    tablesHolder = h('div', { id: 'table-list' });
    exportHolder = h('div', { id: 'export-holder' });
    exportPath = h('input', { type: 'text', id: 'export-path', class: 'grow', placeholder: '导出文件路径（留空：下载文件夹）' });
    exportFormat = h('select', { id: 'export-format' },
      h('option', { value: 'csv' }, 'CSV'), h('option', { value: 'jsonl' }, 'JSON Lines'));
    root.append(
      h('h2', {}, '查询'),
      h('div', { class: 'split' },
        h('div', {},
          h('h3', {}, '关系'),
          h('div', { class: 'scroll' }, tablesHolder)),
        h('div', {},
          h('div', { class: 'panel' },
            sqlBox,
            h('div', { class: 'row' },
              h('button', { type: 'button', id: 'run-query', class: 'primary', onclick: () => run(0) }, '执行（Ctrl+Enter）'),
              limitSelect,
              h('span', { class: 'note' }, '一次一条语句；只读。')),
            resultHolder),
          h('div', { class: 'panel' },
            h('strong', {}, '导出完整结果'),
            h('p', { class: 'note' }, '导出读取整个结果（先 count(*)，再按全部列排序分页），行数核对一致才保留文件。引擎对一页的偏移上限是 10 万行，导出不受它限制，但大结果可能要在“引擎”页调高 SQL 预算。'),
            h('div', { class: 'row' },
              exportFormat, exportPath,
              h('button', { type: 'button', id: 'pick-save', onclick: pickSave }, '浏览…'),
              h('button', { type: 'button', id: 'run-export', onclick: doExport }, '导出完整结果')),
            exportHolder))));
  },
  async show() {
    // not while the engine is busy with something else, and again next time if it did not work
    if (!tablesLoaded && !isBusy()) await loadTables();
  },
};
