// The engine as the window found it: where it is, what it says it is, what it lists, and its budgets.
import { h, replace } from '../lib/dom.js';
import { invoke } from '../lib/bridge.js';
import { call, isBusy, loadInfo, refresh, state, toast } from '../state.js';
import { errorBox, kv, pill } from '../widgets.js';
import { number } from '../lib/format.js';

// the engine's own defaults (crates/mdd-sql/src/control.rs, SqlLimits::default)
const ENGINE_DEFAULTS = { sql_max_steps: 5_000_000, sql_max_scanned_rows: 1_000_000, sql_max_result_rows: 100_000 };

let root;
let infoHolder;
let settingsHolder;

function numberField(id, label, value, hint) {
  const input = h('input', { type: 'number', id, min: 1, value: value ?? '', placeholder: hint });
  return h('label', { class: 'field' }, label, ' ', input);
}

function settingsForm() {
  const s = state.settings ?? {};
  const dialect = h('select', { id: 'set-dialect' },
    ['dexsql-0.1.0', 'dexsql-0.1.1'].map((d) => h('option', { value: d, selected: d === s.dialect }, d)));
  const timeout = numberField('set-timeout', '引擎默认期限（毫秒）', s.timeout_ms, '300000');
  const steps = numberField('set-steps', 'SQL 步数', s.sql_max_steps, `引擎默认 ${number(ENGINE_DEFAULTS.sql_max_steps)}`);
  const scanned = numberField('set-scanned', 'SQL 扫描行数', s.sql_max_scanned_rows, `引擎默认 ${number(ENGINE_DEFAULTS.sql_max_scanned_rows)}`);
  const results = numberField('set-results', 'SQL 结果行数', s.sql_max_result_rows, `引擎默认 ${number(ENGINE_DEFAULTS.sql_max_result_rows)}`);
  const read = (field) => {
    const value = field.querySelector('input').value.trim();
    return value === '' ? null : Number(value);
  };
  const apply = async (settings) => {
    const reply = await invoke('engine_configure', { settings });
    if (!reply.ok) {
      toast(reply.error?.message ?? '设置无效', 'bad');
      return;
    }
    toast('已应用。引擎进程已结束，输入会在下次操作时重新打开。');
    await refresh();
    await loadInfo();
    render();
  };
  return h('div', { class: 'panel', id: 'engine-settings' },
    h('strong', {}, '引擎设置'),
    h('p', { class: 'note' }, '改动会结束并重新启动引擎进程；已打开的输入集保留，并在下一次操作时重新打开。工作台的默认 SQL 预算比引擎默认值宽，因为一个人浏览一个应用时常常要扫描它最大的关系；留空表示用引擎默认。'),
    h('div', { class: 'row' }, h('label', { class: 'field' }, 'SQL 方言 ', dialect), timeout),
    h('div', { class: 'row' }, steps, scanned, results),
    h('div', { class: 'row' },
      h('button', { type: 'button', id: 'apply-settings', class: 'primary', onclick: () => apply({
        dialect: dialect.value,
        timeout_ms: read(timeout) ?? 300_000,
        sql_max_steps: read(steps),
        sql_max_scanned_rows: read(scanned),
        sql_max_result_rows: read(results),
      }) }, '应用并重启引擎'),
      h('button', { type: 'button', id: 'reset-settings', onclick: () => apply({
        dialect: dialect.value, timeout_ms: 300_000, sql_max_steps: null, sql_max_scanned_rows: null, sql_max_result_rows: null,
      }) }, '恢复引擎默认预算'),
      h('button', { type: 'button', class: 'danger', onclick: async () => { await invoke('engine_stop'); await refresh(); render(); toast('引擎已停止'); } }, '停止引擎')));
}

function render() {
  const info = state.info;
  if (!info) return replace(infoHolder, h('p', { class: 'note' }, '检测中…'));
  const version = info.version ?? {};
  replace(settingsHolder, settingsForm());
  replace(infoHolder,
    h('div', { class: 'panel' },
      h('div', { class: 'row' }, h('strong', {}, '引擎'),
        info.start?.ok ? pill(state.running ? '运行中' : '未运行', state.running ? 'ok' : 'warn') : pill('无法启动', 'bad')),
      info.start?.ok ? null : errorBox(info.start?.error),
      kv([
        ['程序', info.binary],
        ['存在', info.binary_exists ? '是' : '否'],
        ['版本', version.engine_version],
        ['build_id', version.build_id],
        ['范围声明', version.implementation_scope],
        ['工作台', `${info.shell.name} ${info.shell.version}（${info.shell.os}/${info.shell.arch}）`],
        ['协议', info.server?.protocolVersion],
        ['服务', info.server?.serverInfo ? `${info.server.serverInfo.name} ${info.server.serverInfo.version}` : null],
      ]),
      info.server?.instructions ? h('p', { class: 'note' }, `服务说明：${info.server.instructions}`) : null),
    h('div', { class: 'panel' },
      h('strong', {}, `引擎列出的工具（${state.tools.length}）`),
      h('p', { class: 'note' }, '工作台的每个视图只在它需要的工具都被引擎列出时才可用；列表来自引擎的 tools/list，工作台里没有写死。'),
      h('div', { class: 'row', id: 'tool-list' }, state.tools.map((t) => pill(t, 'ok')))),
    h('div', { class: 'panel' },
      h('strong', {}, '引擎自述的能力（capabilities 命令，原样）'),
      h('p', { class: 'note' }, '这是 `meguvizdexdash capabilities` 的原样输出。它列出的传输只有 cli-*，没有 MCP，能力清单落后于 MCP 工具面，所以工作台以 tools/list 为准；所有 profile 都未准入。'),
      h('pre', { class: 'code', id: 'capabilities-json' }, JSON.stringify(info.capabilities, null, 2))));
}

export const view = {
  id: 'engine',
  title: '引擎与设置',
  needs: [],
  build(el) {
    root = el;
    infoHolder = h('div', { id: 'engine-info' });
    settingsHolder = h('div', {});
    root.append(h('h2', {}, '引擎与设置'), settingsHolder, infoHolder);
  },
  async show() {
    render();
    if (isBusy()) return;
    const limits = await call('list_datasets', {}, { handle: null, label: '读取引擎限额' });
    if (limits.ok) {
      infoHolder.append(h('div', { class: 'panel' }, h('strong', {}, '引擎限额（list_datasets）'),
        kv(Object.entries(limits.data.limits ?? {}).map(([k, v]) => [k, String(v)]))));
    }
  },
};
