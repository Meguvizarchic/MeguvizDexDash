// The archive side of an input: Manifest (summary, components, XML), member list, resources.arsc, and
// reading one member. Paged by whatever unit the engine pages in (rows or UTF-8 bytes).
import { h, replace } from '../lib/dom.js';
import { bytes, number } from '../lib/format.js';
import { describePage } from '../lib/pager.js';
import { call, currentDataset } from '../state.js';
import { errorBox, kv, pill } from '../widgets.js';

let root;
let inputSelect;
let sectionHolder;
let notice;
let reader;
const sections = [];

function archiveIndexes() {
  const summary = currentDataset()?.summary;
  return Array.isArray(summary?.archive_inputs) ? summary.archive_inputs : [];
}

/** A paged panel. `fetch(offset)` asks the engine; `show(data)` returns {body, next, text, complete}. */
function panel(id, { fetch, show, unit = '行' }) {
  const holder = h('div', { id, class: 'section-body' });
  const run = async (offset = 0, trail = []) => {
    replace(holder, h('p', { class: 'note' }, '读取中…'));
    const reply = await fetch(offset);
    if (!reply.ok) return replace(holder, errorBox(reply.data.error));
    const shown = show(reply.data);
    const more = shown.next !== null && shown.next !== undefined;
    replace(holder, shown.body,
      h('div', { class: 'row pager' },
        h('button', { type: 'button', disabled: trail.length === 0, dataset: { act: 'prev' }, onclick: () => run(trail[trail.length - 1], trail.slice(0, -1)) }, '上一页'),
        h('button', { type: 'button', disabled: !more, dataset: { act: 'next' }, onclick: () => run(shown.next, [...trail, offset]) }, '下一页'),
        h('span', { class: shown.complete && !more ? 'state-ok' : 'state-warn', dataset: { complete: String(!more) } }, shown.text),
        h('span', { class: 'note' }, `偏移单位：${unit}`)));
  };
  return { holder, run };
}

function inputIndex() {
  return Number(inputSelect.value || 0);
}

function permissionsTable(data) {
  return h('table', { class: 'grid' },
    h('thead', {}, h('tr', {}, ['元素', '名称', '其它属性'].map((t) => h('th', {}, t)))),
    h('tbody', {}, (data.permissions ?? []).map((p) => {
      const { 'android:name': name, ...rest } = p.attributes ?? {};
      return h('tr', {}, h('td', {}, p.kind), h('td', { class: 'text' }, name ?? ''), h('td', { class: 'text' }, JSON.stringify(rest) === '{}' ? '' : JSON.stringify(rest)));
    })));
}

function summarySection() {
  return panel('manifest-summary', {
    fetch: (offset) => call('get_manifest', { input_index: inputIndex(), limit: 50, offset }, { label: '读取 Manifest 摘要' }),
    show: (d) => ({
      body: h('div', {},
        h('h3', {}, 'manifest'), kv(Object.entries(d.manifest ?? {})),
        h('h3', {}, 'uses-sdk'), kv(Object.entries(d.uses_sdk ?? {})),
        h('h3', {}, 'application'), kv(Object.entries(d.application ?? {})),
        h('h3', {}, '组件个数'), kv(Object.entries(d.component_counts ?? {})),
        h('h3', {}, `权限（${number(d.total_rows ?? 0)} 个）`), permissionsTable(d)),
      next: d.next_offset,
      text: describePage({ offset: d.offset ?? 0, rows: (d.permissions ?? []).length, nextOffset: d.next_offset, truncated: d.truncated }).text,
      complete: true,
    }),
  });
}

function componentsSection() {
  const kind = h('select', { id: 'component-kind' },
    ['', 'activity', 'activity-alias', 'service', 'receiver', 'provider'].map((k) => h('option', { value: k }, k || '全部种类')));
  const exported = h('input', { type: 'checkbox', id: 'component-exported' });
  const p = panel('manifest-components', {
    fetch: (offset) => {
      const args = { input_index: inputIndex(), limit: 50, offset };
      if (kind.value) args.kind = kind.value;
      if (exported.checked) args.only_exported = true;
      return call('get_manifest_components', args, { label: '读取组件' });
    },
    show: (d) => ({
      body: h('table', { class: 'grid' },
        h('thead', {}, h('tr', {}, ['种类', '名称', 'exported', '原因', 'enabled', 'launcher', 'intent-filter'].map((t) => h('th', {}, t)))),
        h('tbody', {}, (d.components ?? []).map((c) => h('tr', {},
          h('td', {}, c.kind), h('td', { class: 'text', title: c.descriptor }, c.name),
          h('td', {}, c.exported === null ? '未知' : String(c.exported)), h('td', {}, c.exported_reason ?? ''),
          h('td', {}, String(c.enabled)), h('td', {}, c.launcher_intent ? '是' : ''), h('td', { class: 'num' }, (c.intent_filters ?? []).length))))),
      next: d.next_offset,
      text: describePage({ offset: d.offset ?? 0, rows: (d.components ?? []).length, nextOffset: d.next_offset, truncated: d.truncated }).text,
      complete: true,
    }),
  });
  p.controls = h('div', { class: 'row' }, kind, h('label', {}, exported, ' 只看 exported'), h('button', { type: 'button', onclick: () => p.run(0) }, '应用'));
  return p;
}

function xmlSection() {
  return panel('manifest-xml', {
    unit: 'UTF-8 字节',
    fetch: (offset) => call('get_manifest', { input_index: inputIndex(), mode: 'xml', max_bytes: 16384, offset }, { label: '读取 Manifest XML' }),
    show: (d) => ({
      body: h('pre', { class: 'code', id: 'manifest-xml-text' }, d.page?.text ?? ''),
      next: d.page?.next_offset,
      text: `第 ${d.page?.start_line ?? 0}–${d.page?.end_line ?? 0} 行；共 ${number(d.page?.total_bytes ?? 0)} 字节${d.page?.next_offset == null ? '，已是末页' : '，后面还有未加载的部分'}`,
      complete: true,
    }),
  });
}

function membersSection() {
  const prefix = h('input', { type: 'text', id: 'member-prefix', placeholder: '成员名前缀（区分大小写）' });
  const p = panel('archive-members', {
    fetch: (offset) => call('list_resource_files', { input_index: inputIndex(), prefix: prefix.value || undefined, limit: 100, offset }, { label: '列出归档成员' }),
    show: (d) => ({
      body: h('table', { class: 'grid' },
        h('thead', {}, h('tr', {}, ['名称', '字节', '压缩后', 'CRC-32', 'entry_index'].map((t) => h('th', {}, t)))),
        h('tbody', {}, (d.files ?? []).map((f) => h('tr', { class: f.directory ? '' : 'pick', onclick: f.directory ? null : () => readMember(f.name) },
          h('td', { class: 'text' }, f.name), h('td', { class: 'num' }, number(f.bytes)), h('td', { class: 'num' }, number(f.compressed_bytes)),
          h('td', { class: 'num' }, f.crc32), h('td', { class: 'num' }, f.entry_index))))),
      next: d.next_offset,
      text: `${describePage({ offset: d.offset ?? 0, rows: (d.files ?? []).length, nextOffset: d.next_offset, truncated: d.truncated }).text}；成员共 ${number(d.total_rows)} 个（同名成员都会列出）`,
      complete: true,
    }),
  });
  p.controls = h('div', { class: 'row' }, prefix, h('button', { type: 'button', onclick: () => p.run(0) }, '列出'));
  return p;
}

function resourcesSection() {
  const contains = h('input', { type: 'text', id: 'resource-contains', placeholder: 'type/name 包含…' });
  const p = panel('resource-table', {
    fetch: (offset) => call('query_resources', { input_index: inputIndex(), contains: contains.value || undefined, limit: 100, offset }, { label: '查询资源' }),
    show: (d) => ({
      body: h('table', { class: 'grid' },
        h('thead', {}, h('tr', {}, ['名称', 'id', '配置', '类型', '值'].map((t) => h('th', {}, t)))),
        h('tbody', {}, (d.values ?? []).map((v) => h('tr', {},
          h('td', { class: 'text' }, v.name), h('td', { class: 'text' }, v.resource_id_hex), h('td', {}, v.configuration || '（默认）'),
          h('td', {}, v.value_type), h('td', { class: 'text', title: String(v.value) }, v.value === null ? '∅' : String(v.value)))))),
      next: d.next_offset,
      text: `${describePage({ offset: d.offset ?? 0, rows: (d.values ?? []).length, nextOffset: d.next_offset, truncated: d.truncated }).text}；共 ${number(d.total_rows)} 行（每个配置一行）`,
      complete: true,
    }),
  });
  p.controls = h('div', { class: 'row' }, contains, h('button', { type: 'button', onclick: () => p.run(0) }, '查询'));
  return p;
}

async function readMember(name, offset = 0, trail = []) {
  replace(reader, h('p', { class: 'note' }, `读取 ${name}…`));
  const reply = await call('read_resource', { input_index: inputIndex(), name, max_bytes: 16384, offset }, { label: `读取 ${name}` });
  if (!reply.ok) return replace(reader, errorBox(reply.data.error));
  const d = reply.data;
  const textual = d.encoding === 'utf8';
  const next = textual ? d.page?.next_offset : d.next_offset;
  const total = textual ? d.page?.total_bytes : d.total_bytes;
  replace(reader,
    h('div', { class: 'row' }, h('strong', {}, name), pill(d.kind), pill(d.encoding), h('span', { class: 'note' }, `${bytes(d.source_bytes)}；sha256 ${d.source?.sha256 ?? ''}`)),
    h('pre', { class: 'code', id: 'resource-text' }, textual ? (d.page?.text ?? '') : (d.content ?? '')),
    h('div', { class: 'row' },
      h('button', { type: 'button', disabled: trail.length === 0, onclick: () => readMember(name, trail[trail.length - 1], trail.slice(0, -1)) }, '上一页'),
      h('button', { type: 'button', disabled: next == null, onclick: () => readMember(name, next, [...trail, offset]) }, '下一页'),
      h('span', { class: next == null ? 'state-ok' : 'state-warn' },
        next == null ? `已读到末尾（共 ${number(total)} 字节）` : `已读到偏移 ${next} / ${number(total)} 字节；后面还有未加载的部分`)));
}

export const view = {
  id: 'manifest',
  title: 'Manifest 与资源',
  needs: ['get_manifest'],
  build(el) {
    root = el;
    inputSelect = h('select', { id: 'archive-input', 'aria-label': '归档输入' });
    sectionHolder = h('div', { id: 'manifest-sections' });
    notice = h('p', { class: 'note', id: 'manifest-notice', hidden: true });
    reader = h('div', { id: 'member-reader', class: 'panel' }, h('p', { class: 'note' }, '在“归档成员”里点一个成员来读取。'));
    const defs = [
      ['摘要', summarySection()],
      ['组件', componentsSection()],
      ['Manifest XML', xmlSection()],
      ['归档成员', membersSection()],
      ['资源（resources.arsc）', resourcesSection()],
    ];
    const tabs = h('div', { class: 'row', role: 'tablist' });
    defs.forEach(([title, section], i) => {
      sections.push(section);
      const button = h('button', { type: 'button', role: 'tab', dataset: { section: String(i) }, onclick: () => select(i) }, title);
      tabs.append(button);
      section.holder.hidden = true;
      section.button = button;
      sectionHolder.append(...(section.controls ? [section.controls] : []), section.holder);
      if (section.controls) section.controls.hidden = true;
    });
    function select(i) {
      sections.forEach((s, j) => {
        s.holder.hidden = i !== j;
        if (s.controls) s.controls.hidden = i !== j;
        s.button.classList.toggle('primary', i === j);
      });
      sections[i].run(0);
    }
    root.append(h('h2', {}, 'Manifest 与资源'),
      h('div', { class: 'row' }, h('label', {}, '归档输入 ', inputSelect)),
      notice, tabs, h('div', { class: 'panel' }, sectionHolder), reader);
  },
  show() {
    const indexes = archiveIndexes();
    const dataset = currentDataset();
    replace(inputSelect, indexes.map((i) => h('option', { value: i }, `#${i}：${dataset?.inputs?.[i] ?? ''}`)));
    const none = !indexes.length;
    notice.hidden = !none;
    notice.textContent = none ? '当前输入集没有归档输入（只有裸 DEX，或还没有打开输入），没有 Manifest 与资源可看。' : '';
    sectionHolder.hidden = none;
  },
};
