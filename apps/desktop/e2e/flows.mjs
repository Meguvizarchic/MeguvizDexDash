// The user flows of conformance/desktop/user-flow-cases.json, driven through the real window.
// A flow records named checks; it passes only when all of them did.
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, statSync, rmSync, mkdtempSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';

const here = fileURLToPath(new URL('.', import.meta.url));
export const repo = resolve(here, '..', '..', '..');
export const fixture = (relative) => join(repo, 'tests', 'fixtures', relative);
const desktop = (name) => fixture(join('desktop', 'generated', name));
export const NEWPIPE = join(repo, 'artifacts', 'local', 'inputs', 'NewPipe_v0.28.6.apk');

const sha256 = (path) => createHash('sha256').update(readFileSync(path)).digest('hex');

// ---- page helpers -------------------------------------------------------------------------------

const q = (selector) => JSON.stringify(selector);
const count = (app, selector) => app.eval(`document.querySelectorAll(${q(selector)}).length`);

async function nav(app, id) {
  await app.click(`#nav button[data-view="${id}"]`);
  await app.waitFor(`!document.querySelector('#view-${id}').hidden`, { what: `view ${id}` });
}

async function openInputs(app, paths) {
  const before = await count(app, '.dataset');
  await nav(app, 'inputs');
  await app.type('#input-paths', paths.join('\n'));
  await app.click('#open-inputs');
  await app.waitFor(`document.querySelectorAll('.dataset').length === ${before + 1} || !!document.querySelector('#open-error .error-box')`, { what: 'the input set to open or fail' });
}

async function runSql(app, sql, { limit } = {}) {
  await nav(app, 'query');
  if (limit) await app.select('#limit', String(limit));
  await app.type('#sql', sql);
  await app.click('#run-query');
  await app.waitFor(`!!document.querySelector('#query-result table.grid') || !!document.querySelector('#query-result .error-box')`, { what: 'a result or an error', timeout: 60_000 });
}

async function applyEngineButton(app, selector, { expectToast = false } = {}) {
  await app.waitFor(
    `document.querySelector('#busy-text')?.textContent?.trim() === '空闲'`,
    { what: 'the engine to be idle before applying settings' },
  );
  await app.eval(
    `(() => { const el = document.querySelector('#engine-settings') || document.querySelector(${JSON.stringify(selector)}); if (el) el.dataset.e2eGen = 'prev'; })()`,
  );
  await app.click(selector);
  if (expectToast) {
    await app.waitFor(`!!document.querySelector('.toast')`, { what: 'the settings toast' });
  }
  await app.waitFor(
    `(() => { const el = document.querySelector('#engine-settings') || document.querySelector(${JSON.stringify(selector)}); return el?.dataset?.e2eGen !== 'prev' && document.querySelector('#busy-text')?.textContent?.trim() === '空闲'; })()`,
    { what: 'the engine settings update and re-render to settle' },
  );
}

const pagerText = (app) => app.text('#query-result .pager [data-complete]');
const pagerComplete = (app) => app.eval(`document.querySelector('#query-result .pager [data-complete]')?.dataset.complete`);
const firstCell = (app) => app.text('#query-result tbody tr:first-child td:first-child');

function engineChildren(pid) {
  try {
    if (process.platform === 'win32') {
      const out = execFileSync('powershell', ['-NoProfile', '-Command',
        `(Get-CimInstance Win32_Process -Filter "ParentProcessId=${pid}" | Where-Object { $_.Name -eq 'meguvizdexdash.exe' }).ProcessId`], { encoding: 'utf8' });
      return out.split(/\s+/u).filter(Boolean).map(Number);
    }
    const out = execFileSync('pgrep', ['-P', String(pid), '-x', 'meguvizdexdash'], { encoding: 'utf8' });
    return out.split(/\s+/u).filter(Boolean).map(Number);
  } catch {
    return [];
  }
}

function alive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

const THREE_WAY = 'SELECT a.string_idx AS a, b.string_idx AS b, c.string_idx AS c FROM strings a, strings b, strings c ORDER BY 1, 2, 3';
const SIX_WAY = 'SELECT a.string_idx AS a, b.string_idx AS b, c.string_idx AS c, d.string_idx AS d, e.string_idx AS e, f.string_idx AS f FROM strings a, strings b, strings c, strings d, strings e, strings f';
const HEAVY = `SELECT count(*) FROM ${'abcdefghijklmn'.split('').map((x) => `strings ${x}`).join(', ')}`;

// ---- the flows ----------------------------------------------------------------------------------

export const flows = {
  async open_input_shows_provenance({ app, check }) {
    await openInputs(app, [desktop('a.dex')]);
    await app.waitFor(`document.querySelector('.dataset table.grid td')`, { what: 'the DEX member table' });
    const card = await app.text('.dataset');
    check('the input set card appears', await count(app, '.dataset') === 1);
    check('the card carries the sha256 computed outside the app', card.includes(sha256(desktop('a.dex'))), sha256(desktop('a.dex')));
    check('the input kind is shown', card.includes('dex-header') || card.includes('dex'), card.slice(0, 200));
    check('the profile is marked not admitted', card.includes('未准入'));
    check('a snapshot id is shown', /snapshot_id/u.test(card));
    check('the DEX member row names a.dex', card.includes('a.dex'));
    check('the engine chip stays ok', (await app.eval(`document.querySelector('#engine-chip').dataset.state`)) === 'ok');
  },

  async refuse_bad_inputs({ app, check }) {
    await openInputs(app, [join(repo, 'README.md')]);
    const invalid = await app.eval(`document.querySelector('#open-error .error-box')?.dataset.code`);
    check('a text file is INVALID_INPUT', invalid === 'INVALID_INPUT', invalid);
    check('the hint says the input was not accepted as empty', (await app.text('#open-error')).includes('没有把它当作空输入接受'));
    await openInputs(app, [join(tmpdir(), 'mdd-e2e-no-such-file.apk')]);
    const missing = await app.eval(`document.querySelector('#open-error .error-box')?.dataset.code`);
    check('a missing path is INPUT_NOT_FOUND', missing === 'INPUT_NOT_FOUND', missing);
    check('no input set was remembered', await count(app, '.dataset') === 0);
  },

  async query_pages_never_look_complete_when_they_are_not({ app, check }) {
    await openInputs(app, [fixture(join('decode', 'generated', 'manifest-small.apk'))]);
    await runSql(app, THREE_WAY, { limit: 50 });
    check('page 1 has 50 rows', await count(app, '#query-result tbody tr') === 50);
    check('page 1 says more rows are not loaded', (await pagerComplete(app)) === 'false', await pagerText(app));
    check('page 1 text says so in words', (await pagerText(app)).includes('后面还有未加载的行'));
    const firstRow = await app.text('#query-result tbody tr:first-child');
    for (let page = 2; page <= 4; page += 1) {
      await app.click('#query-result [data-act="next"]');
      await app.waitFor(`document.querySelector('#query-result .pager')?.textContent.includes('第 ${(page - 1) * 50 + 1}–')`, { what: `page ${page}` });
      check(`page ${page} is still marked partial`, (await pagerComplete(app)) === 'false');
    }
    await app.click('#query-result [data-act="next"]');
    await app.waitFor(`document.querySelector('#query-result .pager')?.textContent.includes('第 201–216')`, { what: 'the last page' });
    check('the last page has 16 rows', await count(app, '#query-result tbody tr') === 16);
    check('the last page says it is complete with the total', (await pagerText(app)).includes('已是最后一页（结果共 216 行）'), await pagerText(app));
    check('the last page marks complete', (await pagerComplete(app)) === 'true');
    check('next is disabled on the last page', await app.eval(`document.querySelector('#query-result [data-act="next"]').disabled`));
    for (const from of [151, 101, 51, 1]) {
      await app.click('#query-result [data-act="prev"]');
      await app.waitFor(`document.querySelector('#query-result .pager')?.textContent.includes('第 ${from}–')`, { what: `the page starting at ${from}` });
    }
    check('previous x4 restores page 1 with its first row', (await app.text('#query-result tbody tr:first-child')) === firstRow, firstRow);
    await runSql(app, 'SELECT string_idx FROM strings WHERE 1 = 0');
    check('an empty result says the engine confirmed it', (await pagerText(app)).includes('0 行（引擎确认结果已完整）'), await pagerText(app));
  },

  async query_errors_and_budgets_are_understandable({ app, check }) {
    await openInputs(app, [fixture(join('decode', 'generated', 'manifest-small.apk'))]);
    await runSql(app, 'SELEC nope');
    const syntax = await app.eval(`document.querySelector('#query-result .error-box')?.dataset.code`);
    check('invalid SQL is INVALID_ARGUMENT', syntax === 'INVALID_ARGUMENT', syntax);
    check('the engine parser message is shown', (await app.text('#query-result .error-box')).includes('SQL_PARSE_ERROR'));
    check('no table is shown for an error', await count(app, '#query-result table.grid') === 0);

    await nav(app, 'engine');
    await app.type('#set-steps', '2000');
    await applyEngineButton(app, '#apply-settings', { expectToast: true });
    await runSql(app, THREE_WAY);
    const budget = await app.eval(`document.querySelector('#query-result .error-box')?.dataset.code`);
    check('an exhausted budget is QUOTA_EXCEEDED', budget === 'QUOTA_EXCEEDED', budget);
    const hint = await app.text('#query-result .error-box');
    check('the hint points at the engine page', hint.includes('引擎”页调高预算'), hint);
    check('it says the result was not returned as complete', hint.includes('没有被截断后当作完整结果返回'));
    check('no rows are shown', await count(app, '#query-result tbody tr') === 0);

    await nav(app, 'engine');
    await applyEngineButton(app, '#reset-settings');
    await nav(app, 'engine');
    check('the step budget field is empty after the reset', (await app.eval(`document.querySelector('#set-steps').value`)) === '');
    await app.type('#set-steps', '200000000');
    await applyEngineButton(app, '#apply-settings');
    await runSql(app, THREE_WAY, { limit: 50 });
    check('the same query works with a roomy budget', await count(app, '#query-result tbody tr') === 50);
  },

  async long_query_does_not_block_the_window_and_cancels({ app, check }) {
    await openInputs(app, [fixture(join('decode', 'generated', 'manifest-small.apk'))]);
    // the window's default budget ends this join with QUOTA_EXCEEDED after about two seconds; give it room
    await nav(app, 'engine');
    await app.type('#set-steps', '4000000000');
    await app.type('#set-scanned', '40000000000');
    await applyEngineButton(app, '#apply-settings', { expectToast: true });
    await nav(app, 'query');
    await app.type('#sql', HEAVY);
    await app.click('#run-query');
    await app.waitFor(`document.querySelector('#busy-text').textContent.startsWith('执行中')`, { what: 'the busy bar' });
    const first = await app.text('#busy-text');
    await sleep(900);
    const second = await app.text('#busy-text');
    check('the elapsed time keeps advancing', first !== second, `${first} -> ${second}`);
    const switched = Date.now();
    await app.click('#nav button[data-view="engine"]');
    await app.waitFor(`document.querySelector('#nav button[data-view="engine"]').getAttribute('aria-current') === 'page'`, { what: 'the view switch', timeout: 3000 });
    check('a view switch while the engine is busy answers within 3 s', Date.now() - switched < 3000, `${Date.now() - switched} ms`);
    check('the cancel button is shown while busy', !(await app.eval(`document.querySelector('#cancel-button').hidden`)));
    await nav(app, 'query');
    const pressed = Date.now();
    await app.click('#cancel-button');
    await app.waitFor(`document.querySelector('#query-result .error-box')?.dataset.code === 'CANCELLED'`, { what: 'CANCELLED', timeout: 10_000 });
    const took = Date.now() - pressed;
    check('CANCELLED arrives within 3 s of the press', took < 3000, `${took} ms`);
    await app.waitFor(`document.querySelector('#busy-text').textContent === '空闲'`, { what: 'the bar to go idle' });
    check('the bar is idle again', true);
    check('the cancel hint explains the engine was ended', (await app.text('#query-result .error-box')).includes('引擎进程已结束'));
    check('the input set is remembered but not live', (await app.text('#status-note')).includes('需要重新打开'), await app.text('#status-note'));
    await runSql(app, 'SELECT count(*) AS n FROM strings');
    check('the next query works on the same input set', (await firstCell(app)) === '6', await firstCell(app));
    check('the result notes the engine was started again', (await app.text('#query-result')).includes('重新启动引擎与重新打开输入'));
    check('the input set is live again', !(await app.text('#status-note')).includes('需要重新打开'));
  },

  async browse_class_method_smali_and_xrefs({ app, check }) {
    await openInputs(app, [desktop('ab1.dex'), desktop('ab2.dex')]);
    await nav(app, 'browse');
    await app.type('#class-search', 'demo');
    await app.click('#search-classes');
    await app.waitFor(`document.querySelectorAll('#class-list tr.pick').length === 2`, { what: 'two classes' });
    const classes = await app.eval(`[...document.querySelectorAll('#class-list tr.pick')].map(r => r.children[0].textContent)`);
    check('both classes are listed, in order', JSON.stringify(classes) === JSON.stringify(['Ldemo/A;', 'Ldemo/B;']), JSON.stringify(classes));
    await app.eval(`document.querySelectorAll('#class-list tr.pick')[0].click()`);
    // the engine's methods relation lists foo twice here: defined in ab1.dex, merely referenced from ab2.dex
    await app.waitFor(`document.querySelectorAll('#method-list tr.pick').length === 2`, { what: 'the method list' });
    check('the reference-only row is explained', (await app.text('#method-list')).includes('只在这个 DEX 里被引用'));
    const rows = await app.eval(`[...document.querySelectorAll('#method-list tr.pick')].map(r => r.children[4].textContent)`);
    check('one row is a definition and one a reference (access_flags NULL)', rows[0] === '9' && rows[1] === '∅', JSON.stringify(rows));
    await app.eval(`document.querySelector('#method-list tr.pick').click()`);
    await app.waitFor(`!!document.querySelector('#smali-text')`, { what: 'the smali text' });
    check('the smali shows the declaration', (await app.text('#smali-text')).includes('.method public static foo()V'), await app.text('#smali-text'));
    check('the page says it reached the end', (await app.text('#smali-state')).includes('已显示到末尾'));
    const refs = await app.eval(`[...document.querySelectorAll('#smali-text .ref')].map(r => r.dataset.kind + ':' + r.dataset.desc)`);
    check('the invoke target is a clickable method reference', refs.includes('method:Ldemo/B;->bar()V'), JSON.stringify(refs));
    await app.eval(`document.querySelector('#smali-text .ref[data-kind="method"]').click()`);
    await app.waitFor(`document.querySelector('#smali-text')?.dataset.descriptor === 'Ldemo/B;->bar()V'`, { what: 'bar to open' });
    check('following the reference opened bar (defined in the other DEX file)', true);
    check('the xref note names reflection and invoke-custom as unknown', (await app.text('#xref-holder')).includes('反射、动态加载和 invoke-custom'));
    await app.click('#load-callers');
    await app.waitFor(`document.querySelectorAll('#xref-callers tr.pick').length === 1`, { what: 'one caller', timeout: 30_000 });
    check('the caller of bar is foo', (await app.text('#xref-callers tr.pick td:first-child')) === 'Ldemo/A;->foo()V');
    check('the callers answer says it is complete', (await app.text('#xref-callers')).includes('（完整）'));
    await app.click('#load-callees');
    await app.waitFor(`document.querySelectorAll('#xref-callees tr.pick').length === 1`, { what: 'one callee', timeout: 30_000 });
    check('the callee of bar is foo', (await app.text('#xref-callees tr.pick td:first-child')) === 'Ldemo/A;->foo()V');
    await app.eval(`document.querySelector('#xref-callers tr.pick').click()`);
    await app.waitFor(`document.querySelector('#smali-text')?.dataset.descriptor === 'Ldemo/A;->foo()V'`, { what: 'back to foo' });
    check('a click on a caller navigates back to foo', true);
  },

  async smali_pages_say_what_is_not_loaded({ app, check }) {
    await openInputs(app, [desktop('long.dex')]);
    await nav(app, 'browse');
    await app.type('#class-search', 'Ldemo/L');
    await app.click('#search-classes');
    await app.waitFor(`document.querySelectorAll('#class-list tr.pick').length === 1`, { what: 'the class' });
    await app.eval(`document.querySelector('#class-list tr.pick').click()`);
    await app.waitFor(`document.querySelectorAll('#method-list tr.pick').length === 1`, { what: 'the method' });
    await app.eval(`document.querySelector('#method-list tr.pick').click()`);
    await app.waitFor(`!!document.querySelector('#smali-state')`, { what: 'the smali page' });
    const first = await app.text('#smali-state');
    check('page 1 says the tail is not loaded', first.includes('后面还有未加载的部分'), first);
    check('page 1 names its lines and the total', first.includes('共 505 行'), first);
    check('next is enabled', !(await app.eval(`document.querySelector('#smali-next').disabled`)));
    check('previous is disabled on page 1', await app.eval(`document.querySelector('#smali-prev').disabled`));
    const lines1 = (await app.text('#smali-text')).split('\n').length;
    await app.click('#smali-next');
    await app.waitFor(`document.querySelector('#smali-state').textContent.includes('已显示到末尾')`, { what: 'the last smali page' });
    const last = await app.text('#smali-state');
    check('the last page says it reached the end with the total', last.includes('共 505 行'), last);
    check('the two pages together cover the method', lines1 > 250, `page 1 shows ${lines1} lines`);
    await app.click('#smali-prev');
    await app.waitFor(`document.querySelector('#smali-state').textContent.includes('后面还有未加载的部分')`, { what: 'page 1 again' });
    check('previous returns to page 1', true);
  },

  async manifest_and_resources({ app, check }) {
    await openInputs(app, [fixture(join('decode', 'generated', 'manifest-small.apk'))]);
    await nav(app, 'manifest');
    await app.click('[data-section="0"]');
    await app.waitFor(`document.querySelector('#manifest-summary')?.textContent.includes('package')`, { what: 'the summary' });
    check('the summary names the package', (await app.text('#manifest-summary')).includes('package'));
    await app.click('[data-section="1"]');
    await app.waitFor(`!!document.querySelector('#manifest-components table')`, { what: 'the components table' });
    check('the components table is shown', true);
    await app.click('[data-section="2"]');
    await app.waitFor(`document.querySelector('#manifest-xml-text')?.textContent.includes('<manifest')`, { what: 'the XML' });
    check('the XML text starts with the manifest element', (await app.text('#manifest-xml-text')).includes('<manifest'));
    await app.click('[data-section="3"]');
    await app.waitFor(`document.querySelectorAll('#archive-members tbody tr').length > 0`, { what: 'the members' });
    const members = await app.eval(`[...document.querySelectorAll('#archive-members tbody tr td:first-child')].map(t => t.textContent)`);
    check('the member list includes the manifest and the DEX', members.includes('AndroidManifest.xml') && members.some((m) => m.endsWith('.dex')), JSON.stringify(members));
    check('the member total is shown', (await app.text('#archive-members')).includes('成员共'));
    await app.eval(`[...document.querySelectorAll('#archive-members tbody tr')].find(r => r.children[0].textContent === 'AndroidManifest.xml').click()`);
    await app.waitFor(`document.querySelector('#member-reader')?.textContent.includes('sha256')`, { what: 'the member read' });
    check('the member read shows its sha256', /sha256 [0-9a-f]{64}/u.test(await app.text('#member-reader')));
  },

  async export_complete_result({ app, check }) {
    await openInputs(app, [fixture(join('decode', 'generated', 'manifest-small.apk'))]);
    const dir = mkdtempSync(join(tmpdir(), 'mdd-e2e-export-'));
    try {
      await nav(app, 'query');
      await app.type('#sql', THREE_WAY);
      const csv = join(dir, 'three.csv');
      await app.type('#export-path', csv);
      await app.select('#export-format', 'csv');
      await app.click('#run-export');
      await app.waitFor(`!!document.querySelector('#export-report') || !!document.querySelector('#export-holder .error-box')`, { what: 'the export report', timeout: 60_000 });
      check('the report says 216 rows exported', (await app.text('#export-report')).includes('已完整导出 216 行'), await app.text('#export-holder'));
      const lines = readFileSync(csv, 'utf8').trimEnd().split('\n');
      check('the CSV has a header and 216 rows', lines.length === 217 && lines[0] === 'a,b,c', `${lines.length} lines, header ${lines[0]}`);
      check('every row appears once', new Set(lines.slice(1)).size === 216);
      const jsonl = join(dir, 'three.jsonl');
      await app.type('#export-path', jsonl);
      await app.select('#export-format', 'jsonl');
      await app.click('#run-export');
      await app.waitFor(`document.querySelector('#export-report')?.textContent.includes('jsonl')`, { what: 'the JSON Lines report', timeout: 60_000 });
      const records = readFileSync(jsonl, 'utf8').trimEnd().split('\n').map((l) => JSON.parse(l));
      check('the JSON Lines file has a header record and 216 rows', records.length === 217 && records[0].mdd_export === 1 && records[0].rows === 216);
      check('the header record carries the snapshot ids', records[0].snapshot_ids.length === 1);

      const big = join(dir, 'big.csv');
      await app.type('#sql', SIX_WAY);
      await app.type('#export-path', big);
      await app.select('#export-format', 'csv');
      await app.click('#run-export');
      await app.waitFor(`document.querySelector('#busy-text').textContent.startsWith('执行中：导出')`, { what: 'the export to start' });
      await sleep(1500);
      await app.click('#cancel-button');
      await app.waitFor(`document.querySelector('#export-holder .error-box')?.dataset.code === 'CANCELLED'`, { what: 'the export to be cancelled', timeout: 15_000 });
      check('a cancelled export is CANCELLED', true);
      check('no file is left under the chosen name', !existsSync(big));
      check('no half-written .partial file is left', !existsSync(`${big}.partial`));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  },

  async diff_two_inputs_keeps_provenance_and_limits({ app, check }) {
    await openInputs(app, [desktop('a.dex')]);
    await openInputs(app, [desktop('b.dex'), desktop('c.dex')]);
    await nav(app, 'diff');
    await app.select('#diff-a', '1');
    await app.select('#diff-b', '2');
    await app.click('#run-diff');
    await app.waitFor(`!!document.querySelector('#diff-summary') || !!document.querySelector('#diff-result .error-box')`, { what: 'the comparison', timeout: 60_000 });
    const summary = await app.text('#diff-summary');
    check('the summary reports 5 differences', summary.includes('差异 5 项'), summary);
    check('both sides are shown as completely loaded', (await count(app, '#diff-result [data-side] .pill.ok')) === 2);
    const sides = await app.text('#diff-result');
    check('side A shows the input sha256', sides.includes(sha256(desktop('a.dex'))));
    check('side B shows both DEX members', sides.includes('b.dex') && sides.includes('c.dex'));
    check('the summary says equal opcodes do not prove equal operands', summary.includes('不等于方法相同'));
    const keys = await app.eval(`[...document.querySelectorAll('#diff-table tbody tr')].map(r => r.dataset.status + ' ' + r.dataset.key)`);
    const want = ['only_b Ldemo/C;', 'only_a Ldemo/A;->gone()V', 'only_b Ldemo/A;->added()V', 'opcodes_differ Ldemo/A;->body()V', 'only_b Ldemo/C;->only()V'];
    check('the default list is exactly the five differences', want.every((w) => keys.includes(w)) && keys.length === 5, JSON.stringify(keys));
    await app.select('#diff-status', '');
    await app.click('#diff-apply');
    await app.waitFor(`document.querySelectorAll('#diff-table tbody tr').length > 5`, { what: 'all entries' });
    const all = await app.eval(`[...document.querySelectorAll('#diff-table tbody tr')].map(r => r.dataset.status + ' ' + r.dataset.key)`);
    check('opcode-equal methods are listed with the cautious status', all.includes('opcodes_equal Ldemo/A;->ops()V') && all.includes('opcodes_equal Ldemo/A;->same()V'), JSON.stringify(all));
    await app.eval(`document.querySelector('#diff-table tr[data-key="Ldemo/A;->ops()V"]').click()`);
    await app.waitFor(`!!document.querySelector('#compare-smali')`, { what: 'the detail panel' });
    check('the detail says operands were not compared', (await app.text('#diff-detail')).includes('操作数'));
    await app.click('#compare-smali');
    await app.waitFor(`document.querySelector('#smali-diff-state')?.textContent.includes('不同')`, { what: 'the smali comparison' });
    const state = await app.text('#smali-diff-state');
    check('the smali comparison finds one changed line', state.includes('+1 行，-1 行'), state);
    const diffText = await app.text('#smali-diff');
    check('it shows the alpha and beta operands', diffText.includes('alpha') && diffText.includes('beta'));
    await app.eval(`document.querySelector('#diff-table tr[data-key="Ldemo/A;->same()V"]').click()`);
    await app.waitFor(`!!document.querySelector('#compare-smali')`, { what: 'the second detail panel' });
    await app.click('#compare-smali');
    await app.waitFor(`document.querySelector('#smali-diff-state')?.textContent.includes('完全相同')`, { what: 'the identical smali' });
    check('the equal pair is proven identical by its smali', true);
  },

  async capabilities_come_from_the_engine({ app, check }) {
    await nav(app, 'engine');
    await app.waitFor(`document.querySelectorAll('#tool-list .pill').length > 0`, { what: 'the tool list' });
    const shown = await app.eval(`[...document.querySelectorAll('#tool-list .pill')].map(p => p.textContent).sort()`);
    const listed = await app.eval(`window.__TAURI__.core.invoke('engine_info', {callId: 'e2e-info'}).then(i => i.tools.slice().sort())`);
    check('the tools shown are exactly the engine tools/list', JSON.stringify(shown) === JSON.stringify(listed), JSON.stringify(shown));
    check('the engine lists twelve tools', shown.length === 12, String(shown.length));
    const disabled = await app.eval(`[...document.querySelectorAll('#nav button')].filter(b => b.disabled).map(b => b.textContent)`);
    check('no view is disabled when every tool is listed', disabled.length === 0, JSON.stringify(disabled));
    // A settings change ends the engine process and clears what it had listed; two in a row leave moments in which
    // the shell has no tool list, and a second engine_info that finds the engine taken. The views must stay usable
    // through them: sample the buttons for three seconds while both restarts run.
    await app.click('#reset-settings');
    await app.click('#apply-settings');
    const greyed = await app.eval(`new Promise((resolve) => {
      const seen = new Set();
      const timer = setInterval(() => { for (const b of document.querySelectorAll('#nav button')) if (b.disabled) seen.add(b.dataset.view); }, 25);
      setTimeout(() => { clearInterval(timer); resolve([...seen]); }, 3000);
    })`);
    check('no view is greyed out while the engine restarts twice in a row', greyed.length === 0, JSON.stringify(greyed));
    await app.waitFor(`document.querySelectorAll('#tool-list .pill').length === 12 && document.querySelector('#engine-chip').dataset.state === 'ok'`, { what: 'the engine to list its tools again' });
    check('after the restarts the engine chip is not "cannot start"', !(await app.text('#engine-chip')).includes('无法启动'));
    const caps = await app.text('#capabilities-json');
    const profiles = JSON.parse(caps).profiles;
    check('the capabilities output is shown verbatim with every profile not admitted', profiles.length > 0 && profiles.every((p) => p.admitted === false), caps.slice(0, 120));
    check('the page says the capabilities output lags the tool list', (await app.text('#engine-info')).includes('以 tools/list 为准'));
  },

  async missing_engine_is_explained({ launch, check }) {
    const app = await launch({ MDD_ENGINE: join(tmpdir(), 'mdd-e2e-no-such-engine.exe') });
    try {
      await app.waitFor(`document.querySelector('#engine-chip')?.dataset.state === 'bad'`, { what: 'the chip to turn bad' });
      check('the chip says the engine cannot start', (await app.text('#engine-chip')).includes('无法启动'));
      const disabled = await app.eval(`[...document.querySelectorAll('#nav button')].filter(b => b.disabled).map(b => b.dataset.view)`);
      check('every view that needs an engine tool is disabled', ['inputs', 'query', 'browse', 'manifest', 'diff'].every((v) => disabled.includes(v)), JSON.stringify(disabled));
      check('the engine page stays available', !disabled.includes('engine'));
      const title = await app.eval(`document.querySelector('#nav button[data-view="inputs"]').title`);
      check('a disabled view names the tool the engine did not list', title.includes('open_dataset'), title);
      await app.waitFor(`document.querySelector('#view-engine') && !document.querySelector('#view-engine').hidden`, { what: 'the engine page to be shown' });
      const code = await app.eval(`document.querySelector('#engine-info .error-box')?.dataset.code`);
      check('the engine page shows ENGINE_NOT_FOUND', code === 'ENGINE_NOT_FOUND', code);
      check('the hint says how to fix it', (await app.text('#engine-info .error-box')).includes('MDD_ENGINE'));
    } finally {
      await app.close();
    }
  },

  async nothing_leaves_the_machine({ app, check }) {
    // what the page loaded before it tried anything itself
    const before = await app.eval(`performance.getEntriesByType('resource').map(r => r.name).filter(n => !n.startsWith(location.origin) && !n.startsWith('data:') && !n.startsWith('ipc:') && !n.includes('ipc.localhost'))`);
    check('the page loaded nothing from outside its own origin while starting', before.length === 0, JSON.stringify(before));
    const attempt = (script) => app.eval(`(async () => { try { ${script}; return 'allowed'; } catch (e) { return 'blocked'; } })()`);
    check('fetch to an external address is blocked', (await attempt(`await fetch('https://example.com/', {mode: 'no-cors'})`)) === 'blocked');
    check('XMLHttpRequest to an external address is blocked', (await app.eval(`new Promise((resolve) => { const x = new XMLHttpRequest(); x.onerror = () => resolve('blocked'); x.onload = () => resolve('allowed'); try { x.open('GET', 'https://example.com/'); x.send(); } catch (e) { resolve('blocked'); } })`)) === 'blocked');
    check('an external image is blocked', (await app.eval(`new Promise((resolve) => { const i = new Image(); i.onerror = () => resolve('blocked'); i.onload = () => resolve('allowed'); i.src = 'https://example.com/x.png'; })`)) === 'blocked');
  },

  async closing_the_window_ends_the_engine({ app, check }) {
    await openInputs(app, [desktop('a.dex')]);
    const engines = engineChildren(app.pid);
    check('the application has exactly one engine child process', engines.length === 1, JSON.stringify(engines));
    const errors = await app.pageErrors();
    check('the page raised no errors before the window was killed', errors.length === 0, errors.join(' | '));
    app.killApp();
    const deadline = Date.now() + 5000;
    while (engines.some(alive) && Date.now() < deadline) await sleep(100);
    check('the engine process is gone within 5 s of the application being killed', !engines.some(alive), JSON.stringify(engines));
  },

  async real_application_newpipe({ app, check }) {
    await openInputs(app, [NEWPIPE]);
    await app.waitFor(`document.querySelector('.dataset table.grid td')`, { what: 'the DEX member table', timeout: 60_000 });
    check('two DEX files are reported', (await app.text('.dataset')).includes('DEX 个数2'), (await app.text('.dataset')).slice(0, 300));
    await runSql(app, 'SELECT count(*) AS n FROM methods');
    check('the method count is 63560', (await firstCell(app)) === '63560', await firstCell(app));
    await nav(app, 'browse');
    await app.type('#class-search', 'schabi/newpipe/App;');
    await app.click('#search-classes');
    await app.waitFor(`document.querySelectorAll('#class-list tr.pick').length >= 1`, { what: 'the App class', timeout: 60_000 });
    await app.eval(`document.querySelector('#class-list tr.pick').click()`);
    await app.waitFor(`document.querySelectorAll('#method-list tr.pick').length >= 5`, { what: 'the App methods', timeout: 60_000 });
    await app.eval(`[...document.querySelectorAll('#method-list tr.pick')].find(r => r.textContent.includes('onCreate')).click()`);
    await app.waitFor(`!!document.querySelector('#smali-state')`, { what: 'onCreate smali', timeout: 60_000 });
    check('onCreate (504 lines) is shown in a partial first page', (await app.text('#smali-state')).includes('共 504 行'), await app.text('#smali-state'));
    await app.click('#smali-next');
    await app.waitFor(`document.querySelector('#smali-state').textContent.includes('已显示到末尾')`, { what: 'the end of onCreate', timeout: 60_000 });
    check('the second page reaches the end', true);
    await app.click('#load-callees');
    await app.waitFor(`document.querySelector('#xref-callees tr.pick') || document.querySelector('#xref-callees .error-box')`, { what: 'the callees', timeout: 120_000 });
    check('the callees are listed or the engine error is shown', true);
  },
};
