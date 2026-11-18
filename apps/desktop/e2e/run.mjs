// Runs the user flows of conformance/desktop/user-flow-cases.json against the built application.
//
//   node apps/desktop/e2e/run.mjs [--only id,id] [--record path]
//
// Environment: MDD_DESKTOP_EXE (the application), MDD_ENGINE (the engine, else found by the shell).
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { NEWPIPE, flows, repo } from './flows.mjs';

const here = fileURLToPath(new URL('.', import.meta.url));
const args = process.argv.slice(2);
const option = (name) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : undefined; };
const only = option('--only')?.split(',');
const recordPath = option('--record');

// WebView2 (Windows) is driven over the DevTools protocol, WebKitGTK (Linux) through WebDriver
const driverName = process.env.MDD_DRIVER ?? (process.platform === 'win32' ? 'cdp' : 'webdriver');
const { launch } = await import(driverName === 'cdp' ? './cdp.mjs' : './webdriver.mjs');
const exe = process.env.MDD_DESKTOP_EXE ?? join(here, '..', 'target', 'debug', process.platform === 'win32' ? 'mdd-desktop.exe' : 'mdd-desktop');
const cases = JSON.parse(readFileSync(join(repo, 'conformance', 'desktop', 'user-flow-cases.json'), 'utf8')).cases;
const OWN_LAUNCH = new Set(['missing_engine_is_explained']);
const sha256 = (path) => createHash('sha256').update(readFileSync(path)).digest('hex');

if (!existsSync(exe)) {
  console.error(`the application is not built: ${exe}`);
  process.exit(2);
}

const declared = new Set(cases.map((c) => c.id));
const missing = Object.keys(flows).filter((id) => !declared.has(id));
const unimplemented = cases.filter((c) => !flows[c.id]).map((c) => c.id);
if (missing.length || unimplemented.length) {
  console.error('cases and implementations differ:', { implementedButNotDeclared: missing, declaredButNotImplemented: unimplemented });
  process.exit(2);
}

let port = 9400;
const results = [];
let environment = null;

for (const testCase of cases) {
  if (only && !only.includes(testCase.id)) continue;
  const result = { id: testCase.id, title: testCase.title, acceptance: testCase.acceptance, status: 'passed', checks: [] };
  const started = Date.now();
  if (testCase.requires_local_input && !existsSync(NEWPIPE)) {
    result.status = 'not_run';
    result.reason = `${testCase.requires_local_input} is not present (a local, ignored file)`;
    results.push(result);
    console.log(`- ${testCase.id}: not_run (${result.reason})`);
    continue;
  }
  const check = (name, ok, detail = '') => {
    result.checks.push({ name, ok: Boolean(ok), ...(ok ? {} : { detail: String(detail) }) });
  };
  const start = (env = {}) => launch({ exe, port: (port += 1), env });
  let app = null;
  try {
    if (OWN_LAUNCH.has(testCase.id)) {
      await flows[testCase.id]({ launch: start, check });
    } else {
      app = await start();
      await app.waitFor(`document.querySelector('#engine-chip')?.dataset.state === 'ok'`, { what: 'the engine chip to turn ok' });
      if (!environment) {
        environment = {
          driver: driverName,
          ...(await app.environment()),
          engine: await app.eval(`window.__TAURI__.core.invoke('engine_info', { callId: 'environment' }).then((i) => ({ binary: i.binary, version: i.version }))`),
        };
      }
      await flows[testCase.id]({ app, check });
      // a flow that killed the window has nothing left to ask; it checks the page itself before the kill
      if (!app.killed) {
        const errors = await app.pageErrors();
        check('the page raised no errors', errors.length === 0, errors.join(' | '));
      }
    }
  } catch (error) {
    result.status = 'failed';
    result.error = String(error?.stack ?? error).split('\n').slice(0, 6).join('\n');
  } finally {
    if (app) await app.close().catch(() => {});
  }
  if (result.checks.some((c) => !c.ok)) result.status = 'failed';
  if (result.status === 'passed' && result.checks.length === 0) result.status = 'failed', result.error = 'the flow made no checks';
  result.seconds = Number(((Date.now() - started) / 1000).toFixed(1));
  results.push(result);
  const failed = result.checks.filter((c) => !c.ok);
  console.log(`${result.status === 'passed' ? '✓' : '✗'} ${testCase.id} (${result.seconds}s, ${result.checks.length} checks)`);
  for (const c of failed) console.log(`    FAILED: ${c.name}${c.detail ? ` — ${c.detail}` : ''}`);
  if (result.error) console.log(`    ERROR: ${result.error}`);
}

const summary = {
  passed: results.filter((r) => r.status === 'passed').length,
  failed: results.filter((r) => r.status === 'failed').length,
  not_run: results.filter((r) => r.status === 'not_run').length,
};
console.log(summary);

if (recordPath) {
  const record = {
    schema_version: 'mdd.desktop-workflow-run.v1',
    task: 'MDD-073',
    platform: { os: process.platform, arch: process.arch, node: process.version, driver: environment?.driver, webview: environment?.webview, userAgent: environment?.userAgent },
    engine: environment?.engine ?? null,
    application: { path: exe.replace(repo, '<repo>'), sha256: sha256(exe) },
    cases_file_sha256: sha256(join(repo, 'conformance', 'desktop', 'user-flow-cases.json')),
    only: only ?? null,
    summary,
    results,
  };
  mkdirSync(dirname(resolve(recordPath)), { recursive: true });
  writeFileSync(recordPath, `${JSON.stringify(record, null, 2)}\n`);
  console.log('recorded', recordPath);
}
process.exit(summary.failed ? 1 : 0);
