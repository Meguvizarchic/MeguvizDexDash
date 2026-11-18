// Drives the real window through WebDriver, for the platforms where it is a WebKitGTK window (Linux):
// `tauri-driver` starts the application under WebKitWebDriver. Same interface as cdp.mjs, no dependency.
//
// Needs `tauri-driver` and `WebKitWebDriver` on PATH and a display (CI uses xvfb-run).
import { execFileSync, spawn } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { setTimeout as sleep } from 'node:timers/promises';
import { AppBase } from './app-base.mjs';

class WebDriverApp extends AppBase {
  constructor(driver, base, session, exe) {
    super();
    this.driver = driver;
    this.base = base;
    this.session = session;
    this.exe = exe;
    this.stderr = '';
    driver.stderr.on('data', (chunk) => { this.stderr += chunk; });
  }

  async command(method, path, body) {
    const response = await fetch(`${this.base}${path}`, {
      method,
      headers: { 'content-type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const json = await response.json();
    if (json.value?.error) throw new Error(`${method} ${path}: ${json.value.error}: ${json.value.message}`);
    return json.value;
  }

  get pid() {
    try {
      const out = execFileSync('pgrep', ['-n', '-f', this.exe], { encoding: 'utf8' });
      return Number(out.split(/\s+/u).filter(Boolean).pop());
    } catch {
      return undefined;
    }
  }

  killApp() {
    this.killed = true;
    process.kill(this.pid, 'SIGKILL');
  }

  async eval(expression) {
    const script = `const done = arguments[arguments.length - 1];
      (async () => (${expression}))().then((v) => done({ ok: true, v }), (e) => done({ ok: false, e: String((e && e.stack) || e) }));`;
    const out = await this.command('POST', `/session/${this.session}/execute/async`, { script, args: [] });
    if (!out.ok) throw new Error(`page threw: ${out.e}`);
    return out.v;
  }

  async pageErrors() {
    return (await this.eval('window.__mddErrors ?? []')) ?? [];
  }

  async environment() {
    return { webview: 'WebKitGTK (WebDriver)', userAgent: await this.eval('navigator.userAgent') };
  }

  async screenshot(path) {
    const data = await this.command('GET', `/session/${this.session}/screenshot`);
    writeFileSync(path, Buffer.from(data, 'base64'));
  }

  async close() {
    try { await this.command('DELETE', `/session/${this.session}`); } catch { /* the application may be gone already */ }
    this.driver.kill();
    await sleep(500);
  }
}

export async function launch({ exe, port = 4444, env = {} }) {
  const driver = spawn('tauri-driver', ['--port', String(port), '--native-port', String(port + 1000)], {
    env: { ...process.env, ...env },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let stderr = '';
  driver.stderr.on('data', (chunk) => { stderr += chunk; });
  const base = `http://127.0.0.1:${port}`;
  const started = Date.now();
  for (;;) {
    if (driver.exitCode !== null) throw new Error(`tauri-driver exited with ${driver.exitCode}: ${stderr}`);
    try {
      if ((await fetch(`${base}/status`)).ok) break;
    } catch { /* not listening yet */ }
    if (Date.now() - started > 30_000) throw new Error(`tauri-driver did not start: ${stderr}`);
    await sleep(200);
  }
  const created = await fetch(`${base}/session`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ capabilities: { alwaysMatch: { 'tauri:options': { application: exe } } } }),
  });
  const body = await created.json();
  if (body.value?.error) {
    driver.kill();
    throw new Error(`cannot start the application: ${body.value.error}: ${body.value.message}\n${stderr}`);
  }
  const app = new WebDriverApp(driver, base, body.value.sessionId, exe);
  await app.command('POST', `/session/${app.session}/timeouts`, { script: 180_000 });
  await app.eval(`(() => { window.__mddErrors = []; addEventListener('error', (e) => window.__mddErrors.push(String(e.message))); addEventListener('unhandledrejection', (e) => window.__mddErrors.push(String(e.reason))); return true; })()`);
  return app;
}
