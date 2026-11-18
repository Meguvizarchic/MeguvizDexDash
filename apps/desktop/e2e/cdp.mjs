// Drives the real MeguvizDexDash window over the Chrome DevTools protocol that WebView2 exposes when it
// is started with --remote-debugging-port (Windows). No dependency: Node's own fetch and WebSocket.
//
// This is a test driver for the built application, not part of it: the application contains no test hook.
import { execFileSync, spawn } from 'node:child_process';
import { mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { AppBase } from './app-base.mjs';

export class App extends AppBase {
  constructor(child, socket, userData, port) {
    super();
    this.child = child;
    this.socket = socket;
    this.userData = userData;
    this.port = port;
    this.nextId = 0;
    this.pending = new Map();
    this.consoleErrors = [];
    this.exited = false;
    child.once('exit', () => { this.exited = true; });
    socket.addEventListener('message', (event) => this.#message(JSON.parse(event.data)));
  }

  get pid() {
    return this.child.pid;
  }

  killApp() {
    this.killed = true;
    this.child.kill();
  }

  async pageErrors() {
    return this.consoleErrors;
  }

  async environment() {
    const version = await this.send('Browser.getVersion');
    return { webview: version.product, userAgent: version.userAgent };
  }

  #message(message) {
    if (message.id !== undefined) {
      const waiter = this.pending.get(message.id);
      if (waiter) {
        this.pending.delete(message.id);
        if (message.error) waiter.reject(new Error(`${waiter.method}: ${message.error.message}`));
        else waiter.resolve(message.result);
      }
    } else if (message.method === 'Runtime.exceptionThrown') {
      this.consoleErrors.push(message.params.exceptionDetails?.exception?.description ?? 'exception');
    } else if (message.method === 'Runtime.consoleAPICalled' && message.params.type === 'error') {
      this.consoleErrors.push(message.params.args.map((a) => a.value ?? a.description).join(' '));
    }
  }

  send(method, params = {}) {
    const id = (this.nextId += 1);
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject, method });
      this.socket.send(JSON.stringify({ id, method, params }));
    });
  }

  /** Evaluate an expression in the page; promises are awaited and the value comes back as JSON. */
  async eval(expression) {
    const result = await this.send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true });
    if (result.exceptionDetails) {
      throw new Error(`page threw: ${result.exceptionDetails.exception?.description ?? result.exceptionDetails.text}`);
    }
    return result.result.value;
  }

  async screenshot(path) {
    const { data } = await this.send('Page.captureScreenshot', { format: 'png' });
    writeFileSync(path, Buffer.from(data, 'base64'));
  }

  async close() {
    try { this.socket.close(); } catch { /* already closed */ }
    if (!this.exited) {
      this.child.kill();
      await new Promise((resolve) => { if (this.exited) resolve(); else this.child.once('exit', resolve); });
    }
    await sleep(300);
    rmSync(this.userData, { recursive: true, force: true });
  }
}

async function targets(port) {
  const response = await fetch(`http://127.0.0.1:${port}/json/list`);
  return response.json();
}

const RUNTIME_CLIENT = '{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}';

/** Read-only: which WebView2 Runtime versions the registry knows. The window cannot start without one. */
function registeredRuntimes() {
  const found = [];
  for (const root of ['HKLM\\SOFTWARE\\WOW6432Node', 'HKLM\\SOFTWARE', 'HKCU\\SOFTWARE']) {
    try {
      const out = execFileSync('reg', ['query', `${root}\\Microsoft\\EdgeUpdate\\Clients\\${RUNTIME_CLIENT}`, '/v', 'pv'], {
        encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 10_000,
      });
      found.push(`${root} ${/pv\s+REG_SZ\s+(\S+)/.exec(out)?.[1] ?? 'registered, no version'}`);
    } catch { /* not registered under this root */ }
  }
  return found.length ? found.join('; ') : 'none registered';
}

/** Read-only: how many WebView2 browser/helper processes exist on the machine right now. */
function webviewProcesses() {
  try {
    const out = execFileSync('tasklist', ['/FI', 'IMAGENAME eq msedgewebview2.exe', '/NH', '/FO', 'CSV'], {
      encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 10_000,
    });
    return String(out.split('\n').filter((line) => line.toLowerCase().includes('msedgewebview2.exe')).length);
  } catch (error) {
    return `unknown (${error.code ?? error.message})`;
  }
}

/** Read-only: the title Windows reports for the application's window. A runtime that is missing makes the
 *  application stop on a modal "Could not find the WebView2 Runtime" box, which this shows as its title. */
function windowTitle(pid) {
  try {
    const out = execFileSync('tasklist', ['/V', '/FI', `PID eq ${pid}`, '/NH', '/FO', 'CSV'], {
      encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 10_000,
    });
    const fields = out.trim().split('","');
    return fields.length > 1 ? fields[fields.length - 1].replace(/"$/, '') : 'no such process';
  } catch (error) {
    return `unknown (${error.code ?? error.message})`;
  }
}

/** What a window that never appeared leaves behind, for the error message: a runtime that cannot start
 *  (nothing in the user data folder, no helper processes) looks different from a port that never opened. */
function launchFacts({ child, port, stderr, userData, probe }) {
  let entries;
  try { entries = String(readdirSync(userData).length); } catch (error) { entries = `unreadable (${error.code ?? error.message})`; }
  return [
    `no page target on port ${port} within 30 s`,
    `application: ${child.exitCode === null ? `pid ${child.pid}, still running, window title "${windowTitle(child.pid)}"` : `exited with ${child.exitCode}`}; debugging port: ${probe.answered ? probe.last : `never answered (${probe.last})`}`,
    `WebView2 Runtime: ${registeredRuntimes()}; msedgewebview2.exe processes on the machine: ${webviewProcesses()}; user data folder entries: ${entries}`,
    `stderr: ${stderr.trim() || '(empty)'}`,
  ].join('\n');
}

/** A launch that failed must not leave the application, or its user data folder, behind. */
async function abandon(child, userData) {
  if (child.exitCode === null) {
    child.kill();
    await new Promise((resolve) => { if (child.exitCode !== null) resolve(); else child.once('exit', resolve); });
  }
  await sleep(300);
  try { rmSync(userData, { recursive: true, force: true, maxRetries: 5 }); } catch { /* still in use: the temp folder is cleaned with the machine */ }
}

/** Start the application and connect to its window. */
export async function launch({ exe, port = 9333, env = {} }) {
  const userData = mkdtempSync(join(tmpdir(), 'mdd-desktop-e2e-'));
  const child = spawn(exe, [], {
    env: {
      ...process.env,
      ...env,
      WEBVIEW2_USER_DATA_FOLDER: userData,
      WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS: `--remote-debugging-port=${port}`,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let stderr = '';
  child.stderr.on('data', (chunk) => { stderr += chunk; });
  let page;
  const probe = { answered: false, last: 'not tried' };
  const started = Date.now();
  while (!page && Date.now() - started < 30_000) {
    if (child.exitCode !== null) {
      await abandon(child, userData);
      throw new Error(`the application exited with ${child.exitCode}: ${stderr}`);
    }
    try {
      const list = await targets(port);
      probe.answered = true;
      probe.last = `answered with ${list.length} target(s): ${list.map((t) => t.type).join(', ') || 'none'}`;
      page = list.find((t) => t.type === 'page' && !t.url.startsWith('devtools://'));
    } catch (error) {
      probe.last = error.cause?.code ?? error.message; // the port is not open yet
    }
    if (!page) await sleep(200);
  }
  if (!page) {
    const message = launchFacts({ child, port, stderr, userData, probe });
    await abandon(child, userData);
    throw new Error(message);
  }
  const socket = new WebSocket(page.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => {
    socket.addEventListener('open', resolve, { once: true });
    socket.addEventListener('error', () => reject(new Error('cannot connect to the page')), { once: true });
  });
  const app = new App(child, socket, userData, port);
  await app.send('Runtime.enable');
  await app.send('Page.enable');
  return app;
}
