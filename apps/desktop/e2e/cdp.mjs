// Drives the real MeguvizDexDash window over the Chrome DevTools protocol that WebView2 exposes when it
// is started with --remote-debugging-port (Windows). No dependency: Node's own fetch and WebSocket.
//
// This is a test driver for the built application, not part of it: the application contains no test hook.
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
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
  const started = Date.now();
  while (!page && Date.now() - started < 30_000) {
    if (child.exitCode !== null) throw new Error(`the application exited with ${child.exitCode}: ${stderr}`);
    try {
      page = (await targets(port)).find((t) => t.type === 'page' && !t.url.startsWith('devtools://'));
    } catch { /* the port is not open yet */ }
    if (!page) await sleep(200);
  }
  if (!page) throw new Error(`no page target on port ${port}: ${stderr}`);
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
