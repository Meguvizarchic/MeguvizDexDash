// What every driver of the real window offers the flows. A driver supplies `eval`, `screenshot`,
// `pageErrors`, `environment`, `pid`, `killApp` and `close`; the rest is built on `eval`.
import { setTimeout as sleep } from 'node:timers/promises';

export class AppBase {
  async waitFor(expression, { timeout = 20_000, what = expression } = {}) {
    const started = Date.now();
    let last;
    while (Date.now() - started < timeout) {
      try {
        last = await this.eval(expression);
        if (last) return last;
      } catch (error) {
        last = error.message;
      }
      await sleep(100);
    }
    throw new Error(`timed out waiting for ${what} (last: ${JSON.stringify(last)})`);
  }

  async click(selector) {
    await this.waitFor(`!!document.querySelector(${JSON.stringify(selector)})`, { what: `${selector} to exist` });
    await this.eval(`document.querySelector(${JSON.stringify(selector)}).click()`);
  }

  async type(selector, value) {
    await this.waitFor(`!!document.querySelector(${JSON.stringify(selector)})`, { what: `${selector} to exist` });
    await this.eval(`(() => { const e = document.querySelector(${JSON.stringify(selector)}); e.focus(); e.value = ${JSON.stringify(value)}; e.dispatchEvent(new Event('input', {bubbles: true})); e.dispatchEvent(new Event('change', {bubbles: true})); })()`);
  }

  async select(selector, value) {
    await this.type(selector, value);
  }

  text(selector) {
    return this.eval(`document.querySelector(${JSON.stringify(selector)})?.textContent ?? null`);
  }
}
