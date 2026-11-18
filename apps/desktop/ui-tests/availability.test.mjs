import assert from 'node:assert/strict';
import test from 'node:test';
import { adoptInfo, viewAvailability } from '../ui/lib/availability.js';

const NEEDS = ['query', 'decode'];
const started = { start: { ok: true, started: true } };

test('before the engine information has arrived nothing is greyed out', () => {
  assert.deepEqual(viewAvailability(null, [], NEEDS), { available: true, missing: [] });
});

test('a view whose tools are all listed is available', () => {
  assert.equal(viewAvailability(started, ['query', 'decode', 'list_tables'], NEEDS).available, true);
});

test('a listed set that lacks a needed tool makes the view unavailable and names what is missing', () => {
  const result = viewAvailability(started, ['query', 'list_tables'], NEEDS);
  assert.equal(result.available, false);
  assert.deepEqual(result.missing, ['decode']);
});

test('an empty list from an engine that started is unknown, not "nothing listed": the views stay usable', () => {
  // this is what the shell reports while a settings change is restarting the engine
  const result = viewAvailability(started, [], NEEDS);
  assert.equal(result.available, true);
  assert.deepEqual(result.missing, []);
  assert.equal(viewAvailability(started, undefined, NEEDS).available, true);
});

test('an engine that could not start disables every view that needs a tool, and names the tools', () => {
  const failed = { start: { ok: false, error: { code: 'ENGINE_NOT_FOUND' } } };
  const result = viewAvailability(failed, [], NEEDS);
  assert.equal(result.available, false);
  assert.deepEqual(result.missing, NEEDS);
  // even a stale list does not rescue it
  assert.equal(viewAvailability(failed, ['query', 'decode'], NEEDS).available, false);
});

test('a view that needs no tool is available whatever the engine did', () => {
  assert.equal(viewAvailability({ start: { ok: false } }, [], []).available, true);
  assert.equal(viewAvailability(started, ['query'], []).available, true);
});

const known = { start: { ok: true, started: true }, tools: ['query'], version: { engine_version: '1' } };
const busy = { start: { ok: false, error: { code: 'ENGINE_BUSY' } }, tools: [] };
const missingEngine = { start: { ok: false, error: { code: 'ENGINE_NOT_FOUND' } }, tools: [] };

test('an engine that was only busy is not reported as one that cannot start: what was known stays', () => {
  assert.equal(adoptInfo(known, busy), known);
});

test('a busy reply is all there is when nothing was known yet', () => {
  assert.equal(adoptInfo(null, busy), busy);
});

test('a real start failure replaces what was known, and so does any ordinary reply', () => {
  assert.equal(adoptInfo(known, missingEngine), missingEngine);
  const fresh = { start: { ok: true, started: false }, tools: ['query', 'decode'] };
  assert.equal(adoptInfo(known, fresh), fresh);
  // a failure that merely mentions busy in its text is still a failure
  const worded = { start: { ok: false, error: { code: 'ENGINE_START_FAILED', message: 'ENGINE_BUSY' } } };
  assert.equal(adoptInfo(known, worded), worded);
});
