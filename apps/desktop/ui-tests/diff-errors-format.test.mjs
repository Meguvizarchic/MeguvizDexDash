import assert from 'node:assert/strict';
import test from 'node:test';
import { AGREEMENTS, STATUS_LABEL, isAgreement, statusLabel, withContext } from '../ui/lib/diff.js';
import { describeError, isCancelled } from '../ui/lib/errors.js';
import { accessWords, baseName, bytes, millis, number, shortId } from '../ui/lib/format.js';

test('a status that is only an agreement is never worded as "identical"', () => {
  assert.ok(statusLabel('opcodes_equal').includes('操作数未比较'));
  assert.ok(isAgreement('opcodes_equal') && isAgreement('no_code_both') && isAgreement('facts_equal'));
  for (const status of ['only_a', 'only_b', 'count_differs', 'opcodes_differ', 'code_vs_no_code', 'facts_differ']) {
    assert.ok(!isAgreement(status), status);
  }
  assert.deepEqual(AGREEMENTS.every((s) => s in STATUS_LABEL), true);
  assert.equal(statusLabel('something_new'), 'something_new', 'an unknown status is shown, not hidden');
});

test('context keeps every changed line and says how many unchanged lines it skipped', () => {
  const lines = [];
  for (let i = 0; i < 20; i += 1) lines.push({ op: '=', text: `l${i}` });
  lines[10] = { op: '-', text: 'old' };
  lines.splice(11, 0, { op: '+', text: 'new' });
  const shown = withContext(lines, 2);
  assert.deepEqual(shown.map((l) => l.op), ['gap', '=', '=', '-', '+', '=', '=', 'gap']);
  assert.equal(shown[0].skipped, 8);
  assert.equal(shown[shown.length - 1].skipped, 7, "21 lines: 8 before the context, 6 inside it, 7 after");
  const accounted = shown.reduce((n, l) => n + (l.op === 'gap' ? l.skipped : 1), 0);
  assert.equal(accounted, lines.length, 'nothing is dropped without a marker');
});

test('an identical text has no lines to show but is accounted for', () => {
  const lines = [{ op: '=', text: 'a' }, { op: '=', text: 'b' }];
  assert.deepEqual(withContext(lines, 3), [{ op: 'gap', skipped: 2 }]);
  assert.deepEqual(withContext([], 3), []);
});

test('an exhausted SQL budget says what to do and that the result was not returned as complete', () => {
  const e = describeError({ code: 'QUOTA_EXCEEDED', message: 'SQL_WORK_BUDGET' });
  assert.ok(e.hint.includes('引擎”页调高预算'));
  assert.ok(e.hint.includes('没有被截断后当作完整结果返回'));
  assert.equal(describeError({ code: 'QUOTA_EXCEEDED', message: 'MAX_RESULT_BYTES' }).hint.includes('调高预算'), false);
});

test('every shell and engine failure has words, and an unknown one keeps its code and message', () => {
  for (const code of ['DEADLINE_EXCEEDED', 'CANCELLED', 'ENGINE_BUSY', 'ENGINE_NOT_FOUND', 'ENGINE_LOST', 'INVALID_INPUT',
    'INPUT_NOT_FOUND', 'UNSUPPORTED_QUERY', 'INVALID_ARGUMENT', 'UNKNOWN_HANDLE', 'EXPORT_COUNT']) {
    assert.ok(describeError({ code, message: 'm' }).hint.length > 0, code);
  }
  const odd = describeError({ code: 'SOMETHING_ELSE', message: 'details here' });
  assert.equal(odd.code, 'SOMETHING_ELSE');
  assert.equal(odd.message, 'details here');
  assert.equal(odd.hint, '');
  assert.equal(describeError(undefined).code, 'UNKNOWN');
  assert.ok(isCancelled({ code: 'CANCELLED' }) && !isCancelled({ code: 'DEADLINE_EXCEEDED' }) && !isCancelled(undefined));
});

test('numbers, sizes and durations', () => {
  assert.equal(number(63560), '63,560');
  assert.equal(number('x'), 'x');
  assert.equal(bytes(512), '512 B');
  assert.equal(bytes(1024), '1.00 KiB');
  assert.equal(bytes(10885562), '10.4 MiB');
  assert.equal(millis(12), '12 ms');
  assert.equal(millis(1500), '1.50 s');
  assert.equal(millis(12500), '12.5 s');
});

test('short ids, file names and access flags', () => {
  assert.equal(shortId('snapshot-0123456789abcdef0123', 12), 'snapshot-012…');
  assert.equal(shortId('short'), 'short');
  assert.equal(baseName('D:\\a\\b\\App.apk'), 'App.apk');
  assert.equal(baseName('/x/y/z.dex'), 'z.dex');
  assert.equal(accessWords(0x9), 'public static');
  assert.equal(accessWords(0x401), 'public abstract');
  assert.equal(accessWords('x'), '');
});
