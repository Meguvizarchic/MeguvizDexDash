import assert from 'node:assert/strict';
import test from 'node:test';
import { NULL_MARK, cellKind, cellText, cellTitle, rawValue, rowObject, shortText } from '../ui/lib/cells.js';

const cell = (type, value) => ({ type, value });

test('NULL, empty text and the text "NULL" are three different things on screen', () => {
  assert.equal(cellText(cell('null', null)), NULL_MARK);
  assert.equal(cellText(cell('utf8', '')), '“”');
  assert.equal(cellText(cell('utf8', 'NULL')), 'NULL');
  assert.notEqual(cellText(cell('utf8', '')), cellText(cell('null', null)));
  assert.notEqual(cellText(cell('utf8', 'NULL')), cellText(cell('null', null)));
});

test('integers keep every digit: a 64-bit value is shown exactly as the engine sent it', () => {
  assert.equal(cellText(cell('uint64', '18446744073709551615')), '18446744073709551615');
  assert.equal(cellText(cell('int64', '-9223372036854775808')), '-9223372036854775808');
  assert.equal(cellText(cell('float64', 1.5)), '1.5');
  assert.equal(cellText(cell('float64', 'NaN')), 'NaN');
});

test('binary is shown as hex with a prefix and truncated only for display', () => {
  assert.equal(cellText(cell('binary', '00ff')), '0x00ff');
  const long = cell('binary', 'ab'.repeat(100));
  assert.ok(shortText(long).endsWith('…'));
  assert.ok(cellTitle(long).includes('100 bytes'));
  assert.ok(cellTitle(long).includes('ab'.repeat(100)), 'the title carries all of it');
});

test('a long text is cut for the table, never in the value', () => {
  const text = 'x'.repeat(500);
  assert.equal(shortText(cell('utf8', text), 160).length, 161);
  assert.equal(rawValue(cell('utf8', text)), text);
});

test('kinds drive the column styling', () => {
  assert.equal(cellKind(cell('null', null)), 'null');
  assert.equal(cellKind(cell('uint64', '1')), 'num');
  assert.equal(cellKind(cell('float64', 1)), 'num');
  assert.equal(cellKind(cell('binary', '00')), 'bin');
  assert.equal(cellKind(cell('utf8', 'a')), 'text');
  assert.equal(cellKind(undefined), 'text');
});

test('a row becomes an object by column name, with NULL as null and not as empty text', () => {
  const columns = [{ name: 'a' }, { name: 'b' }, { name: 'c' }];
  const row = [cell('uint64', '7'), cell('null', null), cell('utf8', '')];
  assert.deepEqual(rowObject(columns, row), { a: '7', b: null, c: '' });
});
