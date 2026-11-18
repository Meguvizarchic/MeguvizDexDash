import assert from 'node:assert/strict';
import test from 'node:test';
import { describePage, previousOffset } from '../ui/lib/pager.js';

test('a page with a next_offset is never described as the whole result', () => {
  const page = describePage({ offset: 0, rows: 50, nextOffset: 50, truncated: true });
  assert.equal(page.complete, false);
  assert.ok(page.text.includes('后面还有未加载的行'));
  assert.equal(page.from, 1);
  assert.equal(page.to, 50);
});

test('truncated alone is enough to call the page partial', () => {
  assert.equal(describePage({ offset: 0, rows: 3, nextOffset: null, truncated: true }).complete, false);
});

test('the last page says it is the last and gives the total', () => {
  const page = describePage({ offset: 200, rows: 16, nextOffset: null, truncated: false });
  assert.equal(page.complete, true);
  assert.ok(page.text.includes('已是最后一页（结果共 216 行）'), page.text);
});

test('a page whose next_offset is absent and which is not truncated is the last page, not an open-ended one', () => {
  const page = describePage({ offset: 200, rows: 16, nextOffset: undefined, truncated: false });
  assert.equal(page.complete, true);
  assert.equal(describePage({ offset: 0, rows: 3 }).complete, true);
  // but a present next_offset of 0 is still "more": zero is an offset, not "nothing"
  assert.equal(describePage({ offset: 0, rows: 3, nextOffset: 0 }).complete, false);
});

test('an empty first page is a confirmed empty result; an empty later page is past the end', () => {
  const empty = describePage({ offset: 0, rows: 0, nextOffset: null, truncated: false });
  assert.ok(empty.complete && empty.text.includes('0 行（引擎确认结果已完整）'));
  const beyond = describePage({ offset: 400, rows: 0, nextOffset: null, truncated: false });
  assert.ok(beyond.complete && beyond.text.includes('已超出结果末尾'));
});

test('undefined next_offset counts as "no more", like null', () => {
  assert.equal(describePage({ offset: 0, rows: 2 }).complete, true);
});

test('the previous page never goes below zero', () => {
  assert.equal(previousOffset(200, 50), 150);
  assert.equal(previousOffset(30, 50), 0);
  assert.equal(previousOffset(0, 50), 0);
});
