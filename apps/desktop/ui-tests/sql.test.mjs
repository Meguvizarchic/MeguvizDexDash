import assert from 'node:assert/strict';
import test from 'node:test';
import { containsPattern, hasOrderBy, like, oneStatement, quote, startsWithPattern } from '../ui/lib/sql.js';

test('a quote in user input stays inside the literal', () => {
  assert.equal(quote("O'Brien"), "'O''Brien'");
  assert.equal(quote("'; DROP TABLE x; --"), "'''; DROP TABLE x; --'");
  assert.equal(quote(''), "''");
});

test('the LIKE wildcards of the user text are made literal', () => {
  assert.equal(containsPattern('a_b%c'), '%a\\_b\\%c%');
  assert.equal(containsPattern('back\\slash'), '%back\\\\slash%');
  assert.equal(startsWithPattern('Lcom/a_b/'), 'Lcom/a\\_b/%');
  assert.equal(like('descriptor', containsPattern('x')), "descriptor LIKE '%x%' ESCAPE '\\'");
});

test('ORDER BY is found only where it is syntax', () => {
  assert.ok(hasOrderBy('SELECT * FROM t ORDER BY 1'));
  assert.ok(hasOrderBy('select * from t\norder\n  by a'));
  assert.ok(!hasOrderBy('SELECT * FROM t'));
  assert.ok(!hasOrderBy("SELECT 'order by' FROM t"));
  assert.ok(!hasOrderBy('SELECT * FROM t -- order by 1'));
  assert.ok(!hasOrderBy('SELECT * /* order by */ FROM t'));
  assert.ok(!hasOrderBy('SELECT reorder_by FROM t'));
});

test('one statement for the engine: trailing semicolons and blanks go, the text stays', () => {
  assert.equal(oneStatement('  SELECT 1 ;; \n'), 'SELECT 1');
  assert.equal(oneStatement('SELECT 1'), 'SELECT 1');
  assert.equal(oneStatement('SELECT 1; SELECT 2;'), 'SELECT 1; SELECT 2');
  assert.equal(oneStatement(';'), '');
});
