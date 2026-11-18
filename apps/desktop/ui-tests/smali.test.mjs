import assert from 'node:assert/strict';
import test from 'node:test';
import { directiveLength, parseMethodDescriptor, tokenizeLine } from '../ui/lib/smali.js';

const kinds = (line) => tokenizeLine(line).filter((t) => t.kind !== 'text').map((t) => `${t.kind}:${t.desc ?? t.text}`);

test('an invoke line yields a method reference with the descriptor the engine uses', () => {
  assert.deepEqual(kinds('    invoke-static {}, Ldemo/B;->bar()V'), ['method:Ldemo/B;->bar()V']);
  assert.deepEqual(
    kinds('    invoke-virtual {p0, v1}, Lorg/schabi/newpipe/App;->attach(Landroid/content/Context;I)Ljava/lang/String;'),
    ['method:Lorg/schabi/newpipe/App;->attach(Landroid/content/Context;I)Ljava/lang/String;'],
  );
});

test('field references and plain types are told apart', () => {
  assert.deepEqual(kinds('    sget-object v0, Landroid/os/Build;->MODEL:Ljava/lang/String;'),
    ['field:Landroid/os/Build;->MODEL:Ljava/lang/String;']);
  assert.deepEqual(kinds('    new-instance v0, Ljava/lang/StringBuilder;'), ['type:Ljava/lang/StringBuilder;']);
  const array = tokenizeLine('    new-array v0, v1, [[Lfoo/Bar;').find((t) => t.kind === 'type');
  assert.equal(array.desc, 'Lfoo/Bar;');
  assert.equal(array.array, 2);
});

test('nothing inside a string literal is read as a reference', () => {
  const tokens = tokenizeLine('    const-string v0, "Lfake/Class;->name()V and :label"');
  assert.deepEqual(tokens.filter((t) => t.kind === 'method' || t.kind === 'type' || t.kind === 'label'), []);
  assert.equal(tokens.find((t) => t.kind === 'str').text, '"Lfake/Class;->name()V and :label"');
});

test('a string with an escaped quote stays one token', () => {
  const tokens = tokenizeLine('    const-string v0, "say \\"hi\\" Lx/Y;"');
  assert.equal(tokens.filter((t) => t.kind === 'str').length, 1);
  assert.equal(tokens.filter((t) => t.kind === 'type').length, 0);
});

test('labels are found, including inside a catch line', () => {
  assert.deepEqual(kinds('    :cond_0'), ['label::cond_0']);
  assert.deepEqual(kinds('    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0'),
    ['type:Ljava/lang/Exception;', 'label::try_start_0', 'label::try_end_0', 'label::catch_0']);
});

test('tokens put back together are exactly the line', () => {
  for (const line of [
    '    invoke-static {}, Ldemo/B;->bar()V',
    '    const-string v0, "a, b; c"',
    '    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0',
    '',
    'plain text with no references',
  ]) {
    assert.equal(tokenizeLine(line).map((t) => t.text).join(''), line);
  }
});

test('a directive is recognised at the start of a line only', () => {
  assert.equal(directiveLength('.method public static foo()V'), '.method'.length);
  assert.equal(directiveLength('    .registers 13'), '    .registers'.length);
  assert.equal(directiveLength('    invoke-static {}, Lx/Y;->z()V'), 0);
  assert.equal(directiveLength('    const-string v0, ".method"'), 0);
});

test('a method descriptor splits into owner, name, parameters and return type', () => {
  assert.deepEqual(parseMethodDescriptor('Lfoo/Bar;->baz(ILjava/lang/String;)[I'),
    { owner: 'Lfoo/Bar;', name: 'baz', params: 'ILjava/lang/String;', ret: '[I' });
  assert.equal(parseMethodDescriptor('Lfoo/Bar;->field:I'), null);
  assert.equal(parseMethodDescriptor(undefined), null);
});
