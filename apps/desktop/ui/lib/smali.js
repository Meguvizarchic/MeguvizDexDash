// Smali text is the engine's; this only finds the parts a reader wants to follow: method and field
// references, class types, string literals, labels and directives. Nothing is rewritten or interpreted.
const STRING = /"(?:[^"\\]|\\.)*"/g;
// an optional array prefix, a class type, and optionally `->member` with either a signature or a `:type`
const REFERENCE = /(\[*)(L[^;\s,{}()"]+;)(->[^\s(),:"]+(?:\([^)\s"]*\)[^\s,"]*|:[^\s,"]+))?/g;
const LABEL = /:[A-Za-z_][A-Za-z0-9_]*/g;

/** Split one smali line into tokens: {kind: 'text'|'str'|'method'|'field'|'type'|'label', text, desc?}. */
export function tokenizeLine(line) {
  const tokens = [];
  let last = 0;
  for (const match of line.matchAll(STRING)) {
    pushPlain(tokens, line.slice(last, match.index));
    tokens.push({ kind: 'str', text: match[0] });
    last = match.index + match[0].length;
  }
  pushPlain(tokens, line.slice(last));
  return tokens;
}

function pushPlain(tokens, text) {
  if (!text) return;
  let last = 0;
  for (const match of text.matchAll(REFERENCE)) {
    pushLabels(tokens, text.slice(last, match.index));
    const [whole, array, owner, member] = match;
    if (member && member.includes('(')) {
      tokens.push({ kind: 'method', text: whole, desc: owner + member });
    } else if (member) {
      tokens.push({ kind: 'field', text: whole, desc: owner + member });
    } else {
      tokens.push({ kind: 'type', text: whole, desc: owner, array: array.length });
    }
    last = match.index + whole.length;
  }
  pushLabels(tokens, text.slice(last));
}

function pushLabels(tokens, text) {
  if (!text) return;
  let last = 0;
  for (const match of text.matchAll(LABEL)) {
    if (match.index > last) tokens.push({ kind: 'text', text: text.slice(last, match.index) });
    tokens.push({ kind: 'label', text: match[0] });
    last = match.index + match[0].length;
  }
  if (last < text.length) tokens.push({ kind: 'text', text: text.slice(last) });
}

/** A line starting with a directive (`.method`, `.registers`, …): its length, else 0. */
export function directiveLength(line) {
  const match = /^\s*(\.[a-z-]+)/.exec(line);
  return match ? match[0].length : 0;
}

/** Split a descriptor `Lowner;->name(params)ret` into its parts, or null for something else. */
export function parseMethodDescriptor(desc) {
  const match = /^(L[^;]+;)->([^(]+)\((.*)\)(.+)$/.exec(desc ?? '');
  return match ? { owner: match[1], name: match[2], params: match[3], ret: match[4] } : null;
}
