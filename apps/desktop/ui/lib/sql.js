// Building SQL text for the queries the views run on the user's behalf. User input only ever enters a
// statement as a quoted literal, never as syntax.
export function quote(value) {
  return `'${String(value).replaceAll("'", "''")}'`;
}

export const LIKE_ESCAPE = '\\';

/** A LIKE pattern matching `text` anywhere, with the pattern's own wildcards made literal. */
export function containsPattern(text) {
  return `%${escapeLike(text)}%`;
}

export function startsWithPattern(text) {
  return `${escapeLike(text)}%`;
}

function escapeLike(text) {
  return String(text).replace(/[\\%_]/g, (c) => LIKE_ESCAPE + c);
}

/** `column LIKE 'pattern' ESCAPE '\'` */
export function like(column, pattern) {
  return `${column} LIKE ${quote(pattern)} ESCAPE ${quote(LIKE_ESCAPE)}`;
}

export function hasOrderBy(sql) {
  // outside of quoted text and comments: good enough for an advisory, never used to decide a result
  const bare = String(sql)
    .replace(/--[^\n]*/g, ' ')
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/'(?:[^']|'')*'/g, "''")
    .replace(/"(?:[^"]|"")*"/g, '""');
  return /\border\s+by\b/i.test(bare);
}

/** One statement for the engine: the user's text without trailing semicolons and blank space. */
export function oneStatement(sql) {
  return String(sql).trim().replace(/[;\s]+$/u, '');
}
