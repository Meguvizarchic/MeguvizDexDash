// How one typed cell of an engine result is shown. The engine sends every value as
// {"type": ..., "value": ...}: integers as decimal strings (64-bit values do not survive a JSON number),
// binary as lower-case hex, NULL as type "null". NULL, empty text and the text "NULL" stay visibly apart.
export const NULL_MARK = '∅';
const BINARY_PREVIEW = 48;

export function cellKind(cell) {
  switch (cell?.type) {
    case 'null': return 'null';
    case 'uint64':
    case 'int64':
    case 'float64': return 'num';
    case 'binary': return 'bin';
    default: return 'text';
  }
}

export function cellText(cell) {
  if (!cell || cell.type === 'null' || cell.value === null || cell.value === undefined) return NULL_MARK;
  if (cell.type === 'binary') return `0x${cell.value}`;
  if (cell.value === '') return '“”'; // an empty string, shown as a pair of quotes
  return String(cell.value);
}

export function cellTitle(cell) {
  if (!cell) return '';
  if (cell.type === 'null') return 'NULL';
  if (cell.type === 'binary') return `binary, ${cell.value.length / 2} bytes: 0x${cell.value}`;
  return `${cell.type}: ${cell.value}`;
}

export function shortText(cell, limit = 160) {
  const text = cellText(cell);
  const shown = cell?.type === 'binary' && text.length > BINARY_PREVIEW + 2
    ? `${text.slice(0, BINARY_PREVIEW + 2)}…`
    : text;
  return shown.length > limit ? `${shown.slice(0, limit)}…` : shown;
}

/** The statement's rows as plain strings, for places that need a value rather than a display. */
export function rawValue(cell) {
  if (!cell || cell.type === 'null') return null;
  return cell.value;
}

export function rowObject(columns, row) {
  const out = {};
  columns.forEach((column, i) => { out[column.name] = rawValue(row[i]); });
  return out;
}
