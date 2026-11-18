export function number(n) {
  const value = Number(n);
  return Number.isFinite(value) ? value.toLocaleString('en-US') : String(n);
}

export function bytes(n) {
  const value = Number(n);
  if (!Number.isFinite(value)) return String(n);
  if (value < 1024) return `${value} B`;
  const units = ['KiB', 'MiB', 'GiB', 'TiB'];
  let scaled = value / 1024;
  let unit = 0;
  while (scaled >= 1024 && unit < units.length - 1) {
    scaled /= 1024;
    unit += 1;
  }
  return `${scaled.toFixed(scaled < 10 ? 2 : 1)} ${units[unit]}`;
}

export function millis(ms) {
  const value = Number(ms);
  if (!Number.isFinite(value)) return String(ms);
  if (value < 1000) return `${Math.round(value)} ms`;
  return `${(value / 1000).toFixed(value < 10_000 ? 2 : 1)} s`;
}

export function shortId(id, keep = 12) {
  const text = String(id ?? '');
  return text.length > keep + 4 ? `${text.slice(0, keep)}…` : text;
}

export function baseName(path) {
  const parts = String(path).split(/[\\/]/);
  return parts[parts.length - 1] || String(path);
}

/** Access flags as the words smali uses, for the flags that matter when reading a class list. */
export function accessWords(flags) {
  const value = Number(flags);
  if (!Number.isFinite(value)) return '';
  const table = [
    [0x1, 'public'], [0x2, 'private'], [0x4, 'protected'], [0x8, 'static'], [0x10, 'final'],
    [0x20, 'synchronized'], [0x40, 'volatile'], [0x80, 'transient'], [0x100, 'native'],
    [0x200, 'interface'], [0x400, 'abstract'], [0x1000, 'synthetic'], [0x2000, 'annotation'], [0x4000, 'enum'],
  ];
  return table.filter(([bit]) => value & bit).map(([, word]) => word).join(' ');
}
