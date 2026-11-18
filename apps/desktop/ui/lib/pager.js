// What a page of an engine result says about the rest of the result. A page is never allowed to read as
// "the whole answer" unless the engine said so: no next_offset and not truncated.
export function describePage({ offset = 0, rows = 0, nextOffset = null, truncated = false }) {
  const from = rows > 0 ? offset + 1 : 0;
  const to = offset + rows;
  // an absent next_offset arrives as undefined and the default above makes it null: no more rows
  const more = nextOffset !== null;
  if (more || truncated) {
    return {
      complete: false,
      from,
      to,
      text: `已加载第 ${from}–${to} 行；后面还有未加载的行（总数未知，下一页从偏移 ${nextOffset ?? to} 开始）`,
    };
  }
  if (rows === 0 && offset === 0) {
    return { complete: true, from, to, text: '结果为空：0 行（引擎确认结果已完整）' };
  }
  if (rows === 0) {
    return { complete: true, from, to, text: `这一页没有行：偏移 ${offset} 已超出结果末尾` };
  }
  return { complete: true, from, to, text: `第 ${from}–${to} 行，已是最后一页（结果共 ${to} 行）` };
}

export function previousOffset(offset, limit) {
  return Math.max(0, offset - limit);
}
