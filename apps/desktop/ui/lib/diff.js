// How a comparison is worded. The words matter: "opcodes_equal" must never read as "identical".
export const STATUS_LABEL = {
  only_a: '仅 A 有',
  only_b: '仅 B 有',
  count_differs: '出现次数不同',
  opcodes_differ: '操作码序列不同',
  code_vs_no_code: '一边有代码，一边没有',
  facts_differ: '类属性不同',
  opcodes_equal: '操作码序列相同（操作数未比较）',
  no_code_both: '两边都没有代码项',
  facts_equal: '类属性相同',
};

export const AGREEMENTS = ['opcodes_equal', 'no_code_both', 'facts_equal'];

export function statusLabel(status) {
  return STATUS_LABEL[status] ?? status;
}

export function isAgreement(status) {
  return AGREEMENTS.includes(status);
}

/**
 * The lines of a smali comparison worth showing: every changed line with `context` unchanged lines
 * around it; longer unchanged runs become one {op: 'gap', skipped: n} marker. Nothing is dropped silently.
 */
export function withContext(lines, context = 3) {
  const keep = new Array(lines.length).fill(false);
  lines.forEach((line, i) => {
    if (line.op === '=') return;
    for (let j = Math.max(0, i - context); j <= Math.min(lines.length - 1, i + context); j += 1) keep[j] = true;
  });
  const out = [];
  let skipped = 0;
  lines.forEach((line, i) => {
    if (keep[i]) {
      if (skipped) {
        out.push({ op: 'gap', skipped });
        skipped = 0;
      }
      out.push(line);
    } else {
      skipped += 1;
    }
  });
  if (skipped) out.push({ op: 'gap', skipped });
  return out;
}
