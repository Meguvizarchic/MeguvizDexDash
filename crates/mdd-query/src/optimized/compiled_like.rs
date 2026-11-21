//! Zero-allocation compiled LIKE matcher over UTF-16 code units and big-endian UTF-16 byte slices.

use std::fmt;

/// Dialect flavor controlling `LIKE` semantics (kept strictly identical to SQL dialect rules).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum LikeFlavor {
    /// ASCII `A..=Z` case folding, `%` wildcard, literal `_`, trailing escape returns `false`.
    AsciiCiPercentOnly,
    /// Exact UTF-16 unit matching, `%` and `_` wildcards, trailing escape returns error.
    ExactWithUnderscore,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LikeCompileError {
    DanglingEscape,
}

impl fmt::Display for LikeCompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DanglingEscape => write!(f, "LIKE_DANGLING_ESCAPE"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LikeToken {
    Literal(u16),
    One,
    Many,
}

/// Pre-classified structural shape enabling direct specialized scans without general backtracking.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LikeShape {
    AlwaysFalse,
    MatchAll,
    Empty,
    Exact(Box<[u16]>),
    Prefix(Box<[u16]>),
    Suffix(Box<[u16]>),
    PrefixSuffix {
        prefix: Box<[u16]>,
        suffix: Box<[u16]>,
    },
    Contains(Box<[u16]>),
    General(Box<[LikeToken]>),
}

#[derive(Clone, Debug)]
pub struct CompiledLike {
    flavor: LikeFlavor,
    shape: LikeShape,
    pattern_units: usize,
}

#[inline(always)]
fn fold_ci(unit: u16) -> u16 {
    if (65..=90).contains(&unit) {
        unit + 32
    } else {
        unit
    }
}

#[inline(always)]
fn eq_folded(pattern_folded: u16, candidate: u16, ci: bool) -> bool {
    if ci {
        pattern_folded == fold_ci(candidate)
    } else {
        pattern_folded == candidate
    }
}

/// Abstract read access over `&[u16]` or big-endian `&[[u8; 2]]` so one verified implementation
/// covers both decoded Rust slices and borrowed SQLite `TEXT` carriers with zero copies.
pub trait Utf16Source: Copy {
    fn len(self) -> usize;
    fn is_empty(self) -> bool {
        self.len() == 0
    }
    fn get_unchecked_unit(self, index: usize) -> u16;
}

impl Utf16Source for &[u16] {
    #[inline(always)]
    fn len(self) -> usize {
        <[u16]>::len(self)
    }
    #[inline(always)]
    fn get_unchecked_unit(self, index: usize) -> u16 {
        self[index]
    }
}

impl Utf16Source for &[[u8; 2]] {
    #[inline(always)]
    fn len(self) -> usize {
        <[[u8; 2]]>::len(self)
    }
    #[inline(always)]
    fn get_unchecked_unit(self, index: usize) -> u16 {
        u16::from_be_bytes(self[index])
    }
}

impl CompiledLike {
    pub fn compile(
        pattern: &[u16],
        escape: Option<u16>,
        flavor: LikeFlavor,
    ) -> Result<Self, LikeCompileError> {
        let ci = flavor == LikeFlavor::AsciiCiPercentOnly;
        let underscore_wild = flavor == LikeFlavor::ExactWithUnderscore;
        let mut tokens: Vec<LikeToken> = Vec::with_capacity(pattern.len());
        let mut at = 0usize;
        while at < pattern.len() {
            let unit = pattern[at];
            if Some(unit) == escape {
                at += 1;
                let Some(&escaped) = pattern.get(at) else {
                    if underscore_wild {
                        return Err(LikeCompileError::DanglingEscape);
                    }
                    return Ok(Self {
                        flavor,
                        shape: LikeShape::AlwaysFalse,
                        pattern_units: pattern.len(),
                    });
                };
                let lit = if ci { fold_ci(escaped) } else { escaped };
                tokens.push(LikeToken::Literal(lit));
            } else if unit == 37 {
                if !matches!(tokens.last(), Some(LikeToken::Many)) {
                    tokens.push(LikeToken::Many);
                }
            } else if unit == 95 && underscore_wild {
                tokens.push(LikeToken::One);
            } else {
                let lit = if ci { fold_ci(unit) } else { unit };
                tokens.push(LikeToken::Literal(lit));
            }
            at += 1;
        }
        let shape = classify_shape(&tokens);
        Ok(Self {
            flavor,
            shape,
            pattern_units: pattern.len(),
        })
    }

    pub fn compile_be_bytes(
        pattern_be: &[[u8; 2]],
        escape: Option<u16>,
        flavor: LikeFlavor,
    ) -> Result<Self, LikeCompileError> {
        let mut stack_buf = [0u16; 256];
        if pattern_be.len() <= stack_buf.len() {
            for (dst, pair) in stack_buf.iter_mut().zip(pattern_be) {
                *dst = u16::from_be_bytes(*pair);
            }
            Self::compile(&stack_buf[..pattern_be.len()], escape, flavor)
        } else {
            let vec: Vec<u16> = pattern_be.iter().map(|p| u16::from_be_bytes(*p)).collect();
            Self::compile(&vec, escape, flavor)
        }
    }

    pub fn shape(&self) -> &LikeShape {
        &self.shape
    }

    pub fn pattern_units(&self) -> usize {
        self.pattern_units
    }

    #[inline]
    pub fn matches_units(&self, units: &[u16]) -> bool {
        self.matches_source(units)
    }

    #[inline]
    pub fn matches_be_bytes(&self, units_be: &[[u8; 2]]) -> bool {
        self.matches_source(units_be)
    }

    #[inline]
    fn matches_source<S: Utf16Source>(&self, src: S) -> bool {
        let ci = self.flavor == LikeFlavor::AsciiCiPercentOnly;
        let n = src.len();
        match &self.shape {
            LikeShape::AlwaysFalse => false,
            LikeShape::MatchAll => true,
            LikeShape::Empty => n == 0,
            LikeShape::Exact(pat) => {
                if n != pat.len() {
                    return false;
                }
                match_slice_eq(src, 0, pat, ci)
            }
            LikeShape::Prefix(pat) => n >= pat.len() && match_slice_eq(src, 0, pat, ci),
            LikeShape::Suffix(pat) => n >= pat.len() && match_slice_eq(src, n - pat.len(), pat, ci),
            LikeShape::PrefixSuffix { prefix, suffix } => {
                let min_len = prefix.len().saturating_add(suffix.len());
                n >= min_len
                    && match_slice_eq(src, 0, prefix, ci)
                    && match_slice_eq(src, n - suffix.len(), suffix, ci)
            }
            LikeShape::Contains(needle) => contains_needle(src, needle, ci),
            LikeShape::General(tokens) => match_general(src, tokens, ci),
        }
    }
}

fn classify_shape(tokens: &[LikeToken]) -> LikeShape {
    let all_literals = |slice: &[LikeToken]| -> Option<Box<[u16]>> {
        let mut out = Vec::with_capacity(slice.len());
        for tok in slice {
            match tok {
                LikeToken::Literal(u) => out.push(*u),
                _ => return None,
            }
        }
        Some(out.into_boxed_slice())
    };
    match tokens {
        [] => LikeShape::Empty,
        [LikeToken::Many] => LikeShape::MatchAll,
        [LikeToken::Many, rest @ .., LikeToken::Many] if !rest.is_empty() => {
            if let Some(needle) = all_literals(rest) {
                return LikeShape::Contains(needle);
            }
            LikeShape::General(tokens.to_vec().into_boxed_slice())
        }
        [LikeToken::Many, rest @ ..] => {
            if let Some(suffix) = all_literals(rest) {
                return LikeShape::Suffix(suffix);
            }
            LikeShape::General(tokens.to_vec().into_boxed_slice())
        }
        [rest @ .., LikeToken::Many] => {
            if let Some(prefix) = all_literals(rest) {
                return LikeShape::Prefix(prefix);
            }
            LikeShape::General(tokens.to_vec().into_boxed_slice())
        }
        _ => {
            if let Some(exact) = all_literals(tokens) {
                return LikeShape::Exact(exact);
            }
            if let Some(many_pos) = tokens.iter().position(|t| matches!(t, LikeToken::Many))
                && !tokens[many_pos + 1..]
                    .iter()
                    .any(|t| matches!(t, LikeToken::Many))
                && let (Some(prefix), Some(suffix)) = (
                    all_literals(&tokens[..many_pos]),
                    all_literals(&tokens[many_pos + 1..]),
                )
            {
                return LikeShape::PrefixSuffix { prefix, suffix };
            }
            LikeShape::General(tokens.to_vec().into_boxed_slice())
        }
    }
}

#[inline]
fn match_slice_eq<S: Utf16Source>(src: S, start: usize, pat: &[u16], ci: bool) -> bool {
    let Some((&last, prefix)) = pat.split_last() else {
        return true;
    };
    if !eq_folded(last, src.get_unchecked_unit(start + prefix.len()), ci) {
        return false;
    }
    if ci {
        for (i, &p) in prefix.iter().enumerate() {
            if fold_ci(src.get_unchecked_unit(start + i)) != p {
                return false;
            }
        }
    } else {
        for (i, &p) in prefix.iter().enumerate() {
            if src.get_unchecked_unit(start + i) != p {
                return false;
            }
        }
    }
    true
}

#[inline]
fn contains_needle<S: Utf16Source>(src: S, needle: &[u16], ci: bool) -> bool {
    let m = needle.len();
    if m == 0 {
        return true;
    }
    let n = src.len();
    if n < m {
        return false;
    }
    let first = needle[0];
    let last = needle[m - 1];
    let limit = n - m;
    for pos in 0..=limit {
        if eq_folded(first, src.get_unchecked_unit(pos), ci)
            && (m == 1 || eq_folded(last, src.get_unchecked_unit(pos + m - 1), ci))
            && (m <= 2 || match_slice_eq(src, pos + 1, &needle[1..m - 1], ci))
        {
            return true;
        }
    }
    false
}

fn match_general<S: Utf16Source>(src: S, tokens: &[LikeToken], ci: bool) -> bool {
    let n = src.len();
    let (mut input, mut token, mut star, mut restart) = (0usize, 0usize, None, 0usize);
    while input < n {
        if token < tokens.len()
            && match tokens[token] {
                LikeToken::One => true,
                LikeToken::Literal(v) => eq_folded(v, src.get_unchecked_unit(input), ci),
                LikeToken::Many => false,
            }
        {
            input += 1;
            token += 1;
        } else if token < tokens.len() && matches!(tokens[token], LikeToken::Many) {
            star = Some(token);
            token += 1;
            restart = input;
        } else if let Some(s) = star {
            restart += 1;
            input = restart;
            token = s + 1;
        } else {
            return false;
        }
    }
    while token < tokens.len() && matches!(tokens[token], LikeToken::Many) {
        token += 1;
    }
    token == tokens.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference_like(
        value: &[u16],
        pattern: &[u16],
        escape: Option<u16>,
        flavor: LikeFlavor,
    ) -> Result<bool, LikeCompileError> {
        let ci = flavor == LikeFlavor::AsciiCiPercentOnly;
        let underscore_wild = flavor == LikeFlavor::ExactWithUnderscore;
        let mut tokens = Vec::new();
        let mut at = 0;
        while at < pattern.len() {
            let unit = pattern[at];
            if Some(unit) == escape {
                at += 1;
                let Some(&escaped) = pattern.get(at) else {
                    if underscore_wild {
                        return Err(LikeCompileError::DanglingEscape);
                    }
                    return Ok(false);
                };
                tokens.push(LikeToken::Literal(escaped));
            } else if unit == 37 {
                tokens.push(LikeToken::Many);
            } else if unit == 95 && underscore_wild {
                tokens.push(LikeToken::One);
            } else {
                tokens.push(LikeToken::Literal(unit));
            }
            at += 1;
        }
        let fold = |v: u16| {
            if ci && (65..=90).contains(&v) {
                v + 32
            } else {
                v
            }
        };
        let (mut input, mut token, mut star, mut restart) = (0usize, 0usize, None, 0usize);
        while input < value.len() {
            if token < tokens.len()
                && match tokens[token] {
                    LikeToken::One => true,
                    LikeToken::Literal(v) => fold(v) == fold(value[input]),
                    LikeToken::Many => false,
                }
            {
                input += 1;
                token += 1;
            } else if token < tokens.len() && matches!(tokens[token], LikeToken::Many) {
                star = Some(token);
                token += 1;
                restart = input;
            } else if let Some(s) = star {
                restart += 1;
                input = restart;
                token = s + 1;
            } else {
                return Ok(false);
            }
        }
        while token < tokens.len() && matches!(tokens[token], LikeToken::Many) {
            token += 1;
        }
        Ok(token == tokens.len())
    }

    fn u16s(s: &str) -> Vec<u16> {
        s.encode_utf16().collect()
    }

    fn to_be_pairs(units: &[u16]) -> Vec<[u8; 2]> {
        units.iter().map(|u| u.to_be_bytes()).collect()
    }

    #[test]
    fn differential_parity_across_shapes_surrogates_nul_and_escapes() {
        let values: Vec<Vec<u16>> = vec![
            vec![],
            u16s("a"),
            u16s("Lcom/example/DynamicHandler;"),
            u16s("Lcom/example/SubMoss;"),
            u16s("Lcom/example/Sub"),
            u16s("prefix_underscore"),
            u16s("pre%mid\\tail"),
            vec![0x61, 0x0000, 0xd800, 0xdc00, 0xd801, 0x41],
            vec![0xd800],
            vec![0x0130, 0x0041],
        ];
        let patterns: Vec<(Vec<u16>, Option<u16>)> = vec![
            (vec![], None),
            (u16s("%"), None),
            (u16s("%%%"), None),
            (u16s("Lcom/example/%"), None),
            (u16s("lcom/example/%moss;"), None),
            (u16s("%dynamic%"), None),
            (u16s("%Moss;"), None),
            (u16s("prefix_underscore"), None),
            (u16s("prefixXunderscore"), None),
            (u16s("pre\\%mid\\\\tail"), Some(b'\\' as u16)),
            (u16s("Lcom/example/Sub"), None),
            (u16s("a%_%"), None),
            (u16s("%"), Some(b'\\' as u16)),
            (u16s("abc\\"), Some(b'\\' as u16)),
            (vec![b'a' as u16, 0, b'%' as u16], None),
            (vec![0xd800], None),
            (vec![b'%' as u16, 0x41], None),
        ];

        for flavor in [
            LikeFlavor::AsciiCiPercentOnly,
            LikeFlavor::ExactWithUnderscore,
        ] {
            for (pat, esc) in &patterns {
                let compiled = CompiledLike::compile(pat, *esc, flavor);
                let pat_be = to_be_pairs(pat);
                let compiled_be = CompiledLike::compile_be_bytes(&pat_be, *esc, flavor);
                assert_eq!(compiled.is_ok(), compiled_be.is_ok());
                for val in &values {
                    let expected = reference_like(val, pat, *esc, flavor);
                    match (&compiled, expected) {
                        (Ok(c), Ok(exp)) => {
                            assert_eq!(
                                c.matches_units(val),
                                exp,
                                "flavor={flavor:?} val={val:?} pat={pat:?}"
                            );
                            let val_be = to_be_pairs(val);
                            assert_eq!(
                                compiled_be.as_ref().unwrap().matches_be_bytes(&val_be),
                                exp,
                                "be mismatch"
                            );
                        }
                        (Err(e1), Err(e2)) => assert_eq!(*e1, e2),
                        other => panic!("compile vs reference mismatch: {other:?}"),
                    }
                }
            }
        }
    }
}
