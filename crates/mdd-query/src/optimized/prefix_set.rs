//! Fast ASCII case-insensitive prefix and prefix+suffix matching over UTF-8 and UTF-16.

/// Match `bytes` against a pre-lowercased ASCII `lower_prefix` using ASCII case folding.
#[inline]
pub fn matches_ascii_ci_prefix(bytes: &[u8], lower_prefix: &[u8]) -> bool {
    bytes.len() >= lower_prefix.len()
        && bytes[..lower_prefix.len()].eq_ignore_ascii_case(lower_prefix)
}

/// Match `bytes` against non-overlapping `lower_prefix` and `lower_suffix` (both pre-lowercased ASCII).
#[inline]
pub fn matches_ascii_ci_prefix_suffix(
    bytes: &[u8],
    lower_prefix: &[u8],
    lower_suffix: &[u8],
) -> bool {
    let Some(min_len) = lower_prefix.len().checked_add(lower_suffix.len()) else {
        return false;
    };
    if bytes.len() < min_len {
        return false;
    }
    bytes[..lower_prefix.len()].eq_ignore_ascii_case(lower_prefix)
        && bytes[bytes.len() - lower_suffix.len()..].eq_ignore_ascii_case(lower_suffix)
}

/// Match UTF-16 code units against a pre-lowercased ASCII `lower_prefix`.
#[inline]
pub fn matches_utf16_ascii_ci_prefix(units: &[u16], lower_prefix: &[u8]) -> bool {
    if units.len() < lower_prefix.len() {
        return false;
    }
    units[..lower_prefix.len()]
        .iter()
        .zip(lower_prefix)
        .all(|(&u, &b)| u <= 0x7F && (u as u8).to_ascii_lowercase() == b)
}

/// Match UTF-16 code units against non-overlapping pre-lowercased ASCII `lower_prefix` and `lower_suffix`.
#[inline]
pub fn matches_utf16_ascii_ci_prefix_suffix(
    units: &[u16],
    lower_prefix: &[u8],
    lower_suffix: &[u8],
) -> bool {
    let Some(min_len) = lower_prefix.len().checked_add(lower_suffix.len()) else {
        return false;
    };
    if units.len() < min_len {
        return false;
    }
    matches_utf16_ascii_ci_prefix(units, lower_prefix)
        && units[units.len() - lower_suffix.len()..]
            .iter()
            .zip(lower_suffix)
            .all(|(&u, &b)| u <= 0x7F && (u as u8).to_ascii_lowercase() == b)
}

/// Indexed ASCII case-insensitive prefix disjunction matcher.
///
/// Sorts and prunes redundant prefixes (if `a` is a prefix of `b`, `b` is
/// subsumed) and indexes minimal prefixes by lowercase first ASCII byte for
/// O(1) candidate bucket narrowing.
#[derive(Clone, Debug)]
pub struct AsciiPrefixSet {
    empty: bool,
    min_len: usize,
    prefixes: Vec<Box<[u8]>>,
    buckets: [Option<(u16, u16)>; 256],
}

impl AsciiPrefixSet {
    /// Construct from arbitrary ASCII prefix byte slices (case-folded cleanly).
    pub fn new(raw_prefixes: &[&[u8]]) -> Self {
        let mut buckets: [Option<(u16, u16)>; 256] = [None; 256];
        if raw_prefixes.is_empty() {
            return Self {
                empty: true,
                min_len: usize::MAX,
                prefixes: Vec::new(),
                buckets,
            };
        }
        let mut normalized: Vec<Vec<u8>> = raw_prefixes
            .iter()
            .map(|p| p.iter().map(u8::to_ascii_lowercase).collect())
            .collect();
        normalized.sort();
        normalized.dedup();
        // If an empty prefix exists, every input matches; collapse to one empty slice.
        if normalized.first().is_some_and(Vec::is_empty) {
            return Self {
                empty: false,
                min_len: 0,
                prefixes: vec![Box::new([])],
                buckets,
            };
        }
        // Prefix-prune: since `normalized` is lexicographically sorted, if the last
        // kept prefix is a prefix of `cand`, `cand` is strictly redundant.
        let mut minimal: Vec<Box<[u8]>> = Vec::with_capacity(normalized.len());
        for cand in normalized {
            if minimal
                .last()
                .is_some_and(|prev| cand.starts_with(prev.as_ref()))
            {
                continue;
            }
            minimal.push(cand.into_boxed_slice());
        }
        let min_len = minimal.iter().map(|p| p.len()).min().unwrap_or(usize::MAX);
        // Build [start, end) ranges per first byte (entries capped well below u16::MAX in normal SQL;
        // if huge, fall back safely without truncating).
        let mut idx = 0usize;
        while idx < minimal.len() {
            let first = minimal[idx][0];
            let start = idx;
            while idx < minimal.len() && minimal[idx][0] == first {
                idx += 1;
            }
            if let (Ok(s), Ok(e)) = (u16::try_from(start), u16::try_from(idx)) {
                buckets[usize::from(first)] = Some((s, e));
            }
        }
        Self {
            empty: false,
            min_len,
            prefixes: minimal,
            buckets,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.empty
    }

    pub fn min_len(&self) -> usize {
        self.min_len
    }

    pub fn matches_all(&self) -> bool {
        self.min_len == 0
    }

    pub fn minimal_prefixes(&self) -> &[Box<[u8]>] {
        &self.prefixes
    }

    #[inline]
    pub fn matches_utf8(&self, bytes: &[u8]) -> bool {
        if self.empty || bytes.len() < self.min_len {
            return false;
        }
        if self.min_len == 0 {
            return true;
        }
        let first = bytes[0].to_ascii_lowercase();
        let slice = match self.buckets[usize::from(first)] {
            Some((s, e)) => &self.prefixes[usize::from(s)..usize::from(e)],
            None => return false,
        };
        slice
            .iter()
            .any(|p| bytes.len() >= p.len() && bytes[..p.len()].eq_ignore_ascii_case(p))
    }

    #[inline]
    pub fn matches_utf16(&self, units: &[u16]) -> bool {
        if self.empty || units.len() < self.min_len {
            return false;
        }
        if self.min_len == 0 {
            return true;
        }
        let u0 = units[0];
        if u0 > 0x7F {
            return false;
        }
        let first = (u0 as u8).to_ascii_lowercase();
        let slice = match self.buckets[usize::from(first)] {
            Some((s, e)) => &self.prefixes[usize::from(s)..usize::from(e)],
            None => return false,
        };
        slice
            .iter()
            .any(|p| matches_utf16_ascii_ci_prefix(units, p))
    }

    #[inline]
    pub fn matches_utf16_be_bytes(&self, pairs: &[[u8; 2]]) -> bool {
        if self.empty || pairs.len() < self.min_len {
            return false;
        }
        if self.min_len == 0 {
            return true;
        }
        let [hi, lo] = pairs[0];
        if hi != 0 || lo > 0x7F {
            return false;
        }
        let first = lo.to_ascii_lowercase();
        let slice = match self.buckets[usize::from(first)] {
            Some((s, e)) => &self.prefixes[usize::from(s)..usize::from(e)],
            None => return false,
        };
        slice.iter().any(|p| {
            pairs.len() >= p.len()
                && pairs[..p.len()]
                    .iter()
                    .zip(p.iter())
                    .all(|(&[h, l], &b)| h == 0 && l.to_ascii_lowercase() == b)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_prefix_set_prunes_and_matches_utf8_and_utf16() {
        let prefixes: [&[u8]; 4] = [
            b"lcom/example/a/",
            b"LCOM/EXAMPLE/A/SUB/",
            b"lpkg/beta/",
            b"lkntr/common/c",
        ];
        let set = AsciiPrefixSet::new(&prefixes);
        assert_eq!(set.minimal_prefixes().len(), 3);
        let be_bytes =
            |s: &str| -> Vec<[u8; 2]> { s.encode_utf16().map(u16::to_be_bytes).collect() };
        for sample in [
            "Lcom/example/A/Foo;",
            "Lcom/example/A/Sub/Bar;",
            "Lpkg/Beta/Baz;",
            "Lkntr/Common/Comment;",
        ] {
            assert!(set.matches_utf8(sample.as_bytes()), "{sample}");
            let u16s: Vec<u16> = sample.encode_utf16().collect();
            assert!(set.matches_utf16(&u16s), "{sample}");
            assert!(set.matches_utf16_be_bytes(&be_bytes(sample)), "{sample}");
        }
        for miss in ["", "Lcom/example/", "Lother/", "\u{0130}pkg/beta/"] {
            assert!(!set.matches_utf8(miss.as_bytes()), "{miss}");
            let u16s: Vec<u16> = miss.encode_utf16().collect();
            assert!(!set.matches_utf16(&u16s), "{miss}");
            assert!(!set.matches_utf16_be_bytes(&be_bytes(miss)), "{miss}");
        }
    }

    #[test]
    fn prefix_suffix_enforces_non_overlap_length() {
        assert!(!matches_ascii_ci_prefix_suffix(
            b"Lcom/a;", b"lcom/a", b"a;"
        ));
        assert!(matches_ascii_ci_prefix_suffix(
            b"Lcom/aa;",
            b"lcom/a",
            b"a;"
        ));
        assert!(matches_ascii_ci_prefix_suffix(
            b"Lcom/example/FooStub;",
            b"lcom/example/",
            b"stub;"
        ));
        let u16s: Vec<u16> = "Lcom/a;".encode_utf16().collect();
        assert!(!matches_utf16_ascii_ci_prefix_suffix(
            &u16s, b"lcom/a", b"a;"
        ));
        let u16s_ok: Vec<u16> = "Lcom/aa;".encode_utf16().collect();
        assert!(matches_utf16_ascii_ci_prefix_suffix(
            &u16s_ok, b"lcom/a", b"a;"
        ));
    }
}
