//! Bounded per-connection / per-execution memoization cache toggled by `MDD_OPT_QUERY_MEMO`.

use std::ffi::OsStr;

/// Whether query/schema memoization optimization is enabled (default `true`, `"0"` disables).
pub fn query_memo_enabled() -> bool {
    std::env::var_os("MDD_OPT_QUERY_MEMO").as_deref() != Some(OsStr::new("0"))
}

/// Small, bounded FIFO/move-to-front memo cache with deterministic eviction.
#[derive(Debug)]
pub struct SchemaMemo<K, V> {
    capacity: usize,
    enabled: bool,
    entries: Vec<(K, V)>,
}

impl<K: Eq, V> SchemaMemo<K, V> {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            enabled: query_memo_enabled(),
            entries: Vec::new(),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn get(&self, key: &K) -> Option<&V> {
        if !self.enabled {
            return None;
        }
        self.entries
            .iter()
            .rev()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
    }

    pub fn insert(&mut self, key: K, value: V) {
        if !self.enabled {
            return;
        }
        if let Some(pos) = self.entries.iter().position(|(k, _)| k == &key) {
            self.entries.remove(pos);
        } else if self.entries.len() >= self.capacity {
            self.entries.remove(0);
        }
        self.entries.push((key, value));
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_eviction_preserves_most_recent_items() {
        let mut memo = SchemaMemo::with_capacity(2);
        memo.insert("a", 1usize);
        memo.insert("b", 2);
        memo.insert("c", 3);
        assert_eq!(memo.len(), 2);
        assert_eq!(memo.get(&"a"), None);
        assert_eq!(memo.get(&"b"), Some(&2));
        assert_eq!(memo.get(&"c"), Some(&3));
    }
}
