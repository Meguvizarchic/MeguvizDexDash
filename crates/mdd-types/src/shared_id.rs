//! Identifier text shared by many values.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;

/// An identifier text that every fact of a DEX carries: the snapshot and the DEX occurrence it belongs to, the string pool a
/// string is in. They are long (a hundred bytes and more) and the same for every fact of the DEX, so the facts share one
/// allocation of each instead of each owning a copy: for a large DEX that is most of the memory of the metadata layer.
///
/// It reads and compares as the text it is: it dereferences to `str`, equals a `String` or `&str` holding the same text,
/// displays, serializes and deserializes as a plain string, and turns into a `String` or a JSON string.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Hash)]
pub struct SharedId(Arc<str>);

impl SharedId {
    pub fn new(text: &str) -> Self {
        Self(Arc::from(text))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::ops::Deref for SharedId {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for SharedId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&*self.0, f)
    }
}

impl std::fmt::Display for SharedId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&*self.0, f)
    }
}

impl std::borrow::Borrow<str> for SharedId {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for SharedId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl From<&str> for SharedId {
    fn from(text: &str) -> Self {
        Self::new(text)
    }
}

impl From<String> for SharedId {
    fn from(text: String) -> Self {
        Self(Arc::from(text))
    }
}

impl From<&String> for SharedId {
    fn from(text: &String) -> Self {
        Self::new(text)
    }
}

impl From<SharedId> for String {
    fn from(id: SharedId) -> Self {
        id.0.as_ref().to_owned()
    }
}

impl From<SharedId> for Value {
    fn from(id: SharedId) -> Self {
        Value::String(id.0.as_ref().to_owned())
    }
}

impl PartialEq<String> for SharedId {
    fn eq(&self, other: &String) -> bool {
        *self.0 == **other
    }
}

impl PartialEq<str> for SharedId {
    fn eq(&self, other: &str) -> bool {
        *self.0 == *other
    }
}

impl PartialEq<&str> for SharedId {
    fn eq(&self, other: &&str) -> bool {
        *self.0 == **other
    }
}

impl PartialEq<SharedId> for String {
    fn eq(&self, other: &SharedId) -> bool {
        **self == *other.0
    }
}

impl PartialEq<SharedId> for &str {
    fn eq(&self, other: &SharedId) -> bool {
        **self == *other.0
    }
}

impl Serialize for SharedId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SharedId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self::from)
    }
}
