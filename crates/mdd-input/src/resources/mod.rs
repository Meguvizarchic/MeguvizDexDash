//! What an APK holds besides code: compiled values, binary XML written back as text, and the
//! resource table with its configuration variants.
//!
//! Nothing here reads an archive. A member's bytes come in as a slice (the caller has them
//! from a snapshot, checked against the archive's size and CRC), and every answer is a
//! function of those bytes, so an answer can be traced to the member it was read from.
pub mod arsc;
pub mod config;
pub mod framework;
pub mod query;
pub mod value;
pub mod xml;

#[cfg(test)]
mod arsc_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod xml_tests;
