//! Isolated, pinned external providers (`display_only` / non-authoritative views).
//!
//! External providers (such as an optional JADX runner) are disabled unless explicitly configured
//! with a pinned binary SHA-256 digest, isolated scratch dir, strict timeout, and bounded output.
//! Their output can NEVER populate raw byte fingerprints or deterministic call graphs.

pub mod jadx_view;

pub use jadx_view::{
    ExternalProviderConfig, FactTargetKind, IsolatedDecompilerView, ProviderCapabilityStatus,
    invoke_isolated_provider, reject_as_authoritative_fact,
};
