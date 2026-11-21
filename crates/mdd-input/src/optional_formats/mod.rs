//! Optional format handlers strictly isolated from standard `035–040` production DEX capture.
//!
//! Covers verified DEX `041` multi-header containers and explicit `disabled` rejection boundaries
//! for unimplemented runtime formats (`cdex`, `vdex`, `oat`, split bundles, protobuf resources).

pub mod address;
pub mod dex041;
pub mod special_containers;

pub use address::{CodeUnitPc, ContainerOffset, LogicalHeaderOffset};
pub use dex041::{
    Dex041ContainerReport, Dex041StringEntry, LogicalDex041, validate_and_extract_dex041_container,
};
pub use special_containers::{
    CapabilityState, OptionalFormatDescriptor, OptionalFormatKind, OptionalFormatPolicy,
    inspect_special_container,
};
