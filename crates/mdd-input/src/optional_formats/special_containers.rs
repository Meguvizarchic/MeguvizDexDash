//! Explicit registry & fail-closed boundaries for unimplemented / disabled special containers.

use mdd_types::{ErrorCode, MddError, MddResult};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OptionalFormatKind {
    Dex041Container,
    CompactDex,
    Vdex,
    Oat,
    ApkSplitBundle,
    ProtobufResources,
}

impl OptionalFormatKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Dex041Container => "dex-041",
            Self::CompactDex => "cdex",
            Self::Vdex => "vdex",
            Self::Oat => "oat",
            Self::ApkSplitBundle => "apk-split-bundle",
            Self::ProtobufResources => "protobuf-resources",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityState {
    Disabled,
    VerifiedOptional,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct OptionalFormatPolicy {
    /// Whether `dex-041` verified multi-header handling has been explicitly opted into.
    /// Defaults to `false`: unrequested or default core runs do not silently admit `041`.
    pub allow_dex041_container: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OptionalFormatDescriptor {
    pub kind: OptionalFormatKind,
    pub magic_prefix_hex: String,
    pub detected_version: Option<String>,
    pub state: CapabilityState,
}

/// Inspect leading container bytes and explicitly reject disabled / unadmitted special formats.
/// Never returns an empty method list or fake partial success for `cdex`, `vdex`, `oat`, etc.
pub fn inspect_special_container(
    bytes: &[u8],
    policy: &OptionalFormatPolicy,
) -> MddResult<OptionalFormatDescriptor> {
    let prefix: String = bytes.iter().take(8).map(|b| format!("{b:02x}")).collect();
    if bytes.starts_with(b"dex\n041\0") {
        if !policy.allow_dex041_container {
            return Err(MddError::new(
                ErrorCode::UnsupportedCapability,
                "optional.container",
                "DEX 041 container support is disabled unless explicitly enabled and verified",
            )
            .detail("format", "dex-041")
            .detail("capability_state", "disabled"));
        }
        return Ok(OptionalFormatDescriptor {
            kind: OptionalFormatKind::Dex041Container,
            magic_prefix_hex: prefix,
            detected_version: Some("041".to_owned()),
            state: CapabilityState::VerifiedOptional,
        });
    }
    if bytes.starts_with(b"cdex") {
        let ver = bytes
            .get(4..7)
            .map(|s| String::from_utf8_lossy(s).into_owned());
        return Err(MddError::new(
            ErrorCode::UnsupportedCapability,
            "optional.container",
            "CompactDex (cdex) format capability is disabled / not admitted",
        )
        .detail("format", "cdex")
        .detail("detected_version", ver.unwrap_or_default())
        .detail("capability_state", "disabled"));
    }
    if bytes.starts_with(b"vdex") {
        let ver = bytes
            .get(4..8)
            .map(|s| String::from_utf8_lossy(s).into_owned());
        return Err(MddError::new(
            ErrorCode::UnsupportedCapability,
            "optional.container",
            "VDEX runtime container capability is disabled / not admitted",
        )
        .detail("format", "vdex")
        .detail("detected_version", ver.unwrap_or_default())
        .detail("capability_state", "disabled"));
    }
    if bytes.starts_with(b"oat\n") {
        let ver = bytes
            .get(4..7)
            .map(|s| String::from_utf8_lossy(s).into_owned());
        return Err(MddError::new(
            ErrorCode::UnsupportedCapability,
            "optional.container",
            "OAT compiled runtime capability is disabled / not admitted",
        )
        .detail("format", "oat")
        .detail("detected_version", ver.unwrap_or_default())
        .detail("capability_state", "disabled"));
    }
    Err(MddError::new(
        ErrorCode::InvalidInput,
        "optional.container",
        "unrecognized optional container format",
    )
    .detail("magic_prefix_hex", prefix))
}
