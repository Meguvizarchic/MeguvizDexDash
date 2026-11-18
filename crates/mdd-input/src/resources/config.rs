//! `ResTable_config`: the device configuration a resource value is for, and its qualifier
//! string (`en-rUS`, `land`, `night-hdpi-v21`) in the order the platform tools write it.
//!
//! The record grew over the platform's life. A table written with an older, shorter one
//! gives zero for every field beyond its `size`, which is also what the platform does.
use mdd_types::{ErrorCode, MddError, MddResult};

/// What of a configuration is kept: every field the qualifier string can mention, plus
/// the raw bytes, so no field this module does not name is lost.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Configuration {
    raw: Vec<u8>,
}

fn u16_at(bytes: &[u8], at: usize) -> u16 {
    bytes
        .get(at..at + 2)
        .map_or(0, |b| u16::from_le_bytes([b[0], b[1]]))
}
fn u8_at(bytes: &[u8], at: usize) -> u8 {
    bytes.get(at).copied().unwrap_or(0)
}

/// A language or region from its two bytes: two ASCII letters or digits, or the packed
/// three-letter form (top bit of the first byte set).
fn unpack(pair: [u8; 2], base: u8) -> String {
    if pair[0] & 0x80 == 0 {
        return pair
            .iter()
            .take_while(|b| **b != 0)
            .map(|b| char::from(*b))
            .collect();
    }
    let chars = [
        base + (pair[1] & 0x1f),
        base + ((pair[1] & 0xe0) >> 5) + ((pair[0] & 0x03) << 3),
        base + ((pair[0] & 0x7c) >> 2),
    ];
    chars.iter().map(|b| char::from(*b)).collect()
}

fn ascii_field(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take_while(|b| **b != 0)
        .map(|b| char::from(*b))
        .collect()
}

impl Configuration {
    /// Read the record at the start of `bytes`; its own `size` field says how long it is.
    pub fn parse(bytes: &[u8]) -> MddResult<Self> {
        let invalid =
            |message: &str| MddError::new(ErrorCode::InvalidInput, "resources.config", message);
        let size = bytes
            .get(..4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize)
            .ok_or_else(|| invalid("configuration is shorter than its size field"))?;
        if size < 28 || size > bytes.len() {
            return Err(invalid("configuration size is outside the record")
                .detail("size", size.to_string()));
        }
        Ok(Self {
            raw: bytes[..size].to_vec(),
        })
    }

    /// The default configuration: nothing is qualified.
    pub fn default_config() -> Self {
        let mut raw = vec![0u8; 28];
        raw[0] = 28;
        Self { raw }
    }

    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    pub fn is_default(&self) -> bool {
        self.raw[4..].iter().all(|b| *b == 0)
    }

    pub fn sdk_version(&self) -> u16 {
        u16_at(&self.raw, 24)
    }

    /// The qualifier string; empty for the default configuration.
    pub fn qualifier(&self) -> String {
        let r = &self.raw;
        let mut parts: Vec<String> = Vec::new();
        let mcc = u16_at(r, 4);
        let mnc = u16_at(r, 6);
        if mcc != 0 {
            parts.push(format!("mcc{mcc}"));
        }
        if mnc != 0 {
            if mnc == 0xffff {
                parts.push("mnc00".to_owned());
            } else {
                parts.push(format!("mnc{mnc}"));
            }
        }
        if let Some(locale) = self.locale() {
            parts.push(locale);
        }
        let layout = u8_at(r, 28);
        match layout & 0xc0 {
            0x40 => parts.push("ldltr".to_owned()),
            0x80 => parts.push("ldrtl".to_owned()),
            _ => {}
        }
        for (field, prefix) in [(30, "sw"), (32, "w"), (34, "h")] {
            let dp = u16_at(r, field);
            if dp != 0 {
                parts.push(format!("{prefix}{dp}dp"));
            }
        }
        match layout & 0x0f {
            0 => {}
            1 => parts.push("small".to_owned()),
            2 => parts.push("normal".to_owned()),
            3 => parts.push("large".to_owned()),
            4 => parts.push("xlarge".to_owned()),
            other => parts.push(format!("layoutsize{other}")),
        }
        match layout & 0x30 {
            0x10 => parts.push("notlong".to_owned()),
            0x20 => parts.push("long".to_owned()),
            _ => {}
        }
        match u8_at(r, 48) & 3 {
            1 => parts.push("notround".to_owned()),
            2 => parts.push("round".to_owned()),
            _ => {}
        }
        let color = u8_at(r, 49);
        match color & 3 {
            1 => parts.push("nowidecg".to_owned()),
            2 => parts.push("widecg".to_owned()),
            _ => {}
        }
        match color & 0x0c {
            0x04 => parts.push("lowdr".to_owned()),
            0x08 => parts.push("highdr".to_owned()),
            _ => {}
        }
        match u8_at(r, 12) {
            0 => {}
            1 => parts.push("port".to_owned()),
            2 => parts.push("land".to_owned()),
            3 => parts.push("square".to_owned()),
            other => parts.push(format!("orientation{other}")),
        }
        let ui_mode = u8_at(r, 29);
        match ui_mode & 0x0f {
            0 | 1 => {}
            2 => parts.push("desk".to_owned()),
            3 => parts.push("car".to_owned()),
            4 => parts.push("television".to_owned()),
            5 => parts.push("appliance".to_owned()),
            6 => parts.push("watch".to_owned()),
            7 => parts.push("vrheadset".to_owned()),
            other => parts.push(format!("uimode{other}")),
        }
        match ui_mode & 0x30 {
            0x10 => parts.push("notnight".to_owned()),
            0x20 => parts.push("night".to_owned()),
            _ => {}
        }
        match u16_at(r, 14) {
            0 => {}
            120 => parts.push("ldpi".to_owned()),
            160 => parts.push("mdpi".to_owned()),
            213 => parts.push("tvdpi".to_owned()),
            240 => parts.push("hdpi".to_owned()),
            320 => parts.push("xhdpi".to_owned()),
            480 => parts.push("xxhdpi".to_owned()),
            640 => parts.push("xxxhdpi".to_owned()),
            0xfffe => parts.push("anydpi".to_owned()),
            0xffff => parts.push("nodpi".to_owned()),
            other => parts.push(format!("{other}dpi")),
        }
        match u8_at(r, 13) {
            0 => {}
            1 => parts.push("notouch".to_owned()),
            2 => parts.push("stylus".to_owned()),
            3 => parts.push("finger".to_owned()),
            other => parts.push(format!("touchscreen{other}")),
        }
        let input_flags = u8_at(r, 18);
        match input_flags & 3 {
            1 => parts.push("keysexposed".to_owned()),
            2 => parts.push("keyshidden".to_owned()),
            3 => parts.push("keyssoft".to_owned()),
            _ => {}
        }
        match u8_at(r, 16) {
            0 => {}
            1 => parts.push("nokeys".to_owned()),
            2 => parts.push("qwerty".to_owned()),
            3 => parts.push("12key".to_owned()),
            other => parts.push(format!("keyboard{other}")),
        }
        match (input_flags >> 2) & 3 {
            1 => parts.push("navexposed".to_owned()),
            2 => parts.push("navhidden".to_owned()),
            _ => {}
        }
        match u8_at(r, 17) {
            0 => {}
            1 => parts.push("nonav".to_owned()),
            2 => parts.push("dpad".to_owned()),
            3 => parts.push("trackball".to_owned()),
            4 => parts.push("wheel".to_owned()),
            other => parts.push(format!("navigation{other}")),
        }
        let (width, height) = (u16_at(r, 20), u16_at(r, 22));
        if width != 0 || height != 0 {
            parts.push(format!("{width}x{height}"));
        }
        let sdk = self.sdk_version();
        let minor = u16_at(r, 26);
        if sdk != 0 || minor != 0 {
            if minor != 0 {
                parts.push(format!("v{sdk}.{minor}"));
            } else {
                parts.push(format!("v{sdk}"));
            }
        }
        parts.join("-")
    }

    /// `en`, `en-rUS`, or the BCP 47 form `b+sr+Latn+RS` when a script, a variant or a
    /// numbering system is set.
    fn locale(&self) -> Option<String> {
        let r = &self.raw;
        let language = unpack([u8_at(r, 8), u8_at(r, 9)], b'a');
        let region = unpack([u8_at(r, 10), u8_at(r, 11)], b'0');
        let script = ascii_field(r.get(36..40).unwrap_or(&[]));
        let variant = ascii_field(r.get(40..48).unwrap_or(&[]));
        let numbering = ascii_field(r.get(52..60).unwrap_or(&[]));
        if language.is_empty()
            && region.is_empty()
            && script.is_empty()
            && variant.is_empty()
            && numbering.is_empty()
        {
            return None;
        }
        if script.is_empty() && variant.is_empty() && numbering.is_empty() {
            return Some(match (language.is_empty(), region.is_empty()) {
                (false, true) => language,
                (false, false) => format!("{language}-r{region}"),
                (true, false) => format!("r{region}"),
                (true, true) => unreachable!("checked above"),
            });
        }
        let mut tag = String::from("b");
        for part in [&language, &script, &region, &variant] {
            if !part.is_empty() {
                tag.push('+');
                tag.push_str(part);
            }
        }
        if !numbering.is_empty() {
            tag.push_str("+u+nu+");
            tag.push_str(&numbering);
        }
        Some(tag)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(size: usize, set: impl FnOnce(&mut [u8])) -> Configuration {
        let mut raw = vec![0u8; size];
        raw[0] = size as u8;
        set(&mut raw);
        Configuration::parse(&raw).unwrap()
    }

    #[test]
    fn the_default_configuration_has_an_empty_qualifier() {
        assert_eq!(config(56, |_| {}).qualifier(), "");
        assert!(config(56, |_| {}).is_default());
        assert_eq!(Configuration::default_config().qualifier(), "");
    }

    #[test]
    fn qualifiers_come_in_the_platform_order() {
        assert_eq!(
            config(56, |b| b[8..10].copy_from_slice(b"en")).qualifier(),
            "en"
        );
        assert_eq!(
            config(56, |b| {
                b[8..10].copy_from_slice(b"zh");
                b[10..12].copy_from_slice(b"CN");
                b[12] = 1;
            })
            .qualifier(),
            "zh-rCN-port"
        );
        assert_eq!(
            config(56, |b| {
                b[8..10].copy_from_slice(b"en");
                b[12] = 2;
            })
            .qualifier(),
            "en-land"
        );
        assert_eq!(config(56, |b| b[29] = 0x20).qualifier(), "night");
        assert_eq!(
            config(56, |b| b[14..16].copy_from_slice(&240u16.to_le_bytes())).qualifier(),
            "hdpi"
        );
        assert_eq!(
            config(56, |b| b[24..26].copy_from_slice(&21u16.to_le_bytes())).qualifier(),
            "v21"
        );
        assert_eq!(
            config(56, |b| {
                b[4..6].copy_from_slice(&310u16.to_le_bytes());
                b[30..32].copy_from_slice(&600u16.to_le_bytes());
                b[28] = 0x03 | 0x20 | 0x80;
                b[24..26].copy_from_slice(&26u16.to_le_bytes());
            })
            .qualifier(),
            "mcc310-ldrtl-sw600dp-large-long-v26"
        );
    }

    #[test]
    fn a_short_record_reads_as_zero_beyond_its_size_and_a_bad_size_is_refused() {
        assert_eq!(config(28, |b| b[12] = 2).qualifier(), "land");
        assert!(Configuration::parse(&[8, 0, 0, 0, 0, 0, 0, 0]).is_err());
        assert!(Configuration::parse(&[56, 0, 0, 0]).is_err());
        assert!(Configuration::parse(&[]).is_err());
    }

    #[test]
    fn script_variant_and_three_letter_languages_use_the_longer_forms() {
        assert_eq!(
            config(64, |b| {
                b[8..10].copy_from_slice(b"sr");
                b[10..12].copy_from_slice(b"RS");
                b[36..40].copy_from_slice(b"Latn");
            })
            .qualifier(),
            "b+sr+Latn+RS"
        );
        // "fil" packed: f=5, i=8, l=11 (offsets from 'a')
        let (a, b_) = (5u8, 8u8);
        let c = 11u8;
        let first = 0x80 | (c << 2) | (b_ >> 3);
        let second = a | ((b_ & 7) << 5);
        assert_eq!(
            config(56, |b| {
                b[8] = first;
                b[9] = second;
            })
            .qualifier(),
            "fil"
        );
    }
}
