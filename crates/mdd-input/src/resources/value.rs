//! The spelling of a compiled value (`Res_value`): one place, so the XML view of a layout
//! and the table view of `resources.arsc` write the same number the same way.
//!
//! The spellings follow what the reference engine (dexsql 0.1.0) writes, which the
//! recordings in `artifacts/mdd-072/probe/` pin: floats as the shortest decimal that reads
//! back to the same `f32`, dimensions and fractions as the product of the mantissa and the
//! radix constant in `f64` with the unit suffix, colours as `#` and eight hex digits of the
//! raw word whatever the colour type, a reference as `@` and eight hex digits. The two views
//! differ in the spelling of a reference only (`@7f010000` against `@0x7f010000`).
//!
//! A value of a type this module does not know, or a unit it has no suffix for, is spelled
//! with its raw word and type number in angle brackets and never guessed at.

/// The radix constants of `TypedValue.RADIX_MULTS`, written as decimal text so the products
/// are the ones the reference prints (`3.051758E-5` is not the `f32` nearest to 2^-15).
const RADIX_MULTS: [f64; 4] = [0.00390625, 3.051758E-5, 1.192093E-7, 4.656613E-10];
const DIMENSION_UNITS: [&str; 6] = ["px", "dip", "sp", "pt", "in", "mm"];
const FRACTION_UNITS: [&str; 2] = ["%", "%p"];

/// `Res_value.dataType` values.
pub mod data_type {
    pub const NULL: u8 = 0x00;
    pub const REFERENCE: u8 = 0x01;
    pub const ATTRIBUTE: u8 = 0x02;
    pub const STRING: u8 = 0x03;
    pub const FLOAT: u8 = 0x04;
    pub const DIMENSION: u8 = 0x05;
    pub const FRACTION: u8 = 0x06;
    pub const DYNAMIC_REFERENCE: u8 = 0x07;
    pub const DYNAMIC_ATTRIBUTE: u8 = 0x08;
    pub const INT_DEC: u8 = 0x10;
    pub const INT_HEX: u8 = 0x11;
    pub const INT_BOOLEAN: u8 = 0x12;
    pub const COLOR_ARGB8: u8 = 0x1c;
    pub const COLOR_RGB8: u8 = 0x1d;
    pub const COLOR_ARGB4: u8 = 0x1e;
    pub const COLOR_RGB4: u8 = 0x1f;
}

/// How a reference is written.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferenceStyle {
    /// `@7f010000`, `?01010000`: the XML view.
    Compact,
    /// `@0x7f010000`, `?0x01010000`: the table view.
    Prefixed,
}

/// The name a table row gives a value's type.
pub fn type_label(data_type: u8) -> String {
    use data_type::*;
    match data_type {
        NULL => "Null".to_owned(),
        REFERENCE => "Reference".to_owned(),
        ATTRIBUTE => "Attribute".to_owned(),
        STRING => "String".to_owned(),
        FLOAT => "Float".to_owned(),
        DIMENSION => "Dimension".to_owned(),
        FRACTION => "Fraction".to_owned(),
        DYNAMIC_REFERENCE => "DynamicReference".to_owned(),
        DYNAMIC_ATTRIBUTE => "DynamicAttribute".to_owned(),
        INT_DEC => "Dec".to_owned(),
        INT_HEX => "Hex".to_owned(),
        INT_BOOLEAN => "Boolean".to_owned(),
        COLOR_ARGB8 => "ColorArgb8".to_owned(),
        COLOR_RGB8 => "ColorRgb8".to_owned(),
        COLOR_ARGB4 => "ColorArgb4".to_owned(),
        COLOR_RGB4 => "ColorRgb4".to_owned(),
        other => format!("Unknown({other})"),
    }
}

/// The product that `TypedValue.complexToFloat` forms: the upper 24 bits as a signed
/// mantissa, scaled by the radix constant.
fn complex(data: u32) -> f64 {
    let mantissa = (data & 0xffff_ff00) as i32;
    f64::from(mantissa) * RADIX_MULTS[((data >> 4) & 3) as usize]
}

/// The value of a type that is not a pool string, spelled; `None` for a string, which the
/// caller reads from its own pool.
pub fn spell(data_type: u8, data: u32, style: ReferenceStyle) -> Option<String> {
    use data_type::*;
    let (reference, attribute) = match style {
        ReferenceStyle::Compact => (format!("@{data:08x}"), format!("?{data:08x}")),
        ReferenceStyle::Prefixed => (format!("@0x{data:08x}"), format!("?0x{data:08x}")),
    };
    Some(match data_type {
        STRING => return None,
        NULL => format!("<0x{data:x}, type Null>"),
        REFERENCE | DYNAMIC_REFERENCE => reference,
        ATTRIBUTE => attribute,
        DYNAMIC_ATTRIBUTE => match style {
            ReferenceStyle::Compact => format!("<0x{data:x}, type DynamicAttribute>"),
            ReferenceStyle::Prefixed => attribute,
        },
        FLOAT => f32::from_bits(data).to_string(),
        DIMENSION => match DIMENSION_UNITS.get((data & 15) as usize) {
            Some(unit) => format!("{}{unit}", complex(data)),
            None => format!("<0x{data:x}, type Dimension, unit {}>", data & 15),
        },
        FRACTION => match FRACTION_UNITS.get((data & 15) as usize) {
            Some(unit) => format!("{}{unit}", complex(data) * 100.0),
            None => format!("<0x{data:x}, type Fraction, unit {}>", data & 15),
        },
        INT_DEC => (data as i32).to_string(),
        INT_HEX => format!("0x{data:08x}"),
        INT_BOOLEAN => if data != 0 { "true" } else { "false" }.to_owned(),
        COLOR_ARGB8 | COLOR_RGB8 | COLOR_ARGB4 | COLOR_RGB4 => format!("#{data:08x}"),
        other => format!("<0x{data:x}, type Unknown({other})>"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn xml(data_type: u8, data: u32) -> String {
        spell(data_type, data, ReferenceStyle::Compact).unwrap()
    }

    #[test]
    fn numbers_are_spelled_as_the_recordings_spell_them() {
        assert_eq!(xml(0x04, 1.5f32.to_bits()), "1.5");
        assert_eq!(xml(0x04, 0.1f32.to_bits()), "0.1");
        assert_eq!(xml(0x04, 12345678.0f32.to_bits()), "12345678");
        assert_eq!(xml(0x04, 0x7f80_0000), "inf");
        assert_eq!(xml(0x04, 0xff80_0000), "-inf");
        assert_eq!(xml(0x10, 0xffff_ffff), "-1");
        assert_eq!(xml(0x11, 0xabcd), "0x0000abcd");
        assert_eq!(xml(0x12, 2), "true");
        assert_eq!(xml(0x12, 0), "false");
    }

    #[test]
    fn dimensions_and_fractions_use_the_decimal_radix_constants() {
        assert_eq!(xml(0x05, 12 << 8), "12px");
        assert_eq!(xml(0x05, (12 << 8) | 1), "12dip");
        assert_eq!(xml(0x05, (12 << 8) | (1 << 4) | 1), "0.09375000576dip");
        assert_eq!(
            xml(0x05, (12 << 8) | (2 << 4) | 1),
            "0.00036621096959999996dip"
        );
        assert_eq!(xml(0x05, (12 << 8) | (3 << 4) | 1), "0.0000014305115136dip");
        assert_eq!(xml(0x06, 50 << 8), "5000%");
        assert_eq!(xml(0x06, (50 << 8) | 1), "5000%p");
        assert_eq!(xml(0x06, (50 << 8) | (1 << 4)), "39.0625024%");
    }

    #[test]
    fn colours_print_the_raw_word_whatever_the_type() {
        for t in [0x1c, 0x1d, 0x1e, 0x1f] {
            assert_eq!(xml(t, 0x336699), "#00336699");
        }
        assert_eq!(xml(0x1c, 0xff33_6699), "#ff336699");
    }

    #[test]
    fn references_differ_between_the_views_and_odd_types_are_never_guessed() {
        assert_eq!(xml(0x01, 0x7f01_0000), "@7f010000");
        assert_eq!(
            spell(0x01, 0x7f01_0000, ReferenceStyle::Prefixed).unwrap(),
            "@0x7f010000"
        );
        assert_eq!(xml(0x02, 0x0101_0000), "?01010000");
        assert_eq!(xml(0x07, 0x0201_0001), "@02010001");
        assert_eq!(xml(0x08, 0x0201_0002), "<0x2010002, type DynamicAttribute>");
        assert_eq!(
            spell(0x08, 0x0201_0002, ReferenceStyle::Prefixed).unwrap(),
            "?0x02010002"
        );
        assert_eq!(xml(0x00, 1), "<0x1, type Null>");
        assert_eq!(xml(99, 0xdead_beef), "<0xdeadbeef, type Unknown(99)>");
        assert_eq!(spell(0x03, 0, ReferenceStyle::Compact), None);
        assert!(xml(0x05, 9).contains("unit 9"));
    }

    #[test]
    fn labels_name_every_known_type() {
        assert_eq!(type_label(0x1c), "ColorArgb8");
        assert_eq!(type_label(0x10), "Dec");
        assert_eq!(type_label(0x7), "DynamicReference");
        assert_eq!(type_label(99), "Unknown(99)");
    }
}
