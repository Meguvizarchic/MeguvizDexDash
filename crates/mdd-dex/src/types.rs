//! Validated type and prototype metadata; no class-definition inference.
use crate::{
    DexHeader,
    checked_reader::{CheckedReader, invalid},
    strings::DexString,
};
use mdd_types::{DecimalU64, ErrorCode, MddError, MddResult};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TypeShape {
    pub array_dimensions: u8,
    pub shorty: char,
    pub is_void: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DexType {
    pub type_idx: u32,
    pub descriptor_string_idx: u32,
    pub descriptor: String,
    pub shape: TypeShape,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DexPrototype {
    pub proto_idx: u32,
    pub shorty_string_idx: u32,
    pub shorty: String,
    pub return_type_idx: u32,
    pub parameter_type_indices: Vec<u32>,
    pub parameters_byte_offset: Option<DecimalU64>,
    pub descriptor: String,
}

pub const MAX_TOTAL_PARAMETER_REFERENCES: u64 = 16 * 1024 * 1024;
pub const MAX_TOTAL_PROTOTYPE_DESCRIPTOR_BYTES: u64 = 64 * 1024 * 1024;

fn failure(reason: &str, offset: u64, length: u64) -> MddError {
    invalid(reason, "dex.metadata", offset, length)
}

pub(crate) fn name_character(character: char, spaces_allowed: bool) -> bool {
    character.is_ascii_alphanumeric()
        || matches!(character, '$' | '-' | '_')
        || matches!(character as u32, 0x00a1..=0x1fff | 0x2010..=0x2027 | 0x2030..=0xd7ff | 0xe000..=0xffef | 0x10000..=0x10ffff)
        || (spaces_allowed && matches!(character as u32, 0x20 | 0xa0 | 0x2000..=0x200a | 0x202f))
}

pub fn parse_type_descriptor(
    descriptor: &str,
    version: &str,
    allow_void: bool,
) -> MddResult<TypeShape> {
    let dimensions = descriptor.bytes().take_while(|byte| *byte == b'[').count();
    if dimensions > 255 {
        return Err(failure("ARRAY_DIMENSION_LIMIT", 0, descriptor.len() as u64));
    }
    let rest = &descriptor[dimensions..];
    if rest == "V" {
        if dimensions > 0 || !allow_void {
            return Err(failure("VOID_TYPE_POSITION", 0, descriptor.len() as u64));
        }
        return Ok(TypeShape {
            array_dimensions: 0,
            shorty: 'V',
            is_void: true,
        });
    }
    let primitive = match rest {
        "Z" => Some('Z'),
        "B" => Some('B'),
        "S" => Some('S'),
        "C" => Some('C'),
        "I" => Some('I'),
        "J" => Some('J'),
        "F" => Some('F'),
        "D" => Some('D'),
        _ => None,
    };
    let shorty = if let Some(value) = primitive {
        value
    } else if let Some(class_name) = rest
        .strip_prefix('L')
        .and_then(|value| value.strip_suffix(';'))
    {
        if class_name.split('/').any(|part| {
            part.is_empty()
                || part
                    .chars()
                    .any(|character| !name_character(character, version >= "040"))
        }) {
            return Err(failure(
                "INVALID_CLASS_DESCRIPTOR_NAME",
                0,
                descriptor.len() as u64,
            ));
        }
        'L'
    } else {
        return Err(failure(
            "INVALID_TYPE_DESCRIPTOR",
            0,
            descriptor.len() as u64,
        ));
    };
    Ok(TypeShape {
        array_dimensions: dimensions as u8,
        shorty: if dimensions > 0 { 'L' } else { shorty },
        is_void: false,
    })
}

fn scalar_string(strings: &[DexString], index: u32, at: u64) -> MddResult<String> {
    strings
        .get(index as usize)
        .ok_or_else(|| failure("STRING_INDEX_OUT_OF_RANGE", at, 4))?
        .text
        .strict_utf8()
        .map_err(|_| {
            failure("NON_SCALAR_DESCRIPTOR_OR_SHORTY", at, 4).detail("string_idx", u64::from(index))
        })
}

pub fn type_list_item_starts(bytes: &[u8], header: &DexHeader) -> MddResult<Vec<u64>> {
    let Some(section_index) = header.map.iter().position(|item| item.type_code == 0x1001) else {
        return Ok(Vec::new());
    };
    let reader = CheckedReader::new(bytes);
    let section = &header.map[section_index];
    if u64::from(section.count) > MAX_TOTAL_PARAMETER_REFERENCES {
        return Err(MddError::new(
            ErrorCode::QuotaExceeded,
            "dex.metadata",
            "physical type-list item budget exceeded",
        ));
    }
    let section_end = header.map.get(section_index + 1).map_or(
        header.data_range.byte_offset.0 + header.data_range.byte_length.0,
        |item| item.byte_offset.0,
    );
    let type_count = header
        .tables
        .iter()
        .find(|table| table.name == "type_ids")
        .ok_or_else(|| failure("MISSING_TYPE_TABLE", 64, 8))?
        .count;
    let mut starts = Vec::new();
    starts
        .try_reserve_exact(section.count as usize)
        .map_err(|_| {
            MddError::new(
                ErrorCode::QuotaExceeded,
                "dex.metadata",
                "type-list index allocation failed",
            )
        })?;
    let mut cursor = section.byte_offset.0;
    let mut total_references = 0u64;
    for _ in 0..section.count {
        let aligned = cursor
            .checked_add(3)
            .map(|value| value & !3)
            .ok_or_else(|| failure("TYPE_LIST_ALIGNMENT_OVERFLOW", cursor, 4))?;
        if aligned > section_end
            || reader
                .range(cursor, aligned - cursor)?
                .iter()
                .any(|byte| *byte != 0)
        {
            return Err(failure(
                "TYPE_LIST_PADDING",
                cursor,
                aligned.saturating_sub(cursor),
            ));
        }
        cursor = aligned;
        if cursor.checked_add(4).is_none_or(|end| end > section_end) {
            return Err(failure("TRUNCATED_TYPE_LIST", cursor, 4));
        }
        let count = u64::from(reader.u32(cursor)?);
        total_references = total_references
            .checked_add(count)
            .ok_or_else(|| failure("TYPE_LIST_REFERENCE_OVERFLOW", cursor, 4))?;
        if total_references > MAX_TOTAL_PARAMETER_REFERENCES {
            return Err(MddError::new(
                ErrorCode::QuotaExceeded,
                "dex.metadata",
                "physical type-list reference budget exceeded",
            )
            .detail("budget", "physical_type_list_references")
            .detail("limit", MAX_TOTAL_PARAMETER_REFERENCES.to_string()));
        }
        let length = 4 + count * 2;
        let end = cursor
            .checked_add(length)
            .ok_or_else(|| failure("TYPE_LIST_RANGE_OVERFLOW", cursor, length))?;
        if end > section_end {
            return Err(failure("TRUNCATED_TYPE_LIST", cursor, length));
        }
        reader.range(cursor, length)?;
        for index in 0..count {
            let at = cursor + 4 + index * 2;
            if u32::from(reader.u16(at)?) >= type_count {
                return Err(failure("PARAMETER_TYPE_INDEX_OUT_OF_RANGE", at, 2));
            }
        }
        starts.push(cursor);
        cursor = end;
    }
    Ok(starts)
}

pub fn read_types_and_prototypes(
    bytes: &[u8],
    header: &DexHeader,
    strings: &[DexString],
) -> MddResult<(Vec<DexType>, Vec<DexPrototype>)> {
    let reader = CheckedReader::new(bytes);
    let type_table = header
        .tables
        .iter()
        .find(|table| table.name == "type_ids")
        .ok_or_else(|| failure("MISSING_TYPE_TABLE", 64, 8))?;
    let proto_table = header
        .tables
        .iter()
        .find(|table| table.name == "proto_ids")
        .ok_or_else(|| failure("MISSING_PROTO_TABLE", 72, 8))?;
    let mut types = Vec::new();
    types
        .try_reserve_exact(type_table.count as usize)
        .map_err(|_| {
            MddError::new(
                ErrorCode::QuotaExceeded,
                "dex.metadata",
                "type index allocation failed",
            )
        })?;
    let mut previous_string = None;
    for type_idx in 0..type_table.count {
        let at = type_table.range.byte_offset.0 + u64::from(type_idx) * 4;
        let string_idx = reader.u32(at)?;
        if previous_string.is_some_and(|previous| previous >= string_idx) {
            return Err(failure("TYPE_IDS_NOT_STRICT_ORDER", at, 4));
        }
        let descriptor = scalar_string(strings, string_idx, at)?;
        let shape = parse_type_descriptor(&descriptor, &header.version, true).map_err(|error| {
            error
                .detail("type_idx", u64::from(type_idx))
                .detail("descriptor_string_idx", u64::from(string_idx))
                .detail(
                    "byte_offset",
                    strings[string_idx as usize]
                        .text
                        .raw_range
                        .byte_offset
                        .0
                        .to_string(),
                )
        })?;
        types.push(DexType {
            type_idx,
            descriptor_string_idx: string_idx,
            descriptor,
            shape,
        });
        previous_string = Some(string_idx);
    }
    let mut prototypes: Vec<DexPrototype> = Vec::new();
    prototypes
        .try_reserve_exact(proto_table.count as usize)
        .map_err(|_| {
            MddError::new(
                ErrorCode::QuotaExceeded,
                "dex.metadata",
                "prototype index allocation failed",
            )
        })?;
    let physical_type_lists = type_list_item_starts(bytes, header)?;
    let mut total_parameters = 0u64;
    let mut total_descriptor_bytes = 0u64;
    let list_section = header
        .map
        .iter()
        .position(|item| item.type_code == 0x1001)
        .map(|index| {
            (
                header.map[index].byte_offset.0,
                header.map.get(index + 1).map_or(
                    header.data_range.byte_offset.0 + header.data_range.byte_length.0,
                    |item| item.byte_offset.0,
                ),
            )
        });
    for proto_idx in 0..proto_table.count {
        let at = proto_table.range.byte_offset.0 + u64::from(proto_idx) * 12;
        let shorty_idx = reader.u32(at)?;
        let return_idx = reader.u32(at + 4)?;
        let parameters_off = reader.u32(at + 8)?;
        let return_type = types
            .get(return_idx as usize)
            .ok_or_else(|| failure("RETURN_TYPE_INDEX_OUT_OF_RANGE", at + 4, 4))?;
        let shorty = scalar_string(strings, shorty_idx, at)?;
        let mut parameters = Vec::new();
        if parameters_off != 0 {
            let Some((start, end)) = list_section else {
                return Err(failure("MISSING_TYPE_LIST_SECTION", at + 8, 4));
            };
            let offset = u64::from(parameters_off);
            if physical_type_lists.binary_search(&offset).is_err() {
                return Err(failure("TYPE_LIST_OFFSET_NOT_ITEM_START", offset, 4));
            }
            if !parameters_off.is_multiple_of(4) || offset < start || offset + 4 > end {
                return Err(failure("TYPE_LIST_OUTSIDE_SECTION", offset, 4));
            }
            let count = reader.u32(offset)?;
            total_parameters += u64::from(count);
            if total_parameters > MAX_TOTAL_PARAMETER_REFERENCES {
                return Err(MddError::new(
                    ErrorCode::QuotaExceeded,
                    "dex.metadata",
                    "expanded prototype parameters exceed budget",
                )
                .detail("reason", "PARAMETER_REFERENCE_BUDGET")
                .detail("limit", MAX_TOTAL_PARAMETER_REFERENCES.to_string()));
            }
            let length = 4 + u64::from(count) * 2;
            if offset + length > end {
                return Err(failure("TRUNCATED_TYPE_LIST", offset, length));
            }
            reader.range(offset, length)?;
            parameters.try_reserve_exact(count as usize).map_err(|_| {
                MddError::new(
                    ErrorCode::QuotaExceeded,
                    "dex.metadata",
                    "parameter allocation failed",
                )
                .detail("reason", "PARAMETER_ALLOCATION")
                .detail("byte_offset", offset.to_string())
                .detail("byte_length", length.to_string())
            })?;
            for ordinal in 0..count {
                let item_at = offset + 4 + u64::from(ordinal) * 2;
                let index = u32::from(reader.u16(item_at)?);
                let argument = types
                    .get(index as usize)
                    .ok_or_else(|| failure("PARAMETER_TYPE_INDEX_OUT_OF_RANGE", item_at, 2))?;
                if argument.shape.is_void {
                    return Err(failure("VOID_PARAMETER", item_at, 2));
                }
                parameters.push(index);
            }
        }
        // Compare against the previous prototype in place instead of cloning its
        // parameter list into a separate ordering key.
        if prototypes.last().is_some_and(|previous| {
            previous.return_type_idx > return_idx
                || (previous.return_type_idx == return_idx
                    && previous.parameter_type_indices >= parameters)
        }) {
            return Err(failure("PROTO_IDS_NOT_STRICT_ORDER", at, 12));
        }
        let descriptor_bytes = parameters
            .iter()
            .try_fold(return_type.descriptor.len() as u64 + 2, |sum, index| {
                sum.checked_add(types[*index as usize].descriptor.len() as u64)
            })
            .ok_or_else(|| {
                MddError::new(
                    ErrorCode::QuotaExceeded,
                    "dex.metadata",
                    "prototype descriptor size overflow",
                )
            })?;
        total_descriptor_bytes = total_descriptor_bytes
            .checked_add(descriptor_bytes)
            .ok_or_else(|| {
                MddError::new(
                    ErrorCode::QuotaExceeded,
                    "dex.metadata",
                    "prototype descriptor total overflow",
                )
            })?;
        if total_descriptor_bytes > MAX_TOTAL_PROTOTYPE_DESCRIPTOR_BYTES {
            return Err(MddError::new(
                ErrorCode::QuotaExceeded,
                "dex.metadata",
                "expanded prototype descriptors exceed budget",
            )
            .detail("reason", "PROTOTYPE_DESCRIPTOR_BYTE_BUDGET")
            .detail("limit", MAX_TOTAL_PROTOTYPE_DESCRIPTOR_BYTES.to_string()));
        }
        // Compare the shorty byte by byte instead of allocating a throwaway
        // `String` per prototype; only a mismatch materialises the expected
        // value for the error detail.
        let shorty_bytes = shorty.as_bytes();
        let expected_len = parameters.len() + 1;
        let mut shorty_mismatch = shorty_bytes.len() != expected_len;
        if !shorty_mismatch {
            if shorty_bytes[0] != return_type.shape.shorty as u8 {
                shorty_mismatch = true;
            }
            for (ordinal, index) in parameters.iter().enumerate() {
                if shorty_bytes[ordinal + 1] != types[*index as usize].shape.shorty as u8 {
                    shorty_mismatch = true;
                    break;
                }
            }
        }
        let mut descriptor = String::new();
        descriptor
            .try_reserve_exact(descriptor_bytes as usize)
            .map_err(|_| {
                MddError::new(
                    ErrorCode::QuotaExceeded,
                    "dex.metadata",
                    "prototype descriptor allocation failed",
                )
            })?;
        descriptor.push('(');
        for index in &parameters {
            descriptor.push_str(&types[*index as usize].descriptor);
        }
        descriptor.push(')');
        descriptor.push_str(&return_type.descriptor);
        if shorty_mismatch {
            return Err(
                failure("SHORTY_DESCRIPTOR_MISMATCH", at, 4).detail("expected_shorty", {
                    let mut expected = String::with_capacity(expected_len);
                    expected.push(return_type.shape.shorty);
                    for index in &parameters {
                        expected.push(types[*index as usize].shape.shorty);
                    }
                    expected
                }),
            );
        }
        prototypes.push(DexPrototype {
            proto_idx,
            shorty_string_idx: shorty_idx,
            shorty,
            return_type_idx: return_idx,
            parameter_type_indices: parameters,
            parameters_byte_offset: (parameters_off != 0)
                .then_some(DecimalU64(u64::from(parameters_off))),
            descriptor,
        });
    }
    Ok((types, prototypes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        strings::{StringLimits, read_string_pool},
        validate_header,
    };

    #[test]
    fn descriptor_grammar_has_exact_void_array_name_and_version_rules() {
        for text in ["I", "[I", "[[Ljava/lang/String;", "Lpkg/类;", "L\u{1f600};"] {
            assert!(parse_type_descriptor(text, "035", false).is_ok(), "{text}");
        }
        for text in [
            "",
            "[V",
            "V",
            "L;",
            "Lpkg//C;",
            "Lpkg.C;",
            "Lname with space;",
            "Lx\0;",
        ] {
            assert!(
                parse_type_descriptor(text, "035", false).is_err(),
                "{text:?}"
            );
        }
        assert!(parse_type_descriptor("Lname with space;", "040", false).is_ok());
        assert!(parse_type_descriptor(&("[".repeat(256) + "I"), "040", false).is_err());
        assert_eq!(
            parse_type_descriptor(&("[".repeat(255) + "I"), "035", false)
                .unwrap()
                .array_dimensions,
            255
        );
    }

    #[test]
    fn existing_independent_fixture_types_and_empty_proto_match() {
        let raw = include_bytes!("../../../tests/fixtures/generated/structured-035.dex");
        let header = validate_header(raw).unwrap();
        let strings = read_string_pool(raw, &header, StringLimits::default()).unwrap();
        let (types, protos) = read_types_and_prototypes(raw, &header, &strings).unwrap();
        assert_eq!(
            types
                .iter()
                .map(|item| item.descriptor.as_str())
                .collect::<Vec<_>>(),
            ["Lfixture/A;", "Ljava/lang/Object;", "V"]
        );
        assert_eq!(protos[0].descriptor, "()V");
        assert!(protos[0].parameter_type_indices.is_empty());
        assert_eq!(protos[0].parameters_byte_offset, None);
    }

    #[test]
    fn independent_nonempty_parameter_fixture_matches_every_declared_field() {
        let raw = include_bytes!("../../../artifacts/mdd-020/inputs/metadata-035.dex");
        let header = validate_header(raw).unwrap();
        let strings = read_string_pool(raw, &header, StringLimits::default()).unwrap();
        let (types, protos) = read_types_and_prototypes(raw, &header, &strings).unwrap();
        let expected: serde_json::Value =
            serde_json::from_str(include_str!("../../../artifacts/mdd-020/expected.json")).unwrap();
        assert_eq!(
            serde_json::to_value(
                strings
                    .iter()
                    .map(|item| &item.text.utf16_units)
                    .collect::<Vec<_>>()
            )
            .unwrap(),
            expected["strings_utf16"]
        );
        for (actual, reference) in types.iter().zip(expected["types"].as_array().unwrap()) {
            assert_eq!(
                actual.type_idx as u64,
                reference["type_idx"].as_u64().unwrap()
            );
            assert_eq!(
                actual.descriptor_string_idx as u64,
                reference["descriptor_string_idx"].as_u64().unwrap()
            );
            assert_eq!(actual.descriptor, reference["descriptor"].as_str().unwrap());
            assert_eq!(
                actual.shape.shorty.to_string(),
                reference["shorty"].as_str().unwrap()
            );
            assert_eq!(
                actual.shape.array_dimensions as u64,
                reference["array_dimensions"].as_u64().unwrap()
            );
        }
        assert_eq!(
            serde_json::to_value(&protos).unwrap(),
            expected["prototypes"]
        );
    }

    #[test]
    fn independent_metadata_mutants_reject_instead_of_empty_success() {
        let variants = [
            (
                include_bytes!("../../../artifacts/mdd-020/inputs/bad-shorty.dex").as_slice(),
                "SHORTY_DESCRIPTOR_MISMATCH",
            ),
            (
                include_bytes!("../../../artifacts/mdd-020/inputs/bad-return-index.dex").as_slice(),
                "INDEX_OUT_OF_RANGE",
            ),
            (
                include_bytes!("../../../artifacts/mdd-020/inputs/bad-parameter-index.dex")
                    .as_slice(),
                "INDEX_OUT_OF_RANGE",
            ),
            (
                include_bytes!("../../../artifacts/mdd-020/inputs/bad-void-parameter.dex")
                    .as_slice(),
                "VOID_PARAMETER",
            ),
            (
                include_bytes!("../../../artifacts/mdd-020/inputs/bad-utf16-length.dex").as_slice(),
                "STRING_LENGTH_MISMATCH",
            ),
            (
                include_bytes!("../../../artifacts/mdd-020/inputs/bad-mutf8-leading.dex")
                    .as_slice(),
                "INVALID_MUTF8",
            ),
            (
                include_bytes!("../../../artifacts/mdd-020/inputs/bad-type-descriptor.dex")
                    .as_slice(),
                "INVALID_TYPE_DESCRIPTOR",
            ),
            (
                include_bytes!("../../../artifacts/mdd-020/inputs/bad-type-order.dex").as_slice(),
                "TYPE_IDS_NOT_STRICT_ORDER",
            ),
            (
                include_bytes!("../../../artifacts/mdd-020/inputs/bad-prototype-order.dex")
                    .as_slice(),
                "PROTO_IDS_NOT_STRICT_ORDER",
            ),
        ];
        for (raw, expected) in variants {
            let result = validate_header(raw).and_then(|header| {
                let strings = read_string_pool(raw, &header, StringLimits::default())?;
                read_types_and_prototypes(raw, &header, &strings)
            });
            assert_eq!(result.unwrap_err().details["reason"], expected);
        }
    }
}
#[test]
fn prototype_type_list_must_reference_a_real_physical_item_start() {
    let valid = include_bytes!(
        "../../../artifacts/integration/20261028/item-boundaries/valid-unused-type-list.dex"
    );
    let header = crate::validate_header(valid).unwrap();
    let strings =
        crate::strings::read_string_pool(valid, &header, crate::strings::StringLimits::default())
            .unwrap();
    let (_, protos) = read_types_and_prototypes(valid, &header, &strings).unwrap();
    assert_eq!(protos[0].descriptor, "()V");
    assert_eq!(type_list_item_starts(valid, &header).unwrap(), [136]);
    let bad = include_bytes!(
        "../../../artifacts/integration/20261028/item-boundaries/bad-interior-type-list.dex"
    );
    let header = crate::validate_header(bad).unwrap();
    let strings =
        crate::strings::read_string_pool(bad, &header, crate::strings::StringLimits::default())
            .unwrap();
    let error = read_types_and_prototypes(bad, &header, &strings).unwrap_err();
    assert_eq!(error.details["reason"], "TYPE_LIST_OFFSET_NOT_ITEM_START");
}
