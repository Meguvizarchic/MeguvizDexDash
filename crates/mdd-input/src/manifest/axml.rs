use super::*;
use std::collections::BTreeSet;

const NONE: u32 = u32::MAX;
fn range(bytes: &[u8], at: usize, len: usize) -> MddResult<&[u8]> {
    bytes
        .get(
            at..at
                .checked_add(len)
                .ok_or_else(|| invalid("AXML range overflow"))?,
        )
        .ok_or_else(|| invalid("AXML range exceeds chunk"))
}
fn u16_at(bytes: &[u8], at: usize) -> MddResult<u16> {
    Ok(u16::from_le_bytes(range(bytes, at, 2)?.try_into().unwrap()))
}
fn u32_at(bytes: &[u8], at: usize) -> MddResult<u32> {
    Ok(u32::from_le_bytes(range(bytes, at, 4)?.try_into().unwrap()))
}
fn index(build: &Builder, id: u32) -> MddResult<&ResourceText> {
    build
        .strings
        .get(id as usize)
        .map(|v| &v.value)
        .ok_or_else(|| invalid("AXML string index out of bounds"))
}
fn clone_text(build: &mut Builder, id: u32) -> MddResult<ResourceText> {
    let units = index(build, id)?.utf16.len();
    build.units(units)?;
    Ok(index(build, id)?.clone())
}
fn scalar(build: &mut Builder, id: u32) -> MddResult<String> {
    let units = index(build, id)?.utf16.len();
    build.units(units)?;
    index(build, id)?
        .text
        .clone()
        .ok_or_else(|| invalid("AXML structural name has isolated UTF-16 surrogate"))
}
fn optional_scalar(build: &mut Builder, id: u32) -> MddResult<Option<String>> {
    if id == NONE {
        Ok(None)
    } else {
        scalar(build, id).map(Some)
    }
}
fn length8(data: &[u8], at: &mut usize) -> MddResult<usize> {
    let first = *range(data, *at, 1)?.first().unwrap();
    *at += 1;
    if first & 0x80 == 0 {
        return Ok(first as usize);
    }
    let next = range(data, *at, 1)?[0];
    *at += 1;
    Ok((((first & 0x7f) as usize) << 8) | next as usize)
}
fn length16(data: &[u8], at: &mut usize) -> MddResult<usize> {
    let first = u16_at(data, *at)?;
    *at += 2;
    if first & 0x8000 == 0 {
        return Ok(first as usize);
    }
    let next = u16_at(data, *at)?;
    *at += 2;
    Ok((((first & 0x7fff) as usize) << 16) | next as usize)
}

pub(super) fn pool(
    chunk: &[u8],
    offset: usize,
    header: usize,
    build: &mut Builder,
) -> MddResult<()> {
    if header < 28 {
        return Err(invalid("string pool header is too small"));
    }
    let count = u32_at(chunk, 8)? as usize;
    let style_count = u32_at(chunk, 12)? as usize;
    let flags = u32_at(chunk, 16)?;
    if count > build.limits.max_strings {
        return Err(quota("string pool count exceeds budget"));
    }
    if style_count > count || flags & !0x101 != 0 {
        return Err(invalid("invalid string pool flags/style count"));
    }
    let tables_end = header
        .checked_add(
            count
                .checked_add(style_count)
                .and_then(|v| v.checked_mul(4))
                .ok_or_else(|| invalid("pool table overflow"))?,
        )
        .ok_or_else(|| invalid("pool table overflow"))?;
    range(chunk, header, tables_end - header)?;
    let strings_start = u32_at(chunk, 20)? as usize;
    let styles_start = u32_at(chunk, 24)? as usize;
    let strings_end = if styles_start == 0 {
        chunk.len()
    } else {
        styles_start
    };
    if count == 0 && style_count == 0 {
        if styles_start != 0 || (strings_start != 0 && strings_start < tables_end) {
            return Err(invalid("invalid empty string pool"));
        }
        return Ok(());
    }
    if strings_start < tables_end
        || strings_start > strings_end
        || strings_end > chunk.len()
        || (style_count != 0 && (styles_start == 0 || !styles_start.is_multiple_of(4)))
    {
        return Err(invalid("string pool data overlaps header or style data"));
    }
    let utf8 = flags & 0x100 != 0;
    for id in 0..count {
        let start = strings_start
            .checked_add(u32_at(chunk, header + id * 4)? as usize)
            .ok_or_else(|| invalid("pool string offset overflow"))?;
        if start >= strings_end || (!utf8 && start % 2 != 0) {
            return Err(invalid("string pool offset is outside string data"));
        }
        let data = &chunk[..strings_end];
        let mut at = start;
        let value = if utf8 {
            let units = length8(data, &mut at)?;
            let byte_count = length8(data, &mut at)?;
            build.units(units)?;
            let value = std::str::from_utf8(range(data, at, byte_count)?)
                .map_err(|_| invalid("invalid resource UTF-8"))?;
            at += byte_count;
            if range(data, at, 1)?[0] != 0 || value.encode_utf16().count() != units {
                return Err(invalid("resource UTF-8 length/terminator mismatch"));
            }
            at += 1;
            ResourceText::from_str(value)
        } else {
            let units = length16(data, &mut at)?;
            build.units(units)?;
            let raw = range(
                data,
                at,
                units
                    .checked_mul(2)
                    .ok_or_else(|| invalid("UTF-16 byte count overflow"))?,
            )?;
            at += raw.len();
            if u16_at(data, at)? != 0 {
                return Err(invalid("resource UTF-16 terminator missing"));
            }
            at += 2;
            ResourceText::from_units(
                raw.as_chunks::<2>()
                    .0
                    .iter()
                    .map(|v| u16::from_le_bytes([v[0], v[1]]))
                    .collect(),
            )
        };
        build.strings.push(PoolString {
            value,
            source_range: ByteRange {
                offset: offset + start,
                length: at - start,
            },
            encoding: if utf8 {
                "resource_utf8"
            } else {
                "resource_utf16_le"
            }
            .to_owned(),
            styles: Vec::new(),
        });
    }
    for id in 0..style_count {
        let relative = u32_at(chunk, header + (count + id) * 4)?;
        if relative == NONE {
            continue;
        }
        let mut at = styles_start
            .checked_add(relative as usize)
            .ok_or_else(|| invalid("style offset overflow"))?;
        if at % 4 != 0 || at < styles_start {
            return Err(invalid("unaligned style span offset"));
        }
        loop {
            let name = u32_at(chunk, at)?;
            if name == NONE {
                break;
            }
            let first = u32_at(chunk, at + 4)?;
            let last = u32_at(chunk, at + 8)?;
            if name as usize >= count
                || first > last
                || last as usize >= build.strings[id].value.utf16.len()
            {
                return Err(invalid("invalid style span name or character range"));
            }
            if build.strings[id].styles.len() >= build.limits.max_events {
                return Err(quota("style span count exceeds budget"));
            }
            build.units(3)?;
            build.strings[id].styles.push(StyleSpan {
                name_index: name,
                first_utf16: first,
                last_utf16: last,
            });
            at += 12;
        }
    }
    Ok(())
}

fn typed(bytes: &[u8], at: usize, build: &mut Builder) -> MddResult<ManifestValue> {
    if u16_at(bytes, at)? != 8 || range(bytes, at + 2, 1)?[0] != 0 {
        return Err(invalid("invalid Res_value size/reserved byte"));
    }
    let data_type = range(bytes, at + 3, 1)?[0];
    let raw_data = u32_at(bytes, at + 4)?;
    let decoded = match data_type {
        0 => {
            if raw_data > 1 {
                return Err(invalid("invalid compiled NULL value"));
            }
            TypedData::Null {
                empty: raw_data == 1,
            }
        }
        1 | 2 | 7 | 8 => TypedData::UnresolvedReference {
            resource_id: raw_data,
            attribute: data_type == 2 || data_type == 8,
            dynamic: data_type == 7 || data_type == 8,
        },
        3 => TypedData::String {
            value: clone_text(build, raw_data)?,
            string_index: raw_data,
        },
        4 => TypedData::FloatBits,
        5 => TypedData::Dimension {
            unit: (raw_data & 15) as u8,
            radix: ((raw_data >> 4) & 3) as u8,
        },
        6 => TypedData::Fraction {
            unit: (raw_data & 15) as u8,
            radix: ((raw_data >> 4) & 3) as u8,
        },
        0x10 => TypedData::IntDecimal {
            signed: raw_data as i32,
        },
        0x11 => TypedData::IntHex,
        0x12 => TypedData::Boolean {
            value: raw_data != 0,
        },
        0x1c..=0x1f => TypedData::Color,
        _ => TypedData::Unknown,
    };
    Ok(ManifestValue::Compiled {
        data_type,
        raw_data,
        decoded,
    })
}

fn expanded(
    build: &mut Builder,
    ns: u32,
    name: u32,
    active: &[(usize, NamespaceDeclaration)],
) -> MddResult<(ExpandedName, Option<String>, PrefixProvenance)> {
    let local_name = scalar(build, name)?;
    if !super::text::ncname(&local_name) {
        return Err(invalid("invalid AXML local name"));
    }
    let namespace_uri = optional_scalar(build, ns)?;
    let (prefix, provenance) = if let Some(uri) = &namespace_uri {
        build.work(active.len())?;
        let mut visible = BTreeSet::new();
        let candidates: Vec<_> = active
            .iter()
            .rev()
            .filter_map(|(_, binding)| {
                (visible.insert(&binding.prefix) && &binding.uri == uri).then_some(binding)
            })
            .collect();
        if candidates.is_empty() {
            return Err(invalid("AXML namespace URI is not in scope"));
        }
        if candidates.len() == 1 {
            build.units(
                candidates[0]
                    .prefix
                    .as_deref()
                    .map_or(0, |s| s.encode_utf16().count()),
            )?;
            (
                candidates[0].prefix.clone(),
                PrefixProvenance::UniqueNamespaceBinding,
            )
        } else {
            (None, PrefixProvenance::AmbiguousNamespaceBindings)
        }
    } else {
        (None, PrefixProvenance::NoNamespace)
    };
    Ok((
        ExpandedName {
            namespace_uri,
            local_name,
        },
        prefix,
        provenance,
    ))
}

pub(super) fn parse(bytes: &[u8], build: &mut Builder) -> MddResult<()> {
    if u16_at(bytes, 0)? != 3
        || u16_at(bytes, 2)? != 8
        || u32_at(bytes, 4)? as usize != bytes.len()
        || !bytes.len().is_multiple_of(4)
    {
        return Err(invalid("invalid AXML root header/size/alignment"));
    }
    let mut offset = 8;
    let mut has_pool = false;
    let mut has_map = false;
    let mut stack: Vec<usize> = Vec::new();
    let mut namespaces: Vec<(usize, NamespaceDeclaration)> = Vec::new();
    let mut pending = Vec::new();
    while offset < bytes.len() {
        let kind = u16_at(bytes, offset)?;
        let header = u16_at(bytes, offset + 2)? as usize;
        let size = u32_at(bytes, offset + 4)? as usize;
        if header < 8 || size < header || !header.is_multiple_of(4) || !size.is_multiple_of(4) {
            return Err(invalid("invalid AXML chunk header/size/alignment"));
        }
        let chunk = range(bytes, offset, size)?;
        let source_range = ByteRange {
            offset,
            length: size,
        };
        if pending.is_empty()
            && namespaces
                .last()
                .is_some_and(|(depth, _)| *depth == stack.len())
            && matches!(
                build.events.last(),
                Some(ManifestEvent::EndElement { .. } | ManifestEvent::NamespaceEnd { .. })
            )
            && kind != 0x101
        {
            return Err(invalid("namespace end is missing at element boundary"));
        }
        if kind == 1 {
            if has_pool || !build.events.is_empty() || has_map {
                return Err(invalid("duplicate/out-of-order AXML string pool"));
            }
            pool(chunk, offset, header, build)?;
            has_pool = true;
        } else if kind == 0x180 {
            if !has_pool || has_map || !build.events.is_empty() || header != 8 {
                return Err(invalid("invalid AXML resource map ordering/header"));
            }
            if (size - 8) / 4 > build.strings.len() {
                return Err(invalid("resource map exceeds string count"));
            }
            for at in (8..size).step_by(4) {
                build.resource_map.push(u32_at(chunk, at)?);
            }
            has_map = true;
        } else {
            if !has_pool || header != 16 {
                return Err(invalid(
                    "AXML node has invalid header or missing string pool",
                ));
            }
            let comment = u32_at(chunk, 12)?;
            if comment != NONE {
                index(build, comment)?;
            }
            match kind {
                0x100 | 0x101 => {
                    if size != 24 {
                        return Err(invalid("invalid namespace chunk size"));
                    }
                    let prefix =
                        optional_scalar(build, u32_at(chunk, 16)?)?.filter(|s| !s.is_empty());
                    let uri = scalar(build, u32_at(chunk, 20)?)?;
                    super::text::validate_binding(prefix.as_deref(), &uri)?;
                    let declaration = NamespaceDeclaration {
                        prefix,
                        uri,
                        source_range,
                    };
                    let depth = stack.len();
                    if kind == 0x100 {
                        if namespaces.len() >= build.limits.max_attributes {
                            return Err(quota("namespace count exceeds budget"));
                        }
                        build.work(namespaces.len() + 1)?;
                        if namespaces
                            .iter()
                            .any(|(d, n)| *d == depth && n.prefix == declaration.prefix)
                        {
                            return Err(invalid("duplicate namespace binding in element scope"));
                        }
                        namespaces.push((depth, declaration.clone()));
                        pending.push(declaration.clone());
                        build.event(ManifestEvent::NamespaceStart { depth, declaration })?;
                    } else {
                        let (started_depth, started) = namespaces
                            .pop()
                            .ok_or_else(|| invalid("namespace end without start"))?;
                        if started_depth != depth
                            || started.prefix != declaration.prefix
                            || started.uri != declaration.uri
                            || !pending.is_empty()
                        {
                            return Err(invalid("namespace end mismatches start/scope"));
                        }
                        build.event(ManifestEvent::NamespaceEnd { depth, declaration })?;
                    }
                }
                0x102 => {
                    if stack.len() >= build.limits.max_depth
                        || build.nodes.len() >= build.limits.max_nodes
                    {
                        return Err(quota("Manifest node/depth budget exceeded"));
                    }
                    range(chunk, header, 20)?;
                    let (name, prefix, prefix_provenance) =
                        expanded(build, u32_at(chunk, 16)?, u32_at(chunk, 20)?, &namespaces)?;
                    let attr_start = u16_at(chunk, 24)? as usize;
                    let attr_size = u16_at(chunk, 26)? as usize;
                    let count = u16_at(chunk, 28)? as usize;
                    if attr_start < 20
                        || attr_size < 20
                        || !attr_start.is_multiple_of(4)
                        || !attr_size.is_multiple_of(4)
                    {
                        return Err(invalid("invalid attribute stride/start"));
                    }
                    for at in [30, 32, 34] {
                        if u16_at(chunk, at)? as usize > count {
                            return Err(invalid("id/class/style attribute index out of bounds"));
                        }
                    }
                    build.attributes(count)?;
                    let begin = header
                        .checked_add(attr_start)
                        .ok_or_else(|| invalid("attribute offset overflow"))?;
                    range(
                        chunk,
                        begin,
                        count
                            .checked_mul(attr_size)
                            .ok_or_else(|| invalid("attribute size overflow"))?,
                    )?;
                    let mut attributes = Vec::with_capacity(count);
                    let mut seen = BTreeSet::new();
                    for i in 0..count {
                        let at = begin + i * attr_size;
                        let name_id = u32_at(chunk, at + 4)?;
                        let (name, prefix, prefix_provenance) =
                            expanded(build, u32_at(chunk, at)?, name_id, &namespaces)?;
                        if !seen.insert((name.namespace_uri.clone(), name.local_name.clone())) {
                            return Err(invalid("duplicate expanded attribute name"));
                        }
                        let raw_id = u32_at(chunk, at + 8)?;
                        let raw_value = if raw_id == NONE {
                            None
                        } else {
                            Some(clone_text(build, raw_id)?)
                        };
                        attributes.push(ManifestAttribute {
                            name,
                            prefix,
                            prefix_provenance,
                            raw_value,
                            value: typed(chunk, at + 12, build)?,
                            resource_id: build
                                .resource_map
                                .get(name_id as usize)
                                .copied()
                                .filter(|id| *id != 0),
                            source_range: ByteRange {
                                offset: offset + at,
                                length: attr_size,
                            },
                        });
                    }
                    let node = ManifestNode {
                        name,
                        prefix,
                        prefix_provenance,
                        parent: stack.last().copied(),
                        attributes,
                        namespaces: std::mem::take(&mut pending),
                        source_range,
                        line_number: Some(u32_at(chunk, 8)?),
                    };
                    let id = build.push(node, stack.len() + 1)?;
                    stack.push(id);
                }
                0x103 => {
                    if size != 24 || !pending.is_empty() {
                        return Err(invalid("invalid end element chunk"));
                    }
                    let (name, _, _) =
                        expanded(build, u32_at(chunk, 16)?, u32_at(chunk, 20)?, &namespaces)?;
                    let node = stack
                        .pop()
                        .ok_or_else(|| invalid("end element without start"))?;
                    if build.nodes[node].name != name {
                        return Err(invalid("mismatched AXML end element"));
                    }
                    if namespaces.iter().any(|(depth, _)| *depth > stack.len()) {
                        return Err(invalid("namespace outlives its element scope"));
                    }
                    build.event(ManifestEvent::EndElement { node, source_range })?;
                }
                0x104 => {
                    if size != 28 || stack.is_empty() || !pending.is_empty() {
                        return Err(invalid("invalid AXML text chunk/scope"));
                    }
                    let value = clone_text(build, u32_at(chunk, 16)?)?;
                    let typed_value = Some(typed(chunk, 20, build)?);
                    build.event(ManifestEvent::Text {
                        parent: stack.last().copied(),
                        value,
                        typed_value,
                        source_range,
                    })?;
                }
                _ => {
                    return Err(MddError::new(
                        ErrorCode::UnsupportedCapability,
                        "manifest.axml",
                        "unknown AXML chunk type",
                    )
                    .detail("chunk_type", kind));
                }
            }
        }
        offset += size;
    }
    if !has_pool || !stack.is_empty() || !namespaces.is_empty() || !pending.is_empty() {
        return Err(invalid("incomplete AXML tree or namespace scope"));
    }
    Ok(())
}
