//! Tables assembled byte by byte, for what the fixtures built by the Python generator do not reach:
//! sparse and 16-bit type chunks, a type id offset, compact entries, and every way a table can be
//! damaged. Each damage is applied to a table that parses, so a refusal is the damage's.
use super::arsc::{EntryValue, ResourceTable, TableLimits};
use mdd_types::ErrorCode;

fn le16(v: u16) -> Vec<u8> {
    v.to_le_bytes().to_vec()
}
fn le32(v: u32) -> Vec<u8> {
    v.to_le_bytes().to_vec()
}

fn chunk(kind: u16, header_size: usize, fields: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut out = le16(kind);
    out.extend(le16(header_size as u16));
    out.extend(le32((header_size + payload.len()) as u32));
    out.extend_from_slice(fields);
    assert_eq!(out.len(), header_size, "header fields");
    out.extend_from_slice(payload);
    out
}

fn pool(strings: &[&str]) -> Vec<u8> {
    let mut data = Vec::new();
    let mut offsets = Vec::new();
    for s in strings {
        offsets.extend(le32(data.len() as u32));
        data.push(s.encode_utf16().count() as u8);
        data.push(s.len() as u8);
        data.extend_from_slice(s.as_bytes());
        data.push(0);
    }
    while data.len() % 4 != 0 {
        data.push(0);
    }
    let start = 28 + offsets.len();
    let mut fields = le32(strings.len() as u32);
    fields.extend(le32(0));
    fields.extend(le32(0x100));
    fields.extend(le32(start as u32));
    fields.extend(le32(0));
    let mut payload = offsets;
    payload.extend(data);
    chunk(1, 28, &fields, &payload)
}

fn config() -> Vec<u8> {
    let mut c = vec![0u8; 28];
    c[0] = 28;
    c
}

/// A plain entry: size 8, flags, key, then a value of `data_type` and `data`.
fn entry(key: u32, flags: u16, data_type: u8, data: u32) -> Vec<u8> {
    let mut e = le16(8);
    e.extend(le16(flags));
    e.extend(le32(key));
    e.extend(le16(8));
    e.push(0);
    e.push(data_type);
    e.extend(le32(data));
    e
}

fn map_entry(key: u32, parent: u32, items: &[(u32, u8, u32)]) -> Vec<u8> {
    let mut e = le16(16);
    e.extend(le16(1));
    e.extend(le32(key));
    e.extend(le32(parent));
    e.extend(le32(items.len() as u32));
    for (name, kind, data) in items {
        e.extend(le32(*name));
        e.extend(le16(8));
        e.push(0);
        e.push(*kind);
        e.extend(le32(*data));
    }
    e
}

/// A type chunk with its offset table and entries already assembled.
fn type_chunk(type_id: u8, flags: u8, count: u32, table: &[u8], entries: &[u8]) -> Vec<u8> {
    type_chunk_for(&config(), type_id, flags, count, table, entries)
}

fn config_in(language: &[u8; 2]) -> Vec<u8> {
    let mut c = config();
    c[8..10].copy_from_slice(language);
    c
}

fn type_chunk_for(
    config: &[u8],
    type_id: u8,
    flags: u8,
    count: u32,
    table: &[u8],
    entries: &[u8],
) -> Vec<u8> {
    let header = 20 + config.len();
    let mut fields = vec![type_id, flags];
    fields.extend(le16(0));
    fields.extend(le32(count));
    fields.extend(le32((header + table.len()) as u32));
    fields.extend_from_slice(config);
    let mut payload = table.to_vec();
    payload.extend_from_slice(entries);
    chunk(0x201, header, &fields, &payload)
}

fn dense(offsets: &[u32]) -> Vec<u8> {
    offsets.iter().flat_map(|o| le32(*o)).collect()
}

fn package(
    id: u32,
    type_id_offset: u32,
    types: &[&str],
    keys: &[&str],
    body: &[Vec<u8>],
) -> Vec<u8> {
    let type_pool = pool(types);
    let key_pool = pool(keys);
    let mut fields = le32(id);
    let mut name: Vec<u8> = "pkg".encode_utf16().flat_map(u16::to_le_bytes).collect();
    name.resize(256, 0);
    fields.extend(name);
    fields.extend(le32(288));
    fields.extend(le32(types.len() as u32));
    fields.extend(le32((288 + type_pool.len()) as u32));
    fields.extend(le32(keys.len() as u32));
    fields.extend(le32(type_id_offset));
    let mut payload = type_pool;
    payload.extend(key_pool);
    for b in body {
        payload.extend_from_slice(b);
    }
    chunk(0x200, 288, &fields, &payload)
}

fn table_of(values: &[&str], packages: &[Vec<u8>], declared: u32) -> Vec<u8> {
    let mut payload = pool(values);
    for p in packages {
        payload.extend_from_slice(p);
    }
    let mut fields = le32(declared);
    fields.truncate(4);
    chunk(2, 12, &fields, &payload)
}

/// One package, one type "string", keys k0..k3, three plain entries at positions 0, 2 and 3.
fn plain_body() -> Vec<Vec<u8>> {
    let entries: Vec<u8> = [
        entry(0, 0, 3, 0),
        entry(1, 0, 0x10, 7),
        entry(2, 0, 0x12, 1),
    ]
    .concat();
    vec![type_chunk(
        1,
        0,
        4,
        &dense(&[0, 0xffff_ffff, 16, 32]),
        &entries,
    )]
}

fn plain() -> Vec<u8> {
    table_of(
        &["v0"],
        &[package(
            0x7f,
            0,
            &["string"],
            &["k0", "k1", "k2"],
            &plain_body(),
        )],
        1,
    )
}

fn parse(bytes: &[u8]) -> Result<ResourceTable, mdd_types::MddError> {
    ResourceTable::parse(bytes, TableLimits::default())
}

fn rows(table: &ResourceTable) -> Vec<(u32, String, u8, u32)> {
    table
        .entries()
        .iter()
        .map(|e| {
            let EntryValue::Simple(v) = &e.value else {
                panic!("plain")
            };
            (
                e.resource_id,
                table.key_name(e).to_owned(),
                v.data_type,
                v.data,
            )
        })
        .collect()
}

#[test]
fn a_plain_dense_table_reads_and_names_its_entries() {
    let table = parse(&plain()).unwrap();
    assert_eq!(
        rows(&table),
        [
            (0x7f01_0000, "k0".to_owned(), 3, 0),
            (0x7f01_0002, "k1".to_owned(), 0x10, 7),
            (0x7f01_0003, "k2".to_owned(), 0x12, 1),
        ]
    );
    assert_eq!(table.type_name(&table.entries()[0]), "string");
}

#[test]
fn a_sparse_type_chunk_gives_each_entry_its_index() {
    // indexes 3 and 7, at byte offsets 0 and 16 (written as offset / 4)
    let entries: Vec<u8> = [entry(0, 0, 0x10, 30), entry(1, 0, 0x10, 70)].concat();
    let mut sparse = le32(3);
    sparse.extend(le32(7 | (4 << 16)));
    let body = vec![type_chunk(1, 1, 2, &sparse, &entries)];
    let bytes = table_of(
        &["v"],
        &[package(0x7f, 0, &["string"], &["k0", "k1"], &body)],
        1,
    );
    let table = parse(&bytes).unwrap();
    assert_eq!(
        rows(&table),
        [
            (0x7f01_0003, "k0".to_owned(), 0x10, 30),
            (0x7f01_0007, "k1".to_owned(), 0x10, 70)
        ]
    );
}

#[test]
fn a_sixteen_bit_type_chunk_counts_offsets_in_words_and_skips_the_absent() {
    let entries: Vec<u8> = [entry(0, 0, 0x10, 1), entry(1, 0, 0x10, 2)].concat();
    // positions 0, 1 (absent), 2 at byte offsets 0 and 16 -> 0 and 4 words; a fourth word pads the table
    let mut offsets = le16(0);
    offsets.extend(le16(0xffff));
    offsets.extend(le16(4));
    offsets.extend(le16(0xffff));
    let body = vec![type_chunk(1, 2, 3, &offsets, &entries)];
    let bytes = table_of(
        &["v"],
        &[package(0x7f, 0, &["string"], &["k0", "k1"], &body)],
        1,
    );
    let table = parse(&bytes).unwrap();
    assert_eq!(
        rows(&table),
        [
            (0x7f01_0000, "k0".to_owned(), 0x10, 1),
            (0x7f01_0002, "k1".to_owned(), 0x10, 2)
        ]
    );
}

#[test]
fn a_type_id_offset_shifts_the_names_of_the_types() {
    let entries = entry(0, 0, 0x10, 5);
    let body = vec![type_chunk(3, 0, 1, &dense(&[0]), &entries)];
    // type id 3 with an offset of 2 is the first name of the pool
    let bytes = table_of(
        &["v"],
        &[package(0x7f, 2, &["first", "second"], &["k0"], &body)],
        1,
    );
    let table = parse(&bytes).unwrap();
    assert_eq!(table.type_name(&table.entries()[0]), "first");
    assert_eq!(table.entries()[0].resource_id, 0x7f03_0000);
    // the same chunk without the offset names the third type, which the pool does not have
    let bytes = table_of(
        &["v"],
        &[package(0x7f, 0, &["first", "second"], &["k0"], &body)],
        1,
    );
    assert!(parse(&bytes).is_err());
}

#[test]
fn a_map_entry_keeps_its_parent_and_the_order_of_its_items() {
    let entries = map_entry(
        0,
        0x0103_0001,
        &[
            (0x0101_0000, 0x10, 1),
            (0x0101_0001, 0x10, 2),
            (0x0101_0002, 0x10, 3),
        ],
    );
    let body = vec![type_chunk(1, 0, 1, &dense(&[0]), &entries)];
    let bytes = table_of(&["v"], &[package(0x7f, 0, &["style"], &["k0"], &body)], 1);
    let table = parse(&bytes).unwrap();
    let EntryValue::Map { parent, items } = &table.entries()[0].value else {
        panic!("a map entry");
    };
    assert_eq!(*parent, 0x0103_0001);
    assert_eq!(
        items
            .iter()
            .map(|i| (i.name, i.value.data))
            .collect::<Vec<_>>(),
        [(0x0101_0000, 1), (0x0101_0001, 2), (0x0101_0002, 3)]
    );
}

/// The plain table with one byte range replaced.
fn damaged(at: usize, bytes: &[u8]) -> Vec<u8> {
    let mut table = plain();
    table[at..at + bytes.len()].copy_from_slice(bytes);
    table
}

fn find(table: &[u8], needle: &[u8]) -> usize {
    table
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("pattern present")
}

#[test]
fn a_compact_entry_is_unsupported_and_is_not_called_invalid() {
    let entries: Vec<u8> = [entry(0, 0x0008, 0x10, 1)].concat();
    let body = vec![type_chunk(1, 0, 1, &dense(&[0]), &entries)];
    let bytes = table_of(&["v"], &[package(0x7f, 0, &["string"], &["k0"], &body)], 1);
    let error = parse(&bytes).unwrap_err();
    assert_eq!(error.code, ErrorCode::UnsupportedCapability);
}

#[test]
fn every_kind_of_damage_is_refused_and_each_on_a_table_that_otherwise_parses() {
    let good = plain();
    assert!(parse(&good).is_ok());
    // the root chunk: type, header size, declared size, alignment
    assert!(parse(&damaged(0, &le16(9))).is_err());
    assert!(parse(&damaged(2, &le16(8))).is_err());
    assert!(parse(&damaged(4, &le32(good.len() as u32 + 4))).is_err());
    let mut trailing = good.clone();
    trailing.extend([0, 0, 0, 0]);
    assert!(parse(&trailing).is_err(), "bytes after the root chunk");
    let mut cut = good.clone();
    cut.truncate(good.len() - 2);
    assert!(parse(&cut).is_err());
    // the package count
    assert!(parse(&damaged(8, &le32(2))).is_err());
    assert!(parse(&damaged(8, &le32(0))).is_err());
    // a second global pool in place of the package
    let doubled = table_of(
        &["v"],
        &[
            pool(&["w"]),
            package(0x7f, 0, &["string"], &["k0", "k1", "k2"], &plain_body()),
        ],
        1,
    );
    assert!(parse(&doubled).is_err());
    // no global pool at all
    let mut fields = le32(1);
    fields.truncate(4);
    let no_pool = chunk(
        2,
        12,
        &fields,
        &package(0x7f, 0, &["string"], &["k0", "k1", "k2"], &plain_body()),
    );
    assert!(parse(&no_pool).is_err());
    // a chunk whose size is not a multiple of four
    let type_at = find(&good, &[0x01, 0x02, 0x30, 0x00]);
    assert!(parse(&damaged(type_at + 4, &le32(0x31))).is_err());
}

#[test]
fn damage_inside_a_type_chunk_is_refused() {
    let good = plain();
    let type_at = find(&good, &[0x01, 0x02, 0x30, 0x00]);
    // entry count beyond what the chunk holds
    assert!(parse(&damaged(type_at + 12, &le32(1000))).is_err());
    // entries starting inside the offset table
    assert!(parse(&damaged(type_at + 16, &le32(0x30))).is_err());
    // type id zero
    assert!(parse(&damaged(type_at + 8, &[0])).is_err());
    // an entry offset past the chunk
    let table_at = type_at + 0x30;
    assert!(parse(&damaged(table_at, &le32(0x1000))).is_err());
    // a key past the key pool (the pool holds three keys; the third entry is key 2)
    let entry_at = type_at + 0x30 + 16;
    assert!(parse(&damaged(entry_at + 4, &le32(3))).is_err());
    assert!(parse(&damaged(entry_at + 4, &le32(2))).is_ok());
    // a value of size seven, and one with a reserved byte
    assert!(parse(&damaged(entry_at + 8, &le16(4))).is_err());
    assert!(parse(&damaged(entry_at + 10, &[1])).is_err());
    // a string value past the global pool (one string: index 1 is outside)
    assert!(parse(&damaged(entry_at + 12, &le32(1))).is_err());
}

#[test]
fn a_string_value_must_point_inside_the_global_pool() {
    let entries: Vec<u8> = [entry(0, 0, 3, 1)].concat();
    let body = vec![type_chunk(1, 0, 1, &dense(&[0]), &entries)];
    let bytes = table_of(
        &["only"],
        &[package(0x7f, 0, &["string"], &["k0"], &body)],
        1,
    );
    assert!(parse(&bytes).is_err(), "index 1 of a one-string pool");
    let entries: Vec<u8> = [entry(0, 0, 3, 0)].concat();
    let body = vec![type_chunk(1, 0, 1, &dense(&[0]), &entries)];
    let bytes = table_of(
        &["only"],
        &[package(0x7f, 0, &["string"], &["k0"], &body)],
        1,
    );
    assert!(parse(&bytes).is_ok());
}

#[test]
fn a_map_entry_smaller_than_its_header_and_a_cut_item_list_are_refused() {
    let entries = map_entry(0, 0, &[(1, 0x10, 1), (2, 0x10, 2)]);
    let body = vec![type_chunk(1, 0, 1, &dense(&[0]), &entries)];
    let bytes = table_of(&["v"], &[package(0x7f, 0, &["style"], &["k0"], &body)], 1);
    assert!(parse(&bytes).is_ok());
    let at = find(&bytes, &[16, 0, 1, 0]);
    let mut small = bytes.clone();
    small[at..at + 2].copy_from_slice(&le16(8));
    assert!(parse(&small).is_err(), "a map entry of size eight");
    let mut many = bytes.clone();
    many[at + 12..at + 16].copy_from_slice(&le32(3));
    assert!(parse(&many).is_err(), "three items declared, two present");
}

#[test]
fn the_budgets_are_refusals_at_their_edge() {
    let table = plain();
    let entries = TableLimits {
        max_entries: 3,
        ..TableLimits::default()
    };
    // three entries are present, and the type chunk declares four slots: the declaration is what is counted
    assert!(ResourceTable::parse(&table, entries).is_err());
    let entries = TableLimits {
        max_entries: 4,
        ..TableLimits::default()
    };
    assert!(ResourceTable::parse(&table, entries).is_ok());
    let items = map_entry(0, 0, &[(1, 0x10, 1), (2, 0x10, 2)]);
    let body = vec![type_chunk(1, 0, 1, &dense(&[0]), &items)];
    let bytes = table_of(&["v"], &[package(0x7f, 0, &["style"], &["k0"], &body)], 1);
    let limits = |n| TableLimits {
        max_map_items: n,
        ..TableLimits::default()
    };
    assert!(ResourceTable::parse(&bytes, limits(1)).is_err());
    assert!(ResourceTable::parse(&bytes, limits(2)).is_ok());
    let bytes_limit = TableLimits {
        max_bytes: table.len() - 1,
        ..TableLimits::default()
    };
    assert!(ResourceTable::parse(&table, bytes_limit).is_err());
}

#[test]
fn the_configurations_of_one_resource_follow_by_their_qualifier_string_and_not_by_the_file() {
    // the file holds zh, then the default, then de, for the same resource
    let one = |value: u32| entry(0, 0, 0x10, value);
    let body = vec![
        type_chunk_for(&config_in(b"zh"), 1, 0, 1, &dense(&[0]), &one(1)),
        type_chunk_for(&config(), 1, 0, 1, &dense(&[0]), &one(2)),
        type_chunk_for(&config_in(b"de"), 1, 0, 1, &dense(&[0]), &one(3)),
    ];
    let bytes = table_of(&["v"], &[package(0x7f, 0, &["string"], &["k0"], &body)], 1);
    let table = parse(&bytes).unwrap();
    let order: Vec<(String, u32)> = table
        .entries()
        .iter()
        .map(|e| {
            let EntryValue::Simple(v) = &e.value else {
                panic!("plain")
            };
            (table.config(e).qualifier(), v.data)
        })
        .collect();
    assert_eq!(
        order,
        [
            (String::new(), 2),
            ("de".to_owned(), 3),
            ("zh".to_owned(), 1)
        ]
    );
}

#[test]
fn a_map_entry_without_items_is_one_row_that_says_it_is_empty() {
    use super::query::Filter;
    let entries: Vec<u8> = [map_entry(0, 0x0103_0001, &[]), entry(1, 0, 0x10, 9)].concat();
    let body = vec![type_chunk(1, 0, 2, &dense(&[0, 16]), &entries)];
    let bytes = table_of(
        &["v"],
        &[package(0x7f, 0, &["style"], &["k0", "k1"], &body)],
        1,
    );
    let table = parse(&bytes).unwrap();
    let keys = table.query(&Filter::default());
    assert_eq!(keys.len(), 2, "the empty map entry and the plain one");
    let empty = table.row(keys[0]);
    assert!(empty.value.is_none());
    let item = empty.item.as_ref().expect("a map entry says what it is");
    assert_eq!(
        (item.count, item.index, item.parent_id),
        (0, None, 0x0103_0001)
    );
    assert!(table.row(keys[1]).item.is_none());
}

#[test]
fn a_map_entry_whose_size_field_says_eight_is_refused_even_when_nothing_follows_it() {
    // size 8 with a count of zero: no item is read past the end, so only the size itself is wrong
    let mut entry = le16(8);
    entry.extend(le16(1));
    entry.extend(le32(0));
    entry.extend(le32(0));
    entry.extend(le32(0));
    let body = vec![type_chunk(1, 0, 1, &dense(&[0]), &entry)];
    let bytes = table_of(&["v"], &[package(0x7f, 0, &["style"], &["k0"], &body)], 1);
    assert!(parse(&bytes).is_err());
    // the same entry with the size the platform writes is an empty map entry
    let ok = map_entry(0, 0, &[]);
    let body = vec![type_chunk(1, 0, 1, &dense(&[0]), &ok)];
    let bytes = table_of(&["v"], &[package(0x7f, 0, &["style"], &["k0"], &body)], 1);
    assert!(parse(&bytes).is_ok());
}

#[test]
fn a_chunk_of_a_type_not_read_is_counted_and_a_misaligned_one_is_refused() {
    let good = plain();
    let with_unknown = |size: usize| {
        let mut table = good.clone();
        let mut unknown = le16(0x0999);
        unknown.extend(le16(8));
        unknown.extend(le32(size as u32));
        unknown.resize(size, 0);
        table.extend(unknown);
        let total = table.len() as u32;
        table[4..8].copy_from_slice(&le32(total));
        table
    };
    let counted = parse(&with_unknown(12)).unwrap();
    assert_eq!(counted.skipped_chunks(), 1);
    assert_eq!(parse(&good).unwrap().skipped_chunks(), 0);
    // ten bytes: the chunk and, with it, the root chunk are not a whole number of words
    assert!(parse(&with_unknown(10)).is_err());
}

#[test]
fn a_table_must_have_its_global_pool_even_when_no_entry_needs_a_string() {
    let entries = entry(0, 0, 0x10, 5);
    let body = vec![type_chunk(1, 0, 1, &dense(&[0]), &entries)];
    let package = package(0x7f, 0, &["integer"], &["k0"], &body);
    let mut fields = le32(1);
    fields.truncate(4);
    let without = chunk(2, 12, &fields, &package);
    assert!(parse(&without).is_err());
    let with = table_of(
        &["v"],
        &[self::package(0x7f, 0, &["integer"], &["k0"], &body)],
        1,
    );
    assert!(parse(&with).is_ok());
}

#[test]
fn a_type_filter_is_the_whole_type_name() {
    use super::query::Filter;
    let table = parse(&plain()).unwrap();
    let by_type = |t: &str| {
        table
            .query(&Filter {
                resource_type: Some(t.to_owned()),
                ..Filter::default()
            })
            .len()
    };
    assert_eq!(by_type("string"), 3);
    assert_eq!(by_type("str"), 0);
    assert_eq!(by_type("strings"), 0);
    assert_eq!(by_type(""), 0);
}

#[test]
fn a_name_filter_with_a_package_needs_that_package() {
    use super::query::Filter;
    let table = parse(&plain()).unwrap();
    let by_name = |n: &str| {
        table
            .query(&Filter {
                name: Some(n.to_owned()),
                ..Filter::default()
            })
            .len()
    };
    assert_eq!(by_name("string/k0"), 1);
    assert_eq!(by_name("pkg:string/k0"), 1);
    assert_eq!(by_name("other:string/k0"), 0);
    assert_eq!(by_name("k0"), 0);
}
