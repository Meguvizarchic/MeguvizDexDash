use super::{
    arsc::{EntryValue, ResourceTable, TableLimits},
    xml,
};
use crate::manifest::{ManifestLimits, parse_manifest, parse_xml_resource};
use std::{io::Read, path::PathBuf, sync::Arc};

fn fixture(directory: &str, name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(directory)
        .join("generated")
        .join(name)
}

fn member(apk: &str, name: &str) -> Vec<u8> {
    member_of("resources", apk, name)
}

fn member_of(directory: &str, apk: &str, name: &str) -> Vec<u8> {
    let file = std::fs::File::open(fixture(directory, apk)).unwrap();
    let mut archive = zip::ZipArchive::new(file).unwrap();
    let mut entry = archive.by_name(name).unwrap();
    let mut bytes = Vec::new();
    entry.read_to_end(&mut bytes).unwrap();
    bytes
}

fn table() -> ResourceTable {
    ResourceTable::parse(
        &member("resources-small.apk", "resources.arsc"),
        TableLimits::default(),
    )
    .unwrap()
}

#[test]
fn the_table_has_one_row_per_resource_and_configuration_in_id_order() {
    let table = table();
    assert_eq!(table.packages().len(), 1);
    assert_eq!(table.packages()[0].name, "example.test");
    assert_eq!(table.packages()[0].id, 0x7f);
    assert_eq!(table.skipped_chunks(), 0);
    let rows: Vec<(String, String)> = table
        .entries()
        .iter()
        .map(|e| (table.local_name(e), table.config(e).qualifier()))
        .collect();
    // 13 plain entries and 4 map entries; a map entry's items are the query layer's rows
    assert_eq!(rows.len(), 17);
    assert_eq!(
        &rows[..4],
        &[
            ("string/app_name".to_owned(), "".to_owned()),
            ("string/app_name".to_owned(), "en".to_owned()),
            ("string/app_name".to_owned(), "zh-rCN".to_owned()),
            ("string/greeting".to_owned(), "".to_owned()),
        ]
    );
    let first = &table.entries()[0];
    assert_eq!(first.resource_id, 0x7f01_0000);
    assert!(matches!(
        first.value,
        EntryValue::Simple(v) if v.data_type == 3 && v.data == 0
    ));
    assert_eq!(
        table.string(0).unwrap().value.text.as_deref(),
        Some("Hello")
    );
    assert_eq!(
        table.qualified_name(0x7f04_0000).as_deref(),
        Some("example.test:color/accent")
    );
    assert_eq!(table.qualified_name(0x0101_0000), None);
}

#[test]
fn a_map_entry_keeps_its_parent_and_its_named_items() {
    let table = table();
    let style = table
        .entries()
        .iter()
        .find(|e| table.local_name(e) == "style/AppTheme" && table.config(e).is_default())
        .unwrap();
    let EntryValue::Map { parent, items } = &style.value else {
        panic!("a style is a map entry");
    };
    assert_eq!(*parent, 0x0103_0000);
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].name, 0x0101_0000);
}

#[test]
fn a_damaged_table_is_refused_and_never_read_as_far_as_it_goes() {
    let good = member("resources-small.apk", "resources.arsc");
    // the type of the root chunk
    let mut bad = good.clone();
    bad[0] = 9;
    assert!(ResourceTable::parse(&bad, TableLimits::default()).is_err());
    // the size of the root chunk
    let mut short = good.clone();
    short.truncate(good.len() - 4);
    assert!(ResourceTable::parse(&short, TableLimits::default()).is_err());
    // the fixture the reference engine reads past its package: ours refuses it
    let corrupt = member("resources-corrupt.apk", "resources.arsc");
    assert!(ResourceTable::parse(&corrupt, TableLimits::default()).is_err());
    // every prefix of the table either parses or fails, none panics
    for cut in (0..good.len()).step_by(4) {
        let _ = ResourceTable::parse(&good[..cut], TableLimits::default());
    }
    // the entry budget is a refusal, not a clip
    let limits = TableLimits {
        max_entries: 3,
        ..TableLimits::default()
    };
    assert!(ResourceTable::parse(&good, limits).is_err());
}

#[test]
fn a_layout_keeps_what_the_reference_leaves_out() {
    let bytes: Arc<[u8]> = Arc::from(member("resources-small.apk", "res/layout/main.xml"));
    let document = parse_xml_resource(bytes, ManifestLimits::default()).unwrap();
    let text = xml::render(&document).unwrap();
    // The reference writes `android:orientation="14"` for a string attribute (the pool index),
    // and drops the app namespace, the attribute in it and the text node. This text keeps all
    // four; every other line is the reference's.
    assert_eq!(
        text,
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n\
<LinearLayout\n  xmlns:android=\"http://schemas.android.com/apk/res/android\"\n  xmlns:app=\"http://schemas.android.com/apk/res-auto\"\n  android:orientation=\"vertical\"\n  android:layout_width=\"match_parent\"\n  android:layout_height=\"match_parent\">\n  <TextView\n    android:text=\"@7f010000\"\n    android:textSize=\"16sp\"\n    android:textColor=\"#ff336699\"\n    android:enabled=\"true\"\n    app:text=\"hello\">\n    hello\n  </TextView>\n</LinearLayout>\n"
    );
}

#[test]
fn a_manifest_is_written_as_the_reference_writes_it_except_for_its_text_node() {
    let bytes: Arc<[u8]> = Arc::from(member_of(
        "decode",
        "manifest-small.apk",
        "AndroidManifest.xml",
    ));
    let document = parse_manifest(bytes, ManifestLimits::default()).unwrap();
    let text = xml::render(&document).unwrap();
    let expected = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<manifest\n  xmlns:android=\"http://schemas.android.com/apk/res/android\"\n  package=\"example.test\"\n  android:versionCode=\"7\"\n  android:versionName=\"7.2\">\n  <uses-sdk\n    android:minSdkVersion=\"21\"\n    android:targetSdkVersion=\"35\"/>\n  <uses-permission android:name=\"p.permission\"/>\n  <uses-permission android:name=\"p.permission\"/>\n  <permission android:name=\"p.permission\"/>\n  <application>\n    <activity android:name=\".Main\"/>\n    <service\n      android:name=\".Svc\"\n      android:exported=\"true\"/>\n    <receiver android:name=\".Receiver\"/>\n    <provider android:name=\".Provider\"/>\n    <activity-alias android:name=\".Alias\"/>\n    text\n  </application>\n</manifest>\n";
    // the fixture has a text node in <application>; the reference's 690-byte text omits it
    assert_eq!(text, expected);
    assert_eq!(text.len(), 690 + "    text\n".len());
}
