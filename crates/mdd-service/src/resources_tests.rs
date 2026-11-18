//! What the dataset's resource functions promise beyond the happy path: a name that two members share
//! is not guessed at, one table is kept per input, the size cap has its edge where it says, and a
//! dataset without DEX knows it.
use super::{MAX_RESOURCE_BYTES, ResourceFailure, within_cap};
use crate::{Dataset, Dialect, InputRequest};
use mdd_session::ResourceLimits;
use mdd_sql::control::SqlLimits;
use std::{path::PathBuf, sync::Arc};

fn fixture(relative: &str) -> InputRequest {
    InputRequest {
        path: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/resources")
            .join(relative),
        kind: None,
    }
}

fn open(names: &[&str]) -> Dataset {
    let inputs: Vec<InputRequest> = names.iter().map(|n| fixture(n)).collect();
    Dataset::open(
        &inputs,
        Dialect::DexSql010,
        ResourceLimits::default(),
        SqlLimits::default(),
    )
    .unwrap()
}

#[test]
fn the_size_cap_is_exactly_the_stated_number_of_bytes() {
    assert_eq!(MAX_RESOURCE_BYTES, 64 * 1024 * 1024);
    assert!(within_cap(0));
    assert!(within_cap(MAX_RESOURCE_BYTES));
    assert!(!within_cap(MAX_RESOURCE_BYTES + 1));
    assert!(!within_cap(MAX_RESOURCE_BYTES * 2));
}

#[test]
fn a_name_that_two_members_share_is_refused_and_both_are_listed() {
    let dataset = open(&["generated/resources-duplicate.apk"]);
    let files = dataset.resource_files(0).unwrap();
    let shared: Vec<u64> = files
        .iter()
        .filter(|f| f.name == "assets/dup.txt")
        .map(|f| f.entry_index)
        .collect();
    assert_eq!(shared.len(), 2, "both members are listed");
    assert_ne!(shared[0], shared[1]);
    for hex in [false, true] {
        match dataset.resource(0, "assets/dup.txt", hex) {
            Err(ResourceFailure::Several(message)) => {
                assert!(message.contains("2 entries"), "{message}")
            }
            other => panic!(
                "expected the name to be ambiguous, got {:?}",
                other.map(|_| ())
            ),
        }
    }
    // a name that only one member has is read as before
    assert!(dataset.resource(0, "classes.dex", true).is_ok());
}

#[test]
fn each_input_has_its_own_table() {
    let dataset = open(&[
        "generated/resources-small.apk",
        "probe/probe_enums/typed-table.apk",
    ]);
    let first = dataset.resource_table(0).unwrap();
    let second = dataset.resource_table(1).unwrap();
    assert_eq!(first.table.packages()[0].name, "example.test");
    assert_eq!(second.table.packages()[0].name, "example.typed");
    // and a table is parsed once
    assert!(Arc::ptr_eq(&first, &dataset.resource_table(0).unwrap()));
    assert!(Arc::ptr_eq(&second, &dataset.resource_table(1).unwrap()));
}

#[test]
fn a_dataset_without_dex_knows_it_and_a_missing_table_is_not_found() {
    let without = open(&["generated/resources-only.apk"]);
    assert!(!without.has_dex());
    assert_eq!(without.dex_count(), 0);
    assert!(without.require_dex().is_err());
    assert!(without.bridge().is_err());
    let with = open(&["generated/resources-small.apk"]);
    assert!(with.has_dex());
    assert!(with.require_dex().is_ok());
    let bare = open(&["generated/resources-no-arsc.apk"]);
    assert!(matches!(
        bare.resource_table(0),
        Err(ResourceFailure::NotFound(_))
    ));
    assert!(matches!(
        bare.resource_files(3),
        Err(ResourceFailure::NoSuchInput(_))
    ));
}
