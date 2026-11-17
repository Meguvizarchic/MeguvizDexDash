//! Which of the frozen relations each SQL dialect advertises (MDD-070).
//!
//! The registry in [`crate::provider::hostlab`] answers all fifty-six relations of `conformance/manifests/relations.json`.
//! A dialect is held to the relations of the reference it imitates: dexsql 0.1.0 and dexsql 0.1.1 both list the same
//! fifty-six, and answer them alike on every recorded fixture (`artifacts/mdd-070/reference-versions.json`), so neither
//! withholds one today. The list is kept here, per dialect, so that a difference found later is one entry in one place
//! and takes effect in `list_tables`, `describe_table` and the SQL bridge alike: a relation a dialect withholds is not
//! listed, not described and not in the schema its statements are bound against.
//!
//! Naming a profile here grants no admission. Admission is a separate act of qualification
//! (`compatibility/ledger.json`), and nothing in this module can state it.
use crate::{
    dialects::SqlDialect,
    provider::{CompatibilityProfile, SqlRelation, hostlab::ContractRelation},
};

/// The profile held to dexsql 0.1.0.
pub const DEXSQL_010_PROFILE: &str = "dexsql-0.1.0-compat-v1";
/// The profile held to dexsql 0.1.1.
pub const DEXSQL_011_PROFILE: &str = "dexsql-0.1.1-compat-v1";

/// Relations of the registry that a dialect does not advertise, by name. Empty for all three dialects: the two
/// compatibility references list every relation, and the native dialect has no reference to be held to.
fn withheld(dialect: SqlDialect) -> Vec<&'static str> {
    // `mut` is used only by the test-only extension below
    #[cfg_attr(not(test), allow(unused_mut))]
    let mut names: Vec<&'static str> = match dialect {
        SqlDialect::NativeV1 | SqlDialect::DexSql010 | SqlDialect::DexSql011 => Vec::new(),
    };
    // tests only: the effect of a withheld relation is observed through the real bridge and tools
    #[cfg(test)]
    TEST_WITHHELD.with(|extra| names.extend(extra.borrow().iter().copied()));
    names
}

#[cfg(test)]
thread_local! {
    static TEST_WITHHELD: std::cell::RefCell<Vec<&'static str>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// Run `body` with the given relations withheld from every dialect on this thread, and restore the list afterwards.
#[cfg(test)]
pub(crate) fn with_withheld<R>(names: &[&'static str], body: impl FnOnce() -> R) -> R {
    let before = TEST_WITHHELD.with(|extra| extra.replace(names.to_vec()));
    let result = body();
    TEST_WITHHELD.with(|extra| *extra.borrow_mut() = before);
    result
}

/// The compatibility profile a dialect is held to, or `None` for the native dialect, which imitates nothing.
/// The profile is named, not admitted.
pub fn profile_for(dialect: SqlDialect) -> Option<CompatibilityProfile> {
    let name = match dialect {
        SqlDialect::NativeV1 => return None,
        SqlDialect::DexSql010 => DEXSQL_010_PROFILE,
        SqlDialect::DexSql011 => DEXSQL_011_PROFILE,
    };
    CompatibilityProfile::new(name, dialect).ok()
}

/// The relations the dialect advertises, in the order of `relations.json`.
pub fn advertised_relations(dialect: SqlDialect) -> Vec<ContractRelation> {
    advertised_without(&withheld(dialect))
}

/// Whether the dialect advertises the relation of that name. A name that is no frozen relation is none of this
/// module's business and is not hidden by it.
pub fn advertises(dialect: SqlDialect, name: &str) -> bool {
    advertises_without(name, &withheld(dialect))
}

/// The relations a provider offers, less the frozen ones the dialect withholds. Relations of other names (a provider's
/// own physical relations) pass untouched.
pub fn visible_relations(relations: Vec<SqlRelation>, dialect: SqlDialect) -> Vec<SqlRelation> {
    visible_without(relations, &withheld(dialect))
}

fn is_withheld(name: &str, withheld: &[&str]) -> bool {
    ContractRelation::parse(name).is_some() && withheld.contains(&name)
}

fn advertises_without(name: &str, withheld: &[&str]) -> bool {
    !is_withheld(name, withheld)
}

fn advertised_without(withheld: &[&str]) -> Vec<ContractRelation> {
    ContractRelation::all()
        .into_iter()
        .filter(|relation| !withheld.contains(&relation.name()))
        .collect()
}

fn visible_without(relations: Vec<SqlRelation>, withheld: &[&str]) -> Vec<SqlRelation> {
    relations
        .into_iter()
        .filter(|relation| !is_withheld(&relation.name, withheld))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const DIALECTS: [SqlDialect; 3] = [
        SqlDialect::NativeV1,
        SqlDialect::DexSql010,
        SqlDialect::DexSql011,
    ];

    fn read(relative: &str) -> Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(relative);
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    fn frozen() -> Vec<String> {
        read("conformance/manifests/relations.json")["relations"]
            .as_array()
            .unwrap()
            .iter()
            .map(|relation| relation["name"].as_str().unwrap().to_owned())
            .collect()
    }

    fn names(relations: &[ContractRelation]) -> Vec<String> {
        relations.iter().map(|r| r.name().to_owned()).collect()
    }

    #[test]
    fn every_dialect_advertises_the_fifty_six_frozen_relations_in_their_order() {
        for dialect in DIALECTS {
            assert_eq!(
                names(&advertised_relations(dialect)),
                frozen(),
                "{dialect:?}"
            );
            for name in frozen() {
                assert!(advertises(dialect, &name), "{dialect:?} {name}");
            }
        }
    }

    #[test]
    fn the_lists_are_those_the_qualification_record_found_for_each_reference() {
        let record = read("conformance/manifests/full-relation-qualification.json");
        for (dialect, key) in [
            (SqlDialect::DexSql010, "dexsql-0.1.0"),
            (SqlDialect::DexSql011, "dexsql-0.1.1"),
        ] {
            let entry = &record["dialects"][key];
            assert_eq!(
                entry["relations_advertised"].as_u64().unwrap() as usize,
                advertised_relations(dialect).len(),
                "{key}"
            );
        }
        // the two references were found to answer alike, which is why neither dialect withholds anything
        let versions = read("artifacts/mdd-070/reference-versions.json");
        assert_eq!(versions["reading"], "identical");
        for dialect in DIALECTS {
            assert!(withheld(dialect).is_empty(), "{dialect:?}");
        }
        // and a test that withholds one is seen by the public functions, for every dialect, then undone
        with_withheld(&["debug_opcodes"], || {
            for dialect in DIALECTS {
                assert_eq!(advertised_relations(dialect).len(), 55, "{dialect:?}");
                assert!(!advertises(dialect, "debug_opcodes"), "{dialect:?}");
            }
        });
        assert_eq!(advertised_relations(SqlDialect::DexSql010).len(), 56);
    }

    #[test]
    fn the_profiles_are_named_as_the_ledger_names_them_and_are_not_admitted() {
        let ledger = read("compatibility/ledger.json");
        let profiles = ledger["profiles"].as_array().unwrap();
        for (dialect, name) in [
            (SqlDialect::DexSql010, DEXSQL_010_PROFILE),
            (SqlDialect::DexSql011, DEXSQL_011_PROFILE),
        ] {
            let profile = profile_for(dialect).unwrap();
            assert_eq!((profile.name.as_str(), profile.dialect), (name, dialect));
            let entry = profiles
                .iter()
                .find(|entry| entry["name"] == name)
                .unwrap_or_else(|| panic!("{name} is not in the ledger"));
            assert_eq!(entry["admitted"], false, "{name}");
        }
        assert!(profile_for(SqlDialect::NativeV1).is_none());
    }

    #[test]
    fn a_withheld_relation_is_neither_advertised_nor_visible_and_nothing_else_is() {
        let withheld = ["debug_opcodes", "not_a_frozen_relation"];
        let kept = advertised_without(&withheld);
        assert_eq!(kept.len(), 55);
        assert!(!names(&kept).contains(&"debug_opcodes".to_owned()));
        // the order of the others is the order of the registry
        let mut expected = frozen();
        expected.retain(|name| name != "debug_opcodes");
        assert_eq!(names(&kept), expected);
        assert!(!advertises_without("debug_opcodes", &withheld));
        assert!(advertises_without("debug_opcodes_extra", &withheld));
        // a name that is no frozen relation is never hidden, even when listed as withheld
        assert!(advertises_without("not_a_frozen_relation", &withheld));
    }

    #[test]
    fn a_providers_own_relations_pass_through_the_filter() {
        use crate::{provider::SqlColumn, values::SqlType};
        let relation = |name: &str| SqlRelation {
            name: name.to_owned(),
            columns: vec![SqlColumn {
                id: "a".into(),
                name: "a".into(),
                data_type: SqlType::U64,
                nullable: false,
            }],
            required_layers: Vec::new(),
            estimated_rows: None,
        };
        let offered = vec![
            relation("debug_opcodes"),
            relation("native_types"),
            relation("methods"),
        ];
        let seen: Vec<String> = visible_without(offered, &["debug_opcodes", "native_types"])
            .into_iter()
            .map(|relation| relation.name)
            .collect();
        assert_eq!(seen, ["native_types", "methods"]);
    }
}
