//! The public relations beyond the seventeen contract names: what is refused when a layer is missing, and that every
//! one of them answers on a DEX that has the layers. The rows themselves are held to the recorded answers of the
//! reference engine by `conformance/relations/public_relations_diff.py`.
use super::tests::open;
use super::*;
use crate::{SqlBridge, control::SqlLimits, dialects::SqlDialect};
use mdd_input::snapshot::InputKind;
use std::sync::Arc;

const FIXTURE: &str = "tests/fixtures/references/generated/classic-035.dex";

fn needs(relation: PublicRelation, layer: FactLayer) -> bool {
    relation.required_layers().contains(&layer)
}

#[test]
fn a_relation_whose_layer_is_not_built_is_refused_not_answered_empty() {
    let harness = open(&[(FIXTURE, InputKind::RawDex)]);
    // Only metadata and definitions: nothing above them was built.
    let bare = harness.provider(false, false, false);
    for relation in PublicRelation::ALL {
        let name = relation.name();
        let result = bare.require_relation(name);
        let opened = Arc::clone(&bare).open_cursor(
            name,
            crate::control::SqlControl::new(SqlLimits::default(), None),
        );
        let above = needs(relation, FactLayer::CodeLayout)
            || needs(relation, FactLayer::References)
            || needs(relation, FactLayer::Annotations);
        if above {
            let error = result.expect_err(name);
            assert_eq!(error.code, ErrorCode::IncompleteFacts, "{name}");
            assert_eq!(error.details["relation"], name, "{name}");
            assert!(opened.is_err(), "{name}: the cursor path must refuse too");
        } else {
            result.unwrap_or_else(|error| panic!("{name}: {error:?}"));
            assert!(opened.is_ok(), "{name}");
        }
    }
}

#[test]
fn code_without_references_refuses_only_what_needs_the_references() {
    let harness = open(&[(FIXTURE, InputKind::RawDex)]);
    let provider = harness.provider(true, false, true);
    for relation in PublicRelation::ALL {
        let result = provider.require_relation(relation.name());
        if needs(relation, FactLayer::References) {
            let error = result.expect_err(relation.name());
            assert_eq!(
                error.code,
                ErrorCode::IncompleteFacts,
                "{}",
                relation.name()
            );
        } else {
            result.unwrap_or_else(|error| panic!("{}: {error:?}", relation.name()));
        }
    }
}

#[test]
fn every_public_relation_answers_with_its_declared_columns_when_the_layers_are_built() {
    let harness = open(&[(FIXTURE, InputKind::RawDex)]);
    let bridge = SqlBridge::new(
        harness.provider(true, true, true),
        SqlDialect::DexSql011,
        SqlLimits::default(),
    )
    .unwrap();
    for relation in PublicRelation::ALL {
        let name = relation.name();
        let result = bridge
            .query(&format!("SELECT * FROM {name}"))
            .unwrap_or_else(|error| panic!("{name}: {error:?}"));
        assert_eq!(result.columns().len(), relation.columns().len(), "{name}");
        // The header, id and index tables of any DEX are never empty.
        if matches!(
            relation,
            PublicRelation::MapItems | PublicRelation::IdItems | PublicRelation::TypeIds
        ) {
            assert!(!result.rows().is_empty(), "{name} produced no rows");
        }
    }
}

#[test]
fn a_public_relation_is_not_reached_through_another_providers_name() {
    let harness = open(&[(FIXTURE, InputKind::RawDex)]);
    let provider = harness.provider(true, true, true);
    // The native physical relations keep their own spellings; a contract spelling with another case is no name.
    assert!(provider.require_relation("Map_Items").is_err());
    assert!(provider.require_relation("native_map_items").is_err());
    assert!(ContractRelation::parse("map_items").is_some());
    assert!(ContractRelation::parse_ignoring_case("MAP_ITEMS").is_some());
}
