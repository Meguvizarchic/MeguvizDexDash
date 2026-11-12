//! NativeSession / Graph / Rules skeleton behaviour.
//!
//! These tests use only tracked synthetic fixtures; real-APK runs are manual
//! and recorded as artifacts, not as unit-test inputs.
use mdd_facts::hostlab::{
    CATALOG, EXPECTED_FEATURES, FeatureStatus, NativeLayers, NativeSession, RuleRun, Rules,
    catalog::{HostlabCatalog, REQUIRED_CONSTANTS, REQUIRED_LISTS},
    graph::dotted,
};
use std::{collections::BTreeMap, path::PathBuf};

fn fixture(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative)
}

fn structured_session() -> NativeSession {
    let mut session = NativeSession::open(fixture("tests/fixtures/generated/structured-035.dex"))
        .expect("open structured fixture");
    session
        .prepare(NativeLayers::STRUCTURAL)
        .expect("prepare structural layers");
    session
}

#[test]
fn catalog_matches_the_frozen_feature_order() {
    assert_eq!(CATALOG.len(), 27);
    let names: Vec<_> = CATALOG.iter().map(|spec| spec.name).collect();
    assert_eq!(names, EXPECTED_FEATURES.to_vec());
    // Every catalog entry has a body or is explicitly pending; nothing else.
    let implemented = CATALOG
        .iter()
        .filter(|spec| {
            spec.implementation == mdd_facts::hostlab::FeatureImplementation::Implemented
        })
        .count();
    assert_eq!(implemented, 5, "implemented rule count is part of the gate");
    let mut unique = std::collections::BTreeSet::new();
    for spec in CATALOG {
        assert!(unique.insert(spec.name), "duplicate feature id");
    }
}

#[test]
fn unknown_catalog_keys_fail_loudly() {
    let neutral = HostlabCatalog::neutral("test/neutral");
    let error = neutral.list("no.such.list").unwrap_err();
    assert_eq!(error.code, mdd_types::ErrorCode::InternalFault);
    let error = neutral.constant("no.such.constant").unwrap_err();
    assert_eq!(error.code, mdd_types::ErrorCode::InternalFault);
    // A catalog with no lists must not silently produce MISSING verdicts: it is
    // refused at construction, and a rule run never starts on a partial one.
    let empty = HostlabCatalog::new(
        "test/empty".into(),
        "0".repeat(40),
        "0".repeat(64),
        BTreeMap::new(),
        BTreeMap::new(),
    );
    let error = empty.unwrap_err();
    assert_eq!(error.code, mdd_types::ErrorCode::InvalidArgument);
}

fn catalog_parts() -> (BTreeMap<String, Vec<String>>, BTreeMap<String, String>) {
    let lists = REQUIRED_LISTS
        .iter()
        .map(|key| ((*key).to_owned(), vec![format!("synthetic.absent.{key}")]))
        .collect();
    let constants = REQUIRED_CONSTANTS
        .iter()
        .map(|key| ((*key).to_owned(), format!("synthetic.absent.{key}")))
        .collect();
    (lists, constants)
}

#[test]
fn catalog_constructor_validates_keys_and_digests() {
    let build = |lists: BTreeMap<String, Vec<String>>,
                 constants: BTreeMap<String, String>,
                 commit: &str,
                 digest: &str| {
        HostlabCatalog::new(
            "test/c".into(),
            commit.into(),
            digest.into(),
            lists,
            constants,
        )
    };
    let (lists, constants) = catalog_parts();
    let commit = "a".repeat(40);
    let digest = "b".repeat(64);
    let ok = build(lists.clone(), constants.clone(), &commit, &digest).expect("complete catalog");
    assert_eq!(ok.list(REQUIRED_LISTS[0]).unwrap().len(), 1);
    assert_eq!(
        ok.constant(REQUIRED_CONSTANTS[0]).unwrap(),
        format!("synthetic.absent.{}", REQUIRED_CONSTANTS[0])
    );

    // A missing list, a missing constant, an unknown extra key of either kind and
    // malformed digests are each refused, and the error names the offender.
    let mut short = lists.clone();
    short.remove(REQUIRED_LISTS[3]);
    let error = build(short, constants.clone(), &commit, &digest).unwrap_err();
    assert_eq!(error.details["list"], REQUIRED_LISTS[3]);

    let mut short = constants.clone();
    short.remove(REQUIRED_CONSTANTS[1]);
    let error = build(lists.clone(), short, &commit, &digest).unwrap_err();
    assert_eq!(error.details["constant"], REQUIRED_CONSTANTS[1]);

    let mut extra = lists.clone();
    extra.insert("run.blockCandidate".into(), Vec::new());
    let error = build(extra, constants.clone(), &commit, &digest).unwrap_err();
    assert_eq!(error.details["list"], "run.blockCandidate");

    let mut extra = constants.clone();
    extra.insert("block.resultClas".into(), String::new());
    let error = build(lists.clone(), extra, &commit, &digest).unwrap_err();
    assert_eq!(error.details["constant"], "block.resultClas");

    assert!(build(lists.clone(), constants.clone(), "ABC", &digest).is_err());
    assert!(build(lists.clone(), constants.clone(), &commit, &"B".repeat(64)).is_err());
    assert!(
        HostlabCatalog::new("".into(), commit, digest, lists, constants).is_err(),
        "an empty id is refused"
    );
}

#[test]
fn session_binds_one_snapshot_and_reports_occurrence_identity() {
    let session = structured_session();
    assert!(session.is_prepared());
    assert_eq!(session.occurrences().len(), 1);
    assert_eq!(session.class_count().unwrap(), 1);
    assert_eq!(session.occurrence_state(0).unwrap().class_count(), Some(1));
    assert_eq!(session.occurrence_state(0).unwrap().method_count(), Some(4));
    let coverage = session.coverage();
    assert_eq!(
        coverage.snapshot_id,
        session.snapshot().manifest().snapshot_id
    );
    assert_eq!(coverage.total_class_definitions, 1);
    assert_eq!(coverage.class_index_entries, 1);
    assert_eq!(coverage.duplicate_class_descriptor_count, 0);
    assert!(coverage.archive_directory_complete);
    let state = &coverage.occurrences[0];
    assert_eq!(
        state.entry_name.as_deref(),
        None,
        "raw DEX has no member name"
    );
    assert_eq!(
        state.dex_occurrence_id,
        session.inventory().selected_dexes()[0].dex_occurrence_id
    );
    // Optional layers stay visibly unbuilt rather than reported as empty.
    assert_eq!(state.code, mdd_facts::hostlab::LayerState::NotBuilt);
    assert_eq!(state.references, mdd_facts::hostlab::LayerState::NotBuilt);
    assert_eq!(state.annotations, mdd_facts::hostlab::LayerState::NotBuilt);
}

#[test]
fn structural_gate_rejects_an_unprepared_session() {
    let session =
        NativeSession::open(fixture("tests/fixtures/generated/structured-035.dex")).unwrap();
    assert!(!session.is_prepared());
    let error = session.class_count().unwrap_err();
    assert_eq!(error.code, mdd_types::ErrorCode::IncompleteFacts);
    let error = session.graph().map(|_| ()).unwrap_err();
    assert_eq!(error.code, mdd_types::ErrorCode::IncompleteFacts);
    let neutral = HostlabCatalog::neutral("test/neutral");
    let error = Rules::with_catalog(&session, &neutral)
        .err()
        .expect("rules need prepared facts");
    assert_eq!(error.code, mdd_types::ErrorCode::IncompleteFacts);
}

#[test]
fn graph_returns_headers_members_and_inheritance_like_the_reference() {
    let session = structured_session();
    let graph = session.graph().unwrap();
    let node = graph.class("fixture.A").unwrap().expect("fixture.A exists");
    assert_eq!(node.descriptor, "Lfixture/A;");
    assert_eq!(node.superclass.as_deref(), Some("java.lang.Object"));
    assert!(node.interfaces.is_empty());
    assert!(graph.class("fixture.Missing").unwrap().is_none());

    let methods = graph.methods(&["fixture.A"], false).unwrap();
    let names: Vec<_> = methods.iter().map(|method| method.name.as_str()).collect();
    assert_eq!(names, ["caller", "nativeNoBody", "target", "withTry"]);
    // Erased descriptors, not rendered Java generics.
    assert_eq!(methods[0].proto, "()V");
    assert_eq!(methods[0].args.len(), 0);
    assert_eq!(methods[0].result.as_str(), "void");
    assert!(methods[1].is_static(), "nativeNoBody has ACC_STATIC");
    assert_eq!(
        methods[1].reference(),
        "fixture.A#nativeNoBody()V",
        "reference form is owner#name(proto)"
    );

    // `discover` selects owners by return type and returns the whole owner.
    let discovered = graph.discover("V").unwrap();
    assert_eq!(discovered.len(), 4, "whole owner is loaded, not one method");
    assert!(graph.discover("Lmissing/Type;").unwrap().is_empty());
}

#[test]
fn graph_subclass_keeps_platform_shortcuts() {
    let session = structured_session();
    let graph = session.graph().unwrap();
    assert!(graph.subclass("fixture.A", "java.lang.Object").unwrap());
    assert!(!graph.subclass("fixture.A", "Lfixture/A;").unwrap());
    assert!(
        graph
            .subclass("android.widget.TextView", "android.view.View")
            .unwrap()
    );
    assert!(
        graph
            .subclass("android.app.LauncherActivity", "android.app.Activity")
            .unwrap()
    );
    // The shortcut is a prefix rule, not "any name ending in Activity": an
    // application class only matches when its real superclass chain does.
    assert!(
        !graph
            .subclass("com.example.SplashActivity", "android.app.Activity")
            .unwrap()
    );
    assert!(!graph.subclass("fixture.A", "android.app.Activity").unwrap());
    assert!(
        !graph
            .subclass("fixture.Missing", "java.lang.Object")
            .unwrap()
    );
}

#[test]
fn dotted_and_descriptor_helpers_are_exact() {
    assert_eq!(dotted("Lfixture/A;").unwrap(), "fixture.A");
    assert_eq!(dotted("Ljava/util/List;").unwrap(), "java.util.List");
    assert_eq!(dotted("I").unwrap(), "int");
    assert_eq!(dotted("V").unwrap(), "void");
    assert_eq!(dotted("[Ljava/lang/String;").unwrap(), "java.lang.String[]");
    assert_eq!(dotted("[[I").unwrap(), "int[][]");
    assert!(dotted("Q").is_err(), "unknown shape must not be guessed");
    assert!(
        dotted("Lfixture/A").is_err(),
        "unterminated class must fail"
    );
}

#[test]
fn rule_run_reports_every_feature_and_refuses_admission() {
    let session = structured_session();
    let neutral = HostlabCatalog::neutral("test/neutral");
    let run: RuleRun = session.run_rules(&neutral).expect("rules execute");
    assert_eq!(run.features.len(), 27);
    assert_eq!(run.implemented, 5);
    assert_eq!(run.pending, 22);
    assert_eq!(run.catalog_id, neutral.id);
    assert_eq!(run.reference_commit, neutral.reference_commit);
    assert!(!run.complete, "pending rules must keep the run incomplete");
    assert!(
        !run.admitted,
        "MDD-051 admission is not granted by a skeleton"
    );
    for name in EXPECTED_FEATURES {
        let report = run.features.get(name).expect("every feature is reported");
        if report.status == FeatureStatus::NotImplemented {
            assert!(
                report.detail.contains("not implemented"),
                "pending rules explain themselves"
            );
        }
    }
    // On the synthetic fixture nothing references the BIL catalog.
    assert_eq!(run.features["block_update"].status, FeatureStatus::Missing);
    assert_eq!(run.features["block_update"].detail, "-");
    assert_eq!(run.features["full_number"].status, FeatureStatus::Missing);
    assert_eq!(
        run.features["player_status_bar"].status,
        FeatureStatus::Missing
    );
    assert_eq!(
        run.features["teenagers_mode"].status,
        FeatureStatus::Missing
    );
    assert_eq!(run.features["merchandise"].status, FeatureStatus::Missing);
    assert_eq!(run.features["merchandise"].detail, "false");
    // MISSING here is a business verdict about this fixture, not a backend fault.
    assert!(run.features["block_update"].status.is_business_verdict());
    assert!(!run.features["dynamic_tabs"].status.is_business_verdict());
    assert!(
        run.semantic_divergences
            .iter()
            .any(|item| item.id == "admission-gate")
    );
}

#[test]
fn multidex_occurrences_keep_ordinals_and_duplicate_class_evidence() {
    // Two genuinely different DEX members: classes.dex carries Lfixture/A;,
    // classes2.dex is the empty minimal DEX.
    let mut session = NativeSession::open(fixture("tests/fixtures/generated/multidex-stored.apk"))
        .expect("open multidex fixture");
    session.prepare(NativeLayers::STRUCTURAL).unwrap();
    assert_eq!(session.occurrences().len(), 2);
    assert_eq!(session.occurrence_state(0).unwrap().class_count(), Some(1));
    assert_eq!(session.occurrence_state(1).unwrap().class_count(), Some(0));
    assert_eq!(session.class_count().unwrap(), 1);
    let coverage = session.coverage();
    assert_eq!(
        coverage.occurrences[0].entry_name.as_deref(),
        Some("classes.dex")
    );
    assert_eq!(
        coverage.occurrences[1].entry_name.as_deref(),
        Some("classes2.dex")
    );
    assert_eq!(coverage.selected_dex_count, 2);
    assert!(coverage.selected_dex_bytes_complete);
    // DexSQL `file_id` is the archive enumeration order, i.e. `dex_ordinal`.
    assert_eq!(session.hostlab_file_ids().unwrap(), [0, 1]);
}

#[test]
fn duplicate_class_descriptor_is_an_explicit_ambiguity() {
    // The same DEX content twice: Lfixture/A; exists in both occurrences.
    let mut session =
        NativeSession::open(fixture("tests/fixtures/generated/duplicate-content.apk")).unwrap();
    session.prepare(NativeLayers::STRUCTURAL).unwrap();
    let coverage = session.coverage();
    assert_eq!(coverage.total_class_definitions, 2);
    assert_eq!(coverage.class_index_entries, 1);
    assert_eq!(coverage.duplicate_class_descriptor_count, 1);
    assert_eq!(coverage.duplicate_class_descriptors, ["Lfixture/A;"]);
    let graph = session.graph().unwrap();
    let error = graph.class("fixture.A").map(|_| ()).unwrap_err();
    assert_eq!(error.code, mdd_types::ErrorCode::UnsupportedCapability);
    assert!(error.message.contains("duplicate class definitions"));
}

#[test]
fn hostlab_file_id_follows_archive_enumeration_not_numeric_member_order() {
    // `member-policy.apk` stores `classes10.dex` before `classes2.dex`. The
    // frozen backend reports file_id 0 for `classes10.dex` and 1 for
    // `classes2.dex` (independently reproduced against dexsql 0.1.0); a numeric
    // re-sort would instead give [9, 1].
    let mut session = NativeSession::open(fixture("tests/fixtures/generated/member-policy.apk"))
        .expect("open member-policy fixture");
    session.prepare(NativeLayers::STRUCTURAL).unwrap();
    let names: Vec<_> = session
        .occurrences()
        .iter()
        .map(|state| state.entry_name.as_deref().unwrap())
        .collect();
    assert_eq!(names, ["classes10.dex", "classes2.dex"]);
    assert_eq!(session.hostlab_file_ids().unwrap(), [0, 1]);
}
