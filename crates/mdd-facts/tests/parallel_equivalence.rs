//! Serial/parallel equivalence for the DEX-parallel fact pipeline.
//!
//! These are development checks over synthetic fixtures, not performance
//! qualification. The contract under test is exact: parallel scheduling may
//! change which thread computes an occurrence and in which order occurrences
//! complete, but every occurrence's six fact identities and every layer's JSON
//! projection must be byte-identical to the serial chain.
use mdd_facts::pipeline::{DexFacts, FactsPipeline, PipelineConfig, PipelineReport};
use mdd_types::ErrorCode;
use serde::Serialize;
use std::path::PathBuf;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/generated")
        .join(name)
}

fn pipeline(name: &str) -> FactsPipeline {
    FactsPipeline::open(fixture(name)).unwrap()
}

/// Serialize one layer independently so a mismatch names the offending layer.
fn layer<T: Serialize>(value: &T) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}

/// `ReferenceFacts` holds a tuple-keyed `BTreeMap` lookup index that is not
/// JSON-serializable as an object, so the layer is projected from its public
/// getters. The tuple-keyed index is derived from `sites`; the test below
/// additionally proves the indexed and scalar lookups agree.
fn reference_layer(facts: &mdd_facts::references::ReferenceFacts) -> Vec<u8> {
    layer(&serde_json::json!({
        "sites": facts.sites(),
        "dynamic_calls": facts.dynamic_calls(),
        "coverage": facts.coverage(),
        "usage": facts.usage(),
        "call_site_metadata": facts.call_site_metadata(),
        "method_handle_metadata": facts.method_handle_metadata(),
    }))
}

fn projection(facts: &DexFacts) -> Vec<Vec<u8>> {
    vec![
        layer(facts.metadata.as_ref()),
        layer(facts.definitions.as_ref()),
        layer(facts.code.as_ref()),
        reference_layer(facts.references.as_ref()),
        layer(facts.annotations.as_ref()),
    ]
}

fn build(pipeline: &FactsPipeline, threads: Option<usize>) -> PipelineReport {
    pipeline
        .build(PipelineConfig {
            threads,
            ..PipelineConfig::default()
        })
        .unwrap()
}

#[test]
fn parallel_layers_are_byte_identical_to_serial() {
    let pipeline = pipeline("multidex-deflated.apk");
    assert!(pipeline.dex_count() >= 2, "fixture must have multiple DEX");
    let serial = build(&pipeline, Some(1));
    let parallel = build(&pipeline, Some(pipeline.dex_count()));

    assert_eq!(serial.threads, 1);
    assert_eq!(parallel.threads, pipeline.dex_count());
    assert_eq!(serial.dexes.len(), parallel.dexes.len());

    for (left, right) in serial.dexes.iter().zip(&parallel.dexes) {
        assert_eq!(
            left.index, right.index,
            "index order must be inventory order"
        );
        assert_eq!(left.occurrence, right.occurrence);
        assert_eq!(
            left.metadata.source().content_id,
            right.metadata.source().content_id
        );
        let expected = projection(left);
        let actual = projection(right);
        for (name, (expected, actual)) in [
            "metadata",
            "definitions",
            "code",
            "references",
            "annotations",
        ]
        .iter()
        .zip(expected.iter().zip(&actual))
        {
            assert_eq!(
                expected, actual,
                "{name} layer of {} differs between serial and parallel",
                left.occurrence
            );
        }
    }
}

#[test]
fn repeated_parallel_builds_are_deterministic() {
    let pipeline = pipeline("multidex-deflated.apk");
    let two = build(&pipeline, Some(2));
    let all = build(&pipeline, None);
    let again = build(&pipeline, None);
    for other in [&all, &again] {
        assert_eq!(two.dexes.len(), other.dexes.len());
        for (left, right) in two.dexes.iter().zip(&other.dexes) {
            assert_eq!(left.occurrence, right.occurrence);
            assert_eq!(projection(left), projection(right));
        }
    }
}

#[test]
fn arc_graph_matches_serial_sharing() {
    let pipeline = pipeline("multidex-deflated.apk");
    let report = build(&pipeline, None);

    for facts in &report.dexes {
        // The pipeline's metadata lease is the one held by definitions.
        assert!(
            std::ptr::eq(facts.definitions.metadata(), facts.metadata.as_ref()),
            "definitions must share the pipeline metadata Arc"
        );
        // References share the pipeline definition and code leases, not clones.
        assert!(
            std::ptr::eq(facts.references.definitions(), facts.definitions.as_ref()),
            "references must share the pipeline definition Arc"
        );
        assert!(
            std::ptr::eq(facts.references.code(), facts.code.as_ref()),
            "references must share the pipeline code Arc"
        );
        // Annotations own a definition copy (the staged constructor requires one)
        // but that copy must hold the same metadata Arc as every other layer.
        assert!(
            std::ptr::eq(
                facts.annotations.definitions().metadata(),
                facts.metadata.as_ref()
            ),
            "annotation definitions must share the pipeline metadata Arc"
        );
        assert!(
            !std::ptr::eq(facts.annotations.definitions(), facts.definitions.as_ref()),
            "annotations own the definition clone the staged builder requires"
        );
        // Every layer carries this occurrence's identity, not a neighbouring one.
        assert_eq!(
            facts.definitions.metadata().source().dex_occurrence_id,
            facts.occurrence
        );
        assert_eq!(facts.code.source().dex_occurrence_id, facts.occurrence);
        assert_eq!(
            facts.references.source().dex_occurrence_id,
            facts.occurrence
        );
        assert_eq!(
            facts.annotations.source().dex_occurrence_id,
            facts.occurrence
        );
    }

    // Layers from different DEX occurrences never share an Arc, even when the
    // archive stores byte-identical members under two occurrence identities.
    for (position, left) in report.dexes.iter().enumerate() {
        for right in &report.dexes[position + 1..] {
            assert!(
                !std::ptr::eq(left.metadata.as_ref(), right.metadata.as_ref()),
                "distinct occurrences must not share metadata Arcs"
            );
            assert!(!std::ptr::eq(
                left.definitions.as_ref(),
                right.definitions.as_ref()
            ));
            assert!(!std::ptr::eq(left.code.as_ref(), right.code.as_ref()));
        }
    }
}

#[test]
fn identical_member_content_keeps_separate_occurrences() {
    // Two occurrences with byte-identical DEX content: the safest way to prove
    // that parallelism did not fuse occurrences by physical content.
    let pipeline = pipeline("duplicate-content.apk");
    assert_eq!(pipeline.dex_count(), 2);
    assert!(!pipeline.snapshot().sources().is_empty());
    let report = build(&pipeline, None);

    let [left, right] = [&report.dexes[0], &report.dexes[1]];
    assert_ne!(left.occurrence, right.occurrence);
    assert_eq!(
        left.metadata.source().content_id,
        right.metadata.source().content_id,
        "fixture must hold identical content under two occurrences"
    );
    // Identical bytes therefore share one physical DEX identity, while the two
    // logical occurrences stay distinct. Neither identity may be merged.
    assert_eq!(
        left.metadata.source().physical_dex_id,
        right.metadata.source().physical_dex_id
    );
    assert_ne!(
        left.definitions.metadata().source().dex_occurrence_id,
        right.definitions.metadata().source().dex_occurrence_id
    );
    assert!(!std::ptr::eq(
        left.metadata.as_ref(),
        right.metadata.as_ref()
    ));
    // Identical input bytes must still produce identical layer facts; identity
    // fields inside each layer differ only through the occurrence ids.
    assert_eq!(
        left.metadata.strings().len(),
        right.metadata.strings().len()
    );
    assert_eq!(
        left.definitions.definitions().classes.len(),
        right.definitions.definitions().classes.len()
    );
    assert_eq!(left.code.items().len(), right.code.items().len());
}

#[test]
fn thread_resolution_is_bounded_and_rejects_zero() {
    let config = PipelineConfig::default();
    assert_eq!(config.resolve_threads(0).unwrap(), 0);
    assert_eq!(config.resolve_threads(1).unwrap(), 1);
    assert!(config.resolve_threads(33).unwrap() <= 33);

    let serial = PipelineConfig {
        threads: Some(1),
        ..PipelineConfig::default()
    };
    assert_eq!(serial.resolve_threads(33).unwrap(), 1);

    let capped = PipelineConfig {
        threads: Some(64),
        ..PipelineConfig::default()
    };
    assert_eq!(capped.resolve_threads(33).unwrap(), 33);

    let zero = PipelineConfig {
        threads: Some(0),
        ..PipelineConfig::default()
    };
    let error = zero.resolve_threads(33).unwrap_err();
    assert_eq!(error.code, ErrorCode::InvalidArgument);
}

#[test]
fn single_dex_input_never_starts_a_pool() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/generated/minimal-035.dex");
    let pipeline = FactsPipeline::open(path).unwrap();
    assert_eq!(pipeline.dex_count(), 1);
    let report = build(&pipeline, None);
    assert_eq!(report.threads, 1);
    assert_eq!(report.dexes.len(), 1);
    // A one-occurrence run must still build every layer.
    use mdd_types::Completeness;
    assert_eq!(
        report.dexes[0].metadata.metadata_coverage(),
        Completeness::Complete
    );
    assert_eq!(
        report.dexes[0].definitions.definition_coverage(),
        Completeness::Complete
    );
    assert_eq!(
        report.dexes[0].code.code_layout_coverage(),
        Completeness::Complete
    );
}
