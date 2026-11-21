mod error_detail_tests {
    use super::super::*;

    #[test]
    fn source_error_scope_detail_is_preserved() {
        let original = MddError::new(ErrorCode::InvalidInput, "input", "bad input")
            .detail("scope_id", "prior")
            .detail("coverage_scope_id_0", "prior collision");
        let report = CoverageReport {
            snapshot_id: "snapshot".into(),
            scope_id: "actual".into(),
            scope_content_key: "key".into(),
            covers_all_captured_sources: false,
            selected_dex_occurrences: vec![],
            input: Completeness::Partial,
            facts: Completeness::Partial,
            required_layers: vec![],
            issues: vec![CoverageIssue {
                occurrence: None,
                layer: "input".into(),
                column: None,
                reason: "bad".into(),
                blocking: true,
                error: Some(original.clone()),
            }],
            native_facts_only: true,
            profile_admitted: false,
        };
        let returned = report.require_complete().unwrap_err();
        assert_eq!(returned.code, original.code);
        assert_eq!(returned.stage, original.stage);
        assert_eq!(returned.message, original.message);
        for (key, value) in &original.details {
            assert_eq!(returned.details.get(key), Some(value));
        }
        assert_eq!(returned.details["coverage_scope_id_1"], "actual");
    }
}

mod coverage_column_gate_tests {
    use super::super::*;
    use crate::code::CodeFacts;
    use crate::definitions::DefinitionFacts;
    use crate::indexes::{FactView, SelectedScope};
    use crate::metadata::MetadataFacts;
    use mdd_dex::{definitions::DefinitionLimits, instructions::CodeLimits, strings::StringLimits};
    use mdd_input::{
        archive::{ArchiveInventory, ArchiveLimits, InventoryPolicy},
        snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot},
    };
    use std::path::PathBuf;

    fn fixture(relative: &str, copies: usize) -> (Snapshot, Vec<ArchiveInventory>) {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures")
            .join(relative);
        let inputs = (0..copies)
            .map(|_| InputSpec {
                path: path.clone(),
                kind: InputKind::RawDex,
                expected_sha256: None,
            })
            .collect::<Vec<_>>();
        let snapshot = Snapshot::capture(&inputs, CaptureLimits::default()).unwrap();
        let inventories = snapshot
            .sources()
            .iter()
            .map(|source| {
                ArchiveInventory::build(
                    source,
                    InventoryPolicy::default(),
                    ArchiveLimits::default(),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        (snapshot, inventories)
    }

    fn metadata(snapshot: &Snapshot, inventory: &ArchiveInventory) -> MetadataFacts {
        MetadataFacts::build(snapshot, inventory, 0, StringLimits::default()).unwrap()
    }

    fn definitions(snapshot: &Snapshot, inventory: &ArchiveInventory) -> DefinitionFacts {
        DefinitionFacts::build(metadata(snapshot, inventory), DefinitionLimits::default()).unwrap()
    }

    fn code(snapshot: &Snapshot, inventory: &ArchiveInventory) -> CodeFacts {
        CodeFacts::build_all_code_items(snapshot, inventory, 0, CodeLimits::default()).unwrap()
    }

    fn column_request(scope: &SelectedScope, relation: &str, name: &str) -> CoverageRequest {
        let mut request = CoverageRequest::for_scope(scope, &[]);
        request.required_columns.push(ColumnRequirement {
            relation: relation.into(),
            column: name.into(),
            domain: ColumnDomain::FrozenProjection,
        });
        request
    }

    /// The report from per-occurrence states, each computed with a ledger that sees only that DEX's facts, is the report
    /// of the ledger that sees them all: same completeness, same issues in the same order, same errors.
    #[test]
    fn states_computed_one_occurrence_at_a_time_give_the_whole_ledgers_report() {
        let (snapshot, inventories) = fixture("references/generated/classic-035.dex", 3);
        let refs: Vec<&ArchiveInventory> = inventories.iter().collect();
        let scope = SelectedScope::from_inventories(&snapshot, &refs).unwrap();
        // one DEX with metadata only, one with definitions too, one with nothing built
        let meta = metadata(&snapshot, &inventories[0]);
        let defs = definitions(&snapshot, &inventories[1]);
        let ids: Vec<String> = scope
            .dexes()
            .iter()
            .map(|d| d.dex_occurrence_id.clone())
            .collect();
        let views = [
            FactView::unbuilt(&ids[0]).with_metadata(&meta),
            FactView::unbuilt(&ids[1])
                .with_metadata(defs.metadata())
                .with_definitions(&defs),
            FactView::unbuilt(&ids[2]),
        ];
        let whole = CoverageLedger::new(scope.clone(), &views).unwrap();
        let shell = CoverageLedger::new(scope.clone(), &[]).unwrap();
        let requests = [
            CoverageRequest::for_relations(&scope, &["strings"]).unwrap(),
            CoverageRequest::for_relations(&scope, &["classes", "methods"]).unwrap(),
            CoverageRequest::for_relations(&scope, &["code_items"]).unwrap(),
            CoverageRequest::for_relations(&scope, &["method_calls", "annotation_elements"])
                .unwrap(),
            column_request(&scope, "strings", "value"),
            column_request(&scope, "strings", "no_such_column"),
            column_request(&scope, "no_such_relation", "value"),
        ];
        for (n, request) in requests.iter().enumerate() {
            let expected = whole.evaluate(request).unwrap();
            let states: Vec<OccurrenceStates> = views
                .iter()
                .map(|view| {
                    CoverageLedger::new(scope.clone(), std::slice::from_ref(view))
                        .unwrap()
                        .occurrence_states(request, view.occurrence())
                })
                .collect();
            let assembled = shell.evaluate_from_states(request, &states).unwrap();
            assert_eq!(
                serde_json::to_value(&assembled).unwrap(),
                serde_json::to_value(&expected).unwrap(),
                "request {n}"
            );
            // the order the states are handed in does not matter
            let mut reversed = states.clone();
            reversed.reverse();
            assert_eq!(
                serde_json::to_value(shell.evaluate_from_states(request, &reversed).unwrap())
                    .unwrap(),
                serde_json::to_value(&expected).unwrap(),
                "request {n} reversed"
            );
        }
        // an incomplete scope is incomplete either way, and says so
        let incomplete = shell
            .evaluate_from_states(
                &requests[1],
                &[CoverageLedger::new(scope.clone(), &views[..1])
                    .unwrap()
                    .occurrence_states(&requests[1], &ids[0])],
            )
            .expect_err("two occurrences have no state");
        assert_eq!(incomplete.code, ErrorCode::InvalidArgument);
    }

    #[test]
    fn two_states_for_one_occurrence_are_refused() {
        let (snapshot, inventories) = fixture("references/generated/classic-035.dex", 1);
        let scope = SelectedScope::from_inventories(&snapshot, &[&inventories[0]]).unwrap();
        let id = scope.dexes()[0].dex_occurrence_id.clone();
        let shell = CoverageLedger::new(scope.clone(), &[]).unwrap();
        let request = CoverageRequest::for_relations(&scope, &["classes"]).unwrap();
        let one = shell.occurrence_states(&request, &id);
        let refused = shell
            .evaluate_from_states(&request, &[one.clone(), one])
            .expect_err("duplicate state");
        assert_eq!(refused.code, ErrorCode::InvalidArgument);
    }

    /// Every column of the six newly assembled relations reports `Complete`
    /// when its provider gate accepts the request.
    #[test]
    fn assembled_relations_report_complete_when_gates_accept() {
        let (snapshot, inventories) = fixture("references/generated/classic-035.dex", 1);
        let defs = definitions(&snapshot, &inventories[0]);
        let codes = code(&snapshot, &inventories[0]);
        let refs = crate::references::ReferenceFacts::build(
            defs,
            codes,
            crate::references::ReferenceLimits::default(),
        )
        .unwrap();
        let scope = SelectedScope::from_inventories(&snapshot, &[&inventories[0]]).unwrap();
        let view = FactView::unbuilt(&refs.source().dex_occurrence_id).with_references(&refs);
        let ledger = CoverageLedger::new(scope.clone(), &[view]).unwrap();
        let cases: [(&str, &[&str]); 6] = [
            ("dex_files", &["file_id", "byte_len", "map_off"]),
            ("strings", &["string_pool_id", "string_idx", "value"]),
            ("types", &["file_id", "type_idx", "descriptor", "java_name"]),
            (
                "methods",
                &["method_idx", "class_descriptor", "access_flags"],
            ),
            (
                "classes",
                &["class_idx", "descriptor", "superclass_descriptor"],
            ),
            ("code_items", &["method_idx", "code_off", "insns_off"]),
        ];
        for (relation, columns) in cases {
            for column in columns {
                let report = ledger
                    .evaluate(&column_request(&scope, relation, column))
                    .unwrap();
                assert_eq!(
                    report.facts,
                    Completeness::Complete,
                    "{relation}.{column} must be complete when its gate accepts: {:?}",
                    report.issues
                );
                assert!(
                    report.issues.is_empty(),
                    "{relation}.{column} produced issues: {:?}",
                    report.issues
                );
            }
        }
    }

    /// Each of the six relations routes its column through the owning provider
    /// gate: a known column passes and an unknown column is rejected with a real
    /// error, never an unconditional `Ok`.
    #[test]
    fn six_relation_gates_accept_and_reject_through_their_provider() {
        let (snapshot, inventories) = fixture("references/generated/classic-035.dex", 1);
        let defs = definitions(&snapshot, &inventories[0]);
        let codes = code(&snapshot, &inventories[0]);
        let refs = crate::references::ReferenceFacts::build(
            defs,
            codes,
            crate::references::ReferenceLimits::default(),
        )
        .unwrap();
        let view = FactView::unbuilt(&refs.source().dex_occurrence_id).with_references(&refs);
        let cases: [(&str, &str); 6] = [
            ("dex_files", "byte_len"),
            ("strings", "string_idx"),
            ("types", "type_idx"),
            ("methods", "method_idx"),
            ("classes", "class_idx"),
            ("code_items", "code_off"),
        ];
        for (relation, column) in cases {
            let accepted = ColumnSpec {
                relation,
                column,
                data_type: "UInt32",
                nullable: false,
                assembled_projection: true,
            };
            assert!(
                matches!(
                    CoverageLedger::frozen_provider_gate(&view, &accepted),
                    Some(Some(Ok(())))
                ),
                "{relation}.{column} must be accepted by its provider gate"
            );
            let unknown = ColumnSpec {
                column: "invented_column",
                ..accepted
            };
            assert!(
                matches!(
                    CoverageLedger::frozen_provider_gate(&view, &unknown),
                    Some(Some(Err(ref error))) if error.code == ErrorCode::InvalidArgument
                ),
                "{relation} must reject an unknown column through its provider gate"
            );
        }
    }

    /// A relation that no gate arm maps has no proven producer. The gate must
    /// decline (`None`) so `column_state` reports it as `Unknown`; an
    /// unconditional `Ok(())` for the fallback arm would silently complete an
    /// unmapped relation. The four `method_*` relations decline for the same
    /// reason because they are gated inline, not here.
    #[test]
    fn unmapped_relation_is_never_gated_to_complete() {
        let (snapshot, inventories) = fixture("references/generated/classic-035.dex", 1);
        let defs = definitions(&snapshot, &inventories[0]);
        let codes = code(&snapshot, &inventories[0]);
        let refs = crate::references::ReferenceFacts::build(
            defs,
            codes,
            crate::references::ReferenceLimits::default(),
        )
        .unwrap();
        let view = FactView::unbuilt(&refs.source().dex_occurrence_id).with_references(&refs);
        for relation in [
            "invented_relation",
            "method_calls",
            "method_strings",
            "method_field_accesses",
            "method_used_types",
        ] {
            let spec = ColumnSpec {
                relation,
                column: "file_id",
                data_type: "UInt32",
                nullable: false,
                assembled_projection: true,
            };
            assert!(
                CoverageLedger::frozen_provider_gate(&view, &spec).is_none(),
                "{relation} must not be gated by the frozen-provider table"
            );
        }
    }

    /// A column the owning provider refuses must report `Unknown` with the
    /// provider's own error, not an unconditional `Complete`.
    #[test]
    fn provider_gate_rejection_reports_unknown_with_provider_error() {
        let (snapshot, inventories) = fixture("references/generated/classic-035.dex", 1);
        let names = metadata(&snapshot, &inventories[0]);
        let defs = DefinitionFacts::build(names.clone(), DefinitionLimits::default()).unwrap();
        let codes = code(&snapshot, &inventories[0]);
        let scope = SelectedScope::from_inventories(&snapshot, &[&inventories[0]]).unwrap();
        let view = FactView::unbuilt(&names.source().dex_occurrence_id)
            .with_definitions(&defs)
            .with_code(&codes);
        let ledger = CoverageLedger::new(scope.clone(), &[view]).unwrap();
        // Columns with a production projection report `Complete` through the
        // provider that now owns them: `param_descriptors` through the definition
        // gate and the two provenance columns through the scope gate.
        for (relation, column) in [
            ("methods", "param_descriptors"),
            ("dex_files", "source_path"),
            ("dex_files", "entry_name"),
        ] {
            let report = ledger
                .evaluate(&column_request(&scope, relation, column))
                .unwrap();
            assert_eq!(report.facts, Completeness::Complete, "{relation}.{column}");
            assert!(report.issues.is_empty(), "{relation}.{column}");
        }
        // The definition object alone cannot answer the opcode columns: it does
        // not hold the code layout. `column_state` must report the missing
        // provider explicitly rather than fabricating a value.
        let definitions_only =
            FactView::unbuilt(&names.source().dex_occurrence_id).with_definitions(&defs);
        let ledger =
            CoverageLedger::new(scope.clone(), std::slice::from_ref(&definitions_only)).unwrap();
        let occurrence = scope.dexes()[0].dex_occurrence_id.clone();
        for column in ["opcode_count", "opcode_hex"] {
            let spec = ColumnSpec {
                relation: "methods",
                column,
                data_type: "UInt32",
                nullable: true,
                assembled_projection: true,
            };
            assert!(matches!(
                CoverageLedger::frozen_provider_gate(&definitions_only, &spec),
                Some(None)
            ));
            // Without code layout the `AllMethodBodies` layer is itself
            // incomplete, so the aggregate is Partial before the column gate is
            // consulted; the important property is that it is never Complete.
            let (state, reason, _) =
                ledger.column_state(&occurrence, &spec, ColumnDomain::FrozenProjection);
            assert_ne!(state, Completeness::Complete, "methods.{column}");
            assert!(reason.is_some(), "methods.{column}");
            assert_ne!(
                ledger
                    .evaluate(&column_request(&scope, "methods", column))
                    .unwrap()
                    .facts,
                Completeness::Complete,
                "methods.{column} without the code provider"
            );
        }
        // With the code-layout layer present those two columns are complete.
        let definitions_and_code = FactView::unbuilt(&names.source().dex_occurrence_id)
            .with_definitions(&defs)
            .with_code(&codes);
        for column in ["opcode_count", "opcode_hex"] {
            let spec = ColumnSpec {
                relation: "methods",
                column,
                data_type: "UInt32",
                nullable: true,
                assembled_projection: true,
            };
            assert!(
                matches!(
                    CoverageLedger::frozen_provider_gate(&definitions_and_code, &spec),
                    Some(Some(Ok(())))
                ),
                "methods.{column} must be accepted once code layout is built"
            );
        }
        // A provider rejection reaches the caller as Unknown carrying the
        // provider error, not as an unconditional Complete. A reference-backed
        // view is used so every column's layer state is complete first and only
        // the column gate can reject.
        let defs = DefinitionFacts::build(names.clone(), DefinitionLimits::default()).unwrap();
        let refs = crate::references::ReferenceFacts::build(
            defs,
            codes.clone(),
            crate::references::ReferenceLimits::default(),
        )
        .unwrap();
        let view = FactView::unbuilt(&names.source().dex_occurrence_id).with_references(&refs);
        let ledger = CoverageLedger::new(scope.clone(), &[view]).unwrap();
        for (relation, column) in [
            ("dex_files", "invented_column"),
            ("strings", "invented_column"),
            ("types", "invented_column"),
            ("methods", "invented_column"),
            ("classes", "invented_column"),
            ("code_items", "invented_column"),
        ] {
            let spec = ColumnSpec {
                relation,
                column,
                data_type: "UInt32",
                nullable: false,
                assembled_projection: true,
            };
            let occurrence = &scope.dexes()[0].dex_occurrence_id;
            let (state, reason, error) =
                ledger.column_state(occurrence, &spec, ColumnDomain::FrozenProjection);
            assert_eq!(state, Completeness::Unknown, "{relation}.{column}");
            assert_eq!(
                reason.as_deref(),
                Some("column_gate_rejected_required_scope"),
                "{relation}.{column}"
            );
            assert!(
                error.is_some(),
                "{relation}.{column} must carry the provider error"
            );
        }
    }

    /// A missing provider object is an explicit gap, never a silent `Complete`.
    #[test]
    fn missing_provider_object_is_unknown_not_complete() {
        let (snapshot, inventories) = fixture("references/generated/classic-035.dex", 1);
        let names = metadata(&snapshot, &inventories[0]);
        let scope = SelectedScope::from_inventories(&snapshot, &[&inventories[0]]).unwrap();
        // Metadata-only view: definitions-backed and code-backed columns are gaps.
        let view = FactView::unbuilt(&names.source().dex_occurrence_id).with_metadata(&names);
        let ledger = CoverageLedger::new(scope.clone(), &[view]).unwrap();
        for (relation, column) in [
            ("methods", "method_idx"),
            ("classes", "class_idx"),
            ("code_items", "code_off"),
        ] {
            assert_eq!(
                ledger
                    .evaluate(&column_request(&scope, relation, column))
                    .unwrap()
                    .facts,
                Completeness::Unknown,
                "{relation}.{column} without its provider object"
            );
        }
        // Metadata-only columns still resolve through their own provider.
        for (relation, column) in [("dex_files", "byte_len"), ("strings", "string_idx")] {
            assert_eq!(
                ledger
                    .evaluate(&column_request(&scope, relation, column))
                    .unwrap()
                    .facts,
                Completeness::Complete,
                "{relation}.{column} with its provider present"
            );
        }
    }

    /// A legal non-scalar UTF-16 value makes the plain-UTF-8 projections fail;
    /// coverage must not claim those columns are complete.
    #[test]
    fn non_scalar_text_columns_are_not_reported_complete() {
        let (snapshot, inventories) = fixture("references/generated/nonscalar-string-035.dex", 1);
        let names = metadata(&snapshot, &inventories[0]);
        let defs = DefinitionFacts::build(names.clone(), DefinitionLimits::default()).unwrap();
        assert!(
            names
                .strings()
                .iter()
                .any(|fact| fact.data.text.strict_utf8().is_err()),
            "fixture must contain a legal non-scalar string"
        );
        let scope = SelectedScope::from_inventories(&snapshot, &[&inventories[0]]).unwrap();
        let view = FactView::unbuilt(&names.source().dex_occurrence_id).with_definitions(&defs);
        let ledger = CoverageLedger::new(scope.clone(), &[view]).unwrap();
        // The row projection itself is the ground truth for the gap.
        assert!(matches!(
            names.string_rows(0, 0).unwrap_err().code,
            ErrorCode::UnsupportedQuery
        ));
        let report = ledger
            .evaluate(&column_request(&scope, "strings", "value"))
            .unwrap();
        assert_eq!(report.facts, Completeness::Unknown);
        assert!(report.issues.iter().any(|issue| {
            issue.column.as_deref() == Some("strings.value")
                && issue.reason == "non_scalar_UTF16_cannot_be_plain_UTF8"
        }));
        assert!(report.require_complete().is_err());
        // A scalar-only column of the same relation is unaffected.
        assert_eq!(
            ledger
                .evaluate(&column_request(&scope, "strings", "string_idx"))
                .unwrap()
                .facts,
            Completeness::Complete
        );
    }

    /// `classes.source_file` uses the same plain-UTF-8 contract, so a non-scalar
    /// source file must report `Unknown` instead of `Complete`.
    #[test]
    fn non_scalar_class_source_file_is_not_reported_complete() {
        let (snapshot, inventories) =
            fixture("class_source_boundary/generated/surrogate-source.dex", 1);
        let names = metadata(&snapshot, &inventories[0]);
        let defs = DefinitionFacts::build(names.clone(), DefinitionLimits::default()).unwrap();
        assert!(
            defs.definitions().classes.iter().any(|class| class
                .source_file
                .as_ref()
                .is_some_and(|text| text.strict_utf8().is_err())),
            "fixture must carry a non-scalar source file name"
        );
        let scope = SelectedScope::from_inventories(&snapshot, &[&inventories[0]]).unwrap();
        let view = FactView::unbuilt(&names.source().dex_occurrence_id).with_definitions(&defs);
        let ledger = CoverageLedger::new(scope.clone(), &[view]).unwrap();
        assert!(matches!(
            defs.class_rows(0).unwrap_err().code,
            ErrorCode::UnsupportedQuery
        ));
        let report = ledger
            .evaluate(&column_request(&scope, "classes", "source_file"))
            .unwrap();
        assert_eq!(report.facts, Completeness::Unknown);
        assert!(report.issues.iter().any(|issue| {
            issue.column.as_deref() == Some("classes.source_file")
                && issue.reason == "non_scalar_UTF16_cannot_be_plain_UTF8"
        }));
        // An absent source file is a genuine NULL, not a text-conversion gap.
        let (snapshot, inventories) = fixture("class_source_boundary/generated/null-source.dex", 1);
        let names = metadata(&snapshot, &inventories[0]);
        let defs = DefinitionFacts::build(names.clone(), DefinitionLimits::default()).unwrap();
        let scope = SelectedScope::from_inventories(&snapshot, &[&inventories[0]]).unwrap();
        let view = FactView::unbuilt(&names.source().dex_occurrence_id).with_definitions(&defs);
        let ledger = CoverageLedger::new(scope.clone(), &[view]).unwrap();
        assert_eq!(
            ledger
                .evaluate(&column_request(&scope, "classes", "source_file"))
                .unwrap()
                .facts,
            Completeness::Complete
        );
    }

    /// The four reference relations keep their existing behaviour.
    #[test]
    fn reference_relations_keep_their_gate_behaviour() {
        let (snapshot, inventories) = fixture("references/generated/classic-035.dex", 1);
        let defs = definitions(&snapshot, &inventories[0]);
        let codes = code(&snapshot, &inventories[0]);
        let refs = crate::references::ReferenceFacts::build(
            defs,
            codes,
            crate::references::ReferenceLimits::default(),
        )
        .unwrap();
        let scope = SelectedScope::from_inventories(&snapshot, &[&inventories[0]]).unwrap();
        let view = FactView::unbuilt(&refs.source().dex_occurrence_id).with_references(&refs);
        let ledger = CoverageLedger::new(scope.clone(), &[view]).unwrap();
        for (relation, column) in [
            ("method_strings", "method_idx"),
            ("method_calls", "callee_method_idx"),
            ("method_field_accesses", "field_idx"),
            ("method_used_types", "type_idx"),
        ] {
            let report = ledger
                .evaluate(&column_request(&scope, relation, column))
                .unwrap();
            assert_eq!(report.facts, Completeness::Complete, "{relation}.{column}");
        }
        // An unknown column still reports Unknown through the reference gate.
        let report = ledger
            .evaluate(&column_request(&scope, "method_calls", "invented_column"))
            .unwrap();
        assert_eq!(report.facts, Completeness::Unknown);
        // Without reference facts the provider is missing.
        let bare = FactView::unbuilt(&refs.source().dex_occurrence_id);
        let ledger = CoverageLedger::new(scope.clone(), &[bare]).unwrap();
        assert_eq!(
            ledger
                .evaluate(&column_request(&scope, "method_strings", "method_idx"))
                .unwrap()
                .facts,
            Completeness::Unknown
        );
    }

    /// `code_items` needs a complete code layout, not just a present code leaf.
    #[test]
    fn code_items_requires_complete_code_layout() {
        let (snapshot, inventories) = fixture("references/generated/classic-035.dex", 1);
        let names = metadata(&snapshot, &inventories[0]);
        let defs = DefinitionFacts::build(names.clone(), DefinitionLimits::default()).unwrap();
        let projected =
            CodeFacts::build_offsets(&snapshot, &inventories[0], 0, &[], CodeLimits::default())
                .unwrap();
        let scope = SelectedScope::from_inventories(&snapshot, &[&inventories[0]]).unwrap();
        let view = FactView::unbuilt(&names.source().dex_occurrence_id)
            .with_definitions(&defs)
            .with_code(&projected);
        let ledger = CoverageLedger::new(scope.clone(), &[view]).unwrap();
        // The scoped projection omits real bodies, so code_items cannot be complete.
        let report = ledger
            .evaluate(&column_request(&scope, "code_items", "code_off"))
            .unwrap();
        assert_ne!(report.facts, Completeness::Complete);
        assert!(report.require_complete().is_err());
        // The build-free column gate still rejects unknown names and accepts the
        // provider's own assembled column set.
        assert_eq!(
            require_code_item_columns(&["invented_column"])
                .unwrap_err()
                .code,
            ErrorCode::InvalidArgument
        );
        assert!(require_code_item_columns(crate::code::CodeItemRow::COLUMNS).is_ok());
        assert!(require_code_item_columns(&["*"]).is_ok());
    }

    /// Every frozen column of the seven former fallback relations is gated by
    /// its own provider: a known column passes and an invented column is
    /// rejected with the provider's own error, never an unconditional `Ok`.
    ///
    /// `class_*` relations consult `DefinitionFacts`; the four annotation
    /// relations consult `AnnotationFacts`, so the assertion also pins which
    /// fact object owns each projection.
    #[test]
    fn seven_fallback_relations_are_gated_by_their_own_provider() {
        let (snapshot, inventories) = fixture("annotations/generated/annotations-038.dex", 1);
        let definitions = definitions(&snapshot, &inventories[0]);
        let annotations = crate::annotations::AnnotationFacts::build(
            definitions.clone(),
            mdd_dex::annotations::AnnotationLimits::default(),
        )
        .unwrap();
        let view = FactView::unbuilt(&annotations.source().dex_occurrence_id)
            .with_annotations(&annotations);
        // Each relation: (accepted column, owning provider).
        let cases: [(&str, &str, &str); 7] = [
            ("class_interfaces", "interface_descriptor", "definitions"),
            ("class_fields", "field_name", "definitions"),
            ("class_methods", "method_descriptor", "definitions"),
            (
                "annotation_directory_entries",
                "annotation_set_off",
                "annotations",
            ),
            ("annotation_set_entries", "annotation_off", "annotations"),
            ("annotations", "visibility", "annotations"),
            ("annotation_elements", "value_kind", "annotations"),
        ];
        for (relation, column, provider) in cases {
            let accepted = ColumnSpec {
                relation,
                column,
                data_type: "UInt32",
                nullable: false,
                assembled_projection: true,
            };
            assert!(
                matches!(
                    CoverageLedger::frozen_provider_gate(&view, &accepted),
                    Some(Some(Ok(())))
                ),
                "{relation}.{column} must be accepted by its {provider} gate"
            );
            let unknown = ColumnSpec {
                column: "invented_column",
                ..accepted
            };
            assert!(
                matches!(
                    CoverageLedger::frozen_provider_gate(&view, &unknown),
                    Some(Some(Err(ref error))) if error.code == ErrorCode::InvalidArgument
                ),
                "{relation} must reject an unknown column through its {provider} gate"
            );
            // A view that does not carry the owning provider must report the gap
            // instead of borrowing columns from a fact object it lacks.
            let other = FactView::unbuilt(&annotations.source().dex_occurrence_id);
            assert!(
                matches!(
                    CoverageLedger::frozen_provider_gate(&other, &accepted),
                    Some(None)
                ),
                "{relation} without its {provider} provider must be an explicit gap"
            );
        }
        // Every relation in the frozen schema now either has a provider gate or
        // is one of the four inline-gated reference relations. No relation may
        // reach the unconditional fallback that used to answer `Complete`.
        let ungated = column_specs()
            .iter()
            .map(|spec| spec.relation)
            .filter(|relation| {
                !matches!(
                    *relation,
                    "method_strings"
                        | "method_calls"
                        | "method_field_accesses"
                        | "method_used_types"
                )
            })
            .filter(|relation| {
                let spec = ColumnSpec {
                    relation,
                    column: "*",
                    data_type: "UInt32",
                    nullable: false,
                    assembled_projection: true,
                };
                CoverageLedger::frozen_provider_gate(&view, &spec).is_none()
            })
            .collect::<BTreeSet<_>>();
        assert!(
            ungated.is_empty(),
            "relations with no provider gate: {ungated:?}"
        );
    }

    /// A relation the provider refuses must reach the caller as `Unknown`
    /// carrying the provider's own error, and a missing provider object must
    /// be an explicit gap — both through the public `evaluate` path.
    #[test]
    fn seven_fallback_relations_reject_and_report_gap_through_evaluate() {
        let (snapshot, inventories) = fixture("annotations/generated/annotations-038.dex", 1);
        let definitions = definitions(&snapshot, &inventories[0]);
        let annotations = crate::annotations::AnnotationFacts::build(
            definitions.clone(),
            mdd_dex::annotations::AnnotationLimits::default(),
        )
        .unwrap();
        let scope = SelectedScope::from_inventories(&snapshot, &[&inventories[0]]).unwrap();
        let occurrence = annotations.source().dex_occurrence_id.clone();
        let view = FactView::unbuilt(&occurrence).with_annotations(&annotations);
        let ledger = CoverageLedger::new(scope.clone(), &[view]).unwrap();
        for (relation, column) in [
            ("class_interfaces", "invented_column"),
            ("class_fields", "invented_column"),
            ("class_methods", "invented_column"),
            ("annotation_directory_entries", "invented_column"),
            ("annotation_set_entries", "invented_column"),
            ("annotations", "invented_column"),
            ("annotation_elements", "invented_column"),
        ] {
            let spec = ColumnSpec {
                relation,
                column,
                data_type: "UInt32",
                nullable: false,
                assembled_projection: true,
            };
            let (state, reason, error) =
                ledger.column_state(&occurrence, &spec, ColumnDomain::FrozenProjection);
            assert_eq!(state, Completeness::Unknown, "{relation}.{column}");
            assert_eq!(
                reason.as_deref(),
                Some("column_gate_rejected_required_scope"),
                "{relation}.{column}"
            );
            assert!(
                error.is_some_and(|error| error.code == ErrorCode::InvalidArgument),
                "{relation}.{column} must carry the provider's InvalidArgument"
            );
        }
        // A missing provider object never reaches the column gate through
        // `evaluate`: the owning fact layer is already `Unknown`, and
        // `layer_state` answers first. That precedence is asserted here so the
        // column gate cannot be mistaken for the only guard against a missing
        // provider — both arms report `Unknown`, never `Complete`.
        let bare = FactView::unbuilt(&occurrence);
        let ledger = CoverageLedger::new(scope.clone(), &[bare]).unwrap();
        for (relation, column) in [
            ("class_interfaces", "interface_descriptor"),
            ("class_fields", "field_name"),
            ("class_methods", "method_descriptor"),
            ("annotation_directory_entries", "annotation_set_off"),
            ("annotation_set_entries", "annotation_off"),
            ("annotations", "visibility"),
            ("annotation_elements", "value_kind"),
        ] {
            let spec = ColumnSpec {
                relation,
                column,
                data_type: "UInt32",
                nullable: false,
                assembled_projection: true,
            };
            let (state, reason, error) =
                ledger.column_state(&occurrence, &spec, ColumnDomain::FrozenProjection);
            assert_eq!(state, Completeness::Unknown, "{relation}.{column}");
            assert_eq!(
                reason.as_deref(),
                Some("required_fact_scope_not_built"),
                "{relation}.{column}"
            );
            assert!(error.is_none(), "{relation}.{column} has no provider error");
        }
    }

    /// `CoverageRequest::for_scope` still requires no columns (layer-only
    /// semantics are unchanged), while `for_relations` fills them from the
    /// frozen schema and requires the owning fact layers.
    #[test]
    fn relation_request_fills_columns_and_scope_request_stays_layer_only() {
        let (snapshot, inventories) = fixture("annotations/generated/annotations-038.dex", 1);
        let definitions = definitions(&snapshot, &inventories[0]);
        let annotations = crate::annotations::AnnotationFacts::build(
            definitions.clone(),
            mdd_dex::annotations::AnnotationLimits::default(),
        )
        .unwrap();
        let scope = SelectedScope::from_inventories(&snapshot, &[&inventories[0]]).unwrap();
        let view = FactView::unbuilt(&annotations.source().dex_occurrence_id)
            .with_annotations(&annotations);

        // `for_scope` is unchanged: layers only, no column claims.
        let layer_only = CoverageRequest::for_scope(&scope, &[FactLayer::Annotations]);
        assert!(layer_only.required_columns.is_empty());

        let request = CoverageRequest::for_relations(
            &scope,
            &[
                "class_interfaces",
                "class_fields",
                "class_methods",
                "annotation_directory_entries",
                "annotation_set_entries",
                "annotations",
                "annotation_elements",
            ],
        )
        .unwrap();
        let expected_columns = column_specs()
            .iter()
            .filter(|spec| {
                matches!(
                    spec.relation,
                    "class_interfaces"
                        | "class_fields"
                        | "class_methods"
                        | "annotation_directory_entries"
                        | "annotation_set_entries"
                        | "annotations"
                        | "annotation_elements"
                )
            })
            .count();
        assert_eq!(request.required_columns.len(), expected_columns);
        assert!(
            request
                .required_columns
                .iter()
                .all(|column| column.domain == ColumnDomain::FrozenProjection),
            "relation coverage must stay in the frozen projection domain"
        );
        assert!(
            request.required_layers.contains(&FactLayer::Definitions)
                && request.required_layers.contains(&FactLayer::Annotations),
            "the relation request must require the layers that own the columns: {:?}",
            request.required_layers
        );
        // An unknown relation is rejected rather than silently matching nothing.
        assert_eq!(
            CoverageRequest::for_relations(&scope, &["invented_relation"])
                .unwrap_err()
                .code,
            ErrorCode::InvalidArgument
        );

        // The production path reaches the same verdicts as the direct ledger
        // call: the seven relations are Complete only because their providers
        // accept, and an unbuilt provider is Unknown.
        let ledger = CoverageLedger::new(scope.clone(), &[view]).unwrap();
        let report = ledger.evaluate(&request).unwrap();
        assert_eq!(
            report.facts,
            Completeness::Complete,
            "every gated column must be complete here: {:?}",
            report.issues
        );
        assert!(report.require_complete().is_ok());
        assert!(report.required_layers.contains(&FactLayer::Annotations));

        // Dropping the annotation provider turns the four annotation relations
        // into gaps. The `Annotations` layer answers first with
        // `required_fact_scope_not_built`, and every annotation column follows;
        // the three class relations stay complete because their provider and
        // layer are untouched.
        let definitions_only = FactView::unbuilt(&annotations.source().dex_occurrence_id)
            .with_definitions(&definitions);
        let ledger = CoverageLedger::new(scope.clone(), &[definitions_only]).unwrap();
        let report = ledger.evaluate(&request).unwrap();
        assert_eq!(report.facts, Completeness::Unknown);
        assert_eq!(
            report
                .issues
                .iter()
                .filter(|issue| issue.reason == "required_fact_scope_not_built")
                .filter(|issue| issue.layer == "Annotations")
                .count(),
            1,
            "the missing annotation layer must be reported once: {:?}",
            report.issues
        );
        for relation in [
            "annotation_directory_entries",
            "annotation_set_entries",
            "annotations",
            "annotation_elements",
        ] {
            assert!(
                report.issues.iter().any(|issue| issue
                    .column
                    .as_deref()
                    .is_some_and(|column| column.starts_with(&format!("{relation}.")))),
                "{relation} must report a column issue: {:?}",
                report.issues
            );
        }
        for relation in ["class_interfaces", "class_fields", "class_methods"] {
            assert!(
                !report.issues.iter().any(|issue| issue
                    .column
                    .as_deref()
                    .is_some_and(|column| column.starts_with(&format!("{relation}.")))),
                "{relation} keeps its provider and must not report a column issue: {:?}",
                report.issues
            );
        }
        assert!(
            report.require_complete().is_err(),
            "an unbuilt annotation provider must not be reported complete"
        );
    }
}
