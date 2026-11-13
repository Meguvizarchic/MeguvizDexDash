# MDD-026 column qualification (A0 differential folded in)

Development evidence. Admits no profile and does not by itself close MDD-026.

- Frozen columns: 156
- All six categories satisfied by the merged v10 matrix alone: 140
- All six categories satisfied after the fold: 154
- Resolved with a `not_applicable` category: 2
- Unresolved: 0 []

## Categories raised by the fold

- `annotation_elements.file_id:multiplicity`
- `class_fields.file_id:multiplicity`
- `class_interfaces.file_id:multiplicity`
- `class_methods.file_id:multiplicity`
- `classes.file_id:multiplicity`
- `dex_files.entry_name:multiplicity`
- `dex_files.source_path:multiplicity`
- `dex_files.string_pool_id:field_type`
- `method_field_accesses.using_type:null`
- `methods.file_id:multiplicity`
- `methods.opcode_count:field_type`
- `methods.opcode_count:raw_fingerprint`
- `methods.opcode_hex:field_type`
- `methods.opcode_hex:raw_fingerprint`
- `methods.param_descriptors:field_type`
- `methods.param_descriptors:raw_fingerprint`
- `strings.string_pool_id:field_type`
- `types.file_id:multiplicity`

## Declared not applicable (policy statement, not evidence)

- `dex_files.file_id:multiplicity`
- `dex_files.string_pool_id:multiplicity`

## Policy

R1  field_type / raw_fingerprint. A column the harness demoted statically may be
      raised by the production-path differential: in every record the engine
      answered identically to A0 (the committed engine-equal-records manifest, which
      the Rust differential test asserts exactly), all non-NULL cells have the
      SQLite storage class the declared type implies, NULL only where the column is
      nullable, and at least one non-NULL cell was compared byte-for-byte (hex).
  R2  multiplicity. Value repetition kept by the engine and equal to A0 counts for a
      column whose relation has unique full rows by construction. dex_files.file_id
      and dex_files.string_pool_id are occurrence coordinates, unique per row, so the
      category is not_applicable (reported separately, never folded into the count of
      satisfied). dex_files.source_path / entry_name repeat only when the same input
      is listed twice; the recorded A0 case for that is used.
  R3  NULL. A nullable column whose NULL branch is unreachable is satisfied by
      exhaustion only when a named test proves the branch unreachable; the tool does
      not decide that, it records the named test.

Only engine-equal records are evidence. Declared divergences, A0 failures and
engine-only answers are never counted.

## Limits

- The differential compares whole-relation projections; single-column projections are derived from them, not separately differential-tested.
- Evidence is limited to the 185 fixture inputs of the corpus and to records on which the engine equals A0; declared divergences (non-BMP parameter descriptors) are not qualified by this fold.
- not_applicable is a policy statement about unique row keys, not evidence; it is reported separately from satisfied.
- This is a policy decision about how differential evidence counts toward the six categories; it can be reversed by re-running this tool without the fold rules.
