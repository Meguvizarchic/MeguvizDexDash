# Scoped entity authority: runtime QuerySteps

## Observation and root cause

The strict scoped wrapper maintained its own row, entity, lookup and identity
limits, but did not charge its checks to the query-owned `QuerySteps` pool.
The recorded red test uses an actual captured DEX scope, lifecycle, prepared
plan, active query and owner-checked runtime. A valid entity passed the strict
source's `validate_entity` even when the query step limit was zero. This is a
focused source-call counterexample, not a full end-to-end query certificate.

## Change

For runtime-bound wrappers, provider binding comparisons are charged by their
string byte lengths, row traversal by cell count, entity checks by a
conservative search/comparison bound, and definition-index lookups by their
search bound. These are logical work units; worst-case comparison bounds may
exceed actual character comparisons. Each independent check is charged once to
the actual query's `QuerySteps`, in addition to the existing independent
`EntityCheckLimits`. A checkpoint precedes binding callbacks during the bound
phase. Existing first-failure and query ownership checks remain in place.

## Evidence

* Red: `red/record.json`, recorded exit 101, one test failed because
  `validate_entity` returned `Ok(())`; red scoped source SHA-256
  `A57899D06F5B53A4126D837DC65CC72A61E72E4B76467CE9ECB28F9E9EE0DA92`.
  An initial invocation with `--exact` matched zero tests and is excluded
  from the red evidence.
* Green: `green-scoped/record.json`, `cargo test -p mdd-query
  executor::scoped::tests:: -- --nocapture`, exit 0, 21 passed, none ignored.
  These include zero-budget, per-check count, cancellation, first-error and
  query isolation checks. Tested scoped source SHA-256 before and after:
  `8753814A16A660E0B1ACE68A3A6B914CF93A4D4121C35A9F1EAE6E016950F082`.
* Common executor, budget and lock SHA-256, before and after green respectively:
  `0783F45E9C8C6B0D16DC7779ECAB3D09104811A2818569FA1B8AEA264AFFE08F`,
  `407485782A7EA3FBEC62905A2CF7641822AC4F9AD3046F568DA5D751F023D891`,
  `FCF51A7765C73AF5E97F4AEFD238FA0020C6C303AB42C20D48FBC55D8A56C089`.
* Final combined sources: `final-combined-scoped/record.json` repeats the
  scoped test command after the facts and SQL changes were frozen: 21 passed,
  none ignored, exit 0. The four hashes above remained unchanged before and
  after this run. The other changed Rust files also remained unchanged:
  `mdd-facts/src/annotations.rs` SHA-256
  `DB02E79F2C9D25EEF5A9B7B7D60C3132D99C6DDDF48E8E2D76C32CFEC2D1D86B`;
  `mdd-sql/src/dialects/functions.rs`
  `3A4F2BB7A699D3ED830814D61EC417E6BF8DA021027CCE50D07B9F85C28A7BBB`;
  `mdd-sql/src/runtime_tests.rs`
  `03FFEAEBC5AA40970A643481E4989F3F38A7919B30269F3CEB4A00AF3550CCF1`;
  `mdd-sql/src/values.rs`
  `13D19C9E8DF6057A5ADBA421458B361A7E44EB6FB3834F7C299AA246B1A1BABB`.

## Boundaries and remaining gaps

Standalone wrappers retain only their separate limits. Scope/authority
construction, initial pre-binding checks, and provider callbacks (including
their work, allocations and destructors) are not bounded by this runtime
charge. `Control::max_steps` remains separately accounted and does not include
these wrapper charges; neither does this change add wrapper work to
`QueryWorkBytes`. Existing generic `FactSource` execution still does not gain
the sealed scope authority. Source scalar values, code bytes and completeness
are not authenticated by this wrapper. These gaps remain open; this change
does not qualify MDD-034, HostLab replacement, performance, or a release.
No whole-workspace or platform validation was run in this round.
