//! `get_manifest_components`: the application's components with what the manifest says of
//! their exported state, intent filters and metadata.
use super::{fit_rows, limit_of, row_budget, run, window};
use crate::tools::{Failure, Registry, invalid};
use mdd_service::manifest::{EXPORTED_ASSUMPTION, components};
use serde::Deserialize;
use serde_json::{Value, json};

const KINDS: [&str; 5] = [
    "activity",
    "activity-alias",
    "service",
    "receiver",
    "provider",
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Args {
    dataset_id: String,
    input_index: Option<u64>,
    kind: Option<String>,
    limit: Option<u64>,
    max_bytes: Option<u64>,
    #[serde(default)]
    offset: u64,
    #[serde(default)]
    only_exported: bool,
    timeout_ms: Option<u64>,
}

pub fn get_manifest_components(registry: &mut Registry, args: Args) -> Result<Value, Failure> {
    let limit = limit_of(args.limit)?;
    if let Some(kind) = args.kind.as_deref()
        && !KINDS.contains(&kind)
    {
        return Err(invalid(
            "kind must be activity, activity-alias, service, receiver, or provider",
        ));
    }
    let budget = row_budget(args.max_bytes)?;
    let (input_index, found) = run(
        registry,
        "get_manifest_components",
        &args.dataset_id,
        args.input_index,
        args.timeout_ms,
        move |dataset, index| {
            let document = dataset.manifest(index)?;
            Ok(components(&document)?)
        },
    )?;
    let selected: Vec<_> = found
        .components
        .iter()
        .filter(|c| args.kind.as_deref().is_none_or(|kind| c.kind == kind))
        .filter(|c| !args.only_exported || c.exported == Some(true))
        .collect();
    let total = selected.len();
    let (start, end) = window(args.offset, total, limit)?;
    let rows: Vec<Value> = selected[start..end].iter().map(|c| c.row.clone()).collect();
    fit_rows(&rows, budget, &|count| {
        let next = start + count;
        json!({
            "components": &rows[..count],
            "dataset_id": args.dataset_id,
            "exported_assumption": EXPORTED_ASSUMPTION,
            "input_index": input_index,
            "next_offset": (next < total).then_some(next),
            "offset": args.offset,
            "target_sdk": found.target_sdk,
            "total_rows": total,
            "truncated": next < total,
        })
    })
}
