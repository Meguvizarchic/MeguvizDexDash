//! `query_resources`: the rows of `resources.arsc` that match, one per resource, configuration
//! and (for a style, array or plurals) item.
//!
//! Configurations are never merged: the same resource in the default, `en` and `zh-rCN`
//! configurations is three rows, each with its qualifier string. A reference is named, not
//! followed.
use super::{fit_rows, limit_of, row_budget, run, source_json, window};
use crate::tools::{Failure, Registry, invalid};
use mdd_service::resources::{Filter, Row, TableHandle, data_type, type_label};
use mdd_types::MddError;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::sync::Arc;

const REFERENCE_POLICY: &str = "references are named, not recursively evaluated; query the referenced ID and configuration to continue";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Args {
    configuration: Option<String>,
    contains: Option<String>,
    dataset_id: String,
    input_index: Option<u64>,
    limit: Option<u64>,
    max_bytes: Option<u64>,
    name: Option<String>,
    #[serde(default)]
    offset: u64,
    resource_id: Option<u64>,
    resource_type: Option<String>,
    timeout_ms: Option<u64>,
}

fn row_json(handle: &TableHandle, row: &Row<'_>) -> Result<Value, MddError> {
    let table = &handle.table;
    let mut out = Map::new();
    out.insert("configuration".to_owned(), json!(row.configuration));
    out.insert("name".to_owned(), json!(row.name));
    out.insert("package".to_owned(), json!(row.package));
    out.insert("resource_id".to_owned(), json!(row.entry.resource_id));
    out.insert(
        "resource_id_hex".to_owned(),
        json!(format!("0x{:08x}", row.entry.resource_id)),
    );
    // a map entry without items has no value to show
    if let Some(value) = row.value {
        out.insert("raw_data".to_owned(), json!(value.data));
        out.insert("value".to_owned(), json!(table.value_text(value)?));
        out.insert("value_type".to_owned(), json!(type_label(value.data_type)));
        if matches!(
            value.data_type,
            data_type::REFERENCE
                | data_type::ATTRIBUTE
                | data_type::DYNAMIC_REFERENCE
                | data_type::DYNAMIC_ATTRIBUTE
        ) {
            out.insert("reference_id".to_owned(), json!(value.data));
            out.insert(
                "reference_name".to_owned(),
                json!(table.qualified_name(value.data)),
            );
        }
    }
    if let Some(item) = &row.item {
        out.insert("item_count".to_owned(), json!(item.count));
        out.insert("parent_id".to_owned(), json!(item.parent_id));
        if let (Some(index), Some(name_id)) = (item.index, item.name_id) {
            out.insert("item_index".to_owned(), json!(index));
            out.insert("item_name".to_owned(), json!(item.name));
            out.insert("item_name_id".to_owned(), json!(name_id));
        }
    }
    Ok(Value::Object(out))
}

pub fn query_resources(registry: &mut Registry, args: Args) -> Result<Value, Failure> {
    let limit = limit_of(args.limit)?;
    let resource_id = match args.resource_id {
        None => None,
        Some(id) => Some(u32::try_from(id).map_err(|_| invalid("resource_id must fit 32 bits"))?),
    };
    let filter = Filter {
        resource_id,
        resource_type: args.resource_type.clone(),
        name: args.name.clone(),
        configuration: args.configuration.clone(),
        contains: args.contains.clone(),
    };
    let budget = row_budget(args.max_bytes)?;
    let (input_index, handle): (usize, Arc<TableHandle>) = run(
        registry,
        "query_resources",
        &args.dataset_id,
        args.input_index,
        args.timeout_ms,
        move |dataset, index| dataset.resource_table(index),
    )?;
    let keys = handle.table.query(&filter);
    let total = keys.len();
    let (start, end) = window(args.offset, total, limit)?;
    let rows = keys[start..end]
        .iter()
        .map(|key| row_json(&handle, &handle.table.row(*key)))
        .collect::<Result<Vec<_>, MddError>>()
        .map_err(Failure::Execution)?;
    let mut answer = fit_rows(&rows, budget, &|count| {
        let next = start + count;
        json!({
            "dataset_id": args.dataset_id,
            "input_index": input_index,
            "next_offset": (next < total).then_some(next),
            "offset": args.offset,
            "reference_policy": REFERENCE_POLICY,
            "total_rows": total,
            "truncated": next < total,
            "values": &rows[..count],
        })
    })?;
    // beside the reference's fields: where the table came from, and whether a chunk of a type
    // this reader does not know was passed over (the rows are then what the table says, and
    // the table said more)
    if let Value::Object(map) = &mut answer {
        map.insert(
            "skipped_chunks".to_owned(),
            json!(handle.table.skipped_chunks()),
        );
        map.insert("source".to_owned(), source_json(&handle.evidence));
    }
    Ok(answer)
}
