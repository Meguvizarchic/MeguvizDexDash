//! `list_resource_files`: the members of an archive, by name.
use super::{fit_rows, limit_of, row_budget, run, window};
use crate::tools::{Failure, Registry};
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Args {
    dataset_id: String,
    input_index: Option<u64>,
    limit: Option<u64>,
    max_bytes: Option<u64>,
    #[serde(default)]
    offset: u64,
    prefix: Option<String>,
    timeout_ms: Option<u64>,
}

pub fn list_resource_files(registry: &mut Registry, args: Args) -> Result<Value, Failure> {
    let limit = limit_of(args.limit)?;
    let budget = row_budget(args.max_bytes)?;
    let prefix = args.prefix.unwrap_or_default();
    let (input_index, files) = run(
        registry,
        "list_resource_files",
        &args.dataset_id,
        args.input_index,
        args.timeout_ms,
        move |dataset, index| {
            let mut files = dataset.resource_files(index)?;
            files.retain(|file| file.name.starts_with(&prefix));
            Ok(files)
        },
    )?;
    let (start, end) = window(args.offset, files.len(), limit)?;
    let rows: Vec<Value> = files[start..end]
        .iter()
        .map(|file| {
            let mut row = json!({
                "bytes": file.bytes,
                "compressed_bytes": file.compressed_bytes,
                "crc32": file.crc32,
                "directory": file.directory,
                "entry_index": file.entry_index,
                "name": file.name,
            });
            if let (Some(hex), Value::Object(map)) = (&file.raw_name_hex, &mut row) {
                map.insert("raw_name_hex".to_owned(), json!(hex));
            }
            row
        })
        .collect();
    let total = files.len();
    fit_rows(&rows, budget, &|count| {
        let next = start + count;
        json!({
            "dataset_id": args.dataset_id,
            "files": &rows[..count],
            "input_index": input_index,
            "next_offset": (next < total).then_some(next),
            "offset": args.offset,
            "total_rows": total,
            "truncated": next < total,
        })
    })
}
