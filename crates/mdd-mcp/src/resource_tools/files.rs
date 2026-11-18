//! `list_resource_files`: the members of an archive, by name.
use super::{fit_rows, limit_of, row_budget, run, window};
use crate::tools::{Failure, Registry};
use mdd_service::resources::ResourceFile;
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

/// The members whose name starts with `prefix` (case-sensitive; empty keeps all).
fn with_prefix(mut files: Vec<ResourceFile>, prefix: &str) -> Vec<ResourceFile> {
    files.retain(|file| file.name.starts_with(prefix));
    files
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
            let files = dataset.resource_files(index)?;
            Ok(with_prefix(files, &prefix))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn file(name: &str) -> ResourceFile {
        ResourceFile {
            entry_index: 0,
            name: name.to_owned(),
            raw_name_hex: None,
            bytes: 0,
            compressed_bytes: 0,
            crc32: 0,
            directory: false,
        }
    }

    #[test]
    fn a_prefix_is_the_start_of_a_name_and_case_matters() {
        let files = vec![
            file("res/raw/a"),
            file("raw/b"),
            file("Raw/c"),
            file("assets/res/d"),
        ];
        let names = |kept: Vec<ResourceFile>| kept.into_iter().map(|f| f.name).collect::<Vec<_>>();
        assert_eq!(names(with_prefix(files.clone(), "raw/")), ["raw/b"]);
        assert_eq!(names(with_prefix(files.clone(), "res/")), ["res/raw/a"]);
        assert_eq!(names(with_prefix(files.clone(), "")).len(), 4);
        assert!(with_prefix(files, "RAW/").is_empty());
    }
}
