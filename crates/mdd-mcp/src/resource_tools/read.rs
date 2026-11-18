//! `read_resource`: one archive member, as text when it is text, as XML when it is Android
//! binary XML, and as lower-case hex otherwise or on request.
//!
//! The units follow the representation and are never mixed: for text, `offset`,
//! `next_offset` and `total_bytes` count UTF-8 bytes of the text shown; for hex they count
//! bytes of the member as stored. `source_bytes` is always the member's size.
use super::{check_ceiling, page_bytes_of, run, source_json, text_page};
use crate::tools::{Failure, Registry, invalid, refuse, with_kind};
use mdd_service::resources::ResourceKind;
use mdd_types::ErrorCode;
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Args {
    dataset_id: String,
    format: Option<String>,
    input_index: Option<u64>,
    max_bytes: Option<u64>,
    name: String,
    #[serde(default)]
    offset: u64,
    timeout_ms: Option<u64>,
}

pub fn read_resource(registry: &mut Registry, args: Args) -> Result<Value, Failure> {
    let hex = match args.format.as_deref() {
        None | Some("auto") => false,
        Some("hex") => true,
        Some(_) => return Err(invalid("format must be auto or hex")),
    };
    let max_bytes = page_bytes_of(args.max_bytes)?;
    let name = args.name.clone();
    let (input_index, resource) = run(
        registry,
        "read_resource",
        &args.dataset_id,
        args.input_index,
        args.timeout_ms,
        move |dataset, index| dataset.resource(index, &name, hex),
    )?;
    let bytes = resource.evidence.bytes();
    let source_bytes = bytes.len() as u64;
    let answer = match (resource.kind, resource.text.as_deref()) {
        (ResourceKind::AndroidXml | ResourceKind::Text, Some(text)) => {
            let kind = if resource.kind == ResourceKind::AndroidXml {
                "android_xml"
            } else {
                "text"
            };
            json!({
                "dataset_id": args.dataset_id,
                "encoding": "utf8",
                "input_index": input_index,
                "kind": kind,
                "name": args.name,
                "page": text_page(text, args.offset, max_bytes)?,
                "source": source_json(&resource.evidence),
                "source_bytes": source_bytes,
            })
        }
        _ => {
            if args.offset > source_bytes {
                return Err(Failure::Execution(with_kind(
                    refuse(ErrorCode::InvalidArgument, "offset exceeds resource size"),
                    "invalid_range",
                )));
            }
            // a hex page holds a quarter of max_bytes in characters, so half of that in bytes
            let page = usize::try_from(max_bytes / 8).unwrap_or(usize::MAX);
            let start = args.offset as usize;
            let end = bytes.len().min(start.saturating_add(page));
            let content: String = bytes[start..end]
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            json!({
                "content": content,
                "dataset_id": args.dataset_id,
                "encoding": "hex",
                "input_index": input_index,
                "kind": "binary",
                "name": args.name,
                "next_offset": (end < bytes.len()).then_some(end),
                "offset": args.offset,
                "source": source_json(&resource.evidence),
                "source_bytes": source_bytes,
                "total_bytes": source_bytes,
            })
        }
    };
    check_ceiling(registry, &answer)?;
    Ok(answer)
}
