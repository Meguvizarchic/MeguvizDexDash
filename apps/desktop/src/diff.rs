//! Comparing two input sets.
//!
//! Only definitions are compared: the engine's `methods` relation also lists methods that a DEX merely
//! references (no access flags, no code), and those are left out rather than shown as codeless methods.
//!
//! The comparison is made only from rows the engine returned in full: each side's classes and methods
//! are counted first, loaded page by page, and accepted only when the rows loaded are exactly that
//! many and their keys are all distinct (which proves the pages neither skipped nor repeated a row
//! even though no ORDER BY was asked for). A side that cannot be loaded completely makes the whole
//! comparison fail; an unloaded page is never shown as "no difference".
//!
//! What the list can and cannot say is stated with each status. A method is compared by the opcode
//! sequence the engine reports (`methods.opcode_hex`): equal opcodes are `opcodes_equal`, which does
//! NOT mean equal operands — only the smali comparison of one method pair says that. A method with no
//! code item (abstract, native) is kept apart from one with an empty body.
use crate::engine::{Engine, Failure, Lease};
use crate::export::failure_of;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// The engine pages a statement by `offset + limit`, at most this many rows.
pub const ENGINE_WINDOW_ROWS: u64 = 100_000;
const PAGE_ROWS: u64 = 1000;
const STORE_CAPACITY: usize = 3;
const MAX_SMALI_BYTES: usize = 4 * 1024 * 1024;
const MAX_EDIT_DISTANCE: usize = 1500;

#[derive(Clone, Debug, Deserialize)]
pub struct DiffRequest {
    pub call_id: String,
    pub handle_a: u64,
    pub handle_b: u64,
    /// Only classes whose descriptor starts with this (e.g. `Lorg/example/`); empty means all.
    #[serde(default)]
    pub prefix: String,
    pub deadline_ms: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    OnlyA,
    OnlyB,
    CountDiffers,
    OpcodesDiffer,
    CodeVsNoCode,
    FactsDiffer,
    OpcodesEqual,
    NoCodeBoth,
    FactsEqual,
}

impl Status {
    /// Statuses that mean "the two sides agree as far as this comparison can see".
    pub fn is_agreement(self) -> bool {
        matches!(
            self,
            Self::OpcodesEqual | Self::NoCodeBoth | Self::FactsEqual
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Fingerprint {
    NoCode,
    Code { count: u64, hex: String },
}

#[derive(Clone, Debug)]
pub struct ClassItem {
    pub file_id: u64,
    pub def_idx: u64,
    pub access: Option<u64>,
    pub superclass: Option<String>,
    pub interfaces: Option<u64>,
    pub source_file: Option<String>,
}

impl ClassItem {
    fn facts(&self) -> (Option<u64>, Option<String>, Option<u64>, Option<String>) {
        (
            self.access,
            self.superclass.clone(),
            self.interfaces,
            self.source_file.clone(),
        )
    }
}

#[derive(Clone, Debug)]
pub struct MethodItem {
    pub file_id: u64,
    pub method_idx: u64,
    pub access: Option<u64>,
    pub fingerprint: Fingerprint,
}

#[derive(Clone, Debug, Default)]
pub struct Side {
    pub handle: u64,
    pub snapshot_ids: Vec<String>,
    pub content_ids: Vec<String>,
    pub entries: BTreeMap<u64, String>,
    pub classes: BTreeMap<String, Vec<ClassItem>>,
    pub methods: BTreeMap<String, Vec<MethodItem>>,
    pub class_rows: u64,
    pub method_rows: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct Entry {
    pub kind: &'static str,
    pub key: String,
    pub status: Status,
    pub a: Vec<Value>,
    pub b: Vec<Value>,
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct DiffResult {
    pub entries: Vec<Entry>,
    pub summary: Value,
    pub sides: Vec<Value>,
    pub prefix: String,
}

#[derive(Default)]
pub struct DiffStore {
    next: Mutex<u64>,
    results: Mutex<VecDeque<(u64, Arc<DiffResult>)>>,
}

impl DiffStore {
    pub fn put(&self, result: DiffResult) -> u64 {
        let id = {
            let mut next = self.next.lock().unwrap_or_else(|p| p.into_inner());
            *next += 1;
            *next
        };
        let mut results = self.results.lock().unwrap_or_else(|p| p.into_inner());
        results.push_back((id, Arc::new(result)));
        while results.len() > STORE_CAPACITY {
            results.pop_front();
        }
        id
    }

    pub fn get(&self, id: u64) -> Option<Arc<DiffResult>> {
        self.results
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .find(|(key, _)| *key == id)
            .map(|(_, value)| value.clone())
    }
}

// ---- loading one side ------------------------------------------------------------------------

fn uint(cell: &Value) -> Option<u64> {
    match cell["type"].as_str()? {
        "uint64" | "int64" => cell["value"].as_str()?.parse().ok(),
        _ => None,
    }
}

fn text(cell: &Value) -> Option<String> {
    match cell["type"].as_str()? {
        "utf8" => cell["value"].as_str().map(str::to_owned),
        _ => None,
    }
}

/// `column LIKE 'prefix%' ESCAPE '\'` with the prefix's own wildcards and quotes made literal.
fn like_condition(column: &str, prefix: &str) -> Option<String> {
    if prefix.is_empty() {
        return None;
    }
    let mut pattern = String::new();
    for c in prefix.chars() {
        if matches!(c, '\\' | '%' | '_') {
            pattern.push('\\');
        }
        pattern.push(c);
    }
    pattern.push('%');
    Some(format!(
        "{column} LIKE '{}' ESCAPE '\\'",
        pattern.replace('\'', "''")
    ))
}

fn where_of(conditions: impl IntoIterator<Item = String>) -> String {
    let all: Vec<String> = conditions.into_iter().collect();
    if all.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", all.join(" AND "))
    }
}

struct Fetch<'a> {
    engine: &'a Engine,
    lease: &'a Lease<'a>,
    deadline_ms: Option<u64>,
}

impl Fetch<'_> {
    fn query(&self, handle: u64, sql: String, limit: u64, offset: u64) -> Result<Value, Failure> {
        let mut args = json!({"sql": [sql], "limit": limit, "offset": offset});
        if let Some(ms) = self.deadline_ms {
            args["timeout_ms"] = json!(ms);
        }
        let reply = self.engine.call(self.lease, "query", Some(handle), args)?;
        if !reply.ok {
            return Err(failure_of(&reply.data));
        }
        Ok(reply.data["statements"][0].clone())
    }

    fn count(&self, handle: u64, statement: &str) -> Result<u64, Failure> {
        let counted = self.query(
            handle,
            format!("SELECT count(*) FROM (\n{statement}\n)"),
            1,
            0,
        )?;
        uint(&counted["rows"][0][0])
            .ok_or_else(|| Failure::new("DIFF_COUNT", "the engine did not answer the row count"))
    }

    /// Every row of `statement`, in pages; the count must be reached exactly.
    fn all(
        &self,
        handle: u64,
        statement: &str,
        total: u64,
        what: &str,
        mut progress: impl FnMut(u64),
    ) -> Result<Vec<Vec<Value>>, Failure> {
        if total > ENGINE_WINDOW_ROWS {
            return Err(Failure::new(
                "DIFF_SCOPE_TOO_LARGE",
                format!(
                    "{what} has {total} rows, more than the {ENGINE_WINDOW_ROWS} the engine can page through; narrow the comparison with a class prefix such as Lcom/example/"
                ),
            ));
        }
        let mut rows = Vec::with_capacity(total as usize);
        let mut offset = 0u64;
        while offset < total {
            if self.lease.is_cancelled() {
                return Err(Failure::new("CANCELLED", "cancelled"));
            }
            let page = self.query(handle, statement.to_owned(), PAGE_ROWS, offset)?;
            let got = page["rows"].as_array().cloned().unwrap_or_default();
            if got.is_empty() {
                return Err(Failure::new(
                    "DIFF_SHORT",
                    format!("{what}: the engine returned no rows at offset {offset} of {total}"),
                ));
            }
            for row in got {
                rows.push(row.as_array().cloned().unwrap_or_default());
            }
            offset = rows.len() as u64;
            progress(PAGE_ROWS.min(total));
        }
        if rows.len() as u64 != total {
            return Err(Failure::new(
                "DIFF_COUNT",
                format!(
                    "{what}: loaded {} rows but the engine counts {total}",
                    rows.len()
                ),
            ));
        }
        Ok(rows)
    }
}

const CLASS_COLUMNS: &str = "file_id, class_def_idx, descriptor, access_flags, superclass_descriptor, interface_count, source_file";
const METHOD_COLUMNS: &str =
    "file_id, method_idx, class_descriptor, descriptor, access_flags, opcode_count, opcode_hex";

struct Plan {
    class_sql: String,
    method_sql: String,
    entries_sql: String,
}

fn plan(prefix: &str) -> Plan {
    Plan {
        class_sql: format!(
            "SELECT {CLASS_COLUMNS} FROM classes{}",
            where_of(like_condition("descriptor", prefix))
        ),
        // `methods` lists every method id: definitions (access_flags set) and methods only referenced from
        // this DEX (access_flags NULL, no code). Only definitions are compared.
        method_sql: format!(
            "SELECT {METHOD_COLUMNS} FROM methods{}",
            where_of(
                std::iter::once("access_flags IS NOT NULL".to_owned())
                    .chain(like_condition("class_descriptor", prefix))
            )
        ),
        entries_sql: "SELECT file_id, entry_name FROM dex_files ORDER BY file_id".to_owned(),
    }
}

/// A defined method's opcode column: empty means it has no code item (abstract, native); a method with
/// code always has at least one instruction. NULL on a definition is not an answer the comparison can use.
pub fn fingerprint(count: Option<u64>, hex: Option<String>) -> Option<Fingerprint> {
    let hex = hex?;
    Some(if hex.is_empty() {
        Fingerprint::NoCode
    } else {
        Fingerprint::Code {
            count: count.unwrap_or(0),
            hex,
        }
    })
}

fn build_side(
    engine: &Engine,
    handle: u64,
    classes: &[Vec<Value>],
    methods: &[Vec<Value>],
    entries: &[Vec<Value>],
) -> Result<Side, Failure> {
    let dataset = engine
        .datasets()
        .into_iter()
        .find(|d| d.handle == handle)
        .ok_or_else(|| Failure::new("UNKNOWN_HANDLE", format!("no open input set {handle}")))?;
    let sources = dataset.summary["snapshot_manifest"]["sources"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let ids = |key: &str| -> Vec<String> {
        sources
            .iter()
            .filter_map(|s| s[key].as_str().map(str::to_owned))
            .collect()
    };
    side_from_rows(
        handle,
        ids("occurrence_id"),
        ids("content_id"),
        classes,
        methods,
        entries,
    )
}

/// The rows the engine returned, as one side. Pure: this is where a repeated key, a short row or a
/// definition without an opcode value is refused.
pub fn side_from_rows(
    handle: u64,
    snapshot_ids: Vec<String>,
    content_ids: Vec<String>,
    classes: &[Vec<Value>],
    methods: &[Vec<Value>],
    entries: &[Vec<Value>],
) -> Result<Side, Failure> {
    let mut side = Side {
        handle,
        snapshot_ids,
        content_ids,
        class_rows: classes.len() as u64,
        method_rows: methods.len() as u64,
        ..Side::default()
    };
    for row in entries {
        if let (Some(id), Some(name)) = (row.first().and_then(uint), row.get(1).and_then(text)) {
            side.entries.insert(id, name);
        }
    }
    let shape = || {
        Failure::new(
            "DIFF_SHAPE",
            "a row does not have the columns the comparison asked for",
        )
    };
    let mut class_keys = std::collections::BTreeSet::new();
    for row in classes {
        let (Some(file_id), Some(def_idx), Some(descriptor)) = (
            row.first().and_then(uint),
            row.get(1).and_then(uint),
            row.get(2).and_then(text),
        ) else {
            return Err(shape());
        };
        if !class_keys.insert((file_id, def_idx)) {
            return Err(Failure::new(
                "DIFF_UNSTABLE",
                "the engine returned the same class row twice while paging: its row order is not stable",
            ));
        }
        side.classes.entry(descriptor).or_default().push(ClassItem {
            file_id,
            def_idx,
            access: row.get(3).and_then(uint),
            superclass: row.get(4).and_then(text),
            interfaces: row.get(5).and_then(uint),
            source_file: row.get(6).and_then(text),
        });
    }
    let mut method_keys = std::collections::BTreeSet::new();
    for row in methods {
        let (Some(file_id), Some(method_idx), Some(descriptor)) = (
            row.first().and_then(uint),
            row.get(1).and_then(uint),
            row.get(3).and_then(text),
        ) else {
            return Err(shape());
        };
        if !method_keys.insert((file_id, method_idx)) {
            return Err(Failure::new(
                "DIFF_UNSTABLE",
                "the engine returned the same method row twice while paging: its row order is not stable",
            ));
        }
        side.methods
            .entry(descriptor)
            .or_default()
            .push(MethodItem {
                file_id,
                method_idx,
                access: row.get(4).and_then(uint),
                fingerprint: fingerprint(row.get(5).and_then(uint), row.get(6).and_then(text))
                    .ok_or_else(|| {
                        Failure::new(
                            "DIFF_SHAPE",
                            "a defined method has no opcode value; the comparison will not guess",
                        )
                    })?,
            });
    }
    Ok(side)
}

/// Load both sides completely and compare them.
pub fn run_diff(
    engine: &Engine,
    lease: &Lease<'_>,
    request: &DiffRequest,
    mut progress: impl FnMut(u64, u64),
) -> Result<DiffResult, Failure> {
    if request.handle_a == request.handle_b {
        return Err(Failure::invalid(
            "compare two different input sets (open the second one first)",
        ));
    }
    let fetch = Fetch {
        engine,
        lease,
        deadline_ms: request.deadline_ms,
    };
    let plan = plan(&request.prefix);
    let mut totals = Vec::new();
    for handle in [request.handle_a, request.handle_b] {
        totals.push((
            fetch.count(handle, &plan.class_sql)?,
            fetch.count(handle, &plan.method_sql)?,
        ));
    }
    let grand: u64 = totals.iter().map(|(c, m)| c + m).sum();
    let mut done = 0u64;
    let mut sides = Vec::new();
    for (handle, (class_total, method_total)) in
        [request.handle_a, request.handle_b].into_iter().zip(totals)
    {
        let classes = fetch.all(
            handle,
            &plan.class_sql,
            class_total,
            "the class list",
            |n| {
                done += n;
                progress(done.min(grand), grand);
            },
        )?;
        let methods = fetch.all(
            handle,
            &plan.method_sql,
            method_total,
            "the method list",
            |n| {
                done += n;
                progress(done.min(grand), grand);
            },
        )?;
        let entries_total = fetch.count(handle, &plan.entries_sql)?;
        let entries = fetch.all(
            handle,
            &plan.entries_sql,
            entries_total,
            "the DEX member list",
            |_| {},
        )?;
        sides.push(build_side(engine, handle, &classes, &methods, &entries)?);
    }
    progress(grand, grand);
    let b = sides.pop().expect("two sides");
    let a = sides.pop().expect("two sides");
    Ok(compare(&a, &b, &request.prefix))
}

// ---- comparing ---------------------------------------------------------------------------------

fn occurrence(side: &Side, file_id: u64, index: u64, extra: Value) -> Value {
    json!({
        "file_id": file_id,
        "entry": side.entries.get(&file_id),
        "index": index,
        "detail": extra,
    })
}

fn class_entry(descriptor: &str, a: &Side, b: &Side) -> Option<Entry> {
    let left = a.classes.get(descriptor).map(Vec::as_slice).unwrap_or(&[]);
    let right = b.classes.get(descriptor).map(Vec::as_slice).unwrap_or(&[]);
    if left.is_empty() && right.is_empty() {
        return None;
    }
    let show = |side: &Side, items: &[ClassItem]| -> Vec<Value> {
        items
            .iter()
            .map(|c| {
                occurrence(
                    side,
                    c.file_id,
                    c.def_idx,
                    json!({"access_flags": c.access, "superclass": c.superclass, "interfaces": c.interfaces, "source_file": c.source_file}),
                )
            })
            .collect()
    };
    let mut notes = Vec::new();
    let status = if right.is_empty() {
        Status::OnlyA
    } else if left.is_empty() {
        Status::OnlyB
    } else if left.len() != right.len() {
        notes.push(format!(
            "A 定义它 {} 次，B 定义它 {} 次（重复定义按出现次数保留）",
            left.len(),
            right.len()
        ));
        Status::CountDiffers
    } else {
        let mut l: Vec<_> = left.iter().map(ClassItem::facts).collect();
        let mut r: Vec<_> = right.iter().map(ClassItem::facts).collect();
        l.sort();
        r.sort();
        if l == r {
            Status::FactsEqual
        } else {
            notes.push("访问标志、父类、接口个数或 source_file 不同".to_owned());
            Status::FactsDiffer
        }
    };
    Some(Entry {
        kind: "class",
        key: descriptor.to_owned(),
        status,
        a: show(a, left),
        b: show(b, right),
        notes,
    })
}

fn no_code_count(fingerprints: &[(u8, u64, String)]) -> usize {
    fingerprints.iter().filter(|(has, _, _)| *has == 0).count()
}

fn method_entry(descriptor: &str, a: &Side, b: &Side) -> Option<Entry> {
    let left = a.methods.get(descriptor).map(Vec::as_slice).unwrap_or(&[]);
    let right = b.methods.get(descriptor).map(Vec::as_slice).unwrap_or(&[]);
    if left.is_empty() && right.is_empty() {
        return None;
    }
    let show = |side: &Side, items: &[MethodItem]| -> Vec<Value> {
        items
            .iter()
            .map(|m| {
                let (has_code, count, len) = match &m.fingerprint {
                    Fingerprint::NoCode => (false, None, 0),
                    Fingerprint::Code { count, hex } => (true, Some(*count), hex.len()),
                };
                occurrence(
                    side,
                    m.file_id,
                    m.method_idx,
                    json!({"access_flags": m.access, "has_code": has_code, "opcode_count": count, "opcode_hex_chars": len}),
                )
            })
            .collect()
    };
    let mut notes = Vec::new();
    let status = if right.is_empty() {
        Status::OnlyA
    } else if left.is_empty() {
        Status::OnlyB
    } else if left.len() != right.len() {
        notes.push(format!(
            "A 定义它 {} 次，B 定义它 {} 次（重复定义按出现次数保留）",
            left.len(),
            right.len()
        ));
        Status::CountDiffers
    } else {
        let key = |f: &Fingerprint| match f {
            Fingerprint::NoCode => (0u8, 0u64, String::new()),
            Fingerprint::Code { count, hex } => (1u8, *count, hex.clone()),
        };
        let mut l: Vec<_> = left.iter().map(|m| key(&m.fingerprint)).collect();
        let mut r: Vec<_> = right.iter().map(|m| key(&m.fingerprint)).collect();
        l.sort();
        r.sort();
        if l == r {
            if l.iter().all(|(has, _, _)| *has == 0) {
                Status::NoCodeBoth
            } else {
                notes.push("操作码序列相同；操作数（常量、引用、跳转目标）没有被比较，要证明相同请对这一对方法做 smali 对比".to_owned());
                Status::OpcodesEqual
            }
        } else if no_code_count(&l) != no_code_count(&r) {
            notes.push("一边有代码，另一边没有代码项（抽象/native）".to_owned());
            Status::CodeVsNoCode
        } else {
            Status::OpcodesDiffer
        }
    };
    let flags_differ = !left.is_empty() && !right.is_empty() && {
        let mut l: Vec<_> = left.iter().map(|m| m.access).collect();
        let mut r: Vec<_> = right.iter().map(|m| m.access).collect();
        l.sort();
        r.sort();
        l != r
    };
    if flags_differ {
        notes.push("访问标志不同".to_owned());
    }
    Some(Entry {
        kind: "method",
        key: descriptor.to_owned(),
        status,
        a: show(a, left),
        b: show(b, right),
        notes,
    })
}

/// Compare two fully loaded sides. Pure: no engine, no I/O.
pub fn compare(a: &Side, b: &Side, prefix: &str) -> DiffResult {
    let mut entries = Vec::new();
    let class_keys: std::collections::BTreeSet<&String> =
        a.classes.keys().chain(b.classes.keys()).collect();
    for key in class_keys {
        entries.extend(class_entry(key, a, b));
    }
    let method_keys: std::collections::BTreeSet<&String> =
        a.methods.keys().chain(b.methods.keys()).collect();
    for key in method_keys {
        entries.extend(method_entry(key, a, b));
    }
    let by_status = |kind: &str| -> Value {
        let mut out = serde_json::Map::new();
        for entry in entries.iter().filter(|e| e.kind == kind) {
            let name = serde_json::to_value(entry.status).unwrap_or(Value::Null);
            let key = name.as_str().unwrap_or("?").to_owned();
            let current = out.get(&key).and_then(Value::as_u64).unwrap_or(0);
            out.insert(key, json!(current + 1));
        }
        Value::Object(out)
    };
    let differences = entries.iter().filter(|e| !e.status.is_agreement()).count();
    let summary = json!({
        "classes": by_status("class"),
        "methods": by_status("method"),
        "entries": entries.len(),
        "differences": differences,
        "rows": {
            "a": {"classes": a.class_rows, "methods": a.method_rows},
            "b": {"classes": b.class_rows, "methods": b.method_rows},
        },
        "complete": true,
        "method_comparison": "defined methods only (a method merely referenced from a DEX is not compared), by opcode sequence (operands are not compared); smali comparison of a pair is exact",
    });
    let side_json = |s: &Side| {
        json!({
            "handle": s.handle,
            "snapshot_ids": s.snapshot_ids,
            "content_ids": s.content_ids,
            "dex_members": s.entries,
            "classes_loaded": s.class_rows,
            "methods_loaded": s.method_rows,
        })
    };
    DiffResult {
        entries,
        summary,
        sides: vec![side_json(a), side_json(b)],
        prefix: prefix.to_owned(),
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct PageQuery {
    pub diff_id: u64,
    /// "class" or "method"; empty means both.
    #[serde(default)]
    pub kind: String,
    /// One status name; "differences" means every status that is not an agreement; empty means all.
    #[serde(default)]
    pub status: String,
    /// Case-sensitive substring of the key.
    #[serde(default)]
    pub contains: String,
    #[serde(default)]
    pub offset: usize,
    pub limit: Option<usize>,
}

pub fn page(store: &DiffStore, query: &PageQuery) -> Result<Value, Failure> {
    let result = store.get(query.diff_id).ok_or_else(|| {
        Failure::new(
            "UNKNOWN_DIFF",
            "that comparison is gone (only the last few are kept); run it again",
        )
    })?;
    let wanted: Option<Status> = if query.status.is_empty() || query.status == "differences" {
        None
    } else {
        Some(
            serde_json::from_value(Value::String(query.status.clone()))
                .map_err(|_| Failure::invalid(format!("no such status {:?}", query.status)))?,
        )
    };
    let matching: Vec<&Entry> = result
        .entries
        .iter()
        .filter(|e| query.kind.is_empty() || e.kind == query.kind)
        .filter(|e| match wanted {
            Some(status) => e.status == status,
            None => query.status != "differences" || !e.status.is_agreement(),
        })
        .filter(|e| query.contains.is_empty() || e.key.contains(&query.contains))
        .collect();
    let limit = query.limit.unwrap_or(100).clamp(1, 500);
    let rows: Vec<&&Entry> = matching.iter().skip(query.offset).take(limit).collect();
    let end = query.offset + rows.len();
    Ok(json!({
        "total": matching.len(),
        "offset": query.offset,
        "next_offset": if end < matching.len() { json!(end) } else { Value::Null },
        "entries": rows,
    }))
}

// ---- comparing the smali of one method pair -----------------------------------------------------

#[derive(Clone, Debug, Deserialize)]
pub struct SmaliDiffRequest {
    pub call_id: String,
    pub handle_a: u64,
    pub file_id_a: u64,
    pub method_idx_a: u64,
    pub handle_b: u64,
    pub file_id_b: u64,
    pub method_idx_b: u64,
    pub deadline_ms: Option<u64>,
}

fn smali_text(
    engine: &Engine,
    lease: &Lease<'_>,
    handle: u64,
    file_id: u64,
    method_idx: u64,
    deadline_ms: Option<u64>,
) -> Result<String, Failure> {
    let mut text = String::new();
    let mut offset = 0u64;
    loop {
        if lease.is_cancelled() {
            return Err(Failure::new("CANCELLED", "cancelled"));
        }
        let mut args = json!({"file_id": file_id, "method_idx": method_idx, "mode": "smali", "max_lines": 1000, "offset": offset});
        if let Some(ms) = deadline_ms {
            args["timeout_ms"] = json!(ms);
        }
        let reply = engine.call(lease, "decode", Some(handle), args)?;
        if !reply.ok {
            return Err(failure_of(&reply.data));
        }
        let method = &reply.data["methods"][0];
        text.push_str(method["smali"].as_str().unwrap_or(""));
        if text.len() > MAX_SMALI_BYTES {
            return Err(Failure::new(
                "DIFF_SCOPE_TOO_LARGE",
                "the method's smali is over 4 MiB; compare it with an external tool",
            ));
        }
        match method["next_offset"].as_u64() {
            Some(next) => offset = next,
            None => return Ok(text),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum Op {
    #[serde(rename = "=")]
    Equal,
    #[serde(rename = "-")]
    Delete,
    #[serde(rename = "+")]
    Insert,
}

/// The line-by-line difference of two texts, or None when it needs more than `max_d` edits.
pub fn diff_lines(a: &[&str], b: &[&str], max_d: usize) -> Option<Vec<(Op, usize)>> {
    let mut prefix = 0;
    while prefix < a.len() && prefix < b.len() && a[prefix] == b[prefix] {
        prefix += 1;
    }
    let mut suffix = 0;
    while suffix < a.len() - prefix
        && suffix < b.len() - prefix
        && a[a.len() - 1 - suffix] == b[b.len() - 1 - suffix]
    {
        suffix += 1;
    }
    let middle = myers(
        &a[prefix..a.len() - suffix],
        &b[prefix..b.len() - suffix],
        max_d,
    )?;
    let mut script: Vec<(Op, usize)> = (0..prefix).map(|i| (Op::Equal, i)).collect();
    for (op, index) in middle {
        // an Insert indexes b, the others index a; both are shifted by the trimmed prefix
        script.push((op, index + prefix));
    }
    script.extend((0..suffix).map(|i| (Op::Equal, a.len() - suffix + i)));
    Some(script)
}

/// Myers' O(ND) difference. `Equal` and `Delete` index `a`, `Insert` indexes `b`.
pub fn myers(a: &[&str], b: &[&str], max_d: usize) -> Option<Vec<(Op, usize)>> {
    let n = a.len() as i32;
    let m = b.len() as i32;
    if n == 0 && m == 0 {
        return Some(Vec::new());
    }
    let limit = max_d.min((n + m) as usize) as i32;
    let offset = limit + 1;
    let mut v = vec![0i32; (2 * limit + 3) as usize];
    let mut trace: Vec<Vec<i32>> = Vec::new();
    let mut found = None;
    'search: for d in 0..=limit {
        trace.push(v.clone());
        let mut k = -d;
        while k <= d {
            let at = (k + offset) as usize;
            let mut x = if k == -d || (k != d && v[at - 1] < v[at + 1]) {
                v[at + 1]
            } else {
                v[at - 1] + 1
            };
            let mut y = x - k;
            while x < n && y < m && a[x as usize] == b[y as usize] {
                x += 1;
                y += 1;
            }
            v[at] = x;
            if x >= n && y >= m {
                found = Some(d);
                break 'search;
            }
            k += 2;
        }
    }
    let last = found?;
    let (mut x, mut y) = (n, m);
    let mut script = Vec::new();
    for d in (0..=last).rev() {
        let before = &trace[d as usize];
        let k = x - y;
        let at = (k + offset) as usize;
        let previous_k = if k == -d || (k != d && before[at - 1] < before[at + 1]) {
            k + 1
        } else {
            k - 1
        };
        let previous_x = before[(previous_k + offset) as usize];
        let previous_y = previous_x - previous_k;
        while x > previous_x && y > previous_y {
            x -= 1;
            y -= 1;
            script.push((Op::Equal, x as usize));
        }
        if d > 0 {
            if x == previous_x {
                y -= 1;
                script.push((Op::Insert, y as usize));
            } else {
                x -= 1;
                script.push((Op::Delete, x as usize));
            }
        }
    }
    script.reverse();
    Some(script)
}

pub fn smali_diff(
    engine: &Engine,
    lease: &Lease<'_>,
    request: &SmaliDiffRequest,
) -> Result<Value, Failure> {
    let started = Instant::now();
    let left = smali_text(
        engine,
        lease,
        request.handle_a,
        request.file_id_a,
        request.method_idx_a,
        request.deadline_ms,
    )?;
    let right = smali_text(
        engine,
        lease,
        request.handle_b,
        request.file_id_b,
        request.method_idx_b,
        request.deadline_ms,
    )?;
    let a: Vec<&str> = left.lines().collect();
    let b: Vec<&str> = right.lines().collect();
    let identical = left == right;
    let Some(script) = diff_lines(&a, &b, MAX_EDIT_DISTANCE) else {
        return Ok(json!({
            "identical": false,
            "too_different": true,
            "lines_a": a.len(),
            "lines_b": b.len(),
            "note": format!("the two texts differ in more than {MAX_EDIT_DISTANCE} lines; no line diff is shown"),
            "elapsed_ms": started.elapsed().as_millis() as u64,
        }));
    };
    let lines: Vec<Value> = script
        .iter()
        .map(|(op, index)| {
            let text = match op {
                Op::Insert => b[*index],
                _ => a[*index],
            };
            json!({"op": op, "text": text})
        })
        .collect();
    let added = script.iter().filter(|(op, _)| *op == Op::Insert).count();
    let removed = script.iter().filter(|(op, _)| *op == Op::Delete).count();
    Ok(json!({
        "identical": identical,
        "too_different": false,
        "lines_a": a.len(),
        "lines_b": b.len(),
        "added": added,
        "removed": removed,
        "lines": lines,
        "elapsed_ms": started.elapsed().as_millis() as u64,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(text: &str) -> Vec<&str> {
        text.split_whitespace().collect()
    }

    fn apply(a: &[&str], b: &[&str], script: &[(Op, usize)]) -> Vec<String> {
        let mut out = Vec::new();
        for (op, index) in script {
            match op {
                Op::Equal => out.push(a[*index].to_owned()),
                Op::Insert => out.push(b[*index].to_owned()),
                Op::Delete => {}
            }
        }
        out
    }

    fn edit_distance(a: &[&str], b: &[&str]) -> usize {
        let mut table = vec![vec![0usize; b.len() + 1]; a.len() + 1];
        for i in 1..=a.len() {
            for j in 1..=b.len() {
                table[i][j] = if a[i - 1] == b[j - 1] {
                    table[i - 1][j - 1] + 1
                } else {
                    table[i - 1][j].max(table[i][j - 1])
                };
            }
        }
        a.len() + b.len() - 2 * table[a.len()][b.len()]
    }

    #[test]
    fn the_textbook_example_has_the_shortest_script_and_rebuilds_b() {
        let a = lines("A B C A B B A");
        let b = lines("C B A B A C");
        let script = myers(&a, &b, 100).unwrap();
        assert_eq!(apply(&a, &b, &script), b);
        let edits = script.iter().filter(|(op, _)| *op != Op::Equal).count();
        assert_eq!(edits, 5);
        assert_eq!(edits, edit_distance(&a, &b));
    }

    #[test]
    fn every_small_pair_over_a_tiny_alphabet_rebuilds_and_is_minimal() {
        let words = ["a", "b", "c"];
        let all = |max_len: usize| {
            let mut out: Vec<Vec<&str>> = vec![Vec::new()];
            let mut layer: Vec<Vec<&str>> = vec![Vec::new()];
            for _ in 0..max_len {
                layer = layer
                    .iter()
                    .flat_map(|prefix| {
                        words.iter().map(move |w| {
                            let mut next = prefix.clone();
                            next.push(*w);
                            next
                        })
                    })
                    .collect();
                out.extend(layer.iter().cloned());
            }
            out
        };
        let sequences = all(4);
        let mut checked = 0;
        for a in &sequences {
            for b in &sequences {
                let script = diff_lines(a, b, 100).unwrap();
                assert_eq!(apply(a, b, &script), *b, "{a:?} -> {b:?}");
                let edits = script.iter().filter(|(op, _)| *op != Op::Equal).count();
                assert_eq!(edits, edit_distance(a, b), "{a:?} -> {b:?} is not minimal");
                // every line of a is accounted for exactly once, in order
                let from_a: Vec<usize> = script
                    .iter()
                    .filter(|(op, _)| *op != Op::Insert)
                    .map(|(_, i)| *i)
                    .collect();
                assert_eq!(from_a, (0..a.len()).collect::<Vec<_>>());
                checked += 1;
            }
        }
        assert_eq!(checked, sequences.len() * sequences.len());
    }

    #[test]
    fn identical_and_empty_inputs_are_trivial_and_a_cap_is_honoured() {
        assert_eq!(diff_lines(&[], &[], 5).unwrap(), vec![]);
        let same = lines("x y z");
        assert!(
            diff_lines(&same, &same, 0)
                .unwrap()
                .iter()
                .all(|(op, _)| *op == Op::Equal)
        );
        let a = lines("a b c d e f");
        let b = lines("1 2 3 4 5 6");
        assert!(diff_lines(&a, &b, 3).is_none());
        assert!(diff_lines(&a, &b, 12).is_some());
    }

    fn method(file_id: u64, idx: u64, fp: Fingerprint, access: u64) -> MethodItem {
        MethodItem {
            file_id,
            method_idx: idx,
            access: Some(access),
            fingerprint: fp,
        }
    }

    fn code(hex: &str) -> Fingerprint {
        Fingerprint::Code {
            count: hex.split(' ').count() as u64,
            hex: hex.to_owned(),
        }
    }

    fn side(handle: u64, methods: Vec<(&str, Vec<MethodItem>)>) -> Side {
        let mut s = Side {
            handle,
            ..Side::default()
        };
        for (key, items) in methods {
            s.method_rows += items.len() as u64;
            s.methods.insert(key.to_owned(), items);
        }
        s
    }

    fn status_of(result: &DiffResult, key: &str) -> Status {
        result
            .entries
            .iter()
            .find(|e| e.key == key)
            .unwrap_or_else(|| panic!("no entry {key}"))
            .status
    }

    #[test]
    fn methods_are_compared_by_presence_count_and_opcode_sequence_and_no_code_stays_apart() {
        let a = side(
            1,
            vec![
                ("same", vec![method(0, 1, code("1a 0e"), 9)]),
                ("body", vec![method(0, 2, code("1a 0e"), 9)]),
                ("gone", vec![method(0, 3, code("0e"), 9)]),
                (
                    "twice",
                    vec![method(0, 4, code("0e"), 9), method(1, 4, code("0e"), 9)],
                ),
                ("abstract", vec![method(0, 5, Fingerprint::NoCode, 0x401)]),
                (
                    "abstract-vs-code",
                    vec![method(0, 6, Fingerprint::NoCode, 0x401)],
                ),
                ("flags", vec![method(0, 7, code("0e"), 9)]),
            ],
        );
        let b = side(
            2,
            vec![
                ("same", vec![method(0, 11, code("1a 0e"), 9)]),
                ("body", vec![method(0, 12, code("0e"), 9)]),
                ("added", vec![method(0, 13, code("0e"), 9)]),
                ("twice", vec![method(0, 14, code("0e"), 9)]),
                ("abstract", vec![method(0, 15, Fingerprint::NoCode, 0x401)]),
                ("abstract-vs-code", vec![method(0, 16, code("0e"), 9)]),
                ("flags", vec![method(0, 17, code("0e"), 0x19)]),
            ],
        );
        let result = compare(&a, &b, "");
        assert_eq!(status_of(&result, "same"), Status::OpcodesEqual);
        assert_eq!(status_of(&result, "body"), Status::OpcodesDiffer);
        assert_eq!(status_of(&result, "gone"), Status::OnlyA);
        assert_eq!(status_of(&result, "added"), Status::OnlyB);
        assert_eq!(status_of(&result, "twice"), Status::CountDiffers);
        assert_eq!(status_of(&result, "abstract"), Status::NoCodeBoth);
        assert_eq!(status_of(&result, "abstract-vs-code"), Status::CodeVsNoCode);
        // same opcodes but different access flags is still "opcodes equal", with the flag difference noted
        let flags = result.entries.iter().find(|e| e.key == "flags").unwrap();
        assert_eq!(flags.status, Status::OpcodesEqual);
        assert!(flags.notes.iter().any(|n| n.contains("访问标志")));
        // an agreement is not a difference
        assert_eq!(result.summary["differences"], 5);
        assert_eq!(result.summary["methods"]["opcodes_equal"], 2);
    }

    #[test]
    fn an_opcodes_equal_note_says_operands_were_not_compared() {
        let a = side(1, vec![("m", vec![method(0, 1, code("1a 0e"), 9)])]);
        let b = side(2, vec![("m", vec![method(0, 1, code("1a 0e"), 9)])]);
        let entry = &compare(&a, &b, "").entries[0];
        assert_eq!(entry.status, Status::OpcodesEqual);
        assert!(
            entry.notes.iter().any(|n| n.contains("操作数")),
            "{:?}",
            entry.notes
        );
    }

    #[test]
    fn classes_are_compared_by_presence_count_and_facts() {
        let class = |file_id, idx, access| ClassItem {
            file_id,
            def_idx: idx,
            access: Some(access),
            superclass: Some("Ljava/lang/Object;".into()),
            interfaces: Some(0),
            source_file: None,
        };
        let mut a = Side::default();
        let mut b = Side::default();
        a.classes.insert("Lx/Same;".into(), vec![class(0, 1, 1)]);
        b.classes.insert("Lx/Same;".into(), vec![class(0, 9, 1)]);
        a.classes.insert("Lx/Changed;".into(), vec![class(0, 2, 1)]);
        b.classes
            .insert("Lx/Changed;".into(), vec![class(0, 8, 17)]);
        a.classes
            .insert("Lx/Dup;".into(), vec![class(0, 3, 1), class(1, 3, 1)]);
        b.classes.insert("Lx/Dup;".into(), vec![class(0, 7, 1)]);
        a.classes.insert("Lx/Old;".into(), vec![class(0, 4, 1)]);
        b.classes.insert("Lx/New;".into(), vec![class(0, 6, 1)]);
        let result = compare(&a, &b, "");
        assert_eq!(status_of(&result, "Lx/Same;"), Status::FactsEqual);
        assert_eq!(status_of(&result, "Lx/Changed;"), Status::FactsDiffer);
        assert_eq!(status_of(&result, "Lx/Dup;"), Status::CountDiffers);
        assert_eq!(status_of(&result, "Lx/Old;"), Status::OnlyA);
        assert_eq!(status_of(&result, "Lx/New;"), Status::OnlyB);
    }

    #[test]
    fn the_page_filters_by_kind_status_and_text_and_says_what_follows() {
        let a = side(
            1,
            vec![
                ("La;->x()V", vec![method(0, 1, code("0e"), 9)]),
                ("Lb;->y()V", vec![method(0, 2, code("0e"), 9)]),
            ],
        );
        let b = side(
            2,
            vec![
                ("La;->x()V", vec![method(0, 1, code("0e"), 9)]),
                ("Lc;->z()V", vec![method(0, 3, code("0e"), 9)]),
            ],
        );
        let store = DiffStore::default();
        let id = store.put(compare(&a, &b, ""));
        let query = |status: &str, contains: &str, limit: usize| PageQuery {
            diff_id: id,
            kind: "method".into(),
            status: status.into(),
            contains: contains.into(),
            offset: 0,
            limit: Some(limit),
        };
        let all = page(&store, &query("", "", 2)).unwrap();
        assert_eq!(all["total"], 3);
        assert_eq!(all["next_offset"], 2);
        let differences = page(&store, &query("differences", "", 10)).unwrap();
        assert_eq!(differences["total"], 2);
        assert_eq!(differences["next_offset"], Value::Null);
        let only_a = page(&store, &query("only_a", "", 10)).unwrap();
        assert_eq!(only_a["entries"][0]["key"], "Lb;->y()V");
        let named = page(&store, &query("", "Lc;", 10)).unwrap();
        assert_eq!(named["total"], 1);
        assert!(page(&store, &query("nonsense", "", 10)).is_err());
        assert_eq!(
            page(
                &store,
                &PageQuery {
                    diff_id: 999,
                    kind: String::new(),
                    status: String::new(),
                    contains: String::new(),
                    offset: 0,
                    limit: None
                }
            )
            .unwrap_err()
            .code,
            "UNKNOWN_DIFF"
        );
    }

    #[test]
    fn the_store_keeps_only_the_last_few_comparisons() {
        let store = DiffStore::default();
        let ids: Vec<u64> = (0..5)
            .map(|_| store.put(compare(&Side::default(), &Side::default(), "")))
            .collect();
        assert!(store.get(ids[0]).is_none());
        assert!(store.get(ids[1]).is_none());
        assert!(store.get(ids[2]).is_some());
        assert!(store.get(ids[4]).is_some());
    }

    #[test]
    fn a_prefix_filter_escapes_the_patterns_own_wildcards_and_quotes() {
        assert_eq!(like_condition("descriptor", ""), None);
        assert_eq!(
            like_condition("descriptor", "Lcom/a_b/").unwrap(),
            r"descriptor LIKE 'Lcom/a\_b/%' ESCAPE '\'"
        );
        assert_eq!(
            like_condition("descriptor", "L'x%").unwrap(),
            r"descriptor LIKE 'L''x\%%' ESCAPE '\'"
        );
    }

    #[test]
    fn only_definitions_are_asked_for_and_the_prefix_joins_the_same_where() {
        let all = plan("");
        assert!(
            all.method_sql
                .ends_with("FROM methods WHERE access_flags IS NOT NULL"),
            "{}",
            all.method_sql
        );
        assert!(!all.class_sql.contains("WHERE"));
        let scoped = plan("Lx/");
        assert!(
            scoped
                .method_sql
                .contains("WHERE access_flags IS NOT NULL AND class_descriptor LIKE 'Lx/%'"),
            "{}",
            scoped.method_sql
        );
        assert!(scoped.class_sql.contains("WHERE descriptor LIKE 'Lx/%'"));
    }

    #[test]
    fn an_empty_opcode_list_is_no_code_and_a_missing_one_is_refused() {
        assert_eq!(
            fingerprint(Some(0), Some(String::new())),
            Some(Fingerprint::NoCode)
        );
        assert_eq!(
            fingerprint(Some(2), Some("1a 0e".into())),
            Some(Fingerprint::Code {
                count: 2,
                hex: "1a 0e".into()
            })
        );
        assert_eq!(fingerprint(Some(0), None), None);
    }

    fn cell(kind: &str, value: Value) -> Value {
        json!({"type": kind, "value": value})
    }
    fn uint_cell(n: u64) -> Value {
        cell("uint64", json!(n.to_string()))
    }
    fn text_cell(s: &str) -> Value {
        cell("utf8", json!(s))
    }
    fn null_cell() -> Value {
        cell("null", Value::Null)
    }
    fn class_row(file: u64, idx: u64, name: &str) -> Vec<Value> {
        vec![
            uint_cell(file),
            uint_cell(idx),
            text_cell(name),
            uint_cell(1),
            text_cell("Ljava/lang/Object;"),
            uint_cell(0),
            null_cell(),
        ]
    }
    fn method_row(file: u64, idx: u64, descriptor: &str, hex: Option<&str>) -> Vec<Value> {
        let count = hex.map_or(0, |h| h.split(' ').filter(|p| !p.is_empty()).count() as u64);
        vec![
            uint_cell(file),
            uint_cell(idx),
            text_cell("Lx/A;"),
            text_cell(descriptor),
            uint_cell(9),
            uint_cell(count),
            hex.map_or_else(null_cell, text_cell),
        ]
    }
    fn side_of(classes: &[Vec<Value>], methods: &[Vec<Value>]) -> Result<Side, Failure> {
        let entries = vec![vec![uint_cell(0), text_cell("a.dex")]];
        side_from_rows(
            7,
            vec!["snap".into()],
            vec!["sha".into()],
            classes,
            methods,
            &entries,
        )
    }

    #[test]
    fn rows_become_a_side_with_their_provenance_and_their_counts() {
        let side = side_of(
            &[class_row(0, 1, "Lx/A;"), class_row(0, 2, "Lx/B;")],
            &[
                method_row(0, 1, "Lx/A;->a()V", Some("0e")),
                method_row(0, 2, "Lx/A;->b()V", Some("")),
            ],
        )
        .unwrap();
        assert_eq!((side.handle, side.class_rows, side.method_rows), (7, 2, 2));
        assert_eq!(side.snapshot_ids, vec!["snap"]);
        assert_eq!(side.content_ids, vec!["sha"]);
        assert_eq!(side.entries.get(&0).map(String::as_str), Some("a.dex"));
        assert_eq!(side.classes["Lx/A;"].len(), 1);
        assert_eq!(
            side.methods["Lx/A;->a()V"][0].fingerprint,
            Fingerprint::Code {
                count: 1,
                hex: "0e".into()
            }
        );
        assert_eq!(
            side.methods["Lx/A;->b()V"][0].fingerprint,
            Fingerprint::NoCode
        );
    }

    #[test]
    fn a_repeated_row_key_means_the_engine_paged_unstably_and_is_refused() {
        let class =
            side_of(&[class_row(0, 1, "Lx/A;"), class_row(0, 1, "Lx/B;")], &[]).unwrap_err();
        assert_eq!(class.code, "DIFF_UNSTABLE");
        let method = side_of(
            &[],
            &[
                method_row(0, 1, "Lx/A;->a()V", Some("0e")),
                method_row(0, 1, "Lx/A;->b()V", Some("0e")),
            ],
        )
        .unwrap_err();
        assert_eq!(method.code, "DIFF_UNSTABLE");
        // the same index in another DEX file is a different row, not a repeat
        assert!(side_of(&[class_row(0, 1, "Lx/A;"), class_row(1, 1, "Lx/A;")], &[]).is_ok());
        assert!(
            side_of(
                &[],
                &[
                    method_row(0, 1, "Lx/A;->a()V", Some("0e")),
                    method_row(1, 1, "Lx/A;->a()V", Some("0e"))
                ]
            )
            .is_ok()
        );
    }

    #[test]
    fn a_row_without_the_asked_columns_and_a_definition_without_opcodes_are_refused() {
        assert_eq!(
            side_of(&[vec![uint_cell(0)]], &[]).unwrap_err().code,
            "DIFF_SHAPE"
        );
        assert_eq!(
            side_of(&[], &[vec![uint_cell(0), uint_cell(1)]])
                .unwrap_err()
                .code,
            "DIFF_SHAPE"
        );
        let unknown = side_of(&[], &[method_row(0, 1, "Lx/A;->a()V", None)]).unwrap_err();
        assert_eq!(unknown.code, "DIFF_SHAPE");
        assert!(unknown.message.contains("will not guess"));
        // a class name that is not text is not a class name
        let mut odd = class_row(0, 1, "Lx/A;");
        odd[2] = uint_cell(5);
        assert_eq!(side_of(&[odd], &[]).unwrap_err().code, "DIFF_SHAPE");
    }

    #[test]
    fn a_result_past_the_engines_paging_window_is_refused_and_the_limit_itself_is_not() {
        let engine = Engine::new(
            std::env::temp_dir().join("mdd-desktop-no-such-engine.exe"),
            crate::engine::Settings::default(),
        );
        let lease = engine.lease("window", "test", None).unwrap();
        let fetch = Fetch {
            engine: &engine,
            lease: &lease,
            deadline_ms: None,
        };
        let over = fetch
            .all(
                1,
                "SELECT 1",
                ENGINE_WINDOW_ROWS + 1,
                "the method list",
                |_| {},
            )
            .unwrap_err();
        assert_eq!(over.code, "DIFF_SCOPE_TOO_LARGE");
        assert!(over.message.contains("class prefix"), "{}", over.message);
        // exactly the window passes the guard and goes on to ask the engine (which is not there)
        let at = fetch
            .all(1, "SELECT 1", ENGINE_WINDOW_ROWS, "the method list", |_| {})
            .unwrap_err();
        assert_ne!(at.code, "DIFF_SCOPE_TOO_LARGE");
    }
}
