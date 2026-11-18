//! What the window may ask of the shell. Every function here is plain Rust over [`Engine`], so the
//! same code is what the integration tests and the window run; `main.rs` only wires it to Tauri.
use crate::diff::{
    DiffRequest, DiffStore, PageQuery, SmaliDiffRequest, page, run_diff, smali_diff,
};
use crate::engine::{Engine, Failure, Reply, Settings, engine_json};
use crate::export::{ExportReport, ExportRequest, export_query};
use serde::Deserialize;
use serde_json::{Value, json};
use std::time::{Duration, Instant};

#[derive(Clone, Debug, Deserialize)]
pub struct CallRequest {
    pub call_id: String,
    pub tool: String,
    pub handle: Option<u64>,
    #[serde(default = "empty_object")]
    pub args: Value,
    pub deadline_ms: Option<u64>,
}

fn empty_object() -> Value {
    json!({})
}

fn summary_of(request: &CallRequest) -> String {
    let mut what = request.tool.clone();
    if let Some(sql) = request.args["sql"][0].as_str() {
        let line: String = sql.split_whitespace().collect::<Vec<_>>().join(" ");
        what.push_str(": ");
        what.extend(line.chars().take(80));
    }
    what
}

fn finish(outcome: Result<Reply, Failure>, started: Instant) -> Reply {
    outcome.unwrap_or_else(|failure| Reply::failed(&failure, started.elapsed()))
}

/// Everything the window shows about the engine: where it is, what it is, what it lists and holds.
pub fn engine_info(engine: &Engine, call_id: &str) -> Value {
    let started = Instant::now();
    let started_engine =
        match engine.lease(call_id, "start the engine", Some(Duration::from_secs(30))) {
            Ok(lease) => match engine.prepare(&lease, None) {
                Ok((_, started)) => Ok(started),
                Err(failure) => Err(failure),
            },
            Err(failure) => Err(failure),
        };
    let binary = engine.binary();
    let version = engine_json(binary, "version").unwrap_or_else(|f| json!({"error": f.to_value()}));
    let capabilities =
        engine_json(binary, "capabilities").unwrap_or_else(|f| json!({"error": f.to_value()}));
    json!({
        "shell": {
            "name": "mdd-desktop",
            "version": env!("CARGO_PKG_VERSION"),
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
        },
        "binary": binary.display().to_string(),
        "binary_exists": binary.is_file(),
        "settings": engine.settings(),
        "version": version,
        "capabilities": capabilities,
        "tools": engine.tools(),
        "server": engine.server_info(),
        "start": match started_engine {
            Ok(started) => json!({"ok": true, "started": started}),
            Err(failure) => json!({"ok": false, "error": failure.to_value()}),
        },
        "elapsed_ms": started.elapsed().as_millis() as u64,
    })
}

/// What changes while the window is open: cheap, and never starts a process.
pub fn engine_state(engine: &Engine) -> Value {
    json!({
        "running": engine.running(),
        "busy": engine.busy(),
        "datasets": engine.datasets(),
        "settings": engine.settings(),
    })
}

pub fn configure(engine: &Engine, settings: Settings) -> Value {
    match engine.configure(settings) {
        Ok(()) => json!({"ok": true}),
        Err(failure) => json!({"ok": false, "error": failure.to_value()}),
    }
}

pub fn open_inputs(engine: &Engine, call_id: &str, paths: Vec<String>) -> Reply {
    let started = Instant::now();
    finish(
        engine
            .lease(call_id, "open inputs", Some(engine.watchdog_for(None)))
            .and_then(|lease| engine.open_inputs(&lease, paths)),
        started,
    )
}

pub fn close_inputs(engine: &Engine, call_id: &str, handle: u64) -> Reply {
    let started = Instant::now();
    finish(
        engine
            .lease(call_id, "close inputs", Some(Duration::from_secs(30)))
            .and_then(|lease| {
                engine.close_dataset(&lease, handle)?;
                Ok(Reply {
                    ok: true,
                    data: json!({"closed": true, "handle": handle}),
                    elapsed_ms: started.elapsed().as_millis() as u64,
                    started_engine: false,
                })
            }),
        started,
    )
}

pub fn call(engine: &Engine, request: CallRequest) -> Reply {
    let started = Instant::now();
    finish(
        (|| {
            let mut args = request.args.clone();
            if let (Some(ms), Some(object)) = (request.deadline_ms, args.as_object_mut()) {
                object.entry("timeout_ms").or_insert(json!(ms));
            }
            let timeout = args["timeout_ms"].as_u64().or(request.deadline_ms);
            let lease = engine.lease(
                &request.call_id,
                &summary_of(&request),
                Some(engine.watchdog_for(timeout)),
            )?;
            engine.call(&lease, &request.tool, request.handle, args)
        })(),
        started,
    )
}

pub fn export(
    engine: &Engine,
    request: ExportRequest,
    progress: impl FnMut(u64, u64),
) -> Result<ExportReport, Failure> {
    // a page is one call; the watchdog is per call, the export as a whole is bounded by the user's cancel
    let lease = engine.lease(
        &request.call_id,
        "export",
        Some(engine.watchdog_for(request.deadline_ms)),
    )?;
    export_query(engine, &lease, &request, progress)
}

fn reply_of(outcome: Result<Value, Failure>, started: Instant) -> Reply {
    match outcome {
        Ok(data) => Reply {
            ok: true,
            data,
            elapsed_ms: started.elapsed().as_millis() as u64,
            started_engine: false,
        },
        Err(failure) => Reply::failed(&failure, started.elapsed()),
    }
}

/// Load both input sets completely and keep the comparison under an id.
pub fn diff_run(
    engine: &Engine,
    store: &DiffStore,
    request: DiffRequest,
    progress: impl FnMut(u64, u64),
) -> Reply {
    let started = Instant::now();
    reply_of(
        (|| {
            let lease = engine.lease(
                &request.call_id,
                "compare",
                Some(engine.watchdog_for(request.deadline_ms)),
            )?;
            let result = run_diff(engine, &lease, &request, progress)?;
            let summary = result.summary.clone();
            let sides = result.sides.clone();
            let prefix = result.prefix.clone();
            let diff_id = store.put(result);
            Ok(json!({"diff_id": diff_id, "summary": summary, "sides": sides, "prefix": prefix}))
        })(),
        started,
    )
}

pub fn diff_page(store: &DiffStore, query: PageQuery) -> Reply {
    let started = Instant::now();
    reply_of(page(store, &query), started)
}

/// The smali of one method of each side, line by line.
pub fn diff_smali(engine: &Engine, request: SmaliDiffRequest) -> Reply {
    let started = Instant::now();
    reply_of(
        (|| {
            let lease = engine.lease(
                &request.call_id,
                "compare smali",
                Some(engine.watchdog_for(request.deadline_ms)),
            )?;
            smali_diff(engine, &lease, &request)
        })(),
        started,
    )
}
