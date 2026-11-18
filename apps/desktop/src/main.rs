// A Windows release build is a window application, not a console one.
#![cfg_attr(all(not(debug_assertions), windows), windows_subsystem = "windows")]

use mdd_desktop::api::{self, CallRequest};
use mdd_desktop::diff::{DiffRequest, DiffStore, PageQuery, SmaliDiffRequest};
use mdd_desktop::engine::{Engine, Reply, Settings, locate_binary};
use mdd_desktop::export::ExportRequest;
use serde_json::{Value, json};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tauri::{AppHandle, Emitter, Manager, State};
use tauri_plugin_dialog::DialogExt;

struct Shell {
    engine: Arc<Engine>,
    diffs: Arc<DiffStore>,
}

fn joined<T: Send + 'static>(
    work: impl FnOnce() -> T + Send + 'static,
) -> impl std::future::Future<Output = Result<T, String>> {
    let handle = tauri::async_runtime::spawn_blocking(work);
    async move { handle.await.map_err(|error| error.to_string()) }
}

#[tauri::command]
async fn engine_info(shell: State<'_, Shell>, call_id: String) -> Result<Value, String> {
    let engine = shell.engine.clone();
    joined(move || api::engine_info(&engine, &call_id)).await
}

#[tauri::command]
fn engine_state(shell: State<'_, Shell>) -> Value {
    api::engine_state(&shell.engine)
}

#[tauri::command]
async fn engine_configure(shell: State<'_, Shell>, settings: Settings) -> Result<Value, String> {
    let engine = shell.engine.clone();
    joined(move || api::configure(&engine, settings)).await
}

#[tauri::command]
async fn engine_stop(shell: State<'_, Shell>) -> Result<(), String> {
    let engine = shell.engine.clone();
    joined(move || engine.stop()).await
}

#[tauri::command]
async fn open_inputs(
    shell: State<'_, Shell>,
    call_id: String,
    paths: Vec<String>,
) -> Result<Reply, String> {
    let engine = shell.engine.clone();
    joined(move || api::open_inputs(&engine, &call_id, paths)).await
}

#[tauri::command]
async fn close_inputs(
    shell: State<'_, Shell>,
    call_id: String,
    handle: u64,
) -> Result<Reply, String> {
    let engine = shell.engine.clone();
    joined(move || api::close_inputs(&engine, &call_id, handle)).await
}

#[tauri::command]
async fn engine_call(shell: State<'_, Shell>, request: CallRequest) -> Result<Reply, String> {
    let engine = shell.engine.clone();
    joined(move || api::call(&engine, request)).await
}

#[tauri::command]
fn engine_cancel(shell: State<'_, Shell>, call_id: String) -> bool {
    shell.engine.cancel(&call_id)
}

#[tauri::command]
async fn export_query(
    app: AppHandle,
    shell: State<'_, Shell>,
    request: ExportRequest,
) -> Result<Reply, String> {
    let engine = shell.engine.clone();
    joined(move || {
        let started = Instant::now();
        let call_id = request.call_id.clone();
        let outcome = api::export(&engine, request, |done, total| {
            let _ = app.emit(
                "progress",
                json!({"call_id": call_id, "label": "export", "done": done, "total": total}),
            );
        });
        match outcome {
            Ok(report) => Reply {
                ok: true,
                data: serde_json::to_value(report).unwrap_or(Value::Null),
                elapsed_ms: started.elapsed().as_millis() as u64,
                started_engine: false,
            },
            Err(failure) => Reply::failed(&failure, started.elapsed()),
        }
    })
    .await
}

#[tauri::command]
async fn diff_run(
    app: AppHandle,
    shell: State<'_, Shell>,
    request: DiffRequest,
) -> Result<Reply, String> {
    let engine = shell.engine.clone();
    let store = shell.diffs.clone();
    joined(move || {
        let call_id = request.call_id.clone();
        api::diff_run(&engine, &store, request, |done, total| {
            let _ = app.emit(
                "progress",
                json!({"call_id": call_id, "label": "compare", "done": done, "total": total}),
            );
        })
    })
    .await
}

#[tauri::command]
fn diff_page(shell: State<'_, Shell>, query: PageQuery) -> Reply {
    api::diff_page(&shell.diffs, query)
}

#[tauri::command]
async fn diff_smali(shell: State<'_, Shell>, request: SmaliDiffRequest) -> Result<Reply, String> {
    let engine = shell.engine.clone();
    joined(move || api::diff_smali(&engine, request)).await
}

/// The native "open files" dialog. The window itself is granted no file-system access.
#[tauri::command]
async fn pick_inputs(app: AppHandle) -> Result<Vec<String>, String> {
    joined(move || {
        app.dialog()
            .file()
            .add_filter("DEX / APK / JAR / ZIP", &["apk", "dex", "jar", "zip"])
            .blocking_pick_files()
            .map(|files| {
                files
                    .into_iter()
                    .filter_map(|file| file.into_path().ok())
                    .map(|path| path.display().to_string())
                    .collect()
            })
            .unwrap_or_default()
    })
    .await
}

#[tauri::command]
async fn pick_save_path(app: AppHandle, file_name: String) -> Result<Option<String>, String> {
    joined(move || {
        app.dialog()
            .file()
            .set_file_name(file_name)
            .blocking_save_file()
            .and_then(|file| file.into_path().ok())
            .map(|path| path.display().to_string())
    })
    .await
}

/// Where an export is suggested to go: the user's Downloads folder, else the temp directory.
#[tauri::command]
fn suggest_export_dir() -> String {
    let home = std::env::var_os("USERPROFILE").or_else(|| std::env::var_os("HOME"));
    let downloads = home
        .map(|home| PathBuf::from(home).join("Downloads"))
        .filter(|p| p.is_dir());
    downloads
        .unwrap_or_else(std::env::temp_dir)
        .display()
        .to_string()
}

fn main() {
    let binary = locate_binary();
    // The engine's own SQL budgets are sized for a service; a person browsing one application
    // needs room for a scan of its largest relation. The window shows these and can reset them.
    let settings = Settings {
        sql_max_steps: Some(200_000_000),
        sql_max_scanned_rows: Some(50_000_000),
        ..Settings::default()
    };
    let engine = Arc::new(Engine::new(binary, settings));
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(Shell {
            engine: engine.clone(),
            diffs: Arc::new(DiffStore::default()),
        })
        .invoke_handler(tauri::generate_handler![
            engine_info,
            engine_state,
            engine_configure,
            engine_stop,
            open_inputs,
            close_inputs,
            engine_call,
            engine_cancel,
            export_query,
            diff_run,
            diff_page,
            diff_smali,
            pick_inputs,
            pick_save_path,
            suggest_export_dir,
        ])
        .on_window_event(|window, event| {
            // closing the window ends the engine process with it
            if matches!(event, tauri::WindowEvent::Destroyed)
                && let Some(shell) = window.app_handle().try_state::<Shell>()
            {
                shell.engine.stop();
            }
        })
        .run(tauri::generate_context!())
        .expect("the workbench window failed to start");
}
