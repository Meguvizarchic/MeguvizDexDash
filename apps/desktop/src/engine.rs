//! The worker supervisor.
//!
//! The workbench holds no parser and no query engine. It starts one `meguvizdexdash mcp` child
//! process and speaks the same newline-delimited JSON-RPC that HostLab speaks to it, so what the
//! window can do is exactly what the engine's `tools/list` says it can do.
//!
//! The engine answers one request at a time and closes a dataset whose query outlives its deadline.
//! Cancelling therefore means ending the process: the datasets the user opened are remembered by
//! their input paths and are opened again, lazily, the next time a call needs them. A dataset's
//! engine-side id changes with every open, so the window only ever sees the shell's own handle.
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

const PROTOCOL_VERSION: &str = "2025-06-18";
/// How long the shell waits after the engine's own deadline before it ends the process.
const WATCHDOG_GRACE: Duration = Duration::from_secs(10);
const POLL: Duration = Duration::from_millis(20);
const STDERR_LINES: usize = 40;
/// Dialects the MCP server serves; the native dialect has no MCP surface.
pub const DIALECTS: [&str; 2] = ["dexsql-0.1.0", "dexsql-0.1.1"];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Settings {
    pub dialect: String,
    /// The engine's own deadline for an operation that does not ask for a shorter one.
    pub timeout_ms: u64,
    pub sql_max_steps: Option<u64>,
    pub sql_max_scanned_rows: Option<u64>,
    pub sql_max_result_rows: Option<u64>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            dialect: DIALECTS[0].to_owned(),
            timeout_ms: 300_000,
            sql_max_steps: None,
            sql_max_scanned_rows: None,
            sql_max_result_rows: None,
        }
    }
}

impl Settings {
    pub fn check(&self) -> Result<(), Failure> {
        if !DIALECTS.contains(&self.dialect.as_str()) {
            return Err(Failure::invalid(format!(
                "dialect {:?} is not one of {DIALECTS:?}",
                self.dialect
            )));
        }
        let positive = |name: &str, value: u64| {
            if value == 0 {
                Err(Failure::invalid(format!("{name} must be at least 1")))
            } else {
                Ok(())
            }
        };
        positive("timeout_ms", self.timeout_ms)?;
        for (name, value) in [
            ("sql_max_steps", self.sql_max_steps),
            ("sql_max_scanned_rows", self.sql_max_scanned_rows),
            ("sql_max_result_rows", self.sql_max_result_rows),
        ] {
            if let Some(value) = value {
                positive(name, value)?;
            }
        }
        Ok(())
    }

    fn arguments(&self) -> Vec<String> {
        let mut out = vec![
            "mcp".to_owned(),
            "--dialect".to_owned(),
            self.dialect.clone(),
            "--timeout-ms".to_owned(),
            self.timeout_ms.to_string(),
        ];
        for (flag, value) in [
            ("--sql-max-steps", self.sql_max_steps),
            ("--sql-max-scanned-rows", self.sql_max_scanned_rows),
            ("--sql-max-result-rows", self.sql_max_result_rows),
        ] {
            if let Some(value) = value {
                out.push(flag.to_owned());
                out.push(value.to_string());
            }
        }
        out
    }
}

/// Why a call did not produce an engine answer, or what the engine answered in its place.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Failure {
    pub code: String,
    pub message: String,
    /// The engine's own error object, when the engine produced one.
    pub engine: Option<Value>,
}

impl Failure {
    pub fn new(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.to_owned(),
            message: message.into(),
            engine: None,
        }
    }

    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new("INVALID_ARGUMENT", message)
    }

    /// The error object the window renders. An engine error keeps its own fields.
    pub fn to_value(&self) -> Value {
        match &self.engine {
            Some(error) => error.clone(),
            None => json!({"code": self.code, "message": self.message, "origin": "shell"}),
        }
    }
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

/// What a call hands back to the window.
#[derive(Clone, Debug, Serialize)]
pub struct Reply {
    pub ok: bool,
    /// The engine's structured content, or `{"error": …}`.
    pub data: Value,
    pub elapsed_ms: u64,
    /// The engine process had to be started (again) for this call.
    pub started_engine: bool,
}

impl Reply {
    pub fn failed(failure: &Failure, elapsed: Duration) -> Self {
        Self {
            ok: false,
            data: json!({"error": failure.to_value()}),
            elapsed_ms: elapsed.as_millis() as u64,
            started_engine: false,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct DatasetInfo {
    pub handle: u64,
    pub inputs: Vec<String>,
    /// The open_dataset answer: snapshot, sources, DEX count, diagnostics.
    pub summary: Value,
    /// The engine currently holds this dataset open.
    pub live: bool,
}

struct Dataset {
    handle: u64,
    inputs: Vec<String>,
    engine_id: Option<String>,
    summary: Value,
}

#[derive(Clone, Debug, Serialize)]
pub struct Busy {
    pub call_id: String,
    pub what: String,
    pub since_ms: u64,
}

struct BusySlot {
    call_id: String,
    what: String,
    since: Instant,
    cancel: Arc<AtomicBool>,
}

struct Session {
    child: Child,
    stdin: ChildStdin,
    lines: Receiver<std::io::Result<String>>,
    stderr: Arc<Mutex<VecDeque<String>>>,
    next_id: u64,
    tools: Vec<String>,
    server_info: Value,
}

impl Session {
    fn end(mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    fn stderr_tail(&self) -> String {
        // the reader thread may still be draining the pipe of a process that just died
        thread::sleep(Duration::from_millis(30));
        let lines = self.stderr.lock().map(|l| l.clone()).unwrap_or_default();
        lines.into_iter().collect::<Vec<_>>().join("\n")
    }
}

/// One call's control: the user's cancel flag and the shell's own hard deadline.
pub struct Control {
    cancel: Arc<AtomicBool>,
    /// How long one request may go unanswered before the shell ends the process.
    watchdog: Option<Duration>,
}

impl Control {
    fn with_watchdog(&self, watchdog: Duration) -> Self {
        Self {
            cancel: self.cancel.clone(),
            watchdog: Some(watchdog),
        }
    }
}

pub struct Engine {
    binary: PathBuf,
    settings: Mutex<Settings>,
    /// Held for the whole of every request, so nothing the window polls may wait on it: what the window
    /// reads while a query runs (is the engine up, which tools it lists) lives in `view` instead.
    session: Mutex<Option<Session>>,
    view: Mutex<SessionView>,
    datasets: Mutex<Vec<Dataset>>,
    next_handle: Mutex<u64>,
    busy: Mutex<Option<BusySlot>>,
}

#[derive(Default)]
struct SessionView {
    running: bool,
    tools: Vec<String>,
    server_info: Value,
}

/// Holds the engine's single in-flight slot; dropping it frees the slot.
pub struct Lease<'a> {
    engine: &'a Engine,
    control: Control,
    call_id: String,
}

impl Lease<'_> {
    pub fn control(&self) -> &Control {
        &self.control
    }

    pub fn is_cancelled(&self) -> bool {
        self.control.cancel.load(Ordering::SeqCst)
    }
}

impl Drop for Lease<'_> {
    fn drop(&mut self) {
        let mut slot = lock(&self.engine.busy);
        if slot.as_ref().is_some_and(|s| s.call_id == self.call_id) {
            *slot = None;
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Where the engine binary is: `MDD_ENGINE`, then next to the workbench, then the build tree.
pub fn locate_binary() -> PathBuf {
    let name = if cfg!(windows) {
        "meguvizdexdash.exe"
    } else {
        "meguvizdexdash"
    };
    if let Some(explicit) = std::env::var_os("MDD_ENGINE") {
        return PathBuf::from(explicit);
    }
    let mut tried = Vec::new();
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        tried.push(dir.join(name));
        // `cargo run` / `cargo test` put the workbench in apps/desktop/target/<profile>[/deps]
        for up in 1..=5 {
            if let Some(root) = dir.ancestors().nth(up) {
                tried.push(root.join("target").join("debug").join(name));
                tried.push(root.join("target").join("release").join(name));
            }
        }
    }
    tried
        .iter()
        .find(|path| path.is_file())
        .cloned()
        .unwrap_or_else(|| {
            tried
                .into_iter()
                .next()
                .unwrap_or_else(|| PathBuf::from(name))
        })
}

impl Engine {
    pub fn new(binary: PathBuf, settings: Settings) -> Self {
        Self {
            binary,
            settings: Mutex::new(settings),
            session: Mutex::new(None),
            view: Mutex::new(SessionView::default()),
            datasets: Mutex::new(Vec::new()),
            next_handle: Mutex::new(1),
            busy: Mutex::new(None),
        }
    }

    pub fn binary(&self) -> &Path {
        &self.binary
    }

    pub fn settings(&self) -> Settings {
        lock(&self.settings).clone()
    }

    /// Take the single in-flight slot, or say what holds it.
    pub fn lease(
        &self,
        call_id: &str,
        what: &str,
        hard_deadline: Option<Duration>,
    ) -> Result<Lease<'_>, Failure> {
        let mut slot = lock(&self.busy);
        if let Some(running) = slot.as_ref() {
            return Err(Failure {
                code: "ENGINE_BUSY".to_owned(),
                message: format!(
                    "the engine is serving {:?} ({}), started {} ms ago; it answers one request at a time",
                    running.what,
                    running.call_id,
                    running.since.elapsed().as_millis()
                ),
                engine: None,
            });
        }
        let cancel = Arc::new(AtomicBool::new(false));
        *slot = Some(BusySlot {
            call_id: call_id.to_owned(),
            what: what.to_owned(),
            since: Instant::now(),
            cancel: cancel.clone(),
        });
        Ok(Lease {
            engine: self,
            control: Control {
                cancel,
                watchdog: hard_deadline,
            },
            call_id: call_id.to_owned(),
        })
    }

    pub fn busy(&self) -> Option<Busy> {
        lock(&self.busy).as_ref().map(|s| Busy {
            call_id: s.call_id.clone(),
            what: s.what.clone(),
            since_ms: s.since.elapsed().as_millis() as u64,
        })
    }

    /// Ask the running call to stop. The call ends the engine process; false if nothing matches.
    pub fn cancel(&self, call_id: &str) -> bool {
        match lock(&self.busy).as_ref() {
            Some(slot) if slot.call_id == call_id => {
                slot.cancel.store(true, Ordering::SeqCst);
                true
            }
            _ => false,
        }
    }

    pub fn datasets(&self) -> Vec<DatasetInfo> {
        lock(&self.datasets)
            .iter()
            .map(|d| DatasetInfo {
                handle: d.handle,
                inputs: d.inputs.clone(),
                summary: d.summary.clone(),
                live: d.engine_id.is_some(),
            })
            .collect()
    }

    pub fn running(&self) -> bool {
        lock(&self.view).running
    }

    pub fn tools(&self) -> Vec<String> {
        lock(&self.view).tools.clone()
    }

    pub fn server_info(&self) -> Value {
        lock(&self.view).server_info.clone()
    }

    fn publish(&self, session: &Session) {
        *lock(&self.view) = SessionView {
            running: true,
            tools: session.tools.clone(),
            server_info: session.server_info.clone(),
        };
    }

    fn unpublish(&self) {
        *lock(&self.view) = SessionView::default();
    }

    /// Change the engine's dialect and budgets. The process is ended; datasets open again on use.
    pub fn configure(&self, settings: Settings) -> Result<(), Failure> {
        settings.check()?;
        *lock(&self.settings) = settings;
        self.end_session();
        Ok(())
    }

    fn end_session(&self) {
        // a request in flight holds the session: ask it to stop (it ends the process itself), then take over
        if let Some(slot) = lock(&self.busy).as_ref() {
            slot.cancel.store(true, Ordering::SeqCst);
        }
        if let Some(session) = lock(&self.session).take() {
            session.end();
        }
        self.unpublish();
        for dataset in lock(&self.datasets).iter_mut() {
            dataset.engine_id = None;
        }
    }

    /// End the engine process (a user-visible "stop").
    pub fn stop(&self) {
        self.end_session();
    }

    fn spawn(&self) -> Result<Session, Failure> {
        let settings = self.settings();
        let mut child = Command::new(&self.binary)
            .args(settings.arguments())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| {
                Failure::new(
                    "ENGINE_NOT_FOUND",
                    format!(
                        "cannot start the engine {}: {error}. Set MDD_ENGINE or put meguvizdexdash next to the workbench.",
                        self.binary.display()
                    ),
                )
            })?;
        let stdin = child.stdin.take().expect("piped");
        let stdout = child.stdout.take().expect("piped");
        let stderr = child.stderr.take().expect("piped");
        let (sender, lines) = mpsc::channel();
        thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            loop {
                let mut line = String::new();
                match reader.read_line(&mut line) {
                    Ok(0) => break,
                    Ok(_) => {
                        if sender.send(Ok(line)).is_err() {
                            break;
                        }
                    }
                    Err(error) => {
                        let _ = sender.send(Err(error));
                        break;
                    }
                }
            }
        });
        let tail = Arc::new(Mutex::new(VecDeque::new()));
        let tail_writer = tail.clone();
        thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                let mut lines = lock(&tail_writer);
                if lines.len() == STDERR_LINES {
                    lines.pop_front();
                }
                lines.push_back(line);
            }
        });
        Ok(Session {
            child,
            stdin,
            lines,
            stderr: tail,
            next_id: 0,
            tools: Vec::new(),
            server_info: Value::Null,
        })
    }

    /// The running session, started and initialized when there is none. Returns whether it started.
    fn ensure(
        &self,
        guard: &mut MutexGuard<'_, Option<Session>>,
        control: &Control,
    ) -> Result<bool, Failure> {
        if guard.is_some() {
            return Ok(false);
        }
        let mut session = self.spawn()?;
        let control = &control.with_watchdog(Duration::from_secs(30));
        let setup = (|| {
            let init = request(
                &mut session,
                "initialize",
                json!({"protocolVersion": PROTOCOL_VERSION, "capabilities": {},
                       "clientInfo": {"name": "mdd-desktop", "version": env!("CARGO_PKG_VERSION")}}),
                control,
            )?;
            send(
                &mut session,
                &json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            )?;
            let listed = request(&mut session, "tools/list", json!({}), control)?;
            let tools = listed["tools"]
                .as_array()
                .map(|all| {
                    all.iter()
                        .filter_map(|t| t["name"].as_str().map(str::to_owned))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            session.tools = tools;
            session.server_info = json!({
                "serverInfo": init["serverInfo"],
                "protocolVersion": init["protocolVersion"],
                "instructions": init["instructions"],
            });
            Ok::<(), Failure>(())
        })();
        match setup {
            Ok(()) => {
                self.publish(&session);
                **guard = Some(session);
                Ok(true)
            }
            Err(failure) => {
                session.end();
                Err(failure)
            }
        }
    }

    /// Make sure the engine runs and (when `handle` is given) holds that dataset; returns the
    /// engine-side id and whether the process was started. The lease proves the caller owns the slot.
    pub fn prepare(
        &self,
        lease: &Lease<'_>,
        handle: Option<u64>,
    ) -> Result<(Option<String>, bool), Failure> {
        let mut guard = lock(&self.session);
        let started = self.ensure(&mut guard, lease.control())?;
        let Some(handle) = handle else {
            return Ok((None, started));
        };
        let (inputs, known) = {
            let datasets = lock(&self.datasets);
            let dataset = datasets
                .iter()
                .find(|d| d.handle == handle)
                .ok_or_else(|| {
                    Failure::new("UNKNOWN_HANDLE", format!("no open input set {handle}"))
                })?;
            (dataset.inputs.clone(), dataset.engine_id.clone())
        };
        if let Some(id) = known {
            return Ok((Some(id), started));
        }
        let session = guard.as_mut().expect("ensured");
        let reopen = lease.control().with_watchdog(self.watchdog_for(None));
        let opened = tool(session, "open_dataset", json!({"inputs": inputs}), &reopen);
        let (data, is_error) = self.after_call(&mut guard, opened)?;
        if is_error {
            return Err(engine_failure(&data));
        }
        let id = data["dataset_id"].as_str().unwrap_or_default().to_owned();
        if let Some(dataset) = lock(&self.datasets).iter_mut().find(|d| d.handle == handle) {
            dataset.engine_id = Some(id.clone());
        }
        Ok((Some(id), true))
    }

    /// Settle a finished transport call: a failure that ended the conversation drops the session.
    fn after_call(
        &self,
        guard: &mut MutexGuard<'_, Option<Session>>,
        outcome: Result<(Value, bool), Failure>,
    ) -> Result<(Value, bool), Failure> {
        match outcome {
            Ok(done) => Ok(done),
            Err(failure) => {
                if matches!(
                    failure.code.as_str(),
                    "CANCELLED" | "DEADLINE_EXCEEDED" | "ENGINE_LOST" | "ENGINE_PROTOCOL"
                ) && let Some(session) = guard.take()
                {
                    session.end();
                    self.unpublish();
                    for dataset in lock(&self.datasets).iter_mut() {
                        dataset.engine_id = None;
                    }
                }
                Err(failure)
            }
        }
    }

    /// Call one tool of the engine. `args` must not carry `dataset_id`; the shell adds it for `handle`.
    pub fn call(
        &self,
        lease: &Lease<'_>,
        tool_name: &str,
        handle: Option<u64>,
        mut args: Value,
    ) -> Result<Reply, Failure> {
        let started_at = Instant::now();
        let (dataset_id, mut started) = self.prepare(lease, handle)?;
        let mut guard = lock(&self.session);
        let session = guard
            .as_mut()
            .ok_or_else(|| Failure::new("ENGINE_LOST", "the engine is not running"))?;
        if !session.tools.iter().any(|t| t == tool_name) {
            return Err(Failure::new(
                "UNKNOWN_TOOL",
                format!(
                    "the engine does not list a tool named {tool_name:?}; it lists {:?}",
                    session.tools
                ),
            ));
        }
        let object = args
            .as_object_mut()
            .ok_or_else(|| Failure::invalid("arguments must be a JSON object"))?;
        if object.contains_key("dataset_id") {
            return Err(Failure::invalid(
                "dataset_id is the shell's to set; pass a handle",
            ));
        }
        if let Some(id) = dataset_id {
            object.insert("dataset_id".to_owned(), Value::String(id));
        }
        let outcome = tool(session, tool_name, args, lease.control());
        let (data, is_error) = self.after_call(&mut guard, outcome)?;
        if is_error {
            let code = data["error"]["code"].as_str().unwrap_or_default();
            if matches!(code, "DEADLINE_EXCEEDED" | "SNAPSHOT_CLOSED" | "NOT_FOUND") {
                self.resync(&mut guard, lease.control());
            }
        }
        started |= false;
        Ok(Reply {
            ok: !is_error,
            data,
            elapsed_ms: started_at.elapsed().as_millis() as u64,
            started_engine: started,
        })
    }

    /// The engine closes a dataset whose query outlived its deadline: forget the ones it no longer lists.
    fn resync(&self, guard: &mut MutexGuard<'_, Option<Session>>, control: &Control) {
        let Some(session) = guard.as_mut() else {
            return;
        };
        let Ok((data, false)) = tool(session, "list_datasets", json!({}), control) else {
            return;
        };
        let live: Vec<String> = data["datasets"]
            .as_array()
            .map(|all| {
                all.iter()
                    .filter_map(|d| d["dataset_id"].as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        for dataset in lock(&self.datasets).iter_mut() {
            if dataset
                .engine_id
                .as_ref()
                .is_some_and(|id| !live.contains(id))
            {
                dataset.engine_id = None;
            }
        }
    }

    /// Open inputs as a new dataset and remember them under a handle.
    pub fn open_inputs(&self, lease: &Lease<'_>, inputs: Vec<String>) -> Result<Reply, Failure> {
        let started_at = Instant::now();
        if inputs.is_empty() {
            return Err(Failure::invalid("give at least one input"));
        }
        for input in &inputs {
            let meta = std::fs::metadata(input)
                .map_err(|error| Failure::new("INPUT_NOT_FOUND", format!("{input}: {error}")))?;
            if !meta.is_file() {
                return Err(Failure::new(
                    "INPUT_NOT_FOUND",
                    format!("{input} is not a file"),
                ));
            }
        }
        let mut guard = lock(&self.session);
        let started = self.ensure(&mut guard, lease.control())?;
        let session = guard.as_mut().expect("ensured");
        let outcome = tool(
            session,
            "open_dataset",
            json!({"inputs": inputs}),
            lease.control(),
        );
        let (mut data, is_error) = self.after_call(&mut guard, outcome)?;
        if !is_error {
            let id = data["dataset_id"].as_str().unwrap_or_default().to_owned();
            let handle = {
                let mut next = lock(&self.next_handle);
                let handle = *next;
                *next += 1;
                handle
            };
            lock(&self.datasets).push(Dataset {
                handle,
                inputs,
                engine_id: Some(id),
                summary: data.clone(),
            });
            data["handle"] = json!(handle);
        }
        Ok(Reply {
            ok: !is_error,
            data,
            elapsed_ms: started_at.elapsed().as_millis() as u64,
            started_engine: started,
        })
    }

    /// Close a dataset: in the engine when it holds it, and in the shell's memory.
    pub fn close_dataset(&self, lease: &Lease<'_>, handle: u64) -> Result<(), Failure> {
        let engine_id = {
            let datasets = lock(&self.datasets);
            let dataset = datasets
                .iter()
                .find(|d| d.handle == handle)
                .ok_or_else(|| {
                    Failure::new("UNKNOWN_HANDLE", format!("no open input set {handle}"))
                })?;
            dataset.engine_id.clone()
        };
        if let Some(id) = engine_id {
            let mut guard = lock(&self.session);
            if let Some(session) = guard.as_mut() {
                let outcome = tool(
                    session,
                    "close_dataset",
                    json!({"dataset_id": id}),
                    lease.control(),
                );
                // a closed-already dataset is as good as closed
                let _ = self.after_call(&mut guard, outcome);
            }
        }
        lock(&self.datasets).retain(|d| d.handle != handle);
        Ok(())
    }

    /// The hard deadline for a call asking for `timeout_ms` (or the engine default).
    pub fn watchdog_for(&self, timeout_ms: Option<u64>) -> Duration {
        let ms = timeout_ms.unwrap_or_else(|| self.settings().timeout_ms);
        Duration::from_millis(ms) + WATCHDOG_GRACE
    }
}

fn send(session: &mut Session, message: &Value) -> Result<(), Failure> {
    let mut line = message.to_string();
    line.push('\n');
    session
        .stdin
        .write_all(line.as_bytes())
        .and_then(|()| session.stdin.flush())
        .map_err(|error| {
            lost(
                session,
                &format!("the engine did not take the request: {error}"),
            )
        })
}

fn lost(session: &Session, why: &str) -> Failure {
    let tail = session.stderr_tail();
    let exit = session.child.id();
    let detail = if tail.is_empty() {
        String::new()
    } else {
        format!("\nengine stderr:\n{tail}")
    };
    Failure::new(
        "ENGINE_LOST",
        format!("{why} (engine process {exit}){detail}"),
    )
}

/// One JSON-RPC request; the `result` object, or a failure. Honours cancel and the hard deadline.
fn request(
    session: &mut Session,
    method: &str,
    params: Value,
    control: &Control,
) -> Result<Value, Failure> {
    session.next_id += 1;
    let id = session.next_id;
    send(
        session,
        &json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}),
    )?;
    let hard_deadline = control.watchdog.map(|w| Instant::now() + w);
    loop {
        match session.lines.recv_timeout(POLL) {
            Ok(Ok(line)) => {
                let message: Value = serde_json::from_str(line.trim()).map_err(|error| {
                    Failure::new(
                        "ENGINE_PROTOCOL",
                        format!("the engine wrote a line that is not JSON: {error}"),
                    )
                })?;
                if message.get("id").is_none() {
                    continue; // a notification
                }
                if message["id"] != json!(id) {
                    return Err(Failure::new(
                        "ENGINE_PROTOCOL",
                        format!(
                            "the engine answered request {} while {id} was open",
                            message["id"]
                        ),
                    ));
                }
                if let Some(error) = message.get("error") {
                    return Err(Failure {
                        code: "ENGINE_RPC_ERROR".to_owned(),
                        message: error["message"]
                            .as_str()
                            .unwrap_or("the engine refused the request")
                            .to_owned(),
                        engine: Some(json!({
                            "code": format!("RPC_{}", error["code"]),
                            "message": error["message"],
                            "origin": "engine-protocol",
                        })),
                    });
                }
                return Ok(message["result"].clone());
            }
            Ok(Err(error)) => {
                return Err(lost(
                    session,
                    &format!("reading the engine failed: {error}"),
                ));
            }
            Err(RecvTimeoutError::Timeout) => {
                if control.cancel.load(Ordering::SeqCst) {
                    return Err(Failure::new(
                        "CANCELLED",
                        "cancelled: the engine process was ended; open inputs are opened again on the next call",
                    ));
                }
                if hard_deadline.is_some_and(|d| Instant::now() >= d) {
                    return Err(Failure::new(
                        "DEADLINE_EXCEEDED",
                        "the engine did not answer within its deadline; the process was ended",
                    ));
                }
            }
            Err(RecvTimeoutError::Disconnected) => {
                return Err(lost(session, "the engine process ended without answering"));
            }
        }
    }
}

/// `tools/call`: the structured content and whether the tool reported an error.
fn tool(
    session: &mut Session,
    name: &str,
    arguments: Value,
    control: &Control,
) -> Result<(Value, bool), Failure> {
    let result = request(
        session,
        "tools/call",
        json!({"name": name, "arguments": arguments}),
        control,
    )?;
    let is_error = result["isError"].as_bool().unwrap_or(false);
    let data = match result.get("structuredContent") {
        Some(content) if !content.is_null() => content.clone(),
        _ => serde_json::from_str(result["content"][0]["text"].as_str().unwrap_or("null"))
            .unwrap_or_else(|_| json!({"error": {"code": "ENGINE_PROTOCOL", "message": "the tool result carries no structured content"}})),
    };
    Ok((data, is_error))
}

fn engine_failure(data: &Value) -> Failure {
    let error = &data["error"];
    Failure {
        code: error["code"].as_str().unwrap_or("ENGINE_ERROR").to_owned(),
        message: error["message"]
            .as_str()
            .unwrap_or("the engine reported an error")
            .to_owned(),
        engine: Some(error.clone()),
    }
}

/// Run a short engine subcommand (`version`, `capabilities`) and parse its JSON.
pub fn engine_json(binary: &Path, subcommand: &str) -> Result<Value, Failure> {
    let output = Command::new(binary)
        .arg(subcommand)
        .stdin(Stdio::null())
        .output()
        .map_err(|error| {
            Failure::new(
                "ENGINE_NOT_FOUND",
                format!("cannot run {} {subcommand}: {error}", binary.display()),
            )
        })?;
    if !output.status.success() {
        return Err(Failure::new(
            "ENGINE_ERROR",
            format!("{subcommand} exited with {}", output.status),
        ));
    }
    serde_json::from_slice(&output.stdout).map_err(|error| {
        Failure::new(
            "ENGINE_PROTOCOL",
            format!("{subcommand} did not print JSON: {error}"),
        )
    })
}
