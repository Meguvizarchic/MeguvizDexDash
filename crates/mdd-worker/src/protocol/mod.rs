//! `mdd-wire/1` over a real worker child process.
//!
//! The worker side ([`serve_rows`]) answers one request on its stdout, which is
//! the dedicated channel, and obeys the consumer's credit and Cancel frames. The
//! client side ([`run_child`]) spawns the worker, negotiates, grants credit as it
//! consumes, bounds every wait with an absolute deadline, and always reaps the
//! child. Nothing here touches MCP stdout.
//!
//! Boundedness comes from three places that do not depend on each other: the
//! producer cannot write a batch without credit, the reader thread hands frames to
//! the consumer through a bounded queue, and the OS pipe between them is finite. A
//! consumer that stops reading therefore stalls the producer after a bounded
//! amount of output, and the deadline or a cancel then ends the worker.
use mdd_types::MddError;
use mdd_wire::{
    Agreed, Cell, ChannelKind, Completed, Credit, CreditGate, Failure, Frame, FrameKind,
    FrameReader, FrameWriter, Hello, ProducerStream, ResponseStream, Schema, StreamLimits,
    WireError, WireErrorKind, negotiate,
};
use serde_json::Value;
use std::io::{Read, Write};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

/// The stream id the client uses for its single request.
pub const REQUEST_STREAM: u64 = 1;

// ---------------------------------------------------------------------------
// Worker side
// ---------------------------------------------------------------------------

/// How a served request ended on the worker's side.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ServeEnd {
    /// End was written; every batch was delivered against granted credit.
    Completed { rows: u64, batches: u64 },
    /// The row source failed; an Error terminal was written.
    SourceFailed,
    /// The consumer cancelled or vanished before End.
    Stopped(WireErrorKind),
}

/// What a worker serves and how it paces itself.
pub struct ServeConfig {
    pub hello: Hello,
    pub schema: Schema,
    pub limits: StreamLimits,
    /// Most rows in one batch.
    pub batch_rows: usize,
    /// How long the producer waits for credit before it gives up.
    pub credit_wait: Duration,
}

/// Serve one request: write Hello, read the peer's Hello and the Request, then
/// stream `rows` in batches of at most `batch_rows`, each against credit.
///
/// `rows` yields the next row or the failure that ends the stream; a failure after
/// rows were sent is reported with an Error frame, never by just stopping.
/// `on_sent` is called with the number of batches written so far.
pub fn serve_rows<R, W>(
    input: R,
    output: W,
    config: ServeConfig,
    mut rows: impl FnMut() -> Option<Result<Vec<Cell>, MddError>>,
    mut on_sent: impl FnMut(u64),
) -> Result<ServeEnd, WireError>
where
    R: Read + Send + 'static,
    W: Write,
{
    let ServeConfig {
        hello,
        schema,
        limits,
        batch_rows,
        credit_wait,
    } = config;
    let mut writer = FrameWriter::new(output, ChannelKind::Dedicated, hello.max_frame_bytes)?;
    writer.write_frame(
        FrameKind::Hello,
        0,
        &serde_json::to_vec(&hello.to_json()).unwrap_or_default(),
    )?;
    let mut reader = FrameReader::new(input);
    let peer_hello = expect_frame(&mut reader, hello.max_frame_bytes, FrameKind::Hello)?;
    let agreed = negotiate(&hello, &Hello::from_json(&peer_hello.json()?)?)?;
    let request = expect_frame(&mut reader, agreed.max_frame_bytes, FrameKind::Request)?;
    let stream_id = request.header.stream_id;
    let limits = StreamLimits {
        max_body_bytes: agreed.max_frame_bytes.min(limits.max_body_bytes),
        ..limits
    };
    let mut producer = ProducerStream::new(stream_id, limits)?;

    // The control thread owns the input from here on: it turns Credit frames into
    // credit and Cancel, EOF or garbage into a stop signal.
    let gate = Arc::new(CreditGate::new());
    let stop = Arc::new(AtomicBool::new(false));
    let control = {
        let (gate, stop) = (Arc::clone(&gate), Arc::clone(&stop));
        let max = agreed.max_frame_bytes;
        thread::spawn(move || {
            loop {
                match reader.read_frame(max) {
                    Ok(Some(frame)) if frame.header.stream_id == stream_id => {
                        match frame.header.kind {
                            FrameKind::Credit => match mdd_wire::stream::parse_credit(&frame)
                                .and_then(|c| gate.grant(c))
                            {
                                Ok(()) => {}
                                Err(_) => break,
                            },
                            FrameKind::Cancel => break,
                            _ => break,
                        }
                    }
                    // EOF, a protocol fault or another stream: nothing more will
                    // arrive that this request can use.
                    _ => break,
                }
            }
            stop.store(true, Ordering::SeqCst);
            gate.wake();
        })
    };

    let send =
        |writer: &mut FrameWriter<W>, kind, body: &[u8]| writer.write_frame(kind, stream_id, body);
    send(&mut writer, FrameKind::Schema, &producer.schema(schema)?)?;
    let mut sent = 0u64;
    let outcome = loop {
        let mut batch = Vec::new();
        let mut failure = None;
        while batch.len() < batch_rows {
            match rows() {
                Some(Ok(row)) => batch.push(row),
                Some(Err(error)) => {
                    failure = Some(error);
                    break;
                }
                None => break,
            }
        }
        if !batch.is_empty() {
            let body = producer.batch(&batch)?;
            if let Err(error) = gate.reserve(body.len() as u64, credit_wait, &stop) {
                break Ok(ServeEnd::Stopped(error.kind));
            }
            send(&mut writer, FrameKind::Batch, &body)?;
            sent += 1;
            on_sent(sent);
        }
        if let Some(error) = failure {
            send(&mut writer, FrameKind::Error, &producer.error(&error)?)?;
            break Ok(ServeEnd::SourceFailed);
        }
        if batch.len() < batch_rows {
            let body = producer.end()?;
            send(&mut writer, FrameKind::End, &body)?;
            // Counts are in the End body; recompute for the caller from the body.
            let end: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
            let count = |key: &str| {
                end.get(key)
                    .and_then(Value::as_str)
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0)
            };
            break Ok(ServeEnd::Completed {
                rows: count("rows"),
                batches: count("batches"),
            });
        }
    };
    // Dropping the writer's sink closes our stdout; the control thread ends when
    // the consumer closes our stdin or sends Cancel. Do not wait on it forever.
    stop.store(true, Ordering::SeqCst);
    drop(control);
    outcome
}

fn expect_frame<R: Read>(
    reader: &mut FrameReader<R>,
    max: u64,
    kind: FrameKind,
) -> Result<Frame, WireError> {
    match reader.read_frame(max)? {
        Some(frame) if frame.header.kind == kind => Ok(frame),
        Some(frame) => Err(WireError::new(
            WireErrorKind::UnexpectedFrame,
            format!(
                "expected {} but received {}",
                kind.name(),
                frame.header.kind.name()
            ),
        )),
        None => Err(WireError::new(
            WireErrorKind::Disconnected,
            format!("input ended before the {} frame", kind.name()),
        )),
    }
}

// ---------------------------------------------------------------------------
// Client side
// ---------------------------------------------------------------------------

/// Called with the number of batches consumed so far.
pub type BatchHook = Box<dyn Fn(u64, &ClientProbe) + Send>;

pub struct ClientConfig {
    pub hello: Hello,
    pub limits: StreamLimits,
    /// Frames the bounded queue holds ahead of the consumer. The reader thread
    /// can hold one more while it waits for room, so at most `queue_frames + 1`
    /// frames are ever read ahead.
    pub queue_frames: usize,
    /// Credit granted up front and re-granted batch by batch as batches are consumed.
    pub initial_credit: Credit,
    /// Absolute bound on the whole exchange.
    pub deadline: Duration,
    /// How long a finished worker may take to exit before it is killed.
    pub exit_grace: Duration,
    /// Set from another thread to cancel the exchange.
    pub cancel: Arc<AtomicBool>,
    /// Called with the number of batches consumed so far, before the matching
    /// credit is re-granted. A slow or stopped consumer is modelled here.
    pub on_batch: Option<BatchHook>,
}

/// A window onto the worker's stderr for the `on_batch` hook.
pub struct ClientProbe {
    stderr: Arc<Mutex<String>>,
    queued: Arc<AtomicUsize>,
}

impl ClientProbe {
    pub fn child_stderr(&self) -> String {
        self.stderr
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub fn queued_frames(&self) -> usize {
        self.queued.load(Ordering::SeqCst)
    }
}

#[derive(Debug)]
pub struct ClientOutcome {
    pub result: Result<Completed, Failure>,
    pub agreed: Option<Agreed>,
    /// `None` only when the child could not be waited for.
    pub exit: Option<ExitStatus>,
    /// Whether the client had to kill the child (cancel, deadline, protocol fault
    /// or a child that outstayed its grace).
    pub killed: bool,
    /// Most frames read ahead of the consumer at once; at most `queue_frames + 1`.
    pub peak_queued_frames: usize,
    pub stderr: String,
}

enum Item {
    Frame(Frame),
    End,
    Fault(WireError),
}

fn fail(error: WireError, rows_received: u64) -> Failure {
    Failure {
        error,
        peer: None,
        rows_received,
    }
}

/// Run `command` as a worker and collect one verified result.
pub fn run_child(mut command: Command, request_body: &[u8], config: ClientConfig) -> ClientOutcome {
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            return ClientOutcome {
                result: Err(fail(
                    WireError::new(
                        WireErrorKind::Io,
                        format!("cannot start the worker: {error}"),
                    ),
                    0,
                )),
                agreed: None,
                exit: None,
                killed: false,
                peak_queued_frames: 0,
                stderr: String::new(),
            };
        }
    };
    let started = Instant::now();
    let stderr_text = Arc::new(Mutex::new(String::new()));
    let queued = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let stderr_thread = child.stderr.take().map(|mut pipe| {
        let text = Arc::clone(&stderr_text);
        thread::spawn(move || {
            let mut chunk = [0u8; 4096];
            while let Ok(count) = pipe.read(&mut chunk) {
                if count == 0 {
                    break;
                }
                let mut text = text.lock().unwrap_or_else(PoisonError::into_inner);
                if text.len() < 64 * 1024 {
                    text.push_str(&String::from_utf8_lossy(&chunk[..count]));
                }
            }
        })
    });
    let max_frame = config.hello.max_frame_bytes;
    let (sender, receiver) = mpsc::sync_channel::<Item>(config.queue_frames.max(1));
    let reader_thread = child.stdout.take().map(|stdout| {
        let (queued, peak) = (Arc::clone(&queued), Arc::clone(&peak));
        thread::spawn(move || {
            let mut reader = FrameReader::new(stdout);
            loop {
                let item = match reader.read_frame(max_frame) {
                    Ok(Some(frame)) => Item::Frame(frame),
                    Ok(None) => Item::End,
                    Err(error) => Item::Fault(error),
                };
                let last = !matches!(item, Item::Frame(_));
                // Counted before the send so the consumer's decrement can never
                // run first: the count includes the one frame this thread holds
                // while the queue is full.
                let now = queued.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                if sender.send(item).is_err() {
                    queued.fetch_sub(1, Ordering::SeqCst);
                    return;
                }
                if last {
                    return;
                }
            }
        })
    });
    let mut stdin = child.stdin.take();
    let probe = ClientProbe {
        stderr: Arc::clone(&stderr_text),
        queued: Arc::clone(&queued),
    };

    let mut killed = false;
    let mut agreed = None;
    let result = (|| -> Result<Completed, Failure> {
        let deadline = started + config.deadline;
        let next = |wait_for: &str| -> Result<Item, Failure> {
            loop {
                if config.cancel.load(Ordering::SeqCst) {
                    return Err(fail(
                        WireError::new(WireErrorKind::Cancelled, "cancelled by the caller"),
                        0,
                    ));
                }
                let now = Instant::now();
                if now >= deadline {
                    return Err(fail(
                        WireError::new(
                            WireErrorKind::DeadlineExceeded,
                            format!("deadline reached while waiting for {wait_for}"),
                        ),
                        0,
                    ));
                }
                match receiver.recv_timeout((deadline - now).min(Duration::from_millis(10))) {
                    Ok(item) => {
                        queued.fetch_sub(1, Ordering::SeqCst);
                        return Ok(item);
                    }
                    Err(RecvTimeoutError::Timeout) => continue,
                    Err(RecvTimeoutError::Disconnected) => {
                        return Err(fail(
                            WireError::new(WireErrorKind::Disconnected, "the reader ended"),
                            0,
                        ));
                    }
                }
            }
        };
        let write = |stdin: &mut Option<std::process::ChildStdin>,
                     kind,
                     stream,
                     body: &[u8]|
         -> Result<(), Failure> {
            let sink = stdin.as_mut().ok_or_else(|| {
                fail(
                    WireError::new(WireErrorKind::Io, "worker stdin is closed"),
                    0,
                )
            })?;
            FrameWriter::new(sink, ChannelKind::Dedicated, max_frame)
                .and_then(|mut w| w.write_frame(kind, stream, body))
                .map_err(|e| fail(e, 0))
        };

        // Negotiate.
        let hello = match next("the worker's Hello")? {
            Item::Frame(frame)
                if frame.header.kind == FrameKind::Hello && frame.header.stream_id == 0 =>
            {
                frame
            }
            Item::Frame(frame) => {
                return Err(fail(
                    WireError::new(
                        WireErrorKind::UnexpectedFrame,
                        format!("a {} frame before Hello", frame.header.kind.name()),
                    ),
                    0,
                ));
            }
            Item::End => {
                return Err(fail(
                    WireError::new(
                        WireErrorKind::Disconnected,
                        "the worker exited before Hello",
                    ),
                    0,
                ));
            }
            Item::Fault(error) => return Err(fail(error, 0)),
        };
        let peer =
            Hello::from_json(&hello.json().map_err(|e| fail(e, 0))?).map_err(|e| fail(e, 0))?;
        let negotiated = negotiate(&config.hello, &peer).map_err(|e| fail(e, 0))?;
        agreed = Some(negotiated.clone());
        write(
            &mut stdin,
            FrameKind::Hello,
            0,
            &serde_json::to_vec(&config.hello.to_json()).unwrap_or_default(),
        )?;
        write(&mut stdin, FrameKind::Request, REQUEST_STREAM, request_body)?;

        let limits = StreamLimits {
            max_body_bytes: negotiated.max_frame_bytes.min(config.limits.max_body_bytes),
            enforce_credit: true,
            ..config.limits
        };
        let mut stream = ResponseStream::new(REQUEST_STREAM, limits).map_err(|e| fail(e, 0))?;
        let grant = stream
            .grant_credit(config.initial_credit)
            .map_err(|e| fail(e, 0))?;
        write(&mut stdin, FrameKind::Credit, REQUEST_STREAM, &grant)?;

        let mut consumed = 0u64;
        while !stream.is_terminated() {
            let item = next("the next frame").map_err(|f| Failure {
                rows_received: stream.rows_received(),
                ..f
            })?;
            match item {
                Item::Frame(frame) => {
                    let is_batch = frame.header.kind == FrameKind::Batch;
                    let body_bytes = frame.header.body_bytes;
                    stream
                        .accept(&frame)
                        .map_err(|e| fail(e, stream.rows_received()))?;
                    if is_batch {
                        consumed += 1;
                        if let Some(hook) = &config.on_batch {
                            hook(consumed, &probe);
                        }
                        // Re-grant exactly what this batch used; a worker that has
                        // stopped reading its stdin simply never gets here.
                        let refill = stream
                            .grant_credit(Credit {
                                bytes: body_bytes,
                                batches: 1,
                            })
                            .map_err(|e| fail(e, stream.rows_received()))?;
                        // No new credit once the exchange is over time or cancelled:
                        // the worker must not be handed room to write more.
                        let over =
                            config.cancel.load(Ordering::SeqCst) || Instant::now() >= deadline;
                        if !stream.is_terminated() && !over {
                            // A closed pipe means the worker is gone; the next
                            // read reports it as a disconnect.
                            let _ = write(&mut stdin, FrameKind::Credit, REQUEST_STREAM, &refill);
                        }
                    }
                }
                Item::End => break,
                Item::Fault(error) => return Err(fail(error, stream.rows_received())),
            }
        }
        // The terminal has arrived. Whatever else the worker still sends is read
        // within its exit grace: a second terminal, a stray batch or trailing junk
        // makes the stream fail instead of being silently ignored.
        if stream.finish_ready() {
            let drain_until = Instant::now() + config.exit_grace;
            while let Ok(item) =
                receiver.recv_timeout(drain_until.saturating_duration_since(Instant::now()))
            {
                queued.fetch_sub(1, Ordering::SeqCst);
                match item {
                    Item::Frame(frame) => {
                        if let Err(error) = stream.accept(&frame) {
                            return Err(fail(error, stream.rows_received()));
                        }
                    }
                    Item::End => break,
                    Item::Fault(error) => return Err(fail(error, stream.rows_received())),
                }
            }
        }
        stream.finish()
    })();

    // Reap, whatever happened. A worker still running after a failure or beyond
    // its grace period is killed; its pipes then close and both threads end.
    drop(stdin.take());
    let exit = reap(&mut child, result.is_ok(), config.exit_grace, &mut killed);
    drop(receiver);
    let reader_panicked = reader_thread.is_some_and(|thread| thread.join().is_err());
    if let Some(thread) = stderr_thread {
        let _ = thread.join();
    }
    // A panic in the reader would otherwise look like a quiet disconnect.
    let result = if reader_panicked {
        Err(fail(
            WireError::new(WireErrorKind::Io, "the reader thread panicked"),
            result.as_ref().map_or_else(
                |failure| failure.rows_received,
                |done| done.rows.len() as u64,
            ),
        ))
    } else {
        result
    };
    let stderr = stderr_text
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    ClientOutcome {
        result,
        agreed,
        exit,
        killed,
        peak_queued_frames: peak.load(Ordering::SeqCst),
        stderr,
    }
}

fn reap(
    child: &mut Child,
    succeeded: bool,
    grace: Duration,
    killed: &mut bool,
) -> Option<ExitStatus> {
    let until = Instant::now() + if succeeded { grace } else { Duration::ZERO };
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) if Instant::now() < until => thread::sleep(Duration::from_millis(5)),
            Ok(None) => {
                *killed = true;
                let _ = child.kill();
                return child.wait().ok();
            }
            Err(_) => return None,
        }
    }
}

/// The engine error for a client failure: a peer-reported error keeps its own code.
pub fn failure_to_mdd(failure: &Failure) -> MddError {
    match &failure.peer {
        Some(peer) => peer.to_mdd(),
        None => failure.error.to_mdd(),
    }
}
