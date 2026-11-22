//! Pinned, sandboxed subprocess wrapper for optional readable-only decompiler views.

use mdd_types::{DecimalU64, ErrorCode, MddError, MddResult};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderCapabilityStatus {
    Disabled,
    IsolatedDisplayOnly,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FactTargetKind {
    RawFingerprint,
    DeterministicCallGraph,
    HumanDisplayView,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalProviderConfig {
    pub provider_id: String,
    pub declared_version: String,
    pub binary_path: PathBuf,
    pub args: Vec<String>,
    /// Mandatory pinned SHA-256 hex digest of the executable being launched.
    pub expected_binary_sha256: String,
    pub timeout_ms: u64,
    pub max_output_bytes: usize,
    pub enabled: bool,
}

impl Default for ExternalProviderConfig {
    fn default() -> Self {
        Self {
            provider_id: "jadx-optional".to_owned(),
            declared_version: "unconfigured".to_owned(),
            binary_path: PathBuf::new(),
            args: Vec::new(),
            expected_binary_sha256: String::new(),
            timeout_ms: 5_000,
            max_output_bytes: 2 * 1024 * 1024,
            enabled: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IsolatedDecompilerView {
    pub provider_id: String,
    pub provider_version: String,
    pub provider_binary_sha256: String,
    pub source_content_id: String,
    /// Fixed provenance trust label: always `display_only_reconstructed`.
    pub trust_level: String,
    /// Fixed architectural guarantee: never `true` for raw facts or call edges.
    pub authoritative_for_facts: bool,
    pub rendered_text: String,
    pub output_bytes: DecimalU64,
}

/// Explicitly forbid any `IsolatedDecompilerView` from supplying raw byte fingerprints or
/// deterministic call graph facts. Only `FactTargetKind::HumanDisplayView` is ever permitted.
pub fn reject_as_authoritative_fact(
    view: &IsolatedDecompilerView,
    target: FactTargetKind,
) -> MddResult<()> {
    match target {
        FactTargetKind::HumanDisplayView => Ok(()),
        FactTargetKind::RawFingerprint => Err(MddError::new(
            ErrorCode::UnsupportedCapability,
            "worker.provider",
            format!(
                "provider `{}` ({}) produces display-only text and cannot populate raw_fingerprint",
                view.provider_id, view.trust_level
            ),
        )
        .detail("reason", "DISPLAY_ONLY_PROVIDER_FORBIDDEN_FOR_RAW_FINGERPRINT")),
        FactTargetKind::DeterministicCallGraph => Err(MddError::new(
            ErrorCode::UnsupportedCapability,
            "worker.provider",
            format!(
                "provider `{}` ({}) produces display-only text and cannot populate deterministic call graph",
                view.provider_id, view.trust_level
            ),
        )
        .detail("reason", "DISPLAY_ONLY_PROVIDER_FORBIDDEN_FOR_CALL_GRAPH")),
    }
}

struct ScratchCleanup(PathBuf);

impl Drop for ScratchCleanup {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn verify_pinned_binary(path: &Path, expected_hex: &str) -> MddResult<String> {
    if expected_hex.len() != 64
        || !expected_hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(MddError::new(
            ErrorCode::InvalidArgument,
            "worker.provider",
            "expected_binary_sha256 must be lowercase 64-digit hex",
        ));
    }
    let bytes = fs::read(path).map_err(|e| {
        MddError::new(
            ErrorCode::UnavailableBackend,
            "worker.provider",
            format!("provider executable not readable: {e}"),
        )
        .detail("reason", "PROVIDER_BINARY_MISSING")
    })?;
    let actual: String = Sha256::digest(&bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    if actual != expected_hex {
        return Err(MddError::new(
            ErrorCode::InvalidInput,
            "worker.provider",
            "provider binary SHA-256 differs from pinned expected_binary_sha256",
        )
        .detail("reason", "PROVIDER_BINARY_SHA256_MISMATCH")
        .detail("expected_sha256", expected_hex.to_owned())
        .detail("actual_sha256", actual));
    }
    Ok(actual)
}

fn kill_and_reap(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// Run an isolated external provider in a private scratch directory with pinned binary SHA-256,
/// sanitized environment, hard timeout, and bounded output cap.
pub fn invoke_isolated_provider(
    config: &ExternalProviderConfig,
    source_content_id: &str,
) -> MddResult<IsolatedDecompilerView> {
    if !config.enabled {
        return Err(MddError::new(
            ErrorCode::UnsupportedCapability,
            "worker.provider",
            format!(
                "optional external provider `{}` is disabled",
                config.provider_id
            ),
        )
        .detail("capability_state", "disabled"));
    }
    let actual_sha = verify_pinned_binary(&config.binary_path, &config.expected_binary_sha256)?;

    let scratch_id = mdd_types::opaque_id("mdd-prov")?;
    let scratch_dir = std::env::temp_dir().join(scratch_id);
    fs::create_dir_all(&scratch_dir)
        .map_err(|e| MddError::new(ErrorCode::InternalFault, "worker.provider", e.to_string()))?;
    let _cleanup = ScratchCleanup(scratch_dir.clone());

    let mut cmd = Command::new(&config.binary_path);
    cmd.args(&config.args)
        .current_dir(&scratch_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_clear()
        .env("NO_PROXY", "*")
        .env("HTTP_PROXY", "http://127.0.0.1:0")
        .env("HTTPS_PROXY", "http://127.0.0.1:0")
        .env("MDD_PROVIDER_ISOLATED", "1");

    // Preserve only minimal OS runtime loader variables on Windows/Unix.
    for key in [
        "SystemRoot",
        "SYSTEMROOT",
        "PATH",
        "Path",
        "TEMP",
        "TMP",
        "HOME",
    ] {
        if let Some(val) = std::env::var_os(key) {
            cmd.env(key, val);
        }
    }

    let mut child = cmd.spawn().map_err(|e| {
        MddError::new(
            ErrorCode::UnavailableBackend,
            "worker.provider",
            format!("failed spawning isolated provider: {e}"),
        )
    })?;

    let mut stdout = child.stdout.take().ok_or_else(|| {
        kill_and_reap(&mut child);
        MddError::new(
            ErrorCode::InternalFault,
            "worker.provider",
            "stdout pipe missing",
        )
    })?;
    let cap = config.max_output_bytes;
    let mut reader_handle = Some(thread::spawn(move || -> Result<Vec<u8>, String> {
        let mut collected = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            match stdout.read(&mut chunk) {
                Ok(0) => return Ok(collected),
                Ok(n) => {
                    if collected.len().saturating_add(n) > cap {
                        return Err("OUTPUT_LIMIT_EXCEEDED".to_owned());
                    }
                    collected.extend_from_slice(&chunk[..n]);
                }
                Err(e) => return Err(format!("READ_ERROR: {e}")),
            }
        }
    }));

    let deadline = Duration::from_millis(config.timeout_ms.max(1));
    let started = Instant::now();
    let mut finished_output: Option<Result<Vec<u8>, String>> = None;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if let Some(handle) = reader_handle.take_if(|h| h.is_finished()) {
                    match handle.join() {
                        Ok(Ok(bytes)) => {
                            // Stdout EOF can arrive slightly before the OS marks the child exited.
                            finished_output = Some(Ok(bytes));
                        }
                        Ok(Err(reason)) if reason == "OUTPUT_LIMIT_EXCEEDED" => {
                            kill_and_reap(&mut child);
                            return Err(MddError::new(
                                ErrorCode::QuotaExceeded,
                                "worker.provider",
                                "isolated provider stdout exceeded max_output_bytes budget",
                            )
                            .detail("reason", "OUTPUT_LIMIT_EXCEEDED"));
                        }
                        Ok(Err(_)) | Err(_) => {
                            kill_and_reap(&mut child);
                            return Err(MddError::new(
                                ErrorCode::InternalFault,
                                "worker.provider",
                                "isolated provider output stream failed",
                            ));
                        }
                    }
                }
                if started.elapsed() >= deadline {
                    kill_and_reap(&mut child);
                    if let Some(handle) = reader_handle.take() {
                        let _ = handle.join();
                    }
                    return Err(MddError::new(
                        ErrorCode::DeadlineExceeded,
                        "worker.provider",
                        format!("isolated provider timed out after {}ms", config.timeout_ms),
                    )
                    .detail("reason", "PROVIDER_TIMEOUT"));
                }
                thread::sleep(Duration::from_millis(10));
            }
            Err(e) => {
                kill_and_reap(&mut child);
                if let Some(handle) = reader_handle.take() {
                    let _ = handle.join();
                }
                return Err(MddError::new(
                    ErrorCode::InternalFault,
                    "worker.provider",
                    e.to_string(),
                ));
            }
        }
    };

    let output = match finished_output {
        Some(out) => out,
        None => match reader_handle.take() {
            Some(handle) => handle.join().map_err(|_| {
                MddError::new(
                    ErrorCode::InternalFault,
                    "worker.provider",
                    "provider stdout reader panicked",
                )
            })?,
            None => {
                return Err(MddError::new(
                    ErrorCode::InternalFault,
                    "worker.provider",
                    "provider stdout reader state missing",
                ));
            }
        },
    };
    let bytes = match output {
        Ok(b) => b,
        Err(reason) if reason == "OUTPUT_LIMIT_EXCEEDED" => {
            return Err(MddError::new(
                ErrorCode::QuotaExceeded,
                "worker.provider",
                "isolated provider stdout exceeded max_output_bytes budget",
            )
            .detail("reason", "OUTPUT_LIMIT_EXCEEDED"));
        }
        Err(msg) => {
            return Err(MddError::new(
                ErrorCode::InternalFault,
                "worker.provider",
                msg,
            ));
        }
    };

    if !status.success() {
        return Err(MddError::new(
            ErrorCode::InternalFault,
            "worker.provider",
            format!(
                "isolated provider exited with non-zero status {:?}",
                status.code()
            ),
        )
        .detail("reason", "PROVIDER_PROCESS_FAILED"));
    }

    let rendered = String::from_utf8(bytes).map_err(|_| {
        MddError::new(
            ErrorCode::InvalidInput,
            "worker.provider",
            "provider output is not valid UTF-8 display text",
        )
    })?;

    Ok(IsolatedDecompilerView {
        provider_id: config.provider_id.clone(),
        provider_version: config.declared_version.clone(),
        provider_binary_sha256: actual_sha,
        source_content_id: source_content_id.to_owned(),
        trust_level: "display_only_reconstructed".to_owned(),
        authoritative_for_facts: false,
        rendered_text: rendered.clone(),
        output_bytes: DecimalU64(rendered.len() as u64),
    })
}
