//! Probe for isolated external provider verification (pinned SHA, timeout, output cap, display-only guard).

use mdd_worker::providers::{
    ExternalProviderConfig, FactTargetKind, invoke_isolated_provider, reject_as_authoritative_fact,
};
use serde_json::json;
use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let mut enabled = false;
    let mut binary_path: Option<PathBuf> = None;
    let mut expected_sha = String::new();
    let mut timeout_ms = 5_000u64;
    let mut max_bytes = 65_536usize;
    let mut pass_args: Vec<String> = Vec::new();
    let mut check_fact_guard = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--enabled" => enabled = true,
            "--check-fact-guard" => check_fact_guard = true,
            "--binary" => {
                i += 1;
                binary_path = args.get(i).map(PathBuf::from);
            }
            "--expected-sha256" => {
                i += 1;
                expected_sha = args.get(i).cloned().unwrap_or_default();
            }
            "--timeout-ms" => {
                i += 1;
                timeout_ms = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(5_000);
            }
            "--max-output-bytes" => {
                i += 1;
                max_bytes = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(65_536);
            }
            "--arg" => {
                i += 1;
                if let Some(a) = args.get(i) {
                    pass_args.push(a.clone());
                }
            }
            _ => return ExitCode::from(2),
        }
        i += 1;
    }

    let cfg = ExternalProviderConfig {
        provider_id: "jadx-optional".to_owned(),
        declared_version: "1.5.0-pinned".to_owned(),
        binary_path: binary_path.unwrap_or_default(),
        args: pass_args,
        expected_binary_sha256: expected_sha,
        timeout_ms,
        max_output_bytes: max_bytes,
        enabled,
    };

    match invoke_isolated_provider(&cfg, "sha256:test") {
        Ok(view) => {
            let guard_raw = reject_as_authoritative_fact(&view, FactTargetKind::RawFingerprint)
                .err()
                .map(|e| e.code.to_string());
            let guard_cg =
                reject_as_authoritative_fact(&view, FactTargetKind::DeterministicCallGraph)
                    .err()
                    .map(|e| e.code.to_string());
            let guard_disp =
                reject_as_authoritative_fact(&view, FactTargetKind::HumanDisplayView).is_ok();
            let _ = check_fact_guard;
            println!(
                "{}",
                json!({
                    "ok": true,
                    "view": view,
                    "guards": {
                        "raw_fingerprint_rejected_code": guard_raw,
                        "call_graph_rejected_code": guard_cg,
                        "human_display_allowed": guard_disp,
                    }
                })
            );
            ExitCode::SUCCESS
        }
        Err(err) => {
            println!(
                "{}",
                json!({
                    "ok": false,
                    "error_code": err.code.to_string(),
                    "reason": err.details.get("reason").or_else(|| err.details.get("capability_state")),
                    "message": err.message,
                })
            );
            ExitCode::SUCCESS
        }
    }
}
