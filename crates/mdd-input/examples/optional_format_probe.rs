//! Probe binary verifying DEX `041` isolation from standard DEX parsing and special-format rejections.

use mdd_input::optional_formats::{
    OptionalFormatPolicy, inspect_special_container, validate_and_extract_dex041_container,
};
use serde_json::json;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("usage: optional_format_probe <dex041|special> <path> [--enable-041]");
        return ExitCode::from(2);
    }
    let cmd = args[0].as_str();
    let Some(path) = args.get(1).map(PathBuf::from) else {
        eprintln!("missing path");
        return ExitCode::from(2);
    };
    let enable_041 = args.iter().any(|a| a == "--enable-041");
    let bytes = match fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            println!(
                "{}",
                json!({"ok": false, "error_code": "INVALID_INPUT", "message": e.to_string()})
            );
            return ExitCode::SUCCESS;
        }
    };

    match cmd {
        "standard-rejects" => match mdd_dex::validate_header(&bytes) {
            Ok(hdr) => {
                println!(
                    "{}",
                    json!({"ok": false, "error": "standard reader unexpectedly accepted optional container", "version": hdr.version})
                );
                ExitCode::FAILURE
            }
            Err(err) => {
                println!(
                    "{}",
                    json!({"ok": true, "standard_rejected": true, "error_code": err.code.to_string(), "reason": err.details.get("version").or_else(|| err.details.get("reason"))})
                );
                ExitCode::SUCCESS
            }
        },
        "dex041" => {
            let policy = OptionalFormatPolicy {
                allow_dex041_container: enable_041,
            };
            if let Err(err) = inspect_special_container(&bytes, &policy) {
                println!(
                    "{}",
                    json!({
                        "ok": false,
                        "stage": "policy",
                        "error_code": err.code.to_string(),
                        "reason": err.details.get("capability_state").or_else(|| err.details.get("reason")),
                        "message": err.message,
                    })
                );
                return ExitCode::SUCCESS;
            }
            match validate_and_extract_dex041_container(&bytes) {
                Ok(report) => {
                    println!("{}", json!({"ok": true, "report": report}));
                    ExitCode::SUCCESS
                }
                Err(err) => {
                    println!(
                        "{}",
                        json!({
                            "ok": false,
                            "stage": "validator",
                            "error_code": err.code.to_string(),
                            "reason": err.details.get("reason"),
                            "message": err.message,
                        })
                    );
                    ExitCode::SUCCESS
                }
            }
        }
        "special" => {
            let policy = OptionalFormatPolicy::default();
            match inspect_special_container(&bytes, &policy) {
                Ok(desc) => {
                    println!("{}", json!({"ok": true, "descriptor": desc}));
                    ExitCode::SUCCESS
                }
                Err(err) => {
                    println!(
                        "{}",
                        json!({
                            "ok": false,
                            "error_code": err.code.to_string(),
                            "format": err.details.get("format"),
                            "capability_state": err.details.get("capability_state"),
                            "message": err.message,
                        })
                    );
                    ExitCode::SUCCESS
                }
            }
        }
        _ => ExitCode::from(2),
    }
}
