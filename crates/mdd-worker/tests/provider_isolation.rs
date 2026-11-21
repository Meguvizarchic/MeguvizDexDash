//! Verifies external provider isolation, pinned SHA-256 verification, timeout/cap kills, and
//! architectural prohibition from contaminating authoritative facts or fingerprints.

use mdd_types::ErrorCode;
use mdd_worker::providers::{
    ExternalProviderConfig, FactTargetKind, invoke_isolated_provider, reject_as_authoritative_fact,
};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;

fn temp_dir(prefix: &str) -> PathBuf {
    let p = std::env::temp_dir().join(mdd_types::opaque_id(prefix).unwrap());
    fs::create_dir_all(&p).unwrap();
    p
}

#[test]
fn disabled_and_sha_mismatch_and_display_only_guards() {
    let dir = temp_dir("mdd-prov-test");
    let exe = dir.join("dummy_prov.bat");
    fs::write(&exe, b"@echo off\necho class Foo {}\n").unwrap();
    let real_sha: String = Sha256::digest(fs::read(&exe).unwrap())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();

    // Default config is disabled
    let disabled_cfg = ExternalProviderConfig::default();
    assert_eq!(
        invoke_isolated_provider(&disabled_cfg, "sha256:abc")
            .err()
            .unwrap()
            .code,
        ErrorCode::UnsupportedCapability
    );

    // Mismatched SHA-256 refuses execution
    let bad_sha_cfg = ExternalProviderConfig {
        provider_id: "jadx-optional".to_owned(),
        declared_version: "1.5.0".to_owned(),
        binary_path: exe.clone(),
        args: vec![],
        expected_binary_sha256: "0".repeat(64),
        timeout_ms: 2000,
        max_output_bytes: 1024,
        enabled: true,
    };
    assert_eq!(
        invoke_isolated_provider(&bad_sha_cfg, "sha256:abc")
            .err()
            .unwrap()
            .code,
        ErrorCode::InvalidInput
    );

    // Discover Python relative to workspace or PATH so tests remain portable and free of host paths.
    let python = {
        let workspace_venv = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../.venv")
            .join(if cfg!(windows) {
                "Scripts/python.exe"
            } else {
                "bin/python3"
            });
        let exe_names: &[&str] = if cfg!(windows) {
            &["python.exe"]
        } else {
            &["python3", "python"]
        };
        if workspace_venv.is_file() {
            workspace_venv
        } else {
            std::env::var_os("PATH")
                .and_then(|p| {
                    std::env::split_paths(&p)
                        .flat_map(|d| exe_names.iter().map(move |name| d.join(name)))
                        .find(|cand| cand.is_file())
                })
                .unwrap_or_else(|| PathBuf::from(exe_names[0]))
        }
    };
    if python.is_file() {
        let py_sha: String = Sha256::digest(fs::read(&python).unwrap())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let ok_cfg = ExternalProviderConfig {
            provider_id: "jadx-optional".to_owned(),
            declared_version: "1.5.0".to_owned(),
            binary_path: python.clone(),
            args: vec![
                "-c".to_owned(),
                "print('public class DisplayOnly {}')".to_owned(),
            ],
            expected_binary_sha256: py_sha.clone(),
            timeout_ms: 3000,
            max_output_bytes: 4096,
            enabled: true,
        };
        let view = invoke_isolated_provider(&ok_cfg, "sha256:abc").unwrap();
        assert_eq!(view.trust_level, "display_only_reconstructed");
        assert!(!view.authoritative_for_facts);
        assert!(reject_as_authoritative_fact(&view, FactTargetKind::HumanDisplayView).is_ok());
        assert_eq!(
            reject_as_authoritative_fact(&view, FactTargetKind::RawFingerprint)
                .err()
                .unwrap()
                .code,
            ErrorCode::UnsupportedCapability
        );
        assert_eq!(
            reject_as_authoritative_fact(&view, FactTargetKind::DeterministicCallGraph)
                .err()
                .unwrap()
                .code,
            ErrorCode::UnsupportedCapability
        );

        let timeout_cfg = ExternalProviderConfig {
            args: vec!["-c".to_owned(), "import time; time.sleep(5)".to_owned()],
            timeout_ms: 150,
            ..ok_cfg.clone()
        };
        assert_eq!(
            invoke_isolated_provider(&timeout_cfg, "sha256:abc")
                .err()
                .unwrap()
                .code,
            ErrorCode::DeadlineExceeded
        );

        let cap_cfg = ExternalProviderConfig {
            args: vec!["-c".to_owned(), "print('A' * 10000)".to_owned()],
            max_output_bytes: 256,
            ..ok_cfg
        };
        assert_eq!(
            invoke_isolated_provider(&cap_cfg, "sha256:abc")
                .err()
                .unwrap()
                .code,
            ErrorCode::QuotaExceeded
        );
    }

    let _ = real_sha;
    let _ = fs::remove_dir_all(&dir);
}
