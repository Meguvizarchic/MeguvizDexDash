#!/usr/bin/env python3
"""Run MDD-074 optional DEX 041, special container & isolated provider qualification suite."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "conformance/manifests/optional-capabilities.json"
RECORD = ROOT / "artifacts/mdd-074/optional-format-qualification.json"
SOURCES = [
    "crates/mdd-input/src/optional_formats/mod.rs",
    "crates/mdd-input/src/optional_formats/address.rs",
    "crates/mdd-input/src/optional_formats/dex041.rs",
    "crates/mdd-input/src/optional_formats/special_containers.rs",
    "crates/mdd-input/examples/optional_format_probe.rs",
    "crates/mdd-worker/src/providers/mod.rs",
    "crates/mdd-worker/src/providers/jadx_view.rs",
    "crates/mdd-worker/examples/provider_isolation_probe.rs",
    "crates/mdd-worker/tests/provider_isolation.rs",
    "crates/mdd-cache/tests/dex041_cache_invalidation.rs",
    "conformance/manifests/optional-capabilities.json",
    "conformance/optional_formats/run_optional_conformance.py",
    "conformance/optional_formats/test_optional_conformance.py",
]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def encode_uleb128(value: int) -> bytes:
    out = bytearray()
    while True:
        b = value & 0x7F
        value >>= 7
        if value != 0:
            b |= 0x80
        out.append(b)
        if value == 0:
            break
    return bytes(out)


def encode_str_item(text: str) -> bytes:
    raw = text.encode("utf-8")
    return encode_uleb128(len(text.encode("utf-16-le")) // 2) + raw + b"\x00"


def finalize_041_header(buf: bytearray, base: int, file_size: int, total_size: int) -> None:
    buf[base : base + 8] = b"dex\n041\0"
    buf[base + 32 : base + 36] = file_size.to_bytes(4, "little")
    buf[base + 36 : base + 40] = (120).to_bytes(4, "little")
    buf[base + 40 : base + 44] = (0x12345678).to_bytes(4, "little")
    buf[base + 112 : base + 116] = total_size.to_bytes(4, "little")
    buf[base + 116 : base + 120] = base.to_bytes(4, "little")
    sig = hashlib.sha1(buf[base + 32 : base + file_size]).digest()
    buf[base + 12 : base + 32] = sig
    csum = zlib.adler32(bytes(buf[base + 12 : base + file_size])) & 0xFFFFFFFF
    buf[base + 8 : base + 12] = csum.to_bytes(4, "little")


def build_041_container(logical_count: int, shared_strings: list[str], extra_tail: bytes = b"") -> bytes:
    # Each logical DEX occupies 144 bytes: 120B header + string_ids[1 + len(shared)] (wait: keep uniform padding)
    private_str = encode_str_item("local_dup")  # 1 + 9 + 1 = 11 bytes
    string_count = 1 + len(shared_strings)
    ids_bytes = string_count * 4
    unaligned_span = 120 + ids_bytes + len(private_str)
    dex_span = ((unaligned_span + 3) // 4) * 4
    tail_start = dex_span * logical_count

    shared_items = [encode_str_item(s) for s in shared_strings]
    shared_offsets = []
    pos = tail_start
    for item in shared_items:
        shared_offsets.append(pos)
        pos += len(item)
    total_size = pos + len(extra_tail)

    buf = bytearray(total_size)
    cur = tail_start
    for item in shared_items:
        buf[cur : cur + len(item)] = item
        cur += len(item)
    if extra_tail:
        buf[cur : cur + len(extra_tail)] = extra_tail

    for ord_idx in range(logical_count):
        base = ord_idx * dex_span
        ids_off = base + 120
        priv_off = ids_off + ids_bytes
        buf[priv_off : priv_off + len(private_str)] = private_str
        buf[ids_off : ids_off + 4] = priv_off.to_bytes(4, "little")
        for j, soff in enumerate(shared_offsets):
            slot = ids_off + 4 * (1 + j)
            buf[slot : slot + 4] = soff.to_bytes(4, "little")
        buf[base + 56 : base + 60] = string_count.to_bytes(4, "little")
        buf[base + 60 : base + 64] = ids_off.to_bytes(4, "little")
        finalize_041_header(buf, base, dex_span, total_size)
    return bytes(buf)


def ensure_example_binary(pkg: str, name: str) -> Path:
    exe_name = f"{name}.exe" if os.name == "nt" else name
    candidate = ROOT / "target/debug/examples" / exe_name
    if not candidate.is_file():
        done = subprocess.run(
            ["cargo", "build", "--offline", "--locked", "-p", pkg, "--example", name],
            cwd=ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        require(done.returncode == 0, f"failed building {pkg}/{name}: {done.stderr}")
    require(candidate.is_file(), f"missing built example: {candidate}")
    return candidate


def run_json(exe: Path, *args: str) -> dict:
    done = subprocess.run(
        [str(exe), *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    require(done.returncode == 0, f"{exe.name} failed ({args}): {done.stderr}")
    return json.loads(done.stdout)


def run_suite() -> dict:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    require(manifest.get("standard_release_depends_on_mdd_074") is False, "standard release must not depend on MDD-074")

    # 1. Verify Rust tests across mdd-cache (041 invalidation) and mdd-worker (provider isolation).
    for pkg, test_name in [("mdd-cache", "dex041_cache_invalidation"), ("mdd-worker", "provider_isolation")]:
        done = subprocess.run(
            ["cargo", "test", "--offline", "--locked", "-p", pkg, "--test", test_name],
            cwd=ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        require(done.returncode == 0, f"{pkg}/{test_name} failed:\n{done.stdout}\n{done.stderr}")

    opt_probe = ensure_example_binary("mdd-input", "optional_format_probe")
    prov_probe = ensure_example_binary("mdd-worker", "provider_isolation_probe")

    dex041_results = {}
    special_results = {}
    provider_results = {}

    with tempfile.TemporaryDirectory(prefix="mdd074-") as tmp:
        work = Path(tmp)

        # Positive 041 vectors: 1, 2, 3 logical DEX containers
        one_dex = work / "one_041.dex"
        one_dex.write_bytes(build_041_container(1, []))
        two_dex = work / "two_041.dex"
        two_dex.write_bytes(build_041_container(2, ["Lshared/One;", "Lshared/Two;"]))
        three_dex = work / "three_041.dex"
        three_dex.write_bytes(build_041_container(3, ["Lshared/Tri;"]))

        # Standard DEX reader MUST still reject 041!
        std_rej = run_json(opt_probe, "standard-rejects", str(two_dex))
        require(std_rej["standard_rejected"] is True and std_rej["error_code"] == "UNSUPPORTED_CAPABILITY", f"standard reader accepted 041: {std_rej}")

        # Default policy (without --enable-041) must also reject 041!
        def_rej = run_json(opt_probe, "dex041", str(two_dex))
        require(def_rej["ok"] is False and def_rej["error_code"] == "UNSUPPORTED_CAPABILITY", f"default policy failed to reject 041: {def_rej}")

        r1 = run_json(opt_probe, "dex041", str(one_dex), "--enable-041")
        r2 = run_json(opt_probe, "dex041", str(two_dex), "--enable-041")
        r3 = run_json(opt_probe, "dex041", str(three_dex), "--enable-041")
        require(r1["ok"] and r1["report"]["logical_dex_count"] == 1, f"1-dex failed: {r1}")
        require(r2["ok"] and r2["report"]["logical_dex_count"] == 2, f"2-dex failed: {r2}")
        # 2 logical DEX * (1 local + 2 shared) = 6 logical string rows, with 2 physical shared tail offsets
        require(r2["report"]["total_logical_string_occurrences"] == 6, f"shared strings merged prematurely: {r2}")
        require(r2["report"]["physical_shared_string_offsets"] == 2, f"expected 2 shared offsets: {r2}")
        require(r3["ok"] and r3["report"]["logical_dex_count"] == 3 and r3["report"]["total_logical_string_occurrences"] == 6, f"3-dex failed: {r3}")

        dex041_results["positive_1_2_3_logical_dex_and_shared_preserving"] = {
            "passed": True,
            "standard_reader_rejected_code": std_rej["error_code"],
            "default_policy_rejected_code": def_rej["error_code"],
            "two_dex_logical_strings": r2["report"]["total_logical_string_occurrences"],
            "three_dex_logical_strings": r3["report"]["total_logical_string_occurrences"],
        }

        # Negative 041 boundary vectors
        neg_checks = {}

        # a) Truncated shared tail & unterminated shared MUTF-8 string with consistent container_size
        raw2 = bytearray(two_dex.read_bytes())
        trunc_file = work / "neg_trunc.dex"
        trunc_file.write_bytes(bytes(raw2[:-4]))
        res_trunc = run_json(opt_probe, "dex041", str(trunc_file), "--enable-041")
        require(res_trunc["ok"] is False and res_trunc["error_code"] == "INVALID_INPUT", f"trunc 041 failed: {res_trunc}")
        neg_checks["truncated_shared_tail"] = res_trunc["reason"]

        unterm = bytearray(two_dex.read_bytes())
        unterm[-1] = ord("Z")
        span_two = int.from_bytes(unterm[32:36], "little")
        finalize_041_header(unterm, 0, span_two, len(unterm))
        finalize_041_header(unterm, span_two, span_two, len(unterm))
        unterm_file = work / "neg_unterminated_tail.dex"
        unterm_file.write_bytes(bytes(unterm))
        res_unterm = run_json(opt_probe, "dex041", str(unterm_file), "--enable-041")
        require(res_unterm["ok"] is False and res_unterm["reason"] == "TRUNCATED_SHARED_STRING_DATA", f"unterminated 041 failed: {res_unterm}")
        neg_checks["unterminated_shared_string"] = res_unterm["reason"]

        # b) Wrong declared container_size (with updated header checksums)
        bad_csize = bytearray(one_dex.read_bytes())
        span1 = len(bad_csize)
        bad_csize[112:116] = (span1 + 16).to_bytes(4, "little")
        finalize_041_header(bad_csize, 0, span1, span1 + 16)
        bad_csize_file = work / "neg_csize.dex"
        bad_csize_file.write_bytes(bytes(bad_csize))
        res_csize = run_json(opt_probe, "dex041", str(bad_csize_file), "--enable-041")
        require(res_csize["ok"] is False and res_csize["reason"] == "CONTAINER_SIZE_MISMATCH", f"csize failed: {res_csize}")
        neg_checks["wrong_container_size"] = res_csize["reason"]

        # c) Pointer into 120B logical header
        ptr_hdr = bytearray(one_dex.read_bytes())
        ptr_hdr[120:124] = (32).to_bytes(4, "little")
        finalize_041_header(ptr_hdr, 0, len(ptr_hdr), len(ptr_hdr))
        ptr_hdr_file = work / "neg_ptr_hdr.dex"
        ptr_hdr_file.write_bytes(bytes(ptr_hdr))
        res_ptr = run_json(opt_probe, "dex041", str(ptr_hdr_file), "--enable-041")
        require(res_ptr["ok"] is False and res_ptr["reason"] == "STRING_DATA_POINTS_INTO_HEADER", f"ptr_hdr failed: {res_ptr}")
        neg_checks["pointer_into_header"] = res_ptr["reason"]

        # d) Unrecognized trailing garbage bytes in tail region (fail closed, never ignore)
        trailing = build_041_container(2, ["Lshared/X;"], extra_tail=b"\xDE\xAD\xBE\xEF")
        trailing_file = work / "neg_trailing.dex"
        trailing_file.write_bytes(trailing)
        res_trailing = run_json(opt_probe, "dex041", str(trailing_file), "--enable-041")
        require(res_trailing["ok"] is False and res_trailing["reason"] == "UNRECOGNIZED_TRAILING_CONTAINER_DATA", f"trailing failed: {res_trailing}")
        neg_checks["unrecognized_trailing_bytes"] = res_trailing["reason"]

        # e) Mixed DEX 041 + 039 logical header
        mixed = bytearray(two_dex.read_bytes())
        span_half = int.from_bytes(mixed[32:36], "little")
        mixed[span_half : span_half + 8] = b"dex\n039\0"
        mixed_file = work / "neg_mixed.dex"
        mixed_file.write_bytes(bytes(mixed))
        res_mixed = run_json(opt_probe, "dex041", str(mixed_file), "--enable-041")
        require(res_mixed["ok"] is False and res_mixed["error_code"] == "UNSUPPORTED_CAPABILITY", f"mixed failed: {res_mixed}")
        neg_checks["mixed_version_header"] = res_mixed["reason"]

        # f) Zero-progress / tiny file_size < 120
        zero_prog = bytearray(one_dex.read_bytes())
        zero_prog[32:36] = (64).to_bytes(4, "little")
        zero_prog_file = work / "neg_zeroprog.dex"
        zero_prog_file.write_bytes(bytes(zero_prog))
        res_zp = run_json(opt_probe, "dex041", str(zero_prog_file), "--enable-041")
        require(res_zp["ok"] is False and res_zp["reason"] == "ZERO_PROGRESS_OR_TINY_FILE_SIZE", f"zero_prog failed: {res_zp}")
        neg_checks["zero_progress_file_size"] = res_zp["reason"]

        dex041_results["negative_boundaries"] = {"passed": True, "cases": neg_checks}

        # Special containers (cdex, vdex, oat) remain explicitly disabled
        for fmt_id, hdr in [("cdex", b"cdex001\x00" + b"\x00" * 64), ("vdex", b"vdex021\x00" + b"\x00" * 64), ("oat", b"oat\n195\x00" + b"\x00" * 64)]:
            p = work / f"sample.{fmt_id}"
            p.write_bytes(hdr)
            res_spec = run_json(opt_probe, "special", str(p))
            require(res_spec["ok"] is False and res_spec["error_code"] == "UNSUPPORTED_CAPABILITY" and res_spec["capability_state"] == "disabled", f"special {fmt_id} not rejected properly: {res_spec}")
            special_results[fmt_id] = {"passed": True, "error_code": res_spec["error_code"], "capability_state": res_spec["capability_state"]}

        # Isolated provider probe tests (disabled by default, SHA mismatch, timeout, cap, display_only fact guards)
        py_exe = Path(sys.executable).resolve()
        py_sha = sha256_file(py_exe)
        prov_dis = run_json(prov_probe)
        require(prov_dis["ok"] is False and prov_dis["error_code"] == "UNSUPPORTED_CAPABILITY", f"provider default disabled check failed: {prov_dis}")
        prov_bad_sha = run_json(prov_probe, "--enabled", "--binary", str(py_exe), "--expected-sha256", "0" * 64)
        require(prov_bad_sha["ok"] is False and prov_bad_sha["error_code"] == "INVALID_INPUT", f"provider bad sha failed: {prov_bad_sha}")
        prov_timeout = run_json(prov_probe, "--enabled", "--binary", str(py_exe), "--expected-sha256", py_sha, "--timeout-ms", "150", "--arg", "-c", "--arg", "import time; time.sleep(5)")
        require(prov_timeout["ok"] is False and prov_timeout["error_code"] == "DEADLINE_EXCEEDED", f"provider timeout failed: {prov_timeout}")
        prov_cap = run_json(prov_probe, "--enabled", "--binary", str(py_exe), "--expected-sha256", py_sha, "--max-output-bytes", "128", "--arg", "-c", "--arg", "print('X' * 4096)")
        require(prov_cap["ok"] is False and prov_cap["error_code"] == "QUOTA_EXCEEDED", f"provider cap failed: {prov_cap}")
        prov_ok = run_json(prov_probe, "--enabled", "--check-fact-guard", "--binary", str(py_exe), "--expected-sha256", py_sha, "--arg", "-c", "--arg", "print('class Reconstructed {}')")
        require(
            prov_ok["ok"] is True
            and prov_ok["view"]["trust_level"] == "display_only_reconstructed"
            and prov_ok["view"]["authoritative_for_facts"] is False
            and prov_ok["guards"]["raw_fingerprint_rejected_code"] == "UNSUPPORTED_CAPABILITY"
            and prov_ok["guards"]["call_graph_rejected_code"] == "UNSUPPORTED_CAPABILITY",
            f"provider ok guard check failed: {prov_ok}",
        )
        provider_results = {
            "passed": True,
            "disabled_by_default": prov_dis["error_code"],
            "sha_mismatch_code": prov_bad_sha["error_code"],
            "timeout_code": prov_timeout["error_code"],
            "output_cap_code": prov_cap["error_code"],
            "display_only_trust_level": prov_ok["view"]["trust_level"],
            "raw_fingerprint_rejected_code": prov_ok["guards"]["raw_fingerprint_rejected_code"],
            "call_graph_rejected_code": prov_ok["guards"]["call_graph_rejected_code"],
        }

    all_passed = (
        all(v["passed"] for v in dex041_results.values())
        and all(v["passed"] for v in special_results.values())
        and provider_results["passed"]
    )
    return {
        "schema_version": "mdd.optional-format-qualification.v1",
        "task_id": "MDD-074",
        "standard_release_depends_on_mdd_074": False,
        "source_sha256": {p: sha256_file(ROOT / p) for p in SOURCES},
        "dex_041": dex041_results,
        "special_containers_disabled": special_results,
        "isolated_provider": provider_results,
        "all_passed": all_passed,
    }


def check_record(path: Path) -> int:
    require(path.is_file(), f"missing optional qualification record: {path}")
    doc = json.loads(path.read_text(encoding="utf-8"))
    require(doc.get("all_passed") is True, "optional format record all_passed != true")
    require(doc.get("standard_release_depends_on_mdd_074") is False, "standard release flag must be false")
    hashes = doc.get("source_sha256", {})
    for rel in SOURCES:
        actual = sha256_file(ROOT / rel)
        require(hashes.get(rel) == actual, f"source hash drift: {rel}")
    for key in ("cdex", "vdex", "oat"):
        require(doc["special_containers_disabled"][key]["passed"] is True, f"special container check failed: {key}")
    require(doc["isolated_provider"]["passed"] is True, "isolated provider check failed")
    print(f"MDD-074 record check passed: {len(SOURCES)} source hashes current, standard_release_depends_on_mdd_074=False")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=None, help="Ignored generic CLI binary arg when invoked by CI runner")
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    _ = args.binary

    if args.check:
        return check_record(RECORD)

    report = run_suite()
    out = args.out if args.out is not None else RECORD
    if not out.is_absolute():
        out = ROOT / out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"MDD-074 optional format qualification passed -> {out}")
    return 0 if report["all_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
