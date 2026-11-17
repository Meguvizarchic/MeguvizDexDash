"""Audit all detected priority families and compare a pinned baseline APK."""
from concurrent.futures import ProcessPoolExecutor
from types import SimpleNamespace
import json
import os
import sys
import zipfile
import hashlib
import time
import analyze
import hostlab
import surface_workers as W
import source_snapshot
import snapshot_transport
import runner_resources
from audit_common import resource_fingerprints


def scan_apk(apk, sample):
    started = time.monotonic()
    with zipfile.ZipFile(apk) as archive:
        names = [n for n in archive.namelist() if __import__("re").fullmatch(r"classes\d*\.dex", n)]
    names.sort(key=lambda n:int(__import__("re").sub(r"\D", "", n) or 1))
    if not names or len(names) != len(set(names)):
        raise RuntimeError("APK must contain a nonempty, unambiguous DEX inventory")
    jobs = [(str(apk), name, idx) for idx, name in enumerate(names)]
    snapshot = runner_resources.Probe(apk.parent).collect(time.monotonic())
    available = snapshot.get("memory_available_bytes")
    workers = min(2 if available is not None and available >= 4 * runner_resources.GIB else 1,
                  max(1, int(snapshot.get("effective_cpus") or 1)))
    with ProcessPoolExecutor(max_workers=workers, initializer=W.W.init_worker) as pool:
        report = W.summarize(list(pool.map(W.scan, jobs)))
    report["sample"] = sample
    report["resource_fingerprints"] = resource_fingerprints(apk)
    report["scan_execution"] = {"workers": workers, "dex_files": len(names),
                                "elapsed_ms": (time.monotonic()-started)*1000}
    return report


def resource_changes(base, target):
    before, after = base.get("resource_fingerprints", {}), target.get("resource_fingerprints", {})
    return {"added": sorted(set(after)-set(before)), "removed": sorted(set(before)-set(after)),
            "changed": sorted(k for k in set(before)&set(after) if before[k] != after[k]),
            "scope": "global_resources_not_yet_attributed_to_pages"}


def verdict(changes, target, context, resources, has_baseline):
    reasons = []
    if changes:
        reasons.append("structure_or_protocol_drift")
    if any((resources or {}).get(key) for key in ("added", "removed", "changed")):
        reasons.append("native_resource_drift")
    if target["unknown_families"] or target["unregistered_protocols"]:
        reasons.append("unmapped_paths")
    if not context or context.get("unmapped_multi_path_candidates") or context.get("working_tree_dirty"):
        reasons.append("source_contract_review_required")
    if not has_baseline:
        reasons.append("no_comparable_baseline")
    return {"status": "REVIEW_REQUIRED" if reasons else "NO_STATIC_DRIFT_FOUND", "reasons": reasons}


def resolve(code, sha, revision):
    return analyze.inputs(SimpleNamespace(apk=None, version_code=code, sha256=sha, revision=revision))


def audit_sample(sample, revision, *, surface=None):
    folder = hostlab.STATE / "reports" / str(sample["version_code"]) / sample["sha256"][:16]
    previous = set(folder.glob("*/summary.json"))
    argv = ["audit", "--version-code", str(sample["version_code"]),
            "--sha256", sample["sha256"], "--revision", revision]
    rc = analyze.main(argv, surface_output=surface) if surface is not None else analyze.main(argv)
    paths = set(folder.glob("*/summary.json")) - previous
    report = json.loads(next(iter(paths)).read_text(encoding="utf-8")) if len(paths) == 1 else {}
    from analysis.run_intake import EXPECTED_FEATURES
    if (rc not in (0, 1) or not report.get("audit_complete") or
            set(report.get("features", {})) != set(EXPECTED_FEATURES) or
            report.get("sample", {}).get("sha256") != sample["sha256"] or
            report.get("sample", {}).get("revision") != revision):
        raise RuntimeError("Standard audit did not produce usable FEATURE evidence")
    return {"exit_code": rc, "features": report["features"], "runtime_verified": False,
            "audit_backend": report.get("audit_backend", "legacy"),
            "backend_fallback_reason": report.get("backend_fallback_reason"),
            "scope": "offline_auditor_snapshot_not_production_coverage"}


def main():
    code = int(os.environ["HOSTLAB_VERSION"])
    revision = os.environ["HOSTLAB_REVISION"]
    sha = os.environ["HOSTLAB_SHA"]
    out = hostlab.STATE / "remote-output"
    out.mkdir(parents=True, exist_ok=True)
    context, binding = snapshot_transport.load_for_analysis(os.environ.get("HOSTLAB_MODULE_SOURCE", ""))
    source_snapshot.validate(context, expected_sha256=binding["snapshot_sha256"])
    source_context = source_snapshot.public_context(context, binding)
    source_context["freshness"] = ("dispatch_worktree_snapshot" if binding.get("origin") == "worktree"
                                   else "published_unverified_worktree")
    target_apk, target_sample = resolve(code, sha, revision)
    shared = {}
    target_audit = audit_sample(target_sample, revision, surface=shared)
    target = shared.get("report") or scan_apk(target_apk, target_sample)
    target["sample"] = target_sample
    hostlab.write_json(out / "priority-target.json", target)
    baseline_sha = os.environ.get("HOSTLAB_BASELINE_SHA", "")
    baseline = None
    baseline_audit = None
    if baseline_sha:
        repo = hostlab.config()["repo"]
        rows = hostlab.manifest(repo, revision)["samples"]
        row = next(r for r in rows if r["sha256"] == baseline_sha)
        if row.get("certificate_sha256") != target_sample.get("certificate_sha256"):
            raise RuntimeError("Baseline signing lineage differs")
        apk, sample = resolve(row["version_code"], baseline_sha, revision)
        shared = {}
        baseline_audit = audit_sample(sample, revision, surface=shared)
        baseline = shared.get("report") or scan_apk(apk, sample)
        baseline["sample"] = sample
        hostlab.write_json(out / "priority-baseline.json", baseline)
    changes = W.compare(baseline, target) if baseline else []
    resource_diff = resource_changes(baseline, target) if baseline else None
    summary = {"sample": target_sample, "baseline": baseline["sample"] if baseline else None,
               "standard_target_audit": target_audit, "standard_baseline_audit": baseline_audit,
               "changes": changes, "families": target["families"], "unknown_families": target["unknown_families"],
               "coverage_claim": "candidate_discovery_only", "ai_status": "not_configured",
               "source_snapshot": source_context,
               "page_path_matrix": target["page_path_matrix"],
               "protocol_paths": target["protocol_paths"],
               "protocol_twins": target["protocol_twins"], "unregistered_protocols": target["unregistered_protocols"],
               "resource_changes": resource_diff,
               "unclassified_protocol_callers": target["unclassified_protocol_callers"],
               "runtime_verified": False, "limitations": target["limitations"]}
    outcome = verdict(changes, target, source_context, resource_diff, baseline is not None)
    summary["analysis_status"] = outcome["status"]
    summary["review_reasons"] = outcome["reasons"]
    hostlab.write_json(out / "priority-summary.json", summary)
    lines = ["# 页面多路径覆盖与样式变化审计", "", "分析结果：" + summary["analysis_status"], "",
             "任务执行成功不等于模块适配通过。评论区、动态页最高优先级；所有登记路径分别核对。静态证据；AI 未接入，运行期样式启用未知。", "",
             "| 家族 | 类数 | Compose 方法 | 外部 invoke 边 | 证据 |", "|---|---:|---:|---:|---|"]
    for family, r in target["families"].items():
        lines.append(f"| {family} | {r['classes']} | {r['compose_methods']} | {r['external_invoke_edges']} | {r['evidence']} |")
    lines += ["", "## 需要复核的变化", "", *[f"- {r['family']}: {r['kind']}" for r in changes],
              "", "## 原生资源变化", "", str({k:len(v) for k,v in (resource_diff or {}).items() if isinstance(v,list)}),
              "", "## 未归类的源码多路径候选", "", *["- " + name for name in (source_context or {}).get("unmapped_multi_path_candidates", [])],
              "", "## 未归类协议调用者", "", "完整列表见 priority-summary.json；这些调用者不会静默排除。",
              "", "## 未覆盖边界", "", *["- " + s for s in target["limitations"]]]
    (out / "priority-report.md").write_text("\n".join(lines), encoding="utf-8")
    print(json.dumps({"families": len(target["families"]), "changes": len(changes), "ai": "not_configured"}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
