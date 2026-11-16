"""Mutation check for MDD-050: change one behaviour of the provider or the installer at a time and require the
tests to notice.

    python -I artifacts/mdd-050/mutation/mutate_provider.py

Each mutant replaces one exact piece of integrations/hostlab/provider.py or install_meguvizdexdash.py, runs
test_install.py and test_provider.py (the stand-in engine, no network), and restores the file in a `finally`.
A mutant that leaves the tests green is a survivor and exits 1. A pattern that no longer matches exactly once is
also a failure, so the list cannot rot silently. Run it on a clean checkout: it edits the two modules in place."""
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
HOSTLAB = REPO / "integrations" / "hostlab"
BACKUP = Path(tempfile.mkdtemp(prefix="mdd050-mutation-"))

MUTANTS = [
    ("provider.py", "a fallback for INTERNAL_FAULT", 'FALLBACK_ELIGIBLE = ("UNAVAILABLE_BACKEND", "UNSUPPORTED_CAPABILITY", "UNSUPPORTED_QUERY")',
     'FALLBACK_ELIGIBLE = ("UNAVAILABLE_BACKEND", "UNSUPPORTED_CAPABILITY", "UNSUPPORTED_QUERY", "INTERNAL_FAULT")'),
    ("provider.py", "a forced task may fall back", '    if task.get("forced"):\n        return no("forced_backend_never_falls_back")\n',
     '    if False:\n        return no("forced_backend_never_falls_back")\n'),
    ("provider.py", "an explicit dexsql request is routed to the engine", 'routed = backend == "auto" and config.native_engine == ENGINE',
     'routed = backend != "sqlite" and config.native_engine == ENGINE'),
    ("provider.py", "the eligibility test is gone", '    if failure.code not in FALLBACK_ELIGIBLE:\n        return no("error_is_not_a_not_here_error")\n',
     '    if False:\n        return no("error_is_not_a_not_here_error")\n'),
    ("provider.py", "rows already admitted do not stop a fallback", '    if admitted_rows:\n        return no("a_partial_result_was_already_admitted")\n',
     '    if False:\n        return no("a_partial_result_was_already_admitted")\n'),
    ("provider.py", "a request cannot forbid the fallback", '    if negotiation.get("fallback") == "forbid":\n        return no("fallback_forbidden_by_request")\n',
     '    if False:\n        return no("fallback_forbidden_by_request")\n'),
    ("provider.py", "cancellation is caught", "    except Exception as error:\n        failure = classify_failure(error)",
     "    except BaseException as error:\n        failure = classify_failure(error)"),
    ("provider.py", "a failure becomes an empty result", "        if decision.action != \"fallback\":\n            _attach(error, entry)\n            raise\n",
     "        if decision.action != \"fallback\":\n            _attach(error, entry)\n            return {}\n"),
    ("provider.py", "an unadmitted profile is accepted", '    if config.engine.profile_policy == "require_admitted" and not profile["admitted"]:',
     '    if False:'),
    ("provider.py", "a missing tool is not noticed", '    if missing:\n        return ("UNSUPPORTED_CAPABILITY", "tool_not_offered:" + ",".join(missing))',
     '    if False:\n        return ("UNSUPPORTED_CAPABILITY", "tool_not_offered:" + ",".join(missing))'),
    ("provider.py", "a forced engine request shares DexSQL's identity", "    if not forced:\n        return legacy.fingerprint(base) if not negotiation else digest_of(",
     "    if True:\n        return legacy.fingerprint(base) if not negotiation else digest_of("),
    ("provider.py", "a cache base that holds DexSQL's directories is allowed", 'for name, path in {**mine, "cache base": cache_root}.items():',
     'for name, path in mine.items():'),
    ("provider.py", "publishing overwrites", "            os.link(staged, target)", "            os.replace(staged, target)"),
    ("provider.py", "DexSQL's cache variables reach the engine", "if not _SECRET.search(k) and k not in _LEGACY_ENV and k != \"MDD_CACHE_DIR\"}",
     "if not _SECRET.search(k) and k != \"MDD_CACHE_DIR\"}"),
    ("provider.py", "a changed source still completes", 'report["complete"] = bool(report.get("complete")) and report["source_unchanged"]',
     'report["complete"] = bool(report.get("complete"))'),
    ("provider.py", "the engine can be reported as DexSQL", '    if isinstance(dexsql, dict) and (dexsql.get("product") == installer.PRODUCT or "build_id" in dexsql):',
     '    if False:'),
    ("provider.py", "unknown coverage counts as complete", '        if state != "complete":\n            reasons.append(f"{name}_{state}")',
     '        if state == "partial":\n            reasons.append(f"{name}_{state}")'),
    ("provider.py", "a checkpoint of another build is resumed", "    if before != after:\n        raise ValueError(\"checkpoint_engine_identity_changed\")",
     "    if False:\n        raise ValueError(\"checkpoint_engine_identity_changed\")"),
    ("provider.py", "the engine gets DexSQL's --threads", '    return ["mcp", "--dialect", config.engine.dialect,', '    return ["--threads", "2", "mcp", "--dialect", config.engine.dialect,'),
    ("provider.py", "a namespace of another build is taken over", '            if json.loads(path.read_text(encoding="utf-8")) != marker:', '            if False:'),
    ("provider.py", "the input gate ignores the roots", '    if not any(path.is_relative_to(root) for root in resolved):', '    if False:'),
    ("provider.py", "the DEX inventory is not compared", '    if expected is not None and actual != expected:', '    if False:'),
    ("provider.py", "the fallback evidence is dropped", '            result = dict(result, fallback=evidence)', '            result = dict(result)'),
    ("provider.py", "the rollback value still serves the engine", '    if forced and config.native_engine != ENGINE:', '    if False:'),
    ("provider.py", "a fallback is taken without the config's say-so", '    if config.engine.fallback.to != "dexsql":\n        return no("fallback_not_configured")',
     '    if False:\n        return no("fallback_not_configured")'),
    ("install_meguvizdexdash.py", "any digest is accepted", '        if build["sha256"] == digest:\n            return build', '        if True:\n            return build'),
    ("install_meguvizdexdash.py", "the legacy install directory is allowed", '    if _inside(chosen, LEGACY_VENDOR):', '    if False:'),
    ("install_meguvizdexdash.py", "install overwrites", '    if not target.exists():', '    if True:'),
    ("install_meguvizdexdash.py", "the deep tools check is gone", '        if seen["mcp_tools"] != entry["mcp_tools"] or seen["mcp_tools_sha256"] != entry["mcp_tools_sha256"]:',
     '        if False:'),
    ("install_meguvizdexdash.py", "the identity of the build is not compared", '        if seen[key] != entry[key]:', '        if False:'),
    ("install_meguvizdexdash.py", "credentials reach the engine", 'if not _SECRET.search(key)}', 'if True}'),
    ("install_meguvizdexdash.py", "a conflicting pin is accepted", '                    if build != entry:\n                        raise _invalid("the same bytes are already pinned with a different identity")\n                    return build',
     '                    return build'),
    ("install_meguvizdexdash.py", "an admitted profile needs no conformance digest", '        if profile["admitted"] and digest is None:', '        if False:'),
]

survivors = []
for index, (name, label, old, new) in enumerate(MUTANTS, 1):
    path = HOSTLAB / name
    original = path.read_text(encoding="utf-8")
    saved = BACKUP / name
    shutil.copyfile(path, saved)
    if original.count(old) != 1:
        print(f"{index:2} NOT APPLICABLE ({original.count(old)} matches): {label}")
        survivors.append((index, label, "pattern"))
        continue
    path.write_text(original.replace(old, new), encoding="utf-8", newline="\n")
    try:
        done = subprocess.run([sys.executable, "-I", "-m", "unittest", "discover", "-s", str(HOSTLAB), "-p", "test_[ip]*.py"],
                              capture_output=True, text=True, cwd=str(REPO), timeout=300)
    finally:
        shutil.copyfile(saved, path)
    killed = done.returncode != 0
    print(f"{index:2} {'killed' if killed else 'SURVIVED'}: {label}")
    if not killed:
        survivors.append((index, label, "survived"))
print("survivors:", survivors)
shutil.rmtree(BACKUP, ignore_errors=True)
sys.exit(1 if survivors else 0)
