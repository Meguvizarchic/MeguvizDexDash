"""One DEX pass: discover priority families and actual invoke instructions."""
import hashlib
import json
import re
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent / "dexq"))
import dexq_workers as W

RULE_VERSION = 4
RULE_SHA256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
FAMILIES = {
    "comment_legacy_v2": ("Lcom/bilibili/app/comm/comment2/",),
    "comment_native_legacy": ("Lcom/bilibili/app/comment3/ui/holder/",),
    "comment_native_next": ("Lcom/bilibili/app/comment3/ui/nextholder/",),
    "comment_native_exp3": ("Lcom/bilibili/app/comment3/ui/nextholderexp3/",),
    "comment_compose": ("Lkntr/common/comment/",),
    "dynamic_legacy": ("Lcom/bilibili/bplus/followinglist/",),
    "dynamic_compose": ("Lkntr/app/following/followinglist/",),
    "dynamic_opus": ("Lkntr/app/following/opusDetail/", "Lcom/bilibili/opus/"),
    "mine_native": ("Ltv/danmaku/bili/ui/main2/mine/",),
    "mine_account_model": ("Ltv/danmaku/bili/ui/main2/api/AccountMine",),
    "home_legacy": ("Ltv/danmaku/bili/ui/main2/",),
    "home_new_frame": ("Ltv/danmaku/bili/khome/", "Ltv/danmaku/bili/khomeapi/frame/"),
    "search_native": ("Lcom/bilibili/search2/", "Lcom/bilibili/search/"),
    "search_compose": ("Lkntr/app/search/",),
    "detail_legacy": ("Lcom/bilibili/video/videodetail/",),
    "detail_theseus_ugc": ("Lcom/bilibili/ship/theseus/ugc/",),
    "detail_theseus_united": ("Lcom/bilibili/ship/theseus/united/",),
    "pgc_legacy": ("Lcom/bilibili/bangumi/ui/",),
    "pgc_theseus": ("Lcom/bilibili/ship/theseus/ogv/",),
    "player_java": ("Lcom/bilibili/playerbizcommon/", "Ltv/danmaku/ijk/media/player/"),
    "player_kotlin": ("Lkntr/common/player/",),
    "danmaku_legacy": ("Lcom/bilibili/lib/danmaku/",),
    "danmaku_kotlin": ("Lkntr/common/danmaku/",),
    "story_native": ("Lcom/bilibili/video/story/",),
    "story_kotlin": ("Lkntr/app/story/",),
}
PROTOCOLS = {
    "comment_java_moss": "Lcom/bapis/bilibili/main/community/reply/v1/ReplyMoss;",
    "comment_kotlin_moss": "Lcom/bapis/bilibili/main/community/reply/v1/KReplyMoss;",
    "dynamic_java_moss": "Lcom/bapis/bilibili/app/dynamic/v2/DynamicMoss;",
    "dynamic_kotlin_moss": "Lcom/bapis/bilibili/app/dynamic/v2/KDynamicMoss;",
    "search_java_moss": "Lcom/bapis/bilibili/polymer/app/search/v1/SearchMoss;",
    "search_kotlin_moss": "Lcom/bapis/bilibili/polymer/app/search/v1/KSearchMoss;",
    "detail_java_moss": "Lcom/bapis/bilibili/app/viewunite/v1/ViewMoss;",
    "detail_kotlin_moss": "Lcom/bapis/bilibili/app/viewunite/v1/KViewMoss;",
    "danmaku_java_moss": "Lcom/bapis/bilibili/community/service/dm/v1/DMMoss;",
    "danmaku_kotlin_moss": "Lcom/bapis/bilibili/community/service/dm/v1/KDMMoss;",
    "player_java_moss": "Lcom/bapis/bilibili/app/playurl/v1/PlayURLMoss;",
    "player_kotlin_moss": "Lcom/bapis/bilibili/app/playurl/v1/KPlayURLMoss;",
    "pgc_player_moss": "Lcom/bapis/bilibili/pgc/gateway/player/v2/PlayURLMoss;",
    "pgc_view_moss": "Lcom/bapis/bilibili/pgc/gateway/view/v1/ViewMoss;",
}
PAGE_PATHS = {
    "comment": ["comment_legacy_v2", "comment_native_legacy", "comment_native_next", "comment_native_exp3", "comment_compose"],
    "dynamic": ["dynamic_legacy", "dynamic_compose", "dynamic_opus"],
    "home": ["home_legacy", "home_new_frame"],
    "search": ["search_native", "search_compose"],
    "detail": ["detail_legacy", "detail_theseus_ugc", "detail_theseus_united"],
    "pgc": ["pgc_legacy", "pgc_theseus"],
    "player": ["player_java", "player_kotlin"],
    "danmaku": ["danmaku_legacy", "danmaku_kotlin"],
    "story": ["story_native", "story_kotlin"],
    "mine": ["mine_native", "mine_account_model"],
}
PAGE_PROTOCOLS = {
    "comment": ["comment_java_moss", "comment_kotlin_moss"],
    "dynamic": ["dynamic_java_moss", "dynamic_kotlin_moss"],
    "search": ["search_java_moss", "search_kotlin_moss"],
    "detail": ["detail_java_moss", "detail_kotlin_moss"],
    "player": ["player_java_moss", "player_kotlin_moss"],
    "pgc": ["pgc_player_moss", "pgc_view_moss"],
    "danmaku": ["danmaku_java_moss", "danmaku_kotlin_moss"],
}


def family(name):
    for key, prefixes in FAMILIES.items():
        if name.startswith(prefixes):
            return key
    if name.startswith("Lcom/bilibili/app/comment3/ui/"):
        parts = name.split("/")
        return "comment_other_ui:" + (parts[5] if len(parts) > 6 else "(root)")
    if name.startswith("Lkntr/common/comment"):
        return "comment_other_compose"
    if name.startswith("Lkntr/app/following/"):
        parts = name.split("/")
        return "dynamic_other:" + (parts[3] if len(parts) > 4 else "(root)")
    if name.startswith("Lcom/bilibili/bplus/") and any(s in name.lower() for s in ("dynamic", "following", "feed")):
        return "dynamic_other_legacy"
    return None


def scan(job):
    src, member, file_id = job
    _, dex = W.load_dex(src, member)
    classes = []
    owners = {}
    for cls in dex.get_classes():
        name = cls.get_name()
        group = family(name)
        if group:
            owners[name] = group
            fields = sorted((f.get_name(), f.get_descriptor()) for f in cls.get_fields())
            methods = sorted((m.get_name(), W.norm_proto(m.get_descriptor())) for m in cls.get_methods())
            bodies = hashlib.sha256()
            for method in sorted(cls.get_methods(), key=lambda m:(m.get_name(), m.get_descriptor())):
                bodies.update((method.get_name() + W.norm_proto(method.get_descriptor())).encode())
                code = method.get_code()
                if code is not None:
                    bytecode = code.get_bc()
                    raw = getattr(bytecode, "insn", None)
                    bodies.update(raw if isinstance(raw, (bytes, bytearray)) else bytecode.get_raw())
            composer = [n + p for n, p in methods if "Landroidx/compose/runtime/Composer;" in p]
            classes.append({"file_id": file_id, "family": group, "class": name,
                "superclass": cls.get_superclassname(), "fields": fields, "methods": methods,
                "method_bodies_sha256": bodies.hexdigest(),
                "compose_signatures": composer})
    method_ids = dex.get_methods()
    target_indices = {}
    protocol_owners = {v: k for k, v in PROTOCOLS.items()}
    for idx, method in enumerate(method_ids):
        owner = method.get_class_name()
        if owner.startswith("Lcom/bapis/") and owner.endswith("Moss;") and owner not in protocol_owners:
            protocol_owners[owner] = "unregistered_protocol:" + owner
        target_family = protocol_owners.get(owner) or family(owner)
        if target_family:
            target_indices[idx] = (target_family, owner, method.get_name(), W.norm_proto(method.get_descriptor()))
    edges = set()
    edge_counts = {}
    # Scan invokes from every caller, including unknown/obfuscated packages.
    if target_indices:
        for method in dex.get_encoded_methods():
            code = method.get_code()
            if code is None:
                continue
            caller_owner = method.get_class_name()
            source_family = owners.get(caller_owner) or "external_or_unknown"
            caller_signature = None
            for ins in code.get_bc().get_instructions():
                # invoke-custom indexes call-sites, not method_ids. Never interpret
                # its numeric index as a method reference.
                opcode = ins.get_op_value()
                if opcode not in {0x6e, 0x6f, 0x70, 0x71, 0x72, 0x74, 0x75, 0x76, 0x77, 0x78, 0xfa, 0xfb}:
                    continue
                target = target_indices.get(ins.get_ref_kind())
                if target is None:
                    continue
                group, owner, name, proto = target
                key = (source_family, group)
                edge_counts[key] = edge_counts.get(key, 0) + 1
                # Keep all unique caller/callee members, not first N invocations.
                if caller_signature is None:
                    caller_signature = (method.get_name(), W.norm_proto(method.get_descriptor()))
                edges.add((file_id, source_family, caller_owner, *caller_signature, group, owner, name, proto))
    protocol_definitions = []
    for method in dex.get_encoded_methods():
        if method.get_class_name() in protocol_owners:
            protocol_definitions.append((file_id, protocol_owners[method.get_class_name()],
                                         method.get_name(), W.norm_proto(method.get_descriptor())))
    return {"rule_sha256": RULE_SHA256, "classes": classes, "edges": sorted(edges),
            "edge_counts": [(a, b, count) for (a, b), count in sorted(edge_counts.items())],
            "protocol_definitions": protocol_definitions}


def summarize(parts):
    if any(p.get("rule_sha256", RULE_SHA256) != RULE_SHA256 for p in parts):
        raise RuntimeError("Rule source changed during worker execution; rerun with immutable source")
    records = [r for part in parts for r in part["classes"]]
    groups = {key: [] for key in FAMILIES}
    for r in records:
        groups.setdefault(r["family"], []).append(r)
    edges = [edge for part in parts for edge in part["edges"]]
    result = {}
    for key, members in sorted(groups.items()):
        incoming = [e for e in edges if e[5] == key and e[1] != key]
        compose_count = sum(len(r["compose_signatures"]) for r in members)
        fingerprint = hashlib.sha256(json.dumps(sorted(members, key=lambda r:(r["class"], r["file_id"])), sort_keys=True).encode()).hexdigest()
        result[key] = {"classes": len(members), "compose_methods": compose_count,
                       "external_invoke_edges": len(incoming), "fingerprint": fingerprint,
                       "evidence": "static_invoke_observed" if incoming else "definitions_only" if members else "absent",
                       "runtime_enabled": "unknown", "module_coverage": "requires_installer_review"}
    definitions = [r for p in parts for r in p["protocol_definitions"]]
    protocols = {}
    discovered = {r[1]: r[1].split(":", 1)[1] for r in definitions if r[1].startswith("unregistered_protocol:")}
    discovered.update({e[5]: e[6] for e in edges if e[5].startswith("unregistered_protocol:")})
    for key, descriptor in {**PROTOCOLS, **discovered}.items():
        signatures = sorted(set((r[2], r[3]) for r in definitions if r[1] == key))
        callers = [e for e in edges if e[5] == key and e[2] != descriptor]
        protocols[key] = {"definitions": len(signatures), "signatures": signatures,
                          "actual_invoke_edges": len(callers), "runtime_enabled": "unknown"}
    descriptors = {**{value:key for key,value in PROTOCOLS.items()}, **{value:key for key,value in discovered.items()}}
    twins = []
    for owner, key in descriptors.items():
        prefix, name = owner.rsplit("/", 1)
        if name.startswith("K"):
            java = prefix + "/" + name[1:]
            if java in descriptors:
                twins.append({"java": java, "kotlin": owner, "java_path": protocols[descriptors[java]],
                              "kotlin_path": protocols[key], "requires_page_mapping": key.startswith("unregistered_protocol:")})
    return {"rule_version": RULE_VERSION, "rule_sha256": RULE_SHA256, "scope": "offline_static_only", "families": result,
            "protocol_twins": twins, "unregistered_protocols": sorted(discovered),
            "protocol_paths": protocols,
            "unclassified_protocol_callers": [e for e in edges if e[1] == "external_or_unknown" and e[5] in protocols and e[2] != e[6]],
            "page_path_matrix": {page: {"paths": {k: result[k] for k in keys},
                "protocols": {k: protocols[k] for k in PAGE_PROTOCOLS.get(page, [])},
                "complete_coverage": False, "status": "installer_and_runtime_validation_required"}
                for page, keys in PAGE_PATHS.items()},
            "class_records": records, "invoke_edges": edges,
            "protocol_definitions": definitions,
            "unknown_families": sorted(k for k in groups if k not in FAMILIES),
            "limitations": ["Server-controlled visual variants without structural changes may be invisible",
                            "Invoke edges do not resolve interface dispatch or prove runtime activation",
                            "Obfuscation/DEX relocation can change fingerprints without a new style",
                            "Unknown families are investigation candidates, not confirmed new styles"]}


def compare(base, target):
    if base.get("rule_sha256") != target.get("rule_sha256"):
        raise RuntimeError("Cannot attribute host changes across different analysis rules")
    changes = []
    for key in sorted(set(base["families"]) | set(target["families"])):
        before, after = base["families"].get(key), target["families"].get(key)
        if before != after:
            kind = "new_family_candidate" if before is None or before["classes"] == 0 else "retired_family_candidate" if after is None or after["classes"] == 0 else "structure_or_call_path_changed"
            changes.append({"family": key, "kind": kind, "before": before, "after": after,
                            "requires_review": True})
    for key in sorted(set(base.get("protocol_paths", {})) | set(target.get("protocol_paths", {}))):
        before, after = base.get("protocol_paths", {}).get(key), target.get("protocol_paths", {}).get(key)
        if before != after:
            changes.append({"family": key, "kind": "protocol_signature_or_call_path_changed",
                            "before": before, "after": after, "requires_review": True})
    return changes
