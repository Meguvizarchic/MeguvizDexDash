"""Independent reproducibility and standard XML parser check; works under -O."""
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET
import zipfile
from generate import vectors

ROOT = Path(__file__).resolve().parent

def require(ok, message):
    if not ok: raise RuntimeError(message)

def main():
    manifest = json.loads((ROOT / "manifest.json").read_text(encoding="utf-8"))
    encoded = {name: raw for name, raw, _ in vectors()}
    positive = negative = xml = 0
    for case in manifest["cases"]:
        file = ROOT / case["file"]; raw = file.read_bytes()
        require(raw == encoded[file.name], "independent deterministic encoder changed: " + file.name)
        require(len(raw) == case["bytes"] and hashlib.sha256(raw).hexdigest() == case["sha256"], "identity changed: " + file.name)
        if case["expected_error"] is None:
            positive += 1
            with zipfile.ZipFile(str(file) + ".apk") as archive:
                require(len(archive.infolist()) == 1, "fixture APK member count")
                require(archive.read(archive.infolist()[0]) == raw, "independent ZIP CRC/full-member identity")
            if file.suffix == ".xml":
                xml += 1
                # Fixtures are byte-exact synthetic manifests. Reject DTD and
                # entity declarations before parsing so a crafted fixture cannot
                # trigger internal entity expansion, and bound the input size.
                require(len(raw) <= 8 * 1024 * 1024, "fixture XML exceeds parse budget")
                head = raw[:4096].upper()
                require(b"<!DOCTYPE" not in head, "fixture XML may not declare a DTD")
                require(b"<!ENTITY" not in head, "fixture XML may not declare entities")
                root = ET.fromstring(raw)
                require(root.tag == "manifest", "independent text XML root")
        else:
            negative += 1
    print(json.dumps({"cases": positive + negative, "positive": positive, "negative": negative,
                      "all_bytes_reproduced": True, "positive_apk_members_fully_consumed": positive,
                      "independent_elementtree_xml": xml, "negative_scope": "byte identity, expected rejection validated by Rust tests"}))

if __name__ == "__main__": main()
