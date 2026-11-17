"""Backend-independent resource fingerprints, retaining every existing resource entry."""
import hashlib
import zipfile


def resource_fingerprints(apk):
    result = {}
    with zipfile.ZipFile(apk) as archive:
        for entry in archive.infolist():
            if entry.filename != "resources.arsc" and not (entry.filename.startswith("res/") and entry.filename.endswith(".xml")):
                continue
            digest = hashlib.sha256()
            with archive.open(entry) as stream:
                for chunk in iter(lambda: stream.read(65536), b""):
                    digest.update(chunk)
            result[entry.filename] = digest.hexdigest()
    return result
