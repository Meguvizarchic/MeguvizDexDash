"""Generate a synthetic DEX with two classes sharing one physical empty array."""
import hashlib, importlib.util, json, struct
from pathlib import Path
root=Path(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location("annotation_fixture_generator",root/"tests/fixtures/annotations/generate.py")
gen=importlib.util.module_from_spec(spec)
spec.loader.exec_module(gen)
raw,layout=gen.build(["shared_empty_directory","orphan_arrays"])
data=bytearray(raw)
classes=layout["labels"]["class_defs"]
shared=layout["labels"]["empty_array"]
if data[shared] != 0: raise ValueError("expected physical empty array")
for n in range(2): struct.pack_into("<I",data,classes+32*n+28,shared)
data=gen.seal(data)
if [struct.unpack_from("<I",data,classes+32*n+28)[0] for n in range(2)] != [shared,shared]: raise ValueError("bad shared references")
out=Path(__file__).parent
(out/"shared-static-empty.dex").write_bytes(data)
(out/"fixture.json").write_text(json.dumps({"synthetic":True,"classes_offset":classes,"array_offset":shared,"class_definition_ordinals":[0,1],"sha256":hashlib.sha256(data).hexdigest()},indent=2)+"\n",encoding="utf-8")
