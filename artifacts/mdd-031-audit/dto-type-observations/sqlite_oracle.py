"""Observe literal expression value and runtime storage classes in SQLite."""
from pathlib import Path
import hashlib,importlib.util,json,sqlite3,struct
HERE=Path(__file__).resolve().parent;driver=HERE/"reference.py";target=HERE/"sqlite-literals.json"
if target.exists():raise RuntimeError("refusing to overwrite")
spec=importlib.util.spec_from_file_location("dto_reference",driver);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
allowed={"integers","cast","arithmetic","case","comparison","cte"}
PinnedStatements={sql for ident,sql in module.SINGLE if ident in allowed}
def pinned_statement(sql):
 """Reject any statement that is not one of the frozen driver statements."""
 if sql not in PinnedStatements:raise RuntimeError("statement outside the frozen driver table")
 return sql
def storage_class(value):
 """SQLite storage class of a fetched value.

 The sqlite3 driver maps each storage class onto exactly one Python type, so
 the class is read off the value instead of running an extra typeof() probe.
 That keeps every executed statement a frozen constant with no拼接 step.
 """
 if value is None:return "null"
 if isinstance(value,int):return "integer"
 if isinstance(value,float):return "real"
 if isinstance(value,str):return "text"
 if isinstance(value,bytes):return "blob"
 raise RuntimeError(f"unexpected SQLite cell {value!r}")
db=sqlite3.connect(":memory:");records=[]
def encode(value):
 if value is None:return {"type":"null","value":None}
 if isinstance(value,int):return {"type":"integer","value":str(value)}
 if isinstance(value,float):return {"type":"real","f64_be_hex":struct.pack('>d',value).hex()}
 if isinstance(value,str):return {"type":"text","value":value}
 if isinstance(value,bytes):return {"type":"blob","hex":value.hex()}
 raise RuntimeError(f"unexpected SQLite cell {value!r}")
for ident,sql in module.SINGLE:
 if ident not in allowed:continue
 try:
  cur=db.execute(pinned_statement(sql));columns=[x[0] for x in cur.description];rows=cur.fetchall()
  types=[list(storage_class(v) for v in row) for row in rows]
  records.append({"id":ident,"sql":sql,"status":"ok","columns":columns,"rows":[[encode(v) for v in row] for row in rows],"storage_classes":types})
 except sqlite3.Error as e:records.append({"id":ident,"sql":sql,"status":"error","error":type(e).__name__,"message":str(e)})
if {x["id"] for x in records}!=allowed:raise RuntimeError("case set mismatch")
with target.open('x',encoding='utf8',newline='\n') as f:
 json.dump({"sqlite_version":sqlite3.sqlite_version,"driver_sha256":hashlib.sha256(driver.read_bytes()).hexdigest(),"records":records,"scope":"literal expressions and CTE; no A0/A1 or DEX result typing claim","profiles_admitted":False},f,ensure_ascii=True,indent=2);f.write('\n')
print(json.dumps({"path":str(target),"sha256":hashlib.sha256(target.read_bytes()).hexdigest(),"records":len(records)}))
