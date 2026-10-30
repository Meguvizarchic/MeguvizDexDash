import ctypes, hashlib, importlib.util, json, os, re, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3];folder=Path(__file__).resolve().parent
if len(sys.argv)!=2 or sys.argv[1] not in ('probe2','probe3','probe4','probe5','probe6'):raise ValueError('a new named probe is required')
name=sys.argv[1];probe=folder/(name+'.py');source=ROOT/'benchmarks/a2_compact_adapter.py'
class Memory(ctypes.Structure):
 _fields_=[('length',ctypes.c_uint32),('load',ctypes.c_uint32)]+[(x,ctypes.c_uint64) for x in ('total','available','page_total','page_available','virtual_total','virtual_available','extended')]
m=Memory();m.length=ctypes.sizeof(m)
if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(m)):raise RuntimeError('cannot observe memory')
report={'minimum_available_bytes':str(3*1024**3),'available_bytes':str(m.available),'probe_sha256':hashlib.sha256(probe.read_bytes()).hexdigest(),'adapter_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),'scope':'small synthetic real A1 transport; no performance or full audit qualification'}
if m.available<3*1024**3:
 report['status']='blocked_by_memory';(folder/(name+'-admission.json')).write_text(json.dumps(report,indent=2)+'\n',encoding='utf8');print(report['status']);raise SystemExit(2)
spec=importlib.util.spec_from_file_location('job',ROOT/'artifacts/mdd-005/preparation-20261028/windows_job.py');job=importlib.util.module_from_spec(spec);spec.loader.exec_module(job)
env={k:v for k,v in os.environ.items() if not re.search(r'TOKEN|SECRET|PASSWORD|API_KEY',k,re.I)}
result=job.run_job([str(ROOT/'artifacts/local/baseline-venv/Scripts/python.exe'),str(probe)],folder/(name+'-run'),cwd=ROOT,env=env,timeout_seconds=45,memory_bytes=2*1024**3,affinity_mask=15,max_processes=8,max_log_bytes=4*1024**2)
report['job']=result;report['adapter_unchanged']=hashlib.sha256(source.read_bytes()).hexdigest()==report['adapter_sha256'];report['status']='completed' if result['status']=='completed' and result['tree_empty_verified'] and report['adapter_unchanged'] else 'failed';(folder/(name+'-admission.json')).write_text(json.dumps(report,indent=2)+'\n',encoding='utf8');print(json.dumps({'status':report['status'],'exit':result['exit_code'],'tree_empty':result['tree_empty_verified']}))
raise SystemExit(0 if report['status']=='completed' else 1)
