from pathlib import Path
import asyncio,hashlib,importlib.util,json,sys
from mcp import Client
from mcp.client.stdio import StdioServerParameters
ROOT=Path(__file__).resolve().parents[3]
def module(name,path):
 spec=importlib.util.spec_from_file_location(name,ROOT/path);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
adapter=module('a2_adapter','benchmarks/a2_compact_adapter.py')
legacy=module('a2_legacy','artifacts/mdd-005/preparation-20261028/a2_compact_fixture_probe.py')
paging=module('fixed_hostlab_paging','conformance/corpus/hostlab/source-8782f43/analysis_paging.py')
fixture=(ROOT/'tests/fixtures/generated/minimal-035.dex').resolve()
engine=(ROOT/'artifacts/local/baseline-engines/A1-0.1.1-windows/dexsql-windows-amd64.exe').resolve()
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
initial=sha(fixture)
if sha(engine)!='602105c98232120c14d6124fb33574f2f95f12e50e51d25b8834f893925f28d6':raise RuntimeError('engine identity mismatch')
def verify_source():
 if sha(fixture)!=initial:raise RuntimeError('fixture changed')
async def main():
 params=StdioServerParameters(command=str(engine),args=['--threads','2','mcp','--max-datasets','1','--timeout-ms','5000'])
 async with asyncio.timeout(30),Client(params) as client:
  opened=legacy.raw_result(await client.call_tool('open_dataset',{'inputs':[str(fixture)]}),False);dataset=opened['dataset_id']
  try:
   sql='SELECT string_pool_id,string_idx,value FROM strings ORDER BY string_pool_id,string_idx'
   original=await legacy.consume(client,dataset,sql,False)
   query=adapter.CompactRowsAdapter(client,dataset,verify_source=verify_source,continuation_reason=paging.continuation_reason,timeout=20)
   try:
    rows=await query.rows(sql,page_size=2)
   except adapter.CompactAdapterError as exc:
    print(json.dumps({'adapter_error':str(exc),'producer_detail':exc.producer_detail},ensure_ascii=False),flush=True)
    raise
   expected=[dict(zip(original['columns'],row)) for row in original['rows']]
   if rows!=expected:raise RuntimeError('complete CLI DTO differs from standard MCP')
   if query.queries!=1:raise RuntimeError('query count mismatch')
   print(json.dumps({'status':'complete','fixture_sha256':initial,'engine_sha256':sha(engine),'rows':len(rows),'queries':query.queries,'scope':'synthetic real A1 MCP; no full audit or performance qualification'}))
  finally:
   await client.call_tool('close_dataset',{'dataset_id':dataset})
asyncio.run(main())

