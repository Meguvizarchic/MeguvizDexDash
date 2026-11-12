#!/usr/bin/env python3
"""Verify retained class-body recipes using unchanged HostLab ordering and A0 raw ranges."""
from pathlib import Path
import ast
import hashlib
import json
import re
import subprocess
import zipfile

ROOT=Path(__file__).resolve().parents[2]
SQL=("SELECT d.entry_name,c.class_def_idx,c.descriptor,"
     "CASE WHEN cm.method_idx IS NULL THEN 'N' ELSE cm.method_descriptor END AS method_descriptor,"
     "CASE WHEN ci.insns_off IS NULL THEN 'N' ELSE CAST(ci.insns_off AS TEXT) END AS insns_off,"
     "CASE WHEN ci.insns_size IS NULL THEN 'N' ELSE CAST(ci.insns_size AS TEXT) END AS insns_size "
     "FROM classes c JOIN dex_files d ON d.file_id=c.file_id "
     "LEFT JOIN class_methods cm ON cm.file_id=c.file_id AND cm.class_idx=c.class_idx "
     "LEFT JOIN code_items ci ON ci.file_id=cm.file_id AND ci.method_idx=cm.method_idx "
     "ORDER BY c.file_id,c.class_def_idx,cm.method_idx")


def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def require(condition,message):
    if not condition:raise ValueError(message)


def main():
    apk=ROOT/'artifacts/local/inputs/NewPipe_v0.28.6.apk';input_sha='e56ef6280b700696172797f94513ffd3f9aae9349945a2f06e235ec24446be58'
    registry=json.loads((ROOT/'conformance/manifests/engine-binaries.json').read_text(encoding='utf8'))
    item=next(x for x in registry['binaries'] if x['group']=='A0' and x['platform']=='windows_amd64');binary=Path(item['actual_path'])
    require(digest(apk)==input_sha and digest(binary)==item['expected_sha256'],'identity differs')
    source_path=ROOT/'conformance/corpus/hostlab/source-8782f43/native_surface.py'
    # Mirror the pinned native_surface.legacy_body_order rule directly. The
    # frozen function is pure string handling over a method prototype, so this
    # reimplements it rather than compiling and running pinned source here.
    def order(proto):
        parameters, result = proto[1:].split(")", 1)
        tokens = re.findall(r"\[*(?:[ZBSCIJFD]|L[^;]+;)", parameters)
        if "".join(tokens) != parameters:
            raise ValueError("method prototype cannot preserve the legacy bytecode fingerprint ordering")
        return "(" + " ".join(tokens) + ")" + result
    argv=[str(binary),'--threads','1','query','--input',str(apk),'--sql',SQL]
    run=subprocess.run(argv,capture_output=True,check=False,timeout=180)
    out=ROOT/'artifacts/mdd-025/raw-fingerprints/legacy-class-recipes';out.mkdir(parents=True,exist_ok=True)
    (out/'reference-stdout.txt').write_bytes(run.stdout);(out/'reference-stderr.txt').write_bytes(run.stderr)
    require(run.returncode==0 and len(run.stdout)<256*1024*1024,'reference query failed or output budget exceeded')
    rows=[]
    for line in run.stdout.decode('utf8','strict').splitlines():
        line=line.strip()
        if line.startswith('|') and line.endswith('|'):rows.append([x.strip() for x in line[1:-1].split('|')])
    require(rows and rows[0]==['entry_name','class_def_idx','descriptor','method_descriptor','insns_off','insns_size'],'schema differs')
    classes={};raw={}
    with zipfile.ZipFile(apk) as archive:
        for row in rows[1:]:
            require(len(row)==6,'ambiguous row');member,index,owner,method,off,size=row;key=(member,int(index))
            record=classes.setdefault(key,{'descriptor':owner,'methods':[]});require(record['descriptor']==owner,'owner collision')
            if method=='N':require(off=='N' and size=='N','empty class has body');continue
            tail=method.split('->',1)[1];name,proto_tail=tail.split('(',1);proto='('+proto_tail
            payload=b''
            if off!='N':
                if member not in raw:raw[member]=archive.read(member)
                offset=int(off);units=int(size);require(offset>=0 and offset+units*2<=len(raw[member]),'range invalid')
                payload=raw[member][offset:offset+units*2]
            record['methods'].append(((name,order(proto)),(name+proto).encode('utf8'),payload))
        by_member={}
        for (member,index),record in sorted(classes.items()):
            h=hashlib.sha256()
            for _,prefix,payload in sorted(record['methods'],key=lambda value:value[0]):h.update(prefix);h.update(payload)
            by_member.setdefault(member,[]).append({'class_def_idx':index,'descriptor':record['descriptor'],'method_bodies_sha256':h.hexdigest()})
        native_path=ROOT/'artifacts/mdd-025/raw-fingerprints/public-class-recipes/stdout.txt';native=json.loads(native_path.read_bytes())
        checks=[];members=archive.infolist()
        for record in native['selected_dexes']:
            name=members[int(record['member_id'].split(':member:')[1])].filename
            canonical=json.dumps(by_member[name],sort_keys=True,ensure_ascii=False,separators=(',',':')).encode('utf8');actual=hashlib.sha256(canonical).hexdigest()
            require(actual==record['legacy_class_recipe_sha256'] and len(by_member[name])==record['class_count'],'class recipe differs: '+name)
            checks.append({'member':name,'class_count':len(by_member[name]),'canonical_sha256':actual,'equal':True})
    require(digest(apk)==input_sha and digest(binary)==item['expected_sha256'],'source changed')
    result={'record_kind':'observed_legacy_class_body_recipe_comparison','checks':checks,'source_rule_commit':'8782f43d537c442905123e35af325c412caa5188','source_rule_sha256':digest(source_path),'input_sha256':input_sha,'reference_binary_sha256':digest(binary),'native_summary_sha256':digest(native_path),'scope':'all public class method-name/proto/legacy spaced-argument sort/raw-body concatenation only; no full HostLab or performance qualification'}
    (out/'comparison.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf8',newline='\n');print(json.dumps(result,indent=2))


if __name__=='__main__':main()
