"""Project-authored DEX definition fixtures; Python stdlib only.

The semantic expectations are hand-maintained in expected.json. This encoder
is independent of mdd-dex and is not a DEX runtime verifier.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import struct
import zlib

HERE=Path(__file__).resolve().parent
A="Lfixture/Base;"; B="Lfixture/Child;"; E="Lfixture/External;"; I="Lfixture/I0;"; J="Lfixture/I1;"; O="Ljava/lang/Object;"; ARRAY="[Lfixture/Base;"
FIELDS=[(A,"iValue","I"),(A,"mValue","I"),(A,"sValue","I"),(A,"zStatic","I"),(B,"childRef",A),(E,"outside","I")]
METHODS=[(A,"<init>","V",()),(A,"nativeCall","V",()),(A,"privateCall","V",()),(A,"staticCall","I",("I",)),(A,"virtualCall","V",()),(B,"<init>","V",()),(B,"abstractCall","V",()),(B,"overrideCall","I",("I",)),(E,"externalCall","I",("I",)),(I,"iMethod","V",()),(J,"jMethod","V",()),(O,"<init>","V",()),(ARRAY,"clone",O,())]
CLASS_ORDER=[I,J,A,B]
INTERFACES={I:(),J:(I,),A:(J,),B:()}
FIELD_DEFS={A:{"static":[("sValue",9),("zStatic",9)],"instance":[("iValue",1),("mValue",1)]},B:{"static":[],"instance":[("childRef",1)]}}
METHOD_DEFS={I:{"direct":[],"virtual":[("iMethod",0x401)]},J:{"direct":[],"virtual":[("jMethod",0x401)]},A:{"direct":[("<init>",0x10001),("nativeCall",0x109),("privateCall",2),("staticCall",9)],"virtual":[("virtualCall",1)]},B:{"direct":[("<init>",0x10001)],"virtual":[("abstractCall",0x401),("overrideCall",1)]}}


def leb(value):
    out=bytearray()
    while True:
        part=value&127;value>>=7;out.append(part|(128 if value else 0))
        if not value:return bytes(out)


def build(case="definitions-035"):
    output_class_order=([O]+CLASS_ORDER) if case=='nullable-root-class' else list(CLASS_ORDER)
    descriptors=sorted({"I","V",A,B,E,I,J,O,ARRAY})
    prototypes=sorted({(ret,args) for _,_,ret,args in METHODS},key=lambda x:(descriptors.index(x[0]),tuple(descriptors.index(t) for t in x[1])))
    shorty=lambda r,args:("L" if r.startswith(("L","[")) else r)+"".join("L" if t.startswith(("L","[")) else t for t in args)
    extra={"\ud800"} if case in {"source-file-surrogate","invalid-member-surrogate"} else set()
    text=sorted(set(descriptors)|{n for _,n,_ in FIELDS}|{n for _,n,_,_ in METHODS}|{shorty(r,a) for r,a in prototypes}|{"Base.java","Child.java","I0.java","I1.java"}|extra)
    sx={s:i for i,s in enumerate(text)};tx={s:i for i,s in enumerate(descriptors)};px={p:i for i,p in enumerate(prototypes)}
    fields=sorted(FIELDS,key=lambda f:(tx[f[0]],sx[f[1]],tx[f[2]]))
    methods=sorted(METHODS,key=lambda m:(tx[m[0]],sx[m[1]],px[(m[2],m[3])]))
    fi={(o,n):i for i,(o,n,_) in enumerate(fields)};mi={(o,n):i for i,(o,n,_,_) in enumerate(methods)}
    counts=[len(text),len(descriptors),len(prototypes),len(fields),len(methods),len(output_class_order)]
    strides=[4,4,12,8,8,32];offsets=[];cursor=112
    for count,stride in zip(counts,strides):offsets.append(cursor);cursor+=count*stride
    data_off=(cursor+3)&~3;data=bytearray();sections=[]
    absolute=lambda:data_off+len(data)
    def align():
        while absolute()%4:data.append(0)
    lists={}
    all_lists=[]
    for _,args in prototypes:
        if args and args not in all_lists:all_lists.append(args)
    for owner in CLASS_ORDER:
        interfaces=INTERFACES[owner]
        if case=="duplicate-interface" and owner==J:interfaces=(I,I)
        if case=="two-interfaces" and owner==A:interfaces=(I,J)
        if interfaces and interfaces not in all_lists:all_lists.append(interfaces)
    if all_lists:
        align();sections.append((0x1001,len(all_lists),absolute()))
        for values in all_lists:
            align();lists[values]=absolute();data.extend(struct.pack("<I",len(values)))
            data.extend(struct.pack("<"+"H"*len(values),*(tx[t] for t in values)))
    sections.append((0x2002,len(text),absolute()));string_offsets=[]
    for value in text:
        string_offsets.append(absolute());encoded=value.encode('utf-16-le','surrogatepass');units=struct.unpack('<'+'H'*(len(encoded)//2),encoded)
        raw=bytearray()
        for unit in units:
            if 1<=unit<=127:raw.append(unit)
            elif unit<=2047:raw.extend([0xc0|(unit>>6),0x80|(unit&63)])
            else:raw.extend([0xe0|(unit>>12),0x80|((unit>>6)&63),0x80|(unit&63)])
        data.extend(leb(len(units))+raw+b"\0")
    align();code_start=absolute();code_offsets={};code_count=0
    for owner,name,ret,args in methods:
        if (owner,name) not in {(o,n) for o,groups in METHOD_DEFS.items() for group in groups.values() for n,_ in group}:continue
        flags=next(flags for n,flags in METHOD_DEFS[owner]['direct']+METHOD_DEFS[owner]['virtual'] if n==name)
        if flags&(0x100|0x400):continue
        align();code_offsets[(owner,name)]=absolute();code_count+=1
        is_static=bool(flags&8);ins=len(args)+(0 if is_static else 1);registers=ins
        if name=="<init>":
            target=O if owner==A else A;words=[0x1070,mi[(target,"<init>")],0,0x0e];outs=1
        else:words=[0x0e] if ret=="V" else [((registers-1)<<8)|0x0f];outs=0
        if case=="zero-insns-present" and owner==A and name=="privateCall":words=[]
        data.extend(struct.pack("<HHHHII",registers,ins,outs,0,0,len(words)))
        data.extend(struct.pack("<"+"H"*len(words),*words))
    sections.append((0x2001,code_count,code_start))
    class_data_start=absolute();class_offsets={};layout={}
    for owner in CLASS_ORDER:
        if case=='shared-empty-class-data' and owner==J:
            class_offsets[owner]=class_offsets[I];layout[owner]=layout[I];continue
        class_offsets[owner]=absolute();start=absolute()
        fgroups=FIELD_DEFS.get(owner,{"static":[],"instance":[]})
        mgroups=METHOD_DEFS[owner]
        groups=[list(fgroups['static']),list(fgroups['instance']),list(mgroups['direct']),list(mgroups['virtual'])]
        if case in {"empty-class-data","shared-empty-class-data"} and owner==I:groups=[[],[],[],[]]
        for group in groups:data.extend(leb(len(group)))
        local_layout={}
        for kind,group in zip(['static','instance','direct','virtual'],groups):
            previous=0;local_layout[kind]=[]
            for ordinal,(name,flags) in enumerate(group):
                is_field=kind in {'static','instance'}
                index=(fi if is_field else mi)[(owner,name)]
                delta=index-previous
                if case=="duplicate-field-delta" and owner==A and kind=='static' and ordinal==1:delta=0
                if case=="field-delta-overflow" and owner==A and kind=='static' and ordinal==1:delta=0xffffffff
                if case=="method-delta-overflow" and owner==B and kind=='virtual' and ordinal==1:delta=0xffffffff
                if case=="field-index-out-of-range" and owner==A and kind=='static' and ordinal==0:delta=len(fields)
                if case=="method-index-out-of-range" and owner==A and kind=='direct' and ordinal==0:delta=len(methods)
                if case=="wrong-method-owner" and owner==A and kind=='direct' and ordinal==0:delta=mi[(B,'<init>')]
                if case=="wrong-field-owner" and owner==A and kind=='static' and ordinal==0:delta=fi[(B,'childRef')]
                if case=="static-flag-mismatch" and owner==A and kind=='static' and ordinal==0:flags=1
                if case=="virtual-flag-mismatch" and owner==A and kind=='virtual':flags=9
                if case=="virtual-native-no-body" and owner==A and kind=='virtual':flags=0x101
                if case=="duplicate-method-layout" and owner==A and kind=='virtual':index=mi[(A,'staticCall')];delta=index
                at=absolute();data.extend(leb(delta)+leb(flags));code=None
                if not is_field:
                    code=code_offsets.get((owner,name),0)
                    if case=="native-with-code" and owner==A and name=='nativeCall':code=code_offsets[(A,'privateCall')]
                    if case=="concrete-no-body" and owner==A and name=='privateCall':code=0
                    if case=="virtual-native-no-body" and owner==A and kind=='virtual':code=0
                    data.extend(leb(code))
                local_layout[kind].append({'ordinal':ordinal,'name':name,'reference_idx':index,'delta':delta,'byte_offset':at,'access_flags':flags,'code_off':code})
                previous=index
        layout[owner]={'byte_offset':start,'byte_end':absolute(),'groups':local_layout}
    orphan_count=0
    if case.startswith('orphan-'):
        orphan_count=1
        if case=='orphan-empty':
            data.extend(b'\x00\x00\x00\x00')
        elif 'field' in case:
            index=len(fields) if case=='orphan-field-index' else fi[(E,'outside')]
            if case=='orphan-field-defined-owner':index=fi[(A,'sValue')]
            flags=1 if case=='orphan-field-flags' else 9
            data.extend(b'\x01\x00\x00\x00'+leb(index)+leb(flags))
        else:
            count=2 if case=='orphan-method-delta' else 1
            index=len(methods) if case=='orphan-method-index' else mi[(E,'externalCall')]
            if case=='orphan-method-defined-owner':index=mi[(A,'nativeCall')]
            flags=0x101 if case=='orphan-method-kind' else 0x109
            data.extend(b'\x00\x00'+leb(count)+b'\x00'+leb(index)+leb(flags)+b'\x00')
            if count==2:data.extend(leb(0xffffffff)+leb(flags)+b'\x00')
    sections.append((0x2000,len(set(class_offsets.values()))+orphan_count,class_data_start))
    align();map_off=absolute()
    map_rows=[(0,1,0)]+[(kind,count,off) for kind,count,off in zip(range(1,7),counts,offsets)]+sections+[(0x1000,1,map_off)]
    map_rows.sort(key=lambda row:row[2]);data.extend(struct.pack('<I',len(map_rows)))
    for kind,count,off in map_rows:data.extend(struct.pack('<HHII',kind,0,count,off))
    version=case.rsplit('-',1)[1] if case in {'definitions-037','definitions-038','definitions-039','definitions-040'} else '035'
    out=bytearray(data_off)+data;out[:8]=b'dex\n'+version.encode()+b'\0'
    struct.pack_into('<20I',out,32,len(out),112,0x12345678,0,0,map_off,*[x for pair in zip(counts,offsets) for x in pair],len(data),data_off)
    for i,offset in enumerate(string_offsets):struct.pack_into('<I',out,offsets[0]+4*i,offset)
    for i,descriptor in enumerate(descriptors):struct.pack_into('<I',out,offsets[1]+4*i,sx[descriptor])
    for i,(ret,args) in enumerate(prototypes):struct.pack_into('<III',out,offsets[2]+12*i,sx[shorty(ret,args)],tx[ret],lists.get(args,0))
    for i,(owner,name,typ) in enumerate(fields):struct.pack_into('<HHI',out,offsets[3]+8*i,tx[owner],tx[typ],sx['\ud800'] if case=='invalid-member-surrogate' and owner==E else sx[name])
    for i,(owner,name,ret,args) in enumerate(methods):struct.pack_into('<HHI',out,offsets[4]+8*i,tx[owner],px[(ret,args)],sx[name])
    class_order=output_class_order
    if case=='inheritance-order':class_order=[I,J,B,A]
    for i,owner in enumerate(class_order):
        class_index=tx[owner]
        if case=='duplicate-class' and i==1:class_index=tx[I]
        superclass=A if owner==B else O
        interfaces=INTERFACES.get(owner,())
        if case=='duplicate-interface' and owner==J:interfaces=(I,I)
        if case=='two-interfaces' and owner==A:interfaces=(I,J)
        class_data=class_offsets.get(owner,0)
        if case=='class-data-interior' and owner==A:class_data+=1
        if case=='shared-class-data' and owner==A:class_data=class_offsets[I]
        filename=owner.split('/')[-1][:-1]+'.java'
        if case=='source-file-surrogate' and owner==A:filename='\ud800'
        interface_off=lists.get(interfaces,0)
        if case=='interface-list-interior' and owner==A:interface_off=lists[("I",)]+4
        source_index=0xffffffff if owner==O else sx[filename]
        superclass_index=0xffffffff if owner==O else tx[superclass]
        struct.pack_into('<8I',out,offsets[5]+32*i,class_index,0x601 if owner in [I,J] else 1 if owner==O else 0x401,superclass_index,interface_off,source_index,0,class_data,0)
    out[12:32]=hashlib.sha1(out[32:]).digest();struct.pack_into('<I',out,8,zlib.adler32(out[12:]))
    return bytes(out),{'field_indices':{o+'->'+n:i for (o,n),i in fi.items()},'method_indices':{o+'->'+n:i for (o,n),i in mi.items()},'class_data':layout,'type_indices':tx,'class_order':class_order}


def main():
    # This copy of the project generator builds only the extra valid fixture
    # used to exercise class_interfaces.ordinal 0/1.  The project generator is
    # not modified; the copy lives entirely in this evidence directory.
    generated=HERE/'fixtures'/'generated';generated.mkdir(parents=True,exist_ok=True)
    cases={'two-interfaces':'two_distinct_interfaces'}
    records=[]
    for name,expected in cases.items():
        data,layout=build(name);path=generated/(name+'.dex');path.write_bytes(data)
        records.append({'id':name,'path':path.relative_to(HERE).as_posix(),'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'expected':expected,'layout':layout})
    (HERE/'fixtures'/'two-interfaces.manifest.json').write_text(json.dumps({'schema_version':'mdd.evidence-two-interfaces-fixture.v1','generator':'artifacts/mdd-026/evidence-definition-members-fix-20261111/generate_two_interfaces.py','derived_from':'tests/fixtures/definitions/generate.py','source_url':'https://source.android.com/docs/core/runtime/dex-format','runtime_installability_verified':False,'files':records},indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'fixtures_generated':len(records),'ids':list(cases),'scope':'valid DEX with one class implementing two distinct interfaces (ordinal 0/1)'}))

if __name__=='__main__':main()
