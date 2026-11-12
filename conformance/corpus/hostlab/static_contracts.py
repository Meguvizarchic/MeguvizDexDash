"""Static projection contracts; no engine results or query execution."""
import ast
import hashlib
import json

RANGES = {
 "Q01": [("native_cli.py",42,42),("native_graph.py",127,127),("analysis_batch.py",141,141)],
 "Q02": [("native_graph.py",196,196),("native_graph.py",200,200),("native_graph.py",214,214)],
 "Q03": [("native_graph.py",226,226)],
 "Q04": [("native_graph.py",128,128),("native_graph.py",137,137),("native_graph.py",143,143),("native_graph.py",151,151),("native_graph.py",154,154),("native_graph.py",161,161)],
 "Q05": [("native_graph.py",291,291)], "Q06": [("native_rules.py",56,57)],
 "Q07": [("native_audit.py",29,29)],
 "Q08": [("native_surface.py",77,77),("native_surface.py",87,87),("native_surface.py",91,91)],
 "Q09": [("native_surface.py",57,58)], "Q10": [("native_surface.py",126,126)],
 "Q11": [("native_surface.py",137,137)],
 "Q12": [("analysis_plan.py",170,170),("analysis_plan.py",176,176),("analysis_plan.py",179,180),("analysis_plan.py",186,187)],
 "Q13": [("native_cli.py",117,117),("native_cli.py",143,143),("native_cli.py",149,149)],
 "Q14": [], "Q15": [("analysis_plan.py",176,176),("dexq/server.py",216,219),("dexq/server.py",358,359),("dexq/server.py",412,424)], "Q16": []
}


def expression_nodes(text):
    tree = ast.parse(text)
    parent = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    result = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Constant) or not isinstance(node.value, str) or "SELECT " not in node.value: continue
        current = node
        while current in parent and (isinstance(parent[current], ast.JoinedStr) or isinstance(parent[current], ast.BinOp) and isinstance(parent[current].op, ast.Add)):
            current = parent[current]
        result[(current.lineno,current.end_lineno)] = current
    return list(result.values())


def assemble_pinned_sql(node, in_list, descriptor, owners):
    """Rebuild a pinned SQL expression from its AST without executing it.

    Only string constants, `+` concatenation, and the single accepted helper
    shape `in_list(map(descriptor, owners))` are understood. Any other node
    raises, so this cannot silently widen into general evaluation.
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return assemble_pinned_sql(node.left, in_list, descriptor, owners) + \
            assemble_pinned_sql(node.right, in_list, descriptor, owners)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'in_list':
        if len(node.args) != 1:
            raise RuntimeError('pinned SQL: in_list arity changed')
        inner = node.args[0]
        if not (isinstance(inner, ast.Call) and isinstance(inner.func, ast.Name)
                and inner.func.id == 'map' and len(inner.args) == 2):
            raise RuntimeError('pinned SQL: unexpected in_list argument shape')
        mapper, values = inner.args
        if not (isinstance(mapper, ast.Name) and mapper.id == 'descriptor'):
            raise RuntimeError('pinned SQL: unexpected map mapper')
        if not (isinstance(values, ast.Name) and values.id == 'owners'):
            raise RuntimeError('pinned SQL: unexpected map source')
        return in_list(descriptor(owner) for owner in owners)
    raise RuntimeError('pinned SQL: node ' + type(node).__name__ + ' is outside the static assembler')


def enrich(corpus, relations, source, root):
    schemas = {r["name"]: r["columns"] for r in relations}
    sources = {}
    for names in RANGES.values():
        for name,_,_ in names:
            if name not in sources:
                text = (source/name).read_text(encoding="utf-8")
                sources[name] = (text, expression_nodes(text))
    def cols(table,*names):
        lookup={x["name"]:x for x in schemas[table]}
        return [dict(lookup[n],ordinal=i) for i,n in enumerate(names)]
    def wildcard(table):
        return [dict(x,ordinal=i) for i,x in enumerate(schemas[table])]
    def renamed(table,name,alias):
        return [dict(cols(table,name)[0],name=alias)]
    uint=lambda name: {"name":name,"data_type":"UInt64","nullable":False,"ordinal":0,"type_basis":"reference 0.1.0 recorded COUNT(*) metadata, not new execution"}
    variants = {
      "Q01": [{"label":"inventory", "columns":cols("dex_files","file_id","entry_name")},{"label":"pool_mapping","columns":cols("dex_files","file_id","string_pool_id")}],
      "Q02": [{"label":"cf_wildcard","columns":wildcard("class_fields")},{"label":"cm_wildcard","columns":wildcard("class_methods")},{"label":"class_meta","columns":cols("classes","file_id","class_idx","descriptor","access_flags","superclass_descriptor")}],
      "Q03": [{"label":"interface_join","columns":[dict(cols("class_interfaces","interface_descriptor")[0],ordinal=0),dict(cols("classes","descriptor")[0],ordinal=1)]}],
      "Q04": [{"label":"Signature_type","columns":cols("types","file_id","type_idx")},{"label":"directory","columns":cols("annotation_directory_entries","file_id","entry_kind","entry_idx","annotation_set_off")},{"label":"set_entries","columns":cols("annotation_set_entries","file_id","annotation_set_off","annotation_off")},{"label":"annotation_type","columns":cols("annotations","file_id","annotation_off","type_idx")},{"label":"elements","columns":cols("annotation_elements","file_id","annotation_off","ordinal","value_index")},{"label":"string_pool","columns":cols("strings","string_pool_id","string_idx","value")}],
      "Q05": [{"label":"return_discovery","columns":cols("methods","class_descriptor")}],
      "Q06": [{"label":"string_candidates","columns":cols("method_strings","file_id","method_idx","value")}],
      "Q07": [{"label":"class_count","columns":[uint("n")]}],
      "Q08": [{"label":"class_surface","columns":cols("classes","file_id","class_def_idx","descriptor","superclass_descriptor")},{"label":"field_surface","columns":cols("class_fields","file_id","class_descriptor","field_name","field_descriptor")},{"label":"method_surface","columns":cols("class_methods","file_id","class_descriptor","method_idx","method_name","method_descriptor")}],
      "Q09": [{"label":"raw_body_ranges","columns":cols("code_items","method_idx","insns_off","insns_size")}],
      "Q10": [{"label":"call_counts","columns":cols("method_calls","file_id","method","callee")+[dict(uint("n"),ordinal=3)]}],
      "Q11": [{"label":"protocol_definitions","columns":cols("class_methods","file_id","method_descriptor")}],
      "Q12": [{"label":"locate_class","columns":cols("classes","file_id","descriptor")},{"label":"locate_method","columns":cols("class_methods","file_id")+[dict(renamed("class_methods","method_descriptor","descriptor")[0],ordinal=1)]},{"label":"locate_field","columns":cols("class_fields","file_id")+[dict(renamed("class_fields","field_descriptor","descriptor")[0],ordinal=1)]}]+[{"label":"refs_"+kind,"columns":cols(table,"file_id")+[dict(renamed(table,"method","descriptor")[0],ordinal=1)]} for kind,table in [("string","method_strings"),("method","method_calls"),("field","method_field_accesses"),("type","method_used_types")]],
      "Q13": [{"label":"representative_shape","columns":cols("dex_files","file_id","entry_name"),"rows":0},{"label":"hex_value_wrapper","columns":[{"name":n,"ordinal":i,"data_type":"Utf8","nullable":False,"value_encoding":"N for NULL, otherwise uppercase hex of CAST AS TEXT"} for i,n in enumerate(["file_id","entry_name"])]},{"label":"boundary","columns":[{"name":"hostlab_boundary","ordinal":0,"data_type":"Utf8","nullable":False}]}],
      "Q14": [{"label":"arbitrary_select_with","columns":"dynamic statement.columns from actual prepare result","metadata_contract":"name/data_type/nullable in exact projection ordinal; no duplicate columns merged; typed cell count must match; never inferred from base relation schema"}],
      "Q15": [{"label":"legacy_locate_method","columns":[{"name":"file_id","ordinal":0,"data_type":"SQLite INTEGER","nullable":True},{"name":"descriptor","ordinal":1,"data_type":"SQLite TEXT","nullable":True}]}],
      "Q16": [{"label":"native_statement_results","columns":"per-statement dynamic metadata from reference MCP tool response","metadata_contract":"statement_index/kind/columns/rows/total_rows/offset/next_offset/truncated; schema is session TEMP-generation dependent"}]
    }
    def literal(value):
        # Same rule as the pinned native_session.literal: reject control
        # characters, then single-quote with doubled internal quotes.
        if any(c in value for c in "\r\n\0"):
            raise ValueError("audit SQL literal contains unsupported control characters")
        return "'" + value.replace("'", "''") + "'"

    def in_list(values):
        return ",".join(literal(value) for value in values)

    def descriptor(name):
        return 'L' + name.replace('.', '/') + ';'

    owners = ['fixture.A']
    rule_text = (source / 'native_rules.py').read_text()
    q6node = next(n for n in expression_nodes(rule_text) if n.lineno == 56)
    # The pinned Q06 statement is a concatenation of string constants and the
    # in_list(map(descriptor, owners)) helper result. Rebuild it from the AST
    # instead of evaluating the frozen expression: only constants and that one
    # helper call are accepted, so no pinned source is ever executed here.
    exact_q6 = assemble_pinned_sql(q6node, in_list, descriptor, owners)
    for q in corpus:
        expr=[]
        for name,lo,hi in RANGES[q['id']]:
            text,nodes=sources[name]
            for n in nodes:
                if n.lineno<=hi and n.end_lineno>=lo:
                    value={"line":n.lineno,"end_line":n.end_lineno,"expression":ast.get_source_segment(text,n),"expression_kind":type(n).__name__,"source":{"path":(source/name).relative_to(root).as_posix(),"source_commit":"8782f43d537c442905123e35af325c412caa5188","sha256":hashlib.sha256((source/name).read_bytes()).hexdigest()},"execution_status":"static_source_only"}
                    if value not in expr:expr.append(value)
        q['source_expressions']=expr
        q['return_contract']={"schema_origin":"static projection from exact frozen source plus reference relation columns; not an observed result schema", "variants":variants[q['id']],"native_mcp_integer_representation":"exact decimal strings for int64/uint64", "cli_adapter_cell_type":"str or None after strict UTF-8 hex decoding", "null_and_empty_distinct":True}
        q.pop('blocking_reason',None)
        q['runtime_goldens_status']='not_run; production qualification separately blocked, static task does not require production golden'
        if q['id']=='Q06':
            q['representative_sql']=exact_q6
            q['representative_parameter_source']='actual frozen Python SQL expression evaluated with owners=[fixture.A] and original literal/in_list helpers; not an engine execution'
        if q['id'] in {'Q08','Q10'}:
            q['representative_sql']=q['representative_sql'].replace("ESCAPE '\\\\'", "ESCAPE '\\'")
        if q['id']=='Q12':
            q['representative_projection_schema']=next(v['columns'] for v in variants['Q12'] if v['label']=='refs_method')
        elif q['id']=='Q13':
            q['representative_projection_schema']=variants['Q13'][0]['columns']
        elif q['id']=='Q04':
            q['representative_projection_schema']=variants['Q04'][4]['columns']
        else:
            q['representative_projection_schema']=variants[q['id']][0].get('columns')
        if q['id'] in {'Q08','Q10','Q11'}:
            helper_text=(source/'native_surface.py').read_text(encoding='utf-8')
            q['sql_construction_helpers']=[{"source":'source-8782f43/native_surface.py',"line":42,"end_line":46,"code":'\n'.join(helper_text.splitlines()[41:46])},{"source":'source-8782f43/native_surface.py',"line":12,"end_line":29,"code":'\n'.join(helper_text.splitlines()[11:29])}]
        if q['id']=='Q14':
            refs=[]
            for filename,lo,hi in [('analysis_plan.py',64,75),('analysis_paging.py',20,46),('analysis_paging.py',49,77),('analysis_batch.py',149,159),('analysis_batch.py',167,182)]:
                text=(source/filename).read_text(encoding='utf-8')
                refs.append({'source':(source/filename).relative_to(root).as_posix(),'line':lo,'end_line':hi,'code':'\n'.join(text.splitlines()[lo-1:hi])})
            q['dynamic_sql_contract_sources']=refs
        if q['id']=='Q16':
            evidence=root/'evidence/compatibility/0.1.0/mcp-records.json'
            records=json.loads(evidence.read_text())
            q['historical_request_examples']=[{'source':evidence.relative_to(root).as_posix(),'record_index':i,'record_kind':'historical_request_only','request':records[i]['message']} for i in [54,58,62,66,70,74]]
            q['native_query_input_schema_source']='conformance/manifests/tools-and-options.json#/native_mcp/0.1.0/query'
        q['parameter_ranges']={"query_request":{"sql_characters_max":12000,"limit":[1,1000],"offset":[0,99000],"automatic_page_budget":{"default_max_pages":8,"default_max_rows":1000,"max_bytes":1048576}},"audit":{"timeout_seconds":900,"sql_bytes_max":262144,"default_complete_row_budget":500000,"decoded_bytes_max":134217728,"method_calls_rows_max":1000000,"method_calls_decoded_bytes_max":268435456},"local_ids":"nonnegative and checked against the bound snapshot's actual inventory; arbitrary synthetic examples do not expand valid ID ranges"}
    return corpus
