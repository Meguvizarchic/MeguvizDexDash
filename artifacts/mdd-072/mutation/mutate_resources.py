#!/usr/bin/env python3
"""Mutation check for MDD-072: the resource tools must stay what the recorded answers of the reference engine say, and
what the contract says where the two differ on purpose.

It uses the machinery of artifacts/mdd-042/mutation/mutate_mcp.py (one source file edited in place per mutant, the
suites run, the original bytes written back in a finally block, commands with time limits, parts, assembly) with this
task's mutants and suites. A mutant is killed when the unit tests of mdd-input, mdd-service and mdd-mcp, the MCP
process tests or a replay fails; the replays include the comparison with the recorded reference answers
(conformance/mcp/resources_replay.py) against the mutated build and the controls that show that comparison can fail.

Usage: the same as mutate_mcp.py
  mutate_resources.py                     every mutant, then the clean-tree check
  mutate_resources.py --part K/N          the mutants whose position is K-1 modulo N
  mutate_resources.py --clean-only        only the clean-tree check and the hash
  mutate_resources.py --assemble FILE...  merge the parts and the clean-tree output
  mutate_resources.py --anchors           only say which mutants' anchors are not unique in their file
  mutate_resources.py NAME...             only the mutants whose name contains one of the words
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
_spec = importlib.util.spec_from_file_location("mutate_mcp", ROOT / "artifacts/mdd-042/mutation/mutate_mcp.py")
base = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(base)

PY = base.PY
INPUT = "crates/mdd-input/src/resources/"
VALUE, FRAMEWORK, XML, CONFIG, ARSC, QUERY = (INPUT + n for n in ("value.rs", "framework.rs", "xml.rs", "config.rs", "arsc.rs", "query.rs"))
SERVICE = "crates/mdd-service/src/resources.rs"
MANIFEST = "crates/mdd-service/src/manifest.rs"
TOOLS = "crates/mdd-mcp/src/resource_tools/"
COMMON, FILES, COMPONENTS, READ, QUERY_TOOL = (TOOLS + n for n in ("mod.rs", "files.rs", "components.rs", "read.rs", "query.rs"))
BINARY = "target/debug/meguvizdexdash" + (".exe" if sys.platform == "win32" else "")

# the suites of this task: the crates that hold the readers and the tools, the process tests, the replays
base.UNIT_MCP = [*base.CARGO, "-p", "mdd-input", "-p", "mdd-mcp", "-p", "mdd-service", "--lib", *base.TAIL]
base.REPLAYS = [
    *base.REPLAYS,
    ("resources", [PY, "-I", "conformance/mcp/resources_replay.py", "--binary", BINARY,
                   "--out", "artifacts/local/mdd-072-mutation-replay.json"]),
]
base.CONTROLS = [*base.CONTROLS, [PY, "-I", "conformance/mcp/test_resources_replay.py"]]
base.SOURCES = [
    *base.SOURCES, VALUE, FRAMEWORK, XML, CONFIG, ARSC, QUERY, INPUT + "mod.rs", INPUT + "tests.rs", INPUT + "arsc_tests.rs", INPUT + "xml_tests.rs", SERVICE,
    "crates/mdd-service/src/resources_tests.rs", "crates/mdd-service/src/components_tests.rs", COMMON, FILES,
    COMPONENTS, READ, QUERY_TOOL, "crates/mdd-input/src/manifest/mod.rs", "crates/mdd-input/src/manifest/axml.rs",
    "crates/mdd-mcp/src/tool_schemas.json", "conformance/mcp/resources_replay.py", "conformance/mcp/test_resources_replay.py",
    "conformance/mcp/resources-full-contract.json", "artifacts/mdd-072/a0-probe/calls.jsonl",
    "tests/fixtures/resources/generate.py", "tests/fixtures/resources/manifest.json",
]

MUTANTS = [
    # ---- how a compiled value is spelled
    ("value: dip is spelled dp", VALUE, [('"px", "dip", "sp", "pt", "in", "mm"', '"px", "dp", "sp", "pt", "in", "mm"')]),
    ("value: the fraction units are swapped", VALUE, [('["%", "%p"]', '["%p", "%"]')]),
    ("value: a radix constant is the f32 nearest", VALUE, [("3.051758E-5, 1.192093E-7", "3.0517578E-5, 1.192093E-7")]),
    ("value: the radix is read from the wrong bits", VALUE, [("RADIX_MULTS[((data >> 4) & 3) as usize]", "RADIX_MULTS[((data >> 4) & 1) as usize]")]),
    ("value: the mantissa keeps the low byte", VALUE, [("(data & 0xffff_ff00) as i32", "(data & 0xffff_ffff) as i32")]),
    ("value: a fraction is not scaled to percent", VALUE, [("complex(data) * 100.0", "complex(data)")]),
    ("value: a decimal integer is unsigned", VALUE, [("INT_DEC => (data as i32).to_string(),", "INT_DEC => data.to_string(),")]),
    ("value: a hex integer has no fixed width", VALUE, [('INT_HEX => format!("0x{data:08x}"),', 'INT_HEX => format!("0x{data:x}"),')]),
    ("value: a boolean is true only for one", VALUE, [('if data != 0 { "true" }', 'if data == 1 { "true" }')]),
    ("value: a colour has six digits", VALUE, [('format!("#{data:08x}")', 'format!("#{data:06x}")')]),
    ("value: a null has a fixed width", VALUE, [('format!("<0x{data:x}, type Null>")', 'format!("<0x{data:08x}, type Null>")')]),
    ("value: a prefixed reference loses its 0x", VALUE, [('ReferenceStyle::Prefixed => (format!("@0x{data:08x}"), format!("?0x{data:08x}")),', 'ReferenceStyle::Prefixed => (format!("@{data:08x}"), format!("?{data:08x}")),')]),
    ("value: a compact dynamic attribute is a reference", VALUE, [("ReferenceStyle::Compact => format!(\"<0x{data:x}, type DynamicAttribute>\"),", "ReferenceStyle::Compact => attribute,")]),
    ("value: a float is widened before it is written", VALUE, [("FLOAT => f32::from_bits(data).to_string(),", "FLOAT => f64::from(f32::from_bits(data)).to_string(),")]),
    ("value: ColorArgb8 is called ColorRgb8", VALUE, [('COLOR_ARGB8 => "ColorArgb8".to_owned(),', 'COLOR_ARGB8 => "ColorRgb8".to_owned(),')]),
    ("value: an unknown type is not written out", VALUE, [('other => format!("<0x{data:x}, type Unknown({other})>"),', 'other => format!("{data}"),')]),
    ("value: an unknown dimension unit is a bare number", VALUE, [('None => format!("<0x{data:x}, type Dimension, unit {}>", data & 15),', 'None => format!("{}", complex(data)),')]),
    # ---- the framework's named integers
    ("framework: privileged is called system", FRAMEWORK, [('(0x10, "privileged")', '(0x10, "system")')]),
    ("framework: a flag is named when any of its bits is set", FRAMEWORK, [("if left & flag == *flag {", "if left & flag != 0 {")]),
    ("framework: a named flag keeps its bits", FRAMEWORK, [("left &= !flag;", "left &= !0;")]),
    ("framework: foregroundServiceType is not named", FRAMEWORK, [('"foregroundServiceType" => flags(&FOREGROUND_SERVICE_TYPE, data),', '"foregroundServiceType" => None,')]),
    ("framework: mediaPlayback is dataSync", FRAMEWORK, [('(2, "mediaPlayback"),', '(2, "dataSync"),')]),
    ("framework: installLocation 1 is internal", FRAMEWORK, [('(1, "internalOnly")', '(1, "internal")')]),
    ("framework: launchMode 4 is called singleInstance", FRAMEWORK, [('(4, "singleInstancePerTask"),', '(4, "singleInstance"),')]),
    ("framework: zero is the empty flag word", FRAMEWORK, [("(!names.is_empty()).then(|| names.join(\"|\"))", "Some(names.join(\"|\"))")]),
    # ---- binary XML written as text
    ("xml: indentation is three spaces", XML, [('let indent = "  ".repeat(depth);', 'let indent = "   ".repeat(depth);')]),
    ("xml: an ampersand is not escaped", XML, [('\'&\' => out.push_str("&amp;"),', "'&' => out.push('&'),")]),
    ("xml: a double quote is escaped as an apostrophe", XML, [('\'"\' => out.push_str("&quot;"),', '\'"\' => out.push_str("&apos;"),')]),
    ("xml: a control character reference is lower case", XML, [('format!("&#x{:X};", c as u32)', 'format!("&#x{:x};", c as u32)')]),
    ("xml: a default namespace is written with a prefix", XML, [('None => "xmlns=\\"".to_owned(),', 'None => "xmlns:=\\"".to_owned(),')]),
    ("xml: an empty element is not closed", XML, [('out.push_str("/>\\n");', 'out.push_str(">\\n");')]),
    ("xml: a text node is not written", XML, [("escape(text, &mut out);", "let _ = text;")]),
    ("xml: an attribute may use the default namespace", XML, [(".find(|prefix| prefix.is_some() || !attribute);", ".find(|prefix| prefix.is_some() || attribute);")]),
    ("xml: a shadowed prefix is still chosen", XML, [("        !active[position + 1..]\n            .iter()\n            .any(|later| later.prefix == d.prefix)\n", "        true\n")]),
    ("xml: a named integer is only for a decimal one", XML, [("matches!(*kind, data_type::INT_DEC | data_type::INT_HEX)", "matches!(*kind, data_type::INT_DEC)")]),
    ("xml: a named integer in any namespace", XML, [("&& attribute.name.namespace_uri.as_deref() == Some(ANDROID_NS)", "")]),
    ("xml: an unpaired surrogate is replaced", XML, [('.ok_or_else(|| unrepresentable("string with an unpaired surrogate"))', ".or(Some(String::new())).ok_or_else(|| unrepresentable(\"\"))")]),
    ("xml: a namespaced name loses its prefix", XML, [('Some(Some(prefix)) => Ok(format!("{prefix}:{}", name.local_name)),', "Some(Some(_)) => Ok(name.local_name.clone()),")]),
    # ---- the configuration of a resource
    ("config: mnc 0xffff is mnc65535", CONFIG, [("if mnc == 0xffff {", "if mnc == 0xfffe {")]),
    ("config: a region has no r", CONFIG, [('format!("{language}-r{region}")', 'format!("{language}-{region}")')]),
    ("config: night is notnight", CONFIG, [('0x20 => parts.push("night".to_owned()),', '0x20 => parts.push("notnight".to_owned()),')]),
    ("config: 240 dpi is xhdpi", CONFIG, [('240 => parts.push("hdpi".to_owned()),', '240 => parts.push("xhdpi".to_owned()),')]),
    ("config: port and land are swapped", CONFIG, [('1 => parts.push("port".to_owned()),', '1 => parts.push("land".to_owned()),')]),
    ("config: the sdk is api", CONFIG, [('parts.push(format!("v{sdk}"));', 'parts.push(format!("api{sdk}"));')]),
    ("config: a packed language reads five bits wrong", CONFIG, [("base + (pair[1] & 0x1f),", "base + (pair[1] & 0x0f),")]),
    ("config: the smallest width is w", CONFIG, [('[(30, "sw"), (32, "w"), (34, "h")]', '[(30, "w"), (32, "w"), (34, "h")]')]),
    ("config: a record shorter than the old one is accepted", CONFIG, [("if size < 28 || size > bytes.len() {", "if size < 4 || size > bytes.len() {")]),
    ("config: a script does not make a BCP 47 tag", CONFIG, [("if script.is_empty() && variant.is_empty() && numbering.is_empty() {", "if variant.is_empty() && numbering.is_empty() {")]),
    # ---- resources.arsc
    ("arsc: rows are not in resource id order", ARSC, [(".cmp(&(b.package, b.resource_id))", ".cmp(&(b.package, 0))")]),
    ("arsc: configurations are in file order", ARSC, [(".cmp(&qualifiers[b.package][b.config_index])", ".cmp(&qualifiers[a.package][a.config_index])")]),
    ("arsc: configurations are in reverse order", ARSC, [("qualifiers[a.package][a.config_index]\n                        .cmp(&qualifiers[b.package][b.config_index])", "qualifiers[b.package][b.config_index]\n                        .cmp(&qualifiers[a.package][a.config_index])")]),
    ("arsc: the type id is not in the resource id", ARSC, [("(package_id << 24) | ((type_id as u32) << 16) | index as u32", "(package_id << 24) | index as u32")]),
    ("arsc: an absent entry is read", ARSC, [("if offset != NO_ENTRY {", "if offset != 0 {")]),
    ("arsc: a key at the end of the pool is accepted", ARSC, [("if key >= key_count {", "if key > key_count {")]),
    ("arsc: a map entry may be shorter than its header", ARSC, [("if size < 16 {", "if size < 8 {")]),
    ("arsc: a map item is eight bytes", ARSC, [("let p = first + item * 12;", "let p = first + item * 8;")]),
    ("arsc: a value may be shorter than eight bytes", ARSC, [("if size < 8 || u8_at(chunk, at + 2)? != 0 {", "if size < 4 || u8_at(chunk, at + 2)? != 0 {")]),
    ("arsc: a value's reserved byte is not checked", ARSC, [("|| u8_at(chunk, at + 2)? != 0 {", "{")]),
    ("arsc: the package count is a lower bound", ARSC, [("if declared_packages != table.packages.len() {", "if declared_packages > table.packages.len() {")]),
    ("arsc: a second global pool is accepted", ARSC, [('POOL => return Err(invalid("a second global string pool")),', "POOL => {}")]),
    ("arsc: a string index at the pool's end is accepted", ARSC, [("value.data as usize >= limit", "value.data as usize > limit")]),
    ("arsc: a sparse offset counts words", ARSC, [("((word >> 16) as usize) * 4", "((word >> 16) as usize) * 2")]),
    ("arsc: a 16-bit offset counts words", ARSC, [("usize::from(offset) * 4", "usize::from(offset) * 2")]),
    ("arsc: a chunk size need not be aligned", ARSC, [("|| !size.is_multiple_of(4)", "")]),
    ("arsc: the type id offset is ignored", ARSC, [(".checked_sub(1 + type_id_offset)", ".checked_sub(1)")]),
    ("arsc: a compact entry is read as a plain one", ARSC, [("if entry_flags & ENTRY_COMPACT != 0 {", "if false {")]),
    ("arsc: the entry budget is one too many", ARSC, [("> limits.max_entries {", "> limits.max_entries + 1 {")]),
    ("arsc: a table's size may be smaller than its bytes", ARSC, [("|| whole.len() != bytes.len() {", "|| whole.len() > bytes.len() {")]),
    ("arsc: a table with no global pool is accepted", ARSC, [("if !have_pool {", "if false {")]),
    # ---- queries over the table
    ("query: a package-qualified name ignores the package", QUERY, [("Some((qualifier, rest)) => qualifier == package && rest == local,", "Some((_, rest)) => rest == local,")]),
    ("query: a configuration matches by prefix", QUERY, [(".is_some_and(|c| c != configuration)", ".is_some_and(|c| !configuration.starts_with(c))")]),
    ("query: contains ignores case", QUERY, [(".is_some_and(|needle| !self.local_name(entry).contains(needle))", ".is_some_and(|needle| !self.local_name(entry).to_lowercase().contains(&needle.to_lowercase()))")]),
    ("query: a type matches by prefix", QUERY, [(".is_some_and(|t| t != self.type_name(entry))", ".is_some_and(|t| !self.type_name(entry).starts_with(t))")]),
    ("query: a reference is not named", QUERY, [('.map(|name| format!("@{name}"))', ".map(|name| name)")]),
    ("query: an item loses its parent", QUERY, [("                        name: self.qualified_name(name),\n                        parent_id: *parent,", "                        name: self.qualified_name(name),\n                        parent_id: 0,")]),
    ("query: an empty map entry is not a row", QUERY, [("EntryValue::Map { items, .. } if items.is_empty() => keys.push(RowKey {", "EntryValue::Map { items, .. } if false => keys.push(RowKey {")]),
    ("query: an empty map entry has no parent", QUERY, [("                    name: None,\n                    parent_id: *parent,", "                    name: None,\n                    parent_id: 0,")]),
    ("query: an item loses its attribute name", QUERY, [("name: self.qualified_name(name),", "name: None,")]),
    # ---- the archive and the dataset
    ("service: members are in reverse name order", SERVICE, [("a.0.cmp(&b.0).then(a.1.entry_index.cmp(&b.1.entry_index))", "b.0.cmp(&a.0).then(a.1.entry_index.cmp(&b.1.entry_index))")]),
    ("service: a directory entry is read as a file", SERVICE, [("if member.is_directory {", "if false {")]),
    ("service: the resource cap is doubled", SERVICE, [("    declared <= MAX_RESOURCE_BYTES\n", "    declared <= MAX_RESOURCE_BYTES * 2\n")]),
    ("service: binary XML is recognised by another magic", SERVICE, [("starts_with(&[3, 0, 8, 0])", "starts_with(&[3, 0, 9, 0])")]),
    ("service: hex is read as text", SERVICE, [("let (kind, text) = if hex {", "let (kind, text) = if false {")]),
    ("service: a hex read and a text read share a cache entry", SERVICE, [("let key = (input_index, name.to_owned(), hex);", "let key = (input_index, name.to_owned(), false);")]),
    ("service: a name is looked up by prefix", SERVICE, [(".filter(|member| member.raw_name == name.as_bytes())", ".filter(|member| member.raw_name.starts_with(name.as_bytes()))")]),
    ("service: several members of a name are read as the first", SERVICE, [("[one] => *one,", "[one, ..] => *one,")]),
    ("service: a table cache is shared by all inputs", SERVICE, [("self.cache()?.tables.get(&input_index)", "self.cache()?.tables.values().next()")]),
    # ---- the manifest's components
    ("components: a provider is exported at API 17", MANIFEST, [("Some(sdk) => (Some(sdk < 17), REASON_PROVIDER_DEFAULT),", "Some(sdk) => (Some(sdk <= 17), REASON_PROVIDER_DEFAULT),")]),
    ("components: API 31 still defaults to exported", MANIFEST, [("Some(sdk) if sdk < 31 => (Some(true), REASON_FILTER_DEFAULT),", "Some(sdk) if sdk <= 31 => (Some(true), REASON_FILTER_DEFAULT),")]),
    ("components: a component without a filter is exported", MANIFEST, [("return (Some(false), REASON_FILTER_DEFAULT);", "return (Some(true), REASON_FILTER_DEFAULT);")]),
    ("components: a launcher needs only one of the two", MANIFEST, [("&& categories\n                    .iter()\n                    .any(|c| c == \"android.intent.category.LAUNCHER\");", "|| categories\n                    .iter()\n                    .any(|c| c == \"android.intent.category.LAUNCHER\");")]),
    ("components: a dotted name is relative", MANIFEST, [("Some(package) if name.starts_with('.') => format!(\"{package}{name}\"),", "Some(package) if name.starts_with('/') => format!(\"{package}{name}\"),")]),
    ("components: a component is disabled by default", MANIFEST, [(".map_or(Some(true), boolean);", ".map_or(Some(false), boolean);")]),
    ("components: a descriptor keeps its dots", MANIFEST, [("n.replace('.', \"/\")", "n.replace('.', \"$\")")]),
    ("components: any component has a target activity", MANIFEST, [('component.kind == "activity-alias"', 'component.kind != "activity-alias"')]),
    ("components: an explicit exported is ignored", MANIFEST, [('if let Some(attribute) = node.attribute(Some(ANDROID), "exported") {', 'if let Some(attribute) = node.attribute(Some(ANDROID), "exported_") {')]),
    ("manifest: the android namespace is keyed by its prefix", MANIFEST, [('Some(ANDROID) => format!("android:{}", attribute.name.local_name),', "Some(ANDROID) => attribute.name.local_name.clone(),")]),
    # ---- the tools
    ("tools: a page may be exactly the budget plus a byte", COMMON, [("if line_end - start > budget {", "if line_end - start > budget + 1 {")]),
    ("tools: a text page holds half of max_bytes", COMMON, [("let budget = usize::try_from(max_bytes / 4)", "let budget = usize::try_from(max_bytes / 2)")]),
    ("tools: an offset at the end of the rows is refused", COMMON, [("if offset > total as u64 {", "if offset >= total as u64 {")]),
    ("tools: the escaped copy is not counted", COMMON, [("(compact.len() + escaped) as u64", "compact.len() as u64")]),
    ("tools: an answer exactly at the budget is refused", COMMON, [("if observed <= budget && (count > 0 || rows.is_empty()) {", "if observed < budget && (count > 0 || rows.is_empty()) {")]),
    ("tools: a directory is not found", COMMON, [('(refuse(ErrorCode::InvalidInput, &message), "invalid_input")', '(refuse(ErrorCode::InvalidInput, &message), "not_found")')]),
    ("tools: a broken member is not a resource error", COMMON, [('"resource_error"\n            } else if error.stage == "manifest"', '"invalid_input"\n            } else if error.stage == "manifest"')]),
    ("tools: several archives are not ambiguous", COMMON, [('"ambiguous_input",', '"invalid_argument",')]),
    ("tools: an unsupported table is invalid", COMMON, [("ResourceFailure::InvalidTable(error) if error.code == ErrorCode::UnsupportedCapability => {", "ResourceFailure::InvalidTable(error) if false => {")]),
    ("tools: a prefix is a substring", FILES, [("files.retain(|file| file.name.starts_with(prefix));", "files.retain(|file| file.name.contains(prefix));")]),
    ("tools: only_exported keeps the unknown", COMPONENTS, [("c.exported == Some(true))", "c.exported != Some(false))")]),
    ("tools: a hex page holds a quarter of max_bytes", READ, [("usize::try_from(max_bytes / 8)", "usize::try_from(max_bytes / 4)")]),
    ("tools: binary XML is called text", READ, [('"android_xml"', '"text"')]),
    ("tools: a hex offset past the end is accepted", READ, [("if args.offset > source_bytes {", "if args.offset > source_bytes + 1 {")]),
    ("tools: the resource id has no fixed width", QUERY_TOOL, [('format!("0x{id:08x}")', 'format!("0x{id:x}")')]),
    ("tools: an attribute reference row has no reference id", QUERY_TOOL, [("            | data_type::ATTRIBUTE\n", "")]),
    ("tools: a row has no item count", QUERY_TOOL, [('out.insert("item_count".to_owned(), json!(item.count));', "")]),
    ("tools: the default configuration is every configuration", QUERY_TOOL, [("configuration: args.configuration.clone(),", "configuration: args.configuration.clone().filter(|c| !c.is_empty()),")]),
    ("tools: the manifest xml ignores max_bytes", "crates/mdd-mcp/src/tools.rs", [("let max_bytes = resource_tools::page_bytes_of(args.max_bytes)?;\n    let (input_index, text)", "let max_bytes = resource_tools::DEFAULT_MAX_BYTES;\n    let (input_index, text)")]),
    ("tools: a dataset without DEX says it has DEX", "crates/mdd-mcp/src/tools.rs", [('"has_dex": dataset.has_dex(),', '"has_dex": true,')]),
    ("tools: query runs on a dataset without DEX", "crates/mdd-mcp/src/tools.rs", [("    require_dex(&dataset, &args.dataset_id)?;\n    let window = SqlWindow::new(", "    let window = SqlWindow::new(")]),
]

base.MUTANTS = MUTANTS


def anchors() -> int:
    """Which anchors are not unique in their file (no build, no run)."""
    bad = 0
    for name, relative, edits in MUTANTS:
        text = (ROOT / relative).read_text(encoding="utf-8")
        for old, _new in edits:
            count = text.count(old)
            if count != 1:
                bad += 1
                print(f"ANCHOR {count}x  {name}  [{relative}]")
    print(f"{len(MUTANTS)} mutants, {bad} anchors that are not unique")
    return 1 if bad else 0


if __name__ == "__main__":
    if sys.argv[1:] == ["--anchors"]:
        sys.exit(anchors())
    sys.exit(base.main())
