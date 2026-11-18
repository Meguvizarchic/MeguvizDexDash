//! The exported state and the launcher flag of a component, at the edges the platform draws them:
//! a provider below API 17, a component with an intent filter below API 31. Binary manifests are
//! assembled here byte by byte so the target SDK, the filters and the names are exactly what a test says.
use crate::manifest::components;
use mdd_input::manifest::{ManifestLimits, parse_manifest};
use serde_json::Value;
use std::sync::Arc;

const NONE: u32 = 0xffff_ffff;
const ANDROID: &str = "http://schemas.android.com/apk/res/android";

enum Val<'a> {
    Text(&'a str),
    Int(u32),
    Bool(bool),
}

#[derive(Default)]
struct Builder {
    strings: Vec<String>,
    nodes: Vec<Vec<u8>>,
}

fn words(values: &[u32]) -> Vec<u8> {
    values.iter().flat_map(|v| v.to_le_bytes()).collect()
}

fn node(kind: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = kind.to_le_bytes().to_vec();
    out.extend(16u16.to_le_bytes());
    out.extend(((16 + payload.len()) as u32).to_le_bytes());
    out.extend(1u32.to_le_bytes());
    out.extend(NONE.to_le_bytes());
    out.extend_from_slice(payload);
    out
}

impl Builder {
    fn s(&mut self, text: &str) -> u32 {
        if let Some(at) = self.strings.iter().position(|s| s == text) {
            return at as u32;
        }
        self.strings.push(text.to_owned());
        (self.strings.len() - 1) as u32
    }

    fn start(&mut self, name: &str, attrs: &[(&str, Val)]) {
        let name = self.s(name);
        let ns = self.s(ANDROID);
        let mut payload = words(&[NONE, name]);
        for half in [20u16, 20, attrs.len() as u16, 0, 0, 0] {
            payload.extend(half.to_le_bytes());
        }
        for (attr, value) in attrs {
            // `package` has no namespace; everything else is in android's
            let (ns, attr) = if *attr == "package" {
                (NONE, self.s(attr))
            } else {
                (ns, self.s(attr))
            };
            let (raw, kind, data) = match value {
                Val::Text(t) => {
                    let i = self.s(t);
                    (i, 3u8, i)
                }
                Val::Int(n) => (NONE, 0x10, *n),
                Val::Bool(b) => (NONE, 0x12, if *b { NONE } else { 0 }),
            };
            payload.extend(words(&[ns, attr, raw]));
            payload.extend(8u16.to_le_bytes());
            payload.extend([0, kind]);
            payload.extend(data.to_le_bytes());
        }
        self.nodes.push(node(0x102, &payload));
    }

    fn end(&mut self, name: &str) {
        let name = self.s(name);
        self.nodes.push(node(0x103, &words(&[NONE, name])));
    }

    fn finish(mut self) -> Vec<u8> {
        let prefix = self.s("android");
        let uri = self.s(ANDROID);
        let mut body_nodes = vec![node(0x100, &words(&[prefix, uri]))];
        body_nodes.append(&mut self.nodes);
        body_nodes.push(node(0x101, &words(&[prefix, uri])));
        let mut data = Vec::new();
        let mut offsets = Vec::new();
        for s in &self.strings {
            offsets.push(data.len() as u32);
            data.push(s.encode_utf16().count() as u8);
            data.push(s.len() as u8);
            data.extend_from_slice(s.as_bytes());
            data.push(0);
        }
        while data.len() % 4 != 0 {
            data.push(0);
        }
        let start = 28 + 4 * offsets.len();
        let mut pool = 1u16.to_le_bytes().to_vec();
        pool.extend(28u16.to_le_bytes());
        pool.extend(((start + data.len()) as u32).to_le_bytes());
        pool.extend(words(&[
            self.strings.len() as u32,
            0,
            0x100,
            start as u32,
            0,
        ]));
        pool.extend(words(&offsets));
        pool.extend(data);
        let mut body = pool;
        for n in body_nodes {
            body.extend(n);
        }
        let mut out = 3u16.to_le_bytes().to_vec();
        out.extend(8u16.to_le_bytes());
        out.extend(((8 + body.len()) as u32).to_le_bytes());
        out.extend(body);
        out
    }
}

/// A manifest of package `p` and the given target SDK whose application holds what `content` adds.
fn rows(target_sdk: Option<u32>, content: impl FnOnce(&mut Builder)) -> Vec<Value> {
    let mut b = Builder::default();
    b.start("manifest", &[("package", Val::Text("p"))]);
    if let Some(sdk) = target_sdk {
        b.start("uses-sdk", &[("targetSdkVersion", Val::Int(sdk))]);
        b.end("uses-sdk");
    }
    b.start("application", &[]);
    content(&mut b);
    b.end("application");
    b.end("manifest");
    let document = parse_manifest(Arc::from(b.finish()), ManifestLimits::default()).unwrap();
    components(&document)
        .unwrap()
        .components
        .into_iter()
        .map(|c| c.row)
        .collect()
}

fn filter(b: &mut Builder, action: &str, category: Option<&str>) {
    b.start("intent-filter", &[]);
    b.start("action", &[("name", Val::Text(action))]);
    b.end("action");
    if let Some(category) = category {
        b.start("category", &[("name", Val::Text(category))]);
        b.end("category");
    }
    b.end("intent-filter");
}

fn state(row: &Value) -> (Value, &str) {
    (
        row["exported"].clone(),
        row["exported_reason"].as_str().unwrap(),
    )
}

#[test]
fn a_provider_without_exported_is_exported_only_below_api_17() {
    for (sdk, exported) in [(16, true), (17, false), (18, false)] {
        let rows = rows(Some(sdk), |b| {
            b.start("provider", &[("name", Val::Text(".P"))]);
            b.end("provider");
        });
        assert_eq!(
            state(&rows[0]),
            (Value::Bool(exported), "provider_target_sdk_default"),
            "target {sdk}"
        );
    }
    let unknown = rows(None, |b| {
        b.start("provider", &[("name", Val::Text(".P"))]);
        b.end("provider");
    });
    assert_eq!(
        state(&unknown[0]),
        (
            Value::Null,
            "explicit_exported_required_or_target_sdk_unknown"
        )
    );
}

#[test]
fn a_component_with_an_intent_filter_is_exported_by_default_only_below_api_31() {
    for (sdk, expected) in [
        (Some(30), (Value::Bool(true), "intent_filter_default")),
        (
            Some(31),
            (
                Value::Null,
                "explicit_exported_required_or_target_sdk_unknown",
            ),
        ),
        (
            Some(35),
            (
                Value::Null,
                "explicit_exported_required_or_target_sdk_unknown",
            ),
        ),
        (
            None,
            (
                Value::Null,
                "explicit_exported_required_or_target_sdk_unknown",
            ),
        ),
    ] {
        let rows = rows(sdk, |b| {
            b.start("service", &[("name", Val::Text(".S"))]);
            filter(b, "x.ACTION", None);
            b.end("service");
        });
        assert_eq!(state(&rows[0]), expected, "target {sdk:?}");
    }
}

#[test]
fn without_a_filter_a_component_is_not_exported_whatever_the_target_and_an_explicit_value_wins() {
    for sdk in [Some(16), Some(35), None] {
        let rows = rows(sdk, |b| {
            b.start("activity", &[("name", Val::Text(".A"))]);
            b.end("activity");
            b.start(
                "receiver",
                &[("name", Val::Text(".R")), ("exported", Val::Bool(true))],
            );
            filter(b, "x.ACTION", None);
            b.end("receiver");
        });
        assert_eq!(
            state(&rows[0]),
            (Value::Bool(false), "intent_filter_default"),
            "target {sdk:?}"
        );
        assert_eq!(
            state(&rows[1]),
            (Value::Bool(true), "explicit"),
            "target {sdk:?}"
        );
    }
}

#[test]
fn a_launcher_needs_the_main_action_and_the_launcher_category() {
    let rows = rows(Some(35), |b| {
        for (name, action, category) in [
            (
                ".Both",
                "android.intent.action.MAIN",
                Some("android.intent.category.LAUNCHER"),
            ),
            (
                ".OnlyMain",
                "android.intent.action.MAIN",
                Some("android.intent.category.DEFAULT"),
            ),
            (
                ".OnlyLauncher",
                "android.intent.action.VIEW",
                Some("android.intent.category.LAUNCHER"),
            ),
            (".NoCategory", "android.intent.action.MAIN", None),
        ] {
            b.start("activity", &[("name", Val::Text(name))]);
            filter(b, action, category);
            b.end("activity");
        }
    });
    let launcher: Vec<bool> = rows
        .iter()
        .map(|r| r["launcher_intent"].as_bool().unwrap())
        .collect();
    assert_eq!(launcher, [true, false, false, false]);
}

#[test]
fn names_are_made_absolute_against_the_package_and_an_alias_names_its_target() {
    let rows = rows(Some(35), |b| {
        b.start("activity", &[("name", Val::Text(".Dot"))]);
        b.end("activity");
        b.start("activity", &[("name", Val::Text("Bare"))]);
        b.end("activity");
        b.start("activity", &[("name", Val::Text("q.Full"))]);
        b.end("activity");
        b.start(
            "activity-alias",
            &[
                ("name", Val::Text(".Al")),
                ("targetActivity", Val::Text(".Dot")),
            ],
        );
        b.end("activity-alias");
        b.start(
            "service",
            &[("name", Val::Text(".Off")), ("enabled", Val::Bool(false))],
        );
        b.end("service");
    });
    let names: Vec<&str> = rows.iter().map(|r| r["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["p.Dot", "p.Bare", "q.Full", "p.Al", "p.Off"]);
    assert_eq!(rows[0]["descriptor"], "Lp/Dot;");
    assert_eq!(rows[3]["target_activity"], "p.Dot");
    assert_eq!(rows[0]["target_activity"], Value::Null);
    assert_eq!(rows[0]["enabled"], true);
    assert_eq!(rows[4]["enabled"], false);
}
