//! The 27 HostLab structural FEATURE rules.
//!
//! The catalog below is the complete frozen `EXPECTED_FEATURES` list from
//! `analysis/run_intake.py`, in the same order. Each entry names the facts the
//! native rule needs, its output kind, and whether the rule is implemented in
//! this skeleton.
//!
//! A rule that is not implemented reports [`FeatureStatus::NotImplemented`]
//! and carries no business verdict. This is deliberate: the frozen audit
//! treats `MISSING` as a real finding about an application, so emitting
//! `MISSING` for a rule that was never evaluated would fabricate evidence.
//! [`RuleRun::complete`] is `false` whenever any rule is not implemented, and
//! [`RuleRun::admitted`] is `false` unconditionally in this skeleton.
use super::{
    NativeSession,
    graph::{Graph, MethodInfo, descriptor_of},
};
use mdd_types::{ErrorCode, MddError, MddResult};
use serde::Serialize;
use std::collections::BTreeMap;

/// Business verdict, matching the four states the frozen audit publishes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FeatureStatus {
    Found,
    Missing,
    Partial,
    Ambiguous,
    /// The native rule has no implementation yet; never a business verdict.
    NotImplemented,
}

impl FeatureStatus {
    /// Whether this value is a business conclusion that depends only on the
    /// application, i.e. one the frozen TSV writer would accept.
    pub fn is_business_verdict(self) -> bool {
        matches!(
            self,
            Self::Found | Self::Missing | Self::Partial | Self::Ambiguous
        )
    }
}

/// What a rule emits besides its status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputShape {
    /// A `refs()` string of `owner#name(proto)` entries or `-`.
    References,
    /// A `key=value;...` detail string with booleans and counts.
    Detail,
}

/// One catalog entry.
#[derive(Clone, Copy, Debug)]
pub struct FeatureSpec {
    pub name: &'static str,
    /// Structural candidates (class/member lookups).
    pub definitions: bool,
    /// Generic type arguments from `dalvik.annotation.Signature`.
    pub generics: bool,
    /// Method-scoped string constants (`method_strings`).
    pub method_strings: bool,
    /// Invoke/call edges (`method_calls`, `methods`).
    pub calls: bool,
    /// Non-Signature annotations.
    pub annotations: bool,
    pub output: OutputShape,
    pub implementation: FeatureImplementation,
    /// The frozen audit publishes `discovery` rows only for these rules.
    /// Emitting extras would change the TSV shape, so it is explicit here.
    pub publishes_discoveries: bool,
}

/// Implementation state of one rule in this skeleton.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FeatureImplementation {
    /// Produces a business verdict.
    Implemented,
    /// Skeleton present, body pending migration.
    Pending,
}

/// Complete frozen FEATURE catalog, in `EXPECTED_FEATURES` order.
pub const CATALOG: &[FeatureSpec] = &[
    FeatureSpec {
        name: "block_update",
        definitions: true,
        generics: false,
        method_strings: false,
        calls: false,
        annotations: false,
        output: OutputShape::References,
        implementation: FeatureImplementation::Implemented,
        publishes_discoveries: true,
    },
    FeatureSpec {
        name: "player_default_quality",
        definitions: true,
        generics: false,
        method_strings: true,
        calls: false,
        annotations: false,
        output: OutputShape::Detail,
        implementation: FeatureImplementation::Pending,
        publishes_discoveries: true,
    },
    FeatureSpec {
        name: "comment_free_copy",
        definitions: true,
        generics: false,
        method_strings: false,
        calls: false,
        annotations: false,
        output: OutputShape::Detail,
        implementation: FeatureImplementation::Pending,
        publishes_discoveries: false,
    },
    FeatureSpec {
        name: "description_free_copy",
        definitions: true,
        generics: false,
        method_strings: false,
        calls: false,
        annotations: false,
        output: OutputShape::Detail,
        implementation: FeatureImplementation::Pending,
        publishes_discoveries: false,
    },
    FeatureSpec {
        name: "home_top_bar",
        definitions: true,
        generics: false,
        method_strings: false,
        calls: false,
        annotations: false,
        output: OutputShape::Detail,
        implementation: FeatureImplementation::Pending,
        publishes_discoveries: false,
    },
    FeatureSpec {
        name: "mine_entry",
        definitions: true,
        generics: false,
        method_strings: false,
        calls: false,
        annotations: false,
        output: OutputShape::Detail,
        implementation: FeatureImplementation::Pending,
        publishes_discoveries: false,
    },
    FeatureSpec {
        name: "mine_vip",
        definitions: true,
        generics: false,
        method_strings: false,
        calls: false,
        annotations: false,
        output: OutputShape::Detail,
        implementation: FeatureImplementation::Pending,
        publishes_discoveries: false,
    },
    FeatureSpec {
        name: "dynamic_tabs",
        definitions: true,
        generics: true,
        method_strings: false,
        calls: false,
        annotations: false,
        output: OutputShape::Detail,
        implementation: FeatureImplementation::Pending,
        publishes_discoveries: false,
    },
    FeatureSpec {
        name: "full_number",
        definitions: true,
        generics: false,
        method_strings: false,
        calls: false,
        annotations: false,
        output: OutputShape::References,
        implementation: FeatureImplementation::Implemented,
        publishes_discoveries: false,
    },
    FeatureSpec {
        name: "player_portrait",
        definitions: true,
        generics: false,
        method_strings: false,
        calls: false,
        annotations: false,
        output: OutputShape::References,
        implementation: FeatureImplementation::Pending,
        publishes_discoveries: false,
    },
    FeatureSpec {
        name: "player_status_bar",
        definitions: true,
        generics: false,
        method_strings: false,
        calls: false,
        annotations: false,
        output: OutputShape::References,
        implementation: FeatureImplementation::Implemented,
        publishes_discoveries: false,
    },
    FeatureSpec {
        name: "home_recommend",
        definitions: true,
        generics: false,
        method_strings: false,
        calls: false,
        annotations: false,
        output: OutputShape::Detail,
        implementation: FeatureImplementation::Pending,
        publishes_discoveries: false,
    },
    FeatureSpec {
        name: "video_relate",
        definitions: true,
        generics: false,
        method_strings: false,
        calls: false,
        annotations: false,
        output: OutputShape::Detail,
        implementation: FeatureImplementation::Pending,
        publishes_discoveries: false,
    },
    FeatureSpec {
        name: "home_tabs",
        definitions: true,
        generics: true,
        method_strings: false,
        calls: false,
        annotations: false,
        output: OutputShape::References,
        implementation: FeatureImplementation::Pending,
        publishes_discoveries: false,
    },
    FeatureSpec {
        name: "mine_components",
        definitions: true,
        generics: true,
        method_strings: false,
        calls: false,
        annotations: false,
        output: OutputShape::Detail,
        implementation: FeatureImplementation::Pending,
        publishes_discoveries: false,
    },
    FeatureSpec {
        name: "story_purify",
        definitions: true,
        generics: true,
        method_strings: false,
        calls: false,
        annotations: false,
        output: OutputShape::Detail,
        implementation: FeatureImplementation::Pending,
        publishes_discoveries: false,
    },
    FeatureSpec {
        name: "splash_ads",
        definitions: true,
        generics: false,
        method_strings: false,
        calls: false,
        annotations: false,
        output: OutputShape::References,
        implementation: FeatureImplementation::Pending,
        publishes_discoveries: false,
    },
    FeatureSpec {
        name: "bottom_bar",
        definitions: true,
        generics: false,
        method_strings: false,
        calls: false,
        annotations: false,
        output: OutputShape::Detail,
        implementation: FeatureImplementation::Pending,
        publishes_discoveries: false,
    },
    FeatureSpec {
        name: "teenagers_mode",
        definitions: true,
        generics: false,
        method_strings: false,
        calls: false,
        annotations: false,
        output: OutputShape::References,
        implementation: FeatureImplementation::Implemented,
        publishes_discoveries: false,
    },
    FeatureSpec {
        name: "comment_filter",
        definitions: true,
        generics: true,
        method_strings: false,
        calls: false,
        annotations: false,
        output: OutputShape::Detail,
        implementation: FeatureImplementation::Pending,
        publishes_discoveries: false,
    },
    FeatureSpec {
        name: "comment_purify",
        definitions: true,
        generics: false,
        method_strings: false,
        calls: false,
        annotations: false,
        output: OutputShape::Detail,
        implementation: FeatureImplementation::Pending,
        publishes_discoveries: false,
    },
    FeatureSpec {
        name: "comment_topology",
        definitions: true,
        generics: false,
        method_strings: false,
        calls: false,
        annotations: false,
        output: OutputShape::Detail,
        implementation: FeatureImplementation::Pending,
        publishes_discoveries: true,
    },
    FeatureSpec {
        name: "comment_section",
        definitions: true,
        generics: true,
        method_strings: false,
        calls: false,
        annotations: false,
        output: OutputShape::Detail,
        implementation: FeatureImplementation::Pending,
        publishes_discoveries: false,
    },
    FeatureSpec {
        name: "paused_ad",
        definitions: true,
        generics: false,
        method_strings: false,
        calls: false,
        annotations: false,
        output: OutputShape::Detail,
        implementation: FeatureImplementation::Pending,
        publishes_discoveries: false,
    },
    FeatureSpec {
        name: "home_banner",
        definitions: true,
        generics: false,
        method_strings: false,
        calls: false,
        annotations: false,
        output: OutputShape::Detail,
        implementation: FeatureImplementation::Pending,
        publishes_discoveries: false,
    },
    FeatureSpec {
        name: "merchandise",
        definitions: true,
        generics: false,
        method_strings: false,
        calls: false,
        annotations: false,
        output: OutputShape::Detail,
        implementation: FeatureImplementation::Implemented,
        publishes_discoveries: false,
    },
    FeatureSpec {
        name: "game_promotion",
        definitions: true,
        generics: false,
        method_strings: false,
        calls: false,
        annotations: false,
        output: OutputShape::Detail,
        implementation: FeatureImplementation::Pending,
        publishes_discoveries: false,
    },
];

/// The frozen `EXPECTED_FEATURES` list, in order.
pub const EXPECTED_FEATURES: [&str; 27] = [
    "block_update",
    "player_default_quality",
    "comment_free_copy",
    "description_free_copy",
    "home_top_bar",
    "mine_entry",
    "mine_vip",
    "dynamic_tabs",
    "full_number",
    "player_portrait",
    "player_status_bar",
    "home_recommend",
    "video_relate",
    "home_tabs",
    "mine_components",
    "story_purify",
    "splash_ads",
    "bottom_bar",
    "teenagers_mode",
    "comment_filter",
    "comment_purify",
    "comment_topology",
    "comment_section",
    "paused_ad",
    "home_banner",
    "merchandise",
    "game_promotion",
];

/// One rule's output row.
#[derive(Clone, Debug, Serialize)]
pub struct FeatureReport {
    pub status: FeatureStatus,
    pub detail: String,
}

/// A place where the native output can differ from the frozen reference.
/// These are published with every run so no difference is ever silent.
#[derive(Clone, Debug, Serialize)]
pub struct SemanticDivergence {
    pub id: &'static str,
    pub reference: &'static str,
    pub native: &'static str,
    /// Whether the difference can change a FEATURE verdict.
    pub affects_verdict: bool,
}

pub const SEMANTIC_DIVERGENCES: &[SemanticDivergence] = &[
    SemanticDivergence {
        id: "file-id-vs-dex-ordinal",
        reference: "DexSQL `file_id` numbers the selected DEX members in archive enumeration \
                    order (A0 `dexsql 0.1.0` on Bilibili 9.16.1: `file_id=4` is `classes13.dex`, \
                    not `classes5.dex`); Q01 fixes the roster with \
                    `SELECT file_id,entry_name FROM dex_files ORDER BY file_id`.",
        native: "`dex_ordinal` is the index into the validated archive inventory, i.e. the \
                 same enumeration order, so `file_id == dex_ordinal` for archives and `0` for \
                 a raw DEX. `NativeSession::hostlab_file_ids()` states that mapping in one \
                 place; a non-dense ordinal sequence is rejected. The numeric `classes<N>.dex` \
                 order belongs to `native_surface` fingerprints only, never to `file_id`.",
        affects_verdict: false,
    },
    SemanticDivergence {
        id: "block-update-missing-catalog",
        reference: "The frozen audit compares block candidates against `run.blockCandidates` \
                    and reports `MISSING` when none matches.",
        native: "The same comparison is used, so a `MISSING` verdict has the same meaning. \
                 The candidate list is frozen reference data, not an engine inference.",
        affects_verdict: false,
    },
    SemanticDivergence {
        id: "raw-dex-entry-name",
        reference: "A raw `.dex` input is inventoried by the reference as a single file; \
                    the caller supplies the name.",
        native: "A raw `.dex` occurrence has no archive member name (`entry_name: null`).",
        affects_verdict: false,
    },
    SemanticDivergence {
        id: "signature-generics-absent",
        reference: "`native_graph.parse_type` returns `Type.generic` parsed from \
                    `dalvik.annotation.Signature`, and rules such as `dynamic_tabs` and \
                    `comment_filter` test `len(result.generic)`.",
        native: "Types are erased prototype descriptors with no type arguments. Rules that \
                 need generics are `NotImplemented`, never approximated with an erased type.",
        affects_verdict: true,
    },
    SemanticDivergence {
        id: "descriptor-order",
        reference: "DexSQL orders string columns with its own collation; `ORDER BY \
                    m.class_descriptor` in `Graph.discover` therefore uses backend ordering.",
        native: "Owners are ordered by exact Rust `String` (= UTF-8 byte) order. Detail strings \
                 that concatenate several refs can differ in sequence.",
        affects_verdict: false,
    },
    SemanticDivergence {
        id: "catalog-in-core",
        reference: "BIL package names and FEATURE predicates live only in the HostLab \
                    adapter; the generic engine contains none of them.",
        native: "The payload is no longer in the repository: it is loaded from an operator \
                 supplied file through `HostlabCatalog::new` and only the key names \
                 live in `mdd-facts`. The FEATURE rule bodies still live here and must move to \
                 `integrations/hostlab` before admission.",
        affects_verdict: false,
    },
    SemanticDivergence {
        id: "admission-gate",
        reference: "The frozen audit publishes FEATURE rows only when all 27 are present and \
                    each has one of the four business statuses.",
        native: "This skeleton publishes all 27 catalog rows but marks pending ones \
                 `NOT_IMPLEMENTED`; `complete` and `admitted` stay `false`.",
        affects_verdict: false,
    },
];

/// Business data consumed by the rules.
///
/// The payload names classes of the analysed application and is therefore loaded
/// from an operator supplied file at run time ([`HostlabCatalog::new`]); this
/// repository carries only the key names the rules read.
#[derive(Clone, Debug)]
pub struct HostlabCatalog {
    pub id: String,
    pub reference_commit: String,
    pub java_reference_sha256: String,
    pub(super) lists: BTreeMap<String, Vec<String>>,
    pub(super) constants: BTreeMap<String, String>,
}

impl HostlabCatalog {
    pub(super) fn from_parts(
        id: String,
        reference_commit: String,
        java_reference_sha256: String,
        lists: BTreeMap<String, Vec<String>>,
        constants: BTreeMap<String, String>,
    ) -> Self {
        Self {
            id,
            reference_commit,
            java_reference_sha256,
            lists,
            constants,
        }
    }
}

/// Result of one `Rules::run()`.
#[derive(Clone, Debug, Serialize)]
pub struct RuleRun {
    pub schema_version: String,
    pub catalog_id: String,
    pub reference_commit: String,
    pub java_reference_sha256: String,
    pub features: BTreeMap<&'static str, FeatureReport>,
    /// Feature id to `(owner, name(proto))` discoveries, matching the frozen
    /// `DISCOVERY` TSV rows.
    pub discoveries: BTreeMap<&'static str, Vec<(String, String)>>,
    pub implemented: usize,
    pub pending: usize,
    /// Every catalog FEATURE produced a business verdict.
    pub complete: bool,
    /// Always `false` here: MDD-051 requires all 27 rules with equivalence
    /// evidence before any capability admission.
    pub admitted: bool,
    pub semantic_divergences: &'static [SemanticDivergence],
}

/// Rule evaluator, the counterpart of the frozen `class Rules`.
pub struct Rules<'a> {
    graph: Graph<'a>,
    catalog: &'a HostlabCatalog,
}

impl<'a> Rules<'a> {
    /// Build a rule evaluator against an explicit catalog.
    pub fn with_catalog(
        session: &'a NativeSession,
        catalog: &'a HostlabCatalog,
    ) -> MddResult<Self> {
        session.require_structural_complete()?;
        Ok(Self {
            graph: Graph::new(session),
            catalog,
        })
    }

    pub fn graph(&self) -> &Graph<'a> {
        &self.graph
    }

    pub fn run(self) -> MddResult<RuleRun> {
        let mut features = BTreeMap::new();
        let mut discoveries: BTreeMap<&'static str, Vec<(String, String)>> = BTreeMap::new();
        for spec in CATALOG {
            let report = match spec.implementation {
                FeatureImplementation::Implemented => {
                    let (report, found) = self.evaluate(spec)?;
                    // The frozen audit publishes discovery rows for exactly
                    // three rules; publishing more would change the TSV shape.
                    if spec.publishes_discoveries && !found.is_empty() {
                        discoveries.insert(spec.name, found);
                    }
                    report
                }
                FeatureImplementation::Pending => FeatureReport {
                    status: FeatureStatus::NotImplemented,
                    detail: pending_detail(spec),
                },
            };
            features.insert(spec.name, report);
        }
        let implemented = CATALOG
            .iter()
            .filter(|spec| spec.implementation == FeatureImplementation::Implemented)
            .count();
        let pending = CATALOG.len() - implemented;
        let complete = pending == 0
            && features
                .values()
                .all(|report| report.status.is_business_verdict());
        Ok(RuleRun {
            schema_version: "mdd.hostlab-rule-run.v1".into(),
            catalog_id: self.catalog.id.clone(),
            reference_commit: self.catalog.reference_commit.clone(),
            java_reference_sha256: self.catalog.java_reference_sha256.clone(),
            features,
            discoveries,
            implemented,
            pending,
            complete,
            admitted: false,
            semantic_divergences: SEMANTIC_DIVERGENCES,
        })
    }

    /// Dispatch one implemented rule. Returns the report and its discoveries.
    fn evaluate(&self, spec: &FeatureSpec) -> MddResult<(FeatureReport, Vec<(String, String)>)> {
        match spec.name {
            "block_update" => self.block_update(),
            "full_number" => self.full_number(),
            "player_status_bar" => self.player_status_bar(),
            "teenagers_mode" => self.teenagers_mode(),
            "merchandise" => self.merchandise(),
            other => Err(MddError::new(
                ErrorCode::InternalFault,
                "hostlab.rules",
                "catalog marks a rule implemented but no rule body is bound",
            )
            .detail("feature", other)),
        }
    }

    /// `block_update`:
    /// ```text
    /// block = [m for m in g.discover(block.resultClass)
    ///          if not static(m) and not abstract(m)
    ///          and str(m.result) == block.resultClass
    ///          and args(m) == ["android.content.Context"]]
    /// FOUND if any owner in run.blockCandidates else MISSING
    /// detail = refs(block)
    /// ```
    fn block_update(&self) -> MddResult<(FeatureReport, Vec<(String, String)>)> {
        let result_class = self.catalog.constant("block.resultClass")?;
        let context = self.catalog.constant("block.contextArg")?;
        let candidates = self.catalog.list("run.blockCandidates")?;
        let block: Vec<MethodInfo> = self
            .graph
            .discover(&descriptor_of(result_class))?
            .into_iter()
            .filter(|method| {
                !method.is_static()
                    && !method.is_abstract()
                    && method.result.as_str() == result_class
                    && method.args.as_slice() == [super::graph::TypeRef::new(context)]
            })
            .collect();
        let found = block
            .iter()
            .any(|method| candidates.contains(&method.owner.as_str()));
        let statements = block.iter().map(MethodInfo::reference).collect::<Vec<_>>();
        Ok((
            FeatureReport {
                status: if found {
                    FeatureStatus::Found
                } else {
                    FeatureStatus::Missing
                },
                detail: refs(&statements),
            },
            block.iter().map(MethodInfo::signature_key).collect(),
        ))
    }

    /// `full_number`:
    /// ```text
    /// find(auditFullNumber.owners,
    ///      lambda m: static(m) and str(m.result) == "java.lang.String"
    ///                 and m.name in auditFullNumber.names
    ///                 and 1 <= len(m.args) <= 5
    ///                 and (str(m.args[0]) in {"int","long","java.lang.Integer","java.lang.Long"}
    ///                      or (str(m.args[0]) == "java.lang.String"
    ///                          and m.owner == fullNumber.kotlinOwner)))
    /// ```
    fn full_number(&self) -> MddResult<(FeatureReport, Vec<(String, String)>)> {
        let owners = self.catalog.list("auditFullNumber.owners")?;
        let names = self.catalog.list("auditFullNumber.names")?;
        let kotlin_owner = self.catalog.constant("fullNumber.kotlinOwner")?;
        let methods = self.graph.methods(&owners, false)?;
        let full: Vec<MethodInfo> = methods
            .into_iter()
            .filter(|method| {
                method.is_static()
                    && method.result.as_str() == "java.lang.String"
                    && names.contains(&method.name.as_str())
                    && (1..=5).contains(&method.args.len())
                    && (matches!(
                        method.args[0].as_str(),
                        "int" | "long" | "java.lang.Integer" | "java.lang.Long"
                    ) || (method.args[0].as_str() == "java.lang.String"
                        && method.owner == kotlin_owner))
            })
            .collect();
        Ok((
            FeatureReport {
                status: if full.is_empty() {
                    FeatureStatus::Missing
                } else {
                    FeatureStatus::Found
                },
                detail: references(&full),
            },
            full.iter().map(MethodInfo::signature_key).collect(),
        ))
    }

    /// `player_status_bar`:
    /// ```text
    /// g.subclass(playerStatusBar.owner, "android.app.Activity")
    ///   and find([activity], name=="onCreate" and not static
    ///            and args==["android.os.Bundle"] and result=="void")
    /// ```
    fn player_status_bar(&self) -> MddResult<(FeatureReport, Vec<(String, String)>)> {
        let activity = self.catalog.constant("playerStatusBar.owner")?;
        let create: Vec<MethodInfo> = self
            .graph
            .methods(&[activity], false)?
            .into_iter()
            .filter(|method| {
                method.name == "onCreate"
                    && !method.is_static()
                    && method.args.as_slice() == [super::graph::TypeRef::new("android.os.Bundle")]
                    && method.result.as_str() == "void"
            })
            .collect();
        let subclass = self.graph.subclass(activity, "android.app.Activity")?;
        Ok((
            FeatureReport {
                status: if subclass && !create.is_empty() {
                    FeatureStatus::Found
                } else {
                    FeatureStatus::Missing
                },
                detail: references(&create),
            },
            create.iter().map(MethodInfo::signature_key).collect(),
        ))
    }

    /// `teenagers_mode`:
    /// ```text
    /// find(teenagersOwners, name=="onCreate" and not static
    ///      and args==["android.os.Bundle"] and result=="void")
    /// FOUND if any, detail = refs(...)
    /// ```
    fn teenagers_mode(&self) -> MddResult<(FeatureReport, Vec<(String, String)>)> {
        let owners = self.catalog.list("teenagers.owners")?;
        let methods: Vec<MethodInfo> = self
            .graph
            .methods(&owners, false)?
            .into_iter()
            .filter(|method| {
                method.name == "onCreate"
                    && !method.is_static()
                    && method.args.as_slice() == [super::graph::TypeRef::new("android.os.Bundle")]
                    && method.result.as_str() == "void"
            })
            .collect();
        Ok((
            FeatureReport {
                status: if methods.is_empty() {
                    FeatureStatus::Missing
                } else {
                    FeatureStatus::Found
                },
                detail: references(&methods),
            },
            methods.iter().map(MethodInfo::signature_key).collect(),
        ))
    }

    /// `merchandise`:
    /// ```text
    /// bool(find([merchandise.owner],
    ///           name=="createViewEntry"
    ///           and args==["android.content.Context","android.view.ViewGroup"]))
    /// detail = j(merchandise)
    /// ```
    fn merchandise(&self) -> MddResult<(FeatureReport, Vec<(String, String)>)> {
        let owner = self.catalog.constant("merchandise.owner")?;
        let methods = self
            .graph
            .methods(&[owner], false)?
            .into_iter()
            .filter(|method| {
                method.name == "createViewEntry"
                    && method.args.as_slice()
                        == [
                            super::graph::TypeRef::new("android.content.Context"),
                            super::graph::TypeRef::new("android.view.ViewGroup"),
                        ]
            })
            .collect::<Vec<_>>();
        let found = !methods.is_empty();
        Ok((
            FeatureReport {
                status: if found {
                    FeatureStatus::Found
                } else {
                    FeatureStatus::Missing
                },
                detail: found.to_string(),
            },
            methods.iter().map(MethodInfo::signature_key).collect(),
        ))
    }
}

/// The reference `refs()` formatter: `owner#name(proto),...` or `-`.
fn refs(values: &[String]) -> String {
    if values.is_empty() {
        "-".to_owned()
    } else {
        values.join(",")
    }
}

fn references(methods: &[MethodInfo]) -> String {
    refs(
        &methods
            .iter()
            .map(MethodInfo::reference)
            .collect::<Vec<_>>(),
    )
}

fn pending_detail(spec: &FeatureSpec) -> String {
    let mut layers = Vec::new();
    if spec.definitions {
        layers.push("definitions");
    }
    if spec.generics {
        layers.push("signature_generics");
    }
    if spec.method_strings {
        layers.push("method_strings");
    }
    if spec.calls {
        layers.push("method_calls");
    }
    if spec.annotations {
        layers.push("annotations");
    }
    format!(
        "not implemented in the MDD-051 skeleton; migration requires [{}]",
        layers.join(",")
    )
}
