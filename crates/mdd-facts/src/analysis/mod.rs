//! Optional analyses over decoded code: control flow, exception edges, register
//! def-use, call-site classification and method-local reachability.
//!
//! Scope and honesty are the point of this module, so they are stated up front.
//!
//! * **One method at a time.** Nothing here crosses a method boundary. A call is
//!   classified, never followed.
//! * **Facts and inferences are separate.** The decoded instructions are facts. The
//!   blocks, edges, reaching definitions and call classifications are *inferences*
//!   from them, and every result carries [`ANALYSIS_VERSION`], the [`ASSUMPTIONS`] it
//!   rests on, its [`SCOPE`], and whether it ran to completion.
//! * **Over-approximation, never under.** Exception edges are drawn to every handler of
//!   the enclosing try, because the type test is not evaluated; they are marked
//!   `Possible`. A reaching-definition set is a superset of what can reach a use.
//! * **Unknown stays unknown.** A dynamic or reflective call, an invoke whose receiver
//!   decides the target, a control flow that leaves the decoded code: none of these is
//!   turned into an edge or into an empty set. A question that cannot be answered gets
//!   `Unknown` with the reasons, and "no path" is only ever said when it is proven.
//! * **Budgets interrupt, they do not truncate silently.** A stage that runs out of
//!   budget reports `Incomplete` and drops its partial facts.
//!
//! Not provided: constant propagation, inter-procedural call graphs, field/array/heap
//! analysis and type inference.
pub mod calls;
pub mod cfg;
pub mod defuse;
pub mod opcodes;
pub mod reach;
#[cfg(test)]
mod tests;

use mdd_dex::instructions::CodeItem;
use serde::Serialize;

pub use calls::{CallSite, CallTarget, Environment, Resolution, UnknownReason};
pub use cfg::{Cfg, Edge, EdgeKind, Issue, IssueKind, Target};
pub use defuse::{DefUse, Reg};
pub use reach::Reach;

pub const ANALYSIS_VERSION: &str = "mdd.analysis.v1";
/// The required scope of every result of this module.
pub const SCOPE: &str = "single-method-intraprocedural-v1";

/// What the results rest on. Anyone relying on them relies on these.
pub const ASSUMPTIONS: &[&str] = &[
    "the input is a decoded code item whose branch targets are instruction starts (the decoder refuses the rest)",
    "an exception raised by an instruction that may throw can enter every handler of its enclosing try, and leaves the method when the try has no catch-all; handler types are not matched",
    "registers are tracked individually; a wide value is two registers and the pairing is not validated",
    "move-result consumes the value left by an invoke or filled-new-array, whichever last wrote it",
    "an invoke's callee, a reflective call and dynamic loading are not resolved; they are classified",
];

#[derive(Clone, Copy, Debug, Serialize)]
pub struct AnalysisBudget {
    pub max_instructions: u64,
    pub max_blocks: u64,
    pub max_edges: u64,
    /// Instruction visits of the def-use fixpoint, counting repeats.
    pub max_dataflow_steps: u64,
}

impl Default for AnalysisBudget {
    fn default() -> Self {
        Self {
            max_instructions: 1_000_000,
            max_blocks: 1_000_000,
            max_edges: 4_000_000,
            max_dataflow_steps: 50_000_000,
        }
    }
}

/// Why a stage did not complete.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum Incomplete {
    BudgetExceeded {
        resource: &'static str,
        limit: u64,
    },
    NoInstructions,
    /// An opcode the table does not know, or operands that do not match its shape.
    UnsupportedInstruction {
        at: u32,
        opcode: u8,
    },
    /// An earlier stage this one needs did not complete.
    Prerequisite {
        stage: &'static str,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "status", content = "value", rename_all = "snake_case")]
pub enum Stage<T> {
    Complete(T),
    Incomplete(Incomplete),
}

impl<T> Stage<T> {
    pub fn complete(&self) -> Option<&T> {
        match self {
            Self::Complete(value) => Some(value),
            Self::Incomplete(_) => None,
        }
    }

    pub fn incomplete(&self) -> Option<&Incomplete> {
        match self {
            Self::Complete(_) => None,
            Self::Incomplete(reason) => Some(reason),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct MethodAnalysis {
    pub version: &'static str,
    pub scope: &'static str,
    pub assumptions: &'static [&'static str],
    pub code_item_byte_offset: u64,
    /// Whether the call classification could look at method names. When `false`, a
    /// reflective invoker or a class-loader constructor is classified like any other
    /// call: its absence from the unknown sites proves nothing.
    pub call_names_checked: bool,
    pub cfg: Stage<Cfg>,
    pub def_use: Stage<DefUse>,
    pub call_sites: Stage<Vec<CallSite>>,
}

/// Run every stage on one code item. A stage never sees another's partial result: if
/// the CFG is incomplete, the stages that need it are incomplete too.
pub fn analyze(
    code: &CodeItem,
    environment: &Environment,
    budget: &AnalysisBudget,
) -> MethodAnalysis {
    let cfg = cfg::build(code, budget);
    let (def_use, call_sites) = match &cfg {
        Stage::Complete(graph) => (
            defuse::build(code, graph, budget),
            calls::classify(code, graph, environment),
        ),
        Stage::Incomplete(_) => (
            Stage::Incomplete(Incomplete::Prerequisite { stage: "cfg" }),
            Stage::Incomplete(Incomplete::Prerequisite { stage: "cfg" }),
        ),
    };
    MethodAnalysis {
        version: ANALYSIS_VERSION,
        scope: SCOPE,
        assumptions: ASSUMPTIONS,
        code_item_byte_offset: code.raw_range.byte_offset.0,
        call_names_checked: environment.names_checked(),
        cfg,
        def_use,
        call_sites,
    }
}
