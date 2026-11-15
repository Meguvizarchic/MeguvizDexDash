//! Method-local reachability: can control get from one instruction to another?
//!
//! The answer has three values on purpose. `No` is a proof and is given only when the
//! CFG is complete and well formed; anything that could hide a flow the CFG does not
//! show - an issue the build recorded, a stage that ran out of budget, an offset that is
//! not an instruction - gives `Unknown` with the reasons. An empty answer is never used
//! to mean "no".
use super::{
    Incomplete, MethodAnalysis, Stage,
    calls::CallSite,
    cfg::{BlockId, Certainty, Cfg, IssueKind, Target},
};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "cause", rename_all = "snake_case")]
pub enum UnknownCause {
    CfgIncomplete {
        why: Incomplete,
    },
    /// The build found something that does not fit; flows it could not draw may exist.
    CfgNotWellFormed {
        issue: IssueKind,
        at: u32,
    },
    NotAnInstruction {
        offset: u32,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "answer", rename_all = "snake_case")]
pub enum Reach {
    /// A path exists. `certain` is true when one needs no conditional, switch or
    /// exception edge: only straight-line, goto and return flow. `via` lists the block
    /// starts of one witness path.
    Yes {
        certain: bool,
        via: Vec<u32>,
    },
    /// Proven: there is no path, in a complete and well-formed CFG.
    No,
    Unknown {
        causes: Vec<UnknownCause>,
    },
}

impl Reach {
    pub fn is_no(&self) -> bool {
        matches!(self, Self::No)
    }

    pub fn may_reach(&self) -> bool {
        matches!(self, Self::Yes { .. } | Self::Unknown { .. })
    }
}

/// Block-level search from the instruction at `from` in block `start`.
///
/// The start block is left once from `from` onward - only edges whose source is at or
/// after `from` can be taken. If the search comes back to it, it is entered at its first
/// instruction and every edge counts, so a path that loops through the start block and
/// leaves by an edge that sits before `from` is found. With `definite_only`, only
/// `Definite` edges are followed.
fn search(
    cfg: &Cfg,
    start: BlockId,
    from: u32,
    goal: BlockId,
    definite_only: bool,
) -> Option<Vec<BlockId>> {
    // A node is a block and whether it is the restricted first visit of the start block.
    type Node = (BlockId, bool);
    let root: Node = (start, true);
    let mut parent: BTreeMap<Node, Node> = BTreeMap::new();
    let mut seen: BTreeSet<Node> = BTreeSet::from([root]);
    let mut queue = VecDeque::from([root]);
    while let Some(node) = queue.pop_front() {
        let (current, restricted) = node;
        for edge in cfg.successors(current) {
            if restricted && edge.source_offset < from {
                continue;
            }
            if definite_only && edge.certainty != Certainty::Definite {
                continue;
            }
            let Target::Block(to) = edge.to else { continue };
            if to == goal {
                let mut path = vec![goal, current];
                let mut at = node;
                while at != root {
                    at = parent[&at];
                    path.push(at.0);
                }
                path.reverse();
                return Some(path);
            }
            let next: Node = (to, false);
            if seen.insert(next) {
                parent.insert(next, node);
                queue.push_back(next);
            }
        }
    }
    None
}

impl MethodAnalysis {
    /// Can control reach the instruction at code unit `to` from the instruction at `from`?
    pub fn reaches(&self, from: u32, to: u32) -> Reach {
        let cfg = match &self.cfg {
            Stage::Complete(cfg) => cfg,
            Stage::Incomplete(why) => {
                return Reach::Unknown {
                    causes: vec![UnknownCause::CfgIncomplete { why: why.clone() }],
                };
            }
        };
        let mut causes: Vec<UnknownCause> = [from, to]
            .into_iter()
            .filter(|offset| !cfg.is_instruction(*offset))
            .map(|offset| UnknownCause::NotAnInstruction { offset })
            .collect();
        causes.dedup();
        if !causes.is_empty() {
            return Reach::Unknown { causes };
        }
        let (Some(start), Some(goal)) = (cfg.block_of(from), cfg.block_of(to)) else {
            return Reach::Unknown {
                causes: vec![UnknownCause::NotAnInstruction { offset: from }],
            };
        };
        if start.id == goal.id && from <= to {
            return Reach::Yes {
                certain: true,
                via: vec![start.start],
            };
        }
        let starts = |path: Vec<BlockId>| path.into_iter().map(|b| cfg.block(b).start).collect();
        if let Some(path) = search(cfg, start.id, from, goal.id, true) {
            return Reach::Yes {
                certain: true,
                via: starts(path),
            };
        }
        if let Some(path) = search(cfg, start.id, from, goal.id, false) {
            return Reach::Yes {
                certain: false,
                via: starts(path),
            };
        }
        // No path in the graph. That is a proof only if nothing was left out of it.
        if !cfg.well_formed() {
            return Reach::Unknown {
                causes: cfg
                    .issues
                    .iter()
                    .take(8)
                    .map(|i| UnknownCause::CfgNotWellFormed {
                        issue: i.kind,
                        at: i.at,
                    })
                    .collect(),
            };
        }
        Reach::No
    }

    /// The call sites that control can reach from `from`, each with its own answer. A
    /// site whose answer is `Unknown` is listed, not left out.
    pub fn call_sites_from(&self, from: u32) -> Option<Vec<(&CallSite, Reach)>> {
        let sites = self.call_sites.complete()?;
        Some(
            sites
                .iter()
                .map(|site| (site, self.reaches(from, site.at)))
                .collect(),
        )
    }
}
