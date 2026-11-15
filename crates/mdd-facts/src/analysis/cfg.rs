//! Basic blocks and edges of one method.
//!
//! Blocks are cut at every place control can arrive or a try range changes, so a block
//! lies wholly inside or wholly outside each try. Edges are drawn from the decoded
//! branch targets, the switch payloads and the try/handler tables; nothing is inferred
//! about values. Anything that does not fit - a fall-through into payload data, off the
//! end of the code, a handler or try boundary that is not an instruction - is recorded as
//! an [`Issue`] and the edge is *not* invented: the CFG is then not `well_formed`, and
//! reachability refuses to answer "no path" from it.
use super::{
    AnalysisBudget, Incomplete, Stage,
    opcodes::{Flow, info},
};
use mdd_dex::instructions::{CodeItem, PayloadData};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct BlockId(pub u32);

/// Where an edge goes: another block, or out of the method.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "to", content = "block", rename_all = "snake_case")]
pub enum Target {
    Block(BlockId),
    /// `return*`.
    ReturnExit,
    /// An exception that no handler of the method catches (or may not catch).
    ExceptionExit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EdgeKind {
    /// Straight-line flow to the next instruction (also a switch's default).
    Fallthrough,
    /// `goto` or the taken side of an `if`.
    Branch,
    /// One case of a switch; several cases may share a target.
    SwitchCase { key: i32 },
    /// Into a handler of the enclosing try. `type_idx` is `None` for a catch-all.
    Exception { type_idx: Option<u32> },
    /// Out of the method by `return*`.
    Return,
    /// Out of the method by an exception.
    ExceptionExit,
}

/// Whether the edge is taken whenever its source instruction runs.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Certainty {
    /// Follows from the instruction alone (a goto, a fall-through, a return).
    Definite,
    /// May be taken: the side of a condition, a switch case, an exception handler.
    Possible,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Edge {
    pub from: BlockId,
    #[serde(flatten)]
    pub to: Target,
    #[serde(flatten)]
    pub kind: EdgeKind,
    pub certainty: Certainty,
    /// Code unit of the instruction the edge leaves from: the block's last instruction,
    /// or for an exception edge its last instruction that may throw.
    pub source_offset: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Block {
    pub id: BlockId,
    /// First code unit, and one past the last code unit of its last instruction.
    pub start: u32,
    pub end: u32,
    /// Position in the code item's instruction list, and how many instructions.
    pub first_instruction: usize,
    pub instruction_count: usize,
    /// DEX file offset of the first instruction.
    pub byte_offset: u64,
    /// Source line in effect at the block start, when debug info gives one.
    pub source_line: Option<u64>,
    /// The try item whose range holds this block.
    pub try_index: Option<usize>,
    pub reachable: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IssueKind {
    /// An instruction that continues is followed by payload data.
    FallthroughIntoData,
    /// An instruction that continues is the last of the code.
    FallthroughPastEnd,
    HandlerNotAtInstruction,
    TryBoundaryNotAtInstruction,
    /// A try item names a handler the code item does not list.
    HandlerMissing,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct Issue {
    pub kind: IssueKind,
    pub at: u32,
    pub byte_offset: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Cfg {
    pub blocks: Vec<Block>,
    pub edges: Vec<Edge>,
    pub issues: Vec<Issue>,
    /// Code unit ranges `[start, end)` of payload data: not instructions, in no block.
    pub payload_ranges: Vec<(u32, u32)>,
    #[serde(skip)]
    positions: Vec<(u32, u64)>,
    #[serde(skip)]
    starts: BTreeMap<u32, usize>,
    #[serde(skip)]
    offsets: BTreeSet<u32>,
    /// Edge indices leaving each block, so no query scans the whole edge list.
    #[serde(skip)]
    out: Vec<Vec<usize>>,
}

impl Cfg {
    /// No issue was found. Only then may a missing path be called a proof.
    pub fn well_formed(&self) -> bool {
        self.issues.is_empty()
    }

    /// Whether an instruction starts at this code unit.
    pub fn is_instruction(&self, offset: u32) -> bool {
        self.offsets.contains(&offset)
    }

    pub fn entry(&self) -> BlockId {
        BlockId(0)
    }

    pub fn block(&self, id: BlockId) -> &Block {
        &self.blocks[id.0 as usize]
    }

    /// The block holding the instruction that starts at `offset` (a code unit).
    pub fn block_of(&self, offset: u32) -> Option<&Block> {
        let (_, &index) = self.starts.range(..=offset).next_back()?;
        let block = &self.blocks[index];
        (offset < block.end).then_some(block)
    }

    pub fn successors(&self, id: BlockId) -> impl Iterator<Item = &Edge> {
        self.out[id.0 as usize]
            .iter()
            .map(move |&index| &self.edges[index])
    }

    pub fn unreachable_blocks(&self) -> impl Iterator<Item = &Block> {
        self.blocks.iter().filter(|block| !block.reachable)
    }

    /// The source line in effect at a code unit, from the debug info's position events.
    pub fn source_line_at(&self, offset: u32) -> Option<u64> {
        let at = self
            .positions
            .partition_point(|(address, _)| *address <= offset);
        at.checked_sub(1).map(|i| self.positions[i].1)
    }
}

fn over(resource: &'static str, limit: u64) -> Stage<Cfg> {
    Stage::Incomplete(Incomplete::BudgetExceeded { resource, limit })
}

pub fn build(code: &CodeItem, budget: &AnalysisBudget) -> Stage<Cfg> {
    let instructions = &code.instructions;
    if instructions.is_empty() {
        return Stage::Incomplete(Incomplete::NoInstructions);
    }
    if instructions.len() as u64 > budget.max_instructions {
        return over("instructions", budget.max_instructions);
    }
    for instruction in instructions {
        if info(instruction.opcode).is_none() {
            return Stage::Incomplete(Incomplete::UnsupportedInstruction {
                at: instruction.code_unit_offset,
                opcode: instruction.opcode,
            });
        }
    }
    let index: BTreeMap<u32, usize> = instructions
        .iter()
        .enumerate()
        .map(|(position, instruction)| (instruction.code_unit_offset, position))
        .collect();
    let payload_ranges: Vec<(u32, u32)> = code
        .payloads
        .iter()
        .map(|payload| {
            (
                payload.code_unit_offset,
                payload.code_unit_offset + payload.width_code_units,
            )
        })
        .collect();
    let code_end = code.insns_size_code_units;
    let byte_of = |offset: u32| -> u64 {
        index.get(&offset).map_or_else(
            || code.insns_range.byte_offset.0 + u64::from(offset) * 2,
            |&i| instructions[i].byte_offset.0,
        )
    };
    let mut issues: Vec<Issue> = Vec::new();
    let mut issue = |kind: IssueKind, at: u32| {
        issues.push(Issue {
            kind,
            at,
            byte_offset: byte_of(at),
        });
    };

    // ---- leaders: every place control can arrive, and every try boundary
    let mut leaders: BTreeSet<u32> = BTreeSet::from([instructions[0].code_unit_offset]);
    let leader = |offset: u32, leaders: &mut BTreeSet<u32>| {
        if index.contains_key(&offset) {
            leaders.insert(offset);
        }
    };
    for instruction in instructions {
        let flow = info(instruction.opcode).map_or(Flow::Next, |i| i.flow);
        let next = instruction.code_unit_offset + u32::from(instruction.width_code_units);
        match flow {
            Flow::Next => {}
            Flow::Goto | Flow::Conditional => {
                if let Some(target) = instruction.branch_target_code_units {
                    leader(target, &mut leaders);
                }
                leader(next, &mut leaders);
            }
            Flow::Switch => {
                for target in code
                    .switch_targets
                    .iter()
                    .filter(|s| s.instruction_code_unit_offset == instruction.code_unit_offset)
                    .flat_map(|s| s.target_code_units.iter())
                {
                    leader(*target, &mut leaders);
                }
                leader(next, &mut leaders);
            }
            Flow::Return | Flow::Throw => leader(next, &mut leaders),
        }
    }
    // Code after a payload starts a new run: instructions are not contiguous across data.
    for (_, end) in &payload_ranges {
        leader(*end, &mut leaders);
    }
    for handler in &code.handlers {
        for address in handler
            .typed_catches
            .iter()
            .map(|c| c.address_code_units)
            .chain(handler.catch_all_address_code_units)
        {
            if index.contains_key(&address) {
                leaders.insert(address);
            } else {
                issue(IssueKind::HandlerNotAtInstruction, address);
            }
        }
    }
    for item in &code.tries {
        let start = item.start_code_unit;
        let end = start + u32::from(item.code_unit_count);
        for boundary in [start, end] {
            if index.contains_key(&boundary) {
                leaders.insert(boundary);
            } else if boundary != code_end && !payload_ranges.iter().any(|(s, _)| *s == boundary) {
                issue(IssueKind::TryBoundaryNotAtInstruction, boundary);
            }
        }
    }

    // ---- blocks
    let starts_sorted: Vec<u32> = leaders.iter().copied().collect();
    if starts_sorted.len() as u64 > budget.max_blocks {
        return over("blocks", budget.max_blocks);
    }
    let mut blocks: Vec<Block> = Vec::with_capacity(starts_sorted.len());
    let mut block_at: BTreeMap<u32, usize> = BTreeMap::new();
    for (position, &start) in starts_sorted.iter().enumerate() {
        let first = index[&start];
        let limit = starts_sorted.get(position + 1).copied().unwrap_or(u32::MAX);
        let mut count = 0usize;
        let mut end = start;
        while let Some(instruction) = instructions.get(first + count) {
            if instruction.code_unit_offset >= limit
                || (count > 0 && instruction.code_unit_offset != end)
            {
                break;
            }
            end = instruction.code_unit_offset + u32::from(instruction.width_code_units);
            count += 1;
        }
        let try_index = code.tries.iter().position(|item| {
            start >= item.start_code_unit
                && start < item.start_code_unit + u32::from(item.code_unit_count)
        });
        block_at.insert(start, position);
        blocks.push(Block {
            id: BlockId(position as u32),
            start,
            end,
            first_instruction: first,
            instruction_count: count,
            byte_offset: instructions[first].byte_offset.0,
            source_line: None,
            try_index,
            reachable: false,
        });
    }
    let block_of_start = |offset: u32| -> Option<BlockId> {
        block_at
            .get(&offset)
            .map(|&position| BlockId(position as u32))
    };

    // ---- edges
    let mut edges: Vec<Edge> = Vec::new();
    // Running into data or off the end only matters if the block can run at all: the
    // padding nop before a payload falls into data, and is dead.
    let mut flow_issues: Vec<(BlockId, IssueKind, u32)> = Vec::new();
    for block in &blocks {
        let last = &instructions[block.first_instruction + block.instruction_count - 1];
        let Some(inf) = info(last.opcode) else {
            continue;
        };
        let at = last.code_unit_offset;
        let next = block.end;
        let fall = |edges: &mut Vec<Edge>,
                    flow_issues: &mut Vec<(BlockId, IssueKind, u32)>,
                    certainty: Certainty| {
            if let Some(to) = block_of_start(next) {
                edges.push(Edge {
                    from: block.id,
                    to: Target::Block(to),
                    kind: EdgeKind::Fallthrough,
                    certainty,
                    source_offset: at,
                });
            } else if payload_ranges.iter().any(|(s, e)| next >= *s && next < *e) {
                flow_issues.push((block.id, IssueKind::FallthroughIntoData, next));
            } else {
                flow_issues.push((block.id, IssueKind::FallthroughPastEnd, next));
            }
        };
        match inf.flow {
            Flow::Next => fall(&mut edges, &mut flow_issues, Certainty::Definite),
            Flow::Goto => {
                if let Some(to) = last.branch_target_code_units.and_then(block_of_start) {
                    edges.push(Edge {
                        from: block.id,
                        to: Target::Block(to),
                        kind: EdgeKind::Branch,
                        certainty: Certainty::Definite,
                        source_offset: at,
                    });
                }
            }
            Flow::Conditional => {
                if let Some(to) = last.branch_target_code_units.and_then(block_of_start) {
                    edges.push(Edge {
                        from: block.id,
                        to: Target::Block(to),
                        kind: EdgeKind::Branch,
                        certainty: Certainty::Possible,
                        source_offset: at,
                    });
                }
                fall(&mut edges, &mut flow_issues, Certainty::Possible);
            }
            Flow::Switch => {
                let targets = code
                    .switch_targets
                    .iter()
                    .find(|s| s.instruction_code_unit_offset == at);
                let payload = last
                    .payload_target_code_units
                    .and_then(|offset| code.payloads.iter().find(|p| p.code_unit_offset == offset));
                if let (Some(targets), Some(payload)) = (targets, payload) {
                    let keys: Vec<i32> = match &payload.data {
                        PayloadData::PackedSwitch {
                            first_key,
                            relative_targets,
                        } => (0..relative_targets.len() as i64)
                            .map(|n| (i64::from(*first_key) + n) as i32)
                            .collect(),
                        PayloadData::SparseSwitch { keys, .. } => keys.clone(),
                        PayloadData::FillArray { .. } => Vec::new(),
                    };
                    for (key, target) in keys.iter().zip(&targets.target_code_units) {
                        if edges.len() as u64 > budget.max_edges {
                            return over("edges", budget.max_edges);
                        }
                        if let Some(to) = block_of_start(*target) {
                            edges.push(Edge {
                                from: block.id,
                                to: Target::Block(to),
                                kind: EdgeKind::SwitchCase { key: *key },
                                certainty: Certainty::Possible,
                                source_offset: at,
                            });
                        }
                    }
                }
                fall(&mut edges, &mut flow_issues, Certainty::Possible);
            }
            Flow::Return => edges.push(Edge {
                from: block.id,
                to: Target::ReturnExit,
                kind: EdgeKind::Return,
                certainty: Certainty::Definite,
                source_offset: at,
            }),
            Flow::Throw => {}
        }

        // Exception edges leave from the last instruction of the block that may throw.
        let throwing = instructions
            [block.first_instruction..block.first_instruction + block.instruction_count]
            .iter()
            .rev()
            .find(|i| info(i.opcode).is_some_and(|inf| inf.may_throw));
        let Some(throwing) = throwing else { continue };
        let thrown_at = throwing.code_unit_offset;
        let mut caught_all = false;
        if let Some(item) = block.try_index.map(|t| &code.tries[t]) {
            match code
                .handlers
                .iter()
                .find(|h| h.relative_byte_offset == u32::from(item.handler_relative_byte_offset))
            {
                Some(handler) => {
                    for catch in &handler.typed_catches {
                        if let Some(to) = block_of_start(catch.address_code_units) {
                            edges.push(Edge {
                                from: block.id,
                                to: Target::Block(to),
                                kind: EdgeKind::Exception {
                                    type_idx: Some(catch.type_idx),
                                },
                                certainty: Certainty::Possible,
                                source_offset: thrown_at,
                            });
                        }
                    }
                    if let Some(address) = handler.catch_all_address_code_units {
                        caught_all = true;
                        if let Some(to) = block_of_start(address) {
                            edges.push(Edge {
                                from: block.id,
                                to: Target::Block(to),
                                kind: EdgeKind::Exception { type_idx: None },
                                certainty: Certainty::Possible,
                                source_offset: thrown_at,
                            });
                        }
                    }
                }
                None => issue(IssueKind::HandlerMissing, item.start_code_unit),
            }
        }
        if !caught_all {
            edges.push(Edge {
                from: block.id,
                to: Target::ExceptionExit,
                kind: EdgeKind::ExceptionExit,
                certainty: Certainty::Possible,
                source_offset: thrown_at,
            });
        }
        if edges.len() as u64 > budget.max_edges {
            return over("edges", budget.max_edges);
        }
    }
    if edges.len() as u64 > budget.max_edges {
        return over("edges", budget.max_edges);
    }

    // ---- reachability from the entry block
    let mut out: Vec<Vec<usize>> = vec![Vec::new(); blocks.len()];
    for (index, edge) in edges.iter().enumerate() {
        out[edge.from.0 as usize].push(index);
    }
    let mut reached = vec![false; blocks.len()];
    let mut queue = VecDeque::from([0usize]);
    reached[0] = true;
    while let Some(current) = queue.pop_front() {
        for edge in out[current].iter().map(|&i| &edges[i]) {
            if let Target::Block(to) = edge.to
                && !reached[to.0 as usize]
            {
                reached[to.0 as usize] = true;
                queue.push_back(to.0 as usize);
            }
        }
    }

    for (block, kind, at) in flow_issues {
        if reached[block.0 as usize] {
            issues.push(Issue {
                kind,
                at,
                byte_offset: byte_of(at),
            });
        }
    }

    // ---- source positions
    let positions: Vec<(u32, u64)> = code.debug_info.as_ref().map_or_else(Vec::new, |debug| {
        let mut found: Vec<(u32, u64)> = debug
            .usable_source_positions()
            .filter_map(|event| {
                event
                    .source_line
                    .map(|line| (event.address_code_units, line.0))
            })
            .collect();
        found.sort_by_key(|(address, _)| *address);
        found
    });
    let mut cfg = Cfg {
        blocks,
        edges,
        issues,
        payload_ranges,
        positions,
        starts: block_at,
        offsets: index.keys().copied().collect(),
        out,
    };
    for (block, reached) in cfg.blocks.iter_mut().zip(reached) {
        block.reachable = reached;
    }
    let lines: Vec<Option<u64>> = cfg
        .blocks
        .iter()
        .map(|b| cfg.source_line_at(b.start))
        .collect();
    for (block, line) in cfg.blocks.iter_mut().zip(lines) {
        block.source_line = line;
    }
    cfg.issues.sort_by_key(|i| (i.at, i.kind as u8));
    cfg.issues.dedup();
    Stage::Complete(cfg)
}
