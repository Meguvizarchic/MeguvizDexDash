//! Reaching definitions of registers, and from them def-use chains.
//!
//! A forward may-analysis over the CFG: for every use of a register, the set of
//! definitions that can reach it along some path. The set is a superset of what is
//! possible at run time (every possible edge is followed), never a subset.
//!
//! Registers only. Fields, array elements and the heap are not tracked, so a def-use
//! chain says nothing about values that travel through them.
//!
//! Three pseudo-registers carry values that have no register of their own: the result
//! an invoke or `filled-new-array` leaves for `move-result*`, and the exception a
//! handler is entered with for `move-exception`. The parameters are defined at entry.
//! A use that some path reaches with no definition at all is reported as
//! `may_be_undefined` instead of being dropped.
//!
//! An exception edge carries the state *before* the instruction that threw: a throwing
//! instruction does not complete, so its own definitions never reach the handler.
use super::{
    AnalysisBudget, Incomplete, Stage,
    cfg::{BlockId, Cfg, EdgeKind, Target},
    opcodes::{Role, info},
};
use mdd_dex::instructions::{CodeItem, Instruction};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "reg", content = "index", rename_all = "snake_case")]
pub enum Reg {
    V(u16),
    /// The value left by the last invoke or `filled-new-array`.
    Result,
    /// The exception a handler was entered with.
    Exception,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct DefId(pub u32);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "site", rename_all = "snake_case")]
pub enum DefSite {
    /// A parameter, defined on entry.
    Entry,
    /// Written by the instruction at this code unit.
    Instruction { at: u32 },
    /// The exception delivered at a handler's first instruction.
    Handler { at: u32 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct Def {
    pub id: DefId,
    #[serde(flatten)]
    pub reg: Reg,
    #[serde(flatten)]
    pub site: DefSite,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Use {
    pub at: u32,
    pub byte_offset: u64,
    #[serde(flatten)]
    pub reg: Reg,
    /// Every definition that can reach this use, in id order.
    pub reaching: Vec<DefId>,
    /// Some path reaches the use with no definition of the register.
    pub may_be_undefined: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DefUse {
    pub defs: Vec<Def>,
    pub uses: Vec<Use>,
}

impl DefUse {
    pub fn def(&self, id: DefId) -> &Def {
        &self.defs[id.0 as usize]
    }

    /// The uses a definition can reach.
    pub fn uses_of(&self, id: DefId) -> impl Iterator<Item = &Use> {
        self.uses.iter().filter(move |u| u.reaching.contains(&id))
    }

    pub fn uses_at(&self, offset: u32) -> impl Iterator<Item = &Use> {
        self.uses.iter().filter(move |u| u.at == offset)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Token {
    Undefined,
    Def(u32),
}

type State = BTreeMap<Reg, BTreeSet<Token>>;

struct Effects {
    uses: Vec<Reg>,
    defs: Vec<Reg>,
}

/// Registers an instruction reads and writes, uses first. `None` when its operands do
/// not have the shape its opcode promises.
fn effects(instruction: &Instruction) -> Option<Effects> {
    let inf = info(instruction.opcode)?;
    let registers: Vec<u16> = instruction.registers.iter().collect();
    let mut uses = Vec::new();
    let mut defs = Vec::new();
    if inf.variadic_uses {
        uses.extend(registers.iter().map(|r| Reg::V(*r)));
    } else {
        for (position, slot) in inf.slots.iter().enumerate() {
            let Some(slot) = slot else { continue };
            let base = *registers.get(position)?;
            let pair: Vec<Reg> = if slot.wide {
                vec![Reg::V(base), Reg::V(base.checked_add(1)?)]
            } else {
                vec![Reg::V(base)]
            };
            if matches!(slot.role, Role::Use | Role::DefUse) {
                uses.extend(pair.iter().copied());
            }
            if matches!(slot.role, Role::Def | Role::DefUse) {
                defs.extend(pair);
            }
        }
    }
    if inf.reads_result {
        uses.push(Reg::Result);
    }
    if inf.reads_exception {
        uses.push(Reg::Exception);
    }
    if inf.sets_result {
        defs.push(Reg::Result);
    }
    Some(Effects { uses, defs })
}

fn over(limit: u64) -> Stage<DefUse> {
    Stage::Incomplete(Incomplete::BudgetExceeded {
        resource: "dataflow_steps",
        limit,
    })
}

pub fn build(code: &CodeItem, cfg: &Cfg, budget: &AnalysisBudget) -> Stage<DefUse> {
    let instructions = &code.instructions;
    // ---- operand effects of every instruction, once
    let mut all: Vec<Effects> = Vec::with_capacity(instructions.len());
    for instruction in instructions {
        match effects(instruction) {
            Some(found) => all.push(found),
            None => {
                return Stage::Incomplete(Incomplete::UnsupportedInstruction {
                    at: instruction.code_unit_offset,
                    opcode: instruction.opcode,
                });
            }
        }
    }

    // ---- the definitions: parameters, then instructions in code order, then handlers
    let mut defs: Vec<Def> = Vec::new();
    let params_start = code.registers_size.saturating_sub(code.ins_size);
    for register in params_start..code.registers_size {
        defs.push(Def {
            id: DefId(defs.len() as u32),
            reg: Reg::V(register),
            site: DefSite::Entry,
        });
    }
    let mut def_of: BTreeMap<(usize, Reg), DefId> = BTreeMap::new();
    for (position, effect) in all.iter().enumerate() {
        for reg in &effect.defs {
            let id = DefId(defs.len() as u32);
            def_of.insert((position, *reg), id);
            defs.push(Def {
                id,
                reg: *reg,
                site: DefSite::Instruction {
                    at: instructions[position].code_unit_offset,
                },
            });
        }
    }
    // A handler is entered by exception edges only; its first instruction receives the
    // exception. Entered by an ordinary edge as well it would merge both.
    let mut handler_def: BTreeMap<BlockId, DefId> = BTreeMap::new();
    for edge in &cfg.edges {
        if let (EdgeKind::Exception { .. }, Target::Block(to)) = (edge.kind, edge.to)
            && !handler_def.contains_key(&to)
        {
            let id = DefId(defs.len() as u32);
            defs.push(Def {
                id,
                reg: Reg::Exception,
                site: DefSite::Handler {
                    at: cfg.block(to).start,
                },
            });
            handler_def.insert(to, id);
        }
    }

    // ---- registers worth tracking, and the entry state
    let mut tracked: BTreeSet<Reg> = BTreeSet::new();
    for effect in &all {
        tracked.extend(effect.uses.iter().chain(&effect.defs).copied());
    }
    tracked.extend(defs.iter().map(|d| d.reg));
    let mut entry: State = BTreeMap::new();
    for reg in &tracked {
        entry.insert(*reg, BTreeSet::from([Token::Undefined]));
    }
    for def in defs.iter().filter(|d| d.site == DefSite::Entry) {
        entry.insert(def.reg, BTreeSet::from([Token::Def(def.id.0)]));
    }

    // ---- fixpoint
    let blocks = &cfg.blocks;
    let mut in_state: Vec<Option<State>> = vec![None; blocks.len()];
    in_state[0] = Some(entry);
    let mut queue: VecDeque<usize> = VecDeque::from([0usize]);
    let mut queued = vec![false; blocks.len()];
    queued[0] = true;
    let mut steps: u64 = 0;

    let merge = |target: &mut Option<State>, incoming: &State, handler: Option<DefId>| -> bool {
        let mut changed = false;
        let state = target.get_or_insert_with(|| {
            changed = true;
            BTreeMap::new()
        });
        for (reg, tokens) in incoming {
            let slot = state.entry(*reg).or_insert_with(|| {
                changed = true;
                BTreeSet::new()
            });
            for token in tokens {
                changed |= slot.insert(*token);
            }
        }
        if let Some(def) = handler {
            // The exception is whatever this handler's own delivery wrote.
            let wanted = BTreeSet::from([Token::Def(def.0)]);
            if state.get(&Reg::Exception) != Some(&wanted) {
                state.insert(Reg::Exception, wanted);
                changed = true;
            }
        }
        changed
    };

    while let Some(current) = queue.pop_front() {
        queued[current] = false;
        let block = &blocks[current];
        let Some(mut state) = in_state[current].clone() else {
            continue;
        };
        let exception_edges: Vec<(BlockId, u32)> = cfg
            .successors(BlockId(current as u32))
            .filter_map(|e| match (e.kind, e.to) {
                (EdgeKind::Exception { .. }, Target::Block(to)) => Some((to, e.source_offset)),
                _ => None,
            })
            .collect();
        for position in block.first_instruction..block.first_instruction + block.instruction_count {
            steps += 1;
            if steps > budget.max_dataflow_steps {
                return over(budget.max_dataflow_steps);
            }
            let instruction = &instructions[position];
            // The state before an instruction that may throw reaches the handlers.
            if info(instruction.opcode).is_some_and(|i| i.may_throw) {
                for (handler, _) in &exception_edges {
                    let def = handler_def.get(handler).copied();
                    if merge(&mut in_state[handler.0 as usize], &state, def)
                        && !queued[handler.0 as usize]
                    {
                        queued[handler.0 as usize] = true;
                        queue.push_back(handler.0 as usize);
                    }
                }
            }
            for reg in &all[position].defs {
                let id = def_of[&(position, *reg)];
                state.insert(*reg, BTreeSet::from([Token::Def(id.0)]));
            }
        }
        for edge in cfg.successors(BlockId(current as u32)) {
            // Exception edges were handled above, with the state before the throw.
            if matches!(edge.kind, EdgeKind::Exception { .. }) {
                continue;
            }
            let Target::Block(to) = edge.to else { continue };
            if merge(&mut in_state[to.0 as usize], &state, None) && !queued[to.0 as usize] {
                queued[to.0 as usize] = true;
                queue.push_back(to.0 as usize);
            }
        }
    }

    // ---- record the uses against the settled states
    let mut uses: Vec<Use> = Vec::new();
    for (index, block) in blocks.iter().enumerate() {
        let Some(mut state) = in_state[index].clone() else {
            continue;
        };
        for position in block.first_instruction..block.first_instruction + block.instruction_count {
            let instruction = &instructions[position];
            // add-long v2, v2, v2 reads the pair once, however often it is named.
            let distinct: BTreeSet<Reg> = all[position].uses.iter().copied().collect();
            for reg in &distinct {
                let tokens = state.get(reg);
                let mut reaching: Vec<DefId> = tokens
                    .into_iter()
                    .flatten()
                    .filter_map(|t| match t {
                        Token::Def(id) => Some(DefId(*id)),
                        Token::Undefined => None,
                    })
                    .collect();
                reaching.sort();
                uses.push(Use {
                    at: instruction.code_unit_offset,
                    byte_offset: instruction.byte_offset.0,
                    reg: *reg,
                    reaching,
                    may_be_undefined: tokens.is_none_or(|t| t.contains(&Token::Undefined)),
                });
            }
            for reg in &all[position].defs {
                let id = def_of[&(position, *reg)];
                state.insert(*reg, BTreeSet::from([Token::Def(id.0)]));
            }
        }
    }
    uses.sort_by_key(|u| (u.at, u.reg));
    Stage::Complete(DefUse { defs, uses })
}
