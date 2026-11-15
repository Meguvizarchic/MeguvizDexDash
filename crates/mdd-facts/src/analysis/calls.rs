//! Call sites: classified, never resolved.
//!
//! An invoke instruction names a method, but which code runs depends on things this
//! module does not compute: class lookup for a static or direct call, the receiver's
//! type for a virtual, super or interface call, a bootstrap method for `invoke-custom`,
//! the signature for `invoke-polymorphic`. Reflection and dynamic class loading hide the
//! target entirely. So a site carries what the instruction says and an explicit
//! [`Resolution`]; there is no field that could be read as "the callee is X" or "there
//! is no callee".
use super::{Incomplete, Stage, cfg::Cfg, opcodes::info};
use mdd_dex::{
    definitions::MethodReference,
    instructions::{CodeItem, InvokeKind, ReferenceKind},
};
use serde::Serialize;
use std::collections::BTreeMap;

/// What the instruction names, and nothing more.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "names", rename_all = "snake_case")]
pub enum CallTarget {
    /// The method reference of an ordinary invoke.
    Method {
        method_idx: u32,
    },
    Polymorphic {
        method_idx: u32,
        proto_idx: u32,
    },
    Custom {
        call_site_idx: u32,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UnknownReason {
    /// `invoke-polymorphic`: the target depends on the call's signature at run time.
    PolymorphicSignature,
    /// `invoke-custom`: the target is chosen by a bootstrap method.
    CustomBootstrap,
    /// A call to a reflective invoker such as `Method.invoke`.
    ReflectiveInvocation,
    /// A call that loads code at run time, such as `DexClassLoader.<init>`.
    DynamicClassLoading,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "resolution", content = "reason", rename_all = "snake_case")]
pub enum Resolution {
    /// A static or direct call. The reference is what the instruction names; mapping it
    /// to a definition is a class lookup this module does not do.
    NamedOnly,
    /// A virtual, super or interface call: the receiver decides. No candidate set is
    /// computed, and it is not the named method.
    DispatchUnresolved,
    /// The target cannot be decided from the code.
    Unknown(UnknownReason),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CallSite {
    pub at: u32,
    pub byte_offset: u64,
    pub opcode: u8,
    pub mnemonic: String,
    #[serde(flatten)]
    pub target: CallTarget,
    #[serde(flatten)]
    pub resolution: Resolution,
    /// Inside a try range: an exception of the callee may enter a handler here.
    pub in_try: bool,
}

impl CallSite {
    /// The method the instruction names, if it names one that way.
    pub fn named_method(&self) -> Option<u32> {
        match self.target {
            CallTarget::Method { method_idx } | CallTarget::Polymorphic { method_idx, .. } => {
                Some(method_idx)
            }
            CallTarget::Custom { .. } => None,
        }
    }

    pub fn is_unknown(&self) -> bool {
        matches!(self.resolution, Resolution::Unknown(_))
    }
}

/// Methods known by name to hide their target. Built from the method references of the
/// same DEX; without it, reflection and loader calls are classified like any other call
/// and the result says so through [`Environment::names_checked`].
#[derive(Clone, Debug, Default)]
pub struct Environment {
    special: BTreeMap<u32, UnknownReason>,
    names_checked: bool,
}

const REFLECTIVE: &[(&str, &str)] = &[
    ("Ljava/lang/reflect/Method;", "invoke"),
    ("Ljava/lang/reflect/Constructor;", "newInstance"),
    ("Ljava/lang/Class;", "newInstance"),
];
const LOADING: &[(&str, &str)] = &[
    ("Ljava/lang/Class;", "forName"),
    ("Ljava/lang/ClassLoader;", "loadClass"),
    ("Ldalvik/system/DexClassLoader;", "<init>"),
    ("Ldalvik/system/PathClassLoader;", "<init>"),
    ("Ldalvik/system/BaseDexClassLoader;", "<init>"),
    ("Ldalvik/system/InMemoryDexClassLoader;", "<init>"),
];

impl Environment {
    /// No names are known: every ordinary invoke is classified by its opcode alone.
    pub fn none() -> Self {
        Self::default()
    }

    /// Mark the references that name a reflective invoker or a code loader.
    pub fn from_method_references(references: &[MethodReference]) -> Self {
        let mut special = BTreeMap::new();
        for reference in references {
            let pair = (
                reference.class_descriptor.as_str(),
                reference.method_name.as_str(),
            );
            if REFLECTIVE.contains(&pair) {
                special.insert(reference.method_idx, UnknownReason::ReflectiveInvocation);
            } else if LOADING.contains(&pair) {
                special.insert(reference.method_idx, UnknownReason::DynamicClassLoading);
            }
        }
        Self {
            special,
            names_checked: true,
        }
    }

    /// Explicitly mark method indices, for callers that have their own knowledge.
    pub fn with(mut self, method_idx: u32, reason: UnknownReason) -> Self {
        self.special.insert(method_idx, reason);
        self
    }

    /// Whether method names were available to look for reflection and loading.
    pub fn names_checked(&self) -> bool {
        self.names_checked
    }
}

pub fn classify(code: &CodeItem, cfg: &Cfg, environment: &Environment) -> Stage<Vec<CallSite>> {
    let mut sites = Vec::new();
    for instruction in &code.instructions {
        let Some(kind) = instruction.invoke_kind.as_ref() else {
            continue;
        };
        if info(instruction.opcode).is_none() {
            return Stage::Incomplete(Incomplete::UnsupportedInstruction {
                at: instruction.code_unit_offset,
                opcode: instruction.opcode,
            });
        }
        let reference = |wanted: ReferenceKind| {
            instruction
                .references
                .iter()
                .find(|r| r.kind == wanted)
                .map(|r| r.local_index)
        };
        let (target, mut resolution) = match kind {
            InvokeKind::Ordinary | InvokeKind::OrdinaryRange => {
                let Some(method_idx) = reference(ReferenceKind::Method) else {
                    return Stage::Incomplete(Incomplete::UnsupportedInstruction {
                        at: instruction.code_unit_offset,
                        opcode: instruction.opcode,
                    });
                };
                // 0x6e/0x74 virtual, 0x6f/0x75 super, 0x70/0x76 direct, 0x71/0x77 static,
                // 0x72/0x78 interface.
                let resolution = match instruction.opcode {
                    0x70 | 0x71 | 0x76 | 0x77 => Resolution::NamedOnly,
                    _ => Resolution::DispatchUnresolved,
                };
                (CallTarget::Method { method_idx }, resolution)
            }
            InvokeKind::Polymorphic | InvokeKind::PolymorphicRange => {
                let (Some(method_idx), Some(proto_idx)) = (
                    reference(ReferenceKind::Method),
                    reference(ReferenceKind::Prototype),
                ) else {
                    return Stage::Incomplete(Incomplete::UnsupportedInstruction {
                        at: instruction.code_unit_offset,
                        opcode: instruction.opcode,
                    });
                };
                (
                    CallTarget::Polymorphic {
                        method_idx,
                        proto_idx,
                    },
                    Resolution::Unknown(UnknownReason::PolymorphicSignature),
                )
            }
            InvokeKind::Custom | InvokeKind::CustomRange => {
                let Some(call_site_idx) = reference(ReferenceKind::CallSite) else {
                    return Stage::Incomplete(Incomplete::UnsupportedInstruction {
                        at: instruction.code_unit_offset,
                        opcode: instruction.opcode,
                    });
                };
                (
                    CallTarget::Custom { call_site_idx },
                    Resolution::Unknown(UnknownReason::CustomBootstrap),
                )
            }
        };
        // Reflection and loaders hide the target whatever the opcode says.
        if let CallTarget::Method { method_idx } = target
            && let Some(reason) = environment.special.get(&method_idx)
        {
            resolution = Resolution::Unknown(*reason);
        }
        let in_try = cfg
            .block_of(instruction.code_unit_offset)
            .is_some_and(|block| block.try_index.is_some());
        sites.push(CallSite {
            at: instruction.code_unit_offset,
            byte_offset: instruction.byte_offset.0,
            opcode: instruction.opcode,
            mnemonic: instruction.mnemonic.to_string(),
            target,
            resolution,
            in_try,
        });
    }
    Stage::Complete(sites)
}
