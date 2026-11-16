//! The complete smali display of validated facts (MDD-071), built on the instruction
//! renderer of `crate::smali_required`.
//!
//! # Why two modules
//!
//! `smali_required` is the method renderer that MDD-042 delivered and recorded as evidence
//! (its files, tests and mutation script are named by that task's record). This module adds what
//! MDD-071 completes around it — annotations, parameter names, debug directives, class
//! declarations, fields, static values and the `context` view — and reaches the instruction text
//! only through its public hook ([`crate::smali_required::MethodExtras`]). With no extras the instruction text is
//! byte-identical to the MDD-042 text, which the unchanged MDD-042 tests keep proving. Copying
//! the instruction renderer here would give one format two writers; merging the two directories
//! belongs to a later task that re-cuts MDD-042's record.
//!
//! # The format `mdd.smali.v1`
//!
//! This comment is the specification. The independent renderer in
//! `conformance/decode/oracle.py` and `oracle_class.py` and the hand-written texts in
//! `conformance/decode/hand-expected*.txt` were written from it, not from this code. Where
//! the reference engine (dexsql 0.1.0) writes something, the format follows its frame; what it
//! does not write follows baksmali's conventions and is this crate's own choice.
//!
//! **Method** (the instruction lines are specified in `smali_required`):
//!
//! ```text
//! .method <flags> name(params)ret
//!     .registers N
//!     .param pK, "name"            parameters that have a debug name or annotations
//!     .param pK
//!         .annotation ...          (one block per annotation, two levels deep)
//!     .end param
//!     .annotation ...              annotations of the method
//!                                  a blank line
//!     :label                       labels, then `.catch` lines, then the debug lines of the address,
//!     .line N                      then the instruction itself
//!     instruction
//! .end method
//! ```
//!
//! A method without code has no registers line and no blank line: its `.param` and annotation
//! lines follow the `.method` line directly. `pK` is the register a parameter starts in: 0 for
//! the first parameter of a static method, 1 for an instance method's (`p0` is `this`); a `long`
//! or `double` takes two. A parameter's annotations are shown only when the method's annotation
//! slots are as many as its prototype has parameters; otherwise they are counted in `omitted`.
//!
//! **Debug lines** come from the debug program, one directive per event in program order, at the
//! address the program has reached: `.prologue`, `.epilogue`, `.line N`,
//! `.local rX, "name":Ltype;` (with `, "signature"` for the extended form; a missing name or type
//! is `null`), `.end local rX`, `.restart local rX`, `.source "file"` (or `.source null`). A
//! position writes `.line` only when the program gives it a positive line inside the code and is
//! not the pc-to-pc pattern (R8) that keeps a code address where the line should be. An event at
//! no instruction start or past the code writes nothing; both cases are counted in `omitted`
//! (`debug_events_not_at_an_instruction`, `positions_not_source_lines`).
//!
//! **Annotation block** at some indent:
//!
//! ```text
//! .annotation <build|runtime|system> Ltype;
//!     name = value
//! .end annotation
//! ```
//!
//! Elements are in stored order. A *value* is written by [`value`]: booleans as `true`/`false`,
//! `null`, byte/short/int/long as signed hexadecimal with suffix `t`, `s`, none, `L`, a char as
//! `'c'`, floats as the shortest decimal that reads back (`1.0f`, `2.5`, `NaN`, `-Infinityf`),
//! strings in double quotes with `\" \' \\ \b \t \n \f \r` and `\uXXXX` for the rest, types as
//! descriptors, fields and methods as `Lc;->n:t` and `Lc;->n(p)r`, enums as `.enum` plus the
//! field, a method type as its prototype descriptor, a method handle as `method_handle_<index>`,
//! an array as `{}` or `{` / one element per line, comma-separated, one level deeper / `}`, and a
//! nested annotation as `.subannotation Ltype;` / elements / `.end subannotation`.
//!
//! **Class** (`render_class`): `.class <flags> Lc;`, `.super`, `.source "file"`, then, each section
//! after one blank line and only if it has lines, the `.implements` lines, the class annotations,
//! the static fields (in the order the class data stores them, each with ` = value` when the
//! class's static-values array has one at its position) and the instance fields. A field with
//! annotations is followed by its blocks, four spaces deep, and `.end field` at column 0. Flag
//! words are listed in `class.rs`.
//!
//! **Context view** ([`context`]): a header line, then `line N: ` and the original line, for each
//! line of the full text that is a method line, a register line, a label (including the case
//! labels in a switch table) or an exception-table line (class text: class, super, source,
//! implements and field lines). `N` counts lines of the full text from zero.
//!
//! # Versions
//!
//! A change to what a text says or how it is written changes [`SMALI_FORMAT`] (or
//! [`CONTEXT_FORMAT`]); a change to the facts a text is built from does not. The text is a
//! display: it never stands for the raw code bytes, their fingerprint or the facts it was
//! built from, and it states nothing that the bytes do not (no decompilation, no inferred
//! call targets). `mdd.smali.v1` is the first version the engine names; the text MDD-042 wrote
//! was the instruction subset of it.
//!
//! # Units
//!
//! Four numbers are kept apart everywhere in this module and in the tools that use it:
//!
//! * a *byte offset* counts UTF-8 bytes of one rendered text (`offset`, `next_offset`,
//!   `total_bytes`, `max_bytes`);
//! * a *line number* counts lines of one rendered text (`start_line`, `end_line`,
//!   `total_lines`, `max_lines`, and the `line N:` numbers of the context view, which count
//!   lines of the *full* text);
//! * a *method offset* counts methods of one class ordered by method index (`method_offset`,
//!   `method_limit`, `next_method_offset`, `total_methods`);
//! * a *code-unit address* counts 16-bit units of one code item and appears only inside label
//!   names (`:goto_1f` is code-unit address 0x1f) and in `code_units`.

pub mod annotation;
pub mod class;
pub mod context;
pub mod method;
pub mod value;

pub use annotation::{AnnotationIndex, ParameterSlots};
pub use class::{ClassLimits, ClassView, RenderedClass, render_class};
pub use context::{CLASS_CONTEXT_HEADER, CONTEXT_HEADER, class_context, method_context};
pub use method::{ExtrasReport, FullMethod, FullMethodView, SmaliOptions, render_method_full};

/// The version of the smali text format.
pub const SMALI_FORMAT: &str = "mdd.smali.v1";
/// The version of the context view format.
pub const CONTEXT_FORMAT: &str = "mdd.smali-context.v1";
