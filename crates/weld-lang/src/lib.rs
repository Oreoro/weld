//! weld-lang: parse + typecheck rules into IR.
//!
//! Six keywords: `set`, `observe`, `control`, `state`, `deny`, `mark`.
//! One negation form: `not` / `not in`.
//! One temporal operator: `~>` (eventually followed by).

pub mod checker;
pub mod ir;
pub mod lexer;
pub mod parser;

pub use checker::typecheck;
pub use ir::*;

/// Parse and typecheck a rules source string into an IR.
pub fn compile(src: &str) -> Result<Ir, Diagnostic> {
    let (ir, latches) = parser::parse(src, None)?;
    checker::typecheck(ir, latches)
}

/// Parse and typecheck, resolving relative `include` paths against `cwd`.
pub fn compile_with_cwd(src: &str, cwd: &std::path::Path) -> Result<Ir, Diagnostic> {
    let (ir, latches) = parser::parse(src, Some(cwd))?;
    checker::typecheck(ir, latches)
}
