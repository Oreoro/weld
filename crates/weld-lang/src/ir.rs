use std::collections::BTreeMap;
use std::fmt;

#[derive(Debug, Clone, PartialEq)]
pub enum EventPat {
    Exact(String),
    Prefix(String),
}

impl EventPat {
    pub fn parse(word: &str) -> EventPat {
        match word.strip_suffix(".*") {
            Some(base) => EventPat::Prefix(base.to_string()),
            None => EventPat::Exact(word.to_string()),
        }
    }

    pub fn matches(&self, event: &str) -> bool {
        match self {
            EventPat::Exact(n) => n == event,
            EventPat::Prefix(base) => {
                event == base
                    || (event.len() > base.len()
                        && event.starts_with(base.as_str())
                        && event.as_bytes()[base.len()] == b'.')
            }
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            EventPat::Exact(s) => s,
            EventPat::Prefix(s) => s,
        }
    }
}

impl fmt::Display for EventPat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EventPat::Exact(s) => write!(f, "{}", s),
            EventPat::Prefix(s) => write!(f, "{}.*", s),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Arg {
    Var(String),
    Wild,
    Lit(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cmp {
    Eq,
    Ne,
    Lt,
    Gt,
    Le,
    Ge,
}

impl Cmp {
    pub fn eval_i64(&self, a: i64, b: i64) -> bool {
        match self {
            Cmp::Eq => a == b,
            Cmp::Ne => a != b,
            Cmp::Lt => a < b,
            Cmp::Gt => a > b,
            Cmp::Le => a <= b,
            Cmp::Ge => a >= b,
        }
    }

    pub fn eval_str(&self, a: &str, b: &str) -> bool {
        match self {
            Cmp::Eq => a == b,
            Cmp::Ne => a != b,
            Cmp::Lt => a < b,
            Cmp::Gt => a > b,
            Cmp::Le => a <= b,
            Cmp::Ge => a >= b,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Cmp::Eq => "==",
            Cmp::Ne => "!=",
            Cmp::Lt => "<",
            Cmp::Gt => ">",
            Cmp::Le => "<=",
            Cmp::Ge => ">=",
        }
    }
}

/// A guard variable reference. `of` marks a derived variable: `target(c)`
/// reads binding `c` and takes its last whitespace-separated token (the
/// file operand of a command).
#[derive(Debug, Clone, PartialEq)]
pub struct VarRef {
    pub name: String,
    pub of: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    True,
    /// State-name reference; resolved to LatchTest by the typechecker.
    Ref(String),
    In {
        var: VarRef,
        set: String,
        neg: bool,
    },
    Match {
        var: VarRef,
        pattern: String,
        neg: bool,
    },
    VarCmp {
        var: VarRef,
        cmp: Cmp,
        lit: String,
    },
    LatchTest {
        idx: usize,
        cmp: Option<Cmp>,
        lit: String,
    },
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
}

/// One step of a deny trace or a latch trigger.
#[derive(Debug, Clone, PartialEq)]
pub struct Cond {
    pub event: String,
    pub argpats: Vec<Arg>,
    pub guard: Option<Expr>,
}

impl Cond {
    /// A cond is "conditional" when its firing depends on runtime values
    /// (literal arg patterns or a guard). Otherwise a name match decides it.
    pub fn is_conditional(&self) -> bool {
        self.guard.is_some() || self.argpats.iter().any(|a| matches!(a, Arg::Lit(_)))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LatchKind {
    Seen,
    Last,
    Count,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LatchDef {
    pub kind: LatchKind,
    pub event: String,
    pub argpats: Vec<Arg>,
    pub guard: Option<Expr>,
    pub since: Option<Cond>,
    pub cmp: Cmp,
    pub lit: String,
    pub line: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DenyRule {
    pub id: usize,
    pub line: usize,
    pub conds: Vec<Cond>,
}

/// A named state: `state name = expr`.
#[derive(Debug, Clone, PartialEq)]
pub struct StateDecl {
    pub name: String,
    pub expr: Expr,
    pub line: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MarkDecl {
    pub name: String,
    pub expr: Expr,
    pub line: usize,
}

#[derive(Debug, Clone, Default)]
pub struct Ir {
    pub sets: BTreeMap<String, Vec<String>>,
    pub observe: Vec<EventPat>,
    pub control: Vec<EventPat>,
    pub latches: Vec<LatchDef>,
    pub states: Vec<StateDecl>,
    pub state_index: BTreeMap<String, usize>,
    pub denies: Vec<DenyRule>,
    pub marks: Vec<MarkDecl>,
}

impl Ir {
    pub fn event_is_known(&self, event: &str) -> bool {
        self.observe
            .iter()
            .chain(self.control.iter())
            .any(|p| p.matches(event))
    }

    pub fn event_is_control(&self, event: &str) -> bool {
        self.control.iter().any(|p| p.matches(event))
    }

    pub fn event_is_observe(&self, event: &str) -> bool {
        self.observe.iter().any(|p| p.matches(event))
    }
}

#[derive(Debug, Clone)]
pub struct Diagnostic {
    pub line: usize,
    pub col: usize,
    pub message: String,
    pub hint: Option<String>,
}

impl Diagnostic {
    pub fn with_hint(mut self, hint: impl Into<String>) -> Diagnostic {
        self.hint = Some(hint.into());
        self
    }
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}: {}", self.line, self.col, self.message)?;
        if let Some(h) = &self.hint {
            write!(f, "\n  hint: {}", h)?;
        }
        Ok(())
    }
}
