use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use super::ir::*;
use super::lexer::{lex, Token};

type Tok = (usize, Token);

pub fn parse(src: &str, cwd: Option<&Path>) -> Result<(Ir, Vec<LatchDef>), Diagnostic> {
    let toks = lex(src)?;
    let mut p = Parser {
        toks,
        pos: 0,
        cwd: cwd.map(|p| p.to_path_buf()),
        included: BTreeSet::new(),
        latches: Vec::new(),
    };
    let mut ir = Ir::default();
    p.parse_file_into(&mut ir)?;
    Ok((ir, std::mem::take(&mut p.latches)))
}

struct Parser {
    toks: Vec<Tok>,
    pos: usize,
    cwd: Option<PathBuf>,
    included: BTreeSet<PathBuf>,
    latches: Vec<LatchDef>,
}

impl Parser {
    fn peek(&self) -> &Token {
        &self.toks[self.pos].1
    }

    fn peek_word(&self) -> Option<&str> {
        match &self.toks[self.pos].1 {
            Token::Word(w) => Some(w.as_str()),
            _ => None,
        }
    }

    fn line(&self) -> usize {
        self.toks[self.pos].0
    }

    fn bump(&mut self) -> Token {
        let t = self.toks[self.pos].1.clone();
        if self.pos + 1 < self.toks.len() {
            self.pos += 1;
        }
        t
    }

    fn eat(&mut self, t: &Token) -> bool {
        if self.peek() == t {
            self.bump();
            true
        } else {
            false
        }
    }

    fn expect(&mut self, t: &Token) -> Result<(), Diagnostic> {
        if self.eat(t) {
            Ok(())
        } else {
            Err(self.err(format!("expected {}, found {}", t, self.peek())))
        }
    }

    fn expect_word(&mut self) -> Result<String, Diagnostic> {
        match self.peek().clone() {
            Token::Word(w) => {
                self.bump();
                Ok(w)
            }
            other => Err(self.err(format!("expected a name, found {}", other))),
        }
    }

    fn expect_kw(&mut self, w: &str) -> Result<(), Diagnostic> {
        match self.peek().clone() {
            Token::Word(s) if s == w => {
                self.bump();
                Ok(())
            }
            other => Err(self.err(format!("expected '{}', found {}", w, other))),
        }
    }

    fn err(&self, msg: impl Into<String>) -> Diagnostic {
        Diagnostic {
            line: self.line(),
            col: 1,
            message: msg.into(),
            hint: None,
        }
    }

    fn skip_newlines(&mut self) {
        while matches!(self.peek(), Token::Newline) {
            self.bump();
        }
    }

    fn at_eol(&self) -> bool {
        matches!(self.peek(), Token::Newline | Token::Eof)
    }

    fn parse_file_into(&mut self, ir: &mut Ir) -> Result<(), Diagnostic> {
        self.skip_newlines();
        while !matches!(self.peek(), Token::Eof) {
            let kw = self.expect_word()?;
            match kw.as_str() {
                "set" => self.parse_set(ir)?,
                "observe" => self.parse_events(ir, true)?,
                "control" => self.parse_events(ir, false)?,
                "state" => self.parse_state(ir)?,
                "deny" => self.parse_deny(ir)?,
                "mark" => self.parse_mark(ir)?,
                "include" => self.parse_include(ir)?,
                other => {
                    return Err(self
                        .err(format!("unknown declaration '{}'", other))
                        .with_hint(
                            "expected one of: set, observe, control, state, deny, mark, include",
                        ))
                }
            }
            if !self.at_eol() {
                return Err(self.err(format!("unexpected {} after declaration", self.peek())));
            }
            self.skip_newlines();
        }
        Ok(())
    }

    fn parse_set(&mut self, ir: &mut Ir) -> Result<(), Diagnostic> {
        let name = self.expect_word()?;
        self.expect(&Token::Assign)?;
        let mut pats = Vec::new();
        while !self.at_eol() {
            match self.peek().clone() {
                Token::Str(s) => {
                    self.bump();
                    pats.push(s);
                }
                Token::Word(w) => {
                    self.bump();
                    pats.push(w);
                }
                other => return Err(self.err(format!("expected a pattern, found {}", other))),
            }
        }
        if pats.is_empty() {
            return Err(self.err(format!("set '{}' has no patterns", name)));
        }
        if ir.sets.insert(name.clone(), pats).is_some() {
            return Err(self.err(format!("set '{}' declared twice", name)));
        }
        Ok(())
    }

    fn parse_events(&mut self, ir: &mut Ir, observe: bool) -> Result<(), Diagnostic> {
        while !self.at_eol() {
            let w = self.expect_word()?;
            let pat = EventPat::parse(&w);
            let list = if observe {
                &mut ir.observe
            } else {
                &mut ir.control
            };
            list.push(pat);
        }
        Ok(())
    }

    fn parse_state(&mut self, ir: &mut Ir) -> Result<(), Diagnostic> {
        let name = self.expect_word()?;
        self.expect(&Token::Assign)?;
        let line = self.line();
        let expr = self.parse_expr()?;
        if ir.state_index.contains_key(&name) || ir.marks.iter().any(|m| m.name == name) {
            return Err(self.err(format!("'{}' declared twice", name)));
        }
        let idx = ir.states.len();
        ir.states.push(StateDecl {
            name: name.clone(),
            expr,
            line,
        });
        ir.state_index.insert(name, idx);
        Ok(())
    }

    fn parse_mark(&mut self, ir: &mut Ir) -> Result<(), Diagnostic> {
        let name = self.expect_word()?;
        self.expect_kw("if")?;
        let line = self.line();
        let expr = self.parse_expr()?;
        if ir.state_index.contains_key(&name) || ir.marks.iter().any(|m| m.name == name) {
            return Err(self.err(format!("'{}' declared twice", name)));
        }
        ir.marks.push(MarkDecl { name, expr, line });
        Ok(())
    }

    fn parse_include(&mut self, ir: &mut Ir) -> Result<(), Diagnostic> {
        let path = match self.peek().clone() {
            Token::Str(s) => {
                self.bump();
                s
            }
            other => return Err(self.err(format!("expected a path string, found {}", other))),
        };
        let cwd = self
            .cwd
            .clone()
            .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
        let full = if Path::new(&path).is_absolute() {
            PathBuf::from(&path)
        } else {
            cwd.join(&path)
        };
        let key = full.canonicalize().unwrap_or_else(|_| full.clone());
        if !self.included.insert(key.clone()) {
            return Ok(()); // include-once
        }
        let src = std::fs::read_to_string(&key).map_err(|e| Diagnostic {
            line: self.line(),
            col: 1,
            message: format!("cannot read include '{}': {}", path, e),
            hint: None,
        })?;
        let toks = lex(&src)?;
        let mut sub = Parser {
            toks,
            pos: 0,
            cwd: Some(key.parent().unwrap_or(Path::new(".")).to_path_buf()),
            included: self.included.clone(),
            latches: Vec::new(),
        };
        sub.parse_file_into(ir)?;
        self.included = sub.included;
        self.latches.extend(sub.latches);
        Ok(())
    }

    fn parse_deny(&mut self, ir: &mut Ir) -> Result<(), Diagnostic> {
        let line = self.line();
        let mut conds = vec![self.parse_cond()?];
        while self.eat(&Token::Arrow) {
            conds.push(self.parse_cond()?);
        }
        let id = ir.denies.len();
        ir.denies.push(DenyRule { id, line, conds });
        Ok(())
    }

    fn parse_cond(&mut self) -> Result<Cond, Diagnostic> {
        let event = self.parse_event_name()?;
        let argpats = self.parse_opt_args()?;
        let guard = if self.peek_word() == Some("if") {
            self.bump();
            Some(self.parse_expr()?)
        } else {
            None
        };
        Ok(Cond {
            event,
            argpats,
            guard,
        })
    }

    fn parse_cond_no_if(&mut self) -> Result<Cond, Diagnostic> {
        let event = self.parse_event_name()?;
        let argpats = self.parse_opt_args()?;
        Ok(Cond {
            event,
            argpats,
            guard: None,
        })
    }

    fn parse_event_name(&mut self) -> Result<String, Diagnostic> {
        let w = self.expect_word()?;
        if w.ends_with(".*") {
            return Err(Diagnostic {
                line: self.line(),
                col: 1,
                message: format!("trace events must be concrete names, got '{}'", w),
                hint: Some(
                    "wildcards like 'vcs.*' belong in observe/control declarations only".into(),
                ),
            });
        }
        Ok(w)
    }

    fn parse_opt_args(&mut self) -> Result<Vec<Arg>, Diagnostic> {
        if !self.eat(&Token::LParen) {
            return Ok(Vec::new());
        }
        let mut args = Vec::new();
        if matches!(self.peek(), Token::RParen) {
            self.bump();
            return Ok(args);
        }
        loop {
            match self.peek().clone() {
                Token::Word(w) if w == "_" => {
                    self.bump();
                    args.push(Arg::Wild);
                }
                Token::Word(w) => {
                    self.bump();
                    args.push(Arg::Var(w));
                }
                Token::Str(s) => {
                    self.bump();
                    args.push(Arg::Lit(s));
                }
                Token::Int(n) => {
                    self.bump();
                    args.push(Arg::Lit(n.to_string()));
                }
                other => return Err(self.err(format!("expected an argument, found {}", other))),
            }
            if !self.eat(&Token::Comma) {
                break;
            }
        }
        self.expect(&Token::RParen)?;
        Ok(args)
    }

    // ---- expressions ----

    fn parse_expr(&mut self) -> Result<Expr, Diagnostic> {
        let mut lhs = self.parse_and()?;
        while self.peek_word() == Some("or") {
            self.bump();
            let rhs = self.parse_and()?;
            lhs = Expr::Or(Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_and(&mut self) -> Result<Expr, Diagnostic> {
        let mut lhs = self.parse_not()?;
        while self.peek_word() == Some("and") {
            self.bump();
            let rhs = self.parse_not()?;
            lhs = Expr::And(Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_not(&mut self) -> Result<Expr, Diagnostic> {
        if self.peek_word() == Some("not") {
            self.bump();
            let inner = self.parse_not()?;
            return Ok(Expr::Not(Box::new(inner)));
        }
        self.parse_atom()
    }

    fn parse_atom(&mut self) -> Result<Expr, Diagnostic> {
        let line = self.line();
        match self.peek().clone() {
            Token::LParen => {
                self.bump();
                let e = self.parse_expr()?;
                self.expect(&Token::RParen)?;
                Ok(e)
            }
            Token::Word(w) => match w.as_str() {
                "seen" => {
                    self.bump();
                    let cond = self.parse_cond()?;
                    let idx = self.push_latch(LatchDef {
                        kind: LatchKind::Seen,
                        event: cond.event,
                        argpats: cond.argpats,
                        guard: cond.guard,
                        since: None,
                        cmp: Cmp::Eq,
                        lit: String::new(),
                        line,
                    });
                    Ok(Expr::LatchTest {
                        idx,
                        cmp: None,
                        lit: String::new(),
                    })
                }
                "last" => {
                    self.bump();
                    let cond = self.parse_cond_no_if()?;
                    let cmp = self.parse_cmp()?;
                    let lit = self.parse_literal()?;
                    let idx = self.push_latch(LatchDef {
                        kind: LatchKind::Last,
                        event: cond.event,
                        argpats: cond.argpats,
                        guard: None,
                        since: None,
                        cmp,
                        lit: lit.clone(),
                        line,
                    });
                    Ok(Expr::LatchTest {
                        idx,
                        cmp: Some(cmp),
                        lit,
                    })
                }
                "count" => {
                    self.bump();
                    let cond = self.parse_cond_no_if()?;
                    let since = if self.peek_word() == Some("since") {
                        self.bump();
                        Some(self.parse_cond_no_if()?)
                    } else {
                        None
                    };
                    let cmp = self.parse_cmp()?;
                    // Accept negative integers too (e.g. `-1`, which the
                    // lexer produces as a Word); the checker validates the
                    // bound range and reports a proper error.
                    let lit = self.parse_literal()?;
                    let idx = self.push_latch(LatchDef {
                        kind: LatchKind::Count,
                        event: cond.event,
                        argpats: cond.argpats,
                        guard: None,
                        since,
                        cmp,
                        lit: lit.clone(),
                        line,
                    });
                    Ok(Expr::LatchTest {
                        idx,
                        cmp: Some(cmp),
                        lit,
                    })
                }
                _ => {
                    let w = self.expect_word()?;
                    self.parse_var_atom(w)
                }
            },
            other => Err(self.err(format!("expected an expression, found {}", other))),
        }
    }

    fn parse_var_atom(&mut self, w: String) -> Result<Expr, Diagnostic> {
        if w == "env" && matches!(self.peek(), Token::LParen) {
            self.bump();
            let name = match self.peek().clone() {
                Token::Str(s) => {
                    self.bump();
                    s
                }
                other => return Err(self.err(format!("expected a string, found {}", other))),
            };
            self.expect(&Token::RParen)?;
            let cmp = self.parse_cmp()?;
            let lit = self.parse_literal()?;
            return Ok(Expr::VarCmp {
                var: VarRef {
                    name: format!("env:{}", name),
                    of: None,
                },
                cmp,
                lit,
            });
        }
        let mut var = VarRef { name: w, of: None };
        if matches!(self.peek(), Token::LParen) {
            self.bump();
            // e.g. target(c): "target" is derived from the binding "c".
            var.of = Some(self.expect_word()?);
            self.expect(&Token::RParen)?;
        }
        match self.peek().clone() {
            Token::Word(v) if v == "in" => {
                self.bump();
                let set = self.expect_word()?;
                Ok(Expr::In {
                    var,
                    set,
                    neg: false,
                })
            }
            Token::Word(v) if v == "not" => {
                self.bump();
                self.expect_kw("in")?;
                let set = self.expect_word()?;
                Ok(Expr::In {
                    var,
                    set,
                    neg: true,
                })
            }
            Token::Tilde => {
                self.bump();
                let pattern = self.parse_literal()?;
                Ok(Expr::Match {
                    var,
                    pattern,
                    neg: false,
                })
            }
            Token::Eq | Token::Ne | Token::Lt | Token::Gt | Token::Le | Token::Ge => {
                let cmp = self.parse_cmp()?;
                let lit = self.parse_literal()?;
                Ok(Expr::VarCmp { var, cmp, lit })
            }
            _ => Ok(Expr::Ref(var.name)),
        }
    }

    fn parse_cmp(&mut self) -> Result<Cmp, Diagnostic> {
        let c = match self.peek() {
            Token::Eq => Cmp::Eq,
            Token::Ne => Cmp::Ne,
            Token::Lt => Cmp::Lt,
            Token::Gt => Cmp::Gt,
            Token::Le => Cmp::Le,
            Token::Ge => Cmp::Ge,
            other => return Err(self.err(format!("expected a comparison, found {}", other))),
        };
        self.bump();
        Ok(c)
    }

    fn parse_literal(&mut self) -> Result<String, Diagnostic> {
        match self.peek().clone() {
            Token::Str(s) => {
                self.bump();
                Ok(s)
            }
            Token::Word(w) => {
                self.bump();
                Ok(w)
            }
            Token::Int(n) => {
                self.bump();
                Ok(n.to_string())
            }
            other => Err(self.err(format!("expected a literal, found {}", other))),
        }
    }

    fn push_latch(&mut self, def: LatchDef) -> usize {
        if let Some(i) = self.latches.iter().position(|d| d == &def) {
            i
        } else {
            self.latches.push(def);
            self.latches.len() - 1
        }
    }
}
