//! Typechecker: resolves state references, validates events/sets/bounds.

use std::collections::BTreeMap;

use super::ir::*;

pub fn typecheck(mut ir: Ir, latches: Vec<LatchDef>) -> Result<Ir, Diagnostic> {
    ir.latches = latches;

    // Phase 1: resolve state declarations (they may reference other states).
    let mut cache: BTreeMap<String, Expr> = BTreeMap::new();
    let names: Vec<String> = ir.states.iter().map(|s| s.name.clone()).collect();
    for name in &names {
        resolve_state(&mut ir, name, &mut cache, &mut Vec::new())?;
    }

    // Phase 2: inline state refs in marks, deny guards and latch guards.
    let marks = std::mem::take(&mut ir.marks);
    for mut m in marks {
        m.expr = subst(m.expr, &cache, m.line)?;
        ir.marks.push(m);
    }

    let denies = std::mem::take(&mut ir.denies);
    for mut rule in denies {
        for cond in &mut rule.conds {
            if let Some(g) = cond.guard.take() {
                cond.guard = Some(subst(g, &cache, rule.line)?);
            }
        }
        ir.denies.push(rule);
    }

    let latches = std::mem::take(&mut ir.latches);
    for mut l in latches {
        if let Some(g) = l.guard.take() {
            l.guard = Some(subst(g, &cache, l.line)?);
        }
        if let Some(mut since) = l.since.take() {
            if let Some(g) = since.guard.take() {
                since.guard = Some(subst(g, &cache, l.line)?);
            }
            l.since = Some(since);
        }
        ir.latches.push(l);
    }

    check_events(&ir)?;
    check_sets(&ir)?;
    check_count_bounds(&ir)?;
    check_boolean_shapes(&ir)?;
    Ok(ir)
}

/// Resolve one state's expression, detecting cycles via `visiting`.
fn resolve_state(
    ir: &mut Ir,
    name: &str,
    cache: &mut BTreeMap<String, Expr>,
    visiting: &mut Vec<String>,
) -> Result<(), Diagnostic> {
    if cache.contains_key(name) {
        return Ok(());
    }
    if visiting.iter().any(|n| n == name) {
        let line = ir
            .states
            .iter()
            .find(|s| s.name == name)
            .map(|s| s.line)
            .unwrap_or(0);
        return Err(Diagnostic {
            line,
            col: 1,
            message: format!("cyclic state definition involving '{}'", name),
            hint: Some("states cannot reference themselves directly or indirectly".into()),
        });
    }
    visiting.push(name.to_string());

    let idx = ir.state_index[name];
    let line = ir.states[idx].line;
    let expr = ir.states[idx].expr.clone();
    let resolved = subst_phase1(expr, ir, cache, visiting, line)?;

    let idx = ir.state_index[name];
    ir.states[idx].expr = resolved.clone();
    cache.insert(name.to_string(), resolved);
    visiting.pop();
    Ok(())
}

/// Phase 1 substitution: resolves `Ref`s inside a state declaration. When a
/// ref to another (not yet resolved) state is found, that state is resolved
/// first, inlined, and cached.
fn subst_phase1(
    e: Expr,
    ir: &mut Ir,
    cache: &mut BTreeMap<String, Expr>,
    visiting: &mut Vec<String>,
    line: usize,
) -> Result<Expr, Diagnostic> {
    match e {
        Expr::Ref(name) => {
            if let Some(resolved) = cache.get(&name) {
                return Ok(resolved.clone());
            }
            if visiting.iter().any(|n| n == &name) {
                return Err(Diagnostic {
                    line,
                    col: 1,
                    message: format!("cyclic state definition involving '{}'", name),
                    hint: None,
                });
            }
            resolve_state(ir, &name, cache, visiting)?;
            Ok(cache[&name].clone())
        }
        Expr::And(a, b) => {
            let a = subst_phase1(*a, ir, cache, visiting, line)?;
            let b = subst_phase1(*b, ir, cache, visiting, line)?;
            Ok(Expr::And(Box::new(a), Box::new(b)))
        }
        Expr::Or(a, b) => {
            let a = subst_phase1(*a, ir, cache, visiting, line)?;
            let b = subst_phase1(*b, ir, cache, visiting, line)?;
            Ok(Expr::Or(Box::new(a), Box::new(b)))
        }
        Expr::Not(a) => {
            let a = subst_phase1(*a, ir, cache, visiting, line)?;
            Ok(Expr::Not(Box::new(a)))
        }
        other => Ok(other),
    }
}

/// Phase 2 substitution: all states are already resolved and cached, so a
/// `Ref` is simply replaced by its cached (inlined) expression.
fn subst(e: Expr, cache: &BTreeMap<String, Expr>, line: usize) -> Result<Expr, Diagnostic> {
    match e {
        Expr::Ref(name) => cache.get(&name).cloned().ok_or_else(|| Diagnostic {
            line,
            col: 1,
            message: format!("reference to undefined state '{}'", name),
            hint: Some("declare it with 'state name = ...'".into()),
        }),
        Expr::And(a, b) => Ok(Expr::And(
            Box::new(subst(*a, cache, line)?),
            Box::new(subst(*b, cache, line)?),
        )),
        Expr::Or(a, b) => Ok(Expr::Or(
            Box::new(subst(*a, cache, line)?),
            Box::new(subst(*b, cache, line)?),
        )),
        Expr::Not(a) => Ok(Expr::Not(Box::new(subst(*a, cache, line)?))),
        other => Ok(other),
    }
}

// ---------------------------------------------------------------------------
// Event classification
// ---------------------------------------------------------------------------

fn check_events(ir: &Ir) -> Result<(), Diagnostic> {
    // An exact event must not be both observed and controlled.
    for o in &ir.observe {
        if let EventPat::Exact(name) = o {
            if ir.control.iter().any(|c| c.matches(name)) {
                return Err(Diagnostic {
                    line: 0,
                    col: 1,
                    message: format!("event '{}' is both observed and controlled", name),
                    hint: Some("an event must be either observe or control, not both".into()),
                });
            }
        }
    }

    for rule in &ir.denies {
        for (i, cond) in rule.conds.iter().enumerate() {
            if !ir.event_is_known(&cond.event) {
                return Err(Diagnostic {
                    line: rule.line,
                    col: 1,
                    message: format!("deny rule references unknown event '{}'", cond.event),
                    hint: Some(format!(
                        "add '{}' to an observe or control declaration",
                        cond.event
                    )),
                });
            }
            let is_final = i == rule.conds.len() - 1;
            if is_final && ir.event_is_observe(&cond.event) {
                return Err(Diagnostic {
                    line: rule.line,
                    col: 1,
                    message: format!(
                        "cannot deny observable event '{}' — reads cannot be refused",
                        cond.event
                    ),
                    hint: Some(
                        "deny the controllable action instead, or gate it behind a state".into(),
                    ),
                });
            }
        }
    }

    for latch in &ir.latches {
        if !ir.event_is_known(&latch.event) {
            return Err(Diagnostic {
                line: latch.line,
                col: 1,
                message: format!("state references unknown event '{}'", latch.event),
                hint: Some("declare it with observe or control".into()),
            });
        }
        if let Some(since) = &latch.since {
            if !ir.event_is_known(&since.event) {
                return Err(Diagnostic {
                    line: latch.line,
                    col: 1,
                    message: format!("'since' references unknown event '{}'", since.event),
                    hint: None,
                });
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Set references
// ---------------------------------------------------------------------------

fn check_sets(ir: &Ir) -> Result<(), Diagnostic> {
    for rule in &ir.denies {
        for cond in &rule.conds {
            if let Some(g) = &cond.guard {
                check_set_refs(g, ir, rule.line)?;
            }
        }
    }
    for latch in &ir.latches {
        if let Some(g) = &latch.guard {
            check_set_refs(g, ir, latch.line)?;
        }
        if let Some(since) = &latch.since {
            if let Some(g) = &since.guard {
                check_set_refs(g, ir, latch.line)?;
            }
        }
    }
    Ok(())
}

fn check_set_refs(e: &Expr, ir: &Ir, line: usize) -> Result<(), Diagnostic> {
    match e {
        Expr::In { set, .. } => {
            if !ir.sets.contains_key(set) {
                return Err(Diagnostic {
                    line,
                    col: 1,
                    message: format!("reference to undefined set '{}'", set),
                    hint: Some("declare it with 'set name = pattern ...'".into()),
                });
            }
            Ok(())
        }
        Expr::And(a, b) | Expr::Or(a, b) => {
            check_set_refs(a, ir, line)?;
            check_set_refs(b, ir, line)
        }
        Expr::Not(a) => check_set_refs(a, ir, line),
        _ => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// Count bounds
// ---------------------------------------------------------------------------

fn check_count_bounds(ir: &Ir) -> Result<(), Diagnostic> {
    for latch in &ir.latches {
        if latch.kind != LatchKind::Count {
            continue;
        }
        match latch.lit.parse::<i64>() {
            Ok(n) if (0..=10_000).contains(&n) => {}
            _ => {
                return Err(Diagnostic {
                    line: latch.line,
                    col: 1,
                    message: format!(
                        "count bound '{}' must be an integer in 0..=10000",
                        latch.lit
                    ),
                    hint: Some("large bounds blow up the state space".into()),
                })
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Boolean shape of state / mark expressions
// ---------------------------------------------------------------------------

fn check_boolean_shapes(ir: &Ir) -> Result<(), Diagnostic> {
    for s in &ir.states {
        check_boolean(&s.expr, s.line, &format!("state '{}'", s.name))?;
    }
    for m in &ir.marks {
        check_boolean(&m.expr, m.line, &format!("mark '{}'", m.name))?;
    }
    Ok(())
}

fn check_boolean(e: &Expr, line: usize, ctx: &str) -> Result<(), Diagnostic> {
    match e {
        Expr::True | Expr::LatchTest { .. } => Ok(()),
        Expr::And(a, b) | Expr::Or(a, b) => {
            check_boolean(a, line, ctx)?;
            check_boolean(b, line, ctx)
        }
        Expr::Not(a) => check_boolean(a, line, ctx),
        _ => Err(Diagnostic {
            line,
            col: 1,
            message: format!("{} must be a boolean combination of states", ctx),
            hint: Some("only state names combined with and/or/not are allowed here".into()),
        }),
    }
}
