//! weld-synth — supervisory control synthesis.
//!
//! Builds the plant state space from the event alphabet, applies deny-rule
//! monitors, then computes the supremal controllable and nonblocking
//! sublanguage. The result is the maximally permissive supervisor: an event
//! is disabled only when enabling it could lead to a violation.
//!
//! Guards over runtime values are abstracted during synthesis: a guarded
//! condition is treated as "may fire" (both branches explored), so the
//! synthesized supervisor is conservative. The gate evaluates guards
//! concretely at runtime via `decide` and only disables when a guard
//! actually holds.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use weld_lang::{Arg, Cond, EventPat, Expr, Ir, LatchDef, LatchKind, VarRef};

pub const STATE_LIMIT: usize = 250_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Disable { rule: usize },
}

#[derive(Debug)]
pub enum SynthError {
    TooManyStates { count: usize, limit: usize },
    NoPathToMark { rule: usize },
    EmptyAlphabet,
}

impl std::fmt::Display for SynthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SynthError::TooManyStates { count, limit } => write!(
                f,
                "state space too large: {} states exceeds limit of {}",
                count, limit
            ),
            SynthError::NoPathToMark { rule } => write!(
                f,
                "no path to a marked state; rule {} over-constrains the system",
                rule
            ),
            SynthError::EmptyAlphabet => write!(f, "event alphabet is empty"),
        }
    }
}

impl std::error::Error for SynthError {}

/// Runtime latch value.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LatchVal {
    /// `seen` latch: has the (guarded) event occurred yet.
    Flag(bool),
    /// `last` latch: result of the most recent matching event.
    /// `None` = never matched; `Some(s)` = the result string.
    Last(Option<String>),
    /// `count` latch: occurrences since the reset event, saturating.
    Count(u32),
}

/// Symbolic state key: per-rule monitor positions plus latch values.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StateKey {
    pub pos: Vec<u16>,
    pub latches: Vec<LatchVal>,
}

struct StateData {
    key: StateKey,
    /// May-successors per event (guarded branches both enumerated).
    succs: BTreeMap<String, Vec<usize>>,
    /// Rules whose final cond's event matches here: (rule_id, unconditional).
    fire: BTreeMap<String, Vec<(usize, bool)>>,
    marked: bool,
    kept: bool,
    /// Rule responsible for this state being pruned (for diagnostics).
    poison: usize,
}

pub struct Supervisor {
    alphabet: Vec<String>,
    control: BTreeSet<String>,
    states: Vec<StateData>,
    index: BTreeMap<StateKey, usize>,
    initial: usize,
    latch_defs: Vec<LatchDef>,
    rules: Vec<Vec<Cond>>,
    last_domains: Vec<Vec<String>>,
    count_caps: Vec<u32>,
    limit: usize,
}

/// Build the supervisor from an IR.
pub fn synthesize(ir: &Ir) -> Result<Supervisor, SynthError> {
    let alphabet = build_alphabet(ir);
    if alphabet.is_empty() {
        return Err(SynthError::EmptyAlphabet);
    }
    let mut control = BTreeSet::new();
    for p in &ir.control {
        if let EventPat::Exact(name) = p {
            control.insert(name.clone());
        }
    }
    let mut sup = Supervisor {
        alphabet,
        control,
        states: Vec::new(),
        index: BTreeMap::new(),
        initial: 0,
        latch_defs: ir.latches.clone(),
        rules: ir.denies.iter().map(|d| d.conds.clone()).collect(),
        last_domains: build_last_domains(ir),
        count_caps: ir
            .latches
            .iter()
            .map(|l| match l.kind {
                LatchKind::Count => {
                    let n: i64 = l.lit.parse().unwrap_or(0);
                    (n.max(0) as u32 + 1).min(10_001)
                }
                _ => 0,
            })
            .collect(),
        limit: STATE_LIMIT,
    };
    sup.enumerate()?;
    sup.compute_marks(ir);
    sup.fixpoint()?;
    Ok(sup)
}

fn build_alphabet(ir: &Ir) -> Vec<String> {
    let mut set = BTreeSet::new();
    for p in ir.observe.iter().chain(ir.control.iter()) {
        if let EventPat::Exact(n) = p {
            set.insert(n.clone());
        }
    }
    for rule in &ir.denies {
        for c in &rule.conds {
            set.insert(c.event.clone());
        }
    }
    for l in &ir.latches {
        set.insert(l.event.clone());
        if let Some(s) = &l.since {
            set.insert(s.event.clone());
        }
    }
    set.into_iter().collect()
}

fn walk_expr(e: &Expr, f: &mut impl FnMut(&Expr)) {
    f(e);
    match e {
        Expr::And(a, b) | Expr::Or(a, b) => {
            walk_expr(a, f);
            walk_expr(b, f);
        }
        Expr::Not(a) => walk_expr(a, f),
        _ => {}
    }
}

/// Domain of possible `last` results per latch: every literal compared
/// against it anywhere in the program, plus the OTHER sentinel.
fn build_last_domains(ir: &Ir) -> Vec<Vec<String>> {
    let mut domains: Vec<BTreeSet<String>> =
        (0..ir.latches.len()).map(|_| BTreeSet::new()).collect();
    let visit = |e: &Expr, domains: &mut Vec<BTreeSet<String>>| {
        walk_expr(e, &mut |expr| {
            if let Expr::LatchTest {
                idx,
                cmp: Some(_),
                lit,
            } = expr
            {
                if let Some(LatchKind::Last) = ir.latches.get(*idx).map(|d| d.kind) {
                    domains[*idx].insert(lit.clone());
                }
            }
        });
    };
    for s in &ir.states {
        visit(&s.expr, &mut domains);
    }
    for m in &ir.marks {
        visit(&m.expr, &mut domains);
    }
    for rule in &ir.denies {
        for c in &rule.conds {
            if let Some(g) = &c.guard {
                visit(g, &mut domains);
            }
        }
    }
    for l in &ir.latches {
        if let Some(g) = &l.guard {
            visit(g, &mut domains);
        }
    }
    domains
        .into_iter()
        .map(|s| s.into_iter().collect())
        .collect()
}

fn initial_latches(defs: &[LatchDef]) -> Vec<LatchVal> {
    defs.iter()
        .map(|d| match d.kind {
            LatchKind::Seen => LatchVal::Flag(false),
            LatchKind::Last => LatchVal::Last(None),
            LatchKind::Count => LatchVal::Count(0),
        })
        .collect()
}

impl Supervisor {
    fn intern(&mut self, key: StateKey) -> usize {
        if let Some(&i) = self.index.get(&key) {
            return i;
        }
        let i = self.states.len();
        self.states.push(StateData {
            key: key.clone(),
            succs: BTreeMap::new(),
            fire: BTreeMap::new(),
            marked: false,
            kept: true,
            poison: 0,
        });
        self.index.insert(key, i);
        i
    }

    fn enumerate(&mut self) -> Result<(), SynthError> {
        let init_key = StateKey {
            pos: vec![0u16; self.rules.len()],
            latches: initial_latches(&self.latch_defs),
        };
        let init_idx = self.intern(init_key);
        let mut queue = VecDeque::new();
        queue.push_back(init_idx);
        while let Some(idx) = queue.pop_front() {
            let key = self.states[idx].key.clone();
            for event in self.alphabet.clone() {
                let (succs, fires) = self.expand(&key, &event);
                for sk in succs {
                    let is_new = !self.index.contains_key(&sk);
                    let t = self.intern(sk);
                    if is_new {
                        queue.push_back(t);
                    }
                    self.states[idx]
                        .succs
                        .entry(event.clone())
                        .or_default()
                        .push(t);
                }
                if !fires.is_empty() {
                    let entry = self.states[idx].fire.entry(event.clone()).or_default();
                    for (r, hard) in fires {
                        let slot = entry.iter_mut().find(|(rr, _)| *rr == r);
                        match slot {
                            Some(slot) => slot.1 |= hard,
                            None => entry.push((r, hard)),
                        }
                    }
                }
            }
            if self.states.len() > self.limit {
                return Err(SynthError::TooManyStates {
                    count: self.states.len(),
                    limit: self.limit,
                });
            }
        }
        Ok(())
    }

    /// Enumerate may-successors of (key, event) and record firing rules.
    fn expand(&self, key: &StateKey, event: &str) -> (Vec<StateKey>, Vec<(usize, bool)>) {
        let mut fires: Vec<(usize, bool)> = Vec::new();
        let mut per_rule: Vec<Vec<u16>> = Vec::with_capacity(self.rules.len());
        for (r, conds) in self.rules.iter().enumerate() {
            let p = key.pos[r] as usize;
            if p < conds.len() && conds[p].event == event {
                let is_last = p == conds.len() - 1;
                if is_last {
                    fires.push((r, !conds[p].is_conditional()));
                }
                // After the final cond the monitor resets to 0: a completed
                // trace leaves no residual position, so single-cond rules
                // carry no state at all and repeated violations are detected
                // anew instead of latching "fired" forever.
                let next = if is_last { 0usize } else { p + 1 };
                if conds[p].is_conditional() {
                    // May fire (guard true / literal args match) or not.
                    if next == p {
                        per_rule.push(vec![p as u16]);
                    } else {
                        per_rule.push(vec![p as u16, next as u16]);
                    }
                } else {
                    per_rule.push(vec![next as u16]);
                }
            } else {
                per_rule.push(vec![p as u16]);
            }
        }

        let mut per_latch: Vec<Vec<LatchVal>> = Vec::with_capacity(self.latch_defs.len());
        for (i, def) in self.latch_defs.iter().enumerate() {
            let cur = key.latches[i].clone();
            let main_matches = def.event == event;
            let since_ref = def.since.as_ref();
            let since_matches = since_ref.is_some_and(|s| s.event == event);
            if !main_matches && !since_matches {
                per_latch.push(vec![cur]);
                continue;
            }
            let update_conditional =
                def.guard.is_some() || def.argpats.iter().any(|a| matches!(a, Arg::Lit(_)));
            match def.kind {
                LatchKind::Seen => {
                    if update_conditional {
                        per_latch.push(vec![cur.clone(), LatchVal::Flag(true)]);
                    } else {
                        per_latch.push(vec![LatchVal::Flag(true)]);
                    }
                }
                LatchKind::Last => {
                    // `last` updates to one of the compared literals or the
                    // "other" sentinel. If the update is conditional (literal
                    // args / guard), the current value is also possible.
                    let mut vals: Vec<LatchVal> = self.last_domains[i]
                        .iter()
                        .map(|s| LatchVal::Last(Some(s.clone())))
                        .collect();
                    vals.push(LatchVal::Last(Some(OTHER_RESULT.to_string())));
                    if update_conditional {
                        vals.push(cur.clone());
                    }
                    per_latch.push(vals);
                }
                LatchKind::Count => {
                    let c = match cur {
                        LatchVal::Count(c) => c,
                        _ => 0,
                    };
                    let cap = self.count_caps[i];
                    let since_ref = def.since.as_ref();
                    let since_matches = since_ref.is_some_and(|s| s.event == event);
                    let since_cond = since_ref.is_some_and(|s| s.is_conditional());
                    let main_cond = update_conditional;
                    let mut vals = BTreeSet::new();
                    if since_matches && main_matches {
                        // Same event triggers both reset and increment.
                        vals.insert(LatchVal::Count(1.min(cap)));
                        vals.insert(LatchVal::Count((c + 1).min(cap)));
                        if main_cond {
                            vals.insert(LatchVal::Count(0));
                        }
                        if main_cond && since_cond {
                            vals.insert(LatchVal::Count(c.min(cap)));
                        }
                    } else if since_matches {
                        // Reset-only event.
                        vals.insert(LatchVal::Count(0));
                        if since_cond {
                            // Reset is conditional (literal args); it may
                            // not apply, leaving the count unchanged.
                            vals.insert(LatchVal::Count(c));
                        }
                    } else {
                        // Increment only.
                        vals.insert(LatchVal::Count((c + 1).min(cap)));
                        if main_cond {
                            vals.insert(LatchVal::Count(c));
                        }
                    }
                    per_latch.push(vals.into_iter().collect());
                }
            }
        }

        // Cartesian product: first monitor positions, then latch values.
        let mut acc: Vec<(Vec<u16>, Vec<LatchVal>)> = vec![(Vec::new(), Vec::new())];
        for opts in &per_rule {
            let mut next = Vec::new();
            for (pos, lats) in acc {
                for &o in opts {
                    let mut np = pos.clone();
                    np.push(o);
                    next.push((np, lats.clone()));
                }
            }
            acc = next;
        }
        for opts in &per_latch {
            let mut next = Vec::new();
            for (pos, lats) in acc {
                for o in opts {
                    let mut nl = lats.clone();
                    nl.push(o.clone());
                    next.push((pos.clone(), nl));
                }
            }
            acc = next;
        }
        let out = acc
            .into_iter()
            .map(|(pos, latches)| StateKey { pos, latches })
            .collect();
        (out, fires)
    }

    fn compute_marks(&mut self, ir: &Ir) {
        if ir.marks.is_empty() {
            // No marks: nonblocking is vacuous, every state is accepting.
            for sd in &mut self.states {
                sd.marked = true;
            }
            return;
        }
        let marks: Vec<Expr> = ir.marks.iter().map(|m| m.expr.clone()).collect();
        for sd in &mut self.states {
            sd.marked = marks.iter().any(|e| eval_abstract(e, &sd.key.latches));
        }
    }

    /// Supremal controllable + nonblocking sublanguage.
    fn fixpoint(&mut self) -> Result<(), SynthError> {
        let n = self.states.len();
        // Reverse adjacency over allowed edges (may-edges minus
        // hard-disabled control events).
        let mut radj: Vec<Vec<usize>> = vec![Vec::new(); n];
        for (i, sd) in self.states.iter().enumerate() {
            for (e, ts) in &sd.succs {
                let hard = sd.fire.get(e).is_some_and(|v| v.iter().any(|(_, h)| *h));
                if self.control.contains(e) && hard {
                    continue;
                }
                for &t in ts {
                    radj[t].push(i);
                }
            }
        }

        let mut kept: Vec<bool> = vec![true; n];
        loop {
            // Co-reachability to marks within kept, over allowed edges.
            let mut reach = vec![false; n];
            let mut queue = VecDeque::new();
            for i in 0..n {
                if kept[i] && self.states[i].marked {
                    reach[i] = true;
                    queue.push_back(i);
                }
            }
            while let Some(t) = queue.pop_front() {
                for &s in &radj[t] {
                    if kept[s] && !reach[s] {
                        reach[s] = true;
                        queue.push_back(s);
                    }
                }
            }
            // Observe-escape pruning: an uncontrollable event may pull the
            // plant into a non-coreachable state, so the source state cannot
            // guarantee nonblocking either.
            for i in 0..n {
                if !reach[i] {
                    continue;
                }
                'outer: for (e, ts) in &self.states[i].succs {
                    if self.control.contains(e) {
                        continue;
                    }
                    for &t in ts {
                        if kept[t] && !reach[t] {
                            reach[i] = false;
                            break 'outer;
                        }
                    }
                }
            }
            let new_kept: Vec<bool> = (0..n).map(|i| kept[i] && reach[i]).collect();
            if new_kept == kept {
                break;
            }
            kept = new_kept;
        }

        // Attribute poison: for each pruned state, the lowest rule id that
        // can fire there (for diagnostics); 0 if none.
        for (i, sd) in self.states.iter_mut().enumerate() {
            sd.kept = kept[i];
            if !kept[i] {
                sd.poison = sd
                    .fire
                    .values()
                    .flatten()
                    .map(|(r, _)| *r)
                    .min()
                    .unwrap_or(0);
            }
        }

        if !self.states[self.initial].kept {
            return Err(SynthError::NoPathToMark {
                rule: self.states[self.initial].poison,
            });
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // Public queries
    // ------------------------------------------------------------------

    pub fn alphabet(&self) -> &[String] {
        &self.alphabet
    }

    pub fn state_count(&self) -> usize {
        self.states.len()
    }

    pub fn initial(&self) -> usize {
        self.initial
    }

    pub fn key_of(&self, s: usize) -> &StateKey {
        &self.states[s].key
    }

    /// Static (conservative) verdict. `Disable` means "some rule may fire or
    /// the event may leave the safe region"; the gate refines with concrete
    /// guard evaluation via `decide`.
    pub fn verdict(&self, s: usize, event: &str) -> Verdict {
        if !self.states[s].kept {
            return Verdict::Disable {
                rule: self.states[s].poison,
            };
        }
        if let Some(list) = self.states[s].fire.get(event) {
            let min = list.iter().map(|(r, _)| *r).min().unwrap_or(0);
            return Verdict::Disable { rule: min };
        }
        if self.control.contains(event) {
            if let Some(ts) = self.states[s].succs.get(event) {
                for &t in ts {
                    if !self.states[t].kept {
                        return Verdict::Disable {
                            rule: self.states[t].poison,
                        };
                    }
                }
            }
        }
        Verdict::Allow
    }

    /// Concrete runtime verdict: evaluates guards and literal arg patterns
    /// against actual values. `bindings` is cleared and filled with the
    /// arg bindings of the matching rule.
    pub fn decide(
        &self,
        s: usize,
        event: &str,
        args: &[String],
        bindings: &mut BTreeMap<String, String>,
    ) -> Verdict {
        if !self.states[s].kept {
            return Verdict::Disable {
                rule: self.states[s].poison,
            };
        }
        let latches = &self.states[s].key.latches;

        // A rule fires when its final cond matches concretely. Matching a
        // non-final cond only advances the monitor (done in `step`); it is
        // not a violation, so it must not disable the event.
        for (r, conds) in self.rules.iter().enumerate() {
            let p = self.states[s].key.pos[r] as usize;
            if p + 1 == conds.len() && conds[p].event == event {
                bindings.clear();
                if cond_matches(&conds[p], args, bindings, latches) {
                    return Verdict::Disable { rule: r };
                }
            }
        }

        // Control event may leave the safe region (guard-dependent branch).
        if self.control.contains(event) {
            if let Some(ts) = self.states[s].succs.get(event) {
                for &t in ts {
                    if !self.states[t].kept {
                        return Verdict::Disable {
                            rule: self.states[t].poison,
                        };
                    }
                }
            }
        }
        Verdict::Allow
    }

    /// Rules that could fire on this event from this state (for `weld why`).
    pub fn firing_rules(&self, s: usize, event: &str) -> Vec<usize> {
        self.states[s]
            .fire
            .get(event)
            .map(|v| v.iter().map(|(r, _)| *r).collect())
            .unwrap_or_default()
    }

    /// Rules that fire on this event from this state *regardless of the
    /// arguments*: their final condition has no guard and no literal-arg
    /// pattern, so *every* call of this event violates. The tool-list filter
    /// hides a tool only in this case — hiding tools whose event is merely
    /// conditionally denied would leave the agent with no way to do legal
    /// work.
    pub fn hard_firing_rules(&self, s: usize, event: &str) -> Vec<usize> {
        self.states[s]
            .fire
            .get(event)
            .map(|v| {
                v.iter()
                    .filter(|(_, hard)| *hard)
                    .map(|(r, _)| *r)
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn disabled_in(&self, s: usize) -> Vec<(String, usize)> {
        let mut out = Vec::new();
        for e in &self.alphabet {
            if let Verdict::Disable { rule } = self.verdict(s, e) {
                out.push((e.clone(), rule));
            }
        }
        out
    }

    /// Rules that can never fire from the initial state: no reachable state
    /// puts the rule's monitor at its final condition with a matching event.
    /// Usually a sign of a typo in the rule or an over-restrictive guard.
    pub fn dead_rules(&self) -> Vec<usize> {
        let mut alive = vec![false; self.rules.len()];
        for sd in &self.states {
            for rules in sd.fire.values() {
                for (r, _) in rules {
                    alive[*r] = true;
                }
            }
        }
        (0..self.rules.len()).filter(|&r| !alive[r]).collect()
    }

    /// Export the supervisor FSM as a Graphviz DOT graph. Kept states are
    /// drawn normally, pruned (unsafe) states are dashed red, marked
    /// (goal) states are double circles, and deny fires are red self-loops.
    pub fn to_dot(&self, ir: &Ir) -> String {
        let mut out = String::from("digraph supervisor {\n");
        out.push_str("  rankdir=LR;\n");
        out.push_str("  node [shape=ellipse fontname=\"monospace\" fontsize=10];\n");
        out.push_str("  start [shape=point];\n");

        let mut edges = std::collections::BTreeSet::<(usize, usize, String)>::new();
        for (i, sd) in self.states.iter().enumerate() {
            for (event, ts) in &sd.succs {
                for &t in ts {
                    edges.insert((i, t, event.clone()));
                }
            }
        }

        for (i, sd) in self.states.iter().enumerate() {
            let mut label = format!("s{i}");
            for (r, p) in sd.key.pos.iter().enumerate() {
                if *p > 0 {
                    label.push_str(&format!("\\nr{r}@{p}"));
                }
            }
            for (idx, lat) in sd.key.latches.iter().enumerate() {
                let name = ir
                    .states
                    .get(idx)
                    .map(|s| s.name.as_str())
                    .unwrap_or("state");
                let val = match lat {
                    LatchVal::Flag(true) => "1".to_string(),
                    LatchVal::Flag(false) => "0".to_string(),
                    LatchVal::Last(Some(v)) => format!("\"{v}\""),
                    LatchVal::Last(None) => "∅".to_string(),
                    LatchVal::Count(c) => format!("{c}"),
                };
                label.push_str(&format!("\\n{name}={val}"));
            }
            let style = if sd.kept { "solid" } else { "dashed" };
            let fill = if sd.kept { "white" } else { "mistyrose" };
            let shape = if sd.marked { ", peripheries=2" } else { "" };
            out.push_str(&format!(
                "  s{i} [label=\"{label}\" style=\"{style}\" fillcolor=\"{fill}\"{shape}];\n"
            ));
            if i == self.initial {
                out.push_str(&format!("  start -> s{i};\n"));
            }
        }

        for (i, t, event) in edges {
            out.push_str(&format!("  s{i} -> s{t} [label=\"{event}\"];\n"));
        }

        for (i, sd) in self.states.iter().enumerate() {
            for (event, rules) in &sd.fire {
                for (r, _) in rules {
                    out.push_str(&format!(
                        "  s{i} -> s{i} [label=\"{event} ⛔ rule {r}\" color=red fontcolor=red];\n"
                    ));
                }
            }
        }

        out.push_str("}\n");
        out
    }

    /// Concrete runtime transition. `result` is the outcome of the action
    /// (exit code, command output prefix, etc.) used by `last` latches.
    /// Returns the new state id, or None if the transition is impossible.
    pub fn step(
        &self,
        s: usize,
        event: &str,
        args: &[String],
        result: Option<&str>,
    ) -> Option<usize> {
        let sd = self.states.get(s)?;
        let mut pos = sd.key.pos.clone();
        let mut latches = sd.key.latches.clone();

        // Monitors advance iff name + args + guard hold concretely.
        // A matched final cond resets the monitor to 0, matching expand.
        for (r, p) in pos.iter_mut().enumerate() {
            let conds = &self.rules[r];
            let pi = *p as usize;
            if pi < conds.len() && conds[pi].event == event {
                let c = &conds[pi];
                let mut bindings = BTreeMap::new();
                if cond_matches(c, args, &mut bindings, &latches) {
                    if pi + 1 == conds.len() {
                        *p = 0;
                    } else {
                        *p += 1;
                    }
                }
            }
        }

        // Latch updates, computed against the pre-state.
        let mut updates: Vec<(usize, LatchVal)> = Vec::new();
        for (i, def) in self.latch_defs.iter().enumerate() {
            let main_matches = def.event == event;
            let since_matches = def.since.as_ref().is_some_and(|s| s.event == event);
            if !main_matches && !since_matches {
                continue;
            }
            let mut bindings = BTreeMap::new();
            for (ai, a) in def.argpats.iter().enumerate() {
                if let Arg::Var(name) = a {
                    if let Some(v) = args.get(ai) {
                        bindings.insert(name.clone(), v.clone());
                    }
                }
            }
            match def.kind {
                LatchKind::Seen => {
                    if main_matches
                        && args_match(&def.argpats, args)
                        && guard_holds(def.guard.as_ref(), &bindings, &latches)
                    {
                        updates.push((i, LatchVal::Flag(true)));
                    }
                }
                LatchKind::Last => {
                    if main_matches && args_match(&def.argpats, args) {
                        // Snap the result into the synthesis domain so the
                        // successor key resolves to an enumerated state.
                        let v = match result {
                            Some(r) if self.last_domains[i].iter().any(|d| d == r) => {
                                Some(r.to_string())
                            }
                            Some(_) => Some(OTHER_RESULT.to_string()),
                            None => None,
                        };
                        updates.push((i, LatchVal::Last(v)));
                    }
                }
                LatchKind::Count => {
                    let mut c = match latches[i] {
                        LatchVal::Count(c) => c,
                        _ => 0,
                    };
                    if let Some(since) = &def.since {
                        if since.event == event
                            && args_match(&since.argpats, args)
                            && guard_holds(since.guard.as_ref(), &bindings, &latches)
                        {
                            c = 0;
                        }
                    }
                    if main_matches && args_match(&def.argpats, args) {
                        c = (c + 1).min(self.count_caps[i]);
                    }
                    updates.push((i, LatchVal::Count(c)));
                }
            }
        }
        for (i, v) in updates {
            latches[i] = v;
        }

        let key = StateKey { pos, latches };
        self.index.get(&key).copied()
    }
}

/// Sentinel result meaning "matched but value not in any compared literal
/// domain".
const OTHER_RESULT: &str = "\u{0}other";

fn args_match(argpats: &[Arg], args: &[String]) -> bool {
    if argpats.is_empty() {
        return true;
    }
    argpats.iter().enumerate().all(|(i, a)| match a {
        Arg::Wild | Arg::Var(_) => true,
        Arg::Lit(l) => args.get(i) == Some(l),
    })
}

/// Bind Var(argpat) names to concrete args, check literal patterns, and
/// evaluate the guard. Returns true when the cond fires.
fn cond_matches(
    c: &Cond,
    args: &[String],
    bindings: &mut BTreeMap<String, String>,
    latches: &[LatchVal],
) -> bool {
    if !args_match(&c.argpats, args) {
        return false;
    }
    for (i, a) in c.argpats.iter().enumerate() {
        if let Arg::Var(name) = a {
            if let Some(v) = args.get(i) {
                bindings.insert(name.clone(), v.clone());
            }
        }
    }
    guard_holds(c.guard.as_ref(), bindings, latches)
}

fn guard_holds(
    guard: Option<&Expr>,
    bindings: &BTreeMap<String, String>,
    latches: &[LatchVal],
) -> bool {
    match guard {
        Some(g) => eval_concrete(g, bindings, latches),
        None => true,
    }
}

/// Resolve a guard variable to its concrete value. Derived variables
/// (`target(c)`) take the last whitespace-separated token of their source
/// binding. Because that token is a path operand of a command string, it is
/// canonicalized (tilde expanded, made absolute against the current
/// directory, lexically normalized) so set membership compares consistently
/// with the gate's canonicalized path arguments.
fn resolve_var(var: &VarRef, bindings: &BTreeMap<String, String>) -> Option<String> {
    match &var.of {
        Some(src) => bindings
            .get(src)
            .and_then(|v| v.split_whitespace().last())
            .map(canonicalize_token),
        None => bindings.get(&var.name).cloned(),
    }
}

/// Canonicalize a raw path token: expand `~`, make absolute against the
/// current directory, and normalize `.`/`..` lexically.
fn canonicalize_token(raw: &str) -> String {
    let expanded = if raw == "~" {
        std::env::var("HOME").unwrap_or_else(|_| raw.to_string())
    } else if let Some(rest) = raw.strip_prefix("~/") {
        match std::env::var("HOME") {
            Ok(home) => format!("{}/{}", home.trim_end_matches('/'), rest),
            Err(_) => raw.to_string(),
        }
    } else {
        raw.to_string()
    };
    if expanded.starts_with('/') {
        normalize_lexical(&expanded)
    } else {
        match std::env::current_dir() {
            Ok(cwd) => normalize_lexical(&format!("{}/{}", cwd.display(), expanded)),
            Err(_) => normalize_lexical(&expanded),
        }
    }
}

/// Lexically normalize a path: resolve `.` and `..` components without
/// touching the filesystem.
fn normalize_lexical(p: &str) -> String {
    let absolute = p.starts_with('/');
    let mut parts: Vec<&str> = Vec::new();
    for comp in p.split('/') {
        match comp {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    if absolute {
        format!("/{}", parts.join("/"))
    } else {
        parts.join("/")
    }
}

/// Evaluate an expression with concrete bindings. `In`/`Match`/`VarCmp`
/// look up their variable in `bindings`; missing variables evaluate false.
pub fn eval_concrete(e: &Expr, bindings: &BTreeMap<String, String>, latches: &[LatchVal]) -> bool {
    match e {
        Expr::True => true,
        Expr::Ref(_) => false, // unresolved; checker guarantees this can't happen
        Expr::In { var, set, neg } => {
            let hit = resolve_var(var, bindings).is_some_and(|v| set_contains(set, &v));
            hit != *neg
        }
        Expr::Match { var, pattern, neg } => {
            let hit = resolve_var(var, bindings).is_some_and(|v| glob_match(pattern, &v));
            hit != *neg
        }
        Expr::VarCmp { var, cmp, lit } => {
            // env vars read straight from the environment.
            let v = match (var.name.strip_prefix("env:"), &var.of) {
                (Some(name), None) => std::env::var(name).ok(),
                _ => resolve_var(var, bindings),
            };
            match v {
                Some(v) => cmp.eval_str(&v, lit),
                None => false,
            }
        }
        Expr::LatchTest { idx, cmp, lit } => match (&latches[*idx], cmp) {
            (LatchVal::Flag(b), None) => *b,
            (LatchVal::Flag(b), Some(c)) => c.eval_i64(*b as i64, lit.parse().unwrap_or(0)),
            (LatchVal::Last(v), None) => v.is_some(),
            (LatchVal::Last(v), Some(c)) => match v {
                None => false,
                Some(s) => c.eval_str(s, lit),
            },
            (LatchVal::Count(c), Some(cp)) => cp.eval_i64(*c as i64, lit.parse().unwrap_or(0)),
            (LatchVal::Count(_), None) => false,
        },
        Expr::And(a, b) => {
            eval_concrete(a, bindings, latches) && eval_concrete(b, bindings, latches)
        }
        Expr::Or(a, b) => {
            eval_concrete(a, bindings, latches) || eval_concrete(b, bindings, latches)
        }
        Expr::Not(a) => !eval_concrete(a, bindings, latches),
    }
}

/// Abstract evaluation over latch values only (no bindings): used for
/// marking. `In`/`Match`/`VarCmp` cannot be decided abstractly and are
/// treated as false — conservative for marks since it can only reduce the
/// marked set, never enlarge the forbidden set.
fn eval_abstract(e: &Expr, latches: &[LatchVal]) -> bool {
    match e {
        Expr::True => true,
        Expr::LatchTest { idx, cmp, lit } => match (&latches[*idx], cmp) {
            (LatchVal::Flag(b), None) => *b,
            (LatchVal::Flag(b), Some(c)) => c.eval_i64(*b as i64, lit.parse().unwrap_or(0)),
            (LatchVal::Last(v), None) => v.is_some(),
            (LatchVal::Last(v), Some(c)) => match v {
                None => false,
                Some(s) => c.eval_str(s, lit),
            },
            (LatchVal::Count(c), Some(cp)) => cp.eval_i64(*c as i64, lit.parse().unwrap_or(0)),
            (LatchVal::Count(_), None) => false,
        },
        Expr::And(a, b) => eval_abstract(a, latches) && eval_abstract(b, latches),
        Expr::Or(a, b) => eval_abstract(a, latches) || eval_abstract(b, latches),
        Expr::Not(a) => !eval_abstract(a, latches),
        _ => false,
    }
}

/// Set membership: consults the registry of compiled pattern sets
/// installed by the gate.
fn set_contains(set_name: &str, value: &str) -> bool {
    registry::set_contains(set_name, value)
}

/// Minimal glob matcher supporting `*`, `?`, and `|` alternation, used for
/// `~` match guards on command strings (where `*` should cross everything).
/// `a|b` matches if either alternative matches, so `c ~ "curl *|wget *"`
/// is one clause covering both commands.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    pattern
        .split('|')
        .any(|alt| glob_impl(alt.as_bytes(), text.as_bytes()))
}

fn glob_impl(p: &[u8], t: &[u8]) -> bool {
    match (p.first(), t.first()) {
        (None, None) => true,
        (Some(b'*'), _) => glob_impl(&p[1..], t) || (!t.is_empty() && glob_impl(p, &t[1..])),
        (Some(b'?'), Some(_)) => glob_impl(&p[1..], &t[1..]),
        (Some(a), Some(b)) if a == b => glob_impl(&p[1..], &t[1..]),
        _ => false,
    }
}

/// Registry mapping set names to compiled glob sets, installed by the
/// gate before evaluation so `In` guards can resolve membership.
pub mod registry {
    use globset::{Glob, GlobSet, GlobSetBuilder};
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    thread_local! {
        static SETS: RefCell<BTreeMap<String, GlobSet>> = const { RefCell::new(BTreeMap::new()) };
    }

    pub fn install(sets: &BTreeMap<String, Vec<String>>) {
        let mut compiled: BTreeMap<String, GlobSet> = BTreeMap::new();
        for (name, pats) in sets {
            let mut builder = GlobSetBuilder::new();
            for p in pats {
                for variant in compile_pattern(p) {
                    if let Ok(g) = Glob::new(&variant) {
                        builder.add(g);
                    }
                }
            }
            if let Ok(gs) = builder.build() {
                compiled.insert(name.clone(), gs);
            }
        }
        SETS.with(|s| *s.borrow_mut() = compiled);
    }

    /// Expand a leading `~` / `~/` in a set pattern to the user's home
    /// directory, and anchor `./` / `../`-relative patterns to the current
    /// working directory. This mirrors the gate's argument canonicalization
    /// so that `p in project` matches the absolute paths the gate produces.
    ///
    /// Returns every usable variant: the raw/home-expanded pattern (so
    /// relative arguments in offline replays still match) plus, for
    /// cwd-relative patterns, the absolute anchored form (so canonicalized
    /// absolute arguments match too).
    fn compile_pattern(pattern: &str) -> Vec<String> {
        let expanded = expand_home(pattern);
        let mut out = vec![expanded.clone()];
        if expanded.starts_with("./") || expanded.starts_with("../") || expanded == "." {
            if let Ok(cwd) = std::env::current_dir() {
                out.push(normalize_path(&cwd.join(&expanded).to_string_lossy()));
            }
        }
        out
    }

    /// Lexically normalize a path: resolve `.` and `..` components without
    /// touching the filesystem.
    fn normalize_path(p: &str) -> String {
        let absolute = p.starts_with('/');
        let mut parts: Vec<&str> = Vec::new();
        for comp in p.split('/') {
            match comp {
                "" | "." => {}
                ".." => {
                    parts.pop();
                }
                other => parts.push(other),
            }
        }
        if absolute {
            format!("/{}", parts.join("/"))
        } else {
            parts.join("/")
        }
    }

    fn expand_home(pattern: &str) -> String {
        if pattern == "~" {
            return std::env::var("HOME").unwrap_or_else(|_| pattern.to_string());
        }
        if let Some(rest) = pattern.strip_prefix("~/") {
            if let Ok(home) = std::env::var("HOME") {
                return format!("{}/{}", home.trim_end_matches('/'), rest);
            }
        }
        pattern.to_string()
    }

    pub fn set_contains(set_name: &str, value: &str) -> bool {
        SETS.with(|s| {
            s.borrow()
                .get(set_name)
                .is_some_and(|gs| gs.is_match(value))
        })
    }
}
