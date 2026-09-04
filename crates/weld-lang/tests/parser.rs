use weld_lang::ir::*;
use weld_lang::parser::parse;

#[test]
fn parses_set() {
    let (ir, _) = parse("set secrets = **/.env* **/*.pem", None).unwrap();
    assert_eq!(
        ir.sets.get("secrets").unwrap(),
        &vec!["**/.env*".to_string(), "**/*.pem".to_string()]
    );
}

#[test]
fn parses_observe_and_control() {
    let (ir, _) = parse("observe fs.read vcs.*\ncontrol fs.write exec", None).unwrap();
    assert_eq!(
        ir.observe,
        vec![
            EventPat::Exact("fs.read".into()),
            EventPat::Prefix("vcs".into())
        ]
    );
    assert_eq!(
        ir.control,
        vec![
            EventPat::Exact("fs.write".into()),
            EventPat::Exact("exec".into())
        ]
    );
}

#[test]
fn parses_simple_deny() {
    let (ir, _) = parse("control exec\ndeny exec(c) if c ~ \"curl *\"", None).unwrap();
    assert_eq!(ir.denies.len(), 1);
    let rule = &ir.denies[0];
    assert_eq!(rule.conds.len(), 1);
    assert_eq!(rule.conds[0].event, "exec");
    assert_eq!(rule.conds[0].argpats, vec![Arg::Var("c".into())]);
    match &rule.conds[0].guard {
        Some(Expr::Match { var, pattern, neg }) => {
            assert_eq!(var.name, "c");
            assert_eq!(pattern, "curl *");
            assert!(!*neg);
        }
        other => panic!("expected Match, got {:?}", other),
    }
}

#[test]
fn parses_trace_rule() {
    let (ir, _) = parse(
        "observe fs.read\ncontrol vcs.commit\ndeny fs.read(p) if p in secrets ~> vcs.commit(_)",
        None,
    )
    .unwrap();
    let rule = &ir.denies[0];
    assert_eq!(rule.conds.len(), 2);
    assert_eq!(rule.conds[0].event, "fs.read");
    assert_eq!(rule.conds[1].event, "vcs.commit");
    assert_eq!(rule.conds[1].argpats, vec![Arg::Wild]);
}

#[test]
fn parses_seen_state() {
    let (ir, latches) = parse(
        "observe fs.read\ncontrol vcs.push\nset s = **/.env*\nstate tainted = seen fs.read(p) if p in s\n",
        None,
    )
    .unwrap();
    assert_eq!(ir.states.len(), 1);
    assert_eq!(latches.len(), 1);
    assert_eq!(latches[0].kind, LatchKind::Seen);
    assert_eq!(latches[0].event, "fs.read");
}

#[test]
fn parses_last_state() {
    let (_, latches) = parse(
        "observe exec\ncontrol fs.write\nstate ok = last exec(\"cargo test\") == 0\n",
        None,
    )
    .unwrap();
    assert_eq!(latches[0].kind, LatchKind::Last);
    assert_eq!(latches[0].lit, "0");
    assert_eq!(latches[0].cmp, Cmp::Eq);
}

#[test]
fn parses_count_since_state() {
    let (_, latches) = parse(
        "observe fs.delete exec\ncontrol fs.delete\nstate many = count fs.delete(_) since exec(\"cargo test\") > 50\n",
        None,
    )
    .unwrap();
    assert_eq!(latches[0].kind, LatchKind::Count);
    assert_eq!(latches[0].lit, "50");
    assert_eq!(latches[0].cmp, Cmp::Gt);
    let since = latches[0].since.as_ref().unwrap();
    assert_eq!(since.event, "exec");
}

#[test]
fn parses_mark() {
    let (ir, _) = parse(
        "observe exec\ncontrol fs.write\nmark done if last exec(\"cargo build\") == 0\n",
        None,
    )
    .unwrap();
    assert_eq!(ir.marks.len(), 1);
    assert_eq!(ir.marks[0].name, "done");
}

#[test]
fn parses_boolean_combinations() {
    let (ir, _) = parse(
        "observe a b\ncontrol c\nstate s = seen a\nmark done if s and not seen b\n",
        None,
    )
    .unwrap();
    let expr = &ir.marks[0].expr;
    // state ref gets resolved in checker, but parser emits Ref("s")
    match expr {
        Expr::And(l, r) => {
            assert_eq!(**l, Expr::Ref("s".into()));
            match &**r {
                Expr::Not(inner) => match inner.as_ref() {
                    Expr::LatchTest { .. } => {}
                    other => panic!("expected LatchTest inside Not, got {:?}", other),
                },
                other => panic!("expected Not, got {:?}", other),
            }
        }
        other => panic!("expected And, got {:?}", other),
    }
}

#[test]
fn parses_env_guard() {
    let (ir, _) = parse(
        "control db.query\ndeny db.query(q) if env(\"ENV\") == \"production\"",
        None,
    )
    .unwrap();
    match &ir.denies[0].conds[0].guard {
        Some(Expr::VarCmp { var, cmp, lit }) => {
            assert_eq!(var.name, "env:ENV");
            assert_eq!(*cmp, Cmp::Eq);
            assert_eq!(lit, "production");
        }
        other => panic!("expected VarCmp, got {:?}", other),
    }
}

#[test]
fn parses_target_derived_var() {
    let (ir, _) = parse(
        "control exec\ndeny exec(c) if target(c) in build\nset build = ./target/**",
        None,
    )
    .unwrap();
    match &ir.denies[0].conds[0].guard {
        Some(Expr::In { var, set, neg }) => {
            assert_eq!(var.of.as_deref(), Some("c"));
            assert_eq!(set, "build");
            assert!(!*neg);
        }
        other => panic!("expected In, got {:?}", other),
    }
}

#[test]
fn error_unknown_declaration() {
    let d = parse("frobnicate x", None).unwrap_err();
    assert!(d.message.contains("unknown declaration 'frobnicate'"));
    assert!(d.hint.is_some());
}

#[test]
fn error_wildcard_in_trace() {
    let d = parse("observe vcs.*\ndeny vcs.*(_)", None).unwrap_err();
    assert!(d.message.contains("trace events must be concrete names"));
}

#[test]
fn error_unterminated_set() {
    let d = parse("set x =", None).unwrap_err();
    assert!(d.message.contains("no patterns"));
}

#[test]
fn error_duplicate_set() {
    let d = parse("set a = x\nset a = y", None).unwrap_err();
    assert!(d.message.contains("declared twice"));
}

#[test]
fn error_missing_assign_in_set() {
    let d = parse("set a x", None).unwrap_err();
    assert!(d.message.contains("expected '='"));
}
