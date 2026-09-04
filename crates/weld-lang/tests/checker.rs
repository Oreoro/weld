//! Checker tests: state resolution, event classification, set references,
//! count bounds, and boolean shape validation.

use weld_lang::compile;

/// Compile expecting failure; returns the diagnostic message.
fn err(src: &str) -> String {
    compile(src).unwrap_err().message
}

#[test]
fn state_refs_are_inlined() {
    let ir = compile(
        "observe fs.read\ncontrol fs.write\n\
         set s = **/.env*\n\
         state tainted = seen fs.read(p) if p in s\n\
         state double = tainted and not tainted\n",
    )
    .unwrap();

    // The `tainted` ref inside `double` must be inlined to a LatchTest.
    let expr = &ir.states[1].expr;
    let rendered = format!("{expr:?}");
    assert!(!rendered.contains("Ref("), "ref not inlined: {rendered}");
    assert!(rendered.contains("LatchTest"));
}

#[test]
fn error_undefined_state_ref() {
    let m = err("observe exec\nmark done if missing_state\n");
    assert!(m.contains("reference to undefined state"));
}

#[test]
fn cyclic_state_definition() {
    let m = err("observe a\nstate x = y\nstate y = x\n");
    assert!(m.contains("cyclic state definition"));
}

#[test]
fn event_both_observed_and_controlled() {
    let m = err("observe fs.write\ncontrol fs.write\n");
    assert!(m.contains("both observed and controlled"));
}

#[test]
fn deny_references_unknown_event() {
    let m = err("control fs.write\ndeny fs.delete\n");
    assert!(m.contains("unknown event 'fs.delete'"));
}

#[test]
fn deny_observe_final_cond() {
    let m = err("observe fs.read\ndeny fs.read\n");
    assert!(m.contains("cannot deny observable event"));
}

#[test]
fn deny_observe_nonfinal_is_ok() {
    // fs.read is observe but not the final cond, so this is legal.
    let ir = compile(
        "observe fs.read\ncontrol vcs.commit\n\
         deny fs.read(_) ~> vcs.commit(_)\n",
    )
    .unwrap();
    assert_eq!(ir.denies.len(), 1);
}

#[test]
fn undefined_set_reference() {
    let m = err("control fs.write\ndeny fs.write(p) if p in secrets\n");
    assert!(m.contains("reference to undefined set 'secrets'"));
}

#[test]
fn count_bound_too_large() {
    let m = err("observe exec\ncontrol fs.delete\n\
         state many = count fs.delete(_) since exec(\"cargo test\") > 10001\n\
         deny fs.delete(p) if many\n");
    assert!(m.contains("count bound"));
}

#[test]
fn count_bound_negative() {
    let m = err("observe exec\ncontrol fs.delete\n\
         state many = count fs.delete(_) since exec(\"cargo test\") > -1\n\
         deny fs.delete(p) if many\n");
    assert!(m.contains("count bound"));
}

#[test]
fn duplicate_state_declaration() {
    let m = err("observe a\nstate x = seen a\nstate x = seen a\n");
    assert!(m.contains("declared twice"));
}

#[test]
fn non_boolean_mark_expression() {
    let m = err("observe a\ncontrol b\n\
         state t = seen a\n\
         mark done if t and env(\"X\") == \"y\"\n");
    assert!(m.contains("must be a boolean combination"));
}
