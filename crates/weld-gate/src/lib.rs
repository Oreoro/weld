//! weld-gate — the enforcement layer.
//!
//! Two runtime modes:
//! - [`proxy_run`]: a JSON-RPC / MCP stdio proxy. The MCP client connects to
//!   weld; weld spawns the real MCP server as a child process, inspects every
//!   `tools/call` request, maps it to a weld event, and either forwards it or
//!   answers with a structured tool error (so the agent can replan).
//! - `shim_run`: wraps a single command (for shell-only agents), mapping
//!   argv to an `exec` event.

pub mod mapping;
pub mod presets;

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufWriter, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{Arc, Mutex};

use serde_json::Value;
use weld_audit::{AuditEntry, AuditLog};
use weld_lang::{Diagnostic, Ir};
use weld_synth::{synthesize, Supervisor, Verdict};

pub use mapping::map_tool_call;
pub use presets::{PRESET_CI, PRESET_PARANOID, PRESET_SOLO_DEV};

/// Stateless metadata tools with no effect on the machine. They are
/// forwarded without policy evaluation (but still audit-logged) so LLM
/// agents are not needlessly denied scratch-pad operations.
const PASS_THROUGH_TOOLS: &[&str] = &["todo_write", "todowrite", "think"];

/// Compile + typecheck a rules file's source text.
pub fn load_rules(src: &str) -> Result<Ir, Diagnostic> {
    weld_lang::compile(src)
}

/// Write a preset rules file to `./weld.rules`.
pub fn write_default_rules(preset: &str) -> Result<(), String> {
    let content = match preset {
        "solo-dev" => presets::PRESET_SOLO_DEV,
        "ci" => presets::PRESET_CI,
        "paranoid" => presets::PRESET_PARANOID,
        other => return Err(format!("unknown preset '{other}'")),
    };
    std::fs::write("weld.rules", content).map_err(|e| format!("write weld.rules: {e}"))
}

/// Reconstruct supervisor state from prior audit entries (allowed events
/// only) so the shim behaves consistently across process invocations.
pub fn replay_state(sup: &Supervisor, log_path: &std::path::Path) -> usize {
    let mut state = sup.initial();
    let Ok(file) = std::fs::File::open(log_path) else {
        return state;
    };
    for line in std::io::BufReader::new(file).lines().map_while(Result::ok) {
        let Ok(entry) = serde_json::from_str::<AuditEntry>(&line) else {
            continue;
        };
        if entry.verdict != "allow" {
            continue;
        }
        if let Some(next) = sup.step(state, &entry.event, &entry.args, None) {
            state = next;
        }
    }
    state
}

// ---------------------------------------------------------------------------
// MCP stdio proxy
// ---------------------------------------------------------------------------

fn write_line<W: Write>(w: &mut W, line: &str) {
    let _ = w.write_all(line.as_bytes());
    let _ = w.write_all(b"\n");
    let _ = w.flush();
}

fn extract_result_text(v: &Value) -> Option<String> {
    if v.get("error").is_some() {
        return Some("error".to_string());
    }
    v.pointer("/result/content/0/text")
        .and_then(|t| t.as_str())
        .map(|s| s.chars().take(120).collect())
}

/// Build the JSON-RPC error response used when a tool call is denied.
/// Uses a normal error response so agents can see the reason and replan.
/// The reason is inlined into `error.message` (not just `data`) because many
/// MCP clients surface only the message string to the model.
fn deny_response(id: &Value, event: &str, rule: Option<usize>, reason: &str) -> String {
    let message = match rule {
        Some(r) => format!("weld: blocked by rule {r}: {reason}"),
        None => format!("weld: {reason}"),
    };
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": -32602,
            "message": message,
            "data": { "event": event, "rule": rule, "reason": reason }
        }
    })
    .to_string()
}

fn describe_arg(a: &weld_lang::ir::Arg) -> String {
    match a {
        weld_lang::ir::Arg::Wild => "_".to_string(),
        weld_lang::ir::Arg::Var(v) => format!("${v}"),
        weld_lang::ir::Arg::Lit(s) => format!("\"{s}\""),
    }
}

fn describe_var(v: &weld_lang::ir::VarRef) -> String {
    match &v.of {
        Some(src) => format!("{}({})", v.name, src),
        None => v.name.clone(),
    }
}

/// Render a guard expression in plain-language rule syntax.
pub fn describe_expr(ir: &Ir, e: &weld_lang::ir::Expr) -> String {
    use weld_lang::ir::Expr;
    match e {
        Expr::True => "true".into(),
        Expr::Ref(name) => name.clone(),
        Expr::In { var, set, neg } => {
            if *neg {
                format!("{} not in {}", describe_var(var), set)
            } else {
                format!("{} in {}", describe_var(var), set)
            }
        }
        Expr::Match { var, pattern, neg } => {
            let core = format!("{} ~ \"{}\"", describe_var(var), pattern);
            if *neg {
                format!("not {core}")
            } else {
                core
            }
        }
        Expr::VarCmp { var, cmp, lit } => {
            format!("{} {} \"{}\"", describe_var(var), cmp.as_str(), lit)
        }
        Expr::LatchTest { idx, cmp, lit } => {
            let name = ir
                .states
                .get(*idx)
                .map(|s| s.name.as_str())
                .unwrap_or("state");
            match cmp {
                Some(c) => format!("{} {} \"{}\"", name, c.as_str(), lit),
                None => name.to_string(),
            }
        }
        Expr::And(a, b) => format!("{} and {}", describe_expr(ir, a), describe_expr(ir, b)),
        Expr::Or(a, b) => format!("{} or {}", describe_expr(ir, a), describe_expr(ir, b)),
        Expr::Not(e) => format!("not ({})", describe_expr(ir, e)),
    }
}

/// Render one condition step (event + args + optional guard).
pub fn describe_cond(ir: &Ir, c: &weld_lang::ir::Cond) -> String {
    let args = c
        .argpats
        .iter()
        .map(describe_arg)
        .collect::<Vec<_>>()
        .join(", ");
    let guard = c
        .guard
        .as_ref()
        .map(|g| format!(" if {}", describe_expr(ir, g)))
        .unwrap_or_default();
    format!("{}({}){}", c.event, args, guard)
}

/// Render a deny rule in plain language (used by `weld why` and deny responses).
pub fn describe_rule(ir: &Ir, rule_id: usize) -> String {
    match ir.denies.get(rule_id) {
        Some(rule) => {
            let steps: Vec<String> = rule.conds.iter().map(|c| describe_cond(ir, c)).collect();
            let chain = if rule.conds.len() > 1 {
                steps.join(" then ")
            } else {
                steps.join("")
            };
            format!(
                "denied by rule {} (weld.rules line {}): deny {}",
                rule.id, rule.line, chain
            )
        }
        None => format!("denied by rule {rule_id}"),
    }
}

/// Run the MCP stdio proxy: spawn `command`, forward JSON-RPC between
/// stdin/stdout, intercepting `tools/call` requests.
/// Remove tools from a `tools/list` response whose mapped event is
/// *unconditionally* denied at the current state. Tools whose event is only
/// conditionally denied (e.g. `fs.write` denied inside `.git/` but allowed
/// in `src/`) stay visible: the agent needs them to do legitimate work, and
/// weld still enforces the guard at call time. Hiding those would leave the
/// agent with no write path at all — protection so blunt it becomes a
/// denial of service.
fn filter_tools_list(line: &str, sup: &Supervisor, state: usize) -> String {
    let mut v = match serde_json::from_str::<Value>(line) {
        Ok(v) => v,
        Err(_) => return line.to_string(),
    };
    if let Some(tools) = v
        .pointer_mut("/result/tools")
        .and_then(|t| t.as_array_mut())
    {
        tools.retain(|tool| {
            let name = tool.get("name").and_then(|n| n.as_str()).unwrap_or("");
            match mapping::map_tool_call(name, None) {
                Some((event, _)) if !sup.hard_firing_rules(state, &event).is_empty() => {
                    eprintln!("weld: hiding disabled tool '{name}' ({event})");
                    false
                }
                _ => true,
            }
        });
    }
    v.to_string()
}

/// Supervise an MCP `resources/read` request by mapping its URI to a
/// filesystem read event.
#[allow(clippy::too_many_arguments)]
fn supervise_resource_read(
    ir: &Ir,
    sup: &Supervisor,
    state: usize,
    id_val: &Value,
    uri: &str,
    log: &mut AuditLog,
    child: &mut Child,
    writer: &mut BufWriter<ChildStdin>,
    line: &str,
    await_response: &dyn Fn(&Value) -> Option<String>,
) -> Result<(), String> {
    let path = uri.strip_prefix("file://").unwrap_or(uri);
    let args = vec![mapping::canonicalize_arg(path)];
    let mut bindings = BTreeMap::new();
    match sup.decide(state, "fs.read", &args, &mut bindings) {
        Verdict::Allow => {
            write_line(writer, line);
            match await_response(id_val) {
                Some(resp_line) => {
                    let result = serde_json::from_str::<Value>(&resp_line)
                        .ok()
                        .and_then(|v| extract_result_text(&v));
                    let _ = log.append("fs.read", &args, "allow", None, None);
                    if let Some(next) = sup.step(state, "fs.read", &args, result.as_deref()) {
                        let _ = next;
                    }
                }
                None => {
                    let _ = child.wait();
                    return Err("child died while awaiting resources/read response".to_string());
                }
            }
        }
        Verdict::Disable { rule } => {
            let reason = describe_rule(ir, rule);
            let _ = log.append("fs.read", &args, "deny", Some(rule), Some(&reason));
            write_line(
                &mut std::io::stdout().lock(),
                &deny_response(id_val, "fs.read", Some(rule), &reason),
            );
        }
    }
    Ok(())
}

pub fn proxy_run(ir: Ir, command: &[String], server_name: Option<&str>) -> Result<i32, String> {
    let sup = synthesize(&ir).map_err(|e| format!("synthesis: {e}"))?;
    weld_synth::registry::install(&ir.sets);

    let log = AuditLog::open(std::path::Path::new(".weld/audit.jsonl"))
        .map_err(|e| format!("cannot open audit log: {e}"))?;

    let mut child = Command::new(&command[0])
        .args(&command[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| format!("spawn '{}': {e}", command[0]))?;

    let child_stdin = child.stdin.take().ok_or("no child stdin")?;
    let child_stdout = child.stdout.take().ok_or("no child stdout")?;
    let mut writer = BufWriter::new(child_stdin);

    // Reader thread: forwards child stdout to our stdout, and mirrors
    // response lines back so the main loop can correlate results.
    //
    // NOTE: the stdout lock MUST be acquired and released per write here.
    // Holding it across the loop (or across a blocking recv) would deadlock
    // the main thread when it tries to write a deny response to stdout.
    //
    // IDs are carried as JSON values (not coerced to u64): MCP clients may
    // use string ids, and `unwrap_or(0)` would collapse every such id to 0.
    let (resp_tx, resp_rx) = std::sync::mpsc::channel::<(Value, String)>();
    let hold: Arc<Mutex<BTreeSet<String>>> = Arc::new(Mutex::new(BTreeSet::new()));
    let hold_r = Arc::clone(&hold);
    std::thread::spawn(move || {
        for line in std::io::BufReader::new(child_stdout).lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => break,
            };
            if let Ok(v) = serde_json::from_str::<Value>(&line) {
                if v.get("id").is_some() && v.get("method").is_none() {
                    let id = v.get("id").cloned().unwrap_or(Value::Null);
                    let held = hold_r
                        .lock()
                        .map(|h| h.contains(&id.to_string()))
                        .unwrap_or(false);
                    if !held {
                        let mut out = std::io::stdout().lock();
                        let _ = out.write_all(line.as_bytes());
                        let _ = out.write_all(b"\n");
                        let _ = out.flush();
                    }
                    if resp_tx.send((id, line)).is_err() {
                        break;
                    }
                    continue;
                }
            }
            let mut out = std::io::stdout().lock();
            let _ = out.write_all(line.as_bytes());
            let _ = out.write_all(b"\n");
            let _ = out.flush();
        }
    });

    let stdin = std::io::stdin();
    let mut state = sup.initial();
    let mut log = log;

    // Wait for the child's response to a specific request id, discarding
    // stale entries. Returns None if the child died while awaiting.
    let await_response = |expected: &Value| -> Option<String> {
        loop {
            match resp_rx.recv() {
                Ok((rid, line)) if rid == *expected => return Some(line),
                Ok(_) => continue,
                Err(_) => return None,
            }
        }
    };

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        if line.trim().is_empty() {
            continue;
        }
        let msg: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => {
                // Not JSON — pass through blindly.
                let mut out = std::io::stdout().lock();
                let _ = writeln!(out, "{line}");
                continue;
            }
        };

        let is_tools_call = msg.get("method").and_then(|m| m.as_str()) == Some("tools/call");
        let is_request = msg.get("method").is_some();
        let id_val = msg.get("id").cloned().filter(|v| !v.is_null());

        if !is_request {
            // Responses and other non-request messages pass through untouched.
            write_line(&mut writer, &line);
            continue;
        }

        let Some(id_val) = id_val else {
            // Notifications carry no id. Non-tool notifications pass through;
            // a notification-shaped tools/call makes no sense, so drop it.
            if !is_tools_call {
                write_line(&mut writer, &line);
            }
            continue;
        };

        let method = msg.get("method").and_then(|m| m.as_str()).unwrap_or("");

        if !is_tools_call {
            if method == "tools/list" {
                // Hold the response, filter it, then forward. Marking the
                // held id ensures the reader thread does not leak it to
                // stdout first.
                hold.lock().unwrap().insert(id_val.to_string());
                write_line(&mut writer, &line);
                match await_response(&id_val) {
                    Some(resp_line) => {
                        let filtered = filter_tools_list(&resp_line, &sup, state);
                        let _ = log.append("tools.list", &[], "allow", None, None);
                        write_line(&mut std::io::stdout().lock(), &filtered);
                        hold.lock().unwrap().remove(&id_val.to_string());
                    }
                    None => {
                        let _ = child.wait();
                        return Ok(1);
                    }
                }
                continue;
            }
            if method == "resources/read" {
                supervise_resource_read(
                    &ir,
                    &sup,
                    state,
                    &id_val,
                    msg.pointer("/params/uri")
                        .and_then(|u| u.as_str())
                        .unwrap_or(""),
                    &mut log,
                    &mut child,
                    &mut writer,
                    &line,
                    &await_response,
                )?;
                continue;
            }
            // initialize / other protocol requests: forward, then consume
            // the response so it cannot be mistaken for the response of a
            // later supervised call if ids are reused.
            write_line(&mut writer, &line);
            if await_response(&id_val).is_none() {
                let _ = child.wait();
                return Ok(1);
            }
            continue;
        }

        let tool_name = msg
            .get("params")
            .and_then(|p| p.get("name"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let tool_args = msg.get("params").and_then(|p| p.get("arguments")).cloned();

        // Stateless metadata tools (agent scratch pads) have no effect on
        // the machine: forward them without policy evaluation, but log.
        if PASS_THROUGH_TOOLS
            .iter()
            .any(|t| t.eq_ignore_ascii_case(&tool_name))
        {
            let _ = log.append(
                "tool.pass",
                std::slice::from_ref(&tool_name),
                "allow",
                None,
                None,
            );
            write_line(&mut writer, &line);
            if await_response(&id_val).is_none() {
                let _ = child.wait();
                return Ok(1);
            }
            continue;
        }

        let Some((event, event_args)) = mapping::map_tool_call(&tool_name, tool_args.as_ref())
        else {
            // Unknown tool: fail closed, but tell the agent why.
            let reason = format!("unknown tool '{tool_name}'");
            let _ = log.append(&tool_name, &[], "unknown", None, Some(&reason));
            write_line(
                &mut std::io::stdout().lock(),
                &deny_response(&id_val, &tool_name, None, &reason),
            );
            continue;
        };

        // MCP-level policy: every tool call is also an `mcp.tool` event
        // carrying the tool name and the server's `--name`. This lets rules
        // gate servers as a whole (`deny mcp.tool(n, s) if s not in allowed`)
        // even when the mapped event itself has no deny rule.
        if let Some(server) = server_name {
            let mcp_args = vec![tool_name.clone(), server.to_string()];
            let mut mcp_bindings = BTreeMap::new();
            match sup.decide(state, "mcp.tool", &mcp_args, &mut mcp_bindings) {
                Verdict::Disable { rule } => {
                    let reason = describe_rule(&ir, rule);
                    let _ = log.append("mcp.tool", &mcp_args, "deny", Some(rule), Some(&reason));
                    write_line(
                        &mut std::io::stdout().lock(),
                        &deny_response(&id_val, "mcp.tool", Some(rule), &reason),
                    );
                    continue;
                }
                Verdict::Allow => {
                    let _ = log.append("mcp.tool", &mcp_args, "allow", None, None);
                    if let Some(next) = sup.step(state, "mcp.tool", &mcp_args, None) {
                        state = next;
                    }
                }
            }
        }

        let mut bindings = BTreeMap::new();
        match sup.decide(state, &event, &event_args, &mut bindings) {
            Verdict::Allow => {
                // For exec-mapped tools (bash/shell), also derive the concrete
                // filesystem events the command line would perform and judge
                // those too, so `rm migrations/x` via bash hits fs.delete rules.
                let mut derived_deny: Option<(usize, String, Vec<String>)> = None;
                if event == "exec" {
                    if let Some(cmd) = event_args.first() {
                        let tokens: Vec<String> =
                            cmd.split_whitespace().map(str::to_string).collect();
                        let mut derived = mapping::derive_fs_events(&tokens);
                        derived.extend(mapping::derive_agent_events(&tokens));
                        for (ev, args) in derived {
                            let mut derived_bindings = BTreeMap::new();
                            match sup.decide(state, &ev, &args, &mut derived_bindings) {
                                Verdict::Disable { rule } => {
                                    derived_deny = Some((rule, ev, args));
                                    break;
                                }
                                Verdict::Allow => {
                                    let _ = log.append(&ev, &args, "allow", None, None);
                                    if let Some(next) = sup.step(state, &ev, &args, None) {
                                        state = next;
                                    }
                                }
                            }
                        }
                    }
                }
                if let Some((rule, ev, args)) = derived_deny {
                    let reason = describe_rule(&ir, rule);
                    let _ = log.append(&ev, &args, "deny", Some(rule), Some(&reason));
                    write_line(
                        &mut std::io::stdout().lock(),
                        &deny_response(&id_val, &ev, Some(rule), &reason),
                    );
                    continue;
                }

                write_line(&mut writer, &line);
                // Wait for the matching response, capture result, advance.
                match await_response(&id_val) {
                    Some(resp_line) => {
                        let result = serde_json::from_str::<Value>(&resp_line)
                            .ok()
                            .and_then(|v| extract_result_text(&v));
                        let _ = log.append(&event, &event_args, "allow", None, None);
                        state = sup
                            .step(state, &event, &event_args, result.as_deref())
                            .unwrap_or(state);
                    }
                    None => {
                        // Child died while we awaited: fail closed.
                        let _ = log.append(&event, &event_args, "allow", None, None);
                        let _ = child.wait();
                        return Ok(1);
                    }
                }
            }
            Verdict::Disable { rule } => {
                let reason = describe_rule(&ir, rule);
                let _ = log.append(&event, &event_args, "deny", Some(rule), Some(&reason));
                write_line(
                    &mut std::io::stdout().lock(),
                    &deny_response(&id_val, &event, Some(rule), &reason),
                );
            }
        }
    }

    // Client disconnected: shut down child, propagate exit status.
    drop(writer);
    let status = child.wait().map_err(|e| format!("wait: {e}"))?;
    Ok(status.code().unwrap_or(1))
}

/// Run a single command under supervision (shell shim mode).
pub fn shim_run(ir: Ir, command: &[String]) -> Result<i32, String> {
    let sup = synthesize(&ir).map_err(|e| format!("synthesis: {e}"))?;
    weld_synth::registry::install(&ir.sets);

    let log_path = std::path::Path::new(".weld/audit.jsonl");
    let mut log = AuditLog::open(log_path).map_err(|e| format!("cannot open audit log: {e}"))?;

    // Reconstruct state from prior audit entries so multi-command flows work.
    let state = replay_state(&sup, log_path);

    let event_args = vec![command.join(" ")];
    let mut bindings = BTreeMap::new();
    match sup.decide(state, "exec", &event_args, &mut bindings) {
        Verdict::Disable { rule } => {
            let reason = describe_rule(&ir, rule);
            let _ = log.append("exec", &event_args, "deny", Some(rule), Some(&reason));
            eprintln!("weld: {reason}");
            Ok(126) // "command found but not executable" — a familiar lie
        }
        Verdict::Allow => {
            // The exec itself was allowed, but plain file commands (rm, mv,
            // cp, ...) are indistinguishable from harmless ones at the `exec`
            // level. Derive the concrete filesystem events they would perform
            // and judge those too, so `rm migrations/001.sql` hits the same
            // rules as the MCP `delete_file` tool.
            for (event, args) in mapping::derive_fs_events(command) {
                let mut derived_bindings = BTreeMap::new();
                if let Verdict::Disable { rule } =
                    sup.decide(state, &event, &args, &mut derived_bindings)
                {
                    let reason = describe_rule(&ir, rule);
                    let _ = log.append(&event, &args, "deny", Some(rule), Some(&reason));
                    eprintln!("weld: {reason}");
                    return Ok(126);
                }
                let _ = log.append(&event, &args, "allow", None, None);
            }

            for (event, args) in mapping::derive_agent_events(command) {
                let mut derived_bindings = BTreeMap::new();
                if let Verdict::Disable { rule } =
                    sup.decide(state, &event, &args, &mut derived_bindings)
                {
                    let reason = describe_rule(&ir, rule);
                    let _ = log.append(&event, &args, "deny", Some(rule), Some(&reason));
                    eprintln!("weld: {reason}");
                    return Ok(126);
                }
                let _ = log.append(&event, &args, "allow", None, None);
            }

            let _ = log.append("exec", &event_args, "allow", None, None);
            let status = Command::new(&command[0])
                .args(&command[1..])
                .status()
                .map_err(|e| format!("spawn '{}': {e}", command[0]))?;
            let code = status.code().unwrap_or(1);
            let result = code.to_string();
            if sup
                .step(state, "exec", &event_args, Some(&result))
                .is_some()
            {
                // State advances; the shim is single-shot so nothing to store.
            }
            Ok(code)
        }
    }
}
