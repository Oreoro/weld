use clap::{Parser, Subcommand};
use serde_json::Value;
use std::path::{Path, PathBuf};
use weld_audit::verify;
use weld_gate::{load_rules, proxy_run, shim_run, write_default_rules};
use weld_synth::synthesize;

#[derive(Parser)]
#[command(
    name = "weld",
    version,
    about = "Local-first supervisor for AI agents. Unsafe actions become unreachable, not discouraged.",
    after_help = "Run 'weld <command> --help' for command-specific details."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Scaffold a rules file and audit directory for a project.
    Init {
        /// Preset to seed the rules file with.
        #[arg(long, value_parser = ["solo-dev", "ci", "paranoid"], default_value = "solo-dev")]
        preset: String,
        /// Overwrite an existing weld.rules file.
        #[arg(long)]
        force: bool,
    },
    /// Compile rules, synthesize the supervisor, print a report.
    Check {
        /// Rules file to compile.
        #[arg(long, default_value = "weld.rules")]
        rules: PathBuf,
        /// Write the supervisor FSM as a Graphviz DOT file to this path.
        #[arg(long)]
        dot: Option<PathBuf>,
        /// Output machine-readable JSON (for agent feedback loops).
        #[arg(long)]
        json: bool,
    },
    /// Run an MCP server under supervision (stdio proxy).
    Run {
        /// Rules file to enforce.
        #[arg(long, default_value = "weld.rules")]
        rules: PathBuf,
        /// Server name for mcp.tool policy events.
        #[arg(long)]
        name: Option<String>,
        /// The MCP server command to launch.
        #[arg(last = true)]
        command: Vec<String>,
    },
    /// Run a single command under supervision (shell shim).
    Shim {
        /// Rules file to enforce.
        #[arg(long, default_value = "weld.rules")]
        rules: PathBuf,
        /// The command to run.
        #[arg(last = true)]
        command: Vec<String>,
    },
    /// Explain why a rule exists, in plain language.
    Why {
        /// Rule id to explain (see `weld check`).
        id: usize,
        /// Rules file to read from.
        #[arg(long, default_value = "weld.rules")]
        rules: PathBuf,
    },
    /// Verify the hash chain of an audit log.
    Verify {
        /// Path to the audit log.
        #[arg(long, default_value = ".weld/audit.jsonl")]
        log: PathBuf,
    },
    /// Replay a log against a new rules file to see what would change.
    Replay {
        /// Path to the audit log.
        #[arg(long, default_value = ".weld/audit.jsonl")]
        log: PathBuf,
        /// Rules file to replay against.
        #[arg(long, default_value = "weld.rules")]
        rules: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();
    let code = match cli.cmd {
        Cmd::Init { preset, force } => cmd_init(&preset, force),
        Cmd::Check { rules, dot, json } => cmd_check(&rules, dot.as_deref(), json),
        Cmd::Run {
            rules,
            name,
            command,
        } => cmd_run(&rules, name.as_deref(), &command),
        Cmd::Shim { rules, command } => cmd_shim(&rules, &command),
        Cmd::Why { id, rules } => cmd_why(&rules, id),
        Cmd::Verify { log } => cmd_verify(&log),
        Cmd::Replay { log, rules } => cmd_replay(&log, &rules),
    };
    std::process::exit(code);
}

fn cmd_init(preset: &str, force: bool) -> i32 {
    if PathBuf::from("weld.rules").exists() && !force {
        eprintln!("weld.rules already exists (use --force to overwrite)");
        return 1;
    }
    match write_default_rules(preset) {
        Ok(()) => {
            println!("Created weld.rules from the '{preset}' preset.");
            println!("Next: review weld.rules, then run `weld check`.");
            0
        }
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

fn cmd_check(rules: &PathBuf, dot: Option<&Path>, json: bool) -> i32 {
    let src = match std::fs::read_to_string(rules) {
        Ok(s) => s,
        Err(e) => {
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "ok": false,
                        "error": format!("cannot read {}: {}", rules.display(), e)
                    })
                );
            } else {
                eprintln!("error: cannot read {}: {e}", rules.display());
            }
            return 1;
        }
    };
    let ir = match load_rules(&src) {
        Ok(ir) => ir,
        Err(d) => {
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "ok": false,
                        "error": format!("line {}: {}", d.line, d.message),
                        "line": d.line,
                        "hint": d.hint,
                    })
                );
            } else {
                eprintln!("{d}");
            }
            return 1;
        }
    };
    match synthesize(&ir) {
        Ok(sup) => {
            let disabled = sup.disabled_in(sup.initial());
            let dead = sup.dead_rules();

            if json {
                let disabled_json: Vec<Value> = disabled
                    .iter()
                    .map(|(ev, rule)| serde_json::json!({"event": ev, "rule": rule}))
                    .collect();
                println!(
                    "{}",
                    serde_json::json!({
                        "ok": true,
                        "rules": ir.denies.len(),
                        "events": sup.alphabet().len(),
                        "states": sup.state_count(),
                        "disabledAtStart": disabled_json,
                        "deadRules": dead,
                    })
                );
            } else {
                println!("rules:      {}", ir.denies.len());
                println!("events:     {}", sup.alphabet().len());
                println!("states:     {}", sup.state_count());
                println!("disabled at start: {}", disabled.len());
                for (ev, rule) in &disabled {
                    println!("  {ev} (rule {rule})");
                }
                for r in &sup.dead_rules() {
                    println!(
                        "warning: rule {r} can never fire (trigger unreachable from the initial state)"
                    );
                }
                println!("OK: supervisor is safe and nonblocking.");
            }

            if let Some(path) = dot {
                let graph = sup.to_dot(&ir);
                if let Err(e) = std::fs::write(path, graph) {
                    eprintln!("error: cannot write {}: {e}", path.display());
                    return 1;
                }
                if !json {
                    println!("wrote FSM graph to {}", path.display());
                }
            }
            0
        }
        Err(e) => {
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "ok": false,
                        "error": e.to_string(),
                    })
                );
            } else {
                eprintln!("error: {e}");
            }
            1
        }
    }
}

fn cmd_run(rules: &PathBuf, name: Option<&str>, command: &[String]) -> i32 {
    if command.is_empty() {
        eprintln!("error: no command given after '--'");
        return 2;
    }
    let src = match std::fs::read_to_string(rules) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: cannot read {}: {e}", rules.display());
            return 1;
        }
    };
    let ir = match load_rules(&src) {
        Ok(ir) => ir,
        Err(d) => {
            eprintln!("{d}");
            return 1;
        }
    };
    match proxy_run(ir, command, name) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

fn cmd_shim(rules: &PathBuf, command: &[String]) -> i32 {
    if command.is_empty() {
        eprintln!("error: no command given after '--'");
        return 2;
    }
    let src = match std::fs::read_to_string(rules) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: cannot read {}: {e}", rules.display());
            return 1;
        }
    };
    let ir = match load_rules(&src) {
        Ok(ir) => ir,
        Err(d) => {
            eprintln!("{d}");
            return 1;
        }
    };
    match shim_run(ir, command) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

fn cmd_why(rules: &PathBuf, id: usize) -> i32 {
    let src = match std::fs::read_to_string(rules) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: cannot read {}: {e}", rules.display());
            return 1;
        }
    };
    let ir = match load_rules(&src) {
        Ok(ir) => ir,
        Err(d) => {
            eprintln!("{d}");
            return 1;
        }
    };
    match ir.denies.get(id) {
        Some(rule) => {
            println!("rule {} (weld.rules line {}):", rule.id, rule.line);
            for (i, c) in rule.conds.iter().enumerate() {
                let cond = weld_gate::describe_cond(&ir, c);
                if i == 0 {
                    println!("  when {cond}");
                } else {
                    println!("  followed by {cond}");
                }
            }
            0
        }
        None => {
            eprintln!("error: no rule with id {id}");
            1
        }
    }
}

fn cmd_verify(log: &Path) -> i32 {
    match verify(log) {
        Ok(n) => {
            println!("OK: {n} entries verified, chain intact.");
            0
        }
        Err(e) => {
            eprintln!("TAMPERED: {e}");
            1
        }
    }
}

fn cmd_replay(log: &Path, rules: &Path) -> i32 {
    let src = match std::fs::read_to_string(rules) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: cannot read {}: {e}", rules.display());
            return 1;
        }
    };
    let ir = match load_rules(&src) {
        Ok(ir) => ir,
        Err(d) => {
            eprintln!("{d}");
            return 1;
        }
    };
    match weld_audit::replay(log, &ir) {
        Ok((count, would_deny)) => {
            println!("replayed {count} entries against {}", rules.display());
            if would_deny.is_empty() {
                println!("no additional denials under the new rules.");
            } else {
                println!("{} event(s) would now be denied:", would_deny.len());
                for (seq, event, rule) in &would_deny {
                    println!("  seq {seq}: {event} (rule {rule})");
                }
            }
            0
        }
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}
