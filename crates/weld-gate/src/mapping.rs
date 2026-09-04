//! Tool-call → weld-event mapping for MCP `tools/call` requests.
//!
//! The gate intercepts JSON-RPC requests whose `method` is `tools/call`.
//! The `name` field selects a mapping; the ordered `keys` are extracted
//! from `params.arguments` to become the event's positional arguments.

use serde_json::Value;

struct Rule {
    names: &'static [&'static str],
    event: &'static str,
    keys: &'static [&'static str],
}

const MAPPINGS: &[Rule] = &[
    Rule {
        names: &["bash", "shell", "execute_command", "run_command"],
        event: "exec",
        keys: &["command", "cmd"],
    },
    Rule {
        names: &[
            "write_file",
            "create_file",
            "edit_file",
            "create_directory",
            "Write",
            "Edit",
            "MultiEdit",
            "multiedit",
        ],
        event: "fs.write",
        keys: &["path", "file_path"],
    },
    Rule {
        // Jupyter notebook edits key on `notebook_path` instead of `path`.
        names: &["notebook_edit", "notebookedit", "NotebookEdit"],
        event: "fs.write",
        keys: &["notebook_path", "path"],
    },
    Rule {
        names: &[
            "read_file",
            "read_text_file",
            "read_media_file",
            "read_multiple_files",
            "Read",
            "get_file",
        ],
        event: "fs.read",
        keys: &["path", "file_path"],
    },
    // Read-only directory/search tools: observed, not controlled, so they
    // pass through while still being audit-logged.
    Rule {
        names: &[
            "list_directory",
            "directory_tree",
            "search_files",
            "get_file_info",
            "list_allowed_directories",
            "glob",
            "Glob",
            "grep",
            "Grep",
            "list",
        ],
        event: "fs.read",
        keys: &["path"],
    },
    Rule {
        names: &["delete_file", "remove_file"],
        event: "fs.delete",
        keys: &["path", "file_path"],
    },
    Rule {
        names: &["move_file", "rename"],
        event: "fs.move",
        keys: &["source", "destination"],
    },
    Rule {
        names: &[
            "http_request",
            "fetch",
            "web_fetch",
            "webfetch",
            "WebFetch",
            "web_search",
            "websearch",
            "open_url",
        ],
        event: "net.connect",
        keys: &["url", "host"],
    },
    Rule {
        names: &["git_push", "push"],
        event: "vcs.push",
        keys: &["branch"],
    },
    Rule {
        names: &["git_force_push"],
        event: "vcs.force_push",
        keys: &["branch"],
    },
    Rule {
        names: &["git_delete_branch"],
        event: "vcs.branch_delete",
        keys: &["branch"],
    },
    Rule {
        names: &["git_commit", "commit"],
        event: "vcs.commit",
        keys: &["message", "msg"],
    },
    Rule {
        names: &["sql", "query_database", "execute_sql"],
        event: "db.query",
        keys: &["query"],
    },
];

/// Events whose first argument is a filesystem path.
const PATH_EVENTS: &[&str] = &["fs.read", "fs.write", "fs.delete", "fs.move"];

/// Extract the host component from a URL or authority string so that
/// host-based guards (`h not in hosts`) compare against the host itself,
/// not the full URL or an empty string.
///
/// - `"https://api.github.com/repos"` → `"api.github.com"`
/// - `"evil.example.com/x"`           → `"evil.example.com"`
/// - `"127.0.0.1:8080"`               → `"127.0.0.1"`
fn extract_host(raw: &str) -> String {
    let after_scheme = match raw.split_once("://") {
        Some((_scheme, rest)) => rest,
        None => raw,
    };
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    // Strip userinfo if present (e.g. "user@host").
    let host_port = authority.rsplit('@').next().unwrap_or(authority);
    // Strip a port suffix when it is numeric (avoids mangling IPv6).
    match host_port.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => {
            host.to_string()
        }
        _ => host_port.to_string(),
    }
}

/// Commands whose operands we can map to concrete filesystem events, so
/// that `weld shim -- rm x` is judged by `fs.delete` rules rather than only
/// the coarse `exec` clause. Unknown commands derive nothing.
const SHELL_METACHARS: &[char] = &[';', '|', '&', '`', '$', '>', '<', '\n'];

/// Wrapper programs that do not change the effect of the wrapped command.
const WRAPPERS: &[&str] = &["sudo", "nohup", "nice", "command", "time", "stdbuf", "env"];

fn basename(arg: &str) -> &str {
    arg.rsplit(['/', '\\']).next().unwrap_or(arg)
}

fn is_flag(tok: &str) -> bool {
    // `-rf`, `--force`, `-n5`, ... A bare `-` (stdin/stdout) is an operand.
    tok.starts_with('-') && tok.len() > 1
}

/// Make an operand absolute against the process cwd, expand `~`, and
/// normalize `.`/`..` lexically so set membership (`p in project`) matches
/// the same anchored patterns the MCP proxy path produces.
fn canonicalize_operand(raw: &str) -> String {
    let expanded = expand_tilde(raw);
    if expanded.starts_with('/') {
        normalize(&expanded)
    } else {
        match std::env::current_dir() {
            Ok(cwd) => normalize(&format!("{}/{}", cwd.display(), expanded)),
            Err(_) => normalize(&expanded),
        }
    }
}

/// Strip wrapper programs (and env's NAME=value assignments) from the head
/// of a command line so the real command verb can be identified.
fn strip_wrappers(mut rest: &[String]) -> &[String] {
    while let Some(head) = rest.first() {
        if WRAPPERS.iter().any(|w| head == w) {
            rest = &rest[1..];
            // `env` may carry NAME=value assignments before the command.
            while rest.first().map(|t| t.contains('=')).unwrap_or(false) {
                rest = &rest[1..];
            }
        } else {
            break;
        }
    }
    rest
}

/// Derive concrete filesystem events from a command line.
///
/// Returns `(event, args)` pairs such as `("fs.delete", ["/abs/path"])` or
/// `("fs.move", ["/abs/src", "/abs/dst"])`. Returns an empty vector when
/// nothing can be derived confidently (unknown program, shell metachars,
/// no operands). Derived events are *additional* checks on top of `exec`:
/// they never widen what is allowed.
pub fn derive_fs_events(tokens: &[String]) -> Vec<(String, Vec<String>)> {
    if tokens.is_empty() {
        return Vec::new();
    }
    if tokens
        .iter()
        .any(|t| t.chars().any(|c| SHELL_METACHARS.contains(&c)))
    {
        return Vec::new();
    }

    let rest = strip_wrappers(tokens);
    let Some((head, tail)) = rest.split_first() else {
        return Vec::new();
    };

    // Split flags from operands. `--` ends option parsing; everything after
    // it is an operand.
    let mut operands: Vec<String> = Vec::new();
    let mut end_of_flags = false;
    for tok in tail {
        if end_of_flags {
            operands.push(tok.clone());
        } else if tok == "--" {
            end_of_flags = true;
        } else if !is_flag(tok) {
            operands.push(tok.clone());
        }
    }

    let mut out = Vec::new();
    let canon = |p: &str| canonicalize_operand(p);
    match basename(head) {
        "rm" => {
            for op in &operands {
                out.push(("fs.delete".to_string(), vec![canon(op)]));
            }
        }
        "mv" | "move" if operands.len() >= 2 => {
            let dst = canon(&operands[operands.len() - 1]);
            for src in &operands[..operands.len() - 1] {
                out.push(("fs.move".to_string(), vec![canon(src), dst.clone()]));
            }
        }
        "cp" if operands.len() >= 2 => {
            let dst = canon(&operands[operands.len() - 1]);
            for src in &operands[..operands.len() - 1] {
                out.push(("fs.read".to_string(), vec![canon(src)]));
                out.push(("fs.write".to_string(), vec![dst.clone()]));
            }
        }
        "touch" | "mkdir" | "tee" => {
            for op in &operands {
                out.push(("fs.write".to_string(), vec![canon(op)]));
            }
        }
        "cat" | "head" | "tail" | "less" | "more" => {
            for op in &operands {
                out.push(("fs.read".to_string(), vec![canon(op)]));
            }
        }
        _ => {}
    }
    out
}

/// Agent CLI names recognized for agentic-AI event derivation.
pub const AGENT_CLIS: &[&str] = &[
    "opencode",
    "claude",
    "claude-code",
    "codex",
    "codex-exec",
    "aider",
    "gemini",
    "cursor-agent",
    "amp",
    "goose",
    "cline",
    "crush",
    "qwen",
    "agent",
];

/// Derive agentic-AI events from a command line: `agent.spawn(cli)` when the
/// command invokes a known agent CLI, and `llm.call(model)` for the model it
/// would drive (`--model X` / `-m X`, or the CLI name when no model flag is
/// present). Empty when the command is not an agent invocation.
pub fn derive_agent_events(tokens: &[String]) -> Vec<(String, Vec<String>)> {
    if tokens.is_empty() {
        return Vec::new();
    }
    if tokens
        .iter()
        .any(|t| t.chars().any(|c| SHELL_METACHARS.contains(&c)))
    {
        return Vec::new();
    }

    let rest = strip_wrappers(tokens);
    let Some((head, tail)) = rest.split_first() else {
        return Vec::new();
    };
    let cli = basename(head);
    if !AGENT_CLIS.contains(&cli) {
        return Vec::new();
    }

    let mut out = vec![("agent.spawn".to_string(), vec![cli.to_string()])];
    let mut model: Option<String> = None;
    let mut expect_value = false;
    for tok in tail {
        if expect_value {
            model = Some(tok.clone());
            break;
        }
        expect_value = tok == "--model" || tok == "-m";
    }
    let model = model.unwrap_or_else(|| cli.to_string());
    out.push(("llm.call".to_string(), vec![model]));
    out
}

/// Map a tool call to `(event, args)`. Returns `None` for unknown tools
/// (which the gate denies, per the fail-closed rule).
///
/// Path-bearing events are canonicalized before the verdict: `~` expands
/// to `$HOME`, and `.`/`..` components are resolved lexically. Without
/// this, `../` and symlink-adjacent tricks would bypass scope rules.
pub fn map_tool_call(name: &str, args: Option<&Value>) -> Option<(String, Vec<String>)> {
    for rule in MAPPINGS {
        if rule.names.iter().any(|n| n.eq_ignore_ascii_case(name)) {
            let mut vals = Vec::new();
            for key in rule.keys {
                let v = args.and_then(|a| a.get(*key));
                vals.push(match v {
                    Some(Value::String(s)) => s.clone(),
                    Some(other) => other.to_string(),
                    None => String::new(),
                });
            }
            let event = rule.event.to_string();
            if PATH_EVENTS.contains(&event.as_str()) && !vals.is_empty() {
                vals[0] = canonicalize_arg(&vals[0]);
                if event == "fs.move" && vals.len() > 1 {
                    vals[1] = canonicalize_arg(&vals[1]);
                }
            }
            if event == "net.connect" && !vals.is_empty() {
                // Host-based guards compare against the host name, so extract
                // it from the URL when the client sent a full URL.
                let raw = vals
                    .iter()
                    .find(|v| !v.is_empty())
                    .cloned()
                    .unwrap_or_default();
                vals[0] = extract_host(&raw);
            }
            return Some((event, vals));
        }
    }
    None
}

/// Expand a leading `~` in a path to the user's home directory.
fn expand_tilde(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return format!("{}/{}", home.trim_end_matches('/'), rest);
        }
    }
    if path == "~" {
        if let Ok(home) = std::env::var("HOME") {
            return home;
        }
    }
    path.to_string()
}

/// Lexically normalize a path: resolve `.` and `..` components without
/// touching the filesystem. Prevents `../` and symlink-adjacent tricks from
/// bypassing prefix-based scope rules.
fn normalize(p: &str) -> String {
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
    let joined = parts.join("/");
    if p.starts_with('/') {
        format!("/{}", joined)
    } else {
        joined
    }
}

/// Canonicalize a path argument: expand `~`, make absolute, normalize.
pub fn canonicalize_arg(raw: &str) -> String {
    let expanded = expand_tilde(raw);
    normalize(&expanded)
}
