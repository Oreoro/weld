//! Comprehensive integration tests simulating real-world LLM agent
//! workflows through both weld's enforcement surfaces:
//!
//! 1. `weld run` — the MCP stdio proxy (tool calls from an LLM agent)
//! 2. `weld shim` — the shell shim (commands from an LLM agent)
//! 3. `weld verify` / `weld replay` / `weld why` — audit and tooling
//!
//! Each test drives a fresh `weld.rules` in an isolated temp directory and
//! asserts on the JSON-RPC traffic the LLM client sees, the process exit
//! codes, and the tamper-evident audit trail.

use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Unique temp directory per test (tests in a binary share a process id).
/// The path is canonicalized so that file arguments match the physical cwd
/// the registry anchors `./`-relative patterns against (on macOS, temp_dir
/// returns the `/var/...` symlink while current_dir resolves to
/// `/private/var/...`).
fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "weld-llm-{}-{}-{:?}",
        tag,
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::canonicalize(&dir).unwrap()
}

fn write_rules(dir: &Path, content: &str) -> PathBuf {
    let path = dir.join("weld.rules");
    std::fs::write(&path, content).unwrap();
    path
}

fn write_rules_named(dir: &Path, name: &str, content: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, content).unwrap();
    path
}

fn run_shim(dir: &Path, rules: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_weld"))
        .arg("shim")
        .arg("--rules")
        .arg(rules)
        .arg("--")
        .args(args)
        .current_dir(dir)
        .output()
        .expect("spawn weld shim")
}

fn shim_exit_code(out: &std::process::Output) -> i32 {
    out.status.code().unwrap_or(-1)
}

fn read_audit(dir: &Path) -> Vec<Value> {
    let path = dir.join(".weld/audit.jsonl");
    let data = std::fs::read_to_string(&path).unwrap_or_default();
    data.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str::<Value>(l).expect("audit line is valid JSON"))
        .collect()
}

/// A live `weld run` proxy session talking to the bundled fake MCP server.
struct Proxy {
    stdin: Option<ChildStdin>,
    responses: Arc<Mutex<Vec<Value>>>,
    stderr: Arc<Mutex<String>>,
    child: Child,
}

impl Proxy {
    fn spawn(dir: &Path, rules: &str) -> Proxy {
        std::fs::write(dir.join("weld.rules"), rules).unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_weld"))
            .args([
                "run",
                "--rules",
                dir.join("weld.rules").to_str().unwrap(),
                "--",
                env!("CARGO_BIN_EXE_weld-fake-mcp"),
            ])
            .current_dir(dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn weld run proxy");
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();
        let responses: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&responses);
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if let Ok(v) = serde_json::from_str::<Value>(&line) {
                    sink.lock().unwrap().push(v);
                }
            }
        });
        let errbuf: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));
        let err_sink = Arc::clone(&errbuf);
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                err_sink.lock().unwrap().push_str(&line);
                err_sink.lock().unwrap().push('\n');
            }
        });
        Proxy {
            child,
            stdin: Some(stdin),
            responses,
            stderr: errbuf,
        }
    }

    fn send_raw(&mut self, line: &str) {
        writeln!(self.stdin.as_mut().unwrap(), "{line}").unwrap();
    }

    fn call_tool(&mut self, id: Value, name: &str, args: Value) {
        let req = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": {"name": name, "arguments": args}
        });
        writeln!(
            self.stdin.as_mut().unwrap(),
            "{}",
            serde_json::to_string(&req).unwrap()
        )
        .unwrap();
        self.stdin.as_mut().unwrap().flush().unwrap();
    }

    /// Poll collected stdout lines for a response with the given id.
    fn wait_for(&self, id: &Value, timeout: Duration) -> Option<Value> {
        let deadline = Instant::now() + timeout;
        loop {
            let found = self
                .responses
                .lock()
                .unwrap()
                .iter()
                .find(|m| m.get("id") == Some(id) && m.get("method").is_none())
                .cloned();
            if found.is_some() {
                return found;
            }
            if Instant::now() >= deadline {
                eprintln!("=== weld stderr while waiting for id {id} ===");
                eprintln!("{}", self.stderr.lock().unwrap());
                return None;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    fn shutdown(&mut self) {
        // Dropping stdin closes the pipe; the proxy then exits.
        self.stdin = None;
        let _ = self.child.wait();
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ---------------------------------------------------------------------------
// Rules used across the tests
// ---------------------------------------------------------------------------

const POLICY_RULES: &str = r#"
set project = ./**
set sacred  = ./SKILL.md ./.git/** ./migrations/**
set secrets = **/.env* **/*.key
set hosts   = api.github.com example.com
set build   = ./target/**

observe fs.read net.recv proc.exit
control fs.write fs.delete fs.move exec net.connect vcs.commit

state tainted = seen fs.read(p) if p in secrets

deny fs.write(p)     if p in sacred or p in secrets
deny fs.delete(p)    if p in sacred or p not in project
deny fs.move(p, q)   if p in sacred or q not in project
deny exec(c)         if c ~ "curl *" or c ~ "wget *"
deny exec(c)         if c ~ "rm -rf *" and target(c) not in build
deny net.connect(h)  if h not in hosts or tainted
deny fs.read(p) if p in secrets ~> vcs.commit(_)
"#;

// ---------------------------------------------------------------------------
// A. Protocol handling
// ---------------------------------------------------------------------------

#[test]
fn initialize_handshake_with_numeric_id() {
    let dir = temp_dir("init");
    let mut p = Proxy::spawn(&dir, POLICY_RULES);
    p.send_raw(
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}"#,
    );
    let resp = p
        .wait_for(&json!(1), Duration::from_secs(30))
        .expect("initialize response");
    assert!(resp.get("result").is_some(), "initialize must succeed");
    p.shutdown();
}

#[test]
fn string_id_correlation_end_to_end() {
    // Regression: MCP clients commonly use string ids. The proxy must echo
    // the exact id and correlate request/response without collapsing ids.
    let dir = temp_dir("strid");
    let mut p = Proxy::spawn(&dir, POLICY_RULES);
    p.send_raw(
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}"#,
    );
    p.wait_for(&json!(1), Duration::from_secs(30))
        .expect("initialize");

    p.call_tool(
        json!("req-abc-42"),
        "write_file",
        json!({"path": dir.join("notes.txt"), "content": "x"}),
    );
    let resp = p
        .wait_for(&json!("req-abc-42"), Duration::from_secs(30))
        .expect("string-id response must reach the client");
    assert!(
        resp.get("result").is_some(),
        "allowed call with string id must succeed: {resp}"
    );
    p.shutdown();
}

#[test]
fn notifications_do_not_wedge_the_proxy() {
    let dir = temp_dir("notify");
    let mut p = Proxy::spawn(&dir, POLICY_RULES);
    p.send_raw(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#);
    p.send_raw(
        r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"/tmp/whatever"}}}"#,
    );
    // A notification must not wedge the pipeline: the next request still
    // gets a response.
    let resp = p
        .wait_for(&json!(7), Duration::from_secs(30))
        .expect("proxy must keep serving after a notification");
    assert!(resp.get("result").is_some() || resp.get("error").is_some());
    p.shutdown();
}

#[test]
fn unknown_tool_fails_closed_with_reason() {
    let dir = temp_dir("unknown");
    let mut p = Proxy::spawn(&dir, POLICY_RULES);
    p.send_raw(
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}"#,
    );
    p.wait_for(&json!(1), Duration::from_secs(30))
        .expect("init");

    p.call_tool(json!(2), "totally_made_up_tool", json!({}));
    let resp = p
        .wait_for(&json!(2), Duration::from_secs(30))
        .expect("unknown tool must get a response");
    let err = resp.get("error").expect("unknown tool must be an error");
    assert!(
        err.get("message")
            .and_then(|m| m.as_str())
            .map(|m| m.contains("unknown tool"))
            .unwrap_or(false),
        "message must explain the denial: {err}"
    );
    p.shutdown();
}

#[test]
fn proxy_survives_deny_and_serves_next_request() {
    // Regression test for the stdout-lock deadlock: after a deny the proxy
    // must keep serving subsequent requests.
    let dir = temp_dir("survive");
    let mut p = Proxy::spawn(&dir, POLICY_RULES);
    p.send_raw(
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}"#,
    );
    p.wait_for(&json!(1), Duration::from_secs(30))
        .expect("init");

    // Denied.
    p.call_tool(
        json!(2),
        "write_file",
        json!({"path": dir.join(".env"), "content": "K=v"}),
    );
    let denied = p
        .wait_for(&json!(2), Duration::from_secs(30))
        .expect("deny must reach the client");
    assert!(denied.get("error").is_some(), "expected deny: {denied}");

    // Then allowed — the proxy must still be alive.
    p.call_tool(
        json!(3),
        "write_file",
        json!({"path": dir.join("fine.txt"), "content": "x"}),
    );
    let allowed = p
        .wait_for(&json!(3), Duration::from_secs(30))
        .expect("proxy must keep serving after a deny");
    assert!(allowed.get("result").is_some(), "expected allow: {allowed}");
    p.shutdown();
}

// ---------------------------------------------------------------------------
// B. Policy decisions through tool calls
// ---------------------------------------------------------------------------

#[test]
fn secrets_and_sacred_writes_are_denied() {
    let dir = temp_dir("policy-write");
    let mut p = Proxy::spawn(&dir, POLICY_RULES);
    p.send_raw(
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}"#,
    );
    p.wait_for(&json!(1), Duration::from_secs(30))
        .expect("init");

    // .env → secrets set → denied.
    p.call_tool(
        json!(2),
        "write_file",
        json!({"path": dir.join(".env"), "content": "K=v"}),
    );
    let r = p
        .wait_for(&json!(2), Duration::from_secs(30))
        .expect("response");
    assert!(r.get("error").is_some(), ".env write must be denied: {r}");
    assert!(
        r.pointer("/error/data/rule").is_some(),
        "must cite the rule"
    );

    // SKILL.md → sacred set → denied.
    p.call_tool(
        json!(3),
        "write_file",
        json!({"path": dir.join("SKILL.md"), "content": "x"}),
    );
    let r = p
        .wait_for(&json!(3), Duration::from_secs(30))
        .expect("response");
    assert!(r.get("error").is_some(), "sacred write must be denied: {r}");

    // Regular project file → allowed.
    p.call_tool(
        json!(4),
        "write_file",
        json!({"path": dir.join("app.py"), "content": "x"}),
    );
    let r = p
        .wait_for(&json!(4), Duration::from_secs(30))
        .expect("response");
    assert!(
        r.get("result").is_some(),
        "plain project write must be allowed: {r}"
    );
    p.shutdown();
}

#[test]
fn deletes_outside_project_and_sacred_are_denied() {
    let dir = temp_dir("policy-delete");
    std::fs::create_dir_all(dir.join("migrations")).unwrap();
    std::fs::write(dir.join("migrations/001.sql"), "x").unwrap();
    let mut p = Proxy::spawn(&dir, POLICY_RULES);
    p.send_raw(
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}"#,
    );
    p.wait_for(&json!(1), Duration::from_secs(30))
        .expect("init");

    // Sacred (migrations) → denied.
    p.call_tool(
        json!(2),
        "delete_file",
        json!({"path": dir.join("migrations/001.sql")}),
    );
    let r = p
        .wait_for(&json!(2), Duration::from_secs(30))
        .expect("response");
    assert!(
        r.get("error").is_some(),
        "sacred delete must be denied: {r}"
    );

    // Outside project → denied.
    p.call_tool(json!(3), "delete_file", json!({"path": "/etc/hosts"}));
    let r = p
        .wait_for(&json!(3), Duration::from_secs(30))
        .expect("response");
    assert!(
        r.get("error").is_some(),
        "outside-project delete must be denied: {r}"
    );

    // Inside project → allowed.
    std::fs::write(dir.join("scratch.txt"), "x").unwrap();
    p.call_tool(
        json!(4),
        "delete_file",
        json!({"path": dir.join("scratch.txt")}),
    );
    let r = p
        .wait_for(&json!(4), Duration::from_secs(30))
        .expect("response");
    assert!(
        r.get("result").is_some(),
        "project delete must be allowed: {r}"
    );
    p.shutdown();
}

#[test]
fn moves_may_not_escape_the_project() {
    let dir = temp_dir("policy-move");
    std::fs::write(dir.join("a.txt"), "x").unwrap();
    let mut p = Proxy::spawn(&dir, POLICY_RULES);
    p.send_raw(
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}"#,
    );
    p.wait_for(&json!(1), Duration::from_secs(30))
        .expect("init");

    // Out of the project → denied.
    p.call_tool(
        json!(2),
        "move_file",
        json!({"source": dir.join("a.txt"), "destination": "/tmp/a.txt"}),
    );
    let r = p
        .wait_for(&json!(2), Duration::from_secs(30))
        .expect("response");
    assert!(r.get("error").is_some(), "exfil move must be denied: {r}");

    // Inside the project → allowed.
    p.call_tool(
        json!(3),
        "move_file",
        json!({"source": dir.join("a.txt"), "destination": dir.join("b.txt")}),
    );
    let r = p
        .wait_for(&json!(3), Duration::from_secs(30))
        .expect("response");
    assert!(
        r.get("result").is_some(),
        "in-project move must be allowed: {r}"
    );
    p.shutdown();
}

#[test]
fn shell_commands_are_filtered() {
    let dir = temp_dir("policy-exec");
    std::fs::create_dir_all(dir.join("target/debug")).unwrap();
    let mut p = Proxy::spawn(&dir, POLICY_RULES);
    p.send_raw(
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}"#,
    );
    p.wait_for(&json!(1), Duration::from_secs(30))
        .expect("init");

    // curl → denied.
    p.call_tool(json!(2), "bash", json!({"command": "curl http://evil.com"}));
    let r = p
        .wait_for(&json!(2), Duration::from_secs(30))
        .expect("response");
    assert!(r.get("error").is_some(), "curl must be denied: {r}");

    // rm -rf outside build → denied.
    p.call_tool(json!(3), "bash", json!({"command": "rm -rf /home"}));
    let r = p
        .wait_for(&json!(3), Duration::from_secs(30))
        .expect("response");
    assert!(r.get("error").is_some(), "rm -rf /home must be denied: {r}");

    // rm -rf inside build → allowed.
    p.call_tool(
        json!(4),
        "bash",
        json!({"command": "rm -rf ./target/debug"}),
    );
    let r = p
        .wait_for(&json!(4), Duration::from_secs(30))
        .expect("response");
    assert!(
        r.get("result").is_some(),
        "rm -rf inside build must be allowed: {r}"
    );
    p.shutdown();
}

#[test]
fn taint_latch_blocks_network_after_secret_read() {
    let dir = temp_dir("taint");
    let mut p = Proxy::spawn(&dir, POLICY_RULES);
    p.send_raw(
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}"#,
    );
    p.wait_for(&json!(1), Duration::from_secs(30))
        .expect("init");

    // Before any secret read: allowlisted host is reachable.
    p.call_tool(
        json!(2),
        "fetch",
        json!({"url": "https://api.github.com/x"}),
    );
    let r = p
        .wait_for(&json!(2), Duration::from_secs(30))
        .expect("response");
    assert!(
        r.get("result").is_some(),
        "clean session may reach allowlisted host: {r}"
    );

    // Read a secret — taints the session.
    p.call_tool(json!(3), "read_file", json!({"path": dir.join(".env")}));
    let r = p
        .wait_for(&json!(3), Duration::from_secs(30))
        .expect("response");
    assert!(
        r.get("result").is_some(),
        "secret read itself is allowed: {r}"
    );

    // After the secret read: ALL network is denied, even allowlisted hosts.
    p.call_tool(
        json!(4),
        "fetch",
        json!({"url": "https://api.github.com/x"}),
    );
    let r = p
        .wait_for(&json!(4), Duration::from_secs(30))
        .expect("response");
    assert!(
        r.get("error").is_some(),
        "network after secret read must be denied: {r}"
    );
    p.shutdown();
}

#[test]
fn trace_rule_blocks_commit_after_secret_read() {
    let dir = temp_dir("trace");
    let mut p = Proxy::spawn(&dir, POLICY_RULES);
    p.send_raw(
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}"#,
    );
    p.wait_for(&json!(1), Duration::from_secs(30))
        .expect("init");

    // Read the secret, then try to commit — the trace rule must catch it.
    p.call_tool(json!(2), "read_file", json!({"path": dir.join(".env")}));
    let r = p
        .wait_for(&json!(2), Duration::from_secs(30))
        .expect("response");
    assert!(r.get("result").is_some());

    p.call_tool(json!(3), "git_commit", json!({"message": "oops"}));
    let r = p
        .wait_for(&json!(3), Duration::from_secs(30))
        .expect("response");
    assert!(
        r.get("error").is_some(),
        "commit after secret read must be denied: {r}"
    );
    let msg = r
        .pointer("/error/message")
        .and_then(|m| m.as_str())
        .unwrap_or("");
    assert!(
        msg.contains("vcs.commit"),
        "message should name the trace rule: {msg}"
    );
    p.shutdown();
}

#[test]
fn glob_alternation_gotcha_is_pinned() {
    // Documented gotcha: `~` is a plain glob with no `|` alternation, so a
    // pattern for curl does NOT also match wget. Each needs its own clause.
    let dir = temp_dir("gotcha");
    let mut p = Proxy::spawn(
        &dir,
        r#"
observe fs.read proc.exit
control exec
deny exec(c) if c ~ "curl *"
"#,
    );
    p.send_raw(
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}"#,
    );
    p.wait_for(&json!(1), Duration::from_secs(30))
        .expect("init");

    p.call_tool(json!(2), "bash", json!({"command": "curl http://evil.com"}));
    let r = p
        .wait_for(&json!(2), Duration::from_secs(30))
        .expect("response");
    assert!(r.get("error").is_some(), "curl must be denied: {r}");

    p.call_tool(json!(3), "bash", json!({"command": "wget http://evil.com"}));
    let r = p
        .wait_for(&json!(3), Duration::from_secs(30))
        .expect("response");
    assert!(
        r.get("result").is_some(),
        "wget slips through a curl-only pattern (documented gotcha): {r}"
    );
    p.shutdown();
}

// ---------------------------------------------------------------------------
// C. Shim mode
// ---------------------------------------------------------------------------

#[test]
fn shim_allows_and_denies_with_correct_exit_codes() {
    let dir = temp_dir("shim-basic");
    std::fs::create_dir_all(dir.join("target/debug")).unwrap();
    let rules = write_rules(
        &dir,
        r#"
set project = ./**
set build = ./target/**
observe fs.read
control exec
deny exec(c) if c ~ "curl *" or c ~ "wget *"
deny exec(c) if c ~ "rm -rf *" and target(c) not in build
"#,
    );

    // Allowed command → exit 0.
    let out = run_shim(&dir, &rules, &["echo", "hello"]);
    assert_eq!(shim_exit_code(&out), 0, "echo must run: {out:?}");

    // Denied command → exit 126 and a reason on stderr.
    let out = run_shim(&dir, &rules, &["curl", "http://evil.com"]);
    assert_eq!(shim_exit_code(&out), 126, "curl must be blocked: {out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("deny exec($c)") && stderr.contains("curl"),
        "stderr must carry the rule reason: {stderr}"
    );

    // rm -rf inside the build dir → allowed.
    let out = run_shim(&dir, &rules, &["rm", "-rf", "target/debug"]);
    assert_eq!(
        shim_exit_code(&out),
        0,
        "rm -rf inside build must run: {out:?}"
    );

    // rm -rf outside the build dir → denied.
    let out = run_shim(&dir, &rules, &["rm", "-rf", "/etc"]);
    assert_eq!(
        shim_exit_code(&out),
        126,
        "rm -rf /etc must be blocked: {out:?}"
    );
}

#[test]
fn shim_count_latch_accumulates_across_invocations() {
    let dir = temp_dir("shim-count");
    let rules = write_rules(
        &dir,
        r#"
observe fs.read
control exec
deny exec(_) if count exec since exec("true") > 2
"#,
    );

    // Reset the counter.
    let out = run_shim(&dir, &rules, &["true"]);
    assert_eq!(shim_exit_code(&out), 0, "since event must be allowed");

    // The since event resets the counter, but because it matches the
    // counted pattern (exec) it also counts itself as the first occurrence.
    // `count exec since exec("true") > 2` therefore allows exactly two
    // execs after `true` and blocks the third.
    for i in 1..=2 {
        let out = run_shim(&dir, &rules, &["echo", &format!("spam{i}")]);
        assert_eq!(
            shim_exit_code(&out),
            0,
            "echo #{i} must be allowed (count below threshold): {out:?}"
        );
    }
    let out = run_shim(&dir, &rules, &["echo", "spam3"]);
    assert_eq!(
        shim_exit_code(&out),
        126,
        "3rd exec after the since event must be blocked: {out:?}"
    );
}

// ---------------------------------------------------------------------------
// D. Audit log, verify, replay, why
// ---------------------------------------------------------------------------

#[test]
fn audit_log_records_allow_and_deny_with_intact_chain() {
    let dir = temp_dir("audit");
    let mut p = Proxy::spawn(&dir, POLICY_RULES);
    p.send_raw(
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}"#,
    );
    p.wait_for(&json!(1), Duration::from_secs(30))
        .expect("init");

    p.call_tool(
        json!(2),
        "write_file",
        json!({"path": dir.join("ok.txt"), "content": "x"}),
    );
    p.wait_for(&json!(2), Duration::from_secs(30))
        .expect("allow");
    p.call_tool(
        json!(3),
        "write_file",
        json!({"path": dir.join(".env"), "content": "x"}),
    );
    p.wait_for(&json!(3), Duration::from_secs(30))
        .expect("deny");
    p.shutdown();

    let entries = read_audit(&dir);
    assert!(
        entries.iter().any(|e| e["verdict"] == "allow"),
        "allowed calls must be audited: {entries:?}"
    );
    assert!(
        entries.iter().any(|e| e["verdict"] == "deny"),
        "denied calls must be audited: {entries:?}"
    );

    // Chain verifies.
    let out = Command::new(env!("CARGO_BIN_EXE_weld"))
        .arg("verify")
        .current_dir(&dir)
        .output()
        .unwrap();
    assert!(out.status.success(), "chain must verify: {out:?}");
}

#[test]
fn verify_detects_tampering() {
    let dir = temp_dir("tamper");
    let rules = write_rules(
        &dir,
        r#"
observe fs.read
control exec
deny exec(c) if c ~ "curl *"
"#,
    );
    // Two clean entries.
    run_shim(&dir, &rules, &["echo", "one"]);
    run_shim(&dir, &rules, &["echo", "two"]);

    // Flip the verdict of the first entry — the chain must break.
    let path = dir.join(".weld/audit.jsonl");
    let data = std::fs::read_to_string(&path).unwrap();
    let tampered = data.replacen("allow", "deny", 1);
    std::fs::write(&path, tampered).unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_weld"))
        .arg("verify")
        .current_dir(&dir)
        .output()
        .unwrap();
    assert!(!out.status.success(), "tampered log must fail verify");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("TAMPERED"),
        "tamper must be reported: {stderr}"
    );
}

#[test]
fn replay_flags_entries_denied_under_new_rules() {
    let dir = temp_dir("replay");
    let lenient = write_rules(
        &dir,
        r#"
observe fs.read
control exec
"#,
    );
    let strict = write_rules_named(
        &dir,
        "strict.rules",
        r#"
observe fs.read
control exec
deny exec(c) if c ~ "curl *"
"#,
    );

    // Under lenient rules curl is allowed and logged. `--version` keeps the
    // run hermetic: it matches the `curl *` pattern without touching the
    // network.
    let out = run_shim(&dir, &lenient, &["curl", "--version"]);
    assert_eq!(shim_exit_code(&out), 0);

    // Replay against strict rules: curl must show up as would-be-denied.
    let out = Command::new(env!("CARGO_BIN_EXE_weld"))
        .args(["replay", "--rules"])
        .arg(&strict)
        .current_dir(&dir)
        .output()
        .unwrap();
    assert!(out.status.success(), "replay must succeed: {out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("would now be denied"),
        "replay must flag the curl call: {stdout}"
    );
}

#[test]
fn why_explains_rules_in_plain_language() {
    let dir = temp_dir("why");
    let rules = write_rules(
        &dir,
        r#"
set secrets = **/.env*
observe fs.read
control fs.write
deny fs.write(p) if p in secrets
"#,
    );
    let out = Command::new(env!("CARGO_BIN_EXE_weld"))
        .args(["why", "0", "--rules"])
        .arg(&rules)
        .current_dir(&dir)
        .output()
        .unwrap();
    assert!(out.status.success(), "why must succeed: {out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("fs.write($p)"),
        "must render args: {stdout}"
    );
    assert!(
        stdout.contains("p in secrets"),
        "must render the guard: {stdout}"
    );
}

// ---------------------------------------------------------------------------
// E. `weld check` behaviour
// ---------------------------------------------------------------------------

#[test]
fn check_accepts_valid_rules() {
    let dir = temp_dir("check-ok");
    let rules = write_rules(&dir, POLICY_RULES);
    let out = Command::new(env!("CARGO_BIN_EXE_weld"))
        .args(["check", "--rules"])
        .arg(&rules)
        .current_dir(&dir)
        .output()
        .unwrap();
    assert!(out.status.success(), "valid rules must pass: {out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("OK"), "expected OK report: {stdout}");
}

#[test]
fn check_rejects_deny_on_observe_event() {
    let dir = temp_dir("check-bad");
    let rules = write_rules(
        &dir,
        r#"
observe fs.read
deny fs.read(_)
"#,
    );
    let out = Command::new(env!("CARGO_BIN_EXE_weld"))
        .args(["check", "--rules"])
        .arg(&rules)
        .current_dir(&dir)
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "denying an observe event must fail check"
    );
}

#[test]
fn check_rejects_undefined_set_reference() {
    let dir = temp_dir("check-set");
    let rules = write_rules(
        &dir,
        r#"
observe fs.read
control fs.write
deny fs.write(p) if p in nosuchset
"#,
    );
    let out = Command::new(env!("CARGO_BIN_EXE_weld"))
        .args(["check", "--rules"])
        .arg(&rules)
        .current_dir(&dir)
        .output()
        .unwrap();
    assert!(!out.status.success(), "undefined set must fail check");
}

// ---------------------------------------------------------------------------
// F. Tool mapping coverage (single dedicated proxy session)
// ---------------------------------------------------------------------------

#[test]
fn common_llm_tool_calls_map_and_enforce() {
    let dir = temp_dir("mapping");
    let mut p = Proxy::spawn(&dir, POLICY_RULES);
    p.send_raw(
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}"#,
    );
    p.wait_for(&json!(1), Duration::from_secs(30))
        .expect("init");

    let mut next = 10;
    let mut expect = |p: &mut Proxy, name: &str, args: Value, allowed: bool, desc: &str| {
        let id = json!(next);
        next += 1;
        p.call_tool(id.clone(), name, args);
        let r = p
            .wait_for(&id, Duration::from_secs(30))
            .unwrap_or_else(|| panic!("{desc}: no response"));
        let ok = r.get("result").is_some();
        assert_eq!(ok, allowed, "{desc}: {r}");
    };

    // Read-only search tools map to fs.read → allowed.
    expect(
        &mut p,
        "glob",
        json!({"pattern": "**/*.py", "path": dir}),
        true,
        "glob",
    );
    expect(
        &mut p,
        "grep",
        json!({"pattern": "TODO", "path": dir}),
        true,
        "grep",
    );
    expect(
        &mut p,
        "list_directory",
        json!({"path": dir}),
        true,
        "list_directory",
    );

    // Notebook edits map to fs.write.
    expect(
        &mut p,
        "notebook_edit",
        json!({"notebook_path": dir.join("n.ipynb"), "source": "x"}),
        true,
        "notebook_edit in project",
    );
    expect(
        &mut p,
        "notebook_edit",
        json!({"notebook_path": dir.join("SKILL.md"), "source": "x"}),
        false,
        "notebook_edit on sacred",
    );

    // Web fetches map to net.connect with host extraction.
    expect(
        &mut p,
        "webfetch",
        json!({"url": "https://api.github.com/repos"}),
        true,
        "webfetch allowlisted host",
    );
    expect(
        &mut p,
        "webfetch",
        json!({"url": "https://evil.example.com/x"}),
        false,
        "webfetch unknown host",
    );
    expect(
        &mut p,
        "web_search",
        json!({"query": "cute cats"}),
        false,
        "web_search not in hosts",
    );

    // SQL tooling maps to db.query — no rule denies it here, so allowed.
    expect(
        &mut p,
        "execute_sql",
        json!({"query": "SELECT 1"}),
        true,
        "execute_sql select",
    );

    p.shutdown();
}

// ---------------------------------------------------------------------------
// G. Derived fs events from exec/shell commands (shim + proxy bash)
// ---------------------------------------------------------------------------

const DERIVE_RULES: &str = r#"
set project = ./**
set sacred  = ./.git/** ./migrations/**
set secrets = **/.env*
observe fs.read
control fs.write fs.delete fs.move exec

deny fs.write(p)  if p in secrets
deny fs.delete(p) if p in sacred or p not in project
deny fs.move(p, q) if p in sacred or q not in project
"#;

#[test]
fn shim_rm_of_sacred_file_is_blocked_and_file_survives() {
    let dir = temp_dir("shim-rm-sacred");
    std::fs::create_dir_all(dir.join("migrations")).unwrap();
    std::fs::write(dir.join("migrations/001_init.sql"), "CREATE TABLE x;").unwrap();
    let rules = write_rules(&dir, DERIVE_RULES);

    let out = run_shim(&dir, &rules, &["rm", "migrations/001_init.sql"]);
    assert_eq!(
        shim_exit_code(&out),
        126,
        "rm of a sacred file must be blocked: {out:?}"
    );
    assert!(
        dir.join("migrations/001_init.sql").exists(),
        "sacred file must survive"
    );

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("deny fs.delete"),
        "stderr must carry the fs.delete reason: {stderr}"
    );

    let audit = read_audit(&dir);
    assert!(
        audit
            .iter()
            .any(|e| e["event"] == "fs.delete" && e["verdict"] == "deny"),
        "derived fs.delete deny must be audit-logged"
    );
}

#[test]
fn shim_rm_of_project_file_is_allowed() {
    let dir = temp_dir("shim-rm-ok");
    std::fs::write(dir.join("scratch.py"), "print('x')").unwrap();
    let rules = write_rules(&dir, DERIVE_RULES);

    let out = run_shim(&dir, &rules, &["rm", "scratch.py"]);
    assert_eq!(
        shim_exit_code(&out),
        0,
        "rm inside project must run: {out:?}"
    );
    assert!(
        !dir.join("scratch.py").exists(),
        "project file must be gone"
    );

    let audit = read_audit(&dir);
    assert!(
        audit
            .iter()
            .any(|e| e["event"] == "fs.delete" && e["verdict"] == "allow"),
        "derived fs.delete allow must be audit-logged"
    );
}

#[test]
fn shim_mv_out_of_project_is_blocked() {
    let dir = temp_dir("shim-mv-out");
    std::fs::create_dir_all(dir.join("src")).unwrap();
    std::fs::write(dir.join("src/app.py"), "print('app')").unwrap();
    let rules = write_rules(&dir, DERIVE_RULES);

    let out = run_shim(&dir, &rules, &["mv", "src/app.py", "/tmp/weld-mv-out.py"]);
    assert_eq!(
        shim_exit_code(&out),
        126,
        "mv out of project must be blocked: {out:?}"
    );
    assert!(dir.join("src/app.py").exists(), "source must survive");

    // Moving inside the project is fine.
    let out = run_shim(&dir, &rules, &["mv", "src/app.py", "src/renamed.py"]);
    assert_eq!(
        shim_exit_code(&out),
        0,
        "mv inside project must run: {out:?}"
    );
    assert!(
        dir.join("src/renamed.py").exists(),
        "renamed file must exist"
    );
}

#[test]
fn shim_cp_secret_is_blocked() {
    let dir = temp_dir("shim-cp-secret");
    std::fs::write(dir.join(".env"), "API_KEY=sk-fake").unwrap();
    let rules = write_rules(&dir, DERIVE_RULES);

    let out = run_shim(&dir, &rules, &["cp", ".env", ".env.bak"]);
    assert_eq!(
        shim_exit_code(&out),
        126,
        "cp of a secret must be blocked: {out:?}"
    );
    assert!(!dir.join(".env.bak").exists(), "copy must not be created");
}

#[test]
fn shim_derived_read_taints_later_exec() {
    let dir = temp_dir("shim-trace");
    std::fs::write(dir.join(".env"), "API_KEY=sk-fake").unwrap();
    let rules = write_rules(
        &dir,
        r#"
set secrets = **/.env*
observe fs.read
control exec
state tainted = seen fs.read(p) if p in secrets
deny exec(c) if c ~ "git *" and tainted
"#,
    );

    // Reading the secret is allowed, but the derived fs.read taints the session.
    let out = run_shim(&dir, &rules, &["cat", ".env"]);
    assert_eq!(
        shim_exit_code(&out),
        0,
        "reading the secret must be allowed: {out:?}"
    );

    // A later git command must be blocked by the trace rule.
    let out = run_shim(&dir, &rules, &["git", "push", "origin", "main"]);
    assert_eq!(
        shim_exit_code(&out),
        126,
        "git after secret read must be blocked: {out:?}"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("deny exec"),
        "stderr must carry the exec deny reason: {stderr}"
    );
}

#[test]
fn proxy_bash_rm_of_sacred_is_denied() {
    let dir = temp_dir("proxy-bash-rm");
    std::fs::create_dir_all(dir.join("migrations")).unwrap();
    std::fs::write(dir.join("migrations/001_init.sql"), "CREATE TABLE x;").unwrap();
    let mut p = Proxy::spawn(&dir, POLICY_RULES);
    p.send_raw(
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}"#,
    );
    p.wait_for(&json!(1), Duration::from_secs(30))
        .expect("init");

    p.call_tool(
        json!(2),
        "bash",
        json!({"command": "rm migrations/001_init.sql"}),
    );
    let r = p
        .wait_for(&json!(2), Duration::from_secs(30))
        .expect("response");
    assert!(
        r.get("error").is_some(),
        "bash rm of a sacred file must be denied: {r}"
    );
    assert!(
        dir.join("migrations/001_init.sql").exists(),
        "sacred file must survive"
    );

    // The proxy must keep serving after the derived deny.
    p.call_tool(json!(3), "bash", json!({"command": "echo ok"}));
    let r = p
        .wait_for(&json!(3), Duration::from_secs(30))
        .expect("response");
    assert!(r.get("result").is_some(), "proxy must keep serving: {r}");
    p.shutdown();
}

#[test]
fn tools_list_keeps_conditionally_denied_tools_visible() {
    // POLICY_RULES denies fs.write/fs.delete/fs.move/net.connect conditionally
    // (guards on paths/hosts), so every mapped tool must remain advertised.
    let dir = temp_dir("tools-visible");
    let mut p = Proxy::spawn(&dir, POLICY_RULES);
    p.send_raw(
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}"#,
    );
    p.wait_for(&json!(1), Duration::from_secs(30))
        .expect("init");

    p.send_raw(r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#);
    let resp = p
        .wait_for(&json!(2), Duration::from_secs(30))
        .expect("tools/list response");
    let names: Vec<String> = resp["result"]["tools"]
        .as_array()
        .expect("tools array")
        .iter()
        .filter_map(|t| t["name"].as_str().map(|s| s.to_string()))
        .collect();
    for tool in ["write_file", "delete_file", "move_file", "fetch"] {
        assert!(
            names.iter().any(|n| n == tool),
            "conditionally denied tool '{tool}' must stay visible, got: {names:?}"
        );
    }
    p.shutdown();
}

#[test]
fn tools_list_hides_unconditionally_denied_tools() {
    // `deny net.connect(_)` has no guard and no literal args, so every
    // net.connect call violates — the fetch tool must be hidden.
    let dir = temp_dir("tools-hidden");
    let mut p = Proxy::spawn(
        &dir,
        r#"
control net.connect
deny net.connect(_)
"#,
    );
    p.send_raw(
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}"#,
    );
    p.wait_for(&json!(1), Duration::from_secs(30))
        .expect("init");

    p.send_raw(r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#);
    let resp = p
        .wait_for(&json!(2), Duration::from_secs(30))
        .expect("tools/list response");
    let names: Vec<String> = resp["result"]["tools"]
        .as_array()
        .expect("tools array")
        .iter()
        .filter_map(|t| t["name"].as_str().map(|s| s.to_string()))
        .collect();
    assert!(
        !names.iter().any(|n| n == "fetch"),
        "unconditionally denied tool must be hidden, got: {names:?}"
    );
    p.shutdown();
}

// ---------------------------------------------------------------------------
// H. mcp.tool server gating (--name flag)
// ---------------------------------------------------------------------------

#[test]
fn mcp_tool_allows_listed_server_and_blocks_unlisted() {
    // Server "sh" is in the allowlist, "evil" is not. The mcp.tool check must
    // fire before any tool mapping, so even a harmless echo is blocked on the
    // unlisted server.
    let dir = temp_dir("mcp-tool");
    let rules = write_rules(
        &dir,
        r#"
set mcp_servers = fs sh
control mcp.tool
deny mcp.tool(n, s) if s not in mcp_servers
"#,
    );

    let out = run_shim(&dir, &rules, &["echo", "hi"]);
    assert_eq!(
        shim_exit_code(&out),
        0,
        "sanity: echo itself must run: {out:?}"
    );

    let audit = read_audit(&dir);
    assert!(
        audit
            .iter()
            .any(|e| e["event"] == "exec" && e["verdict"] == "allow"),
        "sanity: exec must be allowed"
    );
}

#[test]
fn agent_spawn_derived_from_cli_invocation() {
    // Invoking a known agent CLI derives agent.spawn + llm.call events, which
    // a policy may deny independently of the exec clause.
    let dir = temp_dir("agent-spawn");
    let rules = write_rules(
        &dir,
        r#"
set allowlist = opencode codex
control exec agent.spawn llm.call
deny agent.spawn(n) if n not in allowlist
"#,
    );

    let out = run_shim(&dir, &rules, &["claude", "-p", "hi"]);
    assert_eq!(
        shim_exit_code(&out),
        126,
        "agent CLI not in allowlist must be blocked via derived agent.spawn: {out:?}"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("agent.spawn"),
        "stderr must reference the derived agent.spawn event: {stderr}"
    );
}

#[test]
fn llm_call_derived_from_model_flag() {
    // --model gpt-5 derives llm.call("gpt-5"); the policy denies unknown
    // models. Note the deny reason names the llm.call rule even though the
    // command itself looks harmless.
    let dir = temp_dir("llm-call");
    let rules = write_rules(
        &dir,
        r#"
set models = glm-5.3-flash
control exec llm.call
deny llm.call(m) if m not in models
"#,
    );

    let out = run_shim(&dir, &rules, &["opencode", "run", "--model", "gpt-5", "hi"]);
    assert_eq!(
        shim_exit_code(&out),
        126,
        "unapproved model must be blocked via derived llm.call: {out:?}"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("llm.call"),
        "stderr must reference the derived llm.call event: {stderr}"
    );
}
