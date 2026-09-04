use serde_json::Value;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

#[test]
fn proxy_denies_and_survives() {
    let tmp = std::env::temp_dir().join(format!("weld-it-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    std::fs::write(
        tmp.join("weld.rules"),
        "set secrets = **/.env*\ncontrol fs.write\ndeny fs.write(p) if p in secrets\n",
    )
    .unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_weld"))
        .args(["run", "--", env!("CARGO_BIN_EXE_weld-fake-mcp")])
        .current_dir(&tmp)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn weld");

    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let reader = std::thread::spawn(move || {
        BufReader::new(stdout)
            .lines()
            .map_while(Result::ok)
            .collect::<Vec<String>>()
    });

    let mut send = |id: i64, path: &str| {
        let req = serde_json::json!({
            "jsonrpc": "2.0", "id": id, "method": "tools/call",
            "params": {"name": "write_file", "arguments": {"path": path, "content": "x"}}
        });
        writeln!(stdin, "{}", serde_json::to_string(&req).unwrap()).unwrap();
        stdin.flush().unwrap();
    };

    send(1, &tmp.join(".env").to_string_lossy()); // denied by rule 0
    send(2, &tmp.join("notes.txt").to_string_lossy()); // allowed

    drop(stdin);
    let lines = reader.join().unwrap();
    let _ = child.wait();

    let parsed: Vec<Value> = lines
        .iter()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    let err = parsed
        .iter()
        .find(|m| m.get("id") == Some(&serde_json::json!(1)))
        .expect("deny response must reach the client (no deadlock)");
    assert!(err.get("error").is_some(), "expected JSON-RPC error");
    assert!(
        err.pointer("/error/message")
            .and_then(|m| m.as_str())
            .map(|m| m.contains("deny fs.write"))
            .unwrap_or(false),
        "message must carry the rule reason"
    );

    let ok = parsed
        .iter()
        .find(|m| m.get("id") == Some(&serde_json::json!(2)))
        .expect("proxy must keep serving after a deny");
    assert!(ok.get("result").is_some(), "expected successful result");

    let _ = std::fs::remove_dir_all(&tmp);
}
