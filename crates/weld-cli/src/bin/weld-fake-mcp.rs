//! Minimal MCP-like stdio server used by the proxy integration tests.
//!
//! Line-interactive: reads one JSON-RPC request per line, answers, continues.
//! `write_file`/`delete_file`/`move_file` perform real filesystem operations
//! so tests can verify that denied calls have no side effects, while
//! `read_file` returns actual file contents so allowed reads are observable.

use serde_json::json;
use std::io::{BufRead, Write};

fn main() {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        if line.trim().is_empty() {
            continue;
        }
        let v: serde_json::Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let resp = handle(&v);
        if let Some(resp) = resp {
            let mut out = stdout.lock();
            let _ = serde_json::to_writer(&mut out, &resp);
            let _ = out.write_all(b"\n");
            let _ = out.flush();
        }
    }
}

fn handle(req: &serde_json::Value) -> Option<serde_json::Value> {
    let id = req.get("id")?.clone();
    let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");

    if method == "initialize" {
        return Some(json!({
            "jsonrpc": "2.0", "id": id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "weld-fake-mcp", "version": "0.1.0"}
            }
        }));
    }

    if method == "tools/list" {
        return Some(json!({
            "jsonrpc": "2.0", "id": id,
            "result": {"tools": [
                {"name": "write_file", "description": "Write a file",
                 "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}, "content": {"type": "string"}}}},
                {"name": "read_file", "description": "Read a file",
                 "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}}},
                {"name": "delete_file", "description": "Delete a file",
                 "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}}},
                {"name": "move_file", "description": "Move a file",
                 "inputSchema": {"type": "object", "properties": {"source": {"type": "string"}, "destination": {"type": "string"}}}},
                {"name": "fetch", "description": "Fetch a URL",
                 "inputSchema": {"type": "object", "properties": {"url": {"type": "string"}}}}
            ]}
        }));
    }

    if method == "tools/call" {
        let name = req
            .pointer("/params/name")
            .and_then(|n| n.as_str())
            .unwrap_or("");
        let args = req
            .pointer("/params/arguments")
            .cloned()
            .unwrap_or(json!({}));
        let text = match name {
            "write_file" => {
                let path = args["path"].as_str().unwrap_or("");
                let content = args["content"].as_str().unwrap_or("");
                match std::fs::write(path, content) {
                    Ok(()) => format!("wrote {path}"),
                    Err(e) => format!("error: {e}"),
                }
            }
            "read_file" => {
                let path = args["path"].as_str().unwrap_or("");
                std::fs::read_to_string(path)
                    .map(|c| c.chars().take(80).collect::<String>())
                    .unwrap_or_else(|e| format!("error: {e}"))
            }
            "delete_file" => {
                let path = args["path"].as_str().unwrap_or("");
                match std::fs::remove_file(path) {
                    Ok(()) => format!("deleted {path}"),
                    Err(e) => format!("error: {e}"),
                }
            }
            "move_file" => {
                let src = args["source"].as_str().unwrap_or("");
                let dst = args["destination"].as_str().unwrap_or("");
                match std::fs::rename(src, dst) {
                    Ok(()) => format!("moved {src} -> {dst}"),
                    Err(e) => format!("error: {e}"),
                }
            }
            "list_directory" => {
                let path = args["path"].as_str().unwrap_or("");
                match std::fs::read_dir(path) {
                    Ok(_) => "listing".to_string(),
                    Err(e) => format!("error: {e}"),
                }
            }
            "fetch" => {
                let url = args["url"].as_str().unwrap_or("");
                format!("fetched {url}")
            }
            _ => "ok".to_string(),
        };
        return Some(json!({
            "jsonrpc": "2.0", "id": id,
            "result": {"content": [{"type": "text", "text": text}]}
        }));
    }

    None
}

#[allow(dead_code)]
fn unused_fs() {}
