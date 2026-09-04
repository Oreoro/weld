//! weld-audit — tamper-evident audit log.
//!
//! Every entry is hash-chained: each record includes the SHA-256 of the
//! previous record's canonical bytes. Any tampering breaks the chain and
//! `verify` reports the exact line.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use weld_lang::Ir;
use weld_synth::{synthesize, Verdict};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub seq: u64,
    pub ts: u64,
    pub event: String,
    #[serde(default)]
    pub args: Vec<String>,
    pub verdict: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub prev_hash: String,
    pub hash: String,
}

pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

fn compute_hash(entry: &AuditEntry) -> String {
    let body = format!(
        "{}|{}|{}|{}|{}|{}|{}",
        entry.seq,
        entry.ts,
        entry.event,
        entry.args.join("\u{1f}"),
        entry.verdict,
        entry.rule.map(|r| r.to_string()).unwrap_or_default(),
        entry.reason.clone().unwrap_or_default(),
    );
    let mut hasher = Sha256::new();
    hasher.update(entry.prev_hash.as_bytes());
    hasher.update(body.as_bytes());
    format!("{:x}", hasher.finalize())
}

pub struct AuditLog {
    path: PathBuf,
    last_hash: String,
    next_seq: u64,
}

impl AuditLog {
    pub fn open(path: &Path) -> std::io::Result<AuditLog> {
        let mut last_hash = GENESIS_HASH.to_string();
        let mut next_seq = 0u64;
        if path.exists() {
            let file = File::open(path)?;
            for line in BufReader::new(file).lines() {
                let line = line?;
                if line.trim().is_empty() {
                    continue;
                }
                if let Ok(entry) = serde_json::from_str::<AuditEntry>(&line) {
                    last_hash = entry.hash.clone();
                    next_seq = entry.seq + 1;
                }
            }
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        Ok(AuditLog {
            path: path.to_path_buf(),
            last_hash,
            next_seq,
        })
    }

    pub fn append(
        &mut self,
        event: &str,
        args: &[String],
        verdict: &str,
        rule: Option<usize>,
        reason: Option<&str>,
    ) -> std::io::Result<String> {
        let entry = AuditEntry {
            seq: self.next_seq,
            ts: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            event: event.to_string(),
            args: args.to_vec(),
            verdict: verdict.to_string(),
            rule,
            reason: reason.map(|s| s.to_string()),
            prev_hash: self.last_hash.clone(),
            hash: String::new(),
        };
        let hash = compute_hash(&entry);
        let entry = AuditEntry {
            hash: hash.clone(),
            ..entry
        };
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        writeln!(
            file,
            "{}",
            serde_json::to_string(&entry).expect("serialize audit entry")
        )?;
        file.flush()?;
        self.last_hash = hash.clone();
        self.next_seq += 1;
        Ok(hash)
    }

    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }
}

pub fn verify(path: &Path) -> Result<usize, String> {
    let file = File::open(path).map_err(|e| format!("cannot open {}: {}", path.display(), e))?;
    let mut prev = GENESIS_HASH.to_string();
    let mut count = 0usize;
    for (lineno, line) in BufReader::new(file).lines().enumerate() {
        let line = line.map_err(|e| format!("read error at line {}: {}", lineno + 1, e))?;
        if line.trim().is_empty() {
            continue;
        }
        let entry: AuditEntry = serde_json::from_str(&line)
            .map_err(|e| format!("line {}: invalid JSON: {}", lineno + 1, e))?;
        if entry.prev_hash != prev {
            return Err(format!(
                "line {}: chain broken (prev_hash mismatch)",
                lineno + 1
            ));
        }
        let expected = compute_hash(&entry);
        if entry.hash != expected {
            return Err(format!(
                "line {}: hash mismatch — log was tampered with",
                lineno + 1
            ));
        }
        prev = entry.hash;
        count += 1;
    }
    Ok(count)
}

pub type ReplayResult = (usize, Vec<(u64, String, usize)>);

pub fn replay(log_path: &Path, new_rules: &Ir) -> Result<ReplayResult, String> {
    let sup = synthesize(new_rules).map_err(|e| format!("synthesis failed: {}", e))?;
    let file =
        File::open(log_path).map_err(|e| format!("cannot open {}: {}", log_path.display(), e))?;
    let mut state = sup.initial();
    let mut count = 0usize;
    let mut would_deny = Vec::new();
    for line in BufReader::new(file).lines() {
        let line = line.map_err(|e| format!("read error: {}", e))?;
        if line.trim().is_empty() {
            continue;
        }
        let entry: AuditEntry =
            serde_json::from_str(&line).map_err(|e| format!("invalid JSON in log: {}", e))?;
        count += 1;
        let v = sup.decide(state, &entry.event, &entry.args, &mut BTreeMap::new());
        if let Verdict::Disable { rule } = v {
            would_deny.push((entry.seq, entry.event.clone(), rule));
        }
        if let Some(next) = sup.step(state, &entry.event, &entry.args, None) {
            state = next;
        }
    }
    Ok((count, would_deny))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tamper_detection() {
        let dir = std::env::temp_dir().join("weld-audit-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.jsonl");
        let mut log = AuditLog::open(&path).unwrap();
        log.append("fs.write", &["/tmp/a".into()], "allow", None, None)
            .unwrap();
        log.append(
            "fs.delete",
            &["/tmp/b".into()],
            "deny",
            Some(3),
            Some("sacred"),
        )
        .unwrap();
        assert_eq!(verify(&path).unwrap(), 2);

        let content = std::fs::read_to_string(&path).unwrap();
        let tampered = content.replace("/tmp/b", "/tmp/X");
        std::fs::write(&path, tampered).unwrap();
        assert!(verify(&path).is_err());
    }
}
