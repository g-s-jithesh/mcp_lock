//! Detection vs false-alarm benchmark: `cargo run --example benchmark`
//!
//! Runs every case in `tests/fixtures/attacks` (poisoned twins: must be caught) and
//! `tests/fixtures/benign` (harmless updates: ideally let through) against several
//! policies, and reports how many each one catches and how many it blocks needlessly.
//!
//! Each fixture has `before` (approved) and `after` (served now); either may be `null`
//! (tool added / removed). `known` documents where the default policy deliberately
//! differs from the ideal answer; `tests/corpus.rs` keeps that honest.

use mcp_lock::canonical::canonicalize;
use mcp_lock::classify::{classify, Severity};
use mcp_lock::fingerprint::fingerprint;
use serde::Deserialize;
use serde_json::value::RawValue;
use serde_json::Value;
use std::error::Error;
use std::path::Path;

/// Whether a case is an attack (should be blocked) or a harmless change (should not).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Attack,
    Benign,
}

/// One before/after pair from the corpus.
#[derive(Debug, Deserialize)]
pub struct Case {
    /// File name without `.json`.
    #[serde(skip)]
    pub id: String,
    pub kind: Kind,
    pub technique: String,
    #[serde(default)]
    pub source: Option<String>,
    /// Why the default policy is expected to get this case "wrong" (if it does).
    #[serde(default)]
    pub known: Option<String>,
    /// Raw bytes as written, so `raw-hash` can compare them exactly.
    pub before: Option<Box<RawValue>>,
    pub after: Option<Box<RawValue>>,
}

/// Ways to decide whether a change blocks the tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    /// Any byte difference blocks: what plain hash-pinning does.
    RawHash,
    /// Any difference after canonicalization blocks (mcp-lock's hash, no classifier).
    CanonicalHash,
    /// mcp-lock's default: block on `New` / `Block` severity.
    McpLock,
    /// Block on any change at all, including `Warn`.
    McpLockStrict,
}

impl Policy {
    pub const ALL: [Policy; 4] = [
        Policy::RawHash,
        Policy::CanonicalHash,
        Policy::McpLock,
        Policy::McpLockStrict,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Policy::RawHash => "raw-hash",
            Policy::CanonicalHash => "canonical-hash",
            Policy::McpLock => "mcp-lock (default)",
            Policy::McpLockStrict => "mcp-lock-strict",
        }
    }

    /// Would this policy hide the tool after the change in `case`?
    pub fn blocks(self, case: &Case) -> Result<bool, serde_json::Error> {
        let (before, after) = match (&case.before, &case.after) {
            (_, None) => return Ok(false),      // removed: nothing left to block
            (None, Some(_)) => return Ok(true), // new tools always need approval
            (Some(b), Some(a)) => (b, a),
        };
        if self == Policy::RawHash {
            return Ok(before.get() != after.get());
        }
        let before = canonicalize(&serde_json::from_str::<Value>(before.get())?);
        let after = canonicalize(&serde_json::from_str::<Value>(after.get())?);
        let severity = classify(Some(&before), Some(&after)).severity;
        Ok(match self {
            Policy::RawHash => unreachable!("handled above"),
            Policy::CanonicalHash => fingerprint(&before) != fingerprint(&after),
            Policy::McpLock => severity.hides(),
            Policy::McpLockStrict => severity >= Severity::Warn,
        })
    }
}

/// Load every `*.json` case in `dir`, sorted by file name.
pub fn load(dir: &Path) -> Result<Vec<Case>, Box<dyn Error>> {
    let mut paths: Vec<_> = std::fs::read_dir(dir)?
        .map(|entry| entry.map(|e| e.path()))
        .collect::<Result<_, _>>()?;
    paths.retain(|p| p.extension().is_some_and(|e| e == "json"));
    paths.sort();
    paths
        .iter()
        .map(|path| {
            let text = std::fs::read_to_string(path)?;
            let mut case: Case =
                serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
            case.id = path
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();
            Ok(case)
        })
        .collect()
}

/// The whole corpus: attacks first, then benign changes.
pub fn corpus() -> Result<Vec<Case>, Box<dyn Error>> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let mut cases = load(&root.join("attacks"))?;
    cases.extend(load(&root.join("benign"))?);
    Ok(cases)
}

fn percent(n: usize, total: usize) -> String {
    format!(
        "{n:>2}/{total} ({:>3.0}%)",
        100.0 * n as f64 / total.max(1) as f64
    )
}

fn main() -> Result<(), Box<dyn Error>> {
    let cases = corpus()?;
    let attacks = cases.iter().filter(|c| c.kind == Kind::Attack).count();
    let benign = cases.len() - attacks;
    println!("mcp-lock benchmark: {attacks} attacks, {benign} benign changes\n");
    // Column widths match the rows below: 20, then 16.
    println!("policy               attacks caught   benign blocked");

    let mut details = Vec::new();
    for policy in Policy::ALL {
        let (mut missed, mut false_alarms) = (Vec::new(), Vec::new());
        for case in &cases {
            match (case.kind, policy.blocks(case)?) {
                (Kind::Attack, false) => missed.push(case.id.as_str()),
                (Kind::Benign, true) => false_alarms.push(case.id.as_str()),
                _ => {}
            }
        }
        println!(
            "{:<20} {:<16} {}",
            policy.name(),
            percent(attacks - missed.len(), attacks),
            percent(false_alarms.len(), benign)
        );
        details.push((policy, missed, false_alarms));
    }

    println!();
    for (policy, missed, false_alarms) in details {
        println!("{}", policy.name());
        println!("  missed:  {}", list(&missed));
        println!("  blocked: {}", list(&false_alarms));
    }
    Ok(())
}

fn list(ids: &[&str]) -> String {
    if ids.is_empty() {
        "-".to_owned()
    } else {
        ids.join(", ")
    }
}
