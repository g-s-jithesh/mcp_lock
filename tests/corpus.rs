//! Keeps the attack corpus and the default policy honest: every attack is caught and every
//! benign change is let through, except cases with a documented `known` reason, which must
//! still behave exactly as documented (so a policy change can't silently shift results).

// Reuse the benchmark's loader and policies; its `main` is unused here.
#[path = "../examples/benchmark.rs"]
#[allow(dead_code)]
mod benchmark;

use benchmark::{corpus, Kind, Policy};

#[test]
fn default_policy_matches_the_corpus() {
    let cases = corpus().expect("corpus loads");
    let attacks = cases.iter().filter(|c| c.kind == Kind::Attack).count();
    assert!(attacks >= 20, "attack corpus shrank to {attacks}");
    assert!(cases.len() - attacks >= 10, "benign corpus shrank");

    let mut wrong = Vec::new();
    for case in &cases {
        let blocked = Policy::McpLock.blocks(case).expect("fixture is JSON");
        let ideal = case.kind == Kind::Attack;
        let expected = ideal != case.known.is_some();
        if blocked != expected {
            wrong.push(format!(
                "{} ({:?}, blocked={blocked}): {}",
                case.id, case.kind, case.technique
            ));
        }
    }
    assert!(
        wrong.is_empty(),
        "unexpected results:\n{}",
        wrong.join("\n")
    );
}

#[test]
fn every_attack_is_a_real_change() {
    // If canonicalization erased an attack, no classifier could catch it.
    for case in corpus().expect("corpus loads") {
        if case.kind == Kind::Attack {
            assert!(
                Policy::CanonicalHash
                    .blocks(&case)
                    .expect("fixture is JSON"),
                "{} is invisible after canonicalization",
                case.id
            );
        }
    }
}

#[test]
fn formatting_only_changes_never_block() {
    // Pure re-serialisation must not even change the canonical hash.
    for id in [
        "b01_key_reorder",
        "b02_json_escapes",
        "b03_compact_json",
        "b04_unicode_nfd",
        "b05_crlf_line_endings",
        "b06_required_reordered",
        "b07_enum_reordered",
    ] {
        let cases = corpus().expect("corpus loads");
        let case = cases.iter().find(|c| c.id == id).expect("case exists");
        assert!(!Policy::CanonicalHash.blocks(case).expect("JSON"), "{id}");
        assert!(
            Policy::RawHash.blocks(case).expect("JSON"),
            "{id} should differ in raw bytes"
        );
    }
}
