//! Normalize tool definitions before hashing, so changes that don't alter meaning
//! (key order, Unicode composition, line endings) don't change the fingerprint.
//!
//! Deliberately *not* normalized: whitespace inside strings, zero-width and bidi control
//! characters. Hidden instructions can live there, so they must change the hash.

use serde_json::{Map, Value};
use unicode_normalization::UnicodeNormalization;

/// JSON Schema keywords whose arrays are sets: element order carries no meaning.
const SET_KEYWORDS: [&str; 2] = ["required", "enum"];

/// Return the canonical form of `value`.
///
/// - Object keys end up sorted: serde_json's default `Map` is a `BTreeMap`, so building a
///   new map sorts it, and serializing it later writes keys in that order.
/// - Arrays under `required` / `enum` are sorted; every other array keeps its order.
/// - Strings and keys are NFC-normalized, with `\r\n` and lone `\r` turned into `\n`.
pub fn canonicalize(value: &Value) -> Value {
    match value {
        Value::String(s) => Value::String(normalize_str(s)),
        Value::Array(items) => Value::Array(items.iter().map(canonicalize).collect()),
        Value::Object(map) => {
            let mut out = Map::new();
            for (key, val) in map {
                let mut val = canonicalize(val);
                if SET_KEYWORDS.contains(&key.as_str()) {
                    // ponytail: sorts any array under these keys, including data inside
                    // `default`/`const`; schema-aware walking if that ever causes a miss.
                    sort_set(&mut val);
                }
                out.insert(normalize_str(key), val);
            }
            Value::Object(out)
        }
        // Null, bools and numbers have one representation already.
        other => other.clone(),
    }
}

/// NFC-normalize and unify line endings. Never trims or collapses whitespace.
pub fn normalize_str(s: &str) -> String {
    s.replace("\r\n", "\n").replace('\r', "\n").nfc().collect()
}

/// Sort an array by each element's canonical JSON text (elements may be of mixed types).
fn sort_set(value: &mut Value) {
    if let Value::Array(items) = value {
        items.sort_by_cached_key(Value::to_string);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sorts_set_keywords_but_not_ordinary_arrays() {
        let v = canonicalize(&json!({
            "required": ["b", "a"],
            "enum": [3, "x", 1],
            "oneOf": [{"type": "string"}, {"type": "number"}],
        }));
        assert_eq!(v["required"], json!(["a", "b"]));
        assert_eq!(v["enum"], json!(["x", 1, 3]));
        assert_eq!(v["oneOf"], json!([{"type": "string"}, {"type": "number"}]));
    }

    #[test]
    fn a_property_named_required_is_left_alone() {
        let props = json!({"properties": {"required": {"type": "boolean"}}});
        assert_eq!(canonicalize(&props), props);
    }

    #[test]
    fn normalizes_unicode_and_line_endings_in_strings_and_keys() {
        // "e" + combining acute (NFD) must equal precomposed "é" (NFC).
        let v = canonicalize(&json!({"cafe\u{301}": "line1\r\nline2\rline3"}));
        assert_eq!(v, json!({"caf\u{e9}": "line1\nline2\nline3"}));
    }

    #[test]
    fn keeps_whitespace_and_invisible_characters() {
        let s = "  two  spaces\u{200b}zero-width\u{202e}bidi\t";
        assert_eq!(canonicalize(&json!(s)), json!(s));
    }
}
