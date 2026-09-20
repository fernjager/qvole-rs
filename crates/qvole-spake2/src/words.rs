//! Connection-code word list.
//!
//! Port of `spake2/words.go`. The list is extracted byte-identically from the
//! Go source by `scripts/extract-words.sh` (never retyped by hand) and loaded
//! with `include_str!`.

use std::sync::OnceLock;

/// The word list used for generating human-friendly connection codes
/// (Go: `spake2.CodeWords`).
pub fn code_words() -> &'static [String] {
    static WORDS: OnceLock<Vec<String>> = OnceLock::new();
    WORDS.get_or_init(|| {
        include_str!("words.txt")
            .lines()
            .filter(|l| !l.is_empty())
            .map(str::to_owned)
            .collect()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Port of `TestCodeWords_Count` (internal/util/code_test.go).
    #[test]
    fn test_code_words_count() {
        assert_eq!(code_words().len(), 7762);
    }
}
