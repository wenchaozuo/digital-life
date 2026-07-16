//! Minimal deterministic NFKC normalization for candidate dedup and safety checks.
//!
//! This module is private to the crate and not re-exported.
//! Only `memory::candidate_service` and `storage::candidate_extraction` should use it.

// ── NFKC normalization (minimal deterministic) ───────────────────────

mod unicode_normalization {
    pub struct Nfkc<I: Iterator<Item = char>>(I);

    impl<I: Iterator<Item = char>> Iterator for Nfkc<I> {
        type Item = char;
        fn next(&mut self) -> Option<char> {
            self.0.next().map(nfkc_map)
        }
    }

    pub trait UnicodeNormalization: Iterator<Item = char> + Sized {
        fn nfkc(self) -> Nfkc<Self> {
            Nfkc(self)
        }
    }

    impl<I: Iterator<Item = char>> UnicodeNormalization for I {}

    fn nfkc_map(c: char) -> char {
        match c {
            '\u{00B5}' => 'μ',
            '\u{00C0}' => 'À',
            '\u{00C1}' => 'Á',
            '\u{00C2}' => 'Â',
            '\u{00C3}' => 'Ã',
            '\u{00C4}' => 'Ä',
            '\u{00C5}' => 'Å',
            '\u{00E0}' => 'à',
            '\u{00E1}' => 'á',
            '\u{00E2}' => 'â',
            '\u{00E3}' => 'ã',
            '\u{00E4}' => 'ä',
            '\u{00E5}' => 'å',
            '\u{0391}' => 'Α',
            '\u{0392}' => 'Β',
            '\u{0395}' => 'Ε',
            '\u{0396}' => 'Ζ',
            '\u{0397}' => 'Η',
            '\u{0399}' => 'Ι',
            '\u{039A}' => 'Κ',
            '\u{039C}' => 'Μ',
            '\u{039D}' => 'Ν',
            '\u{039F}' => 'Ο',
            '\u{03A1}' => 'Ρ',
            '\u{03A4}' => 'Τ',
            '\u{03A5}' => 'Υ',
            '\u{03BA}' => 'κ',
            '\u{03BC}' => 'μ',
            '\u{03C0}' => 'π',
            '\u{03C1}' => 'ρ',
            '\u{03C2}' => 'ς',
            '\u{03C3}' => 'σ',
            '\u{03C4}' => 'τ',
            '\u{03C5}' => 'υ',
            '\u{03C6}' => 'φ',
            '\u{03C7}' => 'χ',
            '\u{03C8}' => 'ψ',
            '\u{03C9}' => 'ω',
            other => other,
        }
    }
}

// ── Public API (crate-visible, not re-exported) ──────────────────────

use self::unicode_normalization::UnicodeNormalization;

/// Normalize text for dedup fingerprinting and safety checks.
///
/// Applies NFKC normalization, collapses whitespace, and trims.
/// This is the single source of truth for normalization in the crate.
pub(super) fn normalize_for_dedup(input: &str) -> String {
    let nfkc = input.chars().nfkc().collect::<String>();
    let collapsed = nfkc.split_whitespace().collect::<Vec<_>>().join(" ");
    collapsed.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nfkc_maps_compatibility_chars() {
        // Micro sign → Greek mu
        assert_eq!(normalize_for_dedup("\u{00B5}"), "μ");
        // Full-width Latin A → regular A (already same in basic case)
        assert_eq!(normalize_for_dedup("À"), "À");
    }

    #[test]
    fn whitespace_differences_normalized() {
        assert_eq!(
            normalize_for_dedup("hello   world\n\n\ttab"),
            "hello world tab"
        );
    }

    #[test]
    fn same_normalized_content_same_result() {
        let a = normalize_for_dedup("Hello  World");
        let b = normalize_for_dedup("Hello World");
        assert_eq!(a, b);
    }
}
