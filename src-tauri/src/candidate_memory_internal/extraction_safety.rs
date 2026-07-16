use super::normalization::normalize_for_dedup;

/// Candidate-extraction domain operation that applies the shared candidate
/// memory normalization before safety validation and persistence checks.
pub(crate) fn normalize_proposal_text(input: &str) -> String {
    normalize_for_dedup(input)
}
