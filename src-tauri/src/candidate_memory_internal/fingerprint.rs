use super::normalization::normalize_for_dedup;
use crate::memory::{
    candidate_service::{hex, sha256},
    MemoryKind,
};

const DEDUP_DOMAIN: &str = "candidate-dedup-v1";
const REJECTION_DOMAIN: &str = "candidate-rejection-suppression-v1";

pub(crate) fn compute_dedup_fingerprint(
    life_id: &str,
    subject_id: &str,
    kind: MemoryKind,
    content: &str,
) -> String {
    compute_fingerprint(DEDUP_DOMAIN, life_id, subject_id, kind, content)
}

pub(crate) fn compute_rejection_fingerprint(
    life_id: &str,
    subject_id: &str,
    kind: MemoryKind,
    content: &str,
) -> String {
    compute_fingerprint(REJECTION_DOMAIN, life_id, subject_id, kind, content)
}

fn compute_fingerprint(
    domain: &str,
    life_id: &str,
    subject_id: &str,
    kind: MemoryKind,
    content: &str,
) -> String {
    use std::io::Write;

    let normalized = normalize_for_dedup(content);
    let mut hasher = sha256::Sha256::new();
    write!(hasher, "{domain}").ok();
    write!(hasher, "\x00{life_id}").ok();
    write!(hasher, "\x00{subject_id}").ok();
    write!(hasher, "\x00{}", kind.as_str()).ok();
    write!(hasher, "\x00{normalized}").ok();
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::compute_dedup_fingerprint;
    use crate::memory::MemoryKind;

    #[test]
    fn candidate_dedup_fixed_vector_is_stable() {
        assert_eq!(
            compute_dedup_fingerprint("life-a", "subject", MemoryKind::Fact, "Hello world"),
            "c9b5d72d6f7670f6f34fef6a7711de82959736bc30757c647cf1c5bbccccbfd9"
        );
    }
}
