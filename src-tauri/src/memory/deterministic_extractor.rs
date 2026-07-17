//! Deterministic rule-based candidate extractor for D-7.
//!
//! This extractor uses fixed pattern matching rules to identify first-person
//! user statements that represent preferences, habits, goals, and personal facts.
//! It is model-free, network-free, and fully deterministic.

use std::{future::Future, pin::Pin};

use crate::memory::MemoryKind;
use crate::storage::candidate_extraction::{
    CandidateExtractionBatch, CandidateExtractionProposal, CandidateExtractionRequest,
    CandidateExtractor, ExtractionError, ExtractorDescriptor, ProposalAction, SensitivityHint,
};

/// Maximum proposals per batch (frozen by D-6).
const MAX_PROPOSALS: usize = 5;

/// Deterministic rule-based extractor descriptor.
pub(crate) fn deterministic_descriptor() -> ExtractorDescriptor {
    ExtractorDescriptor {
        extractor_id: "deterministic-candidate-extractor".into(),
        extractor_version: "candidate-rule-v1".into(),
    }
}

/// Rule definition for pattern matching.
struct ExtractionRule {
    kind: MemoryKind,
    markers_zh: &'static [&'static str],
    markers_en: &'static [&'static str],
}

/// All extraction rules, ordered by priority.
const RULES: &[ExtractionRule] = &[
    // Preferences (high priority)
    ExtractionRule {
        kind: MemoryKind::Preference,
        markers_zh: &["我喜欢", "我不喜欢", "我更喜欢", "我偏好", "我最爱"],
        markers_en: &["I like", "I prefer", "I dislike", "I love", "I hate"],
    },
    // Stable habits
    ExtractionRule {
        kind: MemoryKind::Experience,
        markers_zh: &["我通常", "我习惯", "我每天", "我经常", "我总是"],
        markers_en: &["I usually", "I always", "I often", "I normally"],
    },
    // Goals
    ExtractionRule {
        kind: MemoryKind::Goal,
        markers_zh: &["我的目标是", "我打算", "我希望以后", "我计划", "我想要成为"],
        markers_en: &[
            "My goal is",
            "I plan to",
            "I want to",
            "I aim to",
            "I intend to",
        ],
    },
    // Self information / facts
    ExtractionRule {
        kind: MemoryKind::Fact,
        markers_zh: &["我是", "我叫", "我的职业是", "我在", "我的生日是"],
        markers_en: &[
            "I am",
            "I'm",
            "My name is",
            "I work as",
            "I live in",
            "My birthday is",
        ],
    },
    // Boundaries (preferences about interaction)
    ExtractionRule {
        kind: MemoryKind::Preference,
        markers_zh: &["请不要", "不要在", "我不希望你", "别"],
        markers_en: &["Please do not", "Never", "Don't", "Please avoid"],
    },
];

/// Patterns that indicate the text should NOT be extracted.
const EXCLUSION_PATTERNS_ZH: &[&str] = &["吗？", "吗?", "？", "?"];
const EXCLUSION_PATTERNS_EN: &[&str] = &["?", "if I ", "if i ", "he said", "she said", "they said"];

/// Patterns indicating code/log/config fragments.
const TECHNICAL_PATTERNS: &[&str] = &[
    "```",
    "SELECT ",
    "INSERT ",
    "UPDATE ",
    "DELETE ",
    "CREATE TABLE",
    "import ",
    "export ",
    "function ",
    "class ",
    "def ",
    "fn ",
    "0x",
    "sha256:",
    "md5:",
    "Bearer ",
    "Authorization:",
];

pub struct DeterministicCandidateExtractor;

impl Default for DeterministicCandidateExtractor {
    fn default() -> Self {
        Self::new()
    }
}

impl DeterministicCandidateExtractor {
    pub fn new() -> Self {
        Self
    }

    /// Check if text should be excluded (questions, quotes, technical).
    fn is_excluded(text: &str) -> bool {
        let lower = text.to_lowercase();

        // Check for question marks (questions)
        for pattern in EXCLUSION_PATTERNS_ZH {
            if text.contains(pattern) {
                return true;
            }
        }
        for pattern in EXCLUSION_PATTERNS_EN {
            if lower.contains(pattern) {
                return true;
            }
        }

        // Check for technical patterns
        for pattern in TECHNICAL_PATTERNS {
            if text.contains(pattern) {
                return true;
            }
        }

        // Check for third-person references
        if lower.contains("he said") || lower.contains("she said") || lower.contains("they said") {
            return true;
        }

        false
    }

    /// Extract content after a marker.
    fn extract_after_marker<'a>(text: &'a str, marker: &str) -> Option<&'a str> {
        if let Some(pos) = text.find(marker) {
            let after = &text[pos + marker.len()..];
            let trimmed = after.trim();
            if !trimmed.is_empty() && trimmed.len() >= 2 {
                Some(trimmed)
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Apply rules to a single message.
    fn apply_rules(&self, message_id: &str, content: &str) -> Vec<CandidateExtractionProposal> {
        if Self::is_excluded(content) {
            return Vec::new();
        }

        let mut proposals = Vec::new();

        for rule in RULES {
            // Check Chinese markers
            for marker in rule.markers_zh {
                if let Some(extracted) = Self::extract_after_marker(content, marker) {
                    // Remove trailing punctuation
                    let cleaned = extracted.trim_end_matches(|c: char| {
                        c == '。' || c == '，' || c == '！' || c == '.' || c == ',' || c == '!'
                    });
                    if !cleaned.is_empty() && cleaned.len() >= 2 {
                        proposals.push(CandidateExtractionProposal {
                            action: ProposalAction::Propose,
                            kind: Some(rule.kind),
                            content: Some(cleaned.to_string()),
                            summary: None,
                            confidence: Some(0.8),
                            importance: Some(0.7),
                            sensitivity_hint: SensitivityHint::Unknown,
                            conflict_hint: false,
                            source_message_ids: vec![message_id.to_string()],
                        });
                        return proposals; // One rule per message
                    }
                }
            }

            // Check English markers
            for marker in rule.markers_en {
                if let Some(extracted) = Self::extract_after_marker(content, marker) {
                    let cleaned = extracted.trim_end_matches(['.', ',', '!', ';']);
                    if !cleaned.is_empty() && cleaned.len() >= 2 {
                        proposals.push(CandidateExtractionProposal {
                            action: ProposalAction::Propose,
                            kind: Some(rule.kind),
                            content: Some(cleaned.to_string()),
                            summary: None,
                            confidence: Some(0.8),
                            importance: Some(0.7),
                            sensitivity_hint: SensitivityHint::Unknown,
                            conflict_hint: false,
                            source_message_ids: vec![message_id.to_string()],
                        });
                        return proposals; // One rule per message
                    }
                }
            }
        }

        proposals
    }
}

impl CandidateExtractor for DeterministicCandidateExtractor {
    fn descriptor(&self) -> &ExtractorDescriptor {
        // Return a reference to a thread-local or leaked descriptor
        // For simplicity, we'll create a new one each time (it's cheap)
        // In production, this could be a static or thread-local
        Box::leak(Box::new(deterministic_descriptor()))
    }

    fn extract<'a>(
        &'a self,
        request: CandidateExtractionRequest,
    ) -> Pin<Box<dyn Future<Output = Result<CandidateExtractionBatch, ExtractionError>> + Send + 'a>>
    {
        Box::pin(async move {
            let mut proposals = Vec::new();

            for message in &request.messages {
                if proposals.len() >= MAX_PROPOSALS {
                    break;
                }

                let mut message_proposals = self.apply_rules(&message.message_id, &message.content);

                // Truncate to max
                let remaining = MAX_PROPOSALS - proposals.len();
                if message_proposals.len() > remaining {
                    message_proposals.truncate(remaining);
                }

                proposals.extend(message_proposals);
            }

            Ok(CandidateExtractionBatch { proposals })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_request(messages: Vec<(&str, &str)>) -> CandidateExtractionRequest {
        CandidateExtractionRequest {
            run_id: "test-run".into(),
            attempt_sequence: 1,
            life_id: "life-1".into(),
            conversation_id: "conv-1".into(),
            conversation_revision: 1,
            policy_version: "v1".into(),
            snapshot_hash: "a".repeat(64),
            messages: messages
                .into_iter()
                .enumerate()
                .map(
                    |(i, (id, content))| crate::storage::candidate_extraction::ExtractionMessage {
                        message_id: id.into(),
                        sequence_no: i as i64 + 1,
                        content: content.into(),
                    },
                )
                .collect(),
        }
    }

    fn extract(
        extractor: &DeterministicCandidateExtractor,
        request: CandidateExtractionRequest,
    ) -> CandidateExtractionBatch {
        futures::executor::block_on(extractor.extract(request)).unwrap()
    }

    #[test]
    fn extracts_chinese_preference() {
        let extractor = DeterministicCandidateExtractor::new();
        let request = make_request(vec![("msg-1", "我喜欢喝茶")]);
        let batch = extract(&extractor, request);
        assert_eq!(batch.proposals.len(), 1);
        assert_eq!(batch.proposals[0].kind, Some(MemoryKind::Preference));
        assert_eq!(batch.proposals[0].content.as_deref(), Some("喝茶"));
    }

    #[test]
    fn extracts_english_preference() {
        let extractor = DeterministicCandidateExtractor::new();
        let request = make_request(vec![("msg-1", "I like coffee")]);
        let batch = extract(&extractor, request);
        assert_eq!(batch.proposals.len(), 1);
        assert_eq!(batch.proposals[0].kind, Some(MemoryKind::Preference));
        assert_eq!(batch.proposals[0].content.as_deref(), Some("coffee"));
    }

    #[test]
    fn extracts_chinese_habit() {
        let extractor = DeterministicCandidateExtractor::new();
        let request = make_request(vec![("msg-1", "我通常早上八点起床")]);
        let batch = extract(&extractor, request);
        assert_eq!(batch.proposals.len(), 1);
        assert_eq!(batch.proposals[0].kind, Some(MemoryKind::Experience));
    }

    #[test]
    fn extracts_chinese_goal() {
        let extractor = DeterministicCandidateExtractor::new();
        let request = make_request(vec![("msg-1", "我的目标是学会Rust")]);
        let batch = extract(&extractor, request);
        assert_eq!(batch.proposals.len(), 1);
        assert_eq!(batch.proposals[0].kind, Some(MemoryKind::Goal));
    }

    #[test]
    fn extracts_chinese_fact() {
        let extractor = DeterministicCandidateExtractor::new();
        let request = make_request(vec![("msg-1", "我是一名软件工程师")]);
        let batch = extract(&extractor, request);
        assert_eq!(batch.proposals.len(), 1);
        assert_eq!(batch.proposals[0].kind, Some(MemoryKind::Fact));
    }

    #[test]
    fn excludes_questions() {
        let extractor = DeterministicCandidateExtractor::new();
        let request = make_request(vec![("msg-1", "我喜欢咖啡吗？")]);
        let batch = extract(&extractor, request);
        assert_eq!(batch.proposals.len(), 0);
    }

    #[test]
    fn excludes_english_questions() {
        let extractor = DeterministicCandidateExtractor::new();
        let request = make_request(vec![("msg-1", "Do I like coffee?")]);
        let batch = extract(&extractor, request);
        assert_eq!(batch.proposals.len(), 0);
    }

    #[test]
    fn excludes_third_person() {
        let extractor = DeterministicCandidateExtractor::new();
        let request = make_request(vec![("msg-1", "他说他喜欢咖啡")]);
        let batch = extract(&extractor, request);
        assert_eq!(batch.proposals.len(), 0);
    }

    #[test]
    fn excludes_code_blocks() {
        let extractor = DeterministicCandidateExtractor::new();
        let request = make_request(vec![("msg-1", "```rust\nfn main() {}\n```")]);
        let batch = extract(&extractor, request);
        assert_eq!(batch.proposals.len(), 0);
    }

    #[test]
    fn excludes_technical_text() {
        let extractor = DeterministicCandidateExtractor::new();
        let request = make_request(vec![("msg-1", "SELECT * FROM users WHERE id = 1")]);
        let batch = extract(&extractor, request);
        assert_eq!(batch.proposals.len(), 0);
    }

    #[test]
    fn max_five_proposals() {
        let extractor = DeterministicCandidateExtractor::new();
        let messages: Vec<(&str, &str)> = (0..10)
            .map(|i| ("msg", format!("我喜欢{}", i).leak() as &str))
            .collect();
        let request = make_request(messages);
        let batch = extract(&extractor, request);
        assert!(batch.proposals.len() <= 5);
    }

    #[test]
    fn deterministic_same_input_same_output() {
        let extractor = DeterministicCandidateExtractor::new();
        let request1 = make_request(vec![("msg-1", "我喜欢喝茶"), ("msg-2", "我通常早起")]);
        let request2 = make_request(vec![("msg-1", "我喜欢喝茶"), ("msg-2", "我通常早起")]);
        let batch1 = extract(&extractor, request1);
        let batch2 = extract(&extractor, request2);
        assert_eq!(batch1, batch2);
    }

    #[test]
    fn empty_messages_no_proposals() {
        let extractor = DeterministicCandidateExtractor::new();
        let request = make_request(vec![]);
        let batch = extract(&extractor, request);
        assert_eq!(batch.proposals.len(), 0);
    }

    #[test]
    fn no_extraction_from_empty_content() {
        let extractor = DeterministicCandidateExtractor::new();
        let request = make_request(vec![("msg-1", "")]);
        let batch = extract(&extractor, request);
        assert_eq!(batch.proposals.len(), 0);
    }

    #[test]
    fn boundary_marker_extraction() {
        let extractor = DeterministicCandidateExtractor::new();
        let request = make_request(vec![("msg-1", "请不要在晚上十点后打扰我")]);
        let batch = extract(&extractor, request);
        assert_eq!(batch.proposals.len(), 1);
        assert_eq!(batch.proposals[0].kind, Some(MemoryKind::Preference));
    }
}
