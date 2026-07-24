use std::fmt;

use super::error::{LlmExtractionError, LlmExtractionErrorKind};

pub(super) const V1_MAX_SELECTED_USER_MESSAGES: usize = 64;
pub(super) const V1_MAX_SELECTED_UTF8_BYTES: usize = 131_072;
pub(super) const V1_MAX_PROPOSALS: usize = 5;
pub(super) const V1_MAX_PROPOSAL_CONTENT_SCALARS: usize = 4_000;
pub(super) const V1_MAX_PROPOSAL_CONTENT_UTF8_BYTES: usize = 16_384;
pub(super) const V1_MAX_PROPOSAL_SUMMARY_SCALARS: usize = 500;
pub(super) const V1_MAX_PROPOSAL_SUMMARY_UTF8_BYTES: usize = 2_048;

/// The versioned, provider-facing projection of a selected extraction snapshot.
///
/// It deliberately excludes every D-6 run, revision, snapshot, lease, and
/// persistence identity. D-6 validates those facts again when it later accepts
/// a decoded wire result.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ExtractionWireInputV1 {
    messages: Vec<ExtractionWireMessageV1>,
}

#[derive(Clone, PartialEq, Eq)]
pub(super) struct ExtractionWireMessageV1 {
    message_id: String,
    sequence_no: i64,
    content: String,
}

impl ExtractionWireInputV1 {
    /// Builds the only provider input accepted by the V1 protocol boundary.
    pub(crate) fn from_messages(
        messages: Vec<(String, i64, String)>,
    ) -> Result<Self, LlmExtractionError> {
        if messages.is_empty() || messages.len() > V1_MAX_SELECTED_USER_MESSAGES {
            return Err(LlmExtractionError::definitely_not_sent(
                LlmExtractionErrorKind::ExtractionInputInvalid,
            ));
        }

        let mut total_bytes = 0usize;
        let mut projected = Vec::with_capacity(messages.len());
        for (message_id, sequence_no, content) in messages {
            if message_id.trim().is_empty() || content.trim().is_empty() {
                return Err(LlmExtractionError::definitely_not_sent(
                    LlmExtractionErrorKind::ExtractionInputInvalid,
                ));
            }
            total_bytes = total_bytes.saturating_add(content.len());
            projected.push(ExtractionWireMessageV1 {
                message_id,
                sequence_no,
                content,
            });
        }

        if total_bytes > V1_MAX_SELECTED_UTF8_BYTES {
            return Err(LlmExtractionError::definitely_not_sent(
                LlmExtractionErrorKind::ExtractionInputInvalid,
            ));
        }

        Ok(Self {
            messages: projected,
        })
    }

    pub(crate) const fn message_count(&self) -> usize {
        self.messages.len()
    }

    pub(crate) fn total_utf8_bytes(&self) -> usize {
        self.messages
            .iter()
            .map(|message| message.content.len())
            .fold(0usize, |total, len| total.saturating_add(len))
    }

    pub(super) fn messages(&self) -> &[ExtractionWireMessageV1] {
        &self.messages
    }
}

impl fmt::Debug for ExtractionWireInputV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExtractionWireInputV1")
            .field("message_count", &self.message_count())
            .field("total_utf8_bytes", &self.total_utf8_bytes())
            .finish()
    }
}

impl ExtractionWireMessageV1 {
    pub(super) fn message_id(&self) -> &str {
        &self.message_id
    }

    pub(super) const fn sequence_no(&self) -> i64 {
        self.sequence_no
    }

    pub(super) fn content(&self) -> &str {
        &self.content
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExtractionProtocolVersion {
    V1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WireProposalActionV1 {
    Propose,
    Ignore,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WireMemoryKindV1 {
    Preference,
    Goal,
    Experience,
    Fact,
    Relationship,
    Skill,
    Other,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WireSensitivityHintV1 {
    NotSensitive,
    Sensitive,
    Unknown,
}

#[derive(Clone, PartialEq)]
pub(crate) struct ValidatedWireProposalV1 {
    action: WireProposalActionV1,
    kind: Option<WireMemoryKindV1>,
    content: Option<String>,
    summary: Option<String>,
    confidence: Option<f64>,
    importance: Option<f64>,
    sensitivity_hint: Option<WireSensitivityHintV1>,
    conflict_hint: Option<bool>,
    source_message_ids: Vec<String>,
}

impl ValidatedWireProposalV1 {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn propose(
        kind: WireMemoryKindV1,
        content: String,
        summary: String,
        confidence: f64,
        importance: f64,
        sensitivity_hint: WireSensitivityHintV1,
        conflict_hint: bool,
        source_message_ids: Vec<String>,
    ) -> Self {
        Self {
            action: WireProposalActionV1::Propose,
            kind: Some(kind),
            content: Some(content),
            summary: Some(summary),
            confidence: Some(confidence),
            importance: Some(importance),
            sensitivity_hint: Some(sensitivity_hint),
            conflict_hint: Some(conflict_hint),
            source_message_ids,
        }
    }

    pub(super) fn ignore(source_message_ids: Vec<String>) -> Self {
        Self {
            action: WireProposalActionV1::Ignore,
            kind: None,
            content: None,
            summary: None,
            confidence: None,
            importance: None,
            sensitivity_hint: None,
            conflict_hint: None,
            source_message_ids,
        }
    }

    pub(crate) const fn action(&self) -> WireProposalActionV1 {
        self.action
    }

    pub(crate) const fn kind(&self) -> Option<WireMemoryKindV1> {
        self.kind
    }

    pub(crate) fn content(&self) -> Option<&str> {
        self.content.as_deref()
    }

    pub(crate) fn summary(&self) -> Option<&str> {
        self.summary.as_deref()
    }

    pub(crate) const fn confidence(&self) -> Option<f64> {
        self.confidence
    }

    pub(crate) const fn importance(&self) -> Option<f64> {
        self.importance
    }

    pub(crate) const fn sensitivity_hint(&self) -> Option<WireSensitivityHintV1> {
        self.sensitivity_hint
    }

    pub(crate) const fn conflict_hint(&self) -> Option<bool> {
        self.conflict_hint
    }

    pub(crate) fn source_message_ids(&self) -> &[String] {
        &self.source_message_ids
    }
}

impl fmt::Debug for ValidatedWireProposalV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ValidatedWireProposalV1")
            .field("action", &self.action)
            .field("kind", &self.kind)
            .field("sensitivity_hint", &self.sensitivity_hint)
            .field("source_message_count", &self.source_message_ids.len())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LlmExtractionStats {
    input_message_count: usize,
    input_total_bytes: usize,
    proposal_count: usize,
}

impl LlmExtractionStats {
    pub(super) const fn new(
        input_message_count: usize,
        input_total_bytes: usize,
        proposal_count: usize,
    ) -> Self {
        Self {
            input_message_count,
            input_total_bytes,
            proposal_count,
        }
    }

    pub(crate) const fn input_message_count(&self) -> usize {
        self.input_message_count
    }

    pub(crate) const fn input_total_bytes(&self) -> usize {
        self.input_total_bytes
    }

    pub(crate) const fn proposal_count(&self) -> usize {
        self.proposal_count
    }
}

#[derive(Clone)]
pub(crate) struct ValidatedExtractionWireResultV1 {
    protocol_version: ExtractionProtocolVersion,
    proposals: Vec<ValidatedWireProposalV1>,
    stats: LlmExtractionStats,
}

impl ValidatedExtractionWireResultV1 {
    pub(super) fn new(
        proposals: Vec<ValidatedWireProposalV1>,
        input: &ExtractionWireInputV1,
    ) -> Self {
        Self {
            protocol_version: ExtractionProtocolVersion::V1,
            stats: LlmExtractionStats::new(
                input.message_count(),
                input.total_utf8_bytes(),
                proposals.len(),
            ),
            proposals,
        }
    }

    pub(crate) const fn protocol_version(&self) -> ExtractionProtocolVersion {
        self.protocol_version
    }

    pub(crate) fn proposals(&self) -> &[ValidatedWireProposalV1] {
        &self.proposals
    }

    pub(crate) const fn stats(&self) -> LlmExtractionStats {
        self.stats
    }

    pub(crate) fn into_proposals(self) -> Vec<ValidatedWireProposalV1> {
        self.proposals
    }
}

impl fmt::Debug for ValidatedExtractionWireResultV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ValidatedExtractionWireResultV1")
            .field("protocol_version", &self.protocol_version)
            .field("proposal_count", &self.proposals.len())
            .field("stats", &self.stats)
            .finish()
    }
}
