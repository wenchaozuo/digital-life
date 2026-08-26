//! D13-B1 authoritative experience episodes.
//!
//! An experience episode records that one bounded, persisted occurrence took
//! place. It is intentionally an identity-and-timestamps record only: it is
//! not a conversation archive, memory, summary, appraisal, relationship,
//! emotion, prompt context, or model interpretation.

mod conversation;

pub(crate) const EPISODE_KIND: &str = "conversation_turn";
pub(crate) const SOURCE_KIND: &str = "conversation_turn";
pub(crate) const OUTCOME_KIND: &str = "completed";
pub(crate) const COUNTERPART_SUBJECT_ID: &str = "primary_user";
pub(crate) const EPISODE_VERSION: i64 = 1;

pub(crate) use conversation::build_conversation_turn_episode;

const _: fn(&ExperienceEpisode) -> Result<(), ExperienceEpisodeError> = ExperienceEpisode::validate;

/// One immutable authoritative occurrence, backed by SQLite.
///
/// The record deliberately contains no conversation content or semantic
/// interpretation. Its two message identifiers and timestamps bind the
/// occurrence to already-persisted conversation evidence.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) struct ExperienceEpisode {
    pub(crate) episode_id: String,
    pub(crate) life_id: String,
    pub(crate) episode_kind: String,
    pub(crate) source_kind: String,
    pub(crate) source_ref: String,
    pub(crate) conversation_id: String,
    pub(crate) turn_id: String,
    pub(crate) counterpart_subject_id: String,
    pub(crate) user_message_id: String,
    pub(crate) assistant_message_id: String,
    pub(crate) outcome_kind: String,
    pub(crate) started_at: String,
    pub(crate) ended_at: String,
    pub(crate) episode_version: i64,
    pub(crate) created_at: String,
}

impl ExperienceEpisode {
    pub(crate) fn validate(&self) -> Result<(), ExperienceEpisodeError> {
        self.validate_shape()?;
        let expected_source_ref = format!("{}:{}", self.conversation_id, self.turn_id);
        if self.source_ref != expected_source_ref {
            return Err(ExperienceEpisodeError::invalid_argument(
                "source reference is not canonical.",
            ));
        }
        let expected_episode_id = format!(
            "experience-conversation:{}:{}:{}",
            self.life_id, self.conversation_id, self.turn_id
        );
        if self.episode_id != expected_episode_id {
            return Err(ExperienceEpisodeError::invalid_argument(
                "episode identity is not canonical.",
            ));
        }
        Ok(())
    }

    pub(crate) fn validate_shape(&self) -> Result<(), ExperienceEpisodeError> {
        for (name, value) in [
            ("episode identity", self.episode_id.as_str()),
            ("life identity", self.life_id.as_str()),
            ("source reference", self.source_ref.as_str()),
            ("conversation identity", self.conversation_id.as_str()),
            ("turn identity", self.turn_id.as_str()),
            ("counterpart identity", self.counterpart_subject_id.as_str()),
            ("user message identity", self.user_message_id.as_str()),
            (
                "assistant message identity",
                self.assistant_message_id.as_str(),
            ),
            ("started timestamp", self.started_at.as_str()),
            ("ended timestamp", self.ended_at.as_str()),
            ("created timestamp", self.created_at.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(ExperienceEpisodeError::invalid_argument(format!(
                    "{name} must not be empty."
                )));
            }
        }
        if self.episode_kind != EPISODE_KIND {
            return Err(ExperienceEpisodeError::invalid_argument(
                "episode kind must be conversation_turn.",
            ));
        }
        if self.source_kind != SOURCE_KIND {
            return Err(ExperienceEpisodeError::invalid_argument(
                "source kind must be conversation_turn.",
            ));
        }
        if self.outcome_kind != OUTCOME_KIND {
            return Err(ExperienceEpisodeError::invalid_argument(
                "outcome kind must be completed.",
            ));
        }
        if self.counterpart_subject_id != COUNTERPART_SUBJECT_ID {
            return Err(ExperienceEpisodeError::invalid_argument(
                "counterpart subject must be primary_user.",
            ));
        }
        if self.episode_version != EPISODE_VERSION {
            return Err(ExperienceEpisodeError::invalid_argument(
                "episode version must be 1.",
            ));
        }
        if self.user_message_id == self.assistant_message_id {
            return Err(ExperienceEpisodeError::invalid_argument(
                "user and assistant message identities must differ.",
            ));
        }
        if self.started_at > self.ended_at {
            return Err(ExperienceEpisodeError::invalid_argument(
                "episode start must not be after episode end.",
            ));
        }
        if self.created_at != self.ended_at {
            return Err(ExperienceEpisodeError::invalid_argument(
                "episode creation time must equal the completed turn timestamp.",
            ));
        }
        Ok(())
    }
}

const _: fn(
    &crate::conversation::history::AppendConversationTurnResult,
) -> Result<ExperienceEpisode, ExperienceEpisodeError> = build_conversation_turn_episode;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ExperienceEpisodeCommitOutcome {
    Applied { episode: ExperienceEpisode },
    Replayed { episode: ExperienceEpisode },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExperienceEpisodeErrorCode {
    InvalidArgument,
    LifeNotFound,
    SourceNotFound,
    SourceBindingMismatch,
    EpisodeConflict,
    DatabaseUnavailable,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ExperienceEpisodeError {
    pub(crate) code: ExperienceEpisodeErrorCode,
    pub(crate) message: String,
    pub(crate) recoverable: bool,
}

impl ExperienceEpisodeError {
    pub(crate) fn new(code: ExperienceEpisodeErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            recoverable: matches!(
                code,
                ExperienceEpisodeErrorCode::LifeNotFound
                    | ExperienceEpisodeErrorCode::SourceNotFound
                    | ExperienceEpisodeErrorCode::DatabaseUnavailable
            ),
        }
    }

    pub(crate) fn invalid_argument(message: impl Into<String>) -> Self {
        Self::new(ExperienceEpisodeErrorCode::InvalidArgument, message)
    }

    pub(crate) fn life_not_found() -> Self {
        Self::new(
            ExperienceEpisodeErrorCode::LifeNotFound,
            "The specified life was not found.",
        )
    }

    pub(crate) fn source_not_found() -> Self {
        Self::new(
            ExperienceEpisodeErrorCode::SourceNotFound,
            "The persisted conversation source was not found.",
        )
    }

    pub(crate) fn source_binding_mismatch() -> Self {
        Self::new(
            ExperienceEpisodeErrorCode::SourceBindingMismatch,
            "The persisted conversation source does not match the episode evidence.",
        )
    }

    pub(crate) fn episode_conflict() -> Self {
        Self::new(
            ExperienceEpisodeErrorCode::EpisodeConflict,
            "An episode with the same identity or canonical source has conflicting evidence.",
        )
    }

    pub(crate) fn database() -> Self {
        Self::new(
            ExperienceEpisodeErrorCode::DatabaseUnavailable,
            "The experience episode storage operation failed.",
        )
    }
}

/// Crate-internal persistence boundary. Implementations must keep SQLite as
/// the sole authority for episode identity, source binding, replay, and
/// deletion semantics.
pub(crate) trait ExperienceEpisodeRepository: Send + Sync {
    fn find_episode(
        &self,
        episode_id: &str,
    ) -> Result<Option<ExperienceEpisode>, ExperienceEpisodeError>;

    fn find_episode_by_source(
        &self,
        life_id: &str,
        source_kind: &str,
        source_ref: &str,
    ) -> Result<Option<ExperienceEpisode>, ExperienceEpisodeError>;

    fn commit_episode(
        &self,
        episode: ExperienceEpisode,
    ) -> Result<ExperienceEpisodeCommitOutcome, ExperienceEpisodeError>;
}
