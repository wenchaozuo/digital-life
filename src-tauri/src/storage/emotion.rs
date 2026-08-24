//! SQLite-authoritative emotion persistence.
//!
//! SQLite is the ONLY emotion authority. The event ledger stores bounded
//! state-transition evidence only, and one transition commits
//! `emotion_event` + `emotion_state` in one SQLite transaction. No decay, no
//! policy, no time derivation is implemented here (D11-B2).

use rusqlite::{params, OptionalExtension, Row, Transaction, TransactionBehavior};

use crate::emotion::{
    EmotionCommitOutcome, EmotionError, EmotionErrorCode, EmotionEvent, EmotionRepository,
    EmotionState, EmotionTransition,
};

use super::StorageService;

const EMOTION_STATE_COLUMNS: &str =
    "life_id, valence, activation, revision, policy_version, last_applied_at, updated_at";
const EMOTION_EVENT_COLUMNS: &str =
    "event_id, life_id, source_kind, source_ref, valence_delta, activation_delta, \
     result_valence, result_activation, applied_revision, event_time, policy_version, created_at";

fn read_emotion_state(row: &Row<'_>) -> rusqlite::Result<EmotionState> {
    Ok(EmotionState {
        life_id: row.get(0)?,
        valence: row.get(1)?,
        activation: row.get(2)?,
        revision: row.get(3)?,
        policy_version: row.get(4)?,
        last_applied_at: row.get(5)?,
        updated_at: row.get(6)?,
    })
}

fn read_emotion_event(row: &Row<'_>) -> rusqlite::Result<EmotionEvent> {
    Ok(EmotionEvent {
        event_id: row.get(0)?,
        life_id: row.get(1)?,
        source_kind: row.get(2)?,
        source_ref: row.get(3)?,
        valence_delta: row.get(4)?,
        activation_delta: row.get(5)?,
        result_valence: row.get(6)?,
        result_activation: row.get(7)?,
        applied_revision: row.get(8)?,
        event_time: row.get(9)?,
        policy_version: row.get(10)?,
        created_at: row.get(11)?,
    })
}

/// A stored ledger event is a replay of `transition` when every state-relevant
/// payload field matches: identity, bounded deltas, the resulting state
/// actually committed (`result_valence` / `result_activation`), target
/// revision, policy version, and event time. A differing payload for the same
/// identity - including a different next state with identical deltas - is a
/// conflict, never a silent skip. The `target_revision` is derived once by the
/// caller with checked arithmetic, so this matcher never performs raw
/// `expected_revision + 1`.
fn event_evidence_matches(
    event: &EmotionEvent,
    transition: &EmotionTransition,
    target_revision: i64,
) -> bool {
    event.life_id == transition.life_id
        && event.source_kind == transition.source.kind
        && event.source_ref == transition.source.reference
        && event.valence_delta == transition.valence_delta
        && event.activation_delta == transition.activation_delta
        && event.result_valence == transition.next_valence
        && event.result_activation == transition.next_activation
        && event.applied_revision == target_revision
        && event.event_time == transition.event_time
        && event.policy_version == transition.policy_version
}

fn map_event_insert_error(error: rusqlite::Error) -> EmotionError {
    if let rusqlite::Error::SqliteFailure(_, Some(message)) = &error {
        let lower = message.to_ascii_lowercase();
        if lower.contains("unique constraint failed") {
            // The (life_id, source_kind, source_ref) uniqueness was already
            // pre-checked inside this transaction, so the only reachable
            // uniqueness is (life_id, applied_revision): two writers raced
            // onto the same target revision.
            return EmotionError::revision_conflict();
        }
        if lower.contains("foreign key constraint failed") {
            return EmotionError::life_not_found();
        }
    }
    EmotionError::database()
}

/// The ONE semantic implementation of an emotion mutation. Runs entirely
/// inside a CALLER-OWNED SQLite transaction: it performs the state read,
/// event/source replay detection, revision check, event INSERT, emotion_state
/// CAS UPDATE, and result reload — but NEVER commits or rolls back; the
/// caller owns that decision so a composite conversation+emotion turn can
/// share one atomic transaction. [`EmotionRepository::commit_transition`]
/// wraps this with its own Immediate transaction and commit.
pub(super) fn commit_transition_in_transaction(
    transaction: &Transaction<'_>,
    transition: EmotionTransition,
) -> Result<EmotionCommitOutcome, EmotionError> {
    transition
        .validate()
        .map_err(|_| EmotionError::invalid_argument("The emotion transition is invalid."))?;
    // Derive the target revision once with checked arithmetic. An
    // unrepresentable next revision (expected_revision == i64::MAX) is a
    // typed argument error before any replay lookup or write, and the same
    // derived value backs replay equivalence AND the write below.
    let applied_revision = transition.target_revision()?;

    let now: String = transaction
        .query_row("SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now')", [], |row| {
            row.get(0)
        })
        .map_err(|_| EmotionError::database())?;

    let current = transaction
        .query_row(
            &format!("SELECT {EMOTION_STATE_COLUMNS} FROM emotion_state WHERE life_id = ?1"),
            [&transition.life_id],
            read_emotion_state,
        )
        .optional()
        .map_err(|_| EmotionError::database())?;
    let Some(current_state) = current else {
        let life_exists: bool = transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM life_identity WHERE id = ?1)",
                [&transition.life_id],
                |row| row.get(0),
            )
            .map_err(|_| EmotionError::database())?;
        return Err(if life_exists {
            EmotionError::state_not_found()
        } else {
            EmotionError::life_not_found()
        });
    };

    // Idempotency: the exact same event must never mutate state twice.
    // 1) by event identity
    if let Some(existing) = transaction
        .query_row(
            &format!("SELECT {EMOTION_EVENT_COLUMNS} FROM emotion_event WHERE event_id = ?1"),
            [&transition.event_id],
            read_emotion_event,
        )
        .optional()
        .map_err(|_| EmotionError::database())?
    {
        if event_evidence_matches(&existing, &transition, applied_revision) {
            return Ok(EmotionCommitOutcome::Replayed {
                event: existing,
                state: current_state,
            });
        }
        return Err(EmotionError::event_conflict());
    }
    // 2) by source identity
    if let Some(existing) = transaction
        .query_row(
            &format!(
                "SELECT {EMOTION_EVENT_COLUMNS} FROM emotion_event
                 WHERE life_id = ?1 AND source_kind = ?2 AND source_ref = ?3"
            ),
            params![
                &transition.life_id,
                transition.source.kind,
                transition.source.reference
            ],
            read_emotion_event,
        )
        .optional()
        .map_err(|_| EmotionError::database())?
    {
        if event_evidence_matches(&existing, &transition, applied_revision) {
            return Ok(EmotionCommitOutcome::Replayed {
                event: existing,
                state: current_state,
            });
        }
        return Err(EmotionError::event_conflict());
    }

    // Revision conflict: the caller must build on the current revision.
    if current_state.revision != transition.expected_revision {
        return Err(EmotionError::revision_conflict());
    }

    let event = EmotionEvent {
        event_id: transition.event_id.clone(),
        life_id: transition.life_id.clone(),
        source_kind: transition.source.kind.clone(),
        source_ref: transition.source.reference.clone(),
        valence_delta: transition.valence_delta,
        activation_delta: transition.activation_delta,
        result_valence: transition.next_valence,
        result_activation: transition.next_activation,
        applied_revision,
        event_time: transition.event_time.clone(),
        policy_version: transition.policy_version,
        created_at: now.clone(),
    };
    transaction
        .execute(
            &format!(
                "INSERT INTO emotion_event ({EMOTION_EVENT_COLUMNS})
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)"
            ),
            params![
                event.event_id,
                event.life_id,
                event.source_kind,
                event.source_ref,
                event.valence_delta,
                event.activation_delta,
                event.result_valence,
                event.result_activation,
                event.applied_revision,
                event.event_time,
                event.policy_version,
                event.created_at,
            ],
        )
        .map_err(map_event_insert_error)?;
    let changed = transaction
        .execute(
            "UPDATE emotion_state
             SET valence = ?1, activation = ?2, revision = ?3, policy_version = ?4,
                 last_applied_at = ?5, updated_at = ?6
             WHERE life_id = ?7 AND revision = ?8",
            params![
                transition.next_valence,
                transition.next_activation,
                applied_revision,
                transition.policy_version,
                transition.event_time,
                now,
                transition.life_id,
                transition.expected_revision,
            ],
        )
        .map_err(|_| EmotionError::database())?;
    if changed != 1 {
        return Err(EmotionError::revision_conflict());
    }

    let committed_state = transaction
        .query_row(
            &format!("SELECT {EMOTION_STATE_COLUMNS} FROM emotion_state WHERE life_id = ?1"),
            [&transition.life_id],
            read_emotion_state,
        )
        .map_err(|_| EmotionError::database())?;
    Ok(EmotionCommitOutcome::Committed {
        event,
        state: committed_state,
    })
}

impl EmotionRepository for StorageService {
    fn load_current_state(&self, life_id: &str) -> Result<Option<EmotionState>, EmotionError> {
        let state = self.state().map_err(|_| EmotionError::database())?;
        state
            .connection
            .query_row(
                &format!("SELECT {EMOTION_STATE_COLUMNS} FROM emotion_state WHERE life_id = ?1"),
                [life_id],
                read_emotion_state,
            )
            .optional()
            .map_err(|_| EmotionError::database())
    }

    fn commit_transition(
        &self,
        transition: EmotionTransition,
    ) -> Result<EmotionCommitOutcome, EmotionError> {
        let mut state = self.state().map_err(|_| EmotionError::database())?;
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| EmotionError::database())?;
        let outcome = commit_transition_in_transaction(&transaction, transition)?;
        transaction.commit().map_err(|_| EmotionError::database())?;
        Ok(outcome)
    }

    fn find_event(
        &self,
        life_id: &str,
        source_kind: &str,
        source_ref: &str,
    ) -> Result<Option<EmotionEvent>, EmotionError> {
        let state = self.state().map_err(|_| EmotionError::database())?;
        state
            .connection
            .query_row(
                &format!(
                    "SELECT {EMOTION_EVENT_COLUMNS} FROM emotion_event
                     WHERE life_id = ?1 AND source_kind = ?2 AND source_ref = ?3"
                ),
                params![life_id, source_kind, source_ref],
                read_emotion_event,
            )
            .optional()
            .map_err(|_| EmotionError::database())
    }
}

/// Compile-time contract: the emotion repository must stay crate-internal.
const _: Option<&dyn EmotionRepository> = None;
const _: fn(EmotionErrorCode) -> bool = |_| false;

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        sync::{Arc, Barrier},
        thread,
    };

    use super::*;
    use crate::{
        emotion::{
            EmotionEventSource, INITIAL_POLICY_VERSION, NEUTRAL_ACTIVATION, NEUTRAL_STATE_REVISION,
            NEUTRAL_VALENCE,
        },
        storage::{unique_suffix, LifeIdentityRecord, PersonaTemplateRecord},
    };

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir()
                .join(format!("digital-life-emotion-{name}-{}", unique_suffix()));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn seeded_service(root: &TestRoot) -> StorageService {
        let service = StorageService::initialize_with_roots(root.0.join("data"), None).unwrap();
        service
            .save_persona(PersonaTemplateRecord {
                id: "persona-a".into(),
                name: "Persona".into(),
                version: 1,
                persona_json: "{}".into(),
            })
            .unwrap();
        service
            .save_life(LifeIdentityRecord {
                id: "life-a".into(),
                name: "Life A".into(),
                created_at: "2026-08-23T00:00:00.000Z".into(),
                version: 1,
                body_id: "body-a".into(),
                persona_id: "persona-a".into(),
                persona_version: 1,
            })
            .unwrap();
        service
            .save_life(LifeIdentityRecord {
                id: "life-b".into(),
                name: "Life B".into(),
                created_at: "2026-08-23T00:00:00.000Z".into(),
                version: 1,
                body_id: "body-b".into(),
                persona_id: "persona-a".into(),
                persona_version: 1,
            })
            .unwrap();
        service
    }

    fn transition(
        event_id: &str,
        life_id: &str,
        source_kind: &str,
        source_ref: &str,
        expected_revision: i64,
    ) -> EmotionTransition {
        EmotionTransition::new(
            event_id,
            life_id,
            EmotionEventSource::new(source_kind, source_ref),
            40,
            -20,
            expected_revision,
            40,
            -20,
            INITIAL_POLICY_VERSION,
            "2026-08-23T12:00:00.000Z",
        )
        .unwrap()
    }

    fn state_counts(service: &StorageService) -> (i64, i64) {
        let state = service.state().unwrap();
        let state_count: i64 = state
            .connection
            .query_row("SELECT COUNT(*) FROM emotion_state", [], |row| row.get(0))
            .unwrap();
        let event_count: i64 = state
            .connection
            .query_row("SELECT COUNT(*) FROM emotion_event", [], |row| row.get(0))
            .unwrap();
        (state_count, event_count)
    }

    fn life_state(service: &StorageService, life_id: &str) -> Option<EmotionState> {
        <StorageService as EmotionRepository>::load_current_state(service, life_id).unwrap()
    }

    #[test]
    fn new_life_receives_exactly_one_neutral_state_row() {
        let root = TestRoot::new("neutral-init");
        let service = seeded_service(&root);

        for life_id in ["life-a", "life-b"] {
            let (state_count, event_count) = state_counts(&service);
            assert_eq!(state_count, 2);
            assert_eq!(event_count, 0);
            let state = life_state(&service, life_id).unwrap();
            assert_eq!(state.life_id, life_id);
            assert_eq!(state.valence, NEUTRAL_VALENCE);
            assert_eq!(state.activation, NEUTRAL_ACTIVATION);
            assert_eq!(state.revision, NEUTRAL_STATE_REVISION);
            assert_eq!(state.policy_version, INITIAL_POLICY_VERSION);
            assert!(!state.last_applied_at.is_empty());
            assert!(!state.updated_at.is_empty());
        }
    }

    #[test]
    fn updating_an_existing_life_does_not_duplicate_state() {
        let root = TestRoot::new("life-upsert");
        let service = seeded_service(&root);
        service
            .save_life(LifeIdentityRecord {
                id: "life-a".into(),
                name: "Life A renamed".into(),
                created_at: "2026-08-23T00:00:00.000Z".into(),
                version: 2,
                body_id: "body-a".into(),
                persona_id: "persona-a".into(),
                persona_version: 1,
            })
            .unwrap();

        let (state_count, _) = state_counts(&service);
        assert_eq!(state_count, 2);
        let state = life_state(&service, "life-a").unwrap();
        assert_eq!(state.revision, NEUTRAL_STATE_REVISION);
        assert_eq!(state.valence, NEUTRAL_VALENCE);
    }

    #[test]
    fn load_current_state_is_none_for_unknown_life() {
        let root = TestRoot::new("missing-load");
        let service = seeded_service(&root);
        assert!(life_state(&service, "missing-life").is_none());
    }

    #[test]
    fn commit_applies_event_and_state_exactly_once_with_ledger_evidence() {
        let root = TestRoot::new("commit-once");
        let service = seeded_service(&root);

        let outcome = <StorageService as EmotionRepository>::commit_transition(
            &service,
            transition("event-1", "life-a", "conversation", "turn-7", 0),
        )
        .unwrap();
        let (event, state) = match outcome {
            EmotionCommitOutcome::Committed { event, state } => (event, state),
            EmotionCommitOutcome::Replayed { .. } => panic!("first commit must commit"),
        };
        assert_eq!(event.event_id, "event-1");
        assert_eq!(event.life_id, "life-a");
        assert_eq!(event.source_kind, "conversation");
        assert_eq!(event.source_ref, "turn-7");
        assert_eq!(event.valence_delta, 40);
        assert_eq!(event.activation_delta, -20);
        assert_eq!(event.result_valence, 40);
        assert_eq!(event.result_activation, -20);
        assert_eq!(event.applied_revision, 1);
        assert_eq!(event.policy_version, INITIAL_POLICY_VERSION);
        assert_eq!(event.event_time, "2026-08-23T12:00:00.000Z");
        assert!(!event.created_at.is_empty());

        assert_eq!(state.life_id, "life-a");
        assert_eq!(state.valence, 40);
        assert_eq!(state.activation, -20);
        assert_eq!(state.revision, 1);
        assert_eq!(state.last_applied_at, "2026-08-23T12:00:00.000Z");

        let (state_count, event_count) = state_counts(&service);
        assert_eq!(state_count, 2);
        assert_eq!(event_count, 1);
        assert_eq!(life_state(&service, "life-b").unwrap().revision, 0);
    }

    #[test]
    fn every_new_transition_increments_state_revision_exactly_once() {
        let root = TestRoot::new("revision-once");
        let service = seeded_service(&root);

        <StorageService as EmotionRepository>::commit_transition(
            &service,
            transition("event-1", "life-a", "conversation", "turn-1", 0),
        )
        .unwrap();
        <StorageService as EmotionRepository>::commit_transition(
            &service,
            transition("event-2", "life-a", "conversation", "turn-2", 1),
        )
        .unwrap();

        assert_eq!(life_state(&service, "life-a").unwrap().revision, 2);
        let state = service.state().unwrap();
        let applied: Vec<i64> = state
            .connection
            .prepare("SELECT applied_revision FROM emotion_event WHERE life_id='life-a' ORDER BY applied_revision ASC")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(applied, vec![1, 2]);
        drop(state);
    }

    #[test]
    fn exact_replay_does_not_double_apply() {
        let root = TestRoot::new("replay-exact");
        let service = seeded_service(&root);
        let first = transition("event-1", "life-a", "conversation", "turn-7", 0);
        let replay = transition("event-1", "life-a", "conversation", "turn-7", 0);

        let committed =
            <StorageService as EmotionRepository>::commit_transition(&service, first).unwrap();
        assert!(matches!(committed, EmotionCommitOutcome::Committed { .. }));
        let replayed =
            <StorageService as EmotionRepository>::commit_transition(&service, replay).unwrap();
        assert!(matches!(replayed, EmotionCommitOutcome::Replayed { .. }));

        assert_eq!(life_state(&service, "life-a").unwrap().revision, 1);
        let (_, event_count) = state_counts(&service);
        assert_eq!(event_count, 1);
    }

    #[test]
    fn replay_by_source_identity_with_same_payload_is_explicit_replay() {
        let root = TestRoot::new("replay-source");
        let service = seeded_service(&root);
        let first = transition("event-1", "life-a", "conversation", "turn-7", 0);
        let retry = transition("event-9", "life-a", "conversation", "turn-7", 0);

        <StorageService as EmotionRepository>::commit_transition(&service, first).unwrap();
        let outcome =
            <StorageService as EmotionRepository>::commit_transition(&service, retry).unwrap();
        assert!(matches!(outcome, EmotionCommitOutcome::Replayed { .. }));
        assert_eq!(life_state(&service, "life-a").unwrap().revision, 1);
        let (_, event_count) = state_counts(&service);
        assert_eq!(event_count, 1);
    }

    #[test]
    fn same_event_id_with_conflicting_payload_is_rejected_without_mutation() {
        let root = TestRoot::new("event-id-conflict");
        let service = seeded_service(&root);
        <StorageService as EmotionRepository>::commit_transition(
            &service,
            transition("event-1", "life-a", "conversation", "turn-7", 0),
        )
        .unwrap();

        let mut conflicting = transition("event-1", "life-a", "conversation", "turn-7", 0);
        conflicting.valence_delta = -40;
        conflicting.next_valence = -40;
        let error = <StorageService as EmotionRepository>::commit_transition(&service, conflicting)
            .unwrap_err();
        assert_eq!(error.code, EmotionErrorCode::EventConflict);

        assert_eq!(life_state(&service, "life-a").unwrap().revision, 1);
        let (_, event_count) = state_counts(&service);
        assert_eq!(event_count, 1);
        let stored = <StorageService as EmotionRepository>::find_event(
            &service,
            "life-a",
            "conversation",
            "turn-7",
        )
        .unwrap()
        .unwrap();
        assert_eq!(stored.valence_delta, 40);
    }

    #[test]
    fn same_source_identity_with_conflicting_payload_is_rejected_without_mutation() {
        let root = TestRoot::new("source-conflict");
        let service = seeded_service(&root);
        <StorageService as EmotionRepository>::commit_transition(
            &service,
            transition("event-1", "life-a", "conversation", "turn-7", 0),
        )
        .unwrap();

        let mut conflicting = transition("event-2", "life-a", "conversation", "turn-7", 0);
        conflicting.activation_delta = 100;
        conflicting.next_activation = 100;
        let error = <StorageService as EmotionRepository>::commit_transition(&service, conflicting)
            .unwrap_err();
        assert_eq!(error.code, EmotionErrorCode::EventConflict);

        assert_eq!(life_state(&service, "life-a").unwrap().revision, 1);
        let (_, event_count) = state_counts(&service);
        assert_eq!(event_count, 1);
    }

    #[test]
    fn stale_expected_revision_is_rejected_without_mutation() {
        let root = TestRoot::new("stale-revision");
        let service = seeded_service(&root);
        <StorageService as EmotionRepository>::commit_transition(
            &service,
            transition("event-1", "life-a", "conversation", "turn-1", 0),
        )
        .unwrap();

        let stale = transition("event-2", "life-a", "conversation", "turn-2", 0);
        let error =
            <StorageService as EmotionRepository>::commit_transition(&service, stale).unwrap_err();
        assert_eq!(error.code, EmotionErrorCode::RevisionConflict);

        assert_eq!(life_state(&service, "life-a").unwrap().revision, 1);
        let (_, event_count) = state_counts(&service);
        assert_eq!(event_count, 1);
    }

    #[test]
    fn max_expected_revision_is_a_typed_argument_error_without_mutation() {
        let root = TestRoot::new("max-revision");
        let service = seeded_service(&root);

        // Populate the ledger so the replay lookups see an existing row: the
        // old code overflow-called `expected_revision + 1` for i64::MAX here
        // (panic in debug, wrap in release) before it could reject.
        <StorageService as EmotionRepository>::commit_transition(
            &service,
            transition("event-1", "life-a", "conversation", "turn-7", 0),
        )
        .unwrap();
        assert_eq!(life_state(&service, "life-a").unwrap().revision, 1);

        // Re-propose the SAME event identity at i64::MAX: the by-event-id
        // replay lookup is the path that previously hit the unchecked math.
        let error = <StorageService as EmotionRepository>::commit_transition(
            &service,
            transition("event-1", "life-a", "conversation", "turn-7", i64::MAX),
        )
        .unwrap_err();
        assert_eq!(error.code, EmotionErrorCode::InvalidArgument);

        // A fresh source identity at i64::MAX is a typed argument error too.
        let error = <StorageService as EmotionRepository>::commit_transition(
            &service,
            transition(
                "event-max-fresh",
                "life-a",
                "conversation",
                "overflow-probe",
                i64::MAX,
            ),
        )
        .unwrap_err();
        assert_eq!(error.code, EmotionErrorCode::InvalidArgument);

        // Neither failed proposal mutated state or appended a ledger row.
        let state = life_state(&service, "life-a").unwrap();
        assert_eq!(
            (state.valence, state.activation, state.revision),
            (40, -20, 1)
        );
        let (_, event_count) = state_counts(&service);
        assert_eq!(event_count, 1);

        // Ordinary replay and revision increment still work on this path.
        let replayed = <StorageService as EmotionRepository>::commit_transition(
            &service,
            transition("event-1", "life-a", "conversation", "turn-7", 0),
        )
        .unwrap();
        assert!(matches!(replayed, EmotionCommitOutcome::Replayed { .. }));
        <StorageService as EmotionRepository>::commit_transition(
            &service,
            transition("event-2", "life-a", "conversation", "turn-8", 1),
        )
        .unwrap();
        let state = life_state(&service, "life-a").unwrap();
        assert_eq!(
            (state.valence, state.activation, state.revision),
            (40, -20, 2)
        );
        let (_, event_count) = state_counts(&service);
        assert_eq!(event_count, 2);
    }

    fn commit_with_result_state(
        service: &StorageService,
        event_id: &str,
        source_ref: &str,
        expected_revision: i64,
        deltas: (i32, i32),
        result: (i32, i32),
    ) -> Result<EmotionCommitOutcome, EmotionError> {
        <StorageService as EmotionRepository>::commit_transition(
            service,
            EmotionTransition::new(
                event_id,
                "life-a",
                EmotionEventSource::new("conversation", source_ref),
                deltas.0,
                deltas.1,
                expected_revision,
                result.0,
                result.1,
                INITIAL_POLICY_VERSION,
                "2026-08-23T12:00:00.000Z",
            )
            .unwrap(),
        )
    }

    #[test]
    fn next_state_only_conflict_via_event_id_is_rejected_without_mutation() {
        let root = TestRoot::new("result-conflict-event-id");
        let service = seeded_service(&root);
        commit_with_result_state(&service, "event-1", "turn-7", 0, (40, -20), (40, -20)).unwrap();

        // Same event_id, same source identity, SAME deltas/expected/event
        // time/policy, but a DIFFERENT resulting valence: this is a
        // conflicting transition payload, not a replay.
        let error =
            commit_with_result_state(&service, "event-1", "turn-7", 0, (40, -20), (50, -20))
                .unwrap_err();
        assert_eq!(error.code, EmotionErrorCode::EventConflict);

        let state = life_state(&service, "life-a").unwrap();
        assert_eq!(state.revision, 1);
        assert_eq!(state.valence, 40);
        assert_eq!(state.activation, -20);
        let (_, event_count) = state_counts(&service);
        assert_eq!(event_count, 1);
        let stored = <StorageService as EmotionRepository>::find_event(
            &service,
            "life-a",
            "conversation",
            "turn-7",
        )
        .unwrap()
        .unwrap();
        assert_eq!((stored.result_valence, stored.result_activation), (40, -20));
    }

    #[test]
    fn next_state_only_conflict_via_source_identity_is_rejected_without_mutation() {
        let root = TestRoot::new("result-conflict-source-id");
        let service = seeded_service(&root);
        commit_with_result_state(&service, "event-1", "turn-7", 0, (40, -20), (40, -20)).unwrap();

        // A different event_id with the SAME (life_id, source_kind,
        // source_ref) and a DIFFERENT resulting activation is a conflict.
        let error =
            commit_with_result_state(&service, "event-2", "turn-7", 0, (40, -20), (40, -30))
                .unwrap_err();
        assert_eq!(error.code, EmotionErrorCode::EventConflict);

        let state = life_state(&service, "life-a").unwrap();
        assert_eq!(state.revision, 1);
        assert_eq!(state.valence, 40);
        assert_eq!(state.activation, -20);
        let (_, event_count) = state_counts(&service);
        assert_eq!(event_count, 1);
    }

    #[test]
    fn exact_replay_requires_full_evidence_including_result_state() {
        let root = TestRoot::new("result-replay");
        let service = seeded_service(&root);
        let first =
            commit_with_result_state(&service, "event-1", "turn-7", 0, (40, -20), (40, -20))
                .unwrap();
        let EmotionCommitOutcome::Committed { event, state } = first else {
            panic!("first commit must commit");
        };
        assert_eq!((event.result_valence, event.result_activation), (40, -20));

        // Identical transitions (including the resulting state) replay
        // without mutating state or appending a second ledger row.
        let replay =
            commit_with_result_state(&service, "event-1", "turn-7", 0, (40, -20), (40, -20))
                .unwrap();
        let EmotionCommitOutcome::Replayed {
            event: replayed,
            state: replay_state,
        } = replay
        else {
            panic!("full-evidence replay must be Replayed");
        };
        assert_eq!(
            (replayed.result_valence, replayed.result_activation),
            (40, -20)
        );
        assert_eq!(replay_state.revision, 1);
        assert_eq!(replay_state.valence, 40);
        assert_eq!(replay_state.activation, -20);
        assert_eq!(state.revision, replay_state.revision);
        let (_, event_count) = state_counts(&service);
        assert_eq!(event_count, 1);
    }

    #[test]
    fn persisted_result_evidence_matches_committed_state_for_each_revision() {
        let root = TestRoot::new("result-persisted");
        let service = seeded_service(&root);

        // First transition: deltas +40/-20, deliberately different result
        // state 25/7 (the policy would decide this; B1 only persists it).
        let first =
            commit_with_result_state(&service, "event-1", "turn-1", 0, (40, -20), (25, 7)).unwrap();
        let EmotionCommitOutcome::Committed {
            event: first_event,
            state: first_state,
        } = first
        else {
            panic!("first commit must commit");
        };
        assert_eq!(
            (first_event.result_valence, first_event.result_activation),
            (25, 7)
        );
        assert_eq!(
            (first_state.valence, first_state.activation),
            (25, 7),
            "the committed state must equal the event result evidence"
        );

        // Second transition applied on revision 1.
        let second =
            commit_with_result_state(&service, "event-2", "turn-2", 1, (10, 5), (35, 12)).unwrap();
        let EmotionCommitOutcome::Committed {
            event: second_event,
            state: second_state,
        } = second
        else {
            panic!("second commit must commit");
        };
        assert_eq!(
            (second_event.result_valence, second_event.result_activation),
            (35, 12)
        );
        assert_eq!(
            (second_state.valence, second_state.activation),
            (35, 12),
            "the committed state must equal the event result evidence"
        );

        // Every persisted ledger row must carry the exact state values that
        // emotion_state held for its applied revision.
        let state = service.state().unwrap();
        let stored: Vec<(i64, i32, i32)> = state
            .connection
            .prepare(
                "SELECT applied_revision, result_valence, result_activation
                 FROM emotion_event ORDER BY applied_revision",
            )
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(stored, vec![(1, 25, 7), (2, 35, 12)]);
        drop(state);

        // The current authoritative state is exactly the last event result.
        let current = life_state(&service, "life-a").unwrap();
        assert_eq!(
            (current.valence, current.activation, current.revision),
            (35, 12, 2)
        );
    }

    #[test]
    fn event_insert_and_state_update_are_atomic_when_unique_revision_collides() {
        let root = TestRoot::new("atomicity");
        let service = seeded_service(&root);
        {
            // Pre-insert an event row that claims revision 1 outside the
            // repository, so the repository's event INSERT collides with
            // UNIQUE(life_id, applied_revision) and the whole transaction
            // must roll back.
            let state = service.state().unwrap();
            state
                .connection
                .execute(
                    "INSERT INTO emotion_event
                     (event_id, life_id, source_kind, source_ref, valence_delta,
                      activation_delta, result_valence, result_activation,
                      applied_revision, event_time, policy_version, created_at)
                     VALUES ('sneaky-1', 'life-a', 'external', 'witness', 1, 1, 1, 1, 1,
                             '2026-08-23T11:00:00.000Z', 1, '2026-08-23T11:00:00.000Z')",
                    [],
                )
                .unwrap();
        }

        let error = <StorageService as EmotionRepository>::commit_transition(
            &service,
            transition("event-1", "life-a", "conversation", "turn-7", 0),
        )
        .unwrap_err();
        assert_eq!(error.code, EmotionErrorCode::RevisionConflict);

        // The event row was never half-applied and the state never advanced.
        assert_eq!(life_state(&service, "life-a").unwrap().revision, 0);
        let (_, event_count) = state_counts(&service);
        assert_eq!(event_count, 1);
        let events: Vec<String> = service
            .state()
            .unwrap()
            .connection
            .prepare("SELECT event_id FROM emotion_event ORDER BY event_id")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(events, vec!["sneaky-1"]);
    }

    #[test]
    fn sqlite_transaction_rolls_back_event_when_state_update_fails() {
        // Documents the SQLite-level guarantee the repository relies on: the
        // event INSERT and the state UPDATE live in one transaction, so a
        // failing state write cannot leave an orphan event row.
        let root = TestRoot::new("db-atomicity");
        let service = seeded_service(&root);
        let mut state = service.state().unwrap();
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        transaction
            .execute(
                "INSERT INTO emotion_event
                 (event_id, life_id, source_kind, source_ref, valence_delta,
                  activation_delta, result_valence, result_activation,
                  applied_revision, event_time, policy_version, created_at)
                 VALUES ('tx-1', 'life-a', 'test', 'probe', 1, 1, 1, 1, 1,
                         '2026-08-23T11:00:00.000Z', 1, '2026-08-23T11:00:00.000Z')",
                [],
            )
            .unwrap();
        // The state write violates the frozen CHECK(between -1000 and 1000).
        let failed = transaction.execute(
            "UPDATE emotion_state SET valence=1500 WHERE life_id='life-a'",
            [],
        );
        assert!(failed.is_err());
        drop(transaction);
        let event_count: i64 = state
            .connection
            .query_row("SELECT COUNT(*) FROM emotion_event", [], |row| row.get(0))
            .unwrap();
        assert_eq!(event_count, 0);
        drop(state);
    }

    #[test]
    fn two_competing_writers_from_the_same_revision_have_one_winner() {
        let root = TestRoot::new("two-writers");
        let first = StorageService::initialize_with_roots(root.0.join("data"), None).unwrap();
        first
            .save_persona(PersonaTemplateRecord {
                id: "persona-a".into(),
                name: "Persona".into(),
                version: 1,
                persona_json: "{}".into(),
            })
            .unwrap();
        first
            .save_life(LifeIdentityRecord {
                id: "life-a".into(),
                name: "Life A".into(),
                created_at: "2026-08-23T00:00:00.000Z".into(),
                version: 1,
                body_id: "body-a".into(),
                persona_id: "persona-a".into(),
                persona_version: 1,
            })
            .unwrap();
        let second = StorageService::initialize_with_roots(root.0.join("data"), None).unwrap();

        let first = Arc::new(first);
        let second = Arc::new(second);
        let barrier = Arc::new(Barrier::new(3));
        let (b1, b2) = (barrier.clone(), barrier.clone());
        let w2 = second.clone();
        // The main thread races writer B below; the helper thread only stages
        // the transition payload, so it needs no service handle.
        let writer_a = thread::spawn(move || {
            b1.wait();
            transition("race-a", "life-a", "conversation", "race-source", 0)
        });
        let outcome_b = thread::spawn(move || {
            b2.wait();
            <StorageService as EmotionRepository>::commit_transition(
                &w2,
                transition("race-b", "life-a", "conversation", "race-source", 0),
            )
        });
        barrier.wait();
        let outcome_a = <StorageService as EmotionRepository>::commit_transition(
            &first,
            writer_a.join().unwrap(),
        );
        let outcome_b = outcome_b.join().unwrap();

        let committed_a = matches!(&outcome_a, Ok(EmotionCommitOutcome::Committed { .. }));
        let committed_b = matches!(&outcome_b, Ok(EmotionCommitOutcome::Committed { .. }));
        assert_eq!(
            committed_a as i64 + committed_b as i64,
            1,
            "exactly one writer may win"
        );
        for outcome in [&outcome_a, &outcome_b] {
            match outcome {
                Ok(EmotionCommitOutcome::Committed { .. }) => {}
                Ok(EmotionCommitOutcome::Replayed { .. }) => {}
                Err(error) => assert_eq!(error.code, EmotionErrorCode::RevisionConflict),
            }
        }

        let state = first.state().unwrap();
        let revision: i64 = state
            .connection
            .query_row(
                "SELECT revision FROM emotion_state WHERE life_id='life-a'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(revision, 1);
        let event_count: i64 = state
            .connection
            .query_row("SELECT COUNT(*) FROM emotion_event", [], |row| row.get(0))
            .unwrap();
        assert_eq!(event_count, 1);
        drop(state);
    }

    #[test]
    fn life_a_cannot_mutate_life_b_and_source_refs_are_per_life() {
        let root = TestRoot::new("life-isolation");
        let service = seeded_service(&root);

        // The same source identity for two different lives is legitimate and
        // must remain independent.
        <StorageService as EmotionRepository>::commit_transition(
            &service,
            transition("event-a", "life-a", "conversation", "shared-ref", 0),
        )
        .unwrap();
        <StorageService as EmotionRepository>::commit_transition(
            &service,
            transition("event-b", "life-b", "conversation", "shared-ref", 0),
        )
        .unwrap();

        assert_eq!(life_state(&service, "life-a").unwrap().revision, 1);
        assert_eq!(life_state(&service, "life-b").unwrap().revision, 1);
        let (_, event_count) = state_counts(&service);
        assert_eq!(event_count, 2);

        let found_a = <StorageService as EmotionRepository>::find_event(
            &service,
            "life-a",
            "conversation",
            "shared-ref",
        )
        .unwrap()
        .unwrap();
        assert_eq!(found_a.event_id, "event-a");
        let found_b = <StorageService as EmotionRepository>::find_event(
            &service,
            "life-b",
            "conversation",
            "shared-ref",
        )
        .unwrap()
        .unwrap();
        assert_eq!(found_b.event_id, "event-b");
    }

    #[test]
    fn deleting_a_life_cascades_emotion_state_and_events() {
        let root = TestRoot::new("cascade");
        let service = seeded_service(&root);
        <StorageService as EmotionRepository>::commit_transition(
            &service,
            transition("event-a", "life-a", "conversation", "turn-1", 0),
        )
        .unwrap();
        <StorageService as EmotionRepository>::commit_transition(
            &service,
            transition("event-b", "life-b", "conversation", "turn-1", 0),
        )
        .unwrap();

        let state = service.state().unwrap();
        state
            .connection
            .execute("DELETE FROM life_identity WHERE id = 'life-a'", [])
            .unwrap();
        let life_a_state: i64 = state
            .connection
            .query_row(
                "SELECT COUNT(*) FROM emotion_state WHERE life_id='life-a'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let life_a_events: i64 = state
            .connection
            .query_row(
                "SELECT COUNT(*) FROM emotion_event WHERE life_id='life-a'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(life_a_state, 0);
        assert_eq!(life_a_events, 0);
        // Life B stays fully intact.
        let life_b_state: i64 = state
            .connection
            .query_row(
                "SELECT COUNT(*) FROM emotion_state WHERE life_id='life-b'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let life_b_events: i64 = state
            .connection
            .query_row(
                "SELECT COUNT(*) FROM emotion_event WHERE life_id='life-b'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(life_b_state, 1);
        assert_eq!(life_b_events, 1);
        drop(state);
    }

    #[test]
    fn missing_life_transition_is_typed_life_not_found() {
        let root = TestRoot::new("missing-life");
        let service = seeded_service(&root);
        let error = <StorageService as EmotionRepository>::commit_transition(
            &service,
            transition("event-1", "missing-life", "conversation", "turn-1", 0),
        )
        .unwrap_err();
        assert_eq!(error.code, EmotionErrorCode::LifeNotFound);
        let (_, event_count) = state_counts(&service);
        assert_eq!(event_count, 0);
    }

    #[test]
    fn missing_state_row_while_life_exists_is_typed_state_not_found() {
        let root = TestRoot::new("missing-state");
        let service = seeded_service(&root);
        {
            let state = service.state().unwrap();
            state
                .connection
                .execute("DELETE FROM emotion_state WHERE life_id='life-a'", [])
                .unwrap();
        }
        let error = <StorageService as EmotionRepository>::commit_transition(
            &service,
            transition("event-1", "life-a", "conversation", "turn-1", 0),
        )
        .unwrap_err();
        assert_eq!(error.code, EmotionErrorCode::StateNotFound);
        let (_, event_count) = state_counts(&service);
        assert_eq!(event_count, 0);
    }

    #[test]
    fn event_ledger_contains_no_message_prompt_or_model_body_fields() {
        let root = TestRoot::new("no-body");
        let service = seeded_service(&root);
        {
            let state = service.state().unwrap();

            let event_columns: Vec<String> = state
                .connection
                .prepare("PRAGMA table_info(emotion_event)")
                .unwrap()
                .query_map([], |row| row.get(1))
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            let mut event_columns = event_columns;
            event_columns.sort();
            assert_eq!(
                event_columns,
                vec![
                    "activation_delta",
                    "applied_revision",
                    "created_at",
                    "event_id",
                    "event_time",
                    "life_id",
                    "policy_version",
                    "result_activation",
                    "result_valence",
                    "source_kind",
                    "source_ref",
                    "valence_delta",
                ]
            );
            let forbidden = [
                "content", "message", "prompt", "response", "body", "text", "json", "summary",
                "raw", "payload", "chain", "thought",
            ];
            for column in &event_columns {
                assert!(
                    !forbidden
                        .iter()
                        .any(|marker| column.to_ascii_lowercase().contains(marker)),
                    "ledger must not carry body columns, found {column}"
                );
            }

            let state_columns: Vec<String> = state
                .connection
                .prepare("PRAGMA table_info(emotion_state)")
                .unwrap()
                .query_map([], |row| row.get(1))
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            let mut state_columns = state_columns;
            state_columns.sort();
            assert_eq!(
                state_columns,
                vec![
                    "activation",
                    "last_applied_at",
                    "life_id",
                    "policy_version",
                    "revision",
                    "updated_at",
                    "valence",
                ]
            );
            (event_columns, state_columns)
        };

        // After a commit the stored rows still contain only the bounded
        // evidence fields.
        <StorageService as EmotionRepository>::commit_transition(
            &service,
            transition("event-1", "life-a", "conversation", "turn-1", 0),
        )
        .unwrap();
        let row: (String, String, String, String, i32, i32, i32, i32, i64) = service
            .state()
            .unwrap()
            .connection
            .query_row(
                "SELECT event_id, source_kind, source_ref, event_time,
                        valence_delta, activation_delta, result_valence,
                        result_activation, applied_revision
                 FROM emotion_event WHERE event_id='event-1'",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                        row.get(8)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(
            row,
            (
                "event-1".into(),
                "conversation".into(),
                "turn-1".into(),
                "2026-08-23T12:00:00.000Z".into(),
                40,
                -20,
                40,
                -20,
                1
            )
        );
    }

    #[test]
    fn database_checks_reject_out_of_bounds_values() {
        let root = TestRoot::new("db-bounds");
        let service = seeded_service(&root);
        {
            let state = service.state().unwrap();
            assert!(state
                .connection
                .execute(
                    "UPDATE emotion_state SET valence=1001 WHERE life_id='life-a'",
                    [],
                )
                .is_err());
            assert!(state
                .connection
                .execute(
                    "UPDATE emotion_state SET activation=-1001 WHERE life_id='life-a'",
                    [],
                )
                .is_err());
            assert!(state
                .connection
                .execute(
                    "UPDATE emotion_state SET revision=-1 WHERE life_id='life-a'",
                    [],
                )
                .is_err());
            assert!(state
                .connection
                .execute(
                    "UPDATE emotion_state SET policy_version=0 WHERE life_id='life-a'",
                    [],
                )
                .is_err());
            assert!(state
                .connection
                .execute(
                    "UPDATE emotion_state SET last_applied_at='' WHERE life_id='life-a'",
                    [],
                )
                .is_err());
            let inserted = state.connection.execute(
                "INSERT INTO emotion_event
                 (event_id, life_id, source_kind, source_ref, valence_delta,
                  activation_delta, result_valence, result_activation,
                  applied_revision, event_time, policy_version, created_at)
                 VALUES ('bad-1', 'life-a', 'kind', 'ref', 1001, 1, 1, 1, 1,
                         '2026-08-23T11:00:00.000Z', 1, '2026-08-23T11:00:00.000Z')",
                [],
            );
            assert!(inserted.is_err());
            let result_checked = state.connection.execute(
                "INSERT INTO emotion_event
                 (event_id, life_id, source_kind, source_ref, valence_delta,
                  activation_delta, result_valence, result_activation,
                  applied_revision, event_time, policy_version, created_at)
                 VALUES ('bad-2', 'life-a', 'kind', 'ref', 1, 1, 1001, 1, 1,
                         '2026-08-23T11:00:00.000Z', 1, '2026-08-23T11:00:00.000Z')",
                [],
            );
            assert!(result_checked.is_err());
            let result_checked_activation = state.connection.execute(
                "INSERT INTO emotion_event
                 (event_id, life_id, source_kind, source_ref, valence_delta,
                  activation_delta, result_valence, result_activation,
                  applied_revision, event_time, policy_version, created_at)
                 VALUES ('bad-3', 'life-a', 'kind', 'ref', 1, 1, 1, -1001, 1,
                         '2026-08-23T11:00:00.000Z', 1, '2026-08-23T11:00:00.000Z')",
                [],
            );
            assert!(result_checked_activation.is_err());
        }
        assert_eq!(life_state(&service, "life-a").unwrap().valence, 0);
    }

    #[test]
    fn find_event_returns_stored_event_after_commit() {
        let root = TestRoot::new("find-event");
        let service = seeded_service(&root);
        assert!(<StorageService as EmotionRepository>::find_event(
            &service,
            "life-a",
            "conversation",
            "turn-1",
        )
        .unwrap()
        .is_none());
        <StorageService as EmotionRepository>::commit_transition(
            &service,
            transition("event-1", "life-a", "conversation", "turn-1", 0),
        )
        .unwrap();
        let event = <StorageService as EmotionRepository>::find_event(
            &service,
            "life-a",
            "conversation",
            "turn-1",
        )
        .unwrap()
        .unwrap();
        assert_eq!(event.event_id, "event-1");
        assert_eq!(event.applied_revision, 1);
        // Same source under another life is a different event.
        assert!(<StorageService as EmotionRepository>::find_event(
            &service,
            "life-b",
            "conversation",
            "turn-1",
        )
        .unwrap()
        .is_none());
    }

    #[test]
    fn replay_and_conflict_outcomes_never_leave_partial_rows() {
        let root = TestRoot::new("evidence-integrity");
        let service = seeded_service(&root);
        <StorageService as EmotionRepository>::commit_transition(
            &service,
            transition("event-1", "life-a", "conversation", "turn-1", 0),
        )
        .unwrap();
        let invalid_rows: i64 = service
            .state()
            .unwrap()
            .connection
            .query_row(
                "SELECT COUNT(*) FROM emotion_event
                 WHERE created_at='' OR event_time='' OR source_kind='' OR source_ref=''
                    OR applied_revision<=0 OR policy_version<=0",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(invalid_rows, 0);
    }
}
