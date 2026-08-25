//! SQLite-authoritative relationship persistence.
//!
//! SQLite is the ONLY relationship authority. The event ledger stores bounded
//! state-transition evidence only - never message bodies, memory content,
//! prompts, model output, or free-text psychological explanation. One
//! transition commits `relationship_event` + `relationship_state` in one
//! SQLite transaction. No decay and no policy live here (D12-B2).

use rusqlite::{params, OptionalExtension, Row, Transaction, TransactionBehavior};

use crate::relationship::{
    RelationshipCommitOutcome, RelationshipDimensions, RelationshipError, RelationshipErrorCode,
    RelationshipEvent, RelationshipRepository, RelationshipState, RelationshipTransition,
};

use super::StorageService;

const RELATIONSHIP_STATE_COLUMNS: &str =
    "life_id, subject_id, familiarity, trust, emotional_closeness, collaboration, safety, \
     dependency_tendency, boundary_comfort, tension, revision, policy_version, last_applied_at, \
     updated_at";
const RELATIONSHIP_EVENT_COLUMNS: &str =
    "event_id, life_id, subject_id, source_kind, source_ref, change_reason, \
     familiarity_delta, trust_delta, emotional_closeness_delta, collaboration_delta, \
     safety_delta, dependency_tendency_delta, boundary_comfort_delta, tension_delta, \
     result_familiarity, result_trust, result_emotional_closeness, result_collaboration, \
     result_safety, result_dependency_tendency, result_boundary_comfort, result_tension, \
     applied_revision, event_time, policy_version, created_at";

fn read_relationship_state(row: &Row<'_>) -> rusqlite::Result<RelationshipState> {
    Ok(RelationshipState {
        life_id: row.get(0)?,
        subject_id: row.get(1)?,
        values: RelationshipDimensions {
            familiarity: row.get(2)?,
            trust: row.get(3)?,
            emotional_closeness: row.get(4)?,
            collaboration: row.get(5)?,
            safety: row.get(6)?,
            dependency_tendency: row.get(7)?,
            boundary_comfort: row.get(8)?,
            tension: row.get(9)?,
        },
        revision: row.get(10)?,
        policy_version: row.get(11)?,
        last_applied_at: row.get(12)?,
        updated_at: row.get(13)?,
    })
}

fn read_relationship_event(row: &Row<'_>) -> rusqlite::Result<RelationshipEvent> {
    Ok(RelationshipEvent {
        event_id: row.get(0)?,
        life_id: row.get(1)?,
        subject_id: row.get(2)?,
        source_kind: row.get(3)?,
        source_ref: row.get(4)?,
        change_reason: row.get(5)?,
        deltas: RelationshipDimensions {
            familiarity: row.get(6)?,
            trust: row.get(7)?,
            emotional_closeness: row.get(8)?,
            collaboration: row.get(9)?,
            safety: row.get(10)?,
            dependency_tendency: row.get(11)?,
            boundary_comfort: row.get(12)?,
            tension: row.get(13)?,
        },
        result: RelationshipDimensions {
            familiarity: row.get(14)?,
            trust: row.get(15)?,
            emotional_closeness: row.get(16)?,
            collaboration: row.get(17)?,
            safety: row.get(18)?,
            dependency_tendency: row.get(19)?,
            boundary_comfort: row.get(20)?,
            tension: row.get(21)?,
        },
        applied_revision: row.get(22)?,
        event_time: row.get(23)?,
        policy_version: row.get(24)?,
        created_at: row.get(25)?,
    })
}

/// A stored ledger event is a replay of `transition` when EVERY piece of
/// transition evidence matches: identities (life, subject), source identity,
/// change reason, all eight bounded deltas, the resulting eight values
/// actually committed, the target revision, the policy version, and the event
/// time. Any differing payload under the same identity is a conflict, never a
/// silent skip. `target_revision` is derived once by the caller with checked
/// arithmetic; this matcher never performs raw `expected_revision + 1`.
fn event_evidence_matches(
    event: &RelationshipEvent,
    transition: &RelationshipTransition,
    target_revision: i64,
) -> bool {
    let dimensions_match = |stored: &RelationshipDimensions, proposed: &RelationshipDimensions| {
        stored.familiarity == proposed.familiarity
            && stored.trust == proposed.trust
            && stored.emotional_closeness == proposed.emotional_closeness
            && stored.collaboration == proposed.collaboration
            && stored.safety == proposed.safety
            && stored.dependency_tendency == proposed.dependency_tendency
            && stored.boundary_comfort == proposed.boundary_comfort
            && stored.tension == proposed.tension
    };
    event.life_id == transition.life_id
        && event.subject_id == transition.subject_id
        && event.source_kind == transition.source.kind
        && event.source_ref == transition.source.reference
        && event.change_reason == transition.change_reason
        && dimensions_match(&event.deltas, &transition.deltas)
        && dimensions_match(&event.result, &transition.next)
        && event.applied_revision == target_revision
        && event.event_time == transition.event_time
        && event.policy_version == transition.policy_version
}

fn map_event_insert_error(error: rusqlite::Error) -> RelationshipError {
    if let rusqlite::Error::SqliteFailure(_, Some(message)) = &error {
        let lower = message.to_ascii_lowercase();
        if lower.contains("unique constraint failed") {
            // Both (life_id, subject_id, source_kind, source_ref) and
            // (life_id, subject_id, applied_revision) were pre-checked inside
            // this transaction, so a reachable uniqueness violation here means
            // a competing committed writer raced onto the same target
            // revision between our read and our write.
            return RelationshipError::revision_conflict();
        }
        if lower.contains("foreign key constraint failed") {
            return RelationshipError::state_not_found();
        }
    }
    RelationshipError::database()
}

/// The ONE semantic implementation of a relationship mutation. Runs entirely
/// inside a CALLER-OWNED SQLite transaction: it performs the state read,
/// event/source replay detection, revision check, event INSERT,
/// relationship_state CAS UPDATE, and result reload - but NEVER commits or
/// rolls back; the caller owns that decision so a future composite turn can
/// share one atomic transaction. [`RelationshipRepository::commit_transition`]
/// wraps this with its own Immediate transaction and commit.
pub(super) fn commit_transition_in_transaction(
    transaction: &Transaction<'_>,
    transition: RelationshipTransition,
) -> Result<RelationshipCommitOutcome, RelationshipError> {
    transition.validate().map_err(|_| {
        RelationshipError::invalid_argument("The relationship transition is invalid.")
    })?;
    // Derive the target revision once with checked arithmetic. An
    // unrepresentable next revision (expected_revision == i64::MAX) is a
    // typed argument error before any replay lookup or write, and the same
    // derived value backs replay equivalence AND the write below.
    let applied_revision = transition.target_revision()?;

    let now: String = transaction
        .query_row("SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now')", [], |row| {
            row.get(0)
        })
        .map_err(|_| RelationshipError::database())?;

    let current = transaction
        .query_row(
            &format!(
                "SELECT {RELATIONSHIP_STATE_COLUMNS} FROM relationship_state
                 WHERE life_id = ?1 AND subject_id = ?2"
            ),
            [&transition.life_id, &transition.subject_id],
            read_relationship_state,
        )
        .optional()
        .map_err(|_| RelationshipError::database())?;
    let Some(current_state) = current else {
        let life_exists: bool = transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM life_identity WHERE id = ?1)",
                [&transition.life_id],
                |row| row.get(0),
            )
            .map_err(|_| RelationshipError::database())?;
        return Err(if life_exists {
            RelationshipError::state_not_found()
        } else {
            RelationshipError::life_not_found()
        });
    };

    // Idempotency: the exact same event must never mutate state twice.
    // 1) by event identity
    if let Some(existing) = transaction
        .query_row(
            &format!(
                "SELECT {RELATIONSHIP_EVENT_COLUMNS} FROM relationship_event
                 WHERE event_id = ?1"
            ),
            [&transition.event_id],
            read_relationship_event,
        )
        .optional()
        .map_err(|_| RelationshipError::database())?
    {
        if event_evidence_matches(&existing, &transition, applied_revision) {
            return Ok(RelationshipCommitOutcome::Replayed {
                event: existing,
                state: current_state,
            });
        }
        return Err(RelationshipError::event_conflict());
    }
    // 2) by canonical source identity
    if let Some(existing) = transaction
        .query_row(
            &format!(
                "SELECT {RELATIONSHIP_EVENT_COLUMNS} FROM relationship_event
                 WHERE life_id = ?1 AND subject_id = ?2 AND source_kind = ?3 AND source_ref = ?4"
            ),
            params![
                &transition.life_id,
                &transition.subject_id,
                transition.source.kind,
                transition.source.reference
            ],
            read_relationship_event,
        )
        .optional()
        .map_err(|_| RelationshipError::database())?
    {
        if event_evidence_matches(&existing, &transition, applied_revision) {
            return Ok(RelationshipCommitOutcome::Replayed {
                event: existing,
                state: current_state,
            });
        }
        return Err(RelationshipError::event_conflict());
    }

    // Revision conflict: the caller must build on the current revision.
    if current_state.revision != transition.expected_revision {
        return Err(RelationshipError::revision_conflict());
    }

    let event = RelationshipEvent {
        event_id: transition.event_id.clone(),
        life_id: transition.life_id.clone(),
        subject_id: transition.subject_id.clone(),
        source_kind: transition.source.kind.clone(),
        source_ref: transition.source.reference.clone(),
        change_reason: transition.change_reason.clone(),
        deltas: transition.deltas,
        result: transition.next,
        applied_revision,
        event_time: transition.event_time.clone(),
        policy_version: transition.policy_version,
        created_at: now.clone(),
    };
    transaction
        .execute(
            &format!(
                "INSERT INTO relationship_event ({RELATIONSHIP_EVENT_COLUMNS})
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, \
                 ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26)"
            ),
            params![
                event.event_id,
                event.life_id,
                event.subject_id,
                event.source_kind,
                event.source_ref,
                event.change_reason,
                event.deltas.familiarity,
                event.deltas.trust,
                event.deltas.emotional_closeness,
                event.deltas.collaboration,
                event.deltas.safety,
                event.deltas.dependency_tendency,
                event.deltas.boundary_comfort,
                event.deltas.tension,
                event.result.familiarity,
                event.result.trust,
                event.result.emotional_closeness,
                event.result.collaboration,
                event.result.safety,
                event.result.dependency_tendency,
                event.result.boundary_comfort,
                event.result.tension,
                event.applied_revision,
                event.event_time,
                event.policy_version,
                event.created_at,
            ],
        )
        .map_err(map_event_insert_error)?;
    let changed = transaction
        .execute(
            "UPDATE relationship_state
             SET familiarity = ?1, trust = ?2, emotional_closeness = ?3, collaboration = ?4,
                 safety = ?5, dependency_tendency = ?6, boundary_comfort = ?7, tension = ?8,
                 revision = ?9, policy_version = ?10, last_applied_at = ?11, updated_at = ?12
             WHERE life_id = ?13 AND subject_id = ?14 AND revision = ?15",
            params![
                transition.next.familiarity,
                transition.next.trust,
                transition.next.emotional_closeness,
                transition.next.collaboration,
                transition.next.safety,
                transition.next.dependency_tendency,
                transition.next.boundary_comfort,
                transition.next.tension,
                applied_revision,
                transition.policy_version,
                transition.event_time,
                now,
                transition.life_id,
                transition.subject_id,
                transition.expected_revision,
            ],
        )
        .map_err(|_| RelationshipError::database())?;
    if changed != 1 {
        return Err(RelationshipError::revision_conflict());
    }

    let committed_state = transaction
        .query_row(
            &format!(
                "SELECT {RELATIONSHIP_STATE_COLUMNS} FROM relationship_state
                 WHERE life_id = ?1 AND subject_id = ?2"
            ),
            [&transition.life_id, &transition.subject_id],
            read_relationship_state,
        )
        .map_err(|_| RelationshipError::database())?;
    Ok(RelationshipCommitOutcome::Committed {
        event,
        state: committed_state,
    })
}

impl RelationshipRepository for StorageService {
    fn load_current_state(
        &self,
        life_id: &str,
        subject_id: &str,
    ) -> Result<Option<RelationshipState>, RelationshipError> {
        let state = self.state().map_err(|_| RelationshipError::database())?;
        state
            .connection
            .query_row(
                &format!(
                    "SELECT {RELATIONSHIP_STATE_COLUMNS} FROM relationship_state
                     WHERE life_id = ?1 AND subject_id = ?2"
                ),
                params![life_id, subject_id],
                read_relationship_state,
            )
            .optional()
            .map_err(|_| RelationshipError::database())
    }

    fn commit_transition(
        &self,
        transition: RelationshipTransition,
    ) -> Result<RelationshipCommitOutcome, RelationshipError> {
        let mut state = self.state().map_err(|_| RelationshipError::database())?;
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| RelationshipError::database())?;
        let outcome = commit_transition_in_transaction(&transaction, transition)?;
        transaction
            .commit()
            .map_err(|_| RelationshipError::database())?;
        Ok(outcome)
    }

    fn find_event(
        &self,
        life_id: &str,
        subject_id: &str,
        source_kind: &str,
        source_ref: &str,
    ) -> Result<Option<RelationshipEvent>, RelationshipError> {
        let state = self.state().map_err(|_| RelationshipError::database())?;
        state
            .connection
            .query_row(
                &format!(
                    "SELECT {RELATIONSHIP_EVENT_COLUMNS} FROM relationship_event
                     WHERE life_id = ?1 AND subject_id = ?2 AND source_kind = ?3 AND source_ref = ?4"
                ),
                params![life_id, subject_id, source_kind, source_ref],
                read_relationship_event,
            )
            .optional()
            .map_err(|_| RelationshipError::database())
    }
}

/// Compile-time contract: the relationship repository must stay crate-internal.
const _: Option<&dyn RelationshipRepository> = None;
const _: fn(RelationshipErrorCode) -> bool = |_| false;

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
        relationship::{
            RelationshipEventSource, INITIAL_POLICY_VERSION, NEUTRAL_STATE_REVISION,
            PRIMARY_USER_SUBJECT_ID,
        },
        storage::{unique_suffix, LifeIdentityRecord, PersonaTemplateRecord},
    };

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "digital-life-relationship-{name}-{}",
                unique_suffix()
            ));
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
                created_at: "2026-08-25T00:00:00.000Z".into(),
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
                created_at: "2026-08-25T00:00:00.000Z".into(),
                version: 1,
                body_id: "body-b".into(),
                persona_id: "persona-a".into(),
                persona_version: 1,
            })
            .unwrap();
        service
    }

    fn dims(familiarity: i32, trust: i32) -> RelationshipDimensions {
        let mut values = RelationshipDimensions::neutral();
        values.familiarity = familiarity;
        values.trust = trust;
        values
    }

    fn transition(
        event_id: &str,
        life_id: &str,
        source_kind: &str,
        source_ref: &str,
        expected_revision: i64,
    ) -> RelationshipTransition {
        full_transition(
            event_id,
            life_id,
            PRIMARY_USER_SUBJECT_ID,
            source_kind,
            source_ref,
            "policy_conversation_turn",
            expected_revision,
            dims(40, -20),
            dims(40, -20),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn full_transition(
        event_id: &str,
        life_id: &str,
        subject_id: &str,
        source_kind: &str,
        source_ref: &str,
        change_reason: &str,
        expected_revision: i64,
        deltas: RelationshipDimensions,
        next: RelationshipDimensions,
    ) -> RelationshipTransition {
        RelationshipTransition::new(
            event_id,
            life_id,
            subject_id,
            RelationshipEventSource::new(source_kind, source_ref),
            change_reason,
            deltas,
            expected_revision,
            next,
            INITIAL_POLICY_VERSION,
            "2026-08-25T12:00:00.000Z",
        )
        .unwrap()
    }

    fn commit(
        service: &StorageService,
        transition: RelationshipTransition,
    ) -> Result<RelationshipCommitOutcome, RelationshipError> {
        <StorageService as RelationshipRepository>::commit_transition(service, transition)
    }

    fn state_counts(service: &StorageService) -> (i64, i64) {
        let state = service.state().unwrap();
        let state_count: i64 = state
            .connection
            .query_row("SELECT COUNT(*) FROM relationship_state", [], |row| {
                row.get(0)
            })
            .unwrap();
        let event_count: i64 = state
            .connection
            .query_row("SELECT COUNT(*) FROM relationship_event", [], |row| {
                row.get(0)
            })
            .unwrap();
        (state_count, event_count)
    }

    fn primary_state(service: &StorageService, life_id: &str) -> Option<RelationshipState> {
        <StorageService as RelationshipRepository>::load_current_state(
            service,
            life_id,
            PRIMARY_USER_SUBJECT_ID,
        )
        .unwrap()
    }

    #[test]
    fn new_life_receives_exactly_one_neutral_primary_user_state() {
        let root = TestRoot::new("neutral-init");
        let service = seeded_service(&root);

        let (state_count, event_count) = state_counts(&service);
        assert_eq!(state_count, 2);
        assert_eq!(event_count, 0);
        for life_id in ["life-a", "life-b"] {
            let state = primary_state(&service, life_id).unwrap();
            assert_eq!(state.life_id, life_id);
            assert_eq!(state.subject_id, PRIMARY_USER_SUBJECT_ID);
            assert_eq!(state.values, RelationshipDimensions::neutral());
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
                created_at: "2026-08-25T00:00:00.000Z".into(),
                version: 2,
                body_id: "body-a".into(),
                persona_id: "persona-a".into(),
                persona_version: 1,
            })
            .unwrap();

        let (state_count, _) = state_counts(&service);
        assert_eq!(state_count, 2);
        let state = primary_state(&service, "life-a").unwrap();
        assert_eq!(state.revision, NEUTRAL_STATE_REVISION);
        assert_eq!(state.values, RelationshipDimensions::neutral());
    }

    #[test]
    fn load_current_state_is_none_for_unknown_life_or_unknown_subject() {
        let root = TestRoot::new("missing-load");
        let service = seeded_service(&root);
        assert!(primary_state(&service, "missing-life").is_none());
        assert!(
            <StorageService as RelationshipRepository>::load_current_state(
                &service,
                "life-a",
                "unprovisioned_subject"
            )
            .unwrap()
            .is_none()
        );
    }

    #[test]
    fn commit_applies_event_and_state_exactly_once_with_ledger_evidence() {
        let root = TestRoot::new("commit-once");
        let service = seeded_service(&root);

        let outcome = commit(
            &service,
            transition("event-1", "life-a", "conversation", "turn-7", 0),
        )
        .unwrap();
        let (event, state) = match outcome {
            RelationshipCommitOutcome::Committed { event, state } => (event, state),
            RelationshipCommitOutcome::Replayed { .. } => panic!("first commit must commit"),
        };
        assert_eq!(event.event_id, "event-1");
        assert_eq!(event.life_id, "life-a");
        assert_eq!(event.subject_id, PRIMARY_USER_SUBJECT_ID);
        assert_eq!(event.source_kind, "conversation");
        assert_eq!(event.source_ref, "turn-7");
        assert_eq!(event.change_reason, "policy_conversation_turn");
        assert_eq!(event.deltas.familiarity, 40);
        assert_eq!(event.deltas.trust, -20);
        assert_eq!(event.result.familiarity, 40);
        assert_eq!(event.result.trust, -20);
        assert_eq!(event.applied_revision, 1);
        assert_eq!(event.policy_version, INITIAL_POLICY_VERSION);
        assert_eq!(event.event_time, "2026-08-25T12:00:00.000Z");
        assert!(!event.created_at.is_empty());

        assert_eq!(state.life_id, "life-a");
        assert_eq!(state.subject_id, PRIMARY_USER_SUBJECT_ID);
        assert_eq!(state.values.familiarity, 40);
        assert_eq!(state.values.trust, -20);
        assert_eq!(state.revision, 1);
        assert_eq!(state.last_applied_at, "2026-08-25T12:00:00.000Z");

        let (state_count, event_count) = state_counts(&service);
        assert_eq!(state_count, 2);
        assert_eq!(event_count, 1);
        assert_eq!(primary_state(&service, "life-b").unwrap().revision, 0);
    }

    #[test]
    fn every_new_transition_increments_state_revision_exactly_once() {
        let root = TestRoot::new("revision-once");
        let service = seeded_service(&root);

        commit(
            &service,
            transition("event-1", "life-a", "conversation", "turn-1", 0),
        )
        .unwrap();
        commit(
            &service,
            transition("event-2", "life-a", "conversation", "turn-2", 1),
        )
        .unwrap();

        assert_eq!(primary_state(&service, "life-a").unwrap().revision, 2);
        let state = service.state().unwrap();
        let applied: Vec<i64> = state
            .connection
            .prepare(
                "SELECT applied_revision FROM relationship_event
                 WHERE life_id='life-a' ORDER BY applied_revision ASC",
            )
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

        let committed = commit(&service, first).unwrap();
        assert!(matches!(
            committed,
            RelationshipCommitOutcome::Committed { .. }
        ));
        let replayed = commit(&service, replay).unwrap();
        assert!(matches!(
            replayed,
            RelationshipCommitOutcome::Replayed { .. }
        ));

        assert_eq!(primary_state(&service, "life-a").unwrap().revision, 1);
        let (_, event_count) = state_counts(&service);
        assert_eq!(event_count, 1);
    }

    #[test]
    fn replay_by_source_identity_with_same_payload_is_explicit_replay() {
        let root = TestRoot::new("replay-source");
        let service = seeded_service(&root);
        let first = transition("event-1", "life-a", "conversation", "turn-7", 0);
        let retry = transition("event-9", "life-a", "conversation", "turn-7", 0);

        commit(&service, first).unwrap();
        let outcome = commit(&service, retry).unwrap();
        assert!(matches!(
            outcome,
            RelationshipCommitOutcome::Replayed { .. }
        ));
        assert_eq!(primary_state(&service, "life-a").unwrap().revision, 1);
        let (_, event_count) = state_counts(&service);
        assert_eq!(event_count, 1);
    }

    #[test]
    fn same_event_id_with_conflicting_payload_is_rejected_without_mutation() {
        let root = TestRoot::new("event-id-conflict");
        let service = seeded_service(&root);
        commit(
            &service,
            transition("event-1", "life-a", "conversation", "turn-7", 0),
        )
        .unwrap();

        let mut conflicting = transition("event-1", "life-a", "conversation", "turn-7", 0);
        conflicting.deltas.trust = -40;
        conflicting.next.trust = -40;
        let error = commit(&service, conflicting).unwrap_err();
        assert_eq!(error.code, RelationshipErrorCode::EventConflict);

        assert_eq!(primary_state(&service, "life-a").unwrap().revision, 1);
        let (_, event_count) = state_counts(&service);
        assert_eq!(event_count, 1);
        let stored = <StorageService as RelationshipRepository>::find_event(
            &service,
            "life-a",
            PRIMARY_USER_SUBJECT_ID,
            "conversation",
            "turn-7",
        )
        .unwrap()
        .unwrap();
        assert_eq!(stored.deltas.trust, -20);
    }

    #[test]
    fn same_source_identity_with_conflicting_payload_is_rejected_without_mutation() {
        let root = TestRoot::new("source-conflict");
        let service = seeded_service(&root);
        commit(
            &service,
            transition("event-1", "life-a", "conversation", "turn-7", 0),
        )
        .unwrap();

        let mut conflicting = transition("event-2", "life-a", "conversation", "turn-7", 0);
        conflicting.deltas.familiarity = 100;
        conflicting.next.familiarity = 100;
        let error = commit(&service, conflicting).unwrap_err();
        assert_eq!(error.code, RelationshipErrorCode::EventConflict);

        assert_eq!(primary_state(&service, "life-a").unwrap().revision, 1);
        let (_, event_count) = state_counts(&service);
        assert_eq!(event_count, 1);
    }

    #[test]
    fn differing_change_reason_under_same_identity_is_a_conflict() {
        let root = TestRoot::new("reason-conflict");
        let service = seeded_service(&root);
        commit(
            &service,
            full_transition(
                "event-1",
                "life-a",
                PRIMARY_USER_SUBJECT_ID,
                "conversation",
                "turn-7",
                "policy_conversation_turn",
                0,
                dims(40, -20),
                dims(40, -20),
            ),
        )
        .unwrap();

        // Identical evidence EXCEPT the structured change reason: the ledger
        // compares ALL evidence, so this is a conflict, not a replay.
        let error = commit(
            &service,
            full_transition(
                "event-1",
                "life-a",
                PRIMARY_USER_SUBJECT_ID,
                "conversation",
                "turn-7",
                "policy_observation_turn",
                0,
                dims(40, -20),
                dims(40, -20),
            ),
        )
        .unwrap_err();
        assert_eq!(error.code, RelationshipErrorCode::EventConflict);
        assert_eq!(primary_state(&service, "life-a").unwrap().revision, 1);
        let (_, event_count) = state_counts(&service);
        assert_eq!(event_count, 1);
    }

    #[test]
    fn differing_result_state_under_same_deltas_is_a_conflict() {
        let root = TestRoot::new("result-conflict");
        let service = seeded_service(&root);
        commit(
            &service,
            full_transition(
                "event-1",
                "life-a",
                PRIMARY_USER_SUBJECT_ID,
                "conversation",
                "turn-7",
                "policy_conversation_turn",
                0,
                dims(40, -20),
                dims(40, -20),
            ),
        )
        .unwrap();

        // Same deltas everywhere but a DIFFERENT resulting familiarity: the
        // persisted result is part of the replay evidence.
        let error = commit(
            &service,
            full_transition(
                "event-1",
                "life-a",
                PRIMARY_USER_SUBJECT_ID,
                "conversation",
                "turn-7",
                "policy_conversation_turn",
                0,
                dims(40, -20),
                dims(55, -20),
            ),
        )
        .unwrap_err();
        assert_eq!(error.code, RelationshipErrorCode::EventConflict);

        let state = primary_state(&service, "life-a").unwrap();
        assert_eq!((state.revision, state.values.familiarity), (1, 40));
        let (_, event_count) = state_counts(&service);
        assert_eq!(event_count, 1);
    }

    #[test]
    fn stale_expected_revision_is_rejected_without_mutation() {
        let root = TestRoot::new("stale-revision");
        let service = seeded_service(&root);
        commit(
            &service,
            transition("event-1", "life-a", "conversation", "turn-1", 0),
        )
        .unwrap();

        let stale = transition("event-2", "life-a", "conversation", "turn-2", 0);
        let error = commit(&service, stale).unwrap_err();
        assert_eq!(error.code, RelationshipErrorCode::RevisionConflict);

        assert_eq!(primary_state(&service, "life-a").unwrap().revision, 1);
        let (_, event_count) = state_counts(&service);
        assert_eq!(event_count, 1);
    }

    #[test]
    fn max_expected_revision_is_a_typed_argument_error_without_mutation() {
        let root = TestRoot::new("max-revision");
        let service = seeded_service(&root);

        // Populate the ledger so the replay lookups see an existing row: the
        // overflow hazard lives in deriving the target revision from
        // expected_revision == i64::MAX.
        commit(
            &service,
            transition("event-1", "life-a", "conversation", "turn-7", 0),
        )
        .unwrap();
        assert_eq!(primary_state(&service, "life-a").unwrap().revision, 1);

        // Re-propose the SAME event identity at i64::MAX: the by-event-id
        // replay lookup is the path that previously hit the unchecked math.
        let error = commit(
            &service,
            transition("event-1", "life-a", "conversation", "turn-7", i64::MAX),
        )
        .unwrap_err();
        assert_eq!(error.code, RelationshipErrorCode::InvalidArgument);

        // A fresh source identity at i64::MAX is a typed argument error too.
        let error = commit(
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
        assert_eq!(error.code, RelationshipErrorCode::InvalidArgument);

        // Neither failed proposal mutated state or appended a ledger row.
        let state = primary_state(&service, "life-a").unwrap();
        assert_eq!(
            (state.values.familiarity, state.values.trust, state.revision),
            (40, -20, 1)
        );
        let (_, event_count) = state_counts(&service);
        assert_eq!(event_count, 1);

        // Ordinary replay and revision increment still work on this path.
        let replayed = commit(
            &service,
            transition("event-1", "life-a", "conversation", "turn-7", 0),
        )
        .unwrap();
        assert!(matches!(
            replayed,
            RelationshipCommitOutcome::Replayed { .. }
        ));
        commit(
            &service,
            transition("event-2", "life-a", "conversation", "turn-8", 1),
        )
        .unwrap();
        let state = primary_state(&service, "life-a").unwrap();
        assert_eq!(
            (state.values.familiarity, state.values.trust, state.revision),
            (40, -20, 2)
        );
        let (_, event_count) = state_counts(&service);
        assert_eq!(event_count, 2);
    }

    #[test]
    fn event_insert_and_state_update_are_atomic_when_unique_revision_collides() {
        let root = TestRoot::new("atomicity");
        let service = seeded_service(&root);
        {
            // Pre-insert an event row that claims revision 1 outside the
            // repository, so the repository's event INSERT collides with
            // UNIQUE(life_id, subject_id, applied_revision) and the whole
            // transaction must roll back.
            let state = service.state().unwrap();
            state
                .connection
                .execute(
                    "INSERT INTO relationship_event
                     (event_id, life_id, subject_id, source_kind, source_ref, change_reason,
                      familiarity_delta, trust_delta, emotional_closeness_delta,
                      collaboration_delta, safety_delta, dependency_tendency_delta,
                      boundary_comfort_delta, tension_delta,
                      result_familiarity, result_trust, result_emotional_closeness,
                      result_collaboration, result_safety, result_dependency_tendency,
                      result_boundary_comfort, result_tension,
                      applied_revision, event_time, policy_version, created_at)
                     VALUES ('sneaky-1', 'life-a', 'primary_user', 'external', 'witness',
                             'policy_external_witness',
                             1, 1, 1, 1, 1, 1, 1, 1,
                             1, 1, 1, 1, 1, 1, 1, 1,
                             1, '2026-08-25T11:00:00.000Z', 1, '2026-08-25T11:00:00.000Z')",
                    [],
                )
                .unwrap();
        }

        let error = commit(
            &service,
            transition("event-1", "life-a", "conversation", "turn-7", 0),
        )
        .unwrap_err();
        assert_eq!(error.code, RelationshipErrorCode::RevisionConflict);

        // The event row was never half-applied and the state never advanced.
        assert_eq!(primary_state(&service, "life-a").unwrap().revision, 0);
        let (_, event_count) = state_counts(&service);
        assert_eq!(event_count, 1);
        let events: Vec<String> = service
            .state()
            .unwrap()
            .connection
            .prepare("SELECT event_id FROM relationship_event ORDER BY event_id")
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
                "INSERT INTO relationship_event
                 (event_id, life_id, subject_id, source_kind, source_ref, change_reason,
                  familiarity_delta, trust_delta, emotional_closeness_delta,
                  collaboration_delta, safety_delta, dependency_tendency_delta,
                  boundary_comfort_delta, tension_delta,
                  result_familiarity, result_trust, result_emotional_closeness,
                  result_collaboration, result_safety, result_dependency_tendency,
                  result_boundary_comfort, result_tension,
                  applied_revision, event_time, policy_version, created_at)
                 VALUES ('tx-1', 'life-a', 'primary_user', 'test', 'probe',
                         'policy_test_probe',
                         1, 1, 1, 1, 1, 1, 1, 1,
                         1, 1, 1, 1, 1, 1, 1, 1,
                         1, '2026-08-25T11:00:00.000Z', 1, '2026-08-25T11:00:00.000Z')",
                [],
            )
            .unwrap();
        // The state write violates the frozen CHECK(between 0 and 1000).
        let failed = transaction.execute(
            "UPDATE relationship_state SET familiarity=1500
             WHERE life_id='life-a' AND subject_id='primary_user'",
            [],
        );
        assert!(failed.is_err());
        drop(transaction);
        let event_count: i64 = state
            .connection
            .query_row("SELECT COUNT(*) FROM relationship_event", [], |row| {
                row.get(0)
            })
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
                created_at: "2026-08-25T00:00:00.000Z".into(),
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
        let outcome_b_handle = thread::spawn(move || {
            b2.wait();
            <StorageService as RelationshipRepository>::commit_transition(
                &w2,
                transition("race-b", "life-a", "conversation", "race-source", 0),
            )
        });
        barrier.wait();
        let outcome_a = <StorageService as RelationshipRepository>::commit_transition(
            &first,
            writer_a.join().unwrap(),
        );
        let outcome_b = outcome_b_handle.join().unwrap();

        let committed_a = matches!(&outcome_a, Ok(RelationshipCommitOutcome::Committed { .. }));
        let committed_b = matches!(&outcome_b, Ok(RelationshipCommitOutcome::Committed { .. }));
        assert_eq!(
            committed_a as i64 + committed_b as i64,
            1,
            "exactly one writer may win"
        );
        for outcome in [&outcome_a, &outcome_b] {
            match outcome {
                Ok(RelationshipCommitOutcome::Committed { .. }) => {}
                Ok(RelationshipCommitOutcome::Replayed { .. }) => {}
                Err(error) => assert_eq!(error.code, RelationshipErrorCode::RevisionConflict),
            }
        }

        let state = first.state().unwrap();
        let revision: i64 = state
            .connection
            .query_row(
                "SELECT revision FROM relationship_state
                 WHERE life_id='life-a' AND subject_id='primary_user'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(revision, 1);
        let event_count: i64 = state
            .connection
            .query_row("SELECT COUNT(*) FROM relationship_event", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(event_count, 1);
        drop(state);
    }

    #[test]
    fn subjects_are_isolated_and_do_not_contaminate_the_primary_user() {
        let root = TestRoot::new("subject-isolation");
        let service = seeded_service(&root);

        // Advance the primary_user relationship for life-a.
        commit(
            &service,
            transition("event-primary", "life-a", "conversation", "turn-1", 0),
        )
        .unwrap();

        // A structurally supported non-primary subject mutates ONLY its own
        // state row; the primary_user row stays untouched. The subject state
        // row is seeded explicitly because B1 never creates rows implicitly.
        {
            let state = service.state().unwrap();
            state
                .connection
                .execute(
                    "INSERT INTO relationship_state
                     (life_id, subject_id, familiarity, trust, emotional_closeness,
                      collaboration, safety, dependency_tendency, boundary_comfort, tension,
                      revision, policy_version, last_applied_at, updated_at)
                     VALUES ('life-a', 'npc_wanderer_01', 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                             '2026-08-25T00:00:00.000Z', '2026-08-25T00:00:00.000Z')",
                    [],
                )
                .unwrap();
            drop(state);
        }
        commit(
            &service,
            full_transition(
                "event-other-subject",
                "life-a",
                "npc_wanderer_01",
                "interaction",
                "encounter-9",
                "policy_npc_encounter",
                0,
                dims(30, 10),
                dims(30, 10),
            ),
        )
        .unwrap();

        let primary = primary_state(&service, "life-a").unwrap();
        assert_eq!((primary.revision, primary.values.familiarity), (1, 40));
        let other = <StorageService as RelationshipRepository>::load_current_state(
            &service,
            "life-a",
            "npc_wanderer_01",
        )
        .unwrap()
        .unwrap();
        assert_eq!((other.revision, other.values.familiarity), (1, 30));

        // The same source_ref across subjects stays independent.
        assert!(<StorageService as RelationshipRepository>::find_event(
            &service,
            "life-a",
            "npc_wanderer_01",
            "interaction",
            "encounter-9"
        )
        .unwrap()
        .is_some());
        let (_, event_count) = state_counts(&service);
        assert_eq!(event_count, 2);
    }

    #[test]
    fn commit_for_missing_life_and_missing_subject_state_is_typed() {
        let root = TestRoot::new("missing-targets");
        let service = seeded_service(&root);

        let unknown_life = commit(
            &service,
            transition("event-x", "missing-life", "conversation", "turn-1", 0),
        )
        .unwrap_err();
        assert_eq!(unknown_life.code, RelationshipErrorCode::LifeNotFound);

        // An existing life whose subject state row was removed out-of-band
        // must surface the SUBJECT-scoped error, not a life error.
        {
            let state = service.state().unwrap();
            state
                .connection
                .execute(
                    "DELETE FROM relationship_state
                     WHERE life_id='life-b' AND subject_id='primary_user'",
                    [],
                )
                .unwrap();
        }
        let missing_subject = commit(
            &service,
            transition("event-y", "life-b", "conversation", "turn-1", 0),
        )
        .unwrap_err();
        assert_eq!(missing_subject.code, RelationshipErrorCode::StateNotFound);
    }

    #[test]
    fn deleting_a_life_cascades_relationship_state_and_events() {
        let root = TestRoot::new("cascade");
        let service = seeded_service(&root);
        commit(
            &service,
            transition("event-a", "life-a", "conversation", "turn-1", 0),
        )
        .unwrap();
        commit(
            &service,
            transition("event-b", "life-b", "conversation", "turn-1", 0),
        )
        .unwrap();

        let state = service.state().unwrap();
        state
            .connection
            .execute("DELETE FROM life_identity WHERE id = 'life-a'", [])
            .unwrap();

        let remaining_states: Vec<String> = state
            .connection
            .prepare("SELECT life_id FROM relationship_state ORDER BY life_id")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(remaining_states, vec!["life-b"]);
        let remaining_events: Vec<String> = state
            .connection
            .prepare("SELECT event_id FROM relationship_event ORDER BY event_id")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(remaining_events, vec!["event-b"]);
        drop(state);

        assert!(primary_state(&service, "life-a").is_none());
    }

    #[test]
    fn ledger_schema_stores_only_bounded_evidence_columns() {
        let root = TestRoot::new("no-free-text-columns");
        let service = seeded_service(&root);
        let state = service.state().unwrap();

        let forbidden_fragments = [
            "body",
            "prompt",
            "message",
            "memory",
            "summary",
            "content",
            "text",
            "explanation",
            "note",
            "thought",
            "response",
        ];
        for (table, expected_columns) in [
            (
                "relationship_state",
                vec![
                    "life_id",
                    "subject_id",
                    "familiarity",
                    "trust",
                    "emotional_closeness",
                    "collaboration",
                    "safety",
                    "dependency_tendency",
                    "boundary_comfort",
                    "tension",
                    "revision",
                    "policy_version",
                    "last_applied_at",
                    "updated_at",
                ],
            ),
            (
                "relationship_event",
                vec![
                    "event_id",
                    "life_id",
                    "subject_id",
                    "source_kind",
                    "source_ref",
                    "change_reason",
                    "familiarity_delta",
                    "trust_delta",
                    "emotional_closeness_delta",
                    "collaboration_delta",
                    "safety_delta",
                    "dependency_tendency_delta",
                    "boundary_comfort_delta",
                    "tension_delta",
                    "result_familiarity",
                    "result_trust",
                    "result_emotional_closeness",
                    "result_collaboration",
                    "result_safety",
                    "result_dependency_tendency",
                    "result_boundary_comfort",
                    "result_tension",
                    "applied_revision",
                    "event_time",
                    "policy_version",
                    "created_at",
                ],
            ),
        ] {
            let mut statement = state
                .connection
                .prepare(&format!("PRAGMA table_info({table})"))
                .unwrap();
            let columns: Vec<String> = statement
                .query_map([], |row| row.get::<_, String>(1))
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            drop(statement);
            assert_eq!(columns, expected_columns, "{table} schema drifted");
            for fragment in forbidden_fragments {
                assert!(
                    !columns.iter().any(|column| column.contains(fragment)),
                    "{table} must not carry a {fragment:?} column"
                );
            }
        }
        drop(state);
    }

    #[test]
    fn sqlite_check_constraints_enforce_the_frozen_ranges() {
        let root = TestRoot::new("check-constraints");
        let service = seeded_service(&root);
        let state = service.state().unwrap();

        let base_state_insert = |familiarity: i32| {
            state.connection.execute(
                "INSERT INTO relationship_state
                 (life_id, subject_id, familiarity, trust, emotional_closeness,
                  collaboration, safety, dependency_tendency, boundary_comfort, tension,
                  revision, policy_version, last_applied_at, updated_at)
                 VALUES ('life-a', 'probe-subject', ?1, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                         '2026-08-25T11:00:00.000Z', '2026-08-25T11:00:00.000Z')",
                [familiarity],
            )
        };
        assert!(base_state_insert(-1).is_err());
        assert!(base_state_insert(1001).is_err());
        assert!(base_state_insert(0).is_ok());

        // Composite primary key rejects a duplicate (life_id, subject_id).
        let duplicate = state.connection.execute(
            "INSERT INTO relationship_state
             (life_id, subject_id, familiarity, trust, emotional_closeness,
              collaboration, safety, dependency_tendency, boundary_comfort, tension,
              revision, policy_version, last_applied_at, updated_at)
             VALUES ('life-a', 'probe-subject', 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                     '2026-08-25T11:00:00.000Z', '2026-08-25T11:00:00.000Z')",
            [],
        );
        assert!(duplicate.is_err());

        let base_event_insert = |result_trust: i32| {
            state.connection.execute(
                "INSERT INTO relationship_event
                 (event_id, life_id, subject_id, source_kind, source_ref, change_reason,
                  familiarity_delta, trust_delta, emotional_closeness_delta,
                  collaboration_delta, safety_delta, dependency_tendency_delta,
                  boundary_comfort_delta, tension_delta,
                  result_familiarity, result_trust, result_emotional_closeness,
                  result_collaboration, result_safety, result_dependency_tendency,
                  result_boundary_comfort, result_tension,
                  applied_revision, event_time, policy_version, created_at)
                 VALUES ('probe-event', 'life-a', 'probe-subject', 'probe', 'ref-1',
                         'policy_probe',
                         1, 1, 1, 1, 1, 1, 1, 1,
                         0, ?1, 0, 0, 0, 0, 0, 0,
                         1, '2026-08-25T11:00:00.000Z', 1, '2026-08-25T11:00:00.000Z')",
                [result_trust],
            )
        };
        assert!(base_event_insert(1001).is_err());
        assert!(base_event_insert(-1001).is_err());
        assert!(base_event_insert(0).is_ok());

        // Canonical source identity is unique per life/subject pair.
        let duplicate_source = state.connection.execute(
            "INSERT INTO relationship_event
             (event_id, life_id, subject_id, source_kind, source_ref, change_reason,
              familiarity_delta, trust_delta, emotional_closeness_delta,
              collaboration_delta, safety_delta, dependency_tendency_delta,
              boundary_comfort_delta, tension_delta,
              result_familiarity, result_trust, result_emotional_closeness,
              result_collaboration, result_safety, result_dependency_tendency,
              result_boundary_comfort, result_tension,
              applied_revision, event_time, policy_version, created_at)
             VALUES ('probe-event-2', 'life-a', 'probe-subject', 'probe', 'ref-1',
                     'policy_probe',
                     1, 1, 1, 1, 1, 1, 1, 1,
                     0, 0, 0, 0, 0, 0, 0, 0,
                     2, '2026-08-25T11:00:00.000Z', 1, '2026-08-25T11:00:00.000Z')",
            [],
        );
        assert!(duplicate_source.is_err());

        // Events cannot attach to a non-existent relationship_state row.
        let orphan_event = state.connection.execute(
            "INSERT INTO relationship_event
             (event_id, life_id, subject_id, source_kind, source_ref, change_reason,
              familiarity_delta, trust_delta, emotional_closeness_delta,
              collaboration_delta, safety_delta, dependency_tendency_delta,
              boundary_comfort_delta, tension_delta,
              result_familiarity, result_trust, result_emotional_closeness,
              result_collaboration, result_safety, result_dependency_tendency,
              result_boundary_comfort, result_tension,
              applied_revision, event_time, policy_version, created_at)
             VALUES ('orphan-event', 'no-such-state', 'primary_user', 'probe', 'ref-orphan',
                     'policy_probe',
                     1, 1, 1, 1, 1, 1, 1, 1,
                     0, 0, 0, 0, 0, 0, 0, 0,
                     1, '2026-08-25T11:00:00.000Z', 1, '2026-08-25T11:00:00.000Z')",
            [],
        );
        assert!(orphan_event.is_err());
        drop(state);
    }
}
