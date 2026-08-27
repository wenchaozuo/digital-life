//! Trusted D16-C composition of perception focus evidence into the frozen D15
//! autonomy tick.
//!
//! This module owns only the evidence-selection boundary.  The D15 runtime
//! remains the authority for policy, goal selection, intent persistence, CAS,
//! evaluation, and replay.

use crate::{
    perception::{
        foreground_focus::{
            observe_foreground_focus, FocusObservationOutcome, PerceptionFocusState,
        },
        PerceptionError, PerceptionRepository,
    },
    storage::StorageService,
};

use super::{
    deterministic_intent_id, run_autonomy_tick, validate_tick_identity, AutonomyRepository,
    AutonomyTickError, AutonomyTickOutcome, AutonomyTickRequest, INTENT_FOCUS_STATE_AVAILABLE,
    INTENT_FOCUS_STATE_DND, INTENT_FOCUS_STATE_FOCUSED, INTENT_FOCUS_STATE_UNKNOWN,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedAutonomyTickRequest {
    pub(crate) tick_id: String,
    pub(crate) life_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TrustedAutonomyTickError {
    Autonomy(AutonomyTickError),
    Perception(PerceptionError),
}

trait TrustedFocusSource {
    fn observe(
        &self,
        repository: &dyn PerceptionRepository,
        life_id: &str,
    ) -> Result<FocusObservationOutcome, PerceptionError>;
}

#[derive(Clone, Copy, Debug, Default)]
struct B2TrustedFocusSource;

impl TrustedFocusSource for B2TrustedFocusSource {
    fn observe(
        &self,
        repository: &dyn PerceptionRepository,
        life_id: &str,
    ) -> Result<FocusObservationOutcome, PerceptionError> {
        observe_foreground_focus(repository, life_id)
    }
}

/// Run one explicit trusted autonomy tick.
///
/// The caller supplies only the bounded tick and Life identities.  Existing
/// D15 evidence is replayed before the current perception or autonomy policy
/// is consulted; a new focus observation is taken only when the current D15
/// policy requires it.
pub fn run_trusted_autonomy_tick(
    storage: &StorageService,
    request: TrustedAutonomyTickRequest,
) -> Result<AutonomyTickOutcome, TrustedAutonomyTickError> {
    let source = B2TrustedFocusSource;
    run_trusted_autonomy_tick_with_source(storage, request, &source)
}

fn run_trusted_autonomy_tick_with_source(
    storage: &StorageService,
    request: TrustedAutonomyTickRequest,
    source: &dyn TrustedFocusSource,
) -> Result<AutonomyTickOutcome, TrustedAutonomyTickError> {
    validate_tick_identity(&request.tick_id, &request.life_id)
        .map_err(TrustedAutonomyTickError::Autonomy)?;

    let intent_id = deterministic_intent_id(&request.life_id, &request.tick_id);
    if let Some(intent) = storage
        .find_intent(&request.life_id, &intent_id)
        .map_err(|error| TrustedAutonomyTickError::Autonomy(AutonomyTickError::Autonomy(error)))?
    {
        return run_d15_tick(storage, request, intent.focus_state);
    }

    let policy = AutonomyRepository::find_policy(storage, &request.life_id)
        .map_err(|error| TrustedAutonomyTickError::Autonomy(AutonomyTickError::Autonomy(error)))?;
    let focus_state = match policy {
        None => INTENT_FOCUS_STATE_UNKNOWN,
        Some(policy) if !policy.enabled => INTENT_FOCUS_STATE_UNKNOWN,
        Some(policy) if policy.dnd => INTENT_FOCUS_STATE_DND,
        Some(policy) if policy.max_ready_per_window == 0 => INTENT_FOCUS_STATE_UNKNOWN,
        Some(_) => map_focus_observation(
            source
                .observe(storage, &request.life_id)
                .map_err(TrustedAutonomyTickError::Perception)?,
        ),
    };

    run_d15_tick(storage, request, focus_state.to_string())
}

fn run_d15_tick(
    storage: &StorageService,
    request: TrustedAutonomyTickRequest,
    focus_state: String,
) -> Result<AutonomyTickOutcome, TrustedAutonomyTickError> {
    run_autonomy_tick(
        storage,
        AutonomyTickRequest {
            tick_id: request.tick_id,
            life_id: request.life_id,
            focus_state,
        },
    )
    .map_err(TrustedAutonomyTickError::Autonomy)
}

fn map_focus_observation(outcome: FocusObservationOutcome) -> &'static str {
    match outcome {
        FocusObservationOutcome::Disabled => INTENT_FOCUS_STATE_UNKNOWN,
        FocusObservationOutcome::Observed(PerceptionFocusState::Available) => {
            INTENT_FOCUS_STATE_AVAILABLE
        }
        FocusObservationOutcome::Observed(PerceptionFocusState::Focused) => {
            INTENT_FOCUS_STATE_FOCUSED
        }
        FocusObservationOutcome::Observed(PerceptionFocusState::Unknown) => {
            INTENT_FOCUS_STATE_UNKNOWN
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        path::PathBuf,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
    };

    use rusqlite::params;
    use tempfile::TempDir;

    use super::*;
    use crate::{
        autonomy::runtime::AutonomyTickWaitReason,
        autonomy::{
            AutonomyCreateOutcome, LifeAutonomyPolicyCreateRequest, LifeProactiveIntent,
            LifeProactiveIntentCreateRequest, INTENT_FOCUS_STATE_AVAILABLE, INTENT_FOCUS_STATE_DND,
            INTENT_FOCUS_STATE_UNKNOWN, INTENT_KIND_GOAL_CHECK_IN, INTENT_STATUS_DEFERRED,
            INTENT_STATUS_READY,
        },
        experience::{
            ExperienceEpisode, ExperienceEpisodeRepository, EPISODE_KIND, EPISODE_VERSION,
            OUTCOME_KIND, SOURCE_KIND,
        },
        life_intent::{LifeGoalCreateRequest, LifeIntentRepository},
        perception::{
            LifePerceptionPolicyCreateRequest, LifePerceptionPolicyUpdateOutcome,
            LifePerceptionPolicyUpdateRequest, PerceptionError,
        },
        storage::{
            open_authorized_test_connection, LifeIdentityRecord, PersonaTemplateRecord,
            StorageService, DATABASE_FILE_NAME,
        },
    };

    const LIFE_ID: &str = "trusted-autonomy-life";
    const PERSONA_ID: &str = "trusted-autonomy-persona";
    const GOAL_ID: &str = "trusted-autonomy-goal";

    struct Fixture {
        _root: TempDir,
        database_path: PathBuf,
        storage: StorageService,
    }

    impl Fixture {
        fn new() -> Self {
            let root = tempfile::tempdir().unwrap();
            let database_root = root.path().join("default");
            std::fs::create_dir_all(&database_root).unwrap();
            let database_path = database_root.join(DATABASE_FILE_NAME);
            let storage = StorageService::initialize_with_roots(database_root, None).unwrap();
            storage
                .save_persona(PersonaTemplateRecord {
                    id: PERSONA_ID.into(),
                    name: "Trusted Autonomy Persona".into(),
                    version: 1,
                    persona_json: "{}".into(),
                })
                .unwrap();
            storage
                .save_life(LifeIdentityRecord {
                    id: LIFE_ID.into(),
                    name: "Trusted Autonomy Life".into(),
                    created_at: "2026-08-27T00:00:00.000Z".into(),
                    version: 1,
                    body_id: "trusted-autonomy-body".into(),
                    persona_id: PERSONA_ID.into(),
                    persona_version: 1,
                })
                .unwrap();
            Self {
                _root: root,
                database_path,
                storage,
            }
        }

        fn create_goal(&self) {
            LifeIntentRepository::create_goal(
                &self.storage,
                LifeGoalCreateRequest {
                    goal_id: GOAL_ID.into(),
                    life_id: LIFE_ID.into(),
                    title: "Trusted autonomy goal".into(),
                    objective: "Exercise the trusted autonomy composition".into(),
                },
            )
            .unwrap();
        }

        fn create_autonomy_policy(&self, enabled: bool, dnd: bool, max_ready: i64) {
            let outcome = AutonomyRepository::create_policy(
                &self.storage,
                LifeAutonomyPolicyCreateRequest {
                    life_id: LIFE_ID.into(),
                    enabled,
                    dnd,
                    max_ready_per_window: max_ready,
                    window_seconds: 900,
                    min_gap_seconds: 60,
                },
            )
            .unwrap();
            assert!(matches!(
                outcome,
                AutonomyCreateOutcome::Applied(_) | AutonomyCreateOutcome::Replayed(_)
            ));
        }

        fn create_perception_policy(&self, enabled: bool) {
            let outcome = PerceptionRepository::create_policy(
                &self.storage,
                LifePerceptionPolicyCreateRequest {
                    life_id: LIFE_ID.into(),
                    focus_context_enabled: enabled,
                },
            )
            .unwrap();
            assert!(matches!(
                outcome,
                crate::perception::PerceptionCreateOutcome::Applied(_)
                    | crate::perception::PerceptionCreateOutcome::Replayed(_)
            ));
        }

        fn revoke_perception_policy(&self) {
            let outcome = PerceptionRepository::update_policy(
                &self.storage,
                LifePerceptionPolicyUpdateRequest {
                    event_id: "trusted-autonomy-perception-revocation".into(),
                    life_id: LIFE_ID.into(),
                    focus_context_enabled: false,
                    expected_revision: 1,
                },
            )
            .unwrap();
            assert!(matches!(
                outcome,
                LifePerceptionPolicyUpdateOutcome::Applied { .. }
            ));
        }

        fn intent(&self, tick_id: &str) -> LifeProactiveIntent {
            let intent_id = deterministic_intent_id(LIFE_ID, tick_id);
            AutonomyRepository::find_intent(&self.storage, LIFE_ID, &intent_id)
                .unwrap()
                .unwrap()
        }

        fn intent_count(&self) -> i64 {
            let connection = open_authorized_test_connection(&self.database_path).unwrap();
            connection
                .query_row("SELECT COUNT(*) FROM life_proactive_intent", [], |row| {
                    row.get(0)
                })
                .unwrap()
        }

        fn intent_event_count(&self) -> i64 {
            let connection = open_authorized_test_connection(&self.database_path).unwrap();
            connection
                .query_row(
                    "SELECT COUNT(*) FROM life_proactive_intent_event",
                    [],
                    |row| row.get(0),
                )
                .unwrap()
        }

        fn intent_event(&self, tick_id: &str) -> crate::autonomy::LifeProactiveIntentEvent {
            let intent = self.intent(tick_id);
            let event_id =
                super::super::runtime::deterministic_evaluation_event_id(&intent.intent_id);
            AutonomyRepository::find_intent_event(&self.storage, LIFE_ID, &event_id)
                .unwrap()
                .unwrap()
        }

        fn perception_tables(&self) -> Vec<String> {
            let connection = open_authorized_test_connection(&self.database_path).unwrap();
            let mut statement = connection
                .prepare(
                    "SELECT name FROM sqlite_schema
                     WHERE type='table' AND name LIKE 'life_perception_%'
                     ORDER BY name",
                )
                .unwrap();
            statement
                .query_map([], |row| row.get(0))
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap()
        }

        fn insert_old_episode(&self) {
            self.insert_episode_with_age(121);
        }

        fn insert_episode_with_age(&self, age_seconds: i64) {
            let suffix = format!("{}-{}", self.database_path.display(), age_seconds);
            let conversation_id = format!("trusted-autonomy-conversation-{suffix}");
            let turn_id = format!("trusted-autonomy-turn-{suffix}");
            let user_message_id = format!("trusted-autonomy-user-{suffix}");
            let assistant_message_id = format!("trusted-autonomy-assistant-{suffix}");
            let episode_id =
                format!("experience-conversation:{LIFE_ID}:{conversation_id}:{turn_id}");
            let source_ref = format!("{conversation_id}:{turn_id}");
            let connection = open_authorized_test_connection(&self.database_path).unwrap();
            let now: String = connection
                .query_row("SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now')", [], |row| {
                    row.get(0)
                })
                .unwrap();
            let ended_at: String = connection
                .query_row(
                    "SELECT strftime('%Y-%m-%dT%H:%M:%fZ', ?1, ?2)",
                    params![now, format!("-{age_seconds} seconds")],
                    |row| row.get(0),
                )
                .unwrap();
            let started_at: String = connection
                .query_row(
                    "SELECT strftime('%Y-%m-%dT%H:%M:%fZ', ?1, '-1 seconds')",
                    [&ended_at],
                    |row| row.get(0),
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO conversation
                         (id, life_id, title, revision, created_at, updated_at, last_message_at)
                     VALUES (?1, ?2, ?3, 1, ?4, ?4, ?4)",
                    params![
                        conversation_id,
                        LIFE_ID,
                        "Trusted Autonomy Episode",
                        &started_at
                    ],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO conversation_message
                         (id, conversation_id, life_id, turn_id, role, content, sequence_no, created_at)
                     VALUES (?1, ?2, ?3, ?4, 'user', 'test user', 1, ?5),
                            (?6, ?2, ?3, ?4, 'assistant', 'test assistant', 2, ?7)",
                    params![
                        user_message_id,
                        conversation_id,
                        LIFE_ID,
                        turn_id,
                        &started_at,
                        assistant_message_id,
                        &ended_at,
                    ],
                )
                .unwrap();
            drop(connection);
            ExperienceEpisodeRepository::commit_episode(
                &self.storage,
                ExperienceEpisode {
                    episode_id,
                    life_id: LIFE_ID.into(),
                    episode_kind: EPISODE_KIND.into(),
                    source_kind: SOURCE_KIND.into(),
                    source_ref,
                    conversation_id,
                    turn_id,
                    counterpart_subject_id: "primary_user".into(),
                    user_message_id,
                    assistant_message_id,
                    outcome_kind: OUTCOME_KIND.into(),
                    started_at,
                    ended_at: ended_at.clone(),
                    episode_version: EPISODE_VERSION,
                    created_at: ended_at,
                },
            )
            .unwrap();
        }

        fn create_pending_tick_intent(&self, tick_id: &str) -> LifeProactiveIntent {
            let intent_id = deterministic_intent_id(LIFE_ID, tick_id);
            match AutonomyRepository::create_pending_goal_check_in_intent(
                &self.storage,
                LifeProactiveIntentCreateRequest {
                    intent_id,
                    life_id: LIFE_ID.into(),
                    goal_id: GOAL_ID.into(),
                    intent_kind: INTENT_KIND_GOAL_CHECK_IN.into(),
                    importance: super::super::runtime::GOAL_CHECK_IN_IMPORTANCE_V1,
                    user_relevance: super::super::runtime::GOAL_CHECK_IN_USER_RELEVANCE_V1,
                    self_desire: super::super::runtime::GOAL_CHECK_IN_SELF_DESIRE_V1,
                    interruption_cost: super::super::runtime::GOAL_CHECK_IN_INTERRUPTION_COST_V1,
                    focus_state: INTENT_FOCUS_STATE_AVAILABLE.into(),
                    acceptance_score: None,
                    recent_interaction_seconds: Some(121),
                    expires_at: None,
                },
            )
            .unwrap()
            {
                AutonomyCreateOutcome::Applied(intent) => intent,
                AutonomyCreateOutcome::Replayed(_) => panic!("pending intent must be new"),
            }
        }
    }

    struct FakeFocusSource {
        calls: Arc<AtomicUsize>,
        result: Result<FocusObservationOutcome, PerceptionError>,
        panic_if_called: bool,
    }

    impl FakeFocusSource {
        fn returning(result: FocusObservationOutcome) -> Self {
            Self {
                calls: Arc::new(AtomicUsize::new(0)),
                result: Ok(result),
                panic_if_called: false,
            }
        }

        fn failing() -> Self {
            Self {
                calls: Arc::new(AtomicUsize::new(0)),
                result: Err(PerceptionError::database()),
                panic_if_called: false,
            }
        }

        fn rejecting() -> Self {
            Self {
                calls: Arc::new(AtomicUsize::new(0)),
                result: Ok(FocusObservationOutcome::Observed(
                    PerceptionFocusState::Unknown,
                )),
                panic_if_called: true,
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl TrustedFocusSource for FakeFocusSource {
        fn observe(
            &self,
            _repository: &dyn PerceptionRepository,
            _life_id: &str,
        ) -> Result<FocusObservationOutcome, PerceptionError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            assert!(
                !self.panic_if_called,
                "trusted focus source must not be called"
            );
            self.result.clone()
        }
    }

    struct CountingB2FocusSource {
        calls: Arc<AtomicUsize>,
    }

    impl CountingB2FocusSource {
        fn new() -> Self {
            Self {
                calls: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl TrustedFocusSource for CountingB2FocusSource {
        fn observe(
            &self,
            repository: &dyn PerceptionRepository,
            life_id: &str,
        ) -> Result<FocusObservationOutcome, PerceptionError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            B2TrustedFocusSource.observe(repository, life_id)
        }
    }

    fn request(tick_id: &str) -> TrustedAutonomyTickRequest {
        TrustedAutonomyTickRequest {
            tick_id: tick_id.into(),
            life_id: LIFE_ID.into(),
        }
    }

    fn run_with_source(
        fixture: &Fixture,
        tick_id: &str,
        source: &dyn TrustedFocusSource,
    ) -> Result<AutonomyTickOutcome, TrustedAutonomyTickError> {
        run_trusted_autonomy_tick_with_source(&fixture.storage, request(tick_id), source)
    }

    #[test]
    fn production_raw_d15_focus_input_is_test_only_and_trusted_request_is_identity_only() {
        let runtime_source = include_str!("runtime.rs");
        let production_source = runtime_source
            .split_once("#[cfg(test)]")
            .map_or(runtime_source, |(production, _)| production);
        assert!(!production_source.contains("pub(crate) struct AutonomyTickRequest"));
        assert!(runtime_source.contains("pub(super) struct AutonomyTickRequest"));
        assert!(!production_source.contains("pub(crate) fn run_autonomy_tick"));
        assert!(runtime_source.contains("pub(super) fn run_autonomy_tick"));

        let trusted_source = include_str!("trusted_runtime.rs");
        let request_source = trusted_source
            .split_once("pub struct TrustedAutonomyTickRequest {")
            .and_then(|(_, remainder)| remainder.split_once('}'))
            .map(|(request, _)| request)
            .expect("trusted request declaration must be present");
        assert!(request_source.contains("tick_id"));
        assert!(request_source.contains("life_id"));
        assert!(!request_source.contains("focus_state"));
        assert!(!request_source.contains("PID"));
        assert!(!request_source.contains("HWND"));
    }

    #[test]
    fn invalid_trusted_identity_reuses_d15_validation_without_observation() {
        let fixture = Fixture::new();
        let source = FakeFocusSource::rejecting();

        let error = run_with_source(&fixture, &"界".repeat(129), &source).unwrap_err();

        assert!(matches!(
            error,
            TrustedAutonomyTickError::Autonomy(AutonomyTickError::InvalidArgument { .. })
        ));
        assert_eq!(source.calls(), 0);
    }

    #[test]
    fn no_autonomy_policy_returns_disabled_without_observation() {
        let fixture = Fixture::new();
        let source = FakeFocusSource::rejecting();

        let outcome = run_with_source(&fixture, "no-policy", &source).unwrap();

        assert_eq!(outcome, AutonomyTickOutcome::Disabled);
        assert_eq!(source.calls(), 0);
    }

    #[test]
    fn disabled_autonomy_policy_returns_disabled_without_observation() {
        let fixture = Fixture::new();
        fixture.create_autonomy_policy(false, false, 3);
        let source = FakeFocusSource::rejecting();

        let outcome = run_with_source(&fixture, "disabled-policy", &source).unwrap();

        assert_eq!(outcome, AutonomyTickOutcome::Disabled);
        assert_eq!(source.calls(), 0);
    }

    #[test]
    fn dnd_uses_d15_dnd_evidence_without_observation_or_ready() {
        let fixture = Fixture::new();
        fixture.create_goal();
        fixture.create_autonomy_policy(true, true, 3);
        let source = FakeFocusSource::rejecting();

        let outcome = run_with_source(&fixture, "dnd", &source).unwrap();

        assert_eq!(source.calls(), 0);
        assert!(matches!(outcome, AutonomyTickOutcome::Applied { .. }));
        let intent = fixture.intent("dnd");
        assert_eq!(intent.focus_state, INTENT_FOCUS_STATE_DND);
        assert_ne!(intent.status, INTENT_STATUS_READY);
    }

    #[test]
    fn zero_ready_budget_uses_d15_no_ready_budget_without_observation() {
        let fixture = Fixture::new();
        fixture.create_goal();
        fixture.create_autonomy_policy(true, false, 0);
        let source = FakeFocusSource::rejecting();

        let outcome = run_with_source(&fixture, "zero-budget", &source).unwrap();

        assert_eq!(outcome, AutonomyTickOutcome::NoReadyBudget);
        assert_eq!(source.calls(), 0);
        assert_eq!(fixture.intent_count(), 0);
    }

    #[test]
    fn perception_disabled_maps_to_unknown_without_disabling_autonomy() {
        let fixture = Fixture::new();
        fixture.create_goal();
        fixture.create_autonomy_policy(true, false, 3);
        let source = FakeFocusSource::returning(FocusObservationOutcome::Disabled);

        let outcome = run_with_source(&fixture, "perception-disabled", &source).unwrap();

        assert_eq!(source.calls(), 1);
        assert!(matches!(outcome, AutonomyTickOutcome::Applied { .. }));
        let intent = fixture.intent("perception-disabled");
        assert_eq!(intent.focus_state, INTENT_FOCUS_STATE_UNKNOWN);
        assert_eq!(intent.status, INTENT_STATUS_DEFERRED);
    }

    #[test]
    fn available_focus_is_persisted_and_can_be_ready_after_one_observation() {
        let fixture = Fixture::new();
        fixture.create_goal();
        fixture.create_autonomy_policy(true, false, 3);
        fixture.insert_old_episode();
        let source = FakeFocusSource::returning(FocusObservationOutcome::Observed(
            PerceptionFocusState::Available,
        ));

        let outcome = run_with_source(&fixture, "available", &source).unwrap();

        assert_eq!(source.calls(), 1);
        assert!(matches!(outcome, AutonomyTickOutcome::Applied { .. }));
        let intent = fixture.intent("available");
        assert_eq!(intent.focus_state, INTENT_FOCUS_STATE_AVAILABLE);
        assert_eq!(intent.status, INTENT_STATUS_READY);
    }

    #[test]
    fn focused_and_unknown_focus_are_persisted_and_deferred() {
        for (tick_id, focus) in [
            (
                "focused",
                FocusObservationOutcome::Observed(PerceptionFocusState::Focused),
            ),
            (
                "unknown",
                FocusObservationOutcome::Observed(PerceptionFocusState::Unknown),
            ),
        ] {
            let fixture = Fixture::new();
            fixture.create_goal();
            fixture.create_autonomy_policy(true, false, 3);
            fixture.insert_old_episode();
            let source = FakeFocusSource::returning(focus);

            let outcome = run_with_source(&fixture, tick_id, &source).unwrap();

            assert_eq!(source.calls(), 1);
            assert!(matches!(outcome, AutonomyTickOutcome::Applied { .. }));
            let intent = fixture.intent(tick_id);
            assert_eq!(intent.status, INTENT_STATUS_DEFERRED);
            assert_eq!(
                intent.focus_state,
                if tick_id == "focused" {
                    INTENT_FOCUS_STATE_FOCUSED
                } else {
                    INTENT_FOCUS_STATE_UNKNOWN
                }
            );
        }
    }

    #[test]
    fn perception_error_fails_closed_without_d15_persistence() {
        let fixture = Fixture::new();
        fixture.create_goal();
        fixture.create_autonomy_policy(true, false, 3);
        let source = FakeFocusSource::failing();

        let error = run_with_source(&fixture, "perception-error", &source).unwrap_err();

        assert_eq!(
            error,
            TrustedAutonomyTickError::Perception(PerceptionError::database())
        );
        assert_eq!(source.calls(), 1);
        assert_eq!(fixture.intent_count(), 0);
        assert_eq!(fixture.intent_event_count(), 0);
    }

    #[test]
    fn exact_tick_replay_precedes_perception_and_reuses_persisted_evidence() {
        let fixture = Fixture::new();
        fixture.create_goal();
        fixture.create_autonomy_policy(true, false, 3);
        fixture.insert_old_episode();
        let first_source = FakeFocusSource::returning(FocusObservationOutcome::Observed(
            PerceptionFocusState::Available,
        ));

        let first = run_with_source(&fixture, "exact-replay", &first_source).unwrap();
        let original_intent = fixture.intent("exact-replay");
        let original_event = fixture.intent_event("exact-replay");
        let retry_source = FakeFocusSource::rejecting();
        let replay = run_with_source(&fixture, "exact-replay", &retry_source).unwrap();

        assert_eq!(first_source.calls(), 1);
        assert_eq!(retry_source.calls(), 0);
        assert!(matches!(first, AutonomyTickOutcome::Applied { .. }));
        assert!(matches!(replay, AutonomyTickOutcome::Replayed { .. }));
        assert_eq!(fixture.intent("exact-replay"), original_intent);
        assert_eq!(fixture.intent_event("exact-replay"), original_event);
        assert_eq!(fixture.intent_count(), 1);
        assert_eq!(fixture.intent_event_count(), 1);
    }

    #[test]
    fn exact_tick_replay_survives_perception_revocation_without_observation() {
        let fixture = Fixture::new();
        fixture.create_goal();
        fixture.create_autonomy_policy(true, false, 3);
        fixture.create_perception_policy(true);
        fixture.insert_old_episode();
        let first_source = CountingB2FocusSource::new();

        run_with_source(&fixture, "revoked-replay", &first_source).unwrap();
        let original_intent = fixture.intent("revoked-replay");
        let original_event = fixture.intent_event("revoked-replay");
        fixture.revoke_perception_policy();
        let retry_source = FakeFocusSource::rejecting();

        let replay = run_with_source(&fixture, "revoked-replay", &retry_source).unwrap();

        assert_eq!(first_source.calls(), 1);
        assert_eq!(retry_source.calls(), 0);
        assert!(matches!(replay, AutonomyTickOutcome::Replayed { .. }));
        assert_eq!(fixture.intent("revoked-replay"), original_intent);
        assert_eq!(fixture.intent_event("revoked-replay"), original_event);
    }

    #[test]
    fn current_tick_pending_recovery_uses_persisted_focus_without_observation() {
        let fixture = Fixture::new();
        fixture.create_goal();
        fixture.create_autonomy_policy(true, false, 3);
        let pending = fixture.create_pending_tick_intent("pending-recovery");
        let source = FakeFocusSource::rejecting();

        let outcome = run_with_source(&fixture, "pending-recovery", &source).unwrap();

        assert_eq!(source.calls(), 0);
        assert!(matches!(outcome, AutonomyTickOutcome::Applied { .. }));
        let current = fixture.intent("pending-recovery");
        assert_eq!(current.intent_id, pending.intent_id);
        assert_eq!(current.focus_state, INTENT_FOCUS_STATE_AVAILABLE);
        assert_eq!(fixture.intent_count(), 1);
        assert_eq!(fixture.intent_event_count(), 1);
    }

    #[test]
    fn fresh_tick_reobserves_instead_of_caching_previous_focus() {
        let fixture = Fixture::new();
        fixture.create_goal();
        fixture.create_autonomy_policy(true, false, 3);
        fixture.insert_old_episode();
        let source = FakeFocusSource::returning(FocusObservationOutcome::Observed(
            PerceptionFocusState::Available,
        ));

        let first = run_with_source(&fixture, "fresh-first", &source).unwrap();
        let second = run_with_source(&fixture, "fresh-second", &source).unwrap();

        assert!(matches!(first, AutonomyTickOutcome::Applied { .. }));
        assert!(matches!(
            second,
            AutonomyTickOutcome::Waiting {
                reason: AutonomyTickWaitReason::ReadyPendingDelivery,
                ..
            }
        ));
        assert_eq!(source.calls(), 2);
    }

    #[test]
    fn production_b2_entrypoint_uses_real_storage_and_unknown_without_consent() {
        let fixture = Fixture::new();
        fixture.create_goal();
        fixture.create_autonomy_policy(true, false, 3);
        fixture.insert_old_episode();

        let outcome =
            run_trusted_autonomy_tick(&fixture.storage, request("production-b2")).unwrap();

        assert!(matches!(outcome, AutonomyTickOutcome::Applied { .. }));
        let intent = fixture.intent("production-b2");
        assert_eq!(intent.focus_state, INTENT_FOCUS_STATE_UNKNOWN);
        assert_ne!(intent.status, INTENT_STATUS_READY);
    }

    #[test]
    fn trusted_tick_does_not_add_focus_observation_persistence() {
        let fixture = Fixture::new();
        fixture.create_goal();
        fixture.create_autonomy_policy(true, false, 3);
        let before = fixture.perception_tables();
        let source = FakeFocusSource::returning(FocusObservationOutcome::Observed(
            PerceptionFocusState::Unknown,
        ));

        run_with_source(&fixture, "no-observation-history", &source).unwrap();

        let after = fixture.perception_tables();
        assert_eq!(before, after);
        assert_eq!(
            after,
            vec![
                "life_perception_policy".to_string(),
                "life_perception_policy_event".to_string(),
            ]
        );
        assert_eq!(
            fixture.intent("no-observation-history").focus_state,
            INTENT_FOCUS_STATE_UNKNOWN
        );
    }

    #[test]
    fn trusted_focus_mapping_is_bounded_to_d15_states() {
        assert_eq!(
            map_focus_observation(FocusObservationOutcome::Disabled),
            INTENT_FOCUS_STATE_UNKNOWN
        );
        assert_eq!(
            map_focus_observation(FocusObservationOutcome::Observed(
                PerceptionFocusState::Available,
            )),
            INTENT_FOCUS_STATE_AVAILABLE
        );
        assert_eq!(
            map_focus_observation(FocusObservationOutcome::Observed(
                PerceptionFocusState::Focused,
            )),
            INTENT_FOCUS_STATE_FOCUSED
        );
        assert_eq!(
            map_focus_observation(FocusObservationOutcome::Observed(
                PerceptionFocusState::Unknown,
            )),
            INTENT_FOCUS_STATE_UNKNOWN
        );
        assert_ne!(
            map_focus_observation(FocusObservationOutcome::Disabled),
            INTENT_FOCUS_STATE_DND
        );
    }
}
