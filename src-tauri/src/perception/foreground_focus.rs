//! Privacy-minimized foreground-focus observation for D16-B2.
//!
//! The consent gate is evaluated for every request through the frozen D16-B1
//! repository boundary.  An enabled request performs one synchronous,
//! in-memory observation and returns only a bounded focus state.

#[cfg(windows)]
use windows_sys::Win32::UI::WindowsAndMessaging::{GetForegroundWindow, GetWindowThreadProcessId};

use super::{PerceptionError, PerceptionRepository};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PerceptionFocusState {
    Available,
    Focused,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FocusObservationOutcome {
    Disabled,
    Observed(PerceptionFocusState),
}

trait ForegroundFocusObserver: Send + Sync {
    fn observe(&self) -> PerceptionFocusState;
}

#[derive(Clone, Copy, Debug, Default)]
struct WindowsForegroundFocusObserver;

pub(crate) fn observe_foreground_focus(
    repository: &dyn PerceptionRepository,
    life_id: &str,
) -> Result<FocusObservationOutcome, PerceptionError> {
    let observer = WindowsForegroundFocusObserver;
    observe_foreground_focus_with_observer(repository, life_id, &observer)
}

fn observe_foreground_focus_with_observer(
    repository: &dyn PerceptionRepository,
    life_id: &str,
    observer: &dyn ForegroundFocusObserver,
) -> Result<FocusObservationOutcome, PerceptionError> {
    let policy = repository.find_policy(life_id)?;
    if !policy
        .as_ref()
        .is_some_and(|policy| policy.is_focus_context_enabled())
    {
        return Ok(FocusObservationOutcome::Disabled);
    }

    Ok(FocusObservationOutcome::Observed(observer.observe()))
}

fn map_foreground_ownership(
    foreground_window_present: bool,
    foreground_pid: u32,
    current_pid: u32,
) -> PerceptionFocusState {
    if !foreground_window_present || foreground_pid == 0 {
        PerceptionFocusState::Unknown
    } else if foreground_pid == current_pid {
        PerceptionFocusState::Available
    } else {
        PerceptionFocusState::Focused
    }
}

impl ForegroundFocusObserver for WindowsForegroundFocusObserver {
    fn observe(&self) -> PerceptionFocusState {
        #[cfg(windows)]
        {
            let foreground_hwnd = unsafe { GetForegroundWindow() };
            if foreground_hwnd.is_null() {
                return PerceptionFocusState::Unknown;
            }

            let mut foreground_pid = 0_u32;
            let _ = unsafe { GetWindowThreadProcessId(foreground_hwnd, &mut foreground_pid) };
            map_foreground_ownership(true, foreground_pid, std::process::id())
        }

        #[cfg(not(windows))]
        {
            PerceptionFocusState::Unknown
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    use rusqlite::Connection;
    use tempfile::TempDir;

    use super::{
        map_foreground_ownership, observe_foreground_focus, observe_foreground_focus_with_observer,
        FocusObservationOutcome, ForegroundFocusObserver, PerceptionFocusState,
    };
    use crate::{
        perception::{
            LifePerceptionPolicy, LifePerceptionPolicyCreateRequest, LifePerceptionPolicyEvent,
            LifePerceptionPolicyUpdateOutcome, LifePerceptionPolicyUpdateRequest,
            PerceptionCreateOutcome, PerceptionError, PerceptionErrorCode, PerceptionRepository,
        },
        storage::{
            open_authorized_test_connection, LifeIdentityRecord, PersonaTemplateRecord,
            StorageService, DATABASE_FILE_NAME,
        },
    };

    const LIFE_ID: &str = "foreground-focus-life";

    struct CountingObserver {
        calls: Arc<AtomicUsize>,
        result: PerceptionFocusState,
        panic_if_called: bool,
    }

    impl CountingObserver {
        fn returning(result: PerceptionFocusState) -> Self {
            Self {
                calls: Arc::new(AtomicUsize::new(0)),
                result,
                panic_if_called: false,
            }
        }

        fn rejecting() -> Self {
            Self {
                calls: Arc::new(AtomicUsize::new(0)),
                result: PerceptionFocusState::Unknown,
                panic_if_called: true,
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl ForegroundFocusObserver for CountingObserver {
        fn observe(&self) -> PerceptionFocusState {
            self.calls.fetch_add(1, Ordering::SeqCst);
            assert!(!self.panic_if_called, "observer must not be called");
            self.result
        }
    }

    struct StorageFixture {
        root: TempDir,
        storage: StorageService,
    }

    impl StorageFixture {
        fn new() -> Self {
            let root = tempfile::tempdir().unwrap();
            let storage =
                StorageService::initialize_with_roots(root.path().to_path_buf(), None).unwrap();
            storage
                .save_persona(PersonaTemplateRecord {
                    id: "foreground-focus-persona".into(),
                    name: "Foreground Focus Persona".into(),
                    version: 1,
                    persona_json: "{}".into(),
                })
                .unwrap();
            storage
                .save_life(LifeIdentityRecord {
                    id: LIFE_ID.into(),
                    name: "Foreground Focus Life".into(),
                    created_at: "2026-08-27T00:00:00.000Z".into(),
                    version: 1,
                    body_id: "foreground-focus-body".into(),
                    persona_id: "foreground-focus-persona".into(),
                    persona_version: 1,
                })
                .unwrap();
            Self { root, storage }
        }

        fn create_policy(&self, enabled: bool) {
            let outcome = self
                .storage
                .create_policy(LifePerceptionPolicyCreateRequest {
                    life_id: LIFE_ID.into(),
                    focus_context_enabled: enabled,
                })
                .unwrap();
            assert!(matches!(
                outcome,
                PerceptionCreateOutcome::Applied(_) | PerceptionCreateOutcome::Replayed(_)
            ));
        }

        fn connection(&self) -> Connection {
            open_authorized_test_connection(&self.root.path().join(DATABASE_FILE_NAME)).unwrap()
        }
    }

    struct FailingRepository;

    impl PerceptionRepository for FailingRepository {
        fn create_policy(
            &self,
            _request: LifePerceptionPolicyCreateRequest,
        ) -> Result<PerceptionCreateOutcome<LifePerceptionPolicy>, PerceptionError> {
            panic!("the observation path must not create a policy")
        }

        fn find_policy(
            &self,
            _life_id: &str,
        ) -> Result<Option<LifePerceptionPolicy>, PerceptionError> {
            Err(PerceptionError::database())
        }

        fn update_policy(
            &self,
            _request: LifePerceptionPolicyUpdateRequest,
        ) -> Result<LifePerceptionPolicyUpdateOutcome, PerceptionError> {
            panic!("the observation path must not update a policy")
        }

        fn find_policy_event(
            &self,
            _life_id: &str,
            _event_id: &str,
        ) -> Result<Option<LifePerceptionPolicyEvent>, PerceptionError> {
            panic!("the observation path must not read policy events")
        }
    }

    fn perception_persistence_snapshot(fixture: &StorageFixture) -> (Vec<String>, i64, i64) {
        let connection = fixture.connection();
        let tables = connection
            .prepare(
                "SELECT name FROM sqlite_schema
                 WHERE type='table' AND name LIKE 'life_perception_%'
                 ORDER BY name",
            )
            .unwrap()
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let revision: i64 = connection
            .query_row(
                "SELECT revision FROM life_perception_policy WHERE life_id=?1",
                [LIFE_ID],
                |row| row.get(0),
            )
            .unwrap();
        let event_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM life_perception_policy_event WHERE life_id=?1",
                [LIFE_ID],
                |row| row.get(0),
            )
            .unwrap();
        (tables, revision, event_count)
    }

    #[test]
    fn no_policy_disables_observation_before_the_observer() {
        let fixture = StorageFixture::new();
        let observer = CountingObserver::rejecting();

        let outcome =
            observe_foreground_focus_with_observer(&fixture.storage, LIFE_ID, &observer).unwrap();

        assert_eq!(outcome, FocusObservationOutcome::Disabled);
        assert_eq!(observer.calls(), 0);
    }

    #[test]
    fn disabled_policy_disables_observation_before_the_observer() {
        let fixture = StorageFixture::new();
        fixture.create_policy(false);
        let observer = CountingObserver::rejecting();

        let outcome =
            observe_foreground_focus_with_observer(&fixture.storage, LIFE_ID, &observer).unwrap();

        assert_eq!(outcome, FocusObservationOutcome::Disabled);
        assert_eq!(observer.calls(), 0);
    }

    #[test]
    fn enabled_policy_preserves_each_bounded_focus_state_and_observes_once() {
        let fixture = StorageFixture::new();
        fixture.create_policy(true);

        for expected in [
            PerceptionFocusState::Available,
            PerceptionFocusState::Focused,
            PerceptionFocusState::Unknown,
        ] {
            let observer = CountingObserver::returning(expected);
            let outcome =
                observe_foreground_focus_with_observer(&fixture.storage, LIFE_ID, &observer)
                    .unwrap();
            assert_eq!(outcome, FocusObservationOutcome::Observed(expected));
            assert_eq!(observer.calls(), 1);
        }
    }

    #[test]
    fn revocation_is_seen_on_the_next_request_without_consent_caching() {
        let fixture = StorageFixture::new();
        fixture.create_policy(true);
        let observer = CountingObserver::returning(PerceptionFocusState::Available);

        assert_eq!(
            observe_foreground_focus_with_observer(&fixture.storage, LIFE_ID, &observer).unwrap(),
            FocusObservationOutcome::Observed(PerceptionFocusState::Available)
        );
        assert_eq!(observer.calls(), 1);

        let update = fixture
            .storage
            .update_policy(LifePerceptionPolicyUpdateRequest {
                event_id: "foreground-focus-revocation".into(),
                life_id: LIFE_ID.into(),
                focus_context_enabled: false,
                expected_revision: 1,
            })
            .unwrap();
        assert!(matches!(
            update,
            LifePerceptionPolicyUpdateOutcome::Applied { .. }
        ));

        assert_eq!(
            observe_foreground_focus_with_observer(&fixture.storage, LIFE_ID, &observer).unwrap(),
            FocusObservationOutcome::Disabled
        );
        assert_eq!(observer.calls(), 1);
    }

    #[test]
    fn policy_read_failure_is_bounded_and_blocks_the_observer() {
        let observer = CountingObserver::rejecting();
        let error = observe_foreground_focus_with_observer(&FailingRepository, LIFE_ID, &observer)
            .unwrap_err();

        assert_eq!(error.code, PerceptionErrorCode::DatabaseUnavailable);
        assert_eq!(observer.calls(), 0);
    }

    #[test]
    fn foreground_ownership_mapping_is_conservative_and_bounded() {
        assert_eq!(
            map_foreground_ownership(false, 42, 42),
            PerceptionFocusState::Unknown
        );
        assert_eq!(
            map_foreground_ownership(true, 0, 42),
            PerceptionFocusState::Unknown
        );
        assert_eq!(
            map_foreground_ownership(true, 42, 42),
            PerceptionFocusState::Available
        );
        assert_eq!(
            map_foreground_ownership(true, 43, 42),
            PerceptionFocusState::Focused
        );
    }

    #[test]
    fn enabled_observation_does_not_persist_state_or_create_observation_history() {
        let fixture = StorageFixture::new();
        fixture.create_policy(true);
        let before = perception_persistence_snapshot(&fixture);

        for _ in 0..3 {
            let observer = CountingObserver::returning(PerceptionFocusState::Unknown);
            assert_eq!(
                observe_foreground_focus_with_observer(&fixture.storage, LIFE_ID, &observer)
                    .unwrap(),
                FocusObservationOutcome::Observed(PerceptionFocusState::Unknown)
            );
            assert_eq!(observer.calls(), 1);
        }

        let after = perception_persistence_snapshot(&fixture);
        assert_eq!(before, after);
        assert_eq!(
            after.0,
            vec![
                "life_perception_policy".to_string(),
                "life_perception_policy_event".to_string()
            ]
        );
        assert_eq!(after.1, 1);
        assert_eq!(after.2, 0);
    }

    #[test]
    fn production_foreground_focus_source_has_no_forbidden_observer_apis() {
        let source = include_str!("foreground_focus.rs");
        let forbidden_apis = [
            format!("GetWindow{}", "Text"),
            format!("GetClass{}", "Name"),
            format!("Open{}", "Process"),
            format!("QueryFullProcess{}", "ImageName"),
            format!("Print{}", "Window"),
            format!("{}{}", "Bit", "Blt"),
            format!("{}{}", "clip", "board"),
            format!("{}{}", "screen", "shot"),
            format!("{}{}", "O", "CR"),
        ];
        for forbidden_api in forbidden_apis {
            assert!(
                !source.contains(forbidden_api.as_str()),
                "forbidden observer API appeared in the provider source"
            );
        }
    }

    #[test]
    fn raw_foreground_observer_is_not_crate_public_or_reexported() {
        let source = include_str!("foreground_focus.rs");
        let production_source = source
            .split_once("#[cfg(test)]")
            .map_or(source, |(production, _)| production);
        assert!(!production_source.contains("pub(crate) trait ForegroundFocusObserver"));
        assert!(!production_source.contains("pub(crate) struct WindowsForegroundFocusObserver"));

        let perception_module = include_str!("mod.rs");
        assert!(!perception_module.contains("pub use WindowsForegroundFocusObserver"));
        assert!(!perception_module.contains("pub(crate) use WindowsForegroundFocusObserver"));
    }

    #[cfg(windows)]
    #[test]
    fn windows_production_observation_smoke_is_one_bounded_call() {
        let fixture = StorageFixture::new();
        fixture.create_policy(true);

        let outcome = observe_foreground_focus(&fixture.storage, LIFE_ID).unwrap();
        assert!(matches!(
            outcome,
            FocusObservationOutcome::Observed(
                PerceptionFocusState::Available
                    | PerceptionFocusState::Focused
                    | PerceptionFocusState::Unknown
            )
        ));
    }

    #[cfg(not(windows))]
    #[test]
    fn unsupported_production_observation_is_unknown_after_consent() {
        let fixture = StorageFixture::new();
        fixture.create_policy(true);

        assert_eq!(
            observe_foreground_focus(&fixture.storage, LIFE_ID).unwrap(),
            FocusObservationOutcome::Observed(PerceptionFocusState::Unknown)
        );
        let observer = super::WindowsForegroundFocusObserver;
        assert_eq!(observer.observe(), PerceptionFocusState::Unknown);
    }
}
