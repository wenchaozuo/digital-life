//! Process-local bounded semantic result authority for D27.
//!
//! This broker is the only bridge from a successfully settled D26 Vision
//! response to a later Chat handoff.  It stores parsed semantic text only;
//! pixels, encoded images, provider material, and response envelopes never
//! cross this boundary.

use std::{
    sync::Mutex,
    time::{Duration, Instant},
};

#[cfg(test)]
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

pub(crate) const SCREEN_VISION_SEMANTIC_RESULT_TTL: Duration = Duration::from_secs(5 * 60);
pub(crate) const MAX_SEMANTIC_SUMMARY_CHARACTERS: usize = 4_096;
pub(crate) const MAX_SEMANTIC_OBSERVATIONS: usize = 32;
pub(crate) const MAX_SEMANTIC_OBSERVATION_CHARACTERS: usize = 512;
pub(crate) const MAX_SEMANTIC_TOTAL_CHARACTERS: usize = 16_384;
const RESULT_ID_RANDOM_BYTES: usize = 16;
const RESULT_ID_HEX_CHARACTERS: usize = RESULT_ID_RANDOM_BYTES * 2;
const MAX_ID_CHARACTERS: usize = 128;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ScreenVisionSemanticResultErrorCode {
    InvalidArgument,
    ResultUnavailable,
    ResultExpired,
    SynchronizationUnavailable,
    RandomUnavailable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ScreenVisionSemanticResultError {
    pub(crate) code: ScreenVisionSemanticResultErrorCode,
}

impl ScreenVisionSemanticResultError {
    const fn new(code: ScreenVisionSemanticResultErrorCode) -> Self {
        Self { code }
    }
}

/// Bounded semantic fields intentionally have no serde or persistence
/// implementation.  They are internal prompt input, not an IPC DTO.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct ScreenVisionSemanticAnalysis {
    pub(crate) summary: String,
    pub(crate) observations: Vec<String>,
}

impl std::fmt::Debug for ScreenVisionSemanticAnalysis {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ScreenVisionSemanticAnalysis")
            .field("summary_len", &self.summary.chars().count())
            .field("observation_count", &self.observations.len())
            .field(
                "observation_lengths",
                &self
                    .observations
                    .iter()
                    .map(|value| value.chars().count())
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

/// The exact D26 source fence is retained as canonical decimal evidence.
/// `created_at` is monotonic and is never exposed over IPC.
#[derive(Clone)]
pub(crate) struct ScreenVisionSemanticResult {
    pub(crate) result_id: String,
    pub(crate) life_id: String,
    pub(crate) screen_session_fence: String,
    pub(crate) analysis: ScreenVisionSemanticAnalysis,
    pub(crate) created_at: Instant,
}

impl std::fmt::Debug for ScreenVisionSemanticResult {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ScreenVisionSemanticResult")
            .field("result_id", &self.result_id)
            .field("life_id", &self.life_id)
            .field("screen_session_fence", &self.screen_session_fence)
            .field("analysis", &self.analysis)
            .finish_non_exhaustive()
    }
}

enum SemanticResultState {
    Empty,
    Ready(ScreenVisionSemanticResult),
}

trait SemanticResultClock: Send + Sync {
    fn now(&self) -> Instant;
}

struct InstantSemanticResultClock;

impl SemanticResultClock for InstantSemanticResultClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

trait SemanticResultIdSource: Send + Sync {
    fn generate(&self) -> Result<String, ScreenVisionSemanticResultError>;
}

struct CsPrngSemanticResultIdSource;

impl SemanticResultIdSource for CsPrngSemanticResultIdSource {
    fn generate(&self) -> Result<String, ScreenVisionSemanticResultError> {
        let mut bytes = [0_u8; RESULT_ID_RANDOM_BYTES];
        getrandom::fill(&mut bytes).map_err(|_| {
            ScreenVisionSemanticResultError::new(
                ScreenVisionSemanticResultErrorCode::RandomUnavailable,
            )
        })?;
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut result_id = String::with_capacity(RESULT_ID_HEX_CHARACTERS);
        for byte in bytes {
            result_id.push(char::from(HEX[usize::from(byte >> 4)]));
            result_id.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        Ok(result_id)
    }
}

/// Exactly one READY semantic result exists in a process.  A replacement
/// drops the previous semantic payload; there is no history or persistence.
pub(crate) struct ScreenVisionSemanticResultBroker {
    state: Mutex<SemanticResultState>,
    clock: Box<dyn SemanticResultClock>,
    id_source: Box<dyn SemanticResultIdSource>,
    #[cfg(test)]
    install_failures: AtomicUsize,
}

impl ScreenVisionSemanticResultBroker {
    pub(crate) fn new() -> Self {
        Self {
            state: Mutex::new(SemanticResultState::Empty),
            clock: Box::new(InstantSemanticResultClock),
            id_source: Box::new(CsPrngSemanticResultIdSource),
            #[cfg(test)]
            install_failures: AtomicUsize::new(0),
        }
    }

    #[cfg(test)]
    fn with_clock_and_id_source(
        clock: Arc<dyn SemanticResultClock>,
        id_source: Arc<dyn SemanticResultIdSource>,
    ) -> Self {
        Self {
            state: Mutex::new(SemanticResultState::Empty),
            clock: Box::new(ArcClock(clock)),
            id_source: Box::new(ArcIdSource(id_source)),
            install_failures: AtomicUsize::new(0),
        }
    }

    /// Installs a parsed D26 result and returns only its opaque locator.
    pub(crate) fn install(
        &self,
        life_id: String,
        screen_session_fence: String,
        summary: String,
        observations: Vec<String>,
    ) -> Result<String, ScreenVisionSemanticResultError> {
        validate_id("life identity", &life_id)?;
        validate_id("screen session fence", &screen_session_fence)?;
        let analysis = ScreenVisionSemanticAnalysis {
            summary,
            observations,
        };
        validate_analysis(&analysis)?;

        #[cfg(test)]
        if self.install_failures.swap(0, Ordering::AcqRel) > 0 {
            return Err(ScreenVisionSemanticResultError::new(
                ScreenVisionSemanticResultErrorCode::SynchronizationUnavailable,
            ));
        }

        let result_id = self.id_source.generate()?;
        let result = ScreenVisionSemanticResult {
            result_id: result_id.clone(),
            life_id,
            screen_session_fence,
            analysis,
            created_at: self.clock.now(),
        };
        let mut state = self.state.lock().map_err(|_| {
            ScreenVisionSemanticResultError::new(
                ScreenVisionSemanticResultErrorCode::SynchronizationUnavailable,
            )
        })?;
        *state = SemanticResultState::Ready(result);
        Ok(result_id)
    }

    /// Reads an exact result and applies the original five-minute monotonic
    /// deadline.  A read never renews that deadline.
    pub(crate) fn get_exact(
        &self,
        result_id: &str,
    ) -> Result<ScreenVisionSemanticResult, ScreenVisionSemanticResultError> {
        validate_id("Vision result identity", result_id)?;
        let now = self.clock.now();
        let mut state = self.state.lock().map_err(|_| {
            ScreenVisionSemanticResultError::new(
                ScreenVisionSemanticResultErrorCode::SynchronizationUnavailable,
            )
        })?;
        let SemanticResultState::Ready(result) = &*state else {
            return Err(ScreenVisionSemanticResultError::new(
                ScreenVisionSemanticResultErrorCode::ResultUnavailable,
            ));
        };
        if now.saturating_duration_since(result.created_at) >= SCREEN_VISION_SEMANTIC_RESULT_TTL {
            let matches_requested = result.result_id == result_id;
            *state = SemanticResultState::Empty;
            return Err(ScreenVisionSemanticResultError::new(if matches_requested {
                ScreenVisionSemanticResultErrorCode::ResultExpired
            } else {
                ScreenVisionSemanticResultErrorCode::ResultUnavailable
            }));
        }
        if result.result_id != result_id {
            return Err(ScreenVisionSemanticResultError::new(
                ScreenVisionSemanticResultErrorCode::ResultUnavailable,
            ));
        }
        Ok(result.clone())
    }

    pub(crate) fn remove_exact(
        &self,
        result_id: &str,
    ) -> Result<(), ScreenVisionSemanticResultError> {
        validate_id("Vision result identity", result_id)?;
        let mut state = self.state.lock().map_err(|_| {
            ScreenVisionSemanticResultError::new(
                ScreenVisionSemanticResultErrorCode::SynchronizationUnavailable,
            )
        })?;
        match &*state {
            SemanticResultState::Ready(result) if result.result_id == result_id => {
                *state = SemanticResultState::Empty;
                Ok(())
            }
            _ => Err(ScreenVisionSemanticResultError::new(
                ScreenVisionSemanticResultErrorCode::ResultUnavailable,
            )),
        }
    }

    #[cfg(test)]
    pub(crate) fn fail_next_install_for_test(&self) {
        self.install_failures.fetch_add(1, Ordering::AcqRel);
    }

    #[cfg(test)]
    pub(crate) fn is_empty_for_test(&self) -> bool {
        matches!(
            self.state.lock().ok().as_deref(),
            Some(SemanticResultState::Empty)
        )
    }
}

fn validate_id(name: &str, value: &str) -> Result<(), ScreenVisionSemanticResultError> {
    if value.trim().is_empty() || value.chars().count() > MAX_ID_CHARACTERS {
        return Err(ScreenVisionSemanticResultError::new(
            ScreenVisionSemanticResultErrorCode::InvalidArgument,
        ));
    }
    let _ = name;
    Ok(())
}

pub(crate) fn validate_analysis(
    analysis: &ScreenVisionSemanticAnalysis,
) -> Result<(), ScreenVisionSemanticResultError> {
    if analysis.summary.trim().is_empty()
        || analysis.summary.chars().count() > MAX_SEMANTIC_SUMMARY_CHARACTERS
        || analysis.observations.len() > MAX_SEMANTIC_OBSERVATIONS
    {
        return Err(ScreenVisionSemanticResultError::new(
            ScreenVisionSemanticResultErrorCode::InvalidArgument,
        ));
    }
    if analysis.observations.iter().any(|observation| {
        observation.trim().is_empty()
            || observation.chars().count() > MAX_SEMANTIC_OBSERVATION_CHARACTERS
    }) {
        return Err(ScreenVisionSemanticResultError::new(
            ScreenVisionSemanticResultErrorCode::InvalidArgument,
        ));
    }
    let total = analysis.summary.chars().count()
        + analysis
            .observations
            .iter()
            .map(|observation| observation.chars().count())
            .sum::<usize>();
    if total > MAX_SEMANTIC_TOTAL_CHARACTERS {
        return Err(ScreenVisionSemanticResultError::new(
            ScreenVisionSemanticResultErrorCode::InvalidArgument,
        ));
    }
    Ok(())
}

#[cfg(test)]
struct ArcClock(Arc<dyn SemanticResultClock>);

#[cfg(test)]
impl SemanticResultClock for ArcClock {
    fn now(&self) -> Instant {
        self.0.now()
    }
}

#[cfg(test)]
struct ArcIdSource(Arc<dyn SemanticResultIdSource>);

#[cfg(test)]
impl SemanticResultIdSource for ArcIdSource {
    fn generate(&self) -> Result<String, ScreenVisionSemanticResultError> {
        self.0.generate()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone)]
    struct ManualClock {
        now: Arc<Mutex<Instant>>,
    }

    impl ManualClock {
        fn new() -> Self {
            Self {
                now: Arc::new(Mutex::new(Instant::now())),
            }
        }

        fn advance(&self, duration: Duration) {
            let mut now = self.now.lock().expect("semantic clock should not poison");
            *now = now.checked_add(duration).expect("test clock should fit");
        }
    }

    impl SemanticResultClock for ManualClock {
        fn now(&self) -> Instant {
            *self.now.lock().expect("semantic clock should not poison")
        }
    }

    struct SequenceIdSource {
        ids: Mutex<Vec<String>>,
    }

    impl SequenceIdSource {
        fn new(ids: &[&str]) -> Self {
            Self {
                ids: Mutex::new(ids.iter().rev().map(|id| (*id).to_string()).collect()),
            }
        }
    }

    impl SemanticResultIdSource for SequenceIdSource {
        fn generate(&self) -> Result<String, ScreenVisionSemanticResultError> {
            self.ids
                .lock()
                .expect("semantic id source should not poison")
                .pop()
                .ok_or_else(|| {
                    ScreenVisionSemanticResultError::new(
                        ScreenVisionSemanticResultErrorCode::RandomUnavailable,
                    )
                })
        }
    }

    fn broker(clock: ManualClock, ids: &[&str]) -> ScreenVisionSemanticResultBroker {
        ScreenVisionSemanticResultBroker::with_clock_and_id_source(
            Arc::new(clock),
            Arc::new(SequenceIdSource::new(ids)),
        )
    }

    #[test]
    fn valid_result_installs_one_opaque_slot_with_exact_scope() {
        let clock = ManualClock::new();
        let broker = broker(clock, &["result-one"]);
        let result_id = broker
            .install(
                "life-a".to_string(),
                "7".to_string(),
                "bounded summary".to_string(),
                vec!["first observation".to_string()],
            )
            .expect("valid semantic result should install");

        assert_eq!(result_id, "result-one");
        let result = broker
            .get_exact(&result_id)
            .expect("installed result should read");
        assert_eq!(result.life_id, "life-a");
        assert_eq!(result.screen_session_fence, "7");
        assert_eq!(result.analysis.summary, "bounded summary");
        assert_eq!(
            result.analysis.observations,
            vec!["first observation".to_string()]
        );
        let debug = format!("{result:?}");
        assert!(debug.contains("summary_len"));
        assert!(!debug.contains("bounded summary"));
    }

    #[test]
    fn semantic_result_id_uses_os_csprng_sized_lowercase_hex() {
        let result_id = CsPrngSemanticResultIdSource
            .generate()
            .expect("OS CSPRNG should be available");
        assert_eq!(result_id.len(), RESULT_ID_HEX_CHARACTERS);
        assert!(result_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
    }

    #[test]
    fn result_ttl_is_monotonic_and_get_does_not_renew_it() {
        let clock = ManualClock::new();
        let broker = broker(clock.clone(), &["result-ttl"]);
        let result_id = broker
            .install(
                "life-a".to_string(),
                "7".to_string(),
                "summary".to_string(),
                Vec::new(),
            )
            .unwrap();

        clock.advance(SCREEN_VISION_SEMANTIC_RESULT_TTL - Duration::from_secs(1));
        broker
            .get_exact(&result_id)
            .expect("result should still be fresh");
        clock.advance(Duration::from_secs(1));
        let error = broker
            .get_exact(&result_id)
            .expect_err("the original deadline must expire the result");
        assert_eq!(
            error.code,
            ScreenVisionSemanticResultErrorCode::ResultExpired
        );
        assert!(broker.is_empty_for_test());
    }

    #[test]
    fn replacement_drops_the_previous_payload_without_history() {
        let broker = broker(ManualClock::new(), &["result-old", "result-new"]);
        let old_id = broker
            .install(
                "life-a".to_string(),
                "1".to_string(),
                "old summary".to_string(),
                Vec::new(),
            )
            .unwrap();
        let new_id = broker
            .install(
                "life-a".to_string(),
                "2".to_string(),
                "new summary".to_string(),
                Vec::new(),
            )
            .unwrap();

        assert_ne!(old_id, new_id);
        assert_eq!(
            broker.get_exact(&old_id).unwrap_err().code,
            ScreenVisionSemanticResultErrorCode::ResultUnavailable
        );
        assert_eq!(
            broker.get_exact(&new_id).unwrap().analysis.summary,
            "new summary"
        );
    }

    #[test]
    fn malformed_semantic_payload_is_rejected_at_the_broker_boundary() {
        let cases = [
            (" ".to_string(), Vec::new()),
            ("s".repeat(MAX_SEMANTIC_SUMMARY_CHARACTERS + 1), Vec::new()),
            (
                "summary".to_string(),
                vec!["o".repeat(MAX_SEMANTIC_OBSERVATION_CHARACTERS + 1)],
            ),
            (
                "summary".to_string(),
                (0..=MAX_SEMANTIC_OBSERVATIONS)
                    .map(|_| "observation".to_string())
                    .collect(),
            ),
            (
                "s".repeat(MAX_SEMANTIC_SUMMARY_CHARACTERS),
                (0..MAX_SEMANTIC_OBSERVATIONS)
                    .map(|_| "o".repeat(MAX_SEMANTIC_OBSERVATION_CHARACTERS))
                    .collect(),
            ),
        ];

        for (summary, observations) in cases {
            let broker = broker(ManualClock::new(), &["result-invalid"]);
            let error = broker
                .install("life-a".to_string(), "1".to_string(), summary, observations)
                .expect_err("malformed semantic data must fail closed");
            assert_eq!(
                error.code,
                ScreenVisionSemanticResultErrorCode::InvalidArgument
            );
            assert!(broker.is_empty_for_test());
        }
    }

    #[test]
    fn result_slot_failure_is_bounded_and_does_not_install_a_partial_result() {
        let clock = ManualClock::new();
        let broker = broker(clock, &["result-never-issued"]);
        broker.fail_next_install_for_test();

        let error = broker
            .install(
                "life-a".to_string(),
                "7".to_string(),
                "bounded summary".to_string(),
                vec!["bounded observation".to_string()],
            )
            .expect_err("the injected local slot failure must be surfaced");
        assert_eq!(
            error.code,
            ScreenVisionSemanticResultErrorCode::SynchronizationUnavailable
        );
        assert!(broker.is_empty_for_test());
    }

    #[test]
    fn a_new_process_local_broker_starts_empty() {
        let broker = ScreenVisionSemanticResultBroker::new();
        assert!(broker.is_empty_for_test());
        assert_eq!(
            broker.get_exact("missing-result").unwrap_err().code,
            ScreenVisionSemanticResultErrorCode::ResultUnavailable
        );
    }
}
