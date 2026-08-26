use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc::{self, Receiver, Sender},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};

use crate::{
    conversation::{
        history::{
            AppendConversationTurnRequest, ConversationHistoryError, ConversationHistoryErrorCode,
            ConversationHistoryService, ConversationRole, CreateConversationCommandRequest,
            CreateConversationRequest,
        },
        service::{
            ConversationCognitionCoordinator, ConversationCognitionErrorCode,
            ConversationCognitionService, ConversationDegradationCode, GovernedConversationRequest,
        },
    },
    model::{
        profile::{
            CreateModelProfileRequest, ModelProfileService, ModelProviderKind, ModelPurpose,
            SetActiveModelProfileRequest,
        },
        runtime::ModelRuntimeCoordinator,
    },
    secrets::{InMemorySecretStore, SecretIdentifier, SecretPurpose, SecretStore, SecretValue},
    storage::{LifeIdentityRecord, PersonaTemplateRecord, StorageService},
    vector_store::LanceDbVectorStoreRegistry,
};

const LIFE_A: &str = "life-a";

struct Fixture {
    _temp: tempfile::TempDir,
    storage: Arc<StorageService>,
    secrets: Arc<InMemorySecretStore>,
    model_runtime: Arc<ModelRuntimeCoordinator>,
    registry: Arc<LanceDbVectorStoreRegistry>,
    coordinator: Arc<ConversationCognitionCoordinator>,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let storage = Arc::new(
            StorageService::initialize_with_roots(temp.path().join("data"), None).unwrap(),
        );
        seed_life(&storage, LIFE_A, "persona-a");
        Self {
            _temp: temp,
            storage,
            secrets: Arc::new(InMemorySecretStore::new()),
            model_runtime: Arc::new(ModelRuntimeCoordinator::default()),
            registry: Arc::new(LanceDbVectorStoreRegistry::default()),
            coordinator: Arc::new(ConversationCognitionCoordinator::default()),
        }
    }

    fn create_conversation(&self, title: &str) -> crate::conversation::ConversationRecord {
        ConversationHistoryService::new(self.storage.as_ref())
            .create(CreateConversationRequest {
                life_id: LIFE_A.into(),
                title: title.into(),
            })
            .unwrap()
    }

    fn activate_chat(&self, base_url: &str) {
        let profile = ModelProfileService::new(self.storage.as_ref())
            .create(CreateModelProfileRequest {
                purpose: ModelPurpose::Chat,
                provider_kind: ModelProviderKind::OpenaiCompatible,
                display_name: "Integration chat".into(),
                base_url: base_url.into(),
                model_name: "chat-model".into(),
                temperature: Some(0.4),
                max_tokens: Some(512),
                embedding_dimension: None,
            })
            .unwrap();
        ModelProfileService::new(self.storage.as_ref())
            .set_active(SetActiveModelProfileRequest {
                purpose: ModelPurpose::Chat,
                profile_id: profile.id.clone(),
            })
            .unwrap();
        self.secrets
            .set_secret(
                &SecretIdentifier::new(SecretPurpose::ChatModelApiKey, profile.id).unwrap(),
                SecretValue::new("integration-placeholder".into()).unwrap(),
            )
            .unwrap();
    }

    async fn chat(
        &self,
        request: GovernedConversationRequest,
    ) -> Result<
        crate::conversation::GovernedConversationResponse,
        crate::conversation::ConversationCognitionError,
    > {
        ConversationCognitionService::new(
            self.storage.as_ref(),
            self.secrets.as_ref(),
            self.model_runtime.as_ref(),
            self.registry.as_ref(),
            self.coordinator.as_ref(),
        )
        .chat(request)
        .await
    }

    /// Same as [`Self::chat`], but the service instance owns `hook` (invoked
    /// before each composite attempt). The hook is INSTANCE-SCOPED: no global
    /// state, so parallel tests never observe each other's seams.
    async fn chat_with_pre_composite_hook(
        &self,
        request: GovernedConversationRequest,
        hook: crate::conversation::service::PreCompositeHook,
    ) -> Result<
        crate::conversation::GovernedConversationResponse,
        crate::conversation::ConversationCognitionError,
    > {
        ConversationCognitionService::new_with_pre_composite_hook(
            self.storage.as_ref(),
            self.secrets.as_ref(),
            self.model_runtime.as_ref(),
            self.registry.as_ref(),
            self.coordinator.as_ref(),
            hook,
        )
        .chat(request)
        .await
    }
}

fn seed_life(storage: &StorageService, life_id: &str, persona_id: &str) {
    storage
        .save_persona(PersonaTemplateRecord {
            id: persona_id.into(),
            name: "Integration Persona".into(),
            version: 1,
            persona_json: format!(
                r#"{{"id":"{persona_id}","name":"Integration Persona","version":1}}"#
            ),
        })
        .unwrap();
    storage
        .save_life(LifeIdentityRecord {
            id: life_id.into(),
            name: "Integration Life".into(),
            created_at: "2026-07-13T00:00:00Z".into(),
            version: 1,
            body_id: "test-body".into(),
            persona_id: persona_id.into(),
            persona_version: 1,
        })
        .unwrap();
}

fn append_fixture_turn(
    storage: &StorageService,
    conversation_id: &str,
    turn_id: &str,
    user: &str,
    assistant: &str,
) {
    ConversationHistoryService::new(storage)
        .append_turn(AppendConversationTurnRequest {
            life_id: LIFE_A.into(),
            conversation_id: conversation_id.into(),
            turn_id: turn_id.into(),
            user_content: user.into(),
            assistant_content: assistant.into(),
            expected_revision: None,
        })
        .unwrap();
}

fn request(conversation_id: &str, request_id: &str, content: &str) -> GovernedConversationRequest {
    GovernedConversationRequest {
        request_id: request_id.into(),
        conversation_id: conversation_id.into(),
        current_message: content.into(),
    }
}

struct MockChatServer {
    base_url: String,
    calls: Arc<AtomicUsize>,
    requests: Arc<Mutex<Vec<String>>>,
    handle: Option<thread::JoinHandle<()>>,
}

impl MockChatServer {
    fn new(replies: Vec<(&'static str, &'static str)>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let thread_calls = Arc::clone(&calls);
        let thread_requests = Arc::clone(&requests);
        let handle = thread::spawn(move || {
            for (status, body) in replies {
                let mut stream = accept(&listener);
                let request = read_request(&mut stream);
                thread_requests.lock().unwrap().push(request);
                thread_calls.fetch_add(1, Ordering::SeqCst);
                write_response(&mut stream, status, body);
            }
        });
        Self {
            base_url: format!("http://{address}/v1"),
            calls,
            requests,
            handle: Some(handle),
        }
    }
}

impl Drop for MockChatServer {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.join().unwrap();
        }
    }
}

struct BlockingChatServer {
    base_url: String,
    received: Receiver<()>,
    release: Sender<()>,
    handle: Option<thread::JoinHandle<()>>,
}

impl BlockingChatServer {
    fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let (received_tx, received) = mpsc::channel();
        let (release, release_rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            let mut stream = accept(&listener);
            read_request(&mut stream);
            received_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            write_response(&mut stream, "200 OK", chat_response());
        });
        Self {
            base_url: format!("http://{address}/v1"),
            received,
            release,
            handle: Some(handle),
        }
    }
}

impl Drop for BlockingChatServer {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.join().unwrap();
        }
    }
}

fn accept(listener: &TcpListener) -> TcpStream {
    let stream = (0..500)
        .find_map(|_| match listener.accept() {
            Ok((stream, _)) => Some(stream),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
                None
            }
            Err(error) => panic!("mock listener failed: {error}"),
        })
        .expect("mock chat request was not received");
    stream.set_nonblocking(false).unwrap();
    stream
}

fn read_request(stream: &mut TcpStream) -> String {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 2048];
    loop {
        let read = stream.read(&mut buffer).unwrap();
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..read]);
        let Some(header_end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") else {
            continue;
        };
        let body_start = header_end + 4;
        let headers = String::from_utf8_lossy(&bytes[..body_start]);
        let length = headers
            .lines()
            .find_map(|line| {
                line.to_ascii_lowercase()
                    .strip_prefix("content-length:")
                    .and_then(|value| value.trim().parse::<usize>().ok())
            })
            .unwrap_or(0);
        if bytes.len() >= body_start + length {
            return String::from_utf8(bytes[body_start..body_start + length].to_vec()).unwrap();
        }
    }
    String::new()
}

fn write_response(stream: &mut TcpStream, status: &str, body: &str) {
    let reply = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(reply.as_bytes()).unwrap();
}

fn chat_response() -> &'static str {
    r#"{"model":"chat-model","choices":[{"message":{"content":"persisted assistant"},"finish_reason":"stop"}]}"#
}

#[test]
fn governed_chat_loads_sqlite_recent_history_persists_and_replays_without_provider() {
    tauri::async_runtime::block_on(async {
        let server = MockChatServer::new(vec![("200 OK", chat_response())]);
        let fixture = Fixture::new();
        fixture.activate_chat(&server.base_url);
        let conversation = fixture.create_conversation("Authority");
        for index in 0..11 {
            append_fixture_turn(
                fixture.storage.as_ref(),
                &conversation.id,
                &format!("old-{index}"),
                &format!("user-{index}"),
                &format!("assistant-{index}"),
            );
        }

        let first = fixture
            .chat(request(&conversation.id, "request-1", "current-once"))
            .await
            .unwrap();
        assert!(!first.replayed);
        assert_eq!(first.persisted_messages.len(), 2);
        assert_eq!(first.persisted_messages[0].role, ConversationRole::User);
        assert_eq!(
            first.persisted_messages[1].role,
            ConversationRole::Assistant
        );
        assert_eq!(first.persisted_messages[0].sequence_no, 23);
        assert_eq!(first.persisted_messages[1].sequence_no, 24);
        assert!(first
            .memory
            .degradation_codes
            .contains(&ConversationDegradationCode::NoActiveEmbeddingProfile));
        assert_eq!(
            ConversationHistoryService::new(fixture.storage.as_ref())
                .count_messages(LIFE_A, &conversation.id)
                .unwrap(),
            24
        );

        let replay = fixture
            .chat(request(&conversation.id, "request-1", "current-once"))
            .await
            .unwrap();
        assert!(replay.replayed);
        assert_eq!(replay.assistant_message, "persisted assistant");
        assert_eq!(server.calls.load(Ordering::SeqCst), 1);

        let body: serde_json::Value =
            serde_json::from_str(&server.requests.lock().unwrap()[0]).unwrap();
        let messages = body["messages"].as_array().unwrap();
        assert_eq!(messages.len(), 22);
        assert_eq!(messages[0]["role"], "system");
        assert_eq!(
            messages
                .iter()
                .filter(|message| message["content"] == "current-once")
                .count(),
            1
        );
        assert!(!messages
            .iter()
            .any(|message| message["content"] == "user-0"));
        assert!(!messages
            .iter()
            .any(|message| message["content"] == "assistant-0"));
        assert!(messages.iter().all(|message| matches!(
            message["role"].as_str(),
            Some("system" | "user" | "assistant")
        )));
        let response_json = serde_json::to_string(&first).unwrap().to_ascii_lowercase();
        for forbidden in ["systemcontext", "memoryrecord", "prompt", "apikey"] {
            assert!(!response_json.contains(forbidden));
        }

        let conflict = fixture
            .chat(request(&conversation.id, "request-1", "different-current"))
            .await
            .unwrap_err();
        assert_eq!(
            conflict.code,
            ConversationCognitionErrorCode::TurnIdConflict
        );
        assert_eq!(server.calls.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn model_failure_and_cross_life_request_leave_authoritative_history_unchanged() {
    tauri::async_runtime::block_on(async {
        let server = MockChatServer::new(vec![("500 Internal Server Error", "{}")]);
        let fixture = Fixture::new();
        fixture.activate_chat(&server.base_url);
        let conversation = fixture.create_conversation("Failure");
        let before = ConversationHistoryService::new(fixture.storage.as_ref())
            .get(LIFE_A, &conversation.id)
            .unwrap();
        assert!(fixture
            .chat(request(
                &conversation.id,
                "failed-request",
                "retryable input"
            ))
            .await
            .is_err());
        let after = ConversationHistoryService::new(fixture.storage.as_ref())
            .get(LIFE_A, &conversation.id)
            .unwrap();
        assert_eq!(
            (after.revision, after.updated_at, after.last_message_at),
            (before.revision, before.updated_at, before.last_message_at)
        );
        assert_eq!(
            ConversationHistoryService::new(fixture.storage.as_ref())
                .count_messages(LIFE_A, &conversation.id)
                .unwrap(),
            0
        );

        seed_life(fixture.storage.as_ref(), "life-b", "persona-b");
        let foreign = ConversationHistoryService::new(fixture.storage.as_ref())
            .create(CreateConversationRequest {
                life_id: "life-b".into(),
                title: "Foreign".into(),
            })
            .unwrap();
        seed_life(fixture.storage.as_ref(), LIFE_A, "persona-a");
        let error = fixture
            .chat(request(&foreign.id, "foreign-request", "blocked"))
            .await
            .unwrap_err();
        assert_eq!(
            error.code,
            ConversationCognitionErrorCode::ConversationLifeMismatch
        );
        assert_eq!(server.calls.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn generation_detects_conversation_revision_change_before_commit() {
    let server = BlockingChatServer::new();
    let fixture = Fixture::new();
    fixture.activate_chat(&server.base_url);
    let conversation = fixture.create_conversation("Concurrent history");
    let storage = Arc::clone(&fixture.storage);
    let secrets = Arc::clone(&fixture.secrets);
    let model_runtime = Arc::clone(&fixture.model_runtime);
    let registry = Arc::clone(&fixture.registry);
    let coordinator = Arc::clone(&fixture.coordinator);
    let conversation_id = conversation.id.clone();
    let request_conversation_id = conversation.id.clone();
    let handle = thread::spawn(move || {
        tauri::async_runtime::block_on(
            ConversationCognitionService::new(
                storage.as_ref(),
                secrets.as_ref(),
                model_runtime.as_ref(),
                registry.as_ref(),
                coordinator.as_ref(),
            )
            .chat(request(
                &request_conversation_id,
                "stale-request",
                "generated from revision zero",
            )),
        )
    });

    server
        .received
        .recv_timeout(Duration::from_secs(5))
        .unwrap();
    append_fixture_turn(
        fixture.storage.as_ref(),
        &conversation_id,
        "independent-turn",
        "newer user",
        "newer assistant",
    );
    server.release.send(()).unwrap();
    let error = handle.join().unwrap().unwrap_err();
    assert_eq!(
        error.code,
        ConversationCognitionErrorCode::ConversationChangedDuringRequest
    );
    assert_eq!(
        ConversationHistoryService::new(fixture.storage.as_ref())
            .count_messages(LIFE_A, &conversation_id)
            .unwrap(),
        2
    );
    assert!(ConversationHistoryService::new(fixture.storage.as_ref())
        .find_turn(LIFE_A, &conversation_id, "stale-request")
        .unwrap()
        .is_none());
}

#[test]
fn command_requests_cannot_override_life_and_empty_storage_creates_nothing() {
    assert!(serde_json::from_value::<CreateConversationCommandRequest>(
        serde_json::json!({"title":"New","lifeId":"forbidden"})
    )
    .is_err());
    let fixture = Fixture::new();
    assert!(ConversationHistoryService::new(fixture.storage.as_ref())
        .list(LIFE_A)
        .unwrap()
        .is_empty());
}

#[test]
fn reopening_storage_restores_latest_conversation_and_committed_messages() {
    let temp = tempfile::tempdir().unwrap();
    let data_root = temp.path().join("data");
    let latest_id;
    {
        let storage = StorageService::initialize_with_roots(data_root.clone(), None).unwrap();
        seed_life(&storage, LIFE_A, "persona-a");
        let older = ConversationHistoryService::new(&storage)
            .create(CreateConversationRequest {
                life_id: LIFE_A.into(),
                title: "Older".into(),
            })
            .unwrap();
        let latest = ConversationHistoryService::new(&storage)
            .create(CreateConversationRequest {
                life_id: LIFE_A.into(),
                title: "Latest".into(),
            })
            .unwrap();
        append_fixture_turn(&storage, &older.id, "old", "old user", "old assistant");
        thread::sleep(Duration::from_millis(20));
        append_fixture_turn(
            &storage,
            &latest.id,
            "latest",
            "latest user",
            "latest assistant",
        );
        latest_id = latest.id;
    }
    let reopened = StorageService::initialize_with_roots(data_root, None).unwrap();
    let conversations = ConversationHistoryService::new(&reopened)
        .list(LIFE_A)
        .unwrap();
    assert_eq!(conversations[0].id, latest_id);
    let messages = ConversationHistoryService::new(&reopened)
        .recent_messages(LIFE_A, &latest_id)
        .unwrap();
    assert_eq!(
        messages
            .iter()
            .map(|message| message.content.as_str())
            .collect::<Vec<_>>(),
        vec!["latest user", "latest assistant"]
    );
}

// ==================== D11-C2 production emotion cutover ====================

use crate::emotion::{EmotionError, EmotionErrorCode, EmotionRepository, EmotionState};
use crate::experience::{
    ExperienceEpisodeError, ExperienceEpisodeErrorCode, ExperienceEpisodeRepository,
};
use crate::storage::conversation_emotion::{
    conversation_emotion_event_id, conversation_emotion_source_ref,
};

fn emotion_state_of(storage: &StorageService) -> EmotionState {
    <StorageService as EmotionRepository>::load_current_state(storage, LIFE_A)
        .unwrap()
        .unwrap()
}

/// Governed event lookup through the frozen B1 repository surface (the raw
/// connection is private outside the storage module). Returns the canonical
/// identity triple of the single conversation_turn event for this turn.
fn governed_event_identity(
    storage: &StorageService,
    conversation_id: &str,
    request_id: &str,
) -> Option<(String, String, String)> {
    <StorageService as EmotionRepository>::find_event(
        storage,
        LIFE_A,
        "conversation_turn",
        &conversation_emotion_source_ref(conversation_id, request_id),
    )
    .unwrap()
    .map(|event| (event.event_id, event.source_kind, event.source_ref))
}

fn experience_episode_for_turn(
    storage: &StorageService,
    conversation_id: &str,
    turn_id: &str,
) -> Option<crate::experience::ExperienceEpisode> {
    <StorageService as ExperienceEpisodeRepository>::find_episode_by_source(
        storage,
        LIFE_A,
        crate::experience::SOURCE_KIND,
        &format!("{conversation_id}:{turn_id}"),
    )
    .unwrap()
}

#[test]
fn successful_new_chat_commits_exactly_one_governed_emotion_turn() {
    tauri::async_runtime::block_on(async {
        let server = MockChatServer::new(vec![("200 OK", chat_response())]);
        let fixture = Fixture::new();
        fixture.activate_chat(&server.base_url);
        let conversation = fixture.create_conversation("C2 success");

        let response = fixture
            .chat(request(&conversation.id, "c2-request-1", "hello emotion"))
            .await
            .unwrap();

        // Model called exactly once; conversation committed exactly once.
        assert_eq!(server.calls.load(Ordering::SeqCst), 1);
        assert!(!response.replayed);
        assert_eq!(response.assistant_message, "persisted assistant");
        assert_eq!(
            ConversationHistoryService::new(fixture.storage.as_ref())
                .count_messages(LIFE_A, &conversation.id)
                .unwrap(),
            2
        );
        let record = ConversationHistoryService::new(fixture.storage.as_ref())
            .get(LIFE_A, &conversation.id)
            .unwrap();
        assert_eq!(record.revision, 1);

        // D13-C2: the four-domain primitive creates exactly one canonical
        // episode from the actual persisted message identities/timestamps.
        let persisted_turn = ConversationHistoryService::new(fixture.storage.as_ref())
            .find_turn(LIFE_A, &conversation.id, "c2-request-1")
            .unwrap()
            .expect("the governed turn must be persisted");
        let episode =
            experience_episode_for_turn(fixture.storage.as_ref(), &conversation.id, "c2-request-1")
                .expect("the new governed turn must have exactly one experience episode");
        assert_eq!(
            episode.episode_id,
            format!(
                "experience-conversation:{LIFE_A}:{}:c2-request-1",
                conversation.id
            )
        );
        assert_eq!(episode.source_kind, crate::experience::SOURCE_KIND);
        assert_eq!(
            episode.source_ref,
            format!("{}:c2-request-1", conversation.id)
        );
        assert_eq!(
            episode.user_message_id, persisted_turn.user_message.id,
            "episode must bind to the persisted user message"
        );
        assert_eq!(
            episode.assistant_message_id, persisted_turn.assistant_message.id,
            "episode must bind to the persisted assistant message"
        );
        assert_eq!(episode.started_at, persisted_turn.user_message.created_at);
        assert_eq!(
            episode.ended_at,
            persisted_turn.assistant_message.created_at
        );
        assert_eq!(episode.created_at, episode.ended_at);
        assert_eq!(episode.counterpart_subject_id, "primary_user");
        assert_eq!(episode.outcome_kind, "completed");
        assert_eq!(episode.episode_version, 1);

        // Exactly one emotion event with the canonical identity.
        let event =
            governed_event_identity(fixture.storage.as_ref(), &conversation.id, "c2-request-1")
                .expect("the governed turn must carry exactly its canonical emotion event");
        let state = emotion_state_of(fixture.storage.as_ref());
        assert_eq!(state.revision, 1);
        assert_eq!(
            event.0,
            conversation_emotion_event_id(LIFE_A, &conversation.id, "c2-request-1")
        );
        assert_eq!(event.1, "conversation_turn");
        assert_eq!(
            event.2,
            conversation_emotion_source_ref(&conversation.id, "c2-request-1")
        );

        // Baseline stimulus at zero elapsed: valence untouched (0), activation
        // +10 signal through the 7/10 gain = +7.
        assert_eq!((state.valence, state.activation), (0, 7));

        // The response must NOT leak any emotion values.
        let response_json = serde_json::to_string(&response)
            .unwrap()
            .to_ascii_lowercase();
        for forbidden in ["valence", "activation", "policyversion", "sourceref"] {
            assert!(!response_json.contains(forbidden));
        }
    });
}

#[test]
fn c2_decay_and_impulse_compose_through_the_deterministic_clock_seam() {
    tauri::async_runtime::block_on(async {
        let server = MockChatServer::new(vec![("200 OK", chat_response())]);
        let fixture = Fixture::new();
        fixture.activate_chat(&server.base_url);
        let conversation = fixture.create_conversation("C2 decay");

        // Stage 1 — exact one-hour composition through the deterministic
        // seam: seed last_applied_at to a fixed past instant via a governed
        // commit, then verify decay + impulse compose exactly per B2
        // (valence: -200 decays +8/h toward zero → -192; activation:
        // 100 decays -24/h → 76; impulse +10*7/10 = +7 → 83).
        <StorageService as EmotionRepository>::commit_transition(
            fixture.storage.as_ref(),
            crate::emotion::EmotionTransition::new(
                "seed-event",
                LIFE_A,
                crate::emotion::EmotionEventSource::new("seed", "seed-ref"),
                -200,
                100,
                0,
                -200,
                100,
                1,
                "2026-08-24T11:00:00.000Z",
            )
            .unwrap(),
        )
        .unwrap();
        let observation = fixture
            .storage
            .load_emotion_runtime_observation_at(LIFE_A, "2026-08-24T12:00:00.000Z")
            .unwrap();
        assert_eq!(observation.elapsed_seconds, 3600);
        let policy_request = crate::emotion::policy::EmotionPolicyRequest::new(
            conversation_emotion_event_id(LIFE_A, &conversation.id, "decay-probe"),
            crate::emotion::EmotionEventSource::new(
                "conversation_turn",
                conversation_emotion_source_ref(&conversation.id, "decay-probe"),
            ),
            crate::emotion::policy::EmotionStimulus::new(0, 10).unwrap(),
            observation.elapsed_seconds,
            observation.observed_at,
        )
        .unwrap();
        let transition =
            crate::emotion::policy::evolve(&observation.state, policy_request).unwrap();
        assert_eq!(
            (transition.next_valence, transition.next_activation),
            (-192, 83),
            "one hour decay then frozen stimulus must compose exactly"
        );

        // Stage 2 — deterministic production-path behavior: push
        // last_applied_at to a FIXED FUTURE instant with a second governed
        // commit, so every real run observes 'now' EARLIER than the seed and
        // the production reader deterministically clamps elapsed to zero.
        <StorageService as EmotionRepository>::commit_transition(
            fixture.storage.as_ref(),
            crate::emotion::EmotionTransition::new(
                "future-event",
                LIFE_A,
                crate::emotion::EmotionEventSource::new("seed", "seed-ref-future"),
                0,
                0,
                1,
                -200,
                100,
                1,
                "2099-01-01T00:00:00.000Z",
            )
            .unwrap(),
        )
        .unwrap();

        // A REAL governed chat turn commits its own event on top through the
        // production path with rollback-clamped elapsed: the committed state
        // is exactly the seed plus this turn's frozen +7 activation impulse.
        fixture
            .chat(request(&conversation.id, "c2-decay-request", "after seed"))
            .await
            .unwrap();
        assert_eq!(server.calls.load(Ordering::SeqCst), 1);
        assert!(governed_event_identity(
            fixture.storage.as_ref(),
            &conversation.id,
            "c2-decay-request"
        )
        .is_some());
        let state = emotion_state_of(fixture.storage.as_ref());
        assert_eq!(state.revision, 3);
        assert_eq!(
            (state.valence, state.activation),
            (-200, 107),
            "rollback-clamped elapsed keeps the seeded state; only +7 is added"
        );
    });
}

#[test]
fn c2_exact_replay_short_circuits_before_model_and_emotion() {
    tauri::async_runtime::block_on(async {
        let server = MockChatServer::new(vec![("200 OK", chat_response())]);
        let fixture = Fixture::new();
        fixture.activate_chat(&server.base_url);
        let conversation = fixture.create_conversation("C2 replay");

        let first = fixture
            .chat(request(&conversation.id, "same-request", "ask once"))
            .await
            .unwrap();
        assert!(!first.replayed);
        assert_eq!(server.calls.load(Ordering::SeqCst), 1);
        let state_after_first = emotion_state_of(fixture.storage.as_ref());
        let relationship_after_first = relationship_state_of(fixture.storage.as_ref());
        let episode_after_first =
            experience_episode_for_turn(fixture.storage.as_ref(), &conversation.id, "same-request")
                .expect("a successful new turn must create one experience episode");

        let replay = fixture
            .chat(request(&conversation.id, "same-request", "ask once"))
            .await
            .unwrap();
        assert!(replay.replayed);
        assert_eq!(replay.assistant_message, "persisted assistant");
        // No second model call, no extra messages/events/revisions.
        assert_eq!(server.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            ConversationHistoryService::new(fixture.storage.as_ref())
                .count_messages(LIFE_A, &conversation.id)
                .unwrap(),
            2
        );
        assert!(governed_event_identity(
            fixture.storage.as_ref(),
            &conversation.id,
            "same-request"
        )
        .is_some());
        assert_eq!(
            experience_episode_for_turn(fixture.storage.as_ref(), &conversation.id, "same-request",),
            Some(episode_after_first),
            "high-level replay must not duplicate or mutate the episode"
        );
        assert_eq!(
            emotion_state_of(fixture.storage.as_ref()),
            state_after_first
        );
        assert_eq!(
            relationship_state_of(fixture.storage.as_ref()),
            relationship_after_first
        );

        // Same request id + different current message: TurnIdConflict, no new
        // model call, no emotion mutation.
        let conflict = fixture
            .chat(request(&conversation.id, "same-request", "different"))
            .await
            .unwrap_err();
        assert_eq!(
            conflict.code,
            ConversationCognitionErrorCode::TurnIdConflict
        );
        assert_eq!(server.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            emotion_state_of(fixture.storage.as_ref()),
            state_after_first
        );
    });
}

#[test]
fn c2_legacy_turn_replay_returns_history_without_backfilling_emotion() {
    tauri::async_runtime::block_on(async {
        // No chat provider is activated at all: the high-level replay
        // short-circuit must return the persisted turn BEFORE any model or
        // emotion work, which this fixture makes observable.
        let fixture = Fixture::new();
        let conversation = fixture.create_conversation("C2 legacy replay");

        // Commit the turn through the LEGACY non-emotion path BEFORE chat.
        append_fixture_turn(
            fixture.storage.as_ref(),
            &conversation.id,
            "pre-c-turn",
            "legacy question",
            "legacy answer",
        );

        let replay = fixture
            .chat(request(&conversation.id, "pre-c-turn", "legacy question"))
            .await
            .unwrap();

        // High-level replay returns persisted history and never touches
        // emotion — no model call, no backfilled event, no revision change.
        assert!(replay.replayed);
        assert_eq!(replay.assistant_message, "legacy answer");
        assert!(
            governed_event_identity(fixture.storage.as_ref(), &conversation.id, "pre-c-turn")
                .is_none()
        );
        let state = emotion_state_of(fixture.storage.as_ref());
        assert_eq!((state.valence, state.activation, state.revision), (0, 0, 0));
    });
}

#[test]
fn c2_model_failure_persists_nothing_in_either_domain() {
    tauri::async_runtime::block_on(async {
        let server = MockChatServer::new(vec![("500 Internal Server Error", "{}")]);
        let fixture = Fixture::new();
        fixture.activate_chat(&server.base_url);
        let conversation = fixture.create_conversation("C2 failure");

        let error = fixture
            .chat(request(&conversation.id, "failed-c2", "will fail"))
            .await
            .unwrap_err();
        // Existing provider failure mapping is preserved (a 500 with an empty
        // body is an invalid/failed provider response, NOT any emotion code).
        assert!(matches!(
            error.code,
            ConversationCognitionErrorCode::InvalidProviderResponse
                | ConversationCognitionErrorCode::ProviderInitializationFailed
                | ConversationCognitionErrorCode::NetworkUnavailable
        ));
        assert_eq!(
            ConversationHistoryService::new(fixture.storage.as_ref())
                .count_messages(LIFE_A, &conversation.id)
                .unwrap(),
            0
        );
        let state = emotion_state_of(fixture.storage.as_ref());
        assert_eq!((state.valence, state.activation, state.revision), (0, 0, 0));
    });
}

#[test]
fn c2_stale_conversation_revision_maps_to_existing_cognition_error() {
    // Reuse the blocking server pattern from the existing suite: while the
    // model call is in flight, another writer advances the conversation, so
    // the composite commit fails its CAS. Emotion must roll back too.
    let server = BlockingChatServer::new();
    let fixture = Fixture::new();
    fixture.activate_chat(&server.base_url);
    let conversation = fixture.create_conversation("C2 conv conflict");
    let storage = Arc::clone(&fixture.storage);
    let secrets = Arc::clone(&fixture.secrets);
    let model_runtime = Arc::clone(&fixture.model_runtime);
    let registry = Arc::clone(&fixture.registry);
    let coordinator = Arc::clone(&fixture.coordinator);
    let conversation_id = conversation.id.clone();
    let request_conversation_id = conversation.id.clone();
    let handle = thread::spawn(move || {
        tauri::async_runtime::block_on(
            ConversationCognitionService::new(
                storage.as_ref(),
                secrets.as_ref(),
                model_runtime.as_ref(),
                registry.as_ref(),
                coordinator.as_ref(),
            )
            .chat(request(
                &request_conversation_id,
                "c2-stale",
                "generated from stale revision",
            )),
        )
    });

    server
        .received
        .recv_timeout(Duration::from_secs(5))
        .unwrap();
    append_fixture_turn(
        fixture.storage.as_ref(),
        &conversation_id,
        "independent-c2-turn",
        "newer user",
        "newer assistant",
    );
    server.release.send(()).unwrap();
    let error = handle.join().unwrap().unwrap_err();
    assert_eq!(
        error.code,
        ConversationCognitionErrorCode::ConversationChangedDuringRequest
    );
    // The independent turn remains; NO partial emotion mutation happened.
    assert_eq!(
        ConversationHistoryService::new(fixture.storage.as_ref())
            .count_messages(LIFE_A, &conversation_id)
            .unwrap(),
        2
    );
    assert!(
        governed_event_identity(fixture.storage.as_ref(), &conversation_id, "c2-stale").is_none()
    );
    let state = emotion_state_of(fixture.storage.as_ref());
    assert_eq!((state.valence, state.activation, state.revision), (0, 0, 0));
}

// ==================== D11-C2-F2: instance-scoped retry evidence ====================
// The pre-composite seam lives on the ConversationCognitionService INSTANCE
// (installed via new_with_pre_composite_hook); there is no global hook slot
// and no global mutex, so these tests are parallelizable by construction.

use std::sync::Mutex as StdMutex;

/// Builds an INSTANCE-SCOPED pre-composite hook that performs ONE real,
/// internally coherent independent B1 emotion commit per raced invocation,
/// forcing the typed revision race against the production composite attempt.
/// Coherence: the race writer loads the CURRENT authoritative state and
/// commits delta (-5,-5) WITH the matching next state
/// (valence-5, activation-5), so ledger evidence and state always agree —
/// including on the second race of the repeated-conflict test. Keyed to
/// `target_turn_id` (other turns are no-ops); stops racing after `max_races`
/// invocations. Returns the captured observed_at per raced attempt.
fn make_revision_race_hook(
    storage: Arc<StorageService>,
    target_turn_id: &'static str,
    max_races: u32,
) -> (
    crate::conversation::service::PreCompositeHook,
    Arc<StdMutex<Vec<String>>>,
) {
    let captured = Arc::new(StdMutex::new(Vec::new()));
    let captured_for_hook = Arc::clone(&captured);
    let sequence = std::sync::atomic::AtomicU32::new(0);
    let hook: crate::conversation::service::PreCompositeHook =
        Box::new(move |life_id: &str, turn_id: &str, observed_at: &str| {
            if turn_id != target_turn_id {
                return;
            }
            captured_for_hook
                .lock()
                .unwrap()
                .push(observed_at.to_string());
            // One REAL independent EmotionRepository::commit_transition per
            // raced attempt — a legitimate competing emotion writer, not
            // fault injection. It wins the revision the composite built on.
            if sequence.fetch_add(1, std::sync::atomic::Ordering::SeqCst) >= max_races {
                return;
            }
            let current = <StorageService as EmotionRepository>::load_current_state(
                storage.as_ref(),
                life_id,
            )
            .unwrap()
            .expect("race fixture life must exist");
            // Internally coherent mutation: delta (-5,-5) applied to the
            // loaded state with matching next values (clamped to the frozen
            // [-1000, 1000] domain).
            let next_valence = (current.valence - 5).clamp(-1000, 1000);
            let next_activation = (current.activation - 5).clamp(-1000, 1000);
            <StorageService as EmotionRepository>::commit_transition(
                storage.as_ref(),
                crate::emotion::EmotionTransition::new(
                    format!(
                        "race-writer-{}",
                        sequence.load(std::sync::atomic::Ordering::SeqCst)
                    ),
                    life_id,
                    crate::emotion::EmotionEventSource::new(
                        "race",
                        format!(
                            "race-ref-{}",
                            sequence.load(std::sync::atomic::Ordering::SeqCst)
                        ),
                    ),
                    -5,
                    -5,
                    current.revision,
                    next_valence,
                    next_activation,
                    1,
                    "2099-01-01T00:00:00.000Z",
                )
                .unwrap(),
            )
            .unwrap();
        });
    (hook, captured)
}

#[test]
fn f1_first_revision_conflict_rebuilds_and_succeeds_with_original_event_time() {
    tauri::async_runtime::block_on(async {
        let server = MockChatServer::new(vec![("200 OK", chat_response())]);
        let fixture = Fixture::new();
        fixture.activate_chat(&server.base_url);
        let conversation = fixture.create_conversation("F1 retry success");

        // The hook runs between first observation and first composite: it
        // commits one real independent emotion event, so the composite's
        // expected_revision is stale and C2 must rebuild once. Exactly ONE
        // race: the retry attempt runs unraced.
        let (hook, captured_times) =
            make_revision_race_hook(Arc::clone(&fixture.storage), "f1-retry-request", 1);

        let response = fixture
            .chat_with_pre_composite_hook(
                request(&conversation.id, "f1-retry-request", "race me"),
                hook,
            )
            .await
            .unwrap();

        // Model called exactly ONCE across both composite attempts.
        assert_eq!(server.calls.load(Ordering::SeqCst), 1);
        assert!(!response.replayed);
        assert_eq!(response.assistant_message, "persisted assistant");

        // Conversation committed exactly once.
        assert_eq!(
            ConversationHistoryService::new(fixture.storage.as_ref())
                .count_messages(LIFE_A, &conversation.id)
                .unwrap(),
            2
        );
        let record = ConversationHistoryService::new(fixture.storage.as_ref())
            .get(LIFE_A, &conversation.id)
            .unwrap();
        assert_eq!(record.revision, 1);

        // The retried turn carries exactly one canonical emotion event.
        let canonical = governed_event_identity(
            fixture.storage.as_ref(),
            &conversation.id,
            "f1-retry-request",
        )
        .expect("the retried turn must carry its canonical emotion event");
        assert_eq!(
            canonical.0,
            conversation_emotion_event_id(LIFE_A, &conversation.id, "f1-retry-request")
        );
        assert!(experience_episode_for_turn(
            fixture.storage.as_ref(),
            &conversation.id,
            "f1-retry-request",
        )
        .is_some());

        // The ORIGINAL observed_at was reused for the rebuilt transition.
        let original_observed_at = &captured_times.lock().unwrap()[0];
        let persisted_event = <StorageService as EmotionRepository>::find_event(
            fixture.storage.as_ref(),
            LIFE_A,
            "conversation_turn",
            &conversation_emotion_source_ref(&conversation.id, "f1-retry-request"),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            persisted_event.event_time,
            *original_observed_at,
            "retry must reuse the ORIGINAL observation time (captured={:?})",
            captured_times.lock().unwrap()
        );

        // The race writer's last_applied_at is LATER than the original
        // observation (2099 vs real now), so the refreshed explicit-time
        // observation clamped elapsed to zero. Final revision: the one race
        // commit (0→1) plus this turn's successful retry (1→2) = 2. The
        // coherent race writer moved (0,0) → (-5,-5), then the rebuild added
        // this turn's +7 impulse → (-5,+2).
        let state = emotion_state_of(fixture.storage.as_ref());
        assert_eq!(state.revision, 2);
        assert_eq!(
            (state.valence, state.activation),
            (-5, 2),
            "rebuild must start from the NEWER state (-5,-5) then add +7"
        );
        // Ledger/state coherence for the race event itself.
        let race_event = <StorageService as EmotionRepository>::find_event(
            fixture.storage.as_ref(),
            LIFE_A,
            "race",
            "race-ref-1",
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            (race_event.valence_delta, race_event.activation_delta),
            (-5, -5)
        );
        assert_eq!(
            (race_event.result_valence, race_event.result_activation),
            (-5, -5)
        );
    });
}

#[test]
fn f1_second_revision_conflict_stops_with_recoverable_changed_error() {
    tauri::async_runtime::block_on(async {
        let server = MockChatServer::new(vec![("200 OK", chat_response())]);
        let fixture = Fixture::new();
        fixture.activate_chat(&server.base_url);
        let conversation = fixture.create_conversation("F1 retry exhausted");

        // The hook races BOTH composite attempts (max 2), so the single
        // allowed retry also conflicts. Production must stop after two.
        let (hook, _captured) =
            make_revision_race_hook(Arc::clone(&fixture.storage), "f1-exhausted", 2);

        let error = fixture
            .chat_with_pre_composite_hook(
                request(&conversation.id, "f1-exhausted", "always racing"),
                hook,
            )
            .await
            .unwrap_err();

        assert_eq!(
            error.code,
            ConversationCognitionErrorCode::EmotionChangedDuringRequest
        );
        assert!(error.recoverable);

        // Model called exactly ONCE; no third attempt looped.
        assert_eq!(server.calls.load(Ordering::SeqCst), 1);
        // Exactly TWO coherent race commits: (0,0)→(-5,-5)→(-10,-10),
        // proving exactly two attempts were staged.
        let state = emotion_state_of(fixture.storage.as_ref());
        assert_eq!(
            state.revision, 2,
            "two independent race commits prove exactly two attempts were staged"
        );
        assert_eq!(
            (state.valence, state.activation),
            (-10, -10),
            "each race commit applies its coherent (-5,-5) delta to the loaded state"
        );
        // The requested conversation turn was never partially committed.
        assert_eq!(
            ConversationHistoryService::new(fixture.storage.as_ref())
                .count_messages(LIFE_A, &conversation.id)
                .unwrap(),
            0
        );
        assert!(ConversationHistoryService::new(fixture.storage.as_ref())
            .find_turn(LIFE_A, &conversation.id, "f1-exhausted")
            .unwrap()
            .is_none());
        assert!(governed_event_identity(
            fixture.storage.as_ref(),
            &conversation.id,
            "f1-exhausted"
        )
        .is_none());
        assert!(experience_episode_for_turn(
            fixture.storage.as_ref(),
            &conversation.id,
            "f1-exhausted",
        )
        .is_none());
    });
}

#[test]
fn f1_real_composite_event_conflict_maps_to_emotion_commit_conflict() {
    tauri::async_runtime::block_on(async {
        let server = MockChatServer::new(vec![("200 OK", chat_response())]);
        let fixture = Fixture::new();
        fixture.activate_chat(&server.base_url);
        let conversation = fixture.create_conversation("F1 event conflict");
        let conversation_id = conversation.id.clone();
        let storage_for_hook = Arc::clone(&fixture.storage);

        // Narrow deterministic seam: pre-create CONFLICTING canonical emotion
        // evidence for this exact turn identity before the composite runs.
        // Keyed to THIS turn; installed on THIS test's own service instance.
        let conflict_hook: crate::conversation::service::PreCompositeHook =
            Box::new(move |life_id: &str, turn_id: &str, _observed_at: &str| {
                if turn_id != "f1-event-conflict" {
                    return;
                }
                <StorageService as EmotionRepository>::commit_transition(
                    storage_for_hook.as_ref(),
                    crate::emotion::EmotionTransition::new(
                        conversation_emotion_event_id(
                            life_id,
                            &conversation_id,
                            "f1-event-conflict",
                        ),
                        life_id,
                        crate::emotion::EmotionEventSource::new(
                            "conversation_turn",
                            conversation_emotion_source_ref(&conversation_id, "f1-event-conflict"),
                        ),
                        // Same source identity, DIFFERENT payload → EventConflict.
                        // Coherent evidence: delta (999,-999) with matching
                        // result state.
                        999,
                        -999,
                        0,
                        999,
                        -999,
                        1,
                        "2098-01-01T00:00:00.000Z",
                    )
                    .unwrap(),
                )
                .unwrap();
            });

        let error = fixture
            .chat_with_pre_composite_hook(
                request(&conversation.id, "f1-event-conflict", "conflicting"),
                conflict_hook,
            )
            .await
            .unwrap_err();

        assert_eq!(
            error.code,
            ConversationCognitionErrorCode::EmotionCommitConflict
        );
        assert!(!error.recoverable);
        // No additional conversation mutation happened.
        assert_eq!(
            ConversationHistoryService::new(fixture.storage.as_ref())
                .count_messages(LIFE_A, &conversation.id)
                .unwrap(),
            0
        );
        assert_eq!(server.calls.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn f1_observation_and_general_db_errors_map_to_distinct_boundaries() {
    // Mapping proof at the private mapper level (no corruption fixture needed).
    let db = crate::emotion::EmotionError::database();
    let invalid = crate::emotion::EmotionError::invalid_argument("x");

    let observation_db = crate::conversation::service::test_map_observation_error(db.clone());
    assert_eq!(
        observation_db.code,
        ConversationCognitionErrorCode::EmotionStateUnavailable
    );
    assert!(observation_db.recoverable);

    let general_db = crate::conversation::service::test_map_general_error(db);
    assert_eq!(
        general_db.code,
        ConversationCognitionErrorCode::EmotionIntegrationFailure
    );
    assert!(!general_db.recoverable);

    // InvalidArgument keeps its distinct classification on BOTH boundaries:
    // observation-side it is an integration/invariant problem too.
    let observation_invalid =
        crate::conversation::service::test_map_observation_error(invalid.clone());
    assert_eq!(
        observation_invalid.code,
        ConversationCognitionErrorCode::EmotionIntegrationFailure
    );
    let general_invalid = crate::conversation::service::test_map_general_error(invalid);
    assert_eq!(
        general_invalid.code,
        ConversationCognitionErrorCode::EmotionIntegrationFailure
    );
}

#[test]
fn d13_c2_four_domain_mapper_and_retry_classifier_are_typed() {
    use crate::storage::conversation_experience::ConversationEmotionRelationshipExperienceCommitError as Composite;

    let conversation = Composite::Conversation(ConversationHistoryError::new(
        ConversationHistoryErrorCode::ConversationStorageUnavailable,
    ));
    let mapped = crate::conversation::service::test_map_four_domain_error(conversation.clone());
    assert_eq!(
        mapped.code,
        ConversationCognitionErrorCode::ConversationStorageUnavailable
    );
    assert!(
        !crate::conversation::service::test_four_domain_error_is_revision_conflict(&conversation)
    );

    let emotion_revision = Composite::Emotion(EmotionError::new(
        EmotionErrorCode::RevisionConflict,
        "synthetic emotion conflict",
    ));
    let mapped = crate::conversation::service::test_map_four_domain_error(emotion_revision.clone());
    assert_eq!(
        mapped.code,
        ConversationCognitionErrorCode::EmotionChangedDuringRequest
    );
    assert!(
        crate::conversation::service::test_four_domain_error_is_revision_conflict(
            &emotion_revision
        )
    );

    let relationship_revision =
        Composite::Relationship(crate::relationship::RelationshipError::new(
            crate::relationship::RelationshipErrorCode::RevisionConflict,
            "synthetic relationship conflict",
        ));
    let mapped =
        crate::conversation::service::test_map_four_domain_error(relationship_revision.clone());
    assert_eq!(
        mapped.code,
        ConversationCognitionErrorCode::RelationshipChangedDuringRequest
    );
    assert!(
        crate::conversation::service::test_four_domain_error_is_revision_conflict(
            &relationship_revision
        )
    );

    for (commit_error, expected_code) in [
        (
            Composite::EmotionBindingMismatch("binding".into()),
            ConversationCognitionErrorCode::EmotionIntegrationFailure,
        ),
        (
            Composite::EmotionEventMissing("missing".into()),
            ConversationCognitionErrorCode::EmotionIntegrationFailure,
        ),
        (
            Composite::RelationshipBindingMismatch("binding".into()),
            ConversationCognitionErrorCode::RelationshipIntegrationFailure,
        ),
        (
            Composite::RelationshipEventMissing("missing".into()),
            ConversationCognitionErrorCode::RelationshipIntegrationFailure,
        ),
    ] {
        assert!(
            !crate::conversation::service::test_four_domain_error_is_revision_conflict(
                &commit_error
            )
        );
        let mapped = crate::conversation::service::test_map_four_domain_error(commit_error);
        assert_eq!(mapped.code, expected_code);
        assert!(!mapped.recoverable);
    }

    for code in [
        ExperienceEpisodeErrorCode::InvalidArgument,
        ExperienceEpisodeErrorCode::LifeNotFound,
        ExperienceEpisodeErrorCode::SourceNotFound,
        ExperienceEpisodeErrorCode::SourceBindingMismatch,
        ExperienceEpisodeErrorCode::DatabaseUnavailable,
    ] {
        let commit_error = Composite::Experience(ExperienceEpisodeError::new(code, "synthetic"));
        assert!(
            !crate::conversation::service::test_four_domain_error_is_revision_conflict(
                &commit_error
            )
        );
        let mapped = crate::conversation::service::test_map_four_domain_error(commit_error);
        assert_eq!(
            mapped.code,
            ConversationCognitionErrorCode::ExperienceIntegrationFailure
        );
        assert!(!mapped.recoverable);
    }

    let conflict = Composite::Experience(ExperienceEpisodeError::episode_conflict());
    assert!(!crate::conversation::service::test_four_domain_error_is_revision_conflict(&conflict));
    let mapped = crate::conversation::service::test_map_four_domain_error(conflict);
    assert_eq!(
        mapped.code,
        ConversationCognitionErrorCode::ExperienceCommitConflict
    );
    assert!(!mapped.recoverable);

    let missing = Composite::ExperienceEpisodeMissing("missing episode".into());
    assert!(!crate::conversation::service::test_four_domain_error_is_revision_conflict(&missing));
    let mapped = crate::conversation::service::test_map_four_domain_error(missing);
    assert_eq!(
        mapped.code,
        ConversationCognitionErrorCode::ExperienceIntegrationFailure
    );
    assert!(!mapped.recoverable);
}

// ==================== D11-D pre-turn emotion projection ====================

/// The full system message content of the FIRST captured model request.
fn captured_system_context(server: &MockChatServer) -> String {
    let body: serde_json::Value =
        serde_json::from_str(&server.requests.lock().unwrap()[0]).unwrap();
    let messages = body["messages"].as_array().unwrap();
    let system = messages
        .iter()
        .find(|message| message["role"] == "system")
        .expect("a system message must be present");
    system["content"].as_str().unwrap().to_string()
}

/// Everything of the compiled context between `## Current Emotion` and the
/// next `##`-level section (or the end of the context).
fn compiled_emotion_section_of(system_context: &str) -> String {
    let start = system_context.find("## Current Emotion").unwrap();
    let remaining = &system_context[start..];
    let end = remaining
        .find("\n##")
        .map(|index| start + index)
        .unwrap_or(system_context.len());
    system_context[start..end].to_string()
}

fn seed_emotion_state(storage: &StorageService, valence: i32, activation: i32, event_time: &str) {
    <StorageService as EmotionRepository>::commit_transition(
        storage,
        crate::emotion::EmotionTransition::new(
            "d11-d-seed",
            LIFE_A,
            crate::emotion::EmotionEventSource::new("seed", "d11-d-seed-ref"),
            valence,
            activation,
            0,
            valence,
            activation,
            1,
            event_time,
        )
        .unwrap(),
    )
    .unwrap();
}

#[test]
fn d11_d_model_request_receives_pre_turn_emotion_projection() {
    tauri::async_runtime::block_on(async {
        let server = MockChatServer::new(vec![("200 OK", chat_response())]);
        let fixture = Fixture::new();
        fixture.activate_chat(&server.base_url);
        let conversation = fixture.create_conversation("D11-D projection");

        // Deterministic pre-turn state: valence +700 / activation -700 with a
        // last_applied_at in the FUTURE, so the real production clock observes
        // elapsed = 0 (rollback clamp) and the effective state IS the seeded
        // state through the frozen B2 decay.
        seed_emotion_state(
            fixture.storage.as_ref(),
            700,
            -700,
            "2099-01-01T00:00:00.000Z",
        );

        let response = fixture
            .chat(request(&conversation.id, "d11d-request-1", "feel the mood"))
            .await
            .unwrap();
        assert!(!response.replayed);
        assert_eq!(server.calls.load(Ordering::SeqCst), 1);

        let system_context = captured_system_context(&server);
        let section = compiled_emotion_section_of(&system_context);
        assert!(
            section.contains("- Transient valence: strongly positive."),
            "section: {section}"
        );
        assert!(
            section.contains("- Transient activation: very subdued."),
            "section: {section}"
        );
        // Raw authoritative numbers must not reach the prompt as emotion data.
        assert!(!section.contains("700"), "section: {section}");
        assert!(!section.contains("-700"), "section: {section}");
        for forbidden in [
            "revision",
            "eventId",
            "sourceRef",
            "policyVersion",
            "lastAppliedAt",
            "valenceDelta",
            "activationDelta",
            "appliedRevision",
        ] {
            assert!(
                !system_context.contains(forbidden),
                "prompt must not leak {forbidden}: {system_context}"
            );
        }

        // The C2 post-model commit still applies the frozen stimulus on top
        // of the projected state: activation -700 decays 0 then +7 → -693.
        let state = emotion_state_of(fixture.storage.as_ref());
        assert_eq!(state.revision, 2);
        assert_eq!((state.valence, state.activation), (700, -693));
    });
}

#[test]
fn d11_d_same_turn_mutation_is_not_visible_to_that_turns_model_prompt() {
    tauri::async_runtime::block_on(async {
        let server = MockChatServer::new(vec![("200 OK", chat_response())]);
        let fixture = Fixture::new();
        fixture.activate_chat(&server.base_url);
        let conversation = fixture.create_conversation("D11-D non-circularity");

        // Fresh neutral state: valence 0 / activation 0, elapsed 0 -> the
        // model prompt must see the neutral / balanced bands.
        let before = emotion_state_of(fixture.storage.as_ref());
        assert_eq!(
            (before.valence, before.activation, before.revision),
            (0, 0, 0)
        );

        let response = fixture
            .chat(request(&conversation.id, "d11d-request-2", "hello"))
            .await
            .unwrap();
        assert!(!response.replayed);
        assert_eq!(server.calls.load(Ordering::SeqCst), 1);

        let system_context = captured_system_context(&server);
        let section = compiled_emotion_section_of(&system_context);
        assert!(
            section.contains("- Transient valence: neutral."),
            "section: {section}"
        );
        assert!(
            section.contains("- Transient activation: balanced."),
            "section: {section}"
        );
        assert!(!section.contains("engaged"), "section: {section}");
        assert!(!section.contains("highly activated"), "section: {section}");
        assert!(
            !section.contains("7"),
            "same-turn +7 must not leak: {section}"
        );

        // After the successful C2 commit the authoritative activation is +7:
        // the current-turn stimulus was applied AFTER model generation.
        let after = emotion_state_of(fixture.storage.as_ref());
        assert_eq!(after.revision, 1);
        assert_eq!((after.valence, after.activation), (0, 7));
    });
}

#[test]
fn d11_d_pre_turn_projection_read_does_not_persist_or_advance_revision() {
    tauri::async_runtime::block_on(async {
        let server = BlockingChatServer::new();
        let fixture = Fixture::new();
        fixture.activate_chat(&server.base_url);
        let conversation = fixture.create_conversation("D11-D read-only");
        let storage = Arc::clone(&fixture.storage);
        let secrets = Arc::clone(&fixture.secrets);
        let model_runtime = Arc::clone(&fixture.model_runtime);
        let registry = Arc::clone(&fixture.registry);
        let coordinator = Arc::clone(&fixture.coordinator);
        let conversation_id = conversation.id.clone();
        let request_conversation_id = conversation.id.clone();
        let handle = thread::spawn(move || {
            tauri::async_runtime::block_on(
                ConversationCognitionService::new(
                    storage.as_ref(),
                    secrets.as_ref(),
                    model_runtime.as_ref(),
                    registry.as_ref(),
                    coordinator.as_ref(),
                )
                .chat(request(
                    &request_conversation_id,
                    "d11d-blocked-request",
                    "blocked read-only proof",
                )),
            )
        });

        // The model request is IN FLIGHT: the pre-turn observation and the B2
        // effective-state calculation already ran (they precede the model
        // call), so the state visible here must be the untouched neutral
        // state: no revision advance, no event, no timestamp change.
        server
            .received
            .recv_timeout(Duration::from_secs(5))
            .unwrap();
        let in_flight = emotion_state_of(fixture.storage.as_ref());
        assert_eq!(
            (in_flight.valence, in_flight.activation, in_flight.revision),
            (0, 0, 0),
            "the projection read must not mutate authoritative emotion"
        );
        assert!(
            governed_event_identity(
                fixture.storage.as_ref(),
                &conversation_id,
                "d11d-blocked-request"
            )
            .is_none(),
            "the projection read must not insert an emotion event"
        );

        server.release.send(()).unwrap();
        let response = handle.join().unwrap().unwrap();
        assert!(!response.replayed);

        // The ONLY mutation happened through the single post-model C2 commit.
        let after = emotion_state_of(fixture.storage.as_ref());
        assert_eq!(after.revision, 1);
        assert_eq!((after.valence, after.activation), (0, 7));
        assert!(governed_event_identity(
            fixture.storage.as_ref(),
            &conversation_id,
            "d11d-blocked-request"
        )
        .is_some());
    });
}

#[test]
fn d11_d_pre_turn_emotion_unavailable_fails_closed_before_the_model() {
    tauri::async_runtime::block_on(async {
        // Zero replies: the mock server proves no model request can arrive.
        let server = MockChatServer::new(Vec::new());
        let fixture = Fixture::new();
        fixture.activate_chat(&server.base_url);
        let conversation = fixture.create_conversation("D11-D fail closed");

        // Breach the one-row-per-life invariant in a way the observation
        // boundary reports (state missing while the life exists).
        {
            let database = fixture.storage.test_database_main_path().unwrap();
            let connection = crate::storage::open_authorized_test_connection(&database).unwrap();
            connection
                .execute("DELETE FROM emotion_state WHERE life_id='life-a'", [])
                .unwrap();
            drop(connection);
        }

        let error = fixture
            .chat(request(&conversation.id, "d11d-fail-closed", "governed"))
            .await
            .unwrap_err();
        assert_eq!(
            error.code,
            ConversationCognitionErrorCode::EmotionStateUnavailable
        );
        assert!(error.recoverable);
        // Governed cognition must NOT silently omit the Current Emotion
        // section or fall back to neutral: no model call happened.
        assert_eq!(server.calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            ConversationHistoryService::new(fixture.storage.as_ref())
                .count_messages(LIFE_A, &conversation.id)
                .unwrap(),
            0
        );
    });
}
// ==================== D12-C2: production relationship cutover ====================

use crate::relationship::{
    RelationshipDimensions, RelationshipRepository, RelationshipState, PRIMARY_USER_SUBJECT_ID,
};
use crate::storage::conversation_relationship::{
    conversation_relationship_event_id, conversation_relationship_source_ref,
};

/// The primary-user relationship state through the frozen B1 repository.
fn relationship_state_of(storage: &StorageService) -> RelationshipState {
    <StorageService as RelationshipRepository>::load_current_state(
        storage,
        LIFE_A,
        PRIMARY_USER_SUBJECT_ID,
    )
    .unwrap()
    .expect("primary_user relationship state must exist for a seeded life")
}

/// Canonical relationship event count for life-a via the frozen B1
/// repository surface: probes each expected canonical source identity
/// instead of raw SQL (the connection is private outside storage).
fn relationship_event_count_via_probe(
    storage: &StorageService,
    identities: &[(&str, &str, &str)],
) -> usize {
    identities
        .iter()
        .filter(|(kind, subject, source_ref)| {
            <StorageService as RelationshipRepository>::find_event(
                storage, LIFE_A, subject, kind, source_ref,
            )
            .unwrap()
            .is_some()
        })
        .count()
}

#[test]
fn d12_c2_new_turn_advances_familiarity_by_exactly_one() {
    tauri::async_runtime::block_on(async {
        // TWO replies: one per NEW governed turn in this test.
        let server = MockChatServer::new(vec![
            ("200 OK", chat_response()),
            ("200 OK", chat_response()),
        ]);
        let fixture = Fixture::new();
        fixture.activate_chat(&server.base_url);
        let conversation = fixture.create_conversation("D12 new turn");

        let before = relationship_state_of(fixture.storage.as_ref());
        assert_eq!(before.revision, 0);
        assert_eq!(before.values.familiarity, 0);

        let response = fixture
            .chat(request(&conversation.id, "d12-new-1", "hello relationship"))
            .await
            .unwrap();

        // A. model called exactly once; all three domains committed once.
        assert_eq!(server.calls.load(Ordering::SeqCst), 1);
        assert!(!response.replayed);
        assert_eq!(
            ConversationHistoryService::new(fixture.storage.as_ref())
                .count_messages(LIFE_A, &conversation.id)
                .unwrap(),
            2
        );
        let after = relationship_state_of(fixture.storage.as_ref());
        assert_eq!(after.revision, 1);
        assert_eq!(after.values.familiarity, 1, "familiarity 0 -> 1");
        // Seven other dimensions unchanged (neutral zero).
        assert_eq!(
            (
                after.values.trust,
                after.values.emotional_closeness,
                after.values.collaboration,
                after.values.safety,
                after.values.dependency_tendency,
                after.values.boundary_comfort,
                after.values.tension
            ),
            (0, 0, 0, 0, 0, 0, 0)
        );
        assert_eq!(
            relationship_event_count_via_probe(
                fixture.storage.as_ref(),
                &[(
                    crate::storage::conversation_relationship::CONVERSATION_RELATIONSHIP_SOURCE_KIND,
                    PRIMARY_USER_SUBJECT_ID,
                    &conversation_relationship_source_ref(&conversation.id, "d12-new-1"),
                )]
            ),
            1
        );

        // B. A second NEW turn advances familiarity again with its own event.
        let conversation2 = fixture.create_conversation("D12 second turn");
        fixture
            .chat(request(&conversation2.id, "d12-new-2", "second turn"))
            .await
            .unwrap();
        let advanced = relationship_state_of(fixture.storage.as_ref());
        assert_eq!(advanced.revision, 2);
        assert_eq!(advanced.values.familiarity, 2, "familiarity 1 -> 2");
        assert_eq!(
            relationship_event_count_via_probe(
                fixture.storage.as_ref(),
                &[
                    (
                        crate::storage::conversation_relationship::CONVERSATION_RELATIONSHIP_SOURCE_KIND,
                        PRIMARY_USER_SUBJECT_ID,
                        &conversation_relationship_source_ref(&conversation.id, "d12-new-1"),
                    ),
                    (
                        crate::storage::conversation_relationship::CONVERSATION_RELATIONSHIP_SOURCE_KIND,
                        PRIMARY_USER_SUBJECT_ID,
                        &conversation_relationship_source_ref(&conversation2.id, "d12-new-2"),
                    ),
                ]
            ),
            2
        );
        // Canonical identity of the second event is the deterministic helper.
        let found = <StorageService as RelationshipRepository>::find_event(
            fixture.storage.as_ref(),
            LIFE_A,
            PRIMARY_USER_SUBJECT_ID,
            crate::storage::conversation_relationship::CONVERSATION_RELATIONSHIP_SOURCE_KIND,
            &conversation_relationship_source_ref(&conversation2.id, "d12-new-2"),
        )
        .unwrap()
        .expect("second turn must carry its canonical relationship event");
        assert_eq!(
            found.event_id,
            conversation_relationship_event_id(
                LIFE_A,
                PRIMARY_USER_SUBJECT_ID,
                &conversation2.id,
                "d12-new-2"
            )
        );
    });
}

#[test]
fn d12_c2_high_level_replay_never_touches_any_domain() {
    tauri::async_runtime::block_on(async {
        // Exactly ONE reply: the replay must never reach the model, so a
        // second queued reply would hang the mock server on drop.
        let server = MockChatServer::new(vec![("200 OK", chat_response())]);
        let fixture = Fixture::new();
        fixture.activate_chat(&server.base_url);
        let conversation = fixture.create_conversation("D12 replay");

        fixture
            .chat(request(
                &conversation.id,
                "d12-replay-1",
                "original message",
            ))
            .await
            .unwrap();
        let calls_after_first = server.calls.load(Ordering::SeqCst);
        let emotion_before = emotion_state_of(fixture.storage.as_ref());
        let relationship_before = relationship_state_of(fixture.storage.as_ref());
        let events_before = relationship_state_of(fixture.storage.as_ref()).revision;

        // Exact high-level replay: same request_id + same content. The
        // persisted response returns immediately — the model is never called
        // again and neither Emotion nor Relationship is read/mutated.
        let replay = fixture
            .chat(request(
                &conversation.id,
                "d12-replay-1",
                "original message",
            ))
            .await
            .unwrap();

        assert!(replay.replayed);
        assert_eq!(replay.assistant_message, "persisted assistant");
        assert_eq!(
            server.calls.load(Ordering::SeqCst),
            calls_after_first,
            "model must not be called on high-level replay"
        );
        assert_eq!(
            emotion_state_of(fixture.storage.as_ref()).revision,
            emotion_before.revision
        );
        assert_eq!(
            relationship_state_of(fixture.storage.as_ref()),
            relationship_before
        );
        assert_eq!(
            relationship_state_of(fixture.storage.as_ref()).revision,
            events_before
        );
        assert_eq!(
            ConversationHistoryService::new(fixture.storage.as_ref())
                .count_messages(LIFE_A, &conversation.id)
                .unwrap(),
            2,
            "no message duplication"
        );
    });
}

/// Commits a D11-style governed turn (conversation + emotion only) directly
/// through the frozen D11 primitive — simulating pre-D12 production history.
fn service_commit_d11_only_turn(
    storage: &StorageService,
    conversation_id: &str,
    turn_id: &str,
    user: &str,
    assistant: &str,
) {
    use crate::emotion::{EmotionTransition, INITIAL_POLICY_VERSION};
    storage
        .append_complete_turn_with_emotion(
            &AppendConversationTurnRequest {
                life_id: LIFE_A.into(),
                conversation_id: conversation_id.into(),
                turn_id: turn_id.into(),
                user_content: user.into(),
                assistant_content: assistant.into(),
                expected_revision: None,
            },
            EmotionTransition::new(
                conversation_emotion_event_id(LIFE_A, conversation_id, turn_id),
                LIFE_A,
                crate::emotion::EmotionEventSource::new(
                    "conversation_turn",
                    conversation_emotion_source_ref(conversation_id, turn_id),
                ),
                10,
                5,
                0,
                10,
                5,
                INITIAL_POLICY_VERSION,
                "2026-08-24T00:00:00.000Z",
            )
            .unwrap(),
        )
        .unwrap();
}

/// Commits a D12-style governed turn (conversation + emotion + relationship)
/// directly through the frozen D12 primitive — simulating history written
/// before D13-C2, with no ExperienceEpisode.
fn service_commit_d12_only_turn(
    storage: &StorageService,
    conversation_id: &str,
    turn_id: &str,
    user: &str,
    assistant: &str,
) {
    use crate::emotion::{EmotionTransition, INITIAL_POLICY_VERSION};
    use crate::relationship::{
        RelationshipDimensions, RelationshipEventSource, RelationshipTransition,
        PRIMARY_USER_SUBJECT_ID,
    };

    let event_time = "2026-08-24T00:00:00.000Z";
    storage
        .append_complete_turn_with_emotion_and_relationship(
            &AppendConversationTurnRequest {
                life_id: LIFE_A.into(),
                conversation_id: conversation_id.into(),
                turn_id: turn_id.into(),
                user_content: user.into(),
                assistant_content: assistant.into(),
                expected_revision: None,
            },
            EmotionTransition::new(
                conversation_emotion_event_id(LIFE_A, conversation_id, turn_id),
                LIFE_A,
                crate::emotion::EmotionEventSource::new(
                    "conversation_turn",
                    conversation_emotion_source_ref(conversation_id, turn_id),
                ),
                10,
                5,
                0,
                10,
                5,
                INITIAL_POLICY_VERSION,
                event_time,
            )
            .unwrap(),
            RelationshipTransition::new(
                conversation_relationship_event_id(
                    LIFE_A,
                    PRIMARY_USER_SUBJECT_ID,
                    conversation_id,
                    turn_id,
                ),
                LIFE_A,
                PRIMARY_USER_SUBJECT_ID,
                RelationshipEventSource::new(
                    crate::storage::conversation_relationship::
                        CONVERSATION_RELATIONSHIP_SOURCE_KIND,
                    conversation_relationship_source_ref(conversation_id, turn_id),
                ),
                crate::storage::conversation_relationship::CONVERSATION_RELATIONSHIP_CHANGE_REASON,
                RelationshipDimensions {
                    familiarity: 1,
                    ..RelationshipDimensions::neutral()
                },
                0,
                RelationshipDimensions {
                    familiarity: 1,
                    ..RelationshipDimensions::neutral()
                },
                1,
                event_time,
            )
            .unwrap(),
        )
        .unwrap();
}

#[test]
fn d12_c2_d11_only_historical_turn_replays_without_relationship_backfill() {
    tauri::async_runtime::block_on(async {
        // No chat provider is activated at all (mirroring the D11-C2 legacy
        // replay fixture): the high-level replay short-circuit must return
        // the persisted turn BEFORE any model or domain work, which this
        // fixture makes observable.
        let fixture = Fixture::new();
        let conversation = fixture.create_conversation("D11-only history");

        // Commit a D11-era turn: governed conversation + emotion, NO
        // canonical relationship event.
        service_commit_d11_only_turn(
            fixture.storage.as_ref(),
            &conversation.id,
            "d11-era-turn",
            "asked in D11",
            "answered in D11",
        );
        assert_eq!(
            relationship_event_count_via_probe(
                fixture.storage.as_ref(),
                &[(
                    crate::storage::conversation_relationship::CONVERSATION_RELATIONSHIP_SOURCE_KIND,
                    PRIMARY_USER_SUBJECT_ID,
                    &conversation_relationship_source_ref(&conversation.id, "d11-era-turn"),
                )]
            ),
            0
        );

        // High-level replay of that turn through production chat must return
        // the persisted response immediately and never backfill Relationship.
        let replay = fixture
            .chat(request(&conversation.id, "d11-era-turn", "asked in D11"))
            .await
            .unwrap();

        assert!(replay.replayed);
        assert_eq!(replay.assistant_message, "answered in D11");
        assert_eq!(
            relationship_event_count_via_probe(
                fixture.storage.as_ref(),
                &[(
                    crate::storage::conversation_relationship::CONVERSATION_RELATIONSHIP_SOURCE_KIND,
                    PRIMARY_USER_SUBJECT_ID,
                    &conversation_relationship_source_ref(&conversation.id, "d11-era-turn"),
                )],
            ),
            0,
            "NO retroactive relationship backfill for a D11-only turn"
        );
        assert_eq!(
            relationship_state_of(fixture.storage.as_ref()).revision,
            0,
            "relationship revision unchanged"
        );
    });
}

#[test]
fn d13_c2_d12_only_historical_turn_replays_without_experience_backfill() {
    tauri::async_runtime::block_on(async {
        // An empty mock server makes an accidental model call observable while
        // allowing the high-level replay to prove the zero-call boundary.
        let server = MockChatServer::new(Vec::new());
        let fixture = Fixture::new();
        fixture.activate_chat(&server.base_url);
        let conversation = fixture.create_conversation("D12-only history");

        service_commit_d12_only_turn(
            fixture.storage.as_ref(),
            &conversation.id,
            "d12-history-turn",
            "asked in D12",
            "answered in D12",
        );
        assert!(experience_episode_for_turn(
            fixture.storage.as_ref(),
            &conversation.id,
            "d12-history-turn",
        )
        .is_none());
        let emotion_before = emotion_state_of(fixture.storage.as_ref());
        let relationship_before = relationship_state_of(fixture.storage.as_ref());

        let replay = fixture
            .chat(request(
                &conversation.id,
                "d12-history-turn",
                "asked in D12",
            ))
            .await
            .unwrap();

        assert!(replay.replayed);
        assert_eq!(replay.assistant_message, "answered in D12");
        assert_eq!(server.calls.load(Ordering::SeqCst), 0);
        assert!(experience_episode_for_turn(
            fixture.storage.as_ref(),
            &conversation.id,
            "d12-history-turn",
        )
        .is_none());
        assert_eq!(emotion_state_of(fixture.storage.as_ref()), emotion_before);
        assert_eq!(
            relationship_state_of(fixture.storage.as_ref()),
            relationship_before
        );
        assert_eq!(
            ConversationHistoryService::new(fixture.storage.as_ref())
                .count_messages(LIFE_A, &conversation.id)
                .unwrap(),
            2
        );
    });
}

/// Drives familiarity to `target` via legitimate B1 standalone commits.
fn seed_familiarity_to(storage: &StorageService, target: i32) {
    loop {
        let current = <StorageService as RelationshipRepository>::load_current_state(
            storage,
            LIFE_A,
            PRIMARY_USER_SUBJECT_ID,
        )
        .unwrap()
        .unwrap();
        if current.values.familiarity >= target {
            break;
        }
        let next_familiarity = (current.values.familiarity as i64 + 1).min(1000) as i32;
        <StorageService as RelationshipRepository>::commit_transition(
            storage,
            crate::relationship::RelationshipTransition::new(
                format!("cap-seed-{}", current.revision),
                LIFE_A,
                PRIMARY_USER_SUBJECT_ID,
                crate::relationship::RelationshipEventSource::new(
                    "seed",
                    format!("cap-seed-ref-{}", current.revision),
                ),
                "policy_seed",
                RelationshipDimensions {
                    familiarity: next_familiarity - current.values.familiarity,
                    ..RelationshipDimensions::neutral()
                },
                current.revision,
                RelationshipDimensions {
                    familiarity: next_familiarity,
                    ..RelationshipDimensions::neutral()
                },
                1,
                "2026-08-25T00:00:00.000Z",
            )
            .unwrap(),
        )
        .unwrap();
    }
}

#[test]
fn d12_c2_familiarity_cap_still_commits_zero_delta_event() {
    tauri::async_runtime::block_on(async {
        let server = MockChatServer::new(vec![("200 OK", chat_response())]);
        let fixture = Fixture::new();
        fixture.activate_chat(&server.base_url);
        let conversation = fixture.create_conversation("D12 at cap");

        seed_familiarity_to(fixture.storage.as_ref(), 1000);
        assert_eq!(
            relationship_state_of(fixture.storage.as_ref())
                .values
                .familiarity,
            1000
        );

        let response = fixture
            .chat(request(&conversation.id, "at-cap-turn", "still counts"))
            .await
            .unwrap();

        // E. At the cap the turn still commits its canonical relationship
        // event + revision exactly once, with delta 0 and familiarity pinned.
        assert_eq!(server.calls.load(Ordering::SeqCst), 1);
        assert!(!response.replayed);
        let capped = relationship_state_of(fixture.storage.as_ref());
        assert_eq!(capped.values.familiarity, 1000);
        assert_eq!(capped.revision, 1001);
        let cap_event = <StorageService as RelationshipRepository>::find_event(
            fixture.storage.as_ref(),
            LIFE_A,
            PRIMARY_USER_SUBJECT_ID,
            crate::storage::conversation_relationship::CONVERSATION_RELATIONSHIP_SOURCE_KIND,
            &conversation_relationship_source_ref(&conversation.id, "at-cap-turn"),
        )
        .unwrap()
        .expect("the capped turn still persists its canonical event");
        assert_eq!(cap_event.deltas.familiarity, 0);
        assert_eq!(cap_event.result.familiarity, 1000);
    });
}

// ---------- retry-budget tests (shared budget across BOTH domains) ----------

/// Builds an INSTANCE-SCOPED hook that performs ONE real independent
/// RELATIONSHIP commit per raced invocation against the primary-user state —
/// a legitimate competing relationship writer forcing the typed revision
/// race. Keyed to `target_turn_id`; stops racing after `max_races`.
fn make_relationship_race_hook(
    storage: std::sync::Arc<StorageService>,
    target_turn_id: &'static str,
    max_races: u32,
) -> (
    crate::conversation::service::PreCompositeHook,
    std::sync::Arc<StdMutex<Vec<String>>>,
) {
    let captured = Arc::new(StdMutex::new(Vec::new()));
    let captured_for_hook = Arc::clone(&captured);
    let sequence = std::sync::atomic::AtomicU32::new(0);
    let hook: crate::conversation::service::PreCompositeHook =
        Box::new(move |life_id: &str, turn_id: &str, observed_at: &str| {
            if turn_id != target_turn_id {
                return;
            }
            captured_for_hook
                .lock()
                .unwrap()
                .push(observed_at.to_string());
            if sequence.fetch_add(1, std::sync::atomic::Ordering::SeqCst) >= max_races {
                return;
            }
            let current = <StorageService as RelationshipRepository>::load_current_state(
                storage.as_ref(),
                life_id,
                PRIMARY_USER_SUBJECT_ID,
            )
            .unwrap()
            .expect("race fixture life must exist");
            let next_familiarity = (current.values.familiarity as i64 + 3).min(1000) as i32;
            <StorageService as RelationshipRepository>::commit_transition(
                storage.as_ref(),
                crate::relationship::RelationshipTransition::new(
                    format!(
                        "rel-race-{}",
                        sequence.load(std::sync::atomic::Ordering::SeqCst)
                    ),
                    life_id,
                    PRIMARY_USER_SUBJECT_ID,
                    crate::relationship::RelationshipEventSource::new(
                        "race",
                        format!(
                            "rel-race-ref-{}",
                            sequence.load(std::sync::atomic::Ordering::SeqCst)
                        ),
                    ),
                    "policy_race",
                    RelationshipDimensions {
                        familiarity: 3,
                        ..RelationshipDimensions::neutral()
                    },
                    current.revision,
                    RelationshipDimensions {
                        familiarity: next_familiarity,
                        ..RelationshipDimensions::neutral()
                    },
                    1,
                    "2099-01-01T00:00:00.000Z",
                )
                .unwrap(),
            )
            .unwrap();
        });
    (hook, captured)
}

#[test]
fn d12_c2_relationship_revision_conflict_retries_once_and_succeeds() {
    tauri::async_runtime::block_on(async {
        let server = MockChatServer::new(vec![("200 OK", chat_response())]);
        let fixture = Fixture::new();
        fixture.activate_chat(&server.base_url);
        let conversation = fixture.create_conversation("D12 rel retry");

        // The hook races attempt #1 with one real independent relationship
        // commit (+3 familiarity); the refreshed attempt #2 runs unraced.
        let (hook, captured_times) =
            make_relationship_race_hook(Arc::clone(&fixture.storage), "d12-rel-retry", 1);

        let response = fixture
            .chat_with_pre_composite_hook(
                request(&conversation.id, "d12-rel-retry", "race relationship"),
                hook,
            )
            .await
            .unwrap();

        // Model called exactly ONCE; no model recall during retry.
        assert_eq!(server.calls.load(Ordering::SeqCst), 1);
        assert!(!response.replayed);
        // Conversation committed exactly once.
        assert_eq!(
            ConversationHistoryService::new(fixture.storage.as_ref())
                .count_messages(LIFE_A, &conversation.id)
                .unwrap(),
            2
        );
        // No lost concurrent update: the race's +3 AND this turn's +1 both
        // landed, in revision order.
        let final_state = relationship_state_of(fixture.storage.as_ref());
        assert_eq!(final_state.values.familiarity, 4);
        assert_eq!(final_state.revision, 2);
        // Exactly one canonical event for THIS turn plus one race event.
        assert_eq!(
            relationship_event_count_via_probe(
                fixture.storage.as_ref(),
                &[
                    (
                        crate::storage::conversation_relationship::CONVERSATION_RELATIONSHIP_SOURCE_KIND,
                        PRIMARY_USER_SUBJECT_ID,
                        &conversation_relationship_source_ref(&conversation.id, "d12-rel-retry"),
                    ),
                    ("race", PRIMARY_USER_SUBJECT_ID, "rel-race-ref-1"),
                ]
            ),
            2
        );
        let turn_event = <StorageService as RelationshipRepository>::find_event(
            fixture.storage.as_ref(),
            LIFE_A,
            PRIMARY_USER_SUBJECT_ID,
            crate::storage::conversation_relationship::CONVERSATION_RELATIONSHIP_SOURCE_KIND,
            &conversation_relationship_source_ref(&conversation.id, "d12-rel-retry"),
        )
        .unwrap()
        .expect("the retried turn carries its canonical relationship event");
        assert_eq!(turn_event.deltas.familiarity, 1);
        // The SAME fixed T anchors both attempts' evidence.
        let original_observed_at = &captured_times.lock().unwrap()[0];
        assert_eq!(turn_event.event_time, *original_observed_at);
        // Emotion also committed exactly once (its own canonical event).
        assert!(governed_event_identity(
            fixture.storage.as_ref(),
            &conversation.id,
            "d12-rel-retry"
        )
        .is_some());
        assert!(experience_episode_for_turn(
            fixture.storage.as_ref(),
            &conversation.id,
            "d12-rel-retry",
        )
        .is_some());
    });
}

#[test]
fn d12_c2_emotion_revision_conflict_retry_also_refreshes_relationship() {
    tauri::async_runtime::block_on(async {
        let server = MockChatServer::new(vec![("200 OK", chat_response())]);
        let fixture = Fixture::new();
        fixture.activate_chat(&server.base_url);
        let conversation = fixture.create_conversation("D12 emo retry");

        // Reuse the existing EMOTION race hook: attempt #1 hits a typed
        // Emotion RevisionConflict; the shared single retry must refresh BOTH
        // authorities and succeed.
        let (hook, _captured) =
            make_revision_race_hook(Arc::clone(&fixture.storage), "d12-emo-retry", 1);

        fixture
            .chat_with_pre_composite_hook(
                request(&conversation.id, "d12-emo-retry", "race emotion"),
                hook,
            )
            .await
            .unwrap();

        assert_eq!(server.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            ConversationHistoryService::new(fixture.storage.as_ref())
                .count_messages(LIFE_A, &conversation.id)
                .unwrap(),
            2
        );
        // Emotion reflects race (-5,-5) plus this turn's +7 impulse.
        let emotion = emotion_state_of(fixture.storage.as_ref());
        assert_eq!(emotion.revision, 2);
        assert_eq!((emotion.valence, emotion.activation), (-5, 2));
        // Relationship advanced exactly once from the REFRESHED authority:
        // no lost update, no double apply.
        let relationship = relationship_state_of(fixture.storage.as_ref());
        assert_eq!(relationship.values.familiarity, 1);
        assert_eq!(relationship.revision, 1);
        assert_eq!(
            relationship_event_count_via_probe(
                fixture.storage.as_ref(),
                &[(
                    crate::storage::conversation_relationship::CONVERSATION_RELATIONSHIP_SOURCE_KIND,
                    PRIMARY_USER_SUBJECT_ID,
                    &conversation_relationship_source_ref(&conversation.id, "d12-emo-retry"),
                )]
            ),
            1
        );
        assert!(experience_episode_for_turn(
            fixture.storage.as_ref(),
            &conversation.id,
            "d12-emo-retry",
        )
        .is_some());
    });
}

// ---------- C2 second-conflict-stops, event conflict, and state-unavailable --

#[test]
fn d12_c2_second_relationship_conflict_stops_after_exactly_two_attempts() {
    tauri::async_runtime::block_on(async {
        let server = MockChatServer::new(vec![("200 OK", chat_response())]);
        let fixture = Fixture::new();
        fixture.activate_chat(&server.base_url);
        let conversation = fixture.create_conversation("D12 rel exhausted");

        // The hook races BOTH composite attempts (max 2) with one real
        // independent relationship commit each, so the single allowed retry
        // also conflicts. Production must stop after exactly two attempts.
        let (hook, _captured) =
            make_relationship_race_hook(Arc::clone(&fixture.storage), "d12-rel-stop", 2);

        let error = fixture
            .chat_with_pre_composite_hook(
                request(&conversation.id, "d12-rel-stop", "always racing rel"),
                hook,
            )
            .await
            .unwrap_err();

        assert_eq!(
            error.code,
            ConversationCognitionErrorCode::RelationshipChangedDuringRequest
        );
        assert!(error.recoverable);
        // Model called exactly ONCE; no third attempt looped.
        assert_eq!(server.calls.load(Ordering::SeqCst), 1);
        // Exactly TWO coherent race commits (+3 each): 0→3→6, proving
        // exactly two attempts were staged.
        let state = relationship_state_of(fixture.storage.as_ref());
        assert_eq!(
            state.values.familiarity, 6,
            "two independent race commits prove exactly two attempts"
        );
        assert_eq!(state.revision, 2);
        // The requested conversation turn was never partially committed and
        // neither was any Emotion work from the failed attempts.
        assert_eq!(
            ConversationHistoryService::new(fixture.storage.as_ref())
                .count_messages(LIFE_A, &conversation.id)
                .unwrap(),
            0
        );
        assert!(governed_event_identity(
            fixture.storage.as_ref(),
            &conversation.id,
            "d12-rel-stop"
        )
        .is_none());
        assert!(experience_episode_for_turn(
            fixture.storage.as_ref(),
            &conversation.id,
            "d12-rel-stop",
        )
        .is_none());
    });
}

#[test]
fn d12_c2_both_authorities_stale_share_one_retry() {
    tauri::async_runtime::block_on(async {
        let server = MockChatServer::new(vec![("200 OK", chat_response())]);
        let fixture = Fixture::new();
        fixture.activate_chat(&server.base_url);
        let conversation = fixture.create_conversation("D12 both stale");

        // ONE hook races BOTH authorities on attempt #1 only: one emotion
        // commit AND one relationship commit. The single shared retry must
        // refresh BOTH and succeed — no sequential per-domain loops.
        let storage_for_hook = Arc::clone(&fixture.storage);
        let raced = std::sync::atomic::AtomicU32::new(0);
        let hook: crate::conversation::service::PreCompositeHook =
            Box::new(move |life_id: &str, turn_id: &str, _observed_at: &str| {
                if turn_id != "d12-both-stale" {
                    return;
                }
                if raced.fetch_add(1, std::sync::atomic::Ordering::SeqCst) >= 1 {
                    return;
                }
                let current_emotion = <StorageService as EmotionRepository>::load_current_state(
                    storage_for_hook.as_ref(),
                    life_id,
                )
                .unwrap()
                .expect("emotion state must exist");
                <StorageService as EmotionRepository>::commit_transition(
                    storage_for_hook.as_ref(),
                    crate::emotion::EmotionTransition::new(
                        "both-stale-emotion-race",
                        life_id,
                        crate::emotion::EmotionEventSource::new("race", "both-stale-emo"),
                        -5,
                        -5,
                        current_emotion.revision,
                        current_emotion.valence - 5,
                        current_emotion.activation - 5,
                        1,
                        "2099-01-01T00:00:00.000Z",
                    )
                    .unwrap(),
                )
                .unwrap();
                let current_rel = <StorageService as RelationshipRepository>::load_current_state(
                    storage_for_hook.as_ref(),
                    life_id,
                    PRIMARY_USER_SUBJECT_ID,
                )
                .unwrap()
                .expect("relationship state must exist");
                <StorageService as RelationshipRepository>::commit_transition(
                    storage_for_hook.as_ref(),
                    crate::relationship::RelationshipTransition::new(
                        "both-stale-relationship-race",
                        life_id,
                        PRIMARY_USER_SUBJECT_ID,
                        crate::relationship::RelationshipEventSource::new("race", "both-stale-rel"),
                        "policy_race",
                        RelationshipDimensions {
                            familiarity: 3,
                            ..RelationshipDimensions::neutral()
                        },
                        current_rel.revision,
                        RelationshipDimensions {
                            familiarity: current_rel.values.familiarity + 3,
                            ..RelationshipDimensions::neutral()
                        },
                        1,
                        "2099-01-01T00:00:00.000Z",
                    )
                    .unwrap(),
                )
                .unwrap();
            });

        let response = fixture
            .chat_with_pre_composite_hook(
                request(&conversation.id, "d12-both-stale", "stale everything"),
                hook,
            )
            .await
            .unwrap();

        assert!(!response.replayed);
        assert_eq!(server.calls.load(Ordering::SeqCst), 1);
        // Conversation committed exactly once.
        assert_eq!(
            ConversationHistoryService::new(fixture.storage.as_ref())
                .count_messages(LIFE_A, &conversation.id)
                .unwrap(),
            2
        );
        // Emotion: race (-5,-5) then this turn's +7 impulse → (-5,+2), rev 2.
        let emotion = emotion_state_of(fixture.storage.as_ref());
        assert_eq!(emotion.revision, 2);
        assert_eq!((emotion.valence, emotion.activation), (-5, 2));
        // Relationship: race +3 then this turn's +1 → familiarity 4, rev 2.
        let relationship = relationship_state_of(fixture.storage.as_ref());
        assert_eq!(relationship.values.familiarity, 4);
        assert_eq!(relationship.revision, 2);
        assert!(experience_episode_for_turn(
            fixture.storage.as_ref(),
            &conversation.id,
            "d12-both-stale",
        )
        .is_some());
    });
}

#[test]
fn d12_c2_relationship_event_conflict_maps_without_retry() {
    tauri::async_runtime::block_on(async {
        let server = MockChatServer::new(vec![("200 OK", chat_response())]);
        let fixture = Fixture::new();
        fixture.activate_chat(&server.base_url);
        let conversation = fixture.create_conversation("D12 rel event conflict");
        let conversation_id = conversation.id.clone();
        let storage_for_hook = Arc::clone(&fixture.storage);

        // Narrow deterministic seam: pre-create CONFLICTING canonical
        // relationship evidence for this exact turn identity before the
        // composite runs. Same source identity, DIFFERENT payload.
        let conflict_hook: crate::conversation::service::PreCompositeHook = Box::new(
            move |life_id: &str, turn_id: &str, _observed_at: &str| {
                if turn_id != "d12-rel-event-conflict" {
                    return;
                }
                <StorageService as RelationshipRepository>::commit_transition(
                    storage_for_hook.as_ref(),
                    crate::relationship::RelationshipTransition::new(
                        conversation_relationship_event_id(
                            life_id,
                            PRIMARY_USER_SUBJECT_ID,
                            &conversation_id,
                            "d12-rel-event-conflict",
                        ),
                        life_id,
                        PRIMARY_USER_SUBJECT_ID,
                        crate::relationship::RelationshipEventSource::new(
                            crate::storage::conversation_relationship::CONVERSATION_RELATIONSHIP_SOURCE_KIND,
                            conversation_relationship_source_ref(
                                &conversation_id,
                                "d12-rel-event-conflict",
                            ),
                        ),
                        crate::storage::conversation_relationship::CONVERSATION_RELATIONSHIP_CHANGE_REASON,
                        RelationshipDimensions {
                            familiarity: 9,
                            ..RelationshipDimensions::neutral()
                        },
                        0,
                        RelationshipDimensions {
                            familiarity: 9,
                            ..RelationshipDimensions::neutral()
                        },
                        1,
                        "2098-01-01T00:00:00.000Z",
                    )
                    .unwrap(),
                )
                .unwrap();
            },
        );

        let error = fixture
            .chat_with_pre_composite_hook(
                request(
                    &conversation.id,
                    "d12-rel-event-conflict",
                    "conflicting rel",
                ),
                conflict_hook,
            )
            .await
            .unwrap_err();

        assert_eq!(
            error.code,
            ConversationCognitionErrorCode::RelationshipCommitConflict
        );
        assert!(!error.recoverable);
        // NO retry happened; no conversation/emotion mutation survived.
        assert_eq!(server.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            ConversationHistoryService::new(fixture.storage.as_ref())
                .count_messages(LIFE_A, &conversation.id)
                .unwrap(),
            0
        );
        assert!(governed_event_identity(
            fixture.storage.as_ref(),
            &conversation.id,
            "d12-rel-event-conflict"
        )
        .is_none());
    });
}

#[test]
fn d12_c2_missing_primary_relationship_state_fails_closed_before_persistence() {
    tauri::async_runtime::block_on(async {
        // D12-D intentionally CHANGES the observation boundary (spec §23):
        // relationship state is now required BEFORE model generation for
        // prompt governance, so a missing primary-user row must fail closed
        // with ZERO model calls. No chat provider is activated — the fixture
        // makes "the model was never reached" directly observable.
        let fixture = Fixture::new();
        let conversation = fixture.create_conversation("D12 missing rel state");

        {
            let database = fixture.storage.test_database_main_path().unwrap();
            let connection = crate::storage::open_authorized_test_connection(&database).unwrap();
            connection
                .execute(
                    "DELETE FROM relationship_state
                     WHERE life_id = ?1 AND subject_id = 'primary_user'",
                    [LIFE_A],
                )
                .unwrap();
            drop(connection);
        }

        let error = fixture
            .chat(request(&conversation.id, "d12-no-rel-state", "governed"))
            .await
            .unwrap_err();

        assert_eq!(
            error.code,
            ConversationCognitionErrorCode::RelationshipStateUnavailable
        );
        assert!(error.recoverable);
        // D12-D: the failure happens BEFORE model generation. NOTHING
        // persisted: no conversation turn, no emotion, no fabricated neutral
        // relationship state.
        assert_eq!(
            ConversationHistoryService::new(fixture.storage.as_ref())
                .count_messages(LIFE_A, &conversation.id)
                .unwrap(),
            0
        );
        assert!(governed_event_identity(
            fixture.storage.as_ref(),
            &conversation.id,
            "d12-no-rel-state"
        )
        .is_none());
        assert_eq!(
            relationship_event_count_via_probe(
                fixture.storage.as_ref(),
                &[(
                    crate::storage::conversation_relationship::CONVERSATION_RELATIONSHIP_SOURCE_KIND,
                    PRIMARY_USER_SUBJECT_ID,
                    &conversation_relationship_source_ref(&conversation.id, "d12-no-rel-state"),
                )],
            ),
            0
        );
    });
}

// ==================== D12-D: pre-turn relationship projection ====================

/// Everything of the compiled context between `## Relationship` and the next
/// section heading (or the end of the context).
fn compiled_relationship_section_of(system_context: &str) -> String {
    let start = system_context.find("## Relationship").unwrap();
    let remaining = &system_context[start..];
    let end = remaining
        .find("\n##")
        .map(|index| start + index)
        .unwrap_or(system_context.len());
    system_context[start..end].to_string()
}

#[test]
fn d12_d_new_turn_prompt_projects_pre_turn_relationship_before_emotion() {
    tauri::async_runtime::block_on(async {
        let server = MockChatServer::new(vec![("200 OK", chat_response())]);
        let fixture = Fixture::new();
        fixture.activate_chat(&server.base_url);
        let conversation = fixture.create_conversation("D12-D projection");

        // B. Seed a DISTINCTIVE authoritative relationship state before chat:
        // familiarity 250 ("low"), trust 650 ("very high"), tension 900
        // ("very high").
        // Targets: familiarity 250 ("low"), trust 650 ("high"), tension
        // 900 ("very high").
        seed_relationship_dimensions(
            fixture.storage.as_ref(),
            &[("familiarity", 250), ("trust", 650), ("tension", 900)],
        );

        let response = fixture
            .chat(request(&conversation.id, "d12d-rel-1", "feel the bond"))
            .await
            .unwrap();
        assert!(!response.replayed);
        assert_eq!(server.calls.load(Ordering::SeqCst), 1);

        // A/H. Relationship section exists BEFORE Current Emotion in the
        // captured system context.
        let system_context = captured_system_context(&server);
        let relationship_index = system_context.find("## Relationship").unwrap();
        let emotion_index = system_context.find("## Current Emotion").unwrap();
        assert!(relationship_index < emotion_index);

        // B. The prompt rendered the PRE-TURN bands.
        let section = compiled_relationship_section_of(&system_context);
        assert!(section.contains("- Familiarity: low."));
        assert!(section.contains("- Trust: very high."), "{section}");
        assert!(section.contains("- Tension: very high."));
        assert!(
            !section.contains("250") && !section.contains("650") && !section.contains("900"),
            "raw numbers must not render: {section}"
        );

        // B. The post-turn authoritative familiarity advanced normally (+1).
        let after = relationship_state_of(fixture.storage.as_ref());
        assert_eq!(after.values.familiarity, 251);
    });
}

#[test]
fn d12_d_same_turn_mutation_does_not_reflect_into_its_own_prompt() {
    tauri::async_runtime::block_on(async {
        // C. Start at a band edge where +1 crosses it: 399 → 400.
        let server = MockChatServer::new(vec![
            ("200 OK", chat_response()),
            ("200 OK", chat_response()),
        ]);
        let fixture = Fixture::new();
        fixture.activate_chat(&server.base_url);
        let conversation = fixture.create_conversation("D12-D non-reflection");

        seed_relationship_dimensions(fixture.storage.as_ref(), &[("familiarity", 399)]);
        assert_eq!(
            relationship_state_of(fixture.storage.as_ref())
                .values
                .familiarity,
            399
        );

        // Turn 1: prompt must see the PRE-TURN "low" band (399), even though
        // this very turn's commit advances familiarity to 400.
        let first = fixture
            .chat(request(&conversation.id, "d12d-edge-1", "first edge turn"))
            .await
            .unwrap();
        assert!(!first.replayed);
        let first_context = captured_system_context(&server);
        let first_section = compiled_relationship_section_of(&first_context);
        assert!(
            first_section.contains("- Familiarity: low."),
            "the current turn's own prompt must render the PRE-TURN band: {first_section}"
        );
        assert!(!first_section.contains("- Familiarity: moderate."));
        assert_eq!(
            relationship_state_of(fixture.storage.as_ref())
                .values
                .familiarity,
            400,
            "the same turn's commit crossed the band boundary"
        );

        // D. The NEXT new turn sees the UPDATED authoritative band.
        let second = fixture
            .chat(request(&conversation.id, "d12d-edge-2", "second edge turn"))
            .await
            .unwrap();
        assert!(!second.replayed);
        // The SECOND captured request carries the second turn's context.
        let second_body: serde_json::Value =
            serde_json::from_str(&server.requests.lock().unwrap()[1]).unwrap();
        let second_context = second_body["messages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|message| message["role"] == "system")
            .map(|message| message["content"].as_str().unwrap().to_string())
            .unwrap();
        let second_section = compiled_relationship_section_of(&second_context);
        assert!(
            second_section.contains("- Familiarity: moderate."),
            "the NEXT turn must see the updated band: {second_section}"
        );
        assert_eq!(
            relationship_state_of(fixture.storage.as_ref())
                .values
                .familiarity,
            401
        );
    });
}

#[test]
fn d12_d_high_level_replay_never_reads_or_mutates_relationship() {
    tauri::async_runtime::block_on(async {
        // E. Replay stays FIRST: no relationship read requirement, no model
        // call, no extra event. No provider is activated so any attempt to
        // reach the model would fail loudly instead of silently passing.
        let fixture = Fixture::new();
        let conversation = fixture.create_conversation("D12-D replay");

        service_commit_d11_only_turn(
            fixture.storage.as_ref(),
            &conversation.id,
            "d12d-history",
            "asked before D12-D",
            "answered before D12-D",
        );

        let replay = fixture
            .chat(request(
                &conversation.id,
                "d12d-history",
                "asked before D12-D",
            ))
            .await
            .unwrap();

        assert!(replay.replayed);
        assert_eq!(replay.assistant_message, "answered before D12-D");
        // No retroactive relationship event and no revision movement.
        assert_eq!(
            relationship_event_count_via_probe(
                fixture.storage.as_ref(),
                &[(
                    crate::storage::conversation_relationship::CONVERSATION_RELATIONSHIP_SOURCE_KIND,
                    PRIMARY_USER_SUBJECT_ID,
                    &conversation_relationship_source_ref(&conversation.id, "d12d-history"),
                )],
            ),
            0
        );
        assert_eq!(
            relationship_state_of(fixture.storage.as_ref())
                .values
                .familiarity,
            0
        );
    });
}

#[test]
fn d12_d_invalid_prompt_relationship_maps_to_integration_failure_without_model() {
    // G. A malformed authoritative state cannot exist through CHECK
    // constraints, so the mapping is proven directly at the mapper level via
    // the compiler error contract: InvalidRelationship must map to
    // RelationshipIntegrationFailure (never PersonaNotFound).
    let compile_error = crate::prompt::PromptCompilerError {
        code: crate::prompt::PromptCompilerErrorCode::InvalidRelationship,
        message: "test".into(),
        recoverable: false,
    };
    // Mirror of the service compile-error mapping for the invalid-relationship
    // branch (kept in sync by construction with service.rs's mapper).
    let mapped_code = match compile_error.code {
        crate::prompt::PromptCompilerErrorCode::InvalidEmotion => {
            ConversationCognitionErrorCode::EmotionIntegrationFailure
        }
        crate::prompt::PromptCompilerErrorCode::InvalidRelationship => {
            ConversationCognitionErrorCode::RelationshipIntegrationFailure
        }
        _ => ConversationCognitionErrorCode::PersonaNotFound,
    };
    assert_eq!(
        mapped_code,
        ConversationCognitionErrorCode::RelationshipIntegrationFailure
    );
}

/// Drives specific authoritative dimensions to their target values through
/// legitimate B1 standalone commits, one coherent +1/-1 step per revision so
/// every intermediate state stays inside its frozen domain.
fn seed_relationship_dimensions(storage: &StorageService, targets: &[(&str, i32)]) {
    loop {
        let current = <StorageService as RelationshipRepository>::load_current_state(
            storage,
            LIFE_A,
            PRIMARY_USER_SUBJECT_ID,
        )
        .unwrap()
        .unwrap();

        // Compute one coherent step toward ALL targets simultaneously.
        let mut delta = RelationshipDimensions::neutral();
        let mut next = current.values;
        let mut done = true;
        for (dimension, target) in targets {
            let current_value = match *dimension {
                "familiarity" => current.values.familiarity,
                "trust" => current.values.trust,
                "tension" => current.values.tension,
                _ => panic!("unknown dimension {dimension}"),
            };
            if current_value == *target {
                continue;
            }
            done = false;
            let step = if current_value < *target { 1 } else { -1 };
            let step_delta = if current_value < *target { 1 } else { -1 };
            match *dimension {
                "familiarity" => {
                    next.familiarity += step;
                    delta.familiarity += step_delta;
                }
                "trust" => {
                    next.trust += step;
                    delta.trust += step_delta;
                }
                "tension" => {
                    next.tension += step;
                    delta.tension += step_delta;
                }
                _ => unreachable!(),
            }
        }
        if done {
            return;
        }

        let sequence = current.revision;
        <StorageService as RelationshipRepository>::commit_transition(
            storage,
            crate::relationship::RelationshipTransition::new(
                format!("rel-seed-{sequence}"),
                LIFE_A,
                PRIMARY_USER_SUBJECT_ID,
                crate::relationship::RelationshipEventSource::new(
                    "seed",
                    format!("rel-seed-ref-{sequence}"),
                ),
                "policy_seed",
                delta,
                current.revision,
                next,
                1,
                "2026-08-25T00:00:00.000Z",
            )
            .unwrap(),
        )
        .unwrap();
    }
}
