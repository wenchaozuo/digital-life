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
            AppendConversationTurnRequest, ConversationHistoryService, ConversationRole,
            CreateConversationCommandRequest, CreateConversationRequest,
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

use crate::emotion::{EmotionRepository, EmotionState};
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
            emotion_state_of(fixture.storage.as_ref()),
            state_after_first
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
