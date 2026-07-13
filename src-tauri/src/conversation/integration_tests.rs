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
