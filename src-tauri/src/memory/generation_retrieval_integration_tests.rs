use std::{
    future::Future,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::Path,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};

use rusqlite::params;
use tempfile::TempDir;

use crate::{
    memory::{
        context_builder::{
            MemoryContextBuildRequest, MemoryContextBuilder, MemoryContextEntry,
            MemoryContextSource, MAX_INJECTED_MEMORIES, MAX_MEMORY_CHARACTERS,
            MAX_RETRIEVAL_CANDIDATES, MEMORY_CONTEXT_CHARACTER_BUDGET,
        },
        existing_generation_binding::{
            compute_canonical_generation_descriptor, D9D2_GENERATION_DESCRIPTOR_VERSION,
        },
        retrieval_router::{RetrievalCandidate, RetrievalSource},
        retrieval_runtime::{
            GenerationAwareSemanticRetrieval, GovernedRetrievalRequest,
            MemoryRetrievalRuntimeService, RetrievalAvailability, RetrievalDegradationCode,
            RetrievalRuntimeErrorCode,
        },
        revisions::{
            DeleteMemoryPermanentlyRequest, MemoryRevisionService, SetMemorySensitivityRequest,
            UpdateConfirmedMemoryRequest,
        },
        vector_index::{canonical_index_text, canonical_memory_index_hash},
        MemoryKind, MemoryRecord,
    },
    model::{
        profile::{
            CreateModelProfileRequest, ModelProfile, ModelProfileService, ModelProviderKind,
            ModelPurpose, SetActiveModelProfileRequest,
        },
        runtime::ModelRuntimeCoordinator,
        transport::url_policy::validate_and_normalize_url,
    },
    secrets::{InMemorySecretStore, SecretIdentifier, SecretPurpose, SecretStore, SecretValue},
    storage::{
        open_authorized_test_connection, LifeIdentityRecord, PersonaTemplateRecord, StorageService,
    },
    vector_store::{
        generation_store_root, GenerationVectorRecord, LanceDbVectorStoreRegistry,
        VectorGenerationContext, VectorGenerationId, VectorRecord, VectorStore,
    },
};

const LIFE_ID: &str = "life-d10d";
const MODEL_NAME: &str = "test-embedding-model";
const DIMENSION: usize = 2;

fn block_on<T>(future: impl Future<Output = T>) -> T {
    tauri::async_runtime::block_on(future)
}

struct RetrievalFixture {
    _temp: TempDir,
    storage: StorageService,
    secrets: InMemorySecretStore,
    coordinator: ModelRuntimeCoordinator,
    registry: LanceDbVectorStoreRegistry,
    p1_server: EmbeddingServer,
    p2_server: EmbeddingServer,
    p1: ModelProfile,
    p2: ModelProfile,
}

impl RetrievalFixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let storage =
            StorageService::initialize_with_roots(temp.path().join("data"), None).unwrap();
        storage
            .save_persona(PersonaTemplateRecord {
                id: "persona-d10d".into(),
                name: "D10-D integration persona".into(),
                version: 1,
                persona_json: r#"{"id":"persona-d10d","version":1}"#.into(),
            })
            .unwrap();
        storage
            .save_life(LifeIdentityRecord {
                id: LIFE_ID.into(),
                name: "D10-D integration life".into(),
                created_at: "2026-08-22T00:00:00.000Z".into(),
                version: 1,
                body_id: "test-body".into(),
                persona_id: "persona-d10d".into(),
                persona_version: 1,
            })
            .unwrap();

        let p1_server = EmbeddingServer::new(vec![1.0, 0.0]);
        let p2_server = EmbeddingServer::new(vec![0.0, 1.0]);
        let profiles = ModelProfileService::new(&storage);
        let p1 = create_embedding_profile(&profiles, &p1_server.base_url, "Bound P1");
        let p2 = create_embedding_profile(&profiles, &p2_server.base_url, "Active P2");
        profiles
            .set_active(SetActiveModelProfileRequest {
                purpose: ModelPurpose::Embedding,
                profile_id: p2.id.clone(),
            })
            .unwrap();

        let secrets = InMemorySecretStore::new();
        seed_embedding_secret(&secrets, &p1.id);
        seed_embedding_secret(&secrets, &p2.id);

        Self {
            _temp: temp,
            storage,
            secrets,
            coordinator: ModelRuntimeCoordinator::default(),
            registry: LanceDbVectorStoreRegistry::default(),
            p1_server,
            p2_server,
            p1,
            p2,
        }
    }

    fn memory(&self, content: &str, summary: Option<&str>) -> MemoryRecord {
        crate::storage::test_support::insert_confirmed_memory_fixture(
            &self.storage,
            LIFE_ID,
            "fact",
            content,
            summary,
            0.8,
            0.9,
            false,
            false,
        )
    }

    async fn install_generation(
        &self,
        generation_id: &str,
        memory: &MemoryRecord,
        revision: i64,
        content_hash: &str,
    ) -> VectorGenerationContext {
        let context = generation_context(&self.p1, generation_id);
        install_active_generation(&self.storage, &context, &self.p1.id);
        seed_generation(
            &self.storage,
            &self.registry,
            &context,
            generation_record(&context, memory, revision, content_hash),
        )
        .await;
        context
    }

    async fn retrieve(
        &self,
        life_id: &str,
        query: &str,
    ) -> Result<
        crate::memory::retrieval_runtime::GovernedRetrievalResult,
        crate::memory::retrieval_runtime::RetrievalRuntimeError,
    > {
        let runtime = crate::model::runtime::ModelRuntimeService::new(
            &self.storage,
            &self.secrets,
            &self.coordinator,
        );
        let semantic =
            GenerationAwareSemanticRetrieval::new(&self.storage, &runtime, &self.registry);
        let service = MemoryRetrievalRuntimeService::new(&self.storage, &semantic);
        service
            .retrieve(GovernedRetrievalRequest {
                life_id: life_id.into(),
                query: query.into(),
                memory_kind_filter: None,
            })
            .await
    }
}

fn create_embedding_profile(
    profiles: &ModelProfileService<'_, StorageService>,
    base_url: &str,
    display_name: &str,
) -> ModelProfile {
    profiles
        .create(CreateModelProfileRequest {
            purpose: ModelPurpose::Embedding,
            provider_kind: ModelProviderKind::OpenaiCompatible,
            display_name: display_name.into(),
            base_url: base_url.into(),
            model_name: MODEL_NAME.into(),
            temperature: None,
            max_tokens: None,
            embedding_dimension: Some(DIMENSION as u32),
        })
        .unwrap()
}

fn seed_embedding_secret(secrets: &InMemorySecretStore, profile_id: &str) {
    secrets
        .set_secret(
            &SecretIdentifier::new(SecretPurpose::EmbeddingModelApiKey, profile_id).unwrap(),
            SecretValue::new("d10d-loopback-placeholder".into()).unwrap(),
        )
        .unwrap();
}

fn generation_context(profile: &ModelProfile, generation_id: &str) -> VectorGenerationContext {
    let target = validate_and_normalize_url(&profile.base_url).unwrap();
    let descriptor = compute_canonical_generation_descriptor(
        &profile.provider_kind,
        &profile.id,
        &target,
        &profile.model_name,
        DIMENSION,
    )
    .unwrap();
    VectorGenerationContext::new(
        VectorGenerationId::parse(generation_id).unwrap(),
        descriptor,
        DIMENSION,
    )
    .unwrap()
}

fn install_active_generation(
    storage: &StorageService,
    context: &VectorGenerationContext,
    profile_id: &str,
) {
    let connection =
        open_authorized_test_connection(&storage.test_database_main_path().unwrap()).unwrap();
    connection
        .execute(
            "INSERT INTO memory_vector_generation
             (generation_id,descriptor_hash,dimension,state,authority_epoch)
             VALUES (?1,?2,?3,'active',1)",
            params![
                context.generation_id().as_str(),
                context.descriptor_hash(),
                context.dimension() as i64
            ],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO memory_vector_generation_binding
             (generation_id,descriptor_version,embedding_profile_id,created_at)
             VALUES (?1,?2,?3,'2026-08-22T00:00:00.000Z')",
            params![
                context.generation_id().as_str(),
                D9D2_GENERATION_DESCRIPTOR_VERSION,
                profile_id
            ],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO memory_vector_generation_store_witness
             (generation_id,create_operation_id,state,last_error_code,updated_at)
             VALUES (?1,NULL,'ready',NULL,'2026-08-22T00:00:00.000Z')",
            [context.generation_id().as_str()],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE memory_vector_generation_authority
             SET active_generation_id=?1,updated_at='2026-08-22T00:00:00.000Z'
             WHERE singleton=1",
            [context.generation_id().as_str()],
        )
        .unwrap();
}

fn install_ready_generation(
    storage: &StorageService,
    context: &VectorGenerationContext,
    profile_id: &str,
) {
    let connection =
        open_authorized_test_connection(&storage.test_database_main_path().unwrap()).unwrap();
    connection
        .execute(
            "INSERT INTO memory_vector_generation
             (generation_id,descriptor_hash,dimension,state,authority_epoch)
             VALUES (?1,?2,?3,'building',2)",
            params![
                context.generation_id().as_str(),
                context.descriptor_hash(),
                context.dimension() as i64
            ],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO memory_vector_generation_binding
             (generation_id,descriptor_version,embedding_profile_id,created_at)
             VALUES (?1,?2,?3,'2026-08-22T00:00:00.000Z')",
            params![
                context.generation_id().as_str(),
                D9D2_GENERATION_DESCRIPTOR_VERSION,
                profile_id
            ],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO memory_vector_generation_store_witness
             (generation_id,create_operation_id,state,last_error_code,updated_at)
             VALUES (?1,NULL,'ready',NULL,'2026-08-22T00:00:00.000Z')",
            [context.generation_id().as_str()],
        )
        .unwrap();
}

fn promote_generation(database: &Path, old_id: &str, new_id: &str) {
    let connection = open_authorized_test_connection(database).unwrap();
    connection
        .execute_batch(&format!(
            "UPDATE memory_vector_generation_authority
             SET active_generation_id=NULL,updated_at='2026-08-22T00:00:00.000Z'
             WHERE singleton=1;
             UPDATE memory_vector_generation
             SET state='retired',authority_epoch=authority_epoch+1
             WHERE generation_id='{old_id}' AND state='active';
             UPDATE memory_vector_generation
             SET state='active',authority_epoch=authority_epoch+1
             WHERE generation_id='{new_id}' AND state='building';
             UPDATE memory_vector_generation_authority
             SET active_generation_id='{new_id}',updated_at='2026-08-22T00:00:00.000Z'
             WHERE singleton=1"
        ))
        .unwrap();
}

async fn seed_generation(
    storage: &StorageService,
    registry: &LanceDbVectorStoreRegistry,
    context: &VectorGenerationContext,
    record: GenerationVectorRecord,
) {
    let data_root = storage.active_data_root().unwrap();
    let store = registry
        .generation_store_for_write(&data_root, context.generation_id())
        .await
        .unwrap();
    store.create_generation(context).await.unwrap();
    store.upsert_generation(context, record).await.unwrap();
}

fn generation_record(
    context: &VectorGenerationContext,
    memory: &MemoryRecord,
    revision: i64,
    content_hash: &str,
) -> GenerationVectorRecord {
    GenerationVectorRecord::try_new(
        context.generation_id().clone(),
        memory.life_id.clone(),
        memory.id.clone(),
        revision,
        content_hash,
        context.descriptor_hash(),
        vec![1.0, 0.0],
    )
    .unwrap()
}

fn memory_content_hash(memory: &MemoryRecord) -> String {
    let selected = canonical_index_text(memory.summary.as_deref(), &memory.content).unwrap();
    canonical_memory_index_hash(
        memory.kind.as_str(),
        selected,
        &memory.content,
        memory.summary.as_deref(),
    )
}

fn assert_active_authority(
    storage: &StorageService,
    context: &VectorGenerationContext,
    profile_id: &str,
) {
    let connection =
        open_authorized_test_connection(&storage.test_database_main_path().unwrap()).unwrap();
    let active: String = connection
        .query_row(
            "SELECT active_generation_id
             FROM memory_vector_generation_authority WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(active, context.generation_id().as_str());
    let bound: String = connection
        .query_row(
            "SELECT embedding_profile_id FROM memory_vector_generation_binding
             WHERE generation_id=?1",
            [context.generation_id().as_str()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(bound, profile_id);
    let witness: String = connection
        .query_row(
            "SELECT state FROM memory_vector_generation_store_witness
             WHERE generation_id=?1",
            [context.generation_id().as_str()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(witness, "ready");
}

fn context_entries(candidates: &[RetrievalCandidate]) -> Vec<MemoryContextEntry> {
    candidates
        .iter()
        .map(|candidate| MemoryContextEntry {
            memory_id: candidate.memory_id.clone(),
            kind: candidate.kind,
            content: candidate.content.clone(),
            summary: candidate.summary.clone(),
            importance: candidate.importance,
            confidence: candidate.confidence,
            final_score: candidate.final_score,
            source: match candidate.sources {
                RetrievalSource::Keyword => MemoryContextSource::Keyword,
                RetrievalSource::Vector => MemoryContextSource::Vector,
                RetrievalSource::Both => MemoryContextSource::Both,
            },
        })
        .collect()
}

type CallHook = Arc<dyn Fn() + Send + Sync>;
type CallHookCell = Arc<Mutex<Option<CallHook>>>;

struct EmbeddingServer {
    base_url: String,
    calls: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    on_call: CallHookCell,
    address: std::net::SocketAddr,
    handle: Option<thread::JoinHandle<()>>,
}

impl EmbeddingServer {
    fn new(vector: Vec<f32>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let on_call: CallHookCell = Arc::new(Mutex::new(None));
        let thread_calls = Arc::clone(&calls);
        let thread_stop = Arc::clone(&stop);
        let thread_on_call = Arc::clone(&on_call);
        let handle = thread::spawn(move || {
            while !thread_stop.load(Ordering::SeqCst) {
                let Ok((mut stream, _)) = listener.accept() else {
                    thread::sleep(Duration::from_millis(1));
                    continue;
                };
                if stream.set_nonblocking(false).is_err() {
                    continue;
                }
                if read_http_request(&mut stream).is_err() {
                    continue;
                }
                thread_calls.fetch_add(1, Ordering::SeqCst);
                let hook = thread_on_call.lock().unwrap().clone();
                if let Some(hook) = hook {
                    hook();
                }
                let body = serde_json::json!({
                    "object": "list",
                    "model": MODEL_NAME,
                    "data": [{
                        "object": "embedding",
                        "index": 0,
                        "embedding": vector
                    }]
                })
                .to_string();
                let reply = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(reply.as_bytes());
            }
        });
        Self {
            base_url: format!("http://{address}/v1"),
            calls,
            stop,
            on_call,
            address,
            handle: Some(handle),
        }
    }

    fn set_on_call<F>(&self, hook: F)
    where
        F: Fn() + Send + Sync + 'static,
    {
        *self.on_call.lock().unwrap() = Some(Arc::new(hook));
    }
}

impl Drop for EmbeddingServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.address);
        if let Some(handle) = self.handle.take() {
            handle.join().unwrap();
        }
    }
}

fn read_http_request(stream: &mut TcpStream) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        let read = stream.read(&mut buffer)?;
        if read == 0 {
            return Ok(());
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
            return Ok(());
        }
    }
}

#[test]
fn nonexistent_life_real_runtime_short_circuits_external_io() {
    block_on(async {
        let fixture = RetrievalFixture::new();
        let error = fixture
            .retrieve("life-does-not-exist", "ordinary query")
            .await
            .unwrap_err();
        assert_eq!(error.code, RetrievalRuntimeErrorCode::LifeNotFound);
        assert_eq!(fixture.p1_server.calls.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.p2_server.calls.load(Ordering::SeqCst), 0);
    });
}

#[test]
fn generation_retrieval_real_hybrid_uses_bound_profile_sqlite_hydration_and_context_bounds() {
    block_on(async {
        let fixture = RetrievalFixture::new();
        let memory = fixture.memory(
            "authoritative SQLite body loaded from the current memory row",
            Some("SQLite authoritative summary"),
        );
        let context = fixture
            .install_generation(
                "generation-d10d-hybrid",
                &memory,
                1,
                &memory_content_hash(&memory),
            )
            .await;
        assert_active_authority(&fixture.storage, &context, &fixture.p1.id);
        let active_profile = ModelProfileService::new(&fixture.storage)
            .get_active(ModelPurpose::Embedding)
            .unwrap()
            .unwrap();
        assert_eq!(active_profile.profile_id, fixture.p2.id);

        let result = fixture
            .retrieve(LIFE_ID, "authoritative SQLite")
            .await
            .unwrap();
        assert_eq!(result.availability, RetrievalAvailability::Hybrid);
        assert_eq!(result.candidates.len(), 1);
        let candidate = &result.candidates[0];
        assert_eq!(candidate.sources, RetrievalSource::Both);
        assert_eq!(
            candidate.content,
            "authoritative SQLite body loaded from the current memory row"
        );
        assert_eq!(
            candidate.summary.as_deref(),
            Some("SQLite authoritative summary")
        );
        assert!(candidate.vector_score.unwrap() > 0.99);
        assert_eq!(fixture.p1_server.calls.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.p2_server.calls.load(Ordering::SeqCst), 0);

        let context_result = MemoryContextBuilder
            .build(MemoryContextBuildRequest {
                entries: context_entries(&result.candidates),
            })
            .unwrap();
        assert_eq!(context_result.used_count, 1);
        assert!(context_result
            .context
            .as_deref()
            .unwrap()
            .contains("SQLite authoritative summary"));
        assert!(context_result.retrieved_count <= MAX_RETRIEVAL_CANDIDATES);
        assert!(context_result.used_count <= MAX_INJECTED_MEMORIES);
        assert!(
            context_result.context.as_deref().unwrap().chars().count()
                <= MEMORY_CONTEXT_CHARACTER_BUDGET
        );
        assert!(candidate.summary.as_deref().unwrap().chars().count() <= MAX_MEMORY_CHARACTERS);
        assert!(candidate.content.chars().count() <= 32_000);
    });
}

#[test]
fn generation_retrieval_real_vector_only_candidate_hydrates_current_sqlite_body() {
    block_on(async {
        let fixture = RetrievalFixture::new();
        let memory = fixture.memory("opaque authoritative body", None);
        let _context = fixture
            .install_generation(
                "generation-d10d-vector",
                &memory,
                1,
                &memory_content_hash(&memory),
            )
            .await;

        let result = fixture
            .retrieve(LIFE_ID, "semantic query with no lexical overlap")
            .await
            .unwrap();
        assert_eq!(result.candidates.len(), 1);
        let candidate = &result.candidates[0];
        assert_eq!(candidate.sources, RetrievalSource::Vector);
        assert_eq!(candidate.keyword_score, None);
        assert!(candidate.vector_score.unwrap() > 0.99);
        assert_eq!(candidate.content, "opaque authoritative body");
        assert_eq!(fixture.p1_server.calls.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.p2_server.calls.load(Ordering::SeqCst), 0);
    });
}

#[test]
fn generation_retrieval_real_stale_revision_and_hash_are_rejected() {
    block_on(async {
        let fixture = RetrievalFixture::new();
        let memory = fixture.memory("original authoritative body", None);
        let original_hash = memory_content_hash(&memory);
        let _context = fixture
            .install_generation("generation-d10d-stale", &memory, 1, &original_hash)
            .await;
        MemoryRevisionService::new(&fixture.storage)
            .update_confirmed(UpdateConfirmedMemoryRequest {
                life_id: LIFE_ID.into(),
                memory_id: memory.id.clone(),
                expected_revision: 1,
                kind: MemoryKind::Fact,
                content: "current authoritative body".into(),
                summary: None,
            })
            .unwrap();

        let result = fixture
            .retrieve(LIFE_ID, "query without lexical overlap")
            .await
            .unwrap();
        assert!(result.candidates.is_empty());
        assert_eq!(result.availability, RetrievalAvailability::NoMemory);
        assert_eq!(fixture.p1_server.calls.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn generation_retrieval_real_delete_lag_is_rejected_after_sqlite_hydration() {
    block_on(async {
        let fixture = RetrievalFixture::new();
        let memory = fixture.memory("deletion lag body", None);
        let _context = fixture
            .install_generation(
                "generation-d10d-delete",
                &memory,
                1,
                &memory_content_hash(&memory),
            )
            .await;
        MemoryRevisionService::new(&fixture.storage)
            .delete_permanently(DeleteMemoryPermanentlyRequest {
                life_id: LIFE_ID.into(),
                memory_id: memory.id.clone(),
                expected_revision: 1,
            })
            .unwrap();

        let result = fixture
            .retrieve(LIFE_ID, "query without lexical overlap")
            .await
            .unwrap();
        assert!(result.candidates.is_empty());
        assert_eq!(result.availability, RetrievalAvailability::NoMemory);
        assert_eq!(fixture.p1_server.calls.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn generation_retrieval_real_sensitivity_lag_is_rejected_after_sqlite_hydration() {
    block_on(async {
        let fixture = RetrievalFixture::new();
        let memory = fixture.memory("sensitivity lag body", None);
        let _context = fixture
            .install_generation(
                "generation-d10d-sensitive",
                &memory,
                1,
                &memory_content_hash(&memory),
            )
            .await;
        MemoryRevisionService::new(&fixture.storage)
            .set_sensitivity(SetMemorySensitivityRequest {
                life_id: LIFE_ID.into(),
                memory_id: memory.id.clone(),
                expected_revision: 1,
                is_sensitive: true,
            })
            .unwrap();

        let result = fixture
            .retrieve(LIFE_ID, "query without lexical overlap")
            .await
            .unwrap();
        assert!(result.candidates.is_empty());
        assert_eq!(result.availability, RetrievalAvailability::NoMemory);
        assert_eq!(fixture.p1_server.calls.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn generation_retrieval_real_promotion_degrades_to_keyword_without_stale_vector() {
    block_on(async {
        let fixture = RetrievalFixture::new();
        let memory = fixture.memory("promotion keyword body", None);
        let context_one = fixture
            .install_generation(
                "generation-d10d-promotion-one",
                &memory,
                1,
                &memory_content_hash(&memory),
            )
            .await;
        let context_two = generation_context(&fixture.p1, "generation-d10d-promotion-two");
        install_ready_generation(&fixture.storage, &context_two, &fixture.p1.id);
        let database = fixture.storage.test_database_main_path().unwrap();
        let old_id = context_one.generation_id().as_str().to_owned();
        let new_id = context_two.generation_id().as_str().to_owned();
        fixture.p1_server.set_on_call(move || {
            promote_generation(&database, &old_id, &new_id);
        });

        let result = fixture
            .retrieve(LIFE_ID, "promotion keyword")
            .await
            .unwrap();
        assert_eq!(result.availability, RetrievalAvailability::KeywordOnly);
        assert_eq!(result.candidates.len(), 1);
        assert_eq!(result.candidates[0].sources, RetrievalSource::Keyword);
        assert_eq!(result.candidates[0].vector_score, None);
        assert!(result
            .degradation_codes
            .contains(&RetrievalDegradationCode::VectorUnavailable));
        assert_eq!(fixture.p1_server.calls.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.p2_server.calls.load(Ordering::SeqCst), 0);
    });
}

#[test]
fn sensitive_query_real_runtime_skips_generation_provider_after_life_validation() {
    block_on(async {
        let fixture = RetrievalFixture::new();
        let memory = fixture.memory("credential discussion", None);
        let _context = fixture
            .install_generation(
                "generation-d10d-sensitive-query",
                &memory,
                1,
                &memory_content_hash(&memory),
            )
            .await;

        let result = fixture
            .retrieve(LIFE_ID, "credential api_key=fixture-value-123")
            .await
            .unwrap();
        assert_eq!(result.availability, RetrievalAvailability::NoMemory);
        assert!(result
            .degradation_codes
            .contains(&RetrievalDegradationCode::VectorSkippedSensitiveQuery));
        assert_eq!(fixture.p1_server.calls.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.p2_server.calls.load(Ordering::SeqCst), 0);
    });
}

#[test]
fn no_active_generation_real_runtime_degrades_to_keyword_only() {
    block_on(async {
        let fixture = RetrievalFixture::new();
        let _memory = fixture.memory("keyword-only authoritative body", None);
        let result = fixture.retrieve(LIFE_ID, "keyword-only").await.unwrap();
        assert_eq!(result.availability, RetrievalAvailability::KeywordOnly);
        assert_eq!(result.candidates.len(), 1);
        assert_eq!(result.candidates[0].sources, RetrievalSource::Keyword);
        assert!(result
            .degradation_codes
            .contains(&RetrievalDegradationCode::VectorIndexUnavailable));
        assert_eq!(fixture.p1_server.calls.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.p2_server.calls.load(Ordering::SeqCst), 0);
    });
}

#[test]
fn legacy_store_is_ignored_without_active_generation() {
    block_on(async {
        let fixture = RetrievalFixture::new();
        let memory = fixture.memory("legacy ignored authoritative body", None);
        let memory_id = memory.id.clone();
        let content_hash = memory_content_hash(&memory);
        let data_root = fixture.storage.active_data_root().unwrap();
        let legacy = fixture.registry.store_for_write(&data_root).await.unwrap();
        legacy
            .upsert(VectorRecord {
                life_id: LIFE_ID.into(),
                memory_id,
                embedding_model: MODEL_NAME.into(),
                dimension: DIMENSION,
                vector: vec![1.0, 0.0],
                content_hash,
            })
            .await
            .unwrap();
        assert!(data_root.join("vectors").join("lancedb").is_dir());

        let result = fixture
            .retrieve(LIFE_ID, "query without lexical overlap")
            .await
            .unwrap();
        assert!(result.candidates.is_empty());
        assert_eq!(result.availability, RetrievalAvailability::NoMemory);
        assert!(result
            .degradation_codes
            .contains(&RetrievalDegradationCode::VectorIndexUnavailable));
        assert_eq!(fixture.p1_server.calls.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.p2_server.calls.load(Ordering::SeqCst), 0);
    });
}

#[test]
fn active_generation_uses_only_exact_generation_store_path() {
    block_on(async {
        let fixture = RetrievalFixture::new();
        let memory = fixture.memory("exact generation path body", None);
        let context = fixture
            .install_generation(
                "generation-d10d-exact-path",
                &memory,
                1,
                &memory_content_hash(&memory),
            )
            .await;
        let data_root = fixture.storage.active_data_root().unwrap();
        assert!(generation_store_root(&data_root, context.generation_id()).is_dir());
        assert!(!data_root.join("vectors").join("lancedb").exists());
        let result = fixture
            .retrieve(LIFE_ID, "query without lexical overlap")
            .await
            .unwrap();
        assert_eq!(result.candidates.len(), 1);
        assert_eq!(result.candidates[0].sources, RetrievalSource::Vector);
        assert_eq!(fixture.p1_server.calls.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.p2_server.calls.load(Ordering::SeqCst), 0);
    });
}
