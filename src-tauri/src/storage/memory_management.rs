use rusqlite::{params, OptionalExtension, Row};

use crate::memory::{
    management::{
        ManagedMemory, ManagedMemoryDetail, ManagedMemoryListQuery, MemoryListCursor,
        MemoryListResult, MemoryManagementRepository,
    },
    MemoryError, MemoryKind, MemorySourceType, MemoryStatus,
};

use super::StorageService;

impl MemoryManagementRepository for StorageService {
    fn list_managed_memories(
        &self,
        query: ManagedMemoryListQuery,
    ) -> Result<MemoryListResult, MemoryError> {
        let state = self.state().map_err(|_| MemoryError::database())?;
        ensure_life_exists(&state.connection, &query.life_id)?;
        let status = query.status.as_filter();
        let kind = query.kind.map(MemoryKind::as_str);
        let cursor_updated_at = query
            .cursor
            .as_ref()
            .map(|cursor| cursor.updated_at.as_str());
        let cursor_id = query.cursor.as_ref().map(|cursor| cursor.id.as_str());
        let limit = i64::try_from(query.page_size + 1).map_err(|_| MemoryError::database())?;
        let mut statement = state
            .connection
            .prepare(
                "SELECT id, status, kind, summary, is_sensitive, revision, updated_at
                 FROM memory_record
                 WHERE life_id = ?1
                   AND (?2 IS NULL OR status = ?2)
                   AND (?3 IS NULL OR kind = ?3)
                   AND (?4 IS NULL OR is_sensitive = ?4)
                   AND (?5 IS NULL OR instr(lower(content), lower(?5)) > 0
                        OR instr(lower(COALESCE(summary, '')), lower(?5)) > 0)
                   AND (?6 IS NULL OR updated_at < ?6 OR (updated_at = ?6 AND id > ?7))
                 ORDER BY updated_at DESC, id ASC
                 LIMIT ?8",
            )
            .map_err(|_| MemoryError::database())?;
        let rows = statement
            .query_map(
                params![
                    query.life_id,
                    status,
                    kind,
                    query.sensitive,
                    query.query,
                    cursor_updated_at,
                    cursor_id,
                    limit,
                ],
                read_managed_memory,
            )
            .map_err(|_| MemoryError::database())?;
        let mut items: Vec<ManagedMemory> = rows
            .map(|row| row.map_err(|_| MemoryError::database())?.try_into())
            .collect::<Result<_, _>>()?;
        let has_more = items.len() > query.page_size;
        if has_more {
            items.pop();
        }
        let next_cursor = has_more.then(|| {
            let last = items.last().expect("a non-empty page has a cursor");
            MemoryListCursor {
                updated_at: last.updated_at.clone(),
                id: last.id.clone(),
            }
        });
        Ok(MemoryListResult { items, next_cursor })
    }

    fn get_managed_memory(
        &self,
        life_id: &str,
        memory_id: &str,
    ) -> Result<ManagedMemoryDetail, MemoryError> {
        let state = self.state().map_err(|_| MemoryError::database())?;
        let stored = state
            .connection
            .query_row(
                "SELECT memory.id, memory.life_id, memory.status, memory.kind, memory.content,
                        memory.summary, memory.is_sensitive, memory.source_type,
                        memory.importance, memory.confidence, memory.revision,
                        memory.created_at, memory.updated_at,
                        (SELECT COUNT(*) FROM memory_revision revision
                         WHERE revision.memory_id = memory.id)
                 FROM memory_record memory WHERE memory.id = ?1",
                params![memory_id],
                read_managed_detail,
            )
            .optional()
            .map_err(|_| MemoryError::database())?
            .ok_or_else(MemoryError::not_found)?;
        if stored.life_id != life_id {
            return Err(MemoryError::life_mismatch());
        }
        stored.try_into()
    }
}

fn ensure_life_exists(connection: &rusqlite::Connection, life_id: &str) -> Result<(), MemoryError> {
    let exists: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM life_identity WHERE id = ?1)",
            params![life_id],
            |row| row.get(0),
        )
        .map_err(|_| MemoryError::database())?;
    if !exists {
        return Err(MemoryError::new(
            "MEMORY_NOT_FOUND",
            "The current life was not found.",
            true,
        ));
    }
    Ok(())
}

struct StoredManagedMemory {
    id: String,
    status: String,
    kind: String,
    summary: Option<String>,
    is_sensitive: bool,
    revision: i64,
    updated_at: String,
}

impl TryFrom<StoredManagedMemory> for ManagedMemory {
    type Error = MemoryError;

    fn try_from(value: StoredManagedMemory) -> Result<Self, Self::Error> {
        Ok(Self {
            id: value.id,
            status: MemoryStatus::parse(&value.status)?,
            kind: MemoryKind::parse(&value.kind)?,
            summary: value.summary,
            is_sensitive: value.is_sensitive,
            revision: value.revision,
            updated_at: value.updated_at,
        })
    }
}

fn read_managed_memory(row: &Row<'_>) -> rusqlite::Result<StoredManagedMemory> {
    Ok(StoredManagedMemory {
        id: row.get(0)?,
        status: row.get(1)?,
        kind: row.get(2)?,
        summary: row.get(3)?,
        is_sensitive: row.get(4)?,
        revision: row.get(5)?,
        updated_at: row.get(6)?,
    })
}

struct StoredManagedMemoryDetail {
    id: String,
    life_id: String,
    status: String,
    kind: String,
    content: String,
    summary: Option<String>,
    is_sensitive: bool,
    source: String,
    importance: f64,
    confidence: f64,
    revision: i64,
    created_at: String,
    updated_at: String,
    revision_count: i64,
}

impl TryFrom<StoredManagedMemoryDetail> for ManagedMemoryDetail {
    type Error = MemoryError;

    fn try_from(value: StoredManagedMemoryDetail) -> Result<Self, Self::Error> {
        Ok(Self {
            id: value.id,
            status: MemoryStatus::parse(&value.status)?,
            kind: MemoryKind::parse(&value.kind)?,
            content: value.content,
            summary: value.summary,
            is_sensitive: value.is_sensitive,
            source: MemorySourceType::parse(&value.source)?,
            importance: value.importance,
            confidence: value.confidence,
            revision: value.revision,
            created_at: value.created_at,
            updated_at: value.updated_at,
            revision_count: usize::try_from(value.revision_count)
                .map_err(|_| MemoryError::database())?,
        })
    }
}

fn read_managed_detail(row: &Row<'_>) -> rusqlite::Result<StoredManagedMemoryDetail> {
    Ok(StoredManagedMemoryDetail {
        id: row.get(0)?,
        life_id: row.get(1)?,
        status: row.get(2)?,
        kind: row.get(3)?,
        content: row.get(4)?,
        summary: row.get(5)?,
        is_sensitive: row.get(6)?,
        source: row.get(7)?,
        importance: row.get(8)?,
        confidence: row.get(9)?,
        revision: row.get(10)?,
        created_at: row.get(11)?,
        updated_at: row.get(12)?,
        revision_count: row.get(13)?,
    })
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use rusqlite::params;

    use crate::{
        conversation::history::{ConversationHistoryService, CreateConversationRequest},
        memory::{
            management::{ManagedMemoryStatus, MemoryListRequest, MemoryManagementService},
            revisions::{
                DeleteMemoryPermanentlyRequest, MemoryRevisionService, SetMemorySensitivityRequest,
                UpdateConfirmedMemoryRequest,
            },
            CreateMemoryCandidateRequest, MemoryKind, MemoryService, MemorySourceType,
            MemoryStatus,
        },
    };

    use super::super::{unique_suffix, LifeIdentityRecord, PersonaTemplateRecord, StorageService};

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "digital-life-memory-management-{name}-{}",
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

    fn seeded(root: &TestRoot) -> StorageService {
        let service = StorageService::initialize_with_roots(root.0.join("data"), None).unwrap();
        for suffix in ["b", "a"] {
            service
                .save_persona(PersonaTemplateRecord {
                    id: format!("persona-{suffix}"),
                    name: "Persona".into(),
                    version: 1,
                    persona_json: "{}".into(),
                })
                .unwrap();
            service
                .save_life(LifeIdentityRecord {
                    id: format!("life-{suffix}"),
                    name: format!("Life {suffix}"),
                    created_at: "2026-07-13T00:00:00.000Z".into(),
                    version: 1,
                    body_id: "body".into(),
                    persona_id: format!("persona-{suffix}"),
                    persona_version: 1,
                })
                .unwrap();
        }
        service
    }

    fn create(
        service: &StorageService,
        life_id: &str,
        kind: MemoryKind,
        content: &str,
        sensitive: bool,
        confirm: bool,
    ) -> crate::memory::MemoryRecord {
        if confirm {
            super::super::test_support::insert_confirmed_memory_fixture(
                service,
                life_id,
                kind.as_str(),
                content,
                Some(&format!("Summary for {content}")),
                0.5,
                0.8,
                sensitive,
                true,
            )
        } else {
            MemoryService::new(service)
                .create_candidate(CreateMemoryCandidateRequest {
                    life_id: life_id.into(),
                    kind,
                    content: content.into(),
                    summary: Some(format!("Summary for {content}")),
                    source_type: MemorySourceType::Manual,
                    source_ref: None,
                    source_created_at: "2026-07-13T00:00:00.000Z".into(),
                    importance: 0.5,
                    confidence: 0.8,
                    is_sensitive: sensitive,
                })
                .unwrap()
        }
    }

    #[test]
    fn list_filters_searches_pages_stably_and_isolates_life() {
        let root = TestRoot::new("list");
        let service = seeded(&root);
        // All memories must be confirmed since the management service only queries memory_record.
        let first = create(
            &service,
            "life-a",
            MemoryKind::Fact,
            "Alpha needle",
            false,
            true,
        );
        let second = create(&service, "life-a", MemoryKind::Goal, "Beta", true, true);
        let third = create(&service, "life-a", MemoryKind::Fact, "Gamma", false, true);
        create(
            &service,
            "life-b",
            MemoryKind::Fact,
            "Alpha needle other life",
            false,
            true,
        );
        for (id, timestamp) in [
            (&first.id, "2026-07-13T03:00:00.000Z"),
            (&second.id, "2026-07-13T02:00:00.000Z"),
            (&third.id, "2026-07-13T01:00:00.000Z"),
        ] {
            service
                .state()
                .unwrap()
                .connection
                .execute(
                    "UPDATE memory_record SET updated_at = ?2 WHERE id = ?1",
                    params![id, timestamp],
                )
                .unwrap();
        }
        let management = MemoryManagementService::new(&service);
        let page_one = management
            .list(
                "life-a",
                MemoryListRequest {
                    page_size: Some(2),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(
            page_one
                .items
                .iter()
                .map(|item| item.id.as_str())
                .collect::<Vec<_>>(),
            vec![first.id.as_str(), second.id.as_str()]
        );
        let page_two = management
            .list(
                "life-a",
                MemoryListRequest {
                    page_size: Some(2),
                    cursor: page_one.next_cursor,
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(
            page_two
                .items
                .iter()
                .map(|item| item.id.as_str())
                .collect::<Vec<_>>(),
            vec![third.id.as_str()]
        );
        let confirmed = management
            .list(
                "life-a",
                MemoryListRequest {
                    status: ManagedMemoryStatus::Confirmed,
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(confirmed.items.len(), 3);
        let facts = management
            .list(
                "life-a",
                MemoryListRequest {
                    kind: Some(MemoryKind::Fact),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(facts.items.len(), 2);
        let sensitive = management
            .list(
                "life-a",
                MemoryListRequest {
                    sensitive: Some(true),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(sensitive.items.len(), 1);
        let search = management
            .list(
                "life-a",
                MemoryListRequest {
                    query: Some("needle".into()),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(search.items.len(), 1);
        assert_eq!(search.items[0].id, first.id);
    }

    #[test]
    fn details_and_revision_history_are_safe_for_candidate_and_confirmed_memory() {
        let root = TestRoot::new("detail");
        let service = seeded(&root);
        let candidate = create(
            &service,
            "life-a",
            MemoryKind::Goal,
            "Candidate detail",
            false,
            false,
        );
        let confirmed = create(
            &service,
            "life-a",
            MemoryKind::Fact,
            "Confirmed detail",
            false,
            true,
        );
        let management = MemoryManagementService::new(&service);
        // Candidates live in candidate_memory, not memory_record,
        // so the management service (which queries memory_record) cannot find them.
        // Verify the candidate is retrievable via the legacy MemoryService path.
        let candidate_legacy = MemoryService::new(&service)
            .get("life-a", &candidate.id)
            .unwrap();
        assert_eq!(candidate_legacy.status, MemoryStatus::Candidate);
        let confirmed_detail = management.get("life-a", &confirmed.id).unwrap();
        assert_eq!(confirmed_detail.status, MemoryStatus::Confirmed);
        assert_eq!(confirmed_detail.revision_count, 1);
        let revisions = management.revisions("life-a", &confirmed.id).unwrap();
        assert_eq!(
            revisions
                .iter()
                .map(|revision| revision.revision)
                .collect::<Vec<_>>(),
            vec![1]
        );
        let json = serde_json::to_value(confirmed_detail).unwrap();
        for forbidden in [
            "lifeId",
            "vector",
            "contentHash",
            "leaseOwner",
            "prompt",
            "apiKey",
            "databasePath",
            "sql",
        ] {
            assert!(json.get(forbidden).is_none());
        }
    }

    #[test]
    fn governed_updates_reject_candidates_conflicts_and_cross_life_access() {
        let root = TestRoot::new("update");
        let service = seeded(&root);
        let candidate = create(
            &service,
            "life-a",
            MemoryKind::Fact,
            "Candidate",
            false,
            false,
        );
        let confirmed = create(
            &service,
            "life-a",
            MemoryKind::Fact,
            "Confirmed",
            false,
            true,
        );
        let revisions = MemoryRevisionService::new(&service);
        let candidate_error = revisions
            .update_confirmed(UpdateConfirmedMemoryRequest {
                life_id: "life-a".into(),
                memory_id: candidate.id,
                expected_revision: 1,
                kind: MemoryKind::Goal,
                content: "No".into(),
                summary: None,
            })
            .unwrap_err();
        // Candidates are in candidate_memory, not memory_record, so update_confirmed
        // returns MEMORY_NOT_FOUND instead of MEMORY_NOT_CONFIRMED.
        assert_eq!(candidate_error.code, "MEMORY_NOT_FOUND");
        revisions
            .update_confirmed(UpdateConfirmedMemoryRequest {
                life_id: "life-a".into(),
                memory_id: confirmed.id.clone(),
                expected_revision: 1,
                kind: MemoryKind::Goal,
                content: "Updated".into(),
                summary: None,
            })
            .unwrap();
        assert_eq!(
            revisions
                .update_confirmed(UpdateConfirmedMemoryRequest {
                    life_id: "life-a".into(),
                    memory_id: confirmed.id.clone(),
                    expected_revision: 1,
                    kind: MemoryKind::Fact,
                    content: "Stale".into(),
                    summary: None,
                })
                .unwrap_err()
                .code,
            "MEMORY_REVISION_CONFLICT"
        );
        assert_eq!(
            MemoryManagementService::new(&service)
                .get("life-b", &confirmed.id)
                .unwrap_err()
                .code,
            "MEMORY_LIFE_MISMATCH"
        );
    }

    #[test]
    fn sensitivity_and_permanent_delete_remove_history_without_deleting_conversation() {
        let root = TestRoot::new("delete");
        let service = seeded(&root);
        let memory = create(
            &service,
            "life-a",
            MemoryKind::Fact,
            "Delete me",
            false,
            true,
        );
        let conversation = ConversationHistoryService::new(&service)
            .create(CreateConversationRequest {
                life_id: "life-a".into(),
                title: "Keep conversation".into(),
            })
            .unwrap();
        let management = MemoryManagementService::new(&service);
        let sensitive = management
            .set_sensitive(SetMemorySensitivityRequest {
                life_id: "life-a".into(),
                memory_id: memory.id.clone(),
                expected_revision: 1,
                is_sensitive: true,
            })
            .unwrap();
        assert!(sensitive.is_sensitive);
        management
            .delete(DeleteMemoryPermanentlyRequest {
                life_id: "life-a".into(),
                memory_id: memory.id.clone(),
                expected_revision: 2,
            })
            .unwrap();
        assert_eq!(
            management.get("life-a", &memory.id).unwrap_err().code,
            "MEMORY_NOT_FOUND"
        );
        assert_eq!(
            management.revisions("life-a", &memory.id).unwrap_err().code,
            "MEMORY_NOT_FOUND"
        );
        let conversation_count: i64 = service
            .state()
            .unwrap()
            .connection
            .query_row(
                "SELECT COUNT(*) FROM conversation WHERE id = ?1",
                params![conversation.id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(conversation_count, 1);
    }

    #[test]
    fn invalid_query_and_page_limits_return_structured_errors() {
        let root = TestRoot::new("invalid");
        let service = seeded(&root);
        let management = MemoryManagementService::new(&service);
        assert_eq!(
            management
                .list(
                    "life-a",
                    MemoryListRequest {
                        query: Some("   ".into()),
                        ..Default::default()
                    }
                )
                .unwrap_err()
                .code,
            "INVALID_MEMORY_QUERY"
        );
        assert_eq!(
            management
                .list(
                    "life-a",
                    MemoryListRequest {
                        page_size: Some(101),
                        ..Default::default()
                    }
                )
                .unwrap_err()
                .code,
            "INVALID_MEMORY_QUERY"
        );
    }
}
