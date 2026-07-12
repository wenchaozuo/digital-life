use rusqlite::{params, params_from_iter, types::Value};

use crate::memory::{
    retrieval::{MemoryRetrievalRepository, MemoryRetrievalResult, RetrievalQuery},
    MemoryError, MemoryKind,
};

use super::StorageService;

impl MemoryRetrievalRepository for StorageService {
    fn retrieve_confirmed(
        &self,
        query: &RetrievalQuery,
    ) -> Result<Vec<MemoryRetrievalResult>, MemoryError> {
        let state = self.state().map_err(|_| MemoryError::database())?;
        let life_exists: bool = state
            .connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM life_identity WHERE id = ?1)",
                params![query.life_id],
                |row| row.get(0),
            )
            .map_err(|_| MemoryError::database())?;
        if !life_exists {
            return Err(MemoryError::new(
                "LIFE_NOT_FOUND",
                "The specified life was not found.",
                true,
            ));
        }

        let terms: Vec<&str> = query.query_text.split_whitespace().collect();
        let kinds = query.kinds.as_deref().unwrap_or_default();
        let mut sql = String::from(
            "SELECT id, kind, content, summary, importance, confidence, created_at
             FROM memory_record
             WHERE life_id = ? AND status = 'confirmed' AND is_sensitive = 0",
        );
        let mut values = vec![Value::Text(query.life_id.clone())];

        for term in terms {
            sql.push_str(
                " AND (content LIKE ? ESCAPE '\\' COLLATE NOCASE
                        OR COALESCE(summary, '') LIKE ? ESCAPE '\\' COLLATE NOCASE)",
            );
            let pattern = format!("%{}%", escape_like(term));
            values.push(Value::Text(pattern.clone()));
            values.push(Value::Text(pattern));
        }

        if !kinds.is_empty() {
            sql.push_str(" AND kind IN (");
            sql.push_str(&vec!["?"; kinds.len()].join(", "));
            sql.push(')');
            values.extend(
                kinds
                    .iter()
                    .map(|kind| Value::Text(kind.as_str().to_string())),
            );
        }

        sql.push_str(" ORDER BY importance DESC, created_at DESC, id ASC LIMIT ?");
        values.push(Value::Integer(i64::from(query.limit)));

        let mut statement = state
            .connection
            .prepare(&sql)
            .map_err(|_| MemoryError::database())?;
        let rows = statement
            .query_map(params_from_iter(values), |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, f64>(4)?,
                    row.get::<_, f64>(5)?,
                    row.get::<_, String>(6)?,
                ))
            })
            .map_err(|_| MemoryError::database())?;

        rows.map(|row| {
            let (memory_id, kind, content, summary, importance, confidence, created_at) =
                row.map_err(|_| MemoryError::database())?;
            Ok(MemoryRetrievalResult {
                memory_id,
                kind: MemoryKind::parse(&kind)?,
                content,
                summary,
                importance,
                confidence,
                created_at,
            })
        })
        .collect()
    }
}

fn escape_like(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use crate::{
        memory::{
            retrieval::{MemoryRetriever, RetrievalQuery},
            ConfirmMemoryRequest, CreateMemoryCandidateRequest, MemoryKind, MemoryService,
            MemorySourceType,
        },
        storage::{unique_suffix, LifeIdentityRecord, PersonaTemplateRecord, StorageService},
    };

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir()
                .join(format!("digital-life-retrieval-{name}-{}", unique_suffix()));
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
        for suffix in ["a", "b"] {
            service
                .save_persona(PersonaTemplateRecord {
                    id: format!("persona-{suffix}"),
                    name: "Custom Persona".into(),
                    version: 1,
                    persona_json: format!("{{\"id\":\"persona-{suffix}\"}}"),
                })
                .unwrap();
            service
                .save_life(LifeIdentityRecord {
                    id: format!("life-{suffix}"),
                    name: format!("Life {suffix}"),
                    created_at: "2026-07-11T00:00:00.000Z".into(),
                    version: 1,
                    body_id: "default-png".into(),
                    persona_id: format!("persona-{suffix}"),
                    persona_version: 1,
                })
                .unwrap();
        }
        service
    }

    fn create_memory(
        service: &StorageService,
        life_id: &str,
        kind: MemoryKind,
        content: &str,
        summary: Option<&str>,
        importance: f64,
        confirmed: bool,
    ) -> crate::memory::MemoryRecord {
        let candidate = MemoryService::new(service)
            .create_candidate(CreateMemoryCandidateRequest {
                life_id: life_id.into(),
                kind,
                content: content.into(),
                summary: summary.map(str::to_string),
                source_type: MemorySourceType::Manual,
                source_ref: Some("retrieval-test".into()),
                source_created_at: "2026-07-11T01:00:00.000Z".into(),
                importance,
                confidence: 0.8,
                is_sensitive: false,
            })
            .unwrap();

        if confirmed {
            MemoryService::new(service)
                .confirm(ConfirmMemoryRequest {
                    life_id: life_id.into(),
                    memory_id: candidate.id,
                    user_confirmed: true,
                    sensitive_consent: false,
                })
                .unwrap()
        } else {
            candidate
        }
    }

    fn query(life_id: &str, query_text: &str) -> RetrievalQuery {
        RetrievalQuery {
            life_id: life_id.into(),
            query_text: query_text.into(),
            kinds: None,
            limit: 10,
        }
    }

    #[test]
    fn only_confirmed_memories_are_returned() {
        let root = TestRoot::new("confirmed-only");
        let service = seeded_service(&root);
        let confirmed = create_memory(
            &service,
            "life-a",
            MemoryKind::Preference,
            "The user likes coffee.",
            None,
            0.8,
            true,
        );
        create_memory(
            &service,
            "life-a",
            MemoryKind::Preference,
            "The user likes coffee with sugar.",
            None,
            0.9,
            false,
        );

        let results = MemoryRetriever::new(&service)
            .retrieve(query("life-a", "coffee"))
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].memory_id, confirmed.id);
    }

    #[test]
    fn life_id_is_strictly_isolated() {
        let root = TestRoot::new("life-isolation");
        let service = seeded_service(&root);
        create_memory(
            &service,
            "life-b",
            MemoryKind::Fact,
            "A private telescope fact.",
            None,
            0.7,
            true,
        );

        assert!(MemoryRetriever::new(&service)
            .retrieve(query("life-a", "telescope"))
            .unwrap()
            .is_empty());
    }

    #[test]
    fn confirmed_sensitive_memory_is_not_retrieved() {
        let root = TestRoot::new("sensitive-filter");
        let service = seeded_service(&root);
        let candidate = MemoryService::new(&service)
            .create_candidate(CreateMemoryCandidateRequest {
                life_id: "life-a".into(),
                kind: MemoryKind::Fact,
                content: "A sensitive lighthouse fact.".into(),
                summary: None,
                source_type: MemorySourceType::Manual,
                source_ref: Some("retrieval-test".into()),
                source_created_at: "2026-07-11T01:00:00.000Z".into(),
                importance: 0.9,
                confidence: 0.9,
                is_sensitive: true,
            })
            .unwrap();
        MemoryService::new(&service)
            .confirm(ConfirmMemoryRequest {
                life_id: "life-a".into(),
                memory_id: candidate.id,
                user_confirmed: true,
                sensitive_consent: true,
            })
            .unwrap();

        assert!(MemoryRetriever::new(&service)
            .retrieve(query("life-a", "lighthouse"))
            .unwrap()
            .is_empty());
    }

    #[test]
    fn keyword_matches_content_and_summary() {
        let root = TestRoot::new("keyword");
        let service = seeded_service(&root);
        create_memory(
            &service,
            "life-a",
            MemoryKind::Experience,
            "We visited the park.",
            Some("A quiet riverside walk"),
            0.6,
            true,
        );

        let retriever = MemoryRetriever::new(&service);
        assert_eq!(
            retriever.retrieve(query("life-a", "park")).unwrap().len(),
            1
        );
        assert_eq!(
            retriever
                .retrieve(query("life-a", "riverside"))
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn kind_filter_is_applied() {
        let root = TestRoot::new("kind-filter");
        let service = seeded_service(&root);
        create_memory(
            &service,
            "life-a",
            MemoryKind::Preference,
            "Coffee is preferred.",
            None,
            0.7,
            true,
        );
        create_memory(
            &service,
            "life-a",
            MemoryKind::Fact,
            "Coffee contains caffeine.",
            None,
            0.8,
            true,
        );
        let mut retrieval_query = query("life-a", "coffee");
        retrieval_query.kinds = Some(vec![MemoryKind::Preference]);

        let results = MemoryRetriever::new(&service)
            .retrieve(retrieval_query)
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].kind, MemoryKind::Preference);
    }

    #[test]
    fn limit_and_importance_order_are_applied() {
        let root = TestRoot::new("limit-order");
        let service = seeded_service(&root);
        create_memory(
            &service,
            "life-a",
            MemoryKind::Fact,
            "A shared keyword with lower importance.",
            None,
            0.2,
            true,
        );
        let higher = create_memory(
            &service,
            "life-a",
            MemoryKind::Fact,
            "A shared keyword with higher importance.",
            None,
            0.9,
            true,
        );
        let mut retrieval_query = query("life-a", "shared keyword");
        retrieval_query.limit = 1;

        let results = MemoryRetriever::new(&service)
            .retrieve(retrieval_query)
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].memory_id, higher.id);
    }

    #[test]
    fn newer_memory_wins_when_importance_is_equal() {
        let root = TestRoot::new("time-order");
        let service = seeded_service(&root);
        let older = create_memory(
            &service,
            "life-a",
            MemoryKind::Experience,
            "A shared journey from earlier.",
            None,
            0.7,
            true,
        );
        let newer = create_memory(
            &service,
            "life-a",
            MemoryKind::Experience,
            "A shared journey from later.",
            None,
            0.7,
            true,
        );
        {
            let state = service.state().unwrap();
            state
                .connection
                .execute(
                    "UPDATE memory_record SET created_at = ?2 WHERE id = ?1",
                    rusqlite::params![older.id, "2026-07-11T01:00:00.000Z"],
                )
                .unwrap();
            state
                .connection
                .execute(
                    "UPDATE memory_record SET created_at = ?2 WHERE id = ?1",
                    rusqlite::params![newer.id, "2026-07-11T02:00:00.000Z"],
                )
                .unwrap();
        }

        let results = MemoryRetriever::new(&service)
            .retrieve(query("life-a", "shared journey"))
            .unwrap();
        assert_eq!(results[0].memory_id, newer.id);
        assert_eq!(results[1].memory_id, older.id);
    }

    #[test]
    fn no_match_returns_empty_results() {
        let root = TestRoot::new("no-match");
        let service = seeded_service(&root);
        create_memory(
            &service,
            "life-a",
            MemoryKind::Fact,
            "The sky is blue.",
            None,
            0.5,
            true,
        );

        assert!(MemoryRetriever::new(&service)
            .retrieve(query("life-a", "volcano"))
            .unwrap()
            .is_empty());
    }

    #[test]
    fn deleted_memory_cannot_be_retrieved() {
        let root = TestRoot::new("deleted");
        let service = seeded_service(&root);
        let memory = create_memory(
            &service,
            "life-a",
            MemoryKind::Experience,
            "A removable mountain memory.",
            None,
            0.5,
            true,
        );
        MemoryService::new(&service)
            .delete("life-a", &memory.id)
            .unwrap();

        assert!(MemoryRetriever::new(&service)
            .retrieve(query("life-a", "mountain"))
            .unwrap()
            .is_empty());
    }

    #[test]
    fn empty_database_does_not_create_default_memory() {
        let root = TestRoot::new("empty-database");
        let service = seeded_service(&root);
        assert!(MemoryRetriever::new(&service)
            .retrieve(query("life-a", "anything"))
            .unwrap()
            .is_empty());

        let state = service.state().unwrap();
        let count: i64 = state
            .connection
            .query_row("SELECT COUNT(*) FROM memory_record", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn missing_life_returns_structured_error() {
        let root = TestRoot::new("missing-life");
        let service = seeded_service(&root);
        let error = MemoryRetriever::new(&service)
            .retrieve(query("missing-life", "anything"))
            .unwrap_err();
        assert_eq!(error.code, "LIFE_NOT_FOUND");
    }
}
