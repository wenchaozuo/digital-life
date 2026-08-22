use crate::memory::{MemoryError, MemoryKind};
use serde::{Deserialize, Serialize};

const MAX_QUERY_LENGTH: usize = 4000;
const MAX_RESULT_LIMIT: u32 = 100;

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RetrievalQuery {
    pub life_id: String,
    pub query_text: String,
    pub kinds: Option<Vec<MemoryKind>>,
    pub limit: u32,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryRetrievalResult {
    pub memory_id: String,
    pub kind: MemoryKind,
    pub content: String,
    pub summary: Option<String>,
    pub importance: f64,
    pub confidence: f64,
    pub created_at: String,
}

pub trait MemoryRetrievalRepository {
    fn retrieve_confirmed(
        &self,
        query: &RetrievalQuery,
    ) -> Result<Vec<MemoryRetrievalResult>, MemoryError>;
}

pub struct MemoryRetriever<'a, R: MemoryRetrievalRepository> {
    repository: &'a R,
}

impl<'a, R: MemoryRetrievalRepository> MemoryRetriever<'a, R> {
    pub fn new(repository: &'a R) -> Self {
        Self { repository }
    }

    pub fn retrieve(
        &self,
        query: RetrievalQuery,
    ) -> Result<Vec<MemoryRetrievalResult>, MemoryError> {
        validate_query(&query)?;
        self.repository.retrieve_confirmed(&query)
    }
}

fn validate_query(query: &RetrievalQuery) -> Result<(), MemoryError> {
    if query.life_id.trim().is_empty() {
        return Err(invalid_query("lifeId must not be empty."));
    }

    let query_text = query.query_text.trim();
    if query_text.is_empty() {
        return Err(invalid_query("queryText must not be empty."));
    }
    if query_text.chars().count() > MAX_QUERY_LENGTH {
        return Err(invalid_query("queryText is too long."));
    }
    if query.limit == 0 || query.limit > MAX_RESULT_LIMIT {
        return Err(invalid_query("limit must be between 1 and 100."));
    }

    Ok(())
}

fn invalid_query(message: &str) -> MemoryError {
    MemoryError::new("INVALID_RETRIEVAL_QUERY", message, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_query_and_invalid_limit() {
        let base = RetrievalQuery {
            life_id: "life-1".into(),
            query_text: "coffee".into(),
            kinds: None,
            limit: 5,
        };

        let mut empty = base.clone();
        empty.query_text = "  ".into();
        assert_eq!(
            validate_query(&empty).unwrap_err().code,
            "INVALID_RETRIEVAL_QUERY"
        );

        let mut invalid_limit = base;
        invalid_limit.limit = 0;
        assert_eq!(
            validate_query(&invalid_limit).unwrap_err().code,
            "INVALID_RETRIEVAL_QUERY"
        );
    }
}
