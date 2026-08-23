//! D10-E compile/reachability evidence: the legacy retrieval surfaces are
//! structurally withdrawn from the production build.  These tests assert the
//! authoritative source shape (the same style used by the group1 registration
//! tests) so a future re-introduction of the legacy production dependency
//! fails this suite, not at runtime in the field.

const MEMORY_MOD_SOURCE: &str = include_str!("mod.rs");
const ROUTER_SOURCE: &str = include_str!("retrieval_router.rs");
const STORAGE_RETRIEVAL_SOURCE: &str = include_str!("../storage/memory_retrieval.rs");
const VECTOR_STORE_SOURCE: &str = include_str!("../vector_store/mod.rs");

/// The authoritative sources are compared CRLF-agnostically so the same
/// structural proof holds on any checkout.
fn normalized(source: &str) -> String {
    source.replace("\r\n", "\n")
}

#[test]
fn d10_e_legacy_memory_retrieval_module_is_test_only() {
    // The legacy abstraction must be gated out of production builds.
    let source = normalized(MEMORY_MOD_SOURCE);
    assert!(
        source.contains("#[cfg(test)]\npub(crate) mod retrieval;"),
        "memory::retrieval must be test-only in memory/mod.rs"
    );
    let without_legacy_declaration = source.replace("#[cfg(test)]\npub(crate) mod retrieval;", "");
    assert!(
        !without_legacy_declaration.contains("mod retrieval;"),
        "no ungated retrieval module declaration may remain"
    );
}

#[test]
fn d10_e_production_router_uses_internal_keyword_id_boundary() {
    let router = normalized(ROUTER_SOURCE);
    assert!(
        router.contains("fn retrieve_keyword_ids"),
        "the internal keyword-ID boundary must exist"
    );
    assert!(
        router.contains(
            "trait AuthoritativeMemoryRetrievalRepository:\n    KeywordRetrievalRepository + Send + Sync"
        ),
        "the production repository boundary must derive from the keyword-ID boundary, not the legacy abstraction"
    );
    assert!(
        router.contains("match repository.retrieve_keyword_ids(&KeywordRetrievalQuery"),
        "the governed path must call the keyword-ID boundary"
    );
}

#[test]
fn d10_e_storage_keyword_repository_returns_ids_only() {
    let storage = normalized(STORAGE_RETRIEVAL_SOURCE);
    assert!(
        storage.contains("impl KeywordRetrievalRepository for StorageService"),
        "StorageService must implement the internal keyword-ID repository"
    );
    assert!(
        storage.contains("#[cfg(test)]\nimpl MemoryRetrievalRepository for StorageService"),
        "the legacy keyword implementation must be test-only"
    );
}

#[test]
fn d10_e_legacy_vector_search_types_are_test_only() {
    let vector_store = normalized(VECTOR_STORE_SOURCE);
    assert!(
        vector_store.contains(
            "#[cfg(test)]\n#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]\n#[serde(rename_all = \"camelCase\")]\npub struct VectorSearchQuery"
        ),
        "VectorSearchQuery must be test-only"
    );
    assert!(
        vector_store.contains(
            "#[cfg(test)]\n#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]\n#[serde(rename_all = \"camelCase\")]\npub struct VectorSearchHit"
        ),
        "VectorSearchHit must be test-only"
    );
    assert!(
        vector_store.contains("#[cfg(test)]\n    fn search<'a>("),
        "VectorStore::search must be test-only on the trait"
    );
}
