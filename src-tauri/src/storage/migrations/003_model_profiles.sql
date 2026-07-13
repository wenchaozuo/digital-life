CREATE TABLE model_profile (
    id TEXT PRIMARY KEY CHECK (length(trim(id)) > 0),
    purpose TEXT NOT NULL CHECK (purpose IN ('chat', 'embedding')),
    provider_kind TEXT NOT NULL CHECK (provider_kind = 'openai_compatible'),
    display_name TEXT NOT NULL CHECK (length(trim(display_name)) > 0),
    base_url TEXT NOT NULL CHECK (length(trim(base_url)) > 0),
    model_name TEXT NOT NULL CHECK (length(trim(model_name)) > 0),
    temperature REAL,
    max_tokens INTEGER,
    embedding_dimension INTEGER,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (id, purpose),
    CHECK (
        (purpose = 'chat'
            AND temperature IS NOT NULL
            AND temperature >= 0.0
            AND temperature <= 2.0
            AND max_tokens IS NOT NULL
            AND max_tokens > 0
            AND max_tokens <= 1000000
            AND embedding_dimension IS NULL)
        OR
        (purpose = 'embedding'
            AND temperature IS NULL
            AND max_tokens IS NULL
            AND embedding_dimension IS NOT NULL
            AND embedding_dimension > 0
            AND embedding_dimension <= 65536)
    )
);

CREATE INDEX idx_model_profile_purpose
    ON model_profile(purpose);

CREATE TABLE active_model_profile (
    purpose TEXT PRIMARY KEY CHECK (purpose IN ('chat', 'embedding')),
    profile_id TEXT NOT NULL,
    FOREIGN KEY (profile_id, purpose)
        REFERENCES model_profile(id, purpose)
        ON DELETE CASCADE
);
