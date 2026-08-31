CREATE TABLE model_profile_029 (
    id TEXT PRIMARY KEY CHECK (length(trim(id)) > 0),
    purpose TEXT NOT NULL CHECK (purpose IN ('chat', 'embedding', 'candidate_extraction', 'vision')),
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
        OR
        (purpose = 'candidate_extraction'
            AND temperature IS NOT NULL
            AND temperature = 0.0
            AND max_tokens IS NOT NULL
            AND typeof(max_tokens) = 'integer'
            AND max_tokens >= 1
            AND max_tokens <= 4096
            AND embedding_dimension IS NULL)
        OR
        (purpose = 'vision'
            AND temperature IS NOT NULL
            AND temperature = 0.0
            AND max_tokens IS NOT NULL
            AND typeof(max_tokens) = 'integer'
            AND max_tokens >= 1
            AND max_tokens <= 4096
            AND embedding_dimension IS NULL)
    )
);

INSERT INTO model_profile_029 (
    rowid,
    id,
    purpose,
    provider_kind,
    display_name,
    base_url,
    model_name,
    temperature,
    max_tokens,
    embedding_dimension,
    created_at,
    updated_at
)
SELECT
    rowid,
    id,
    purpose,
    provider_kind,
    display_name,
    base_url,
    model_name,
    temperature,
    max_tokens,
    embedding_dimension,
    created_at,
    updated_at
FROM model_profile;

CREATE TABLE active_model_profile_029 (
    source_rowid INTEGER NOT NULL,
    purpose TEXT PRIMARY KEY CHECK (purpose IN ('chat', 'embedding', 'candidate_extraction', 'vision')),
    profile_id TEXT NOT NULL
);

INSERT INTO active_model_profile_029 (source_rowid, purpose, profile_id)
SELECT rowid, purpose, profile_id
FROM active_model_profile;

DROP TABLE active_model_profile;
DROP TABLE model_profile;

ALTER TABLE model_profile_029 RENAME TO model_profile;

CREATE INDEX idx_model_profile_purpose
    ON model_profile(purpose);

CREATE TABLE active_model_profile (
    purpose TEXT PRIMARY KEY CHECK (purpose IN ('chat', 'embedding', 'candidate_extraction', 'vision')),
    profile_id TEXT NOT NULL,
    FOREIGN KEY (profile_id, purpose)
        REFERENCES model_profile(id, purpose)
        ON DELETE CASCADE
);

INSERT INTO active_model_profile (rowid, purpose, profile_id)
SELECT source_rowid, purpose, profile_id
FROM active_model_profile_029;

DROP TABLE active_model_profile_029;
