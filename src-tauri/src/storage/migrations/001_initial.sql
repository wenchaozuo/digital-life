CREATE TABLE persona_template (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    version INTEGER NOT NULL,
    persona_json TEXT NOT NULL
);

CREATE TABLE life_identity (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_at TEXT NOT NULL,
    version INTEGER NOT NULL,
    body_id TEXT NOT NULL,
    persona_id TEXT NOT NULL,
    persona_version INTEGER NOT NULL,
    FOREIGN KEY (persona_id) REFERENCES persona_template(id)
);

CREATE TABLE app_state (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    current_life_id TEXT,
    FOREIGN KEY (current_life_id) REFERENCES life_identity(id)
);
