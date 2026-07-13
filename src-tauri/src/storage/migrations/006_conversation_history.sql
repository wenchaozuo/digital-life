CREATE TABLE IF NOT EXISTS conversation (
    id TEXT PRIMARY KEY NOT NULL,
    life_id TEXT NOT NULL,
    title TEXT NOT NULL CHECK (
        length(trim(title)) BETWEEN 1 AND 120
    ),
    revision INTEGER NOT NULL DEFAULT 0 CHECK (revision >= 0),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    last_message_at TEXT NOT NULL,
    UNIQUE (id, life_id),
    FOREIGN KEY (life_id) REFERENCES life_identity(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_conversation_life_recent
    ON conversation(life_id, last_message_at DESC, id ASC);

CREATE TABLE IF NOT EXISTS conversation_message (
    id TEXT PRIMARY KEY NOT NULL,
    conversation_id TEXT NOT NULL,
    life_id TEXT NOT NULL,
    turn_id TEXT NOT NULL CHECK (length(trim(turn_id)) > 0),
    role TEXT NOT NULL CHECK (role IN ('user', 'assistant')),
    content TEXT NOT NULL CHECK (
        length(trim(content)) > 0 AND length(content) <= 32000
    ),
    sequence_no INTEGER NOT NULL CHECK (sequence_no > 0),
    created_at TEXT NOT NULL,
    UNIQUE (conversation_id, sequence_no),
    UNIQUE (conversation_id, turn_id, role),
    FOREIGN KEY (conversation_id, life_id)
        REFERENCES conversation(id, life_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_conversation_message_sequence
    ON conversation_message(conversation_id, life_id, sequence_no ASC);
