CREATE TABLE body_package (
    body_id TEXT PRIMARY KEY
        CHECK (body_id GLOB 'live2d-*'
            AND length(body_id) > 7
            AND length(body_id) <= 96
            AND substr(body_id, 8) NOT GLOB '*[^0-9a-fA-F]*'),
    display_name TEXT NOT NULL
        CHECK (display_name <> '' AND length(display_name) <= 128),
    presentation_kind TEXT NOT NULL
        CHECK (presentation_kind = 'live2d'),
    model_entry_path TEXT NOT NULL
        CHECK (model_entry_path <> '' AND length(model_entry_path) <= 512),
    package_content_hash TEXT NOT NULL
        CHECK (length(package_content_hash) = 64
            AND package_content_hash NOT GLOB '*[^0-9a-fA-F]*'),
    package_version INTEGER NOT NULL
        CHECK (package_version = 1),
    installed_at TEXT NOT NULL
        CHECK (installed_at <> '')
);
