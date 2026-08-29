CREATE TABLE live2d_core_component (
    slot TEXT PRIMARY KEY NOT NULL CHECK (slot = 'active'),
    runtime_family TEXT NOT NULL CHECK (runtime_family = 'cubism4'),
    version_label TEXT NOT NULL CHECK (length(trim(version_label)) BETWEEN 1 AND 128),
    sha256 TEXT NOT NULL CHECK (
        length(sha256) = 64
        AND lower(sha256) = sha256
        AND sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    managed_relative_path TEXT NOT NULL CHECK (managed_relative_path = 'live2dcubismcore.min.js'),
    installed_at TEXT NOT NULL CHECK (length(trim(installed_at)) > 0)
);