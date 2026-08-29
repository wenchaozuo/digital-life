CREATE TABLE body_package_asset (
    body_id TEXT NOT NULL,
    relative_path TEXT NOT NULL
        CHECK (relative_path <> '' AND length(relative_path) <= 512),
    asset_kind TEXT NOT NULL
        CHECK (asset_kind IN (
            'model3', 'moc3', 'png', 'physics3', 'pose3', 'userdata3',
            'cdi3', 'motion3', 'expression3'
        )),
    content_hash TEXT NOT NULL
        CHECK (length(content_hash) = 64
            AND content_hash NOT GLOB '*[^0-9a-fA-F]*'),
    size_bytes INTEGER NOT NULL
        CHECK (size_bytes BETWEEN 0 AND 33554432),
    PRIMARY KEY (body_id, relative_path),
    FOREIGN KEY (body_id) REFERENCES body_package(body_id) ON DELETE CASCADE
);
