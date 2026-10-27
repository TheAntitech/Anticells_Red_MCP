CREATE TABLE catalog_schema_migrations (
    version INTEGER PRIMARY KEY
);
CREATE TABLE catalog_state (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    revision INTEGER NOT NULL DEFAULT 0 CHECK (revision >= 0)
);
INSERT INTO catalog_state(singleton) VALUES (1);
CREATE TABLE catalog_records (
    id TEXT PRIMARY KEY NOT NULL,
    namespace TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('technique', 'template', 'data')),
    position INTEGER NOT NULL CHECK (position >= 0),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    revision INTEGER NOT NULL CHECK (revision >= 1),
    memberships BLOB NOT NULL,
    content BLOB NOT NULL,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX records_namespace_order ON catalog_records(namespace, position, id);
INSERT INTO catalog_schema_migrations(version) VALUES (1);
