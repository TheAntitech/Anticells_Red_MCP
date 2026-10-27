CREATE TABLE report_schema_migrations (version INTEGER PRIMARY KEY);
INSERT INTO report_schema_migrations VALUES (1);
CREATE TABLE sessions (id TEXT PRIMARY KEY, created_at TEXT NOT NULL, status TEXT NOT NULL, document BLOB NOT NULL);
CREATE TABLE runs (id TEXT PRIMARY KEY, session_id TEXT NOT NULL REFERENCES sessions(id), created_at TEXT NOT NULL, status TEXT NOT NULL, document BLOB NOT NULL);
CREATE INDEX runs_session ON runs(session_id, created_at);
CREATE TABLE results (id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE, created_at TEXT NOT NULL, document BLOB NOT NULL);
CREATE INDEX results_run ON results(run_id, created_at);
CREATE TABLE exports (id TEXT PRIMARY KEY, filename TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL, document BLOB NOT NULL);
CREATE TABLE export_runs (export_id TEXT NOT NULL REFERENCES exports(id) ON DELETE CASCADE, run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE, PRIMARY KEY(export_id, run_id));
