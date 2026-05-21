SCHEMA_V1 = """
CREATE TABLE IF NOT EXISTS vault_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    username TEXT,
    encrypted_password BLOB NOT NULL,
    url TEXT,
    notes BLOB,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    tags TEXT
);

CREATE INDEX IF NOT EXISTS idx_vault_title ON vault_entries(title);
CREATE INDEX IF NOT EXISTS idx_vault_username ON vault_entries(username);
CREATE INDEX IF NOT EXISTS idx_vault_updated ON vault_entries(updated_at);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT NOT NULL,
    timestamp TIMESTAMP NOT NULL,
    entry_id INTEGER,
    details TEXT,
    signature BLOB
);

CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_entry ON audit_log(entry_id);

CREATE TABLE IF NOT EXISTS settings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    setting_key TEXT NOT NULL UNIQUE,
    setting_value TEXT,
    encrypted INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_settings_key ON settings(setting_key);

CREATE TABLE IF NOT EXISTS key_store (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_type TEXT NOT NULL,
    key_data BLOB NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_keystore_type_version ON key_store(key_type, version);
"""

SCHEMA_V2 = """
CREATE TABLE IF NOT EXISTS key_store_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_type TEXT NOT NULL,
    key_data BLOB NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_keystore_type_version ON key_store_new(key_type, version);
"""

SCHEMA_V3 = """
INSERT OR IGNORE INTO settings (setting_key, setting_value, encrypted)
VALUES
('password_policy.min_length', '12', 0),
('password_policy.require_uppercase', 'true', 0),
('password_policy.require_lowercase', 'true', 0),
('password_policy.require_digits', 'true', 0),
('password_policy.require_special', 'true', 0),
('key_derivation.argon2', '{"time_cost":3,"memory_cost":65536,"parallelism":2,"hash_len":32,"salt_len":16}', 0),
('key_derivation.pbkdf2', '{"iterations":100000,"dklen":32,"hash_name":"sha256","salt_len":16}', 0),
('security.auto_lock_timeout_sec', '900', 0),
('clipboard.clear_timeout_sec', '30', 0);
"""

SCHEMA_V4 = """
CREATE TABLE IF NOT EXISTS vault_entries_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    encrypted_data BLOB NOT NULL,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    tags TEXT
);

CREATE INDEX IF NOT EXISTS idx_vault_created_v4 ON vault_entries_new(created_at);
CREATE INDEX IF NOT EXISTS idx_vault_updated_v4 ON vault_entries_new(updated_at);
"""

SCHEMA_V5 = """
CREATE TABLE IF NOT EXISTS audit_log_new (
    sequence_number INTEGER PRIMARY KEY AUTOINCREMENT,
    previous_hash TEXT NOT NULL,
    entry_data BLOB NOT NULL,
    entry_hash TEXT NOT NULL,
    signature TEXT NOT NULL,
    signature_algorithm TEXT NOT NULL DEFAULT 'Ed25519',
    timestamp TEXT NOT NULL,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    user_id TEXT NOT NULL,
    source TEXT NOT NULL,
    entry_id INTEGER
);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp_v5 ON audit_log_new(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_event_type_v5 ON audit_log_new(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_sequence_v5 ON audit_log_new(sequence_number);
CREATE INDEX IF NOT EXISTS idx_audit_severity_v5 ON audit_log_new(severity);

CREATE TABLE IF NOT EXISTS audit_write_control (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    allow_mutation INTEGER NOT NULL DEFAULT 0
);

INSERT OR IGNORE INTO audit_write_control(id, allow_mutation)
VALUES (1, 0);

CREATE TABLE IF NOT EXISTS audit_public_keys (
    key_id TEXT PRIMARY KEY,
    algorithm TEXT NOT NULL,
    public_key TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_entry_keys (
    sequence_number INTEGER PRIMARY KEY,
    algorithm TEXT NOT NULL,
    public_key TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log_archive (
    archive_id INTEGER PRIMARY KEY AUTOINCREMENT,
    archived_at TEXT NOT NULL,
    first_sequence INTEGER NOT NULL,
    last_sequence INTEGER NOT NULL,
    entry_count INTEGER NOT NULL,
    reason TEXT NOT NULL,
    archive_data BLOB NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_archive_time_v5 ON audit_log_archive(archived_at);
CREATE INDEX IF NOT EXISTS idx_audit_archive_range_v5 ON audit_log_archive(first_sequence, last_sequence);

CREATE TABLE IF NOT EXISTS audit_security_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    details TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_security_time_v5 ON audit_security_log(timestamp);

INSERT OR IGNORE INTO settings (setting_key, setting_value, encrypted)
VALUES
('audit.rotation.max_entries', '10000', 0),
('audit.rotation.max_age_days', '365', 0),
('audit.verification.interval_hours', '24', 0),
('audit.verification.recent_entries', '1000', 0),
('audit.export.schedule', 'disabled', 0),
('audit.export.retention_days', '90', 0);
"""
