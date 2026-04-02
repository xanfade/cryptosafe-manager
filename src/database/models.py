SCHEMA_V1 = """
CREATE TABLE IF NOT EXISTS vault_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    username TEXT,
    encrypted_password BLOB NOT NULL,
    url TEXT,
    notes BLOB,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    tags TEXT
);

CREATE INDEX IF NOT EXISTS idx_vault_title ON vault_entries(title);
CREATE INDEX IF NOT EXISTS idx_vault_username ON vault_entries(username);
CREATE INDEX IF NOT EXISTS idx_vault_updated ON vault_entries(updated_at);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT NOT NULL,
    timestamp TEXT NOT NULL,
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
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_keystore_type_version
ON key_store(key_type, version);
"""

SCHEMA_V2 = """
CREATE TABLE IF NOT EXISTS key_store_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_type TEXT NOT NULL,
    key_data BLOB NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_keystore_type_version
ON key_store_new(key_type, version);
"""

SCHEMA_V3 = """
INSERT OR IGNORE INTO settings (setting_key, setting_value, encrypted) VALUES
('password_policy.min_length', '12', 0),
('password_policy.require_uppercase', 'true', 0),
('password_policy.require_lowercase', 'true', 0),
('password_policy.require_digits', 'true', 0),
('password_policy.require_special', 'true', 0),
('key_derivation.argon2', '{"time_cost":3,"memory_cost":65536,"parallelism":2,"hash_len":32,"salt_len":16}', 0),
('key_derivation.pbkdf2', '{"iterations":600000,"dklen":32,"hash_name":"sha256","salt_len":16}', 0),
('security.auto_lock_timeout_sec', '900', 0);
"""

SCHEMA_V4 = """
CREATE TABLE IF NOT EXISTS vault_entries_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    encrypted_blob BLOB NOT NULL,
    tags TEXT,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_vault_updated_v4 ON vault_entries_new(updated_at);
"""