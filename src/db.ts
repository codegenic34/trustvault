import { DatabaseSync } from 'node:sqlite';
import path from 'path';
import fs from 'fs';

export const STORAGE_DIR = path.join(__dirname, '..', 'storage');
const DB_PATH = path.join(__dirname, '..', 'trustvault.db');

// Ensure private storage directory exists (never inside public/)
fs.mkdirSync(STORAGE_DIR, { recursive: true });

export const db = new DatabaseSync(DB_PATH);

export function initDB(): void {
  db.exec('PRAGMA journal_mode = WAL');
  db.exec('PRAGMA foreign_keys = ON');

  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      username      TEXT    UNIQUE NOT NULL COLLATE NOCASE,
      password_hash TEXT    NOT NULL,
      role          TEXT    NOT NULL CHECK(role IN ('admin', 'owner', 'viewer')),
      active        INTEGER NOT NULL DEFAULT 1,
      created_at    TEXT    NOT NULL DEFAULT (datetime('now')),
      full_name     TEXT,
      email         TEXT,
      last_login    TEXT
    );

    CREATE TABLE IF NOT EXISTS sessions (
      id          TEXT    PRIMARY KEY,
      user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      csrf_token  TEXT    NOT NULL,
      expires_at  TEXT    NOT NULL,
      created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
      user_agent  TEXT,
      last_active TEXT    NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS documents (
      id            TEXT    PRIMARY KEY,
      owner_id      INTEGER NOT NULL REFERENCES users(id),
      storage_name  TEXT    NOT NULL UNIQUE,
      original_name TEXT    NOT NULL,
      mime_type     TEXT    NOT NULL,
      category      TEXT    NOT NULL DEFAULT '',
      size          INTEGER NOT NULL,
      created_at    TEXT    NOT NULL DEFAULT (datetime('now')),
      deleted       INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS permissions (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      document_id  TEXT    NOT NULL REFERENCES documents(id),
      grantee_id   INTEGER NOT NULL REFERENCES users(id),
      can_read     INTEGER NOT NULL DEFAULT 0,
      can_edit     INTEGER NOT NULL DEFAULT 0,
      granted_by   INTEGER NOT NULL REFERENCES users(id),
      granted_at   TEXT    NOT NULL DEFAULT (datetime('now')),
      revoked_at   TEXT,
      UNIQUE(document_id, grantee_id)
    );

    CREATE TABLE IF NOT EXISTS audit_log (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp   TEXT    NOT NULL,
      actor_id    INTEGER,
      action      TEXT    NOT NULL,
      resource_id TEXT,
      outcome     TEXT    NOT NULL CHECK(outcome IN ('ALLOW', 'DENY')),
      detail      TEXT,
      deny_reason TEXT,
      prev_hash   TEXT    NOT NULL DEFAULT '',
      row_hash    TEXT    NOT NULL
    );

    -- Triggers make audit_log truly append-only at the DB layer
    CREATE TRIGGER IF NOT EXISTS audit_no_update
    BEFORE UPDATE ON audit_log
    BEGIN
      SELECT RAISE(ABORT, 'audit_log is append-only: UPDATE not permitted');
    END;

    CREATE TRIGGER IF NOT EXISTS audit_no_delete
    BEFORE DELETE ON audit_log
    BEGIN
      SELECT RAISE(ABORT, 'audit_log is append-only: DELETE not permitted');
    END;
  `);

  // Safe migrations for pre-existing databases
  try { db.exec('ALTER TABLE users ADD COLUMN full_name TEXT'); } catch {}
  try { db.exec('ALTER TABLE users ADD COLUMN email TEXT'); } catch {}
  try { db.exec('ALTER TABLE users ADD COLUMN last_login TEXT'); } catch {}
  try { db.exec('ALTER TABLE sessions ADD COLUMN user_agent TEXT'); } catch {}
  try { db.exec('ALTER TABLE sessions ADD COLUMN last_active TEXT'); } catch {}
}
