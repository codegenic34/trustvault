import crypto from 'crypto';
import { db } from './db';

export type DenyReason =
  | 'NOT_FOUND'
  | 'NO_PERMISSION'
  | 'REVOKED'
  | 'DISABLED_USER'
  | 'WRONG_ROLE'
  | 'RATE_LIMITED'
  | 'INVALID_CREDENTIALS'
  | 'CSRF_INVALID'
  | 'SESSION_EXPIRED';

export interface AuditEntry {
  actor_id?: number | null;
  action: string;
  resource_id?: string | null;
  outcome: 'ALLOW' | 'DENY';
  detail?: string | null;
  deny_reason?: DenyReason | null;
}

interface AuditRow {
  id: number;
  timestamp: string;
  actor_id: number | null;
  action: string;
  resource_id: string | null;
  outcome: string;
  detail: string | null;
  deny_reason: string | null;
  prev_hash: string;
  row_hash: string;
}

function buildHashInput(
  prevHash: string,
  timestamp: string,
  entry: AuditEntry
): string {
  // Null-byte separator prevents hash-collision via concatenation tricks
  return [
    prevHash,
    timestamp,
    String(entry.actor_id ?? ''),
    entry.action,
    entry.resource_id ?? '',
    entry.outcome,
    entry.detail ?? '',
    entry.deny_reason ?? '',
  ].join('\x00');
}

/**
 * Append one entry to the audit log inside a serialised transaction so the
 * hash chain cannot fork under concurrent requests.
 * node:sqlite DatabaseSync is single-threaded synchronous — BEGIN IMMEDIATE
 * serialises any concurrent callers in the event loop.
 */
export function writeAudit(entry: AuditEntry): void {
  db.exec('BEGIN IMMEDIATE');
  try {
    const last = db
      .prepare('SELECT row_hash FROM audit_log ORDER BY id DESC LIMIT 1')
      .get() as { row_hash: string } | undefined;

    const prevHash = last?.row_hash ?? '';
    const timestamp = new Date().toISOString();
    const rowHash = crypto
      .createHash('sha256')
      .update(buildHashInput(prevHash, timestamp, entry), 'utf8')
      .digest('hex');

    db.prepare(`
      INSERT INTO audit_log
        (timestamp, actor_id, action, resource_id, outcome, detail, deny_reason, prev_hash, row_hash)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      timestamp,
      entry.actor_id ?? null,
      entry.action,
      entry.resource_id ?? null,
      entry.outcome,
      entry.detail ?? null,
      entry.deny_reason ?? null,
      prevHash,
      rowHash
    );

    db.exec('COMMIT');
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }
}

/**
 * Recompute every SHA-256 link in the chain and return the first broken row.
 */
export function verifyAuditChain(): {
  valid: boolean;
  totalRows: number;
  brokenAt?: number;
} {
  const rows = db
    .prepare('SELECT * FROM audit_log ORDER BY id ASC')
    .all() as unknown as AuditRow[];

  let prevHash = '';
  for (const row of rows) {
    if (row.prev_hash !== prevHash) {
      return { valid: false, totalRows: rows.length, brokenAt: row.id };
    }
    const expected = crypto
      .createHash('sha256')
      .update(buildHashInput(prevHash, row.timestamp, row as unknown as AuditEntry), 'utf8')
      .digest('hex');
    if (row.row_hash !== expected) {
      return { valid: false, totalRows: rows.length, brokenAt: row.id };
    }
    prevHash = row.row_hash;
  }
  return { valid: true, totalRows: rows.length };
}
