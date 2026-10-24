import { db } from './db';
import type { DenyReason } from './audit';

export type Action =
  | 'read'
  | 'download'
  | 'edit_metadata'
  | 'delete'
  | 'manage_permissions'
  | 'view_permissions';

export interface SessionUser {
  id: number;
  username: string;
  role: 'admin' | 'owner' | 'viewer';
  active: number;
}

export interface AuthorizeResult {
  ok: boolean;
  reason?: DenyReason;
}

interface DocRow {
  id: string;
  owner_id: number;
  deleted: number;
}

interface PermRow {
  can_read: number;
  can_edit: number;
  revoked_at: string | null;
}

/**
 * THE single choke-point for every document action.
 *
 * Rules enforced here:
 *  - Disabled user → DISABLED_USER (Rule 16)
 *  - Load resource from DB; never trust client data (GEMINI Rule 2)
 *  - Nonexistent == unauthorized → NOT_FOUND (client sees 404 either way)
 *  - Admin role alone does NOT satisfy any document action (Rule 12)
 *  - Only owner can manage_permissions / delete (Rules 13, 4)
 *  - Revoked grant detected per-request (GEMINI Rule 4)
 *  - Default deny
 */
export function authorize(
  user: SessionUser,
  action: Action,
  documentId: string
): AuthorizeResult {
  if (!user.active) return { ok: false, reason: 'DISABLED_USER' };

  const doc = db
    .prepare('SELECT id, owner_id, deleted FROM documents WHERE id = ?')
    .get(documentId) as DocRow | undefined;

  if (!doc || doc.deleted) return { ok: false, reason: 'NOT_FOUND' };

  // manage_permissions / view_permissions: owner ONLY (not even editors, not admin)
  if (action === 'manage_permissions' || action === 'view_permissions') {
    return user.id === doc.owner_id
      ? { ok: true }
      : { ok: false, reason: 'WRONG_ROLE' };
  }

  // delete: owner ONLY
  if (action === 'delete') {
    return user.id === doc.owner_id
      ? { ok: true }
      : { ok: false, reason: 'NO_PERMISSION' };
  }

  // read / download: owner OR active can_read grant (admin gets no free pass)
  if (action === 'read' || action === 'download') {
    if (user.id === doc.owner_id) return { ok: true };

    const perm = db
      .prepare(
        `SELECT can_read, revoked_at
         FROM permissions
         WHERE document_id = ? AND grantee_id = ? AND can_read = 1
         LIMIT 1`
      )
      .get(documentId, user.id) as PermRow | undefined;

    if (!perm) return { ok: false, reason: 'NO_PERMISSION' };
    if (perm.revoked_at !== null) return { ok: false, reason: 'REVOKED' };
    return { ok: true };
  }

  // edit_metadata: owner OR active can_edit grant
  if (action === 'edit_metadata') {
    if (user.id === doc.owner_id) return { ok: true };

    const perm = db
      .prepare(
        `SELECT can_edit, revoked_at
         FROM permissions
         WHERE document_id = ? AND grantee_id = ? AND can_edit = 1
         LIMIT 1`
      )
      .get(documentId, user.id) as PermRow | undefined;

    if (!perm) return { ok: false, reason: 'NO_PERMISSION' };
    if (perm.revoked_at !== null) return { ok: false, reason: 'REVOKED' };
    return { ok: true };
  }

  return { ok: false, reason: 'NO_PERMISSION' };
}
