import { Router, Request, Response } from 'express';
import { z } from 'zod';
import { db } from '../db';
import { requireAuth } from '../auth';
import { verifyCsrf } from '../middleware/security';
import { authorize } from '../authorize';
import { writeAudit } from '../audit';

// mergeParams: true lets us read :id from the parent router
const router = Router({ mergeParams: true });
router.use(requireAuth);

const GrantSchema = z.object({
  username: z.string().min(1).max(64).regex(/^[a-zA-Z0-9_.-]+$/),
  can_read: z.boolean(),
  can_edit: z.boolean(),
});

// ── GET /api/documents/:id/permissions (owner only) ──────────────────────────

router.get('/', (req: Request, res: Response) => {
  const user = req.user!;
  const { id } = req.params;

  const authResult = authorize(user, 'view_permissions', id);
  if (!authResult.ok) {
    writeAudit({
      actor_id: user.id,
      action: 'ACCESS_DENIED',
      resource_id: id,
      outcome: 'DENY',
      detail: 'View permissions denied',
      deny_reason: authResult.reason,
    });
    res.status(404).json({ error: 'Document not found or access denied' });
    return;
  }

  const permissions = db
    .prepare(
      `SELECT p.id, p.grantee_id, u.username AS grantee_username,
              p.can_read, p.can_edit, p.granted_at, p.revoked_at,
              gb.username AS granted_by_username
       FROM permissions p
       JOIN users u  ON u.id  = p.grantee_id
       JOIN users gb ON gb.id = p.granted_by
       WHERE p.document_id = ?
       ORDER BY p.granted_at ASC`
    )
    .all(id);

  res.json({ permissions });
});

// ── POST /api/documents/:id/permissions ─ Grant (owner only) ─────────────────

router.post('/', verifyCsrf, (req: Request, res: Response) => {
  const user = req.user!;
  const { id } = req.params;

  const authResult = authorize(user, 'manage_permissions', id);
  if (!authResult.ok) {
    writeAudit({
      actor_id: user.id,
      action: 'GRANT_PERMISSION',
      resource_id: id,
      outcome: 'DENY',
      detail: 'Grant permission denied',
      deny_reason: authResult.reason,
    });
    res.status(404).json({ error: 'Document not found or access denied' });
    return;
  }

  const parsed = GrantSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid input' });
    return;
  }

  const { username, can_read, can_edit } = parsed.data;

  const grantee = db
    .prepare('SELECT id FROM users WHERE username = ?')
    .get(username) as { id: number } | undefined;

  if (!grantee) {
    res.status(404).json({ error: 'User not found' });
    return;
  }

  if (grantee.id === user.id) {
    res.status(400).json({ error: 'Cannot grant permissions to yourself' });
    return;
  }

  // Upsert: update if a row (even revoked) already exists for this (doc, user) pair
  db.prepare(`
    INSERT INTO permissions (document_id, grantee_id, can_read, can_edit, granted_by, revoked_at)
    VALUES (?, ?, ?, ?, ?, NULL)
    ON CONFLICT(document_id, grantee_id) DO UPDATE SET
      can_read   = excluded.can_read,
      can_edit   = excluded.can_edit,
      granted_by = excluded.granted_by,
      granted_at = datetime('now'),
      revoked_at = NULL
  `).run(id, grantee.id, can_read ? 1 : 0, can_edit ? 1 : 0, user.id);

  writeAudit({
    actor_id: user.id,
    action: 'GRANT_PERMISSION',
    resource_id: id,
    outcome: 'ALLOW',
    detail: `Granted to ${username}: can_read=${can_read}, can_edit=${can_edit}`,
  });

  res.json({ message: 'Permission granted' });
});

// ── DELETE /api/documents/:id/permissions/:userId ─ Revoke (owner only) ──────

router.delete('/:userId', verifyCsrf, (req: Request, res: Response) => {
  const user = req.user!;
  const { id, userId } = req.params;

  const authResult = authorize(user, 'manage_permissions', id);
  if (!authResult.ok) {
    writeAudit({
      actor_id: user.id,
      action: 'REVOKE_PERMISSION',
      resource_id: id,
      outcome: 'DENY',
      detail: `Revoke denied for user ${userId}`,
      deny_reason: authResult.reason,
    });
    res.status(404).json({ error: 'Document not found or access denied' });
    return;
  }

  const targetId = parseInt(userId, 10);
  if (isNaN(targetId)) {
    res.status(400).json({ error: 'Invalid user ID' });
    return;
  }

  const perm = db
    .prepare(
      `SELECT id FROM permissions
       WHERE document_id = ? AND grantee_id = ? AND revoked_at IS NULL`
    )
    .get(id, targetId) as { id: number } | undefined;

  if (!perm) {
    res.status(404).json({ error: 'Active permission not found' });
    return;
  }

  db.prepare(
    `UPDATE permissions SET revoked_at = datetime('now')
     WHERE document_id = ? AND grantee_id = ?`
  ).run(id, targetId);

  const target = db
    .prepare('SELECT username FROM users WHERE id = ?')
    .get(targetId) as { username: string } | undefined;

  writeAudit({
    actor_id: user.id,
    action: 'REVOKE_PERMISSION',
    resource_id: id,
    outcome: 'ALLOW',
    detail: `Revoked permission for user ${target?.username ?? targetId}`,
  });

  res.json({ message: 'Permission revoked' });
});

export default router;
