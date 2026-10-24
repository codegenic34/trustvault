import { Router, Request, Response } from 'express';
import { z } from 'zod';
import type { SQLInputValue } from 'node:sqlite';
import { db } from '../db';
import { requireAuth, requireAdmin } from '../auth';
import { verifyAuditChain, writeAudit } from '../audit';
import { verifyCsrf } from '../middleware/security';

const router = Router();
router.use(requireAuth, requireAdmin);

const AuditQuerySchema = z.object({
  action:   z.string().max(50).optional(),
  outcome:  z.enum(['ALLOW', 'DENY']).optional(),
  actor_id: z.string().regex(/^\d+$/).optional(),
  from:     z.string().max(30).optional(),
  to:       z.string().max(30).optional(),
  limit:    z.string().regex(/^\d+$/).transform(Number).optional(),
  offset:   z.string().regex(/^\d+$/).transform(Number).optional(),
});

// ── GET /api/audit ─ Filtered audit log (admin only) ─────────────────────────

router.get('/', (req: Request, res: Response) => {
  const parsed = AuditQuerySchema.safeParse(req.query);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid query parameters' });
    return;
  }

  const { action, outcome, actor_id, from, to } = parsed.data;
  const limit  = Math.min(parsed.data.limit  ?? 100, 500);
  const offset = parsed.data.offset ?? 0;

  const conditions: string[] = [];
  const params: Record<string, SQLInputValue> = { limit, offset };

  if (action)   { conditions.push('al.action = @action');      params.action   = action; }
  if (outcome)  { conditions.push('al.outcome = @outcome');    params.outcome  = outcome; }
  if (actor_id) { conditions.push('al.actor_id = @actor_id'); params.actor_id = parseInt(actor_id, 10); }
  if (from)     { conditions.push('al.timestamp >= @from');    params.from     = from; }
  if (to)       { conditions.push('al.timestamp <= @to');      params.to       = to; }

  const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';

  const logs = db.prepare(`
    SELECT al.id, al.timestamp, al.actor_id, al.action, al.resource_id,
           al.outcome, al.detail, al.deny_reason,
           u.username AS actor_username
    FROM audit_log al
    LEFT JOIN users u ON u.id = al.actor_id
    ${where}
    ORDER BY al.id DESC
    LIMIT @limit OFFSET @offset
  `).all(params);

  const countParams: Record<string, SQLInputValue> = {};
  if (action) countParams.action = params.action;
  if (outcome) countParams.outcome = params.outcome;
  if (actor_id) countParams.actor_id = params.actor_id;
  if (from) countParams.from = params.from;
  if (to) countParams.to = params.to;

  const { count } = db.prepare(
    `SELECT COUNT(*) AS count FROM audit_log al ${where}`
  ).get(countParams) as { count: number };

  res.json({ logs, total: count, limit, offset });
});

// ── GET /api/audit/verify ─ Hash-chain integrity check ───────────────────────

router.get('/verify', (_req: Request, res: Response) => {
  const result = verifyAuditChain();
  res.json(result);
});

// ── GET /api/audit/suspicious ─ Highlighted anomalies ────────────────────────

router.get('/suspicious', (_req: Request, res: Response) => {
  // Users with ≥ 3 DENY events in the last 24 hours
  const repeatedDenials = db.prepare(`
    SELECT al.actor_id,
           u.username,
           COUNT(*)          AS deny_count,
           MAX(al.timestamp) AS last_attempt
    FROM audit_log al
    LEFT JOIN users u ON u.id = al.actor_id
    WHERE al.outcome   = 'DENY'
      AND al.timestamp > datetime('now', '-24 hours')
      AND al.actor_id IS NOT NULL
    GROUP BY al.actor_id
    HAVING deny_count >= 3
    ORDER BY deny_count DESC
  `).all();

  // Any access attempt after a permission was revoked
  const postRevocation = db.prepare(`
    SELECT al.id, al.timestamp, al.actor_id, al.resource_id,
           u.username AS actor_username
    FROM audit_log al
    LEFT JOIN users u ON u.id = al.actor_id
    WHERE al.deny_reason = 'REVOKED'
    ORDER BY al.timestamp DESC
    LIMIT 100
  `).all();

  // Access attempts by disabled users
  const disabledAttempts = db.prepare(`
    SELECT al.id, al.timestamp, al.actor_id,
           u.username AS actor_username
    FROM audit_log al
    LEFT JOIN users u ON u.id = al.actor_id
    WHERE al.deny_reason = 'DISABLED_USER'
    ORDER BY al.timestamp DESC
    LIMIT 100
  `).all();

  res.json({ repeatedDenials, postRevocation, disabledAttempts });
});

// ── GET /users ─ List all users for admin management ────────────────────────
router.get('/users', (_req: Request, res: Response) => {
  const users = db.prepare(`
    SELECT id, username, role, active, created_at, full_name, email, last_login
    FROM users
    ORDER BY id ASC
  `).all();
  res.json({ users });
});

const ChangeRoleSchema = z.object({
  role: z.enum(['owner', 'viewer']),
});

// ── POST /users/:id/role ─ Switch between viewer and owner (admin only) ──────
router.post('/users/:id/role', verifyCsrf, (req: Request, res: Response) => {
  const userId = parseInt(req.params.id, 10);
  if (isNaN(userId)) {
    res.status(400).json({ error: 'Invalid user ID' });
    return;
  }

  const parsed = ChangeRoleSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'Role must be either "owner" or "viewer"' });
    return;
  }

  const { role } = parsed.data;

  const target = db
    .prepare('SELECT id, username, role FROM users WHERE id = ?')
    .get(userId) as { id: number; username: string; role: string } | undefined;

  if (!target) {
    res.status(404).json({ error: 'User not found' });
    return;
  }

  if (target.role === 'admin') {
    res.status(400).json({ error: 'Cannot change administrator role' });
    return;
  }

  if (target.role === role) {
    res.json({ message: `User is already an ${role}`, user: target });
    return;
  }

  db.prepare('UPDATE users SET role = ? WHERE id = ?').run(role, userId);

  writeAudit({
    actor_id: req.user!.id,
    action: 'ROLE_CHANGED',
    outcome: 'ALLOW',
    detail: `Admin changed role of user ${target.username} from ${target.role} to ${role}`,
  });

  res.json({
    message: `User ${target.username} role updated to ${role} successfully.`,
    user: { id: target.id, username: target.username, role },
  });
});

export default router;

