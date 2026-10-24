import { Router, Request, Response } from 'express';
import { z } from 'zod';
import type { SQLInputValue } from 'node:sqlite';
import { db } from '../db';
import { requireAuth, requireAdmin } from '../auth';
import { verifyAuditChain } from '../audit';

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

  const { count } = db.prepare(
    `SELECT COUNT(*) AS count FROM audit_log al ${where}`
  ).get(params) as { count: number };

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

export default router;
