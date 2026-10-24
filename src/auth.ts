import crypto from 'crypto';
import { Request, Response, NextFunction } from 'express';
import { db } from './db';
import { writeAudit } from './audit';
import type { SessionUser } from './authorize';

const SESSION_DURATION_MS = 8 * 60 * 60 * 1000; // 8 hours

export function createSession(userId: number, userAgent?: string): {
  token: string;
  csrfToken: string;
} {
  const token = crypto.randomBytes(32).toString('hex');
  const csrfToken = crypto.randomBytes(32).toString('hex');
  const now = new Date().toISOString();
  const expiresAt = new Date(Date.now() + SESSION_DURATION_MS).toISOString();
  try {
    db.prepare(
      'INSERT INTO sessions (id, user_id, csrf_token, expires_at, user_agent, last_active) VALUES (?, ?, ?, ?, ?, ?)'
    ).run(token, userId, csrfToken, expiresAt, userAgent || 'Unknown Device / Browser', now);
  } catch {
    db.prepare(
      'INSERT INTO sessions (id, user_id, csrf_token, expires_at) VALUES (?, ?, ?, ?)'
    ).run(token, userId, csrfToken, expiresAt);
  }
  return { token, csrfToken };
}

export function deleteSession(token: string): void {
  db.prepare('DELETE FROM sessions WHERE id = ?').run(token);
}

/**
 * Middleware: validates the session cookie and the user's active flag on
 * EVERY request so revoked sessions and disabled accounts take effect
 * immediately on the next request (GEMINI Rules 4 & 16).
 */
export function requireAuth(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  const token = req.cookies?.['tv_session'];
  if (!token || typeof token !== 'string') {
    res.status(401).json({ error: 'Not authenticated' });
    return;
  }

  const row = db
    .prepare(
      `SELECT s.user_id, s.expires_at, s.csrf_token,
              u.username, u.role, u.active
       FROM sessions s
       JOIN users u ON u.id = s.user_id
       WHERE s.id = ?`
    )
    .get(token) as
    | {
        user_id: number;
        expires_at: string;
        csrf_token: string;
        username: string;
        role: string;
        active: number;
      }
    | undefined;

  if (!row) {
    res.status(401).json({ error: 'Invalid session' });
    return;
  }

  if (new Date(row.expires_at) < new Date()) {
    deleteSession(token);
    res.status(401).json({ error: 'Session expired' });
    return;
  }

  // Rule 16: disabled user sessions stop working on the next request
  if (!row.active) {
    writeAudit({
      actor_id: row.user_id,
      action: 'AUTH_CHECK',
      outcome: 'DENY',
      detail: 'Request blocked — user account is disabled',
      deny_reason: 'DISABLED_USER',
    });
    res.status(401).json({ error: 'Account disabled' });
    return;
  }

  req.user = {
    id: row.user_id,
    username: row.username,
    role: row.role as 'admin' | 'owner' | 'viewer',
    active: row.active,
  };
  req.csrfToken = row.csrf_token;
  try {
    db.prepare('UPDATE sessions SET last_active = datetime("now") WHERE id = ?').run(token);
  } catch {}
  next();
}

export function requireAdmin(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  if (!req.user || req.user.role !== 'admin') {
    writeAudit({
      actor_id: req.user?.id ?? null,
      action: 'ACCESS_DENIED',
      outcome: 'DENY',
      detail: 'Admin route accessed by non-admin',
      deny_reason: 'WRONG_ROLE',
    });
    res.status(403).json({ error: 'Forbidden' });
    return;
  }
  next();
}

// Augment Express Request so all routes get typed req.user / req.csrfToken
declare global {
  namespace Express {
    interface Request {
      user?: SessionUser;
      csrfToken?: string;
    }
  }
}
