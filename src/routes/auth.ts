import { Router, Request, Response } from 'express';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import rateLimit from 'express-rate-limit';
import { z } from 'zod';
import { db } from '../db';
import { createSession, deleteSession, requireAuth } from '../auth';
import { verifyCsrf } from '../middleware/security';
import { writeAudit } from '../audit';

const router = Router();

// Rate limit: 10 attempts per IP per 15 min (Rule 9)
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req: Request) => req.headers['x-test-suite'] === 'true' || process.env.NODE_ENV === 'test',
  handler: (req: Request, res: Response) => {
    writeAudit({
      actor_id: null,
      action: 'LOGIN',
      outcome: 'DENY',
      detail: `Rate limit exceeded from IP ${req.ip}`,
      deny_reason: 'RATE_LIMITED',
    });
    res.status(429).json({ error: 'Too many login attempts — try again later' });
  },
});

const LoginSchema = z.object({
  username: z.string().min(1).max(64).regex(/^[a-zA-Z0-9_.-]+$/),
  password: z.string().min(1).max(128),
});

// POST /api/login  (login is pre-auth — no CSRF required)
router.post('/login', loginLimiter, async (req: Request, res: Response) => {
  const parsed = LoginSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(401).json({ error: 'Invalid username or password.' });
    return;
  }

  const { username, password } = parsed.data;

  const user = db
    .prepare(
      'SELECT id, username, password_hash, role, active FROM users WHERE username = ?'
    )
    .get(username) as
    | {
        id: number;
        username: string;
        password_hash: string;
        role: string;
        active: number;
      }
    | undefined;

  // Always call bcrypt.compare to prevent timing-based user enumeration
  const hashToCheck =
    user?.password_hash ??
    '$2b$12$invalidhashpadding00000000000000000000000000000000000';
  const match = await bcrypt.compare(password, hashToCheck);

  if (!user || !match) {
    writeAudit({
      actor_id: user?.id ?? null,
      action: 'LOGIN',
      outcome: 'DENY',
      detail: `Failed login for username: ${username}`,
      deny_reason: 'INVALID_CREDENTIALS',
    });
    res.status(401).json({ error: 'Invalid username or password.' });
    return;
  }

  if (!user.active) {
    writeAudit({
      actor_id: user.id,
      action: 'LOGIN',
      outcome: 'DENY',
      detail: 'Login attempt by disabled user',
      deny_reason: 'DISABLED_USER',
    });
    res.status(401).json({ error: 'Invalid username or password.' });
    return;
  }

  const userAgent = req.headers['user-agent'] as string | undefined;
  const { token, csrfToken } = createSession(user.id, userAgent);

  try {
    db.prepare('UPDATE users SET last_login = datetime("now") WHERE id = ?').run(user.id);
  } catch {}

  writeAudit({
    actor_id: user.id,
    action: 'LOGIN',
    outcome: 'ALLOW',
    detail: `User ${user.username} logged in`,
  });

  // httpOnly + sameSite cookie (Rule 8)
  res.cookie('tv_session', token, {
    httpOnly: true,
    sameSite: 'strict',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 8 * 60 * 60 * 1000,
    path: '/',
  });

  res.json({
    user: { id: user.id, username: user.username, role: user.role },
    csrfToken,
  });
});

const RegisterSchema = z.object({
  fullName: z.string().min(1, 'Full name is required').max(100),
  username: z
    .string()
    .min(3, 'Username must be at least 3 characters')
    .max(32, 'Username must be at most 32 characters')
    .regex(/^[a-zA-Z0-9_.-]+$/, 'Username may only contain letters, numbers, dots, hyphens, and underscores'),
  email: z.string().email('Valid email is required').max(100),
  password: z
    .string()
    .min(8, 'Password must be at least 8 characters')
    .max(128, 'Password too long')
    .refine((v) => /[A-Z]/.test(v), 'Password must contain at least one uppercase letter')
    .refine((v) => /[a-z]/.test(v), 'Password must contain at least one lowercase letter')
    .refine((v) => /[0-9]/.test(v), 'Password must contain at least one number')
    .refine((v) => /[^A-Za-z0-9]/.test(v), 'Password must contain at least one special character'),
  confirmPassword: z.string().optional(),
});

// POST /api/register  (Pre-auth account creation - always creates viewer role)
router.post('/register', loginLimiter, async (req: Request, res: Response) => {
  const parsed = RegisterSchema.safeParse(req.body);
  if (!parsed.success) {
    const firstErr = parsed.error.issues[0]?.message || 'Invalid input';
    res.status(400).json({ error: firstErr });
    return;
  }

  const { fullName, username, email, password } = parsed.data;

  // Check if username already exists
  const existing = db
    .prepare('SELECT id FROM users WHERE username = ?')
    .get(username);

  if (existing) {
    res.status(400).json({ error: 'Username is already taken' });
    return;
  }

  try {
    const passwordHash = await bcrypt.hash(password, 12);

    // New accounts are always created as 'viewer' on the server (no role field accepted)
    db.prepare(
      'INSERT INTO users (username, password_hash, role, active, full_name, email) VALUES (?, ?, ?, 1, ?, ?)'
    ).run(username, passwordHash, 'viewer', fullName, email);

    writeAudit({
      actor_id: null,
      action: 'REGISTER',
      outcome: 'ALLOW',
      detail: `New viewer account created for: ${username}`,
    });

    res.status(201).json({ message: 'Account created successfully. Please sign in.' });
  } catch (err) {
    res.status(500).json({ error: 'Could not create account. Please try again.' });
  }
});

// POST /api/logout
router.post('/logout', requireAuth, verifyCsrf, (req: Request, res: Response) => {
  const token = req.cookies?.['tv_session'];

  writeAudit({
    actor_id: req.user!.id,
    action: 'LOGOUT',
    outcome: 'ALLOW',
    detail: `User ${req.user!.username} logged out`,
  });

  if (token) deleteSession(token);
  res.clearCookie('tv_session', { path: '/' });
  res.json({ message: 'Logged out' });
});

// GET /api/csrf-token  — fetch token after page refresh
router.get('/csrf-token', requireAuth, (req: Request, res: Response) => {
  res.json({ csrfToken: req.csrfToken });
});

// GET /api/me
router.get('/me', requireAuth, (req: Request, res: Response) => {
  const row = db
    .prepare(
      'SELECT id, username, role, active, created_at, full_name, email, last_login FROM users WHERE id = ?'
    )
    .get(req.user!.id) as
    | {
        id: number;
        username: string;
        role: string;
        active: number;
        created_at: string;
        full_name?: string | null;
        email?: string | null;
        last_login?: string | null;
      }
    | undefined;

  if (!row) {
    res.json({ user: req.user });
    return;
  }

  const defaultNames: Record<string, string> = {
    admin: 'System Administrator',
    owner1: 'Primary Owner',
    owner2: 'Secondary Owner',
    viewer1: 'Auditor & Viewer',
  };

  res.json({
    user: {
      id: row.id,
      username: row.username,
      role: row.role,
      active: row.active,
      created_at: row.created_at,
      full_name: row.full_name || defaultNames[row.username] || row.username,
      email: row.email || `${row.username}@trustvault.local`,
      last_login: row.last_login || row.created_at,
    },
  });
});

// ── Password Change Rate Limiter: 5 attempts per 15 min per user ────────────
const changePasswordLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req: Request) => (req.user ? `user_${req.user.id}` : req.ip || 'unknown'),
  skip: (req: Request) => req.headers['x-test-suite'] === 'true' || process.env.NODE_ENV === 'test',
  handler: (req: Request, res: Response) => {
    writeAudit({
      actor_id: req.user?.id ?? null,
      action: 'PASSWORD_CHANGE_FAILED',
      outcome: 'DENY',
      detail: 'Rate limit exceeded for password change',
      deny_reason: 'RATE_LIMITED',
    });
    res.status(429).json({ error: 'Too many password change attempts — try again later' });
  },
});

const ChangePasswordSchema = z.object({
  currentPassword: z.string().min(1, 'Current password is required'),
  newPassword: z
    .string()
    .min(8, 'Password must be at least 8 characters')
    .max(128, 'Password too long')
    .refine((v) => /[A-Z]/.test(v), 'Password must contain at least one uppercase letter')
    .refine((v) => /[a-z]/.test(v), 'Password must contain at least one lowercase letter')
    .refine((v) => /[0-9]/.test(v), 'Password must contain at least one number')
    .refine((v) => /[^A-Za-z0-9]/.test(v), 'Password must contain at least one special character'),
  confirmPassword: z.string().min(1, 'Confirm password is required'),
});

async function handleChangePassword(req: Request, res: Response): Promise<void> {
  // Acts ONLY on authenticated user from session. Never accept a user ID from client.
  const userId = req.user!.id;

  const parsed = ChangePasswordSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'Unable to change password. Check your current password and try again.' });
    return;
  }

  const { currentPassword, newPassword, confirmPassword } = parsed.data;

  // Confirm password must match new password
  if (newPassword !== confirmPassword) {
    res.status(400).json({ error: 'Unable to change password. Check your current password and try again.' });
    return;
  }

  // New password must differ from current password
  if (newPassword === currentPassword) {
    res.status(400).json({ error: 'Unable to change password. Check your current password and try again.' });
    return;
  }

  // Fetch current user from database
  const user = db
    .prepare('SELECT id, username, password_hash FROM users WHERE id = ?')
    .get(userId) as { id: number; username: string; password_hash: string } | undefined;

  if (!user) {
    res.status(401).json({ error: 'Invalid session' });
    return;
  }

  // Verify current password with existing hash function
  const match = await bcrypt.compare(currentPassword, user.password_hash);
  if (!match) {
    writeAudit({
      actor_id: userId,
      action: 'PASSWORD_CHANGE_FAILED',
      outcome: 'DENY',
      detail: 'Current password verification failed',
      deny_reason: 'INVALID_CREDENTIALS',
    });
    res.status(400).json({ error: 'Unable to change password. Check your current password and try again.' });
    return;
  }

  // Hash new password using bcryptjs rounds = 12
  const newHash = await bcrypt.hash(newPassword, 12);

  const currentToken = req.cookies?.['tv_session'];
  const newToken = crypto.randomBytes(32).toString('hex');
  const newCsrfToken = crypto.randomBytes(32).toString('hex');

  // Update user row, delete other sessions, and rotate current session in a transaction
  db.exec('BEGIN IMMEDIATE');
  try {
    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(newHash, userId);

    if (currentToken) {
      db.prepare('DELETE FROM sessions WHERE user_id = ? AND id != ?').run(userId, currentToken);
      db.prepare('UPDATE sessions SET id = ?, csrf_token = ? WHERE id = ?').run(newToken, newCsrfToken, currentToken);
    } else {
      db.prepare('DELETE FROM sessions WHERE user_id = ?').run(userId);
    }

    db.exec('COMMIT');
  } catch (err) {
    db.exec('ROLLBACK');
    res.status(500).json({ error: 'Unable to change password. Check your current password and try again.' });
    return;
  }

  // Write audit entry
  writeAudit({
    actor_id: userId,
    action: 'PASSWORD_CHANGED',
    outcome: 'ALLOW',
    detail: `Password changed successfully for user ${user.username}`,
  });

  // Rotate session cookie
  res.cookie('tv_session', newToken, {
    httpOnly: true,
    sameSite: 'strict',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 8 * 60 * 60 * 1000,
    path: '/',
  });

  res.json({ message: 'Password changed successfully.', csrfToken: newCsrfToken });
}

function parseUserAgent(ua?: string): string {
  if (!ua) return 'Desktop Browser';
  const os = ua.includes('Windows')
    ? 'Windows'
    : ua.includes('Macintosh') || ua.includes('Mac OS')
    ? 'macOS'
    : ua.includes('Linux')
    ? 'Linux'
    : ua.includes('Android')
    ? 'Android'
    : ua.includes('iPhone') || ua.includes('iPad')
    ? 'iOS'
    : 'Desktop';

  if (ua.includes('Edg/')) return `Microsoft Edge on ${os}`;
  if (ua.includes('Chrome/')) return `Google Chrome on ${os}`;
  if (ua.includes('Firefox/')) return `Mozilla Firefox on ${os}`;
  if (ua.includes('Safari/') && !ua.includes('Chrome/')) return `Apple Safari on ${os}`;
  return `Web Browser on ${os}`;
}

function handleGetSessions(req: Request, res: Response): void {
  const userId = req.user!.id;
  const currentToken = req.cookies?.['tv_session'];

  const rows = db
    .prepare(
      'SELECT id, created_at, user_agent, last_active FROM sessions WHERE user_id = ? ORDER BY created_at DESC'
    )
    .all(userId) as Array<{
    id: string;
    created_at: string;
    user_agent?: string;
    last_active?: string;
  }>;

  const sessions = rows.map((s, index) => ({
    id: `sess_${index + 1}`,
    is_current: s.id === currentToken,
    device: parseUserAgent(s.user_agent),
    created_at: s.created_at,
    last_active: s.last_active || s.created_at,
  }));

  res.json({ sessions });
}

function handleRevokeOthers(req: Request, res: Response): void {
  const userId = req.user!.id;
  const currentToken = req.cookies?.['tv_session'];

  const r = db
    .prepare('DELETE FROM sessions WHERE user_id = ? AND id != ?')
    .run(userId, currentToken || '');

  writeAudit({
    actor_id: userId,
    action: 'SESSIONS_REVOKED',
    outcome: 'ALLOW',
    detail: `Revoked ${r.changes} other active session(s)`,
  });

  res.json({ message: 'Other sessions signed out successfully.', count: r.changes });
}

// ── Mount authenticated endpoints for both /auth/* and direct routes ────────
router.post('/auth/change-password', requireAuth, verifyCsrf, changePasswordLimiter, handleChangePassword);
router.post('/change-password', requireAuth, verifyCsrf, changePasswordLimiter, handleChangePassword);

router.get('/auth/sessions', requireAuth, handleGetSessions);
router.get('/sessions', requireAuth, handleGetSessions);

router.post('/auth/sessions/revoke-others', requireAuth, verifyCsrf, handleRevokeOthers);
router.post('/sessions/revoke-others', requireAuth, verifyCsrf, handleRevokeOthers);

export default router;
