import { Router, Request, Response } from 'express';
import bcrypt from 'bcryptjs';
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
    res.status(400).json({ error: 'Invalid input' });
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
    res.status(401).json({ error: 'Invalid credentials' });
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
    res.status(401).json({ error: 'Account disabled' });
    return;
  }

  const { token, csrfToken } = createSession(user.id);

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
  res.json({ user: req.user });
});

export default router;
