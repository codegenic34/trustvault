import { Request, Response, NextFunction } from 'express';
import { writeAudit } from '../audit';

/**
 * Verify the X-CSRF-Token header on all mutating requests (POST/PATCH/DELETE).
 * The token is bound to the session row and validated here — not the cookie.
 * requireAuth must run before this middleware (it populates req.csrfToken).
 */
export function verifyCsrf(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  const header = req.headers['x-csrf-token'];
  const expected = req.csrfToken;

  if (
    !header ||
    !expected ||
    typeof header !== 'string' ||
    header !== expected
  ) {
    writeAudit({
      actor_id: req.user?.id ?? null,
      action: 'ACCESS_DENIED',
      outcome: 'DENY',
      detail: `CSRF mismatch on ${req.method} ${req.path}`,
      deny_reason: 'CSRF_INVALID',
    });
    res.status(403).json({ error: 'CSRF token invalid or missing' });
    return;
  }
  next();
}
