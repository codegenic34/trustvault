# THREATS.md

| Threat | What I did about it | Status |
|---|---|---|
| Example: user A opens user B's document by guessing the ID | Central authorize() on every route; 404 on denial; tested | Mitigated |
| Password change without current password | Server requires and bcrypt-verifies current password; writes PASSWORD_CHANGE_FAILED audit entry on failure | Mitigated |
| Session fixation after password change | Session ID rotated to a new cryptographically random token in DB and Set-Cookie header immediately upon change | Mitigated |
| Stolen session surviving a password change | All other active sessions for that user deleted atomically in DB transaction upon successful password change | Mitigated |
| Brute forcing the current password | Rate limited to 5 attempts per 15 minutes per authenticated user via express-rate-limit; audited on exceed | Mitigated |