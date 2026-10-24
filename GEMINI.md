Project: TrustVault, a secure document-sharing app for a security-graded hackathon.

1. ALL document access goes through ONE function: authorize(user, action, documentId). No inline permission checks in handlers. Default deny.
2. Never trust client IDs: load the resource, then check access. Not-granted and nonexistent both return 404 and log the real reason in the audit table.
3. Listings and search return only documents the user can read.
4. Sessions and permissions are checked in the database on EVERY request, so revoking access or disabling a user works on the next request. No long-lived tokens or cached grants.
5. Files are stored outside any public folder under random UUID names and streamed only via an authorized endpoint, with Content-Disposition: attachment and X-Content-Type-Options: nosniff. Validate extension allowlist, magic bytes, and size.
6. Audit log is append-only and hash-chained (each row stores the previous row's hash). Add DB triggers that block UPDATE and DELETE on it. Log every action AND every denied attempt.
7. Passwords hashed with bcrypt or argon2, httpOnly sameSite cookies, rate-limit login, validate all input, security headers.
8. Write negative tests: user A must never reach user B's document by read, download, edit, delete, permission list, or search.
9. Keep commits small and meaningful.