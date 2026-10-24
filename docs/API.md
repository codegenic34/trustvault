# TrustVault API Reference

Base URL: `http://localhost:3000`

All JSON request bodies require `Content-Type: application/json`.  
All state-changing endpoints require the `X-CSRF-Token` header (value returned on login or from `GET /api/csrf-token`).  
Authentication is via an `httpOnly`, `sameSite=strict` cookie (`tv_session`) set on successful login.

---

## Authentication

### `POST /api/login`
**Who may call:** Anyone (rate-limited: 10 requests / 15 min per IP)

Request body:
```json
{ "username": "owner1", "password": "Owner1234!" }
```

Response `200`:
```json
{
  "user": { "id": 1, "username": "owner1", "role": "owner" },
  "csrfToken": "<64-hex-chars>"
}
```

Errors: `400` invalid input · `401` wrong credentials / account disabled · `429` rate limit exceeded.

---

### `POST /api/logout`
**Who may call:** Any authenticated user  
**Requires:** `X-CSRF-Token` header

Deletes the server-side session. Clears the session cookie.  
Response `200`: `{ "message": "Logged out" }`

---

### `GET /api/csrf-token`
**Who may call:** Any authenticated user

Returns the CSRF token for the current session (useful after a page refresh).  
Response `200`: `{ "csrfToken": "<64-hex-chars>" }`

---

### `GET /api/me`
**Who may call:** Any authenticated user

Response `200`:
```json
{
  "user": {
    "id": 1,
    "username": "owner1",
    "role": "owner",
    "active": 1,
    "full_name": "Primary Owner",
    "email": "owner1@trustvault.local",
    "created_at": "2026-10-24T12:00:00.000Z",
    "last_login": "2026-10-24T14:30:00.000Z"
  }
}
```

---

### `POST /api/auth/change-password`
**Who may call:** Any authenticated user (own account only)  
**Requires:** `X-CSRF-Token` header, rate-limited (5 attempts / 15 min per user)

Request body:
```json
{
  "currentPassword": "Owner1234!",
  "newPassword": "NewOwnerPass123!",
  "confirmPassword": "NewOwnerPass123!"
}
```

Rules:
- Validated server-side: 8+ chars, at least one uppercase, lowercase, digit, and special character.
- `confirmPassword` must match `newPassword`.
- `newPassword` must differ from `currentPassword`.
- Current password verified with bcrypt before change.
- Updates password in a transaction, revokes all other sessions, and rotates the current session ID and cookie.
- Writes a `PASSWORD_CHANGED` audit entry (or `PASSWORD_CHANGE_FAILED` with outcome `DENY` on incorrect current password or validation failure).

Response `200`:
```json
{
  "message": "Password changed successfully.",
  "csrfToken": "<new-64-hex-chars>"
}
```

Errors: `400` validation failure / wrong current password · `401` not authenticated · `429` rate limit exceeded.

---

### `GET /api/auth/sessions`
**Who may call:** Any authenticated user (own account only)

Returns all active sessions for the authenticated user. Exposes no secret tokens.

Response `200`:
```json
{
  "sessions": [
    {
      "id": "sess_1",
      "is_current": true,
      "device": "Google Chrome on Windows",
      "created_at": "2026-10-24T14:00:00.000Z",
      "last_active": "2026-10-24T14:35:00.000Z"
    }
  ]
}
```

---

### `POST /api/auth/sessions/revoke-others`
**Who may call:** Any authenticated user (own account only)  
**Requires:** `X-CSRF-Token` header

Revokes all active sessions for the calling user *except* the session making the request. Writes a `SESSIONS_REVOKED` audit log entry.

Response `200`:
```json
{
  "message": "Other sessions signed out successfully.",
  "count": 2
}
```

---

## Documents

### `POST /api/documents`
**Who may call:** `owner` role only  
**Requires:** `X-CSRF-Token`, `multipart/form-data`

Fields:
- `file` — the file (pdf, png, jpg, txt, docx; max 5 MB; magic-byte validated)
- `category` — optional string (max 64 chars, `[a-zA-Z0-9 _-]`)

Response `201`:
```json
{
  "document": { "id": "<uuid>", "original_name": "report.pdf", "category": "finance",
                "size": 12345, "mime_type": "application/pdf" }
}
```

Errors: `400` bad file / type / category · `403` not an owner.

---

### `GET /api/documents`
**Who may call:** Any authenticated user (results scoped to caller's grants)

Admin sees **no documents** unless explicitly granted `can_read`.

Query params (all optional):
| Param | Description |
|---|---|
| `q` | Full-text search on name AND category |
| `name` | Filename LIKE filter |
| `category` | Exact category filter |
| `from` | ISO 8601 lower bound for `created_at` |
| `to` | ISO 8601 upper bound for `created_at` |

Response `200`:
```json
{
  "documents": [
    { "id": "…", "original_name": "…", "category": "…", "size": 0,
      "mime_type": "…", "created_at": "…", "owner_name": "…",
      "is_owner": 1, "can_read": 1, "can_edit": 0 }
  ]
}
```

---

### `GET /api/documents/:id/download`
**Who may call:** Document owner OR a user with an active `can_read` grant

Response: binary file stream with:
- `Content-Disposition: attachment; filename="..."`
- `Content-Type: application/octet-stream`
- `X-Content-Type-Options: nosniff`

Errors: `404` not found or no permission (real reason logged internally).

---

### `PATCH /api/documents/:id`
**Who may call:** Document owner OR a user with an active `can_edit` grant  
**Requires:** `X-CSRF-Token`

Request body (at least one field required):
```json
{ "original_name": "new-name.txt", "category": "archive" }
```

Response `200`: `{ "message": "Document updated" }`  
Errors: `400` bad input · `404` not found or no permission.

---

### `DELETE /api/documents/:id`
**Who may call:** Document owner only  
**Requires:** `X-CSRF-Token`

Performs a soft-delete (`deleted = 1`). File remains on disk.  
Response `200`: `{ "message": "Document deleted" }`  
Errors: `404` not found or no permission.

---

## Permissions

All permission endpoints are owner-only. Editors and admins have no access.

### `GET /api/documents/:id/permissions`
**Who may call:** Document owner only

Response `200`:
```json
{
  "permissions": [
    { "id": 1, "grantee_id": 3, "grantee_username": "viewer1",
      "can_read": 1, "can_edit": 0, "granted_at": "…", "revoked_at": null,
      "granted_by_username": "owner1" }
  ]
}
```

---

### `POST /api/documents/:id/permissions`
**Who may call:** Document owner only  
**Requires:** `X-CSRF-Token`

Request body:
```json
{ "username": "viewer1", "can_read": true, "can_edit": false }
```

Upserts — re-granting a revoked user restores access immediately.  
Response `200`: `{ "message": "Permission granted" }`  
Errors: `400` bad input / self-grant · `404` doc not found / user not found.

---

### `DELETE /api/documents/:id/permissions/:userId`
**Who may call:** Document owner only  
**Requires:** `X-CSRF-Token`

Sets `revoked_at = NOW()`. Revocation takes effect on the grantee's **next request** (no session cache).  
Response `200`: `{ "message": "Permission revoked" }`  
Errors: `404` doc not found / permission not found.

---

## Admin (admin role only)

Admin users have **no implicit document access**. They may only call these endpoints.

### `GET /api/audit`
**Who may call:** `admin` only

Query params (all optional):
| Param | Description |
|---|---|
| `action` | Exact action name (e.g. `LOGIN`, `DOWNLOAD`, `REVOKE_PERMISSION`) |
| `outcome` | `ALLOW` or `DENY` |
| `actor_id` | Integer user ID |
| `from` | Timestamp lower bound |
| `to` | Timestamp upper bound |
| `limit` | Max rows returned (default 100, max 500) |
| `offset` | Pagination offset (default 0) |

Response `200`:
```json
{
  "logs": [ { "id": 1, "timestamp": "…", "actor_id": 2, "actor_username": "…",
              "action": "DOWNLOAD", "resource_id": "…", "outcome": "ALLOW",
              "detail": "…", "deny_reason": null } ],
  "total": 42, "limit": 100, "offset": 0
}
```

---

### `GET /api/audit/verify`
**Who may call:** `admin` only

Recomputes every SHA-256 hash in the chain and reports the first discrepancy.

Response `200`:
```json
{ "valid": true, "totalRows": 125 }
```
or
```json
{ "valid": false, "totalRows": 125, "brokenAt": 37 }
```

---

### `GET /api/audit/suspicious`
**Who may call:** `admin` only

Returns three lists:
- `repeatedDenials` — users with ≥ 3 DENY events in the last 24 hours
- `postRevocation` — access attempts after permission revocation
- `disabledAttempts` — access attempts by disabled accounts

Response `200`:
```json
{
  "repeatedDenials":   [ { "actor_id": 3, "username": "…", "deny_count": 5, "last_attempt": "…" } ],
  "postRevocation":    [ { "id": 12, "timestamp": "…", "actor_id": 3, "resource_id": "…", "actor_username": "…" } ],
  "disabledAttempts":  [ { "id": 15, "timestamp": "…", "actor_id": 4, "actor_username": "…" } ]
}
```

---

## Error format

All errors return:
```json
{ "error": "Human-readable message" }
```

**Note:** Resource-level denials (no permission, not found, revoked) all return `404`. The real reason is never sent to the client — it is logged to `audit_log.deny_reason` only.
