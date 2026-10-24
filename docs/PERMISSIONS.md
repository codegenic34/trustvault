# TrustVault Permissions Model

## Roles

| Role | Description |
|---|---|
| `admin` | System administrator. Sees audit metadata and permission-change events only. Has **no implicit access** to any document. |
| `owner` | Can upload documents, grant/revoke access to their own documents, and perform all operations on documents they own. |
| `viewer` | Can only access documents for which they have been explicitly granted permission. |

---

## Document Ownership

Every document has exactly one **owner** — the user who uploaded it. Ownership cannot be transferred.

---

## Permission Grants

An owner can grant another user (any role) one or both of:

| Flag | Effect |
|---|---|
| `can_read` | Grantee may list, search for, and download the document |
| `can_edit` | Grantee may update the document's `original_name` and `category` metadata |

Grants are stored in the `permissions` table as a single row per `(document_id, grantee_id)` pair.

---

## Permission Revocation

Revocation is **immediate on the grantee's next request**. There is no grace period or cached session state.  
Internally, revocation sets `permissions.revoked_at = NOW()`. The row is retained for the audit trail.

If an owner re-grants a previously revoked user, the existing row is updated (`revoked_at = NULL`) and access is restored.

---

## The `authorize()` Function

Every document action in the codebase is validated by a single function:

```
authorize(user: SessionUser, action: Action, documentId: string): AuthorizeResult
```

**Possible actions:** `read`, `download`, `edit_metadata`, `delete`, `manage_permissions`, `view_permissions`

### Decision table

| Action | Owner | Granted (can_read) | Granted (can_edit) | Admin (no grant) | Revoked grant |
|---|---|---|---|---|---|
| `read` | ✅ | ✅ | — | ❌ | ❌ |
| `download` | ✅ | ✅ | — | ❌ | ❌ |
| `edit_metadata` | ✅ | — | ✅ | ❌ | ❌ |
| `delete` | ✅ | ❌ | ❌ | ❌ | ❌ |
| `manage_permissions` | ✅ | ❌ | ❌ | ❌ | ❌ |
| `view_permissions` | ✅ | ❌ | ❌ | ❌ | ❌ |

**Default deny** — any action not explicitly allowed above is denied.

---

## Admin Scope

Admin has access **only** to:
- `GET /api/audit` — audit log with filters
- `GET /api/audit/verify` — hash-chain integrity check
- `GET /api/audit/suspicious` — anomaly detection

The admin role alone **never satisfies** any document action. An admin who needs to read a document must be explicitly granted `can_read` by that document's owner (the same path as any other user).

---

## Disabled Users

When `users.active = 0`:
- All existing sessions for the user stop working **immediately on the next request**
- Login attempts are rejected
- Every blocked request is logged to the audit table with `deny_reason = DISABLED_USER`

---

## Audit Log Coverage

Every action — allowed or denied — is written to the append-only `audit_log` table.

| Event | Logged as |
|---|---|
| Successful login | `action=LOGIN, outcome=ALLOW` |
| Failed login | `action=LOGIN, outcome=DENY` |
| Logout | `action=LOGOUT, outcome=ALLOW` |
| Upload | `action=UPLOAD, outcome=ALLOW\|DENY` |
| Download | `action=DOWNLOAD, outcome=ALLOW\|DENY` |
| Edit metadata | `action=EDIT_METADATA, outcome=ALLOW\|DENY` |
| Delete document | `action=DELETE_DOCUMENT, outcome=ALLOW\|DENY` |
| Grant permission | `action=GRANT_PERMISSION, outcome=ALLOW\|DENY` |
| Revoke permission | `action=REVOKE_PERMISSION, outcome=ALLOW\|DENY` |
| CSRF failure | `action=ACCESS_DENIED, deny_reason=CSRF_INVALID` |
| Disabled user request | `action=AUTH_CHECK, deny_reason=DISABLED_USER` |

Denied events always include the **real reason** in `deny_reason`, while the client receives only a generic `404` or `403`.

---

## Hash Chain Integrity

Each audit row stores:
- `prev_hash` — SHA-256 hash of the previous row (empty string for row 1)
- `row_hash` — SHA-256 of `\x00`-separated: `prev_hash, timestamp, actor_id, action, resource_id, outcome, detail, deny_reason`

SQLite `BEFORE UPDATE` and `BEFORE DELETE` triggers call `RAISE(ABORT, …)` to make tampering impossible at the database layer.  
The chain can be re-verified at any time via `GET /api/audit/verify`.
