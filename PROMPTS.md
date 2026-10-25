# PROMPTS.md

Entries are written as I build, with dates.

## Reused context
- `GEMINI.md`: standing security rules given to the agent on every task.
  - Central `authorize(user, action, documentId)` enforcement with default deny.
  - Zero client trust: load resource then check access; return 404 for ungranted and nonexistent.
  - Database-checked sessions and permissions on every request; no long-lived token caching.
  - Secure storage outside public root with random UUID filenames and attachment streaming.
  - Hash-chained append-only audit logging with SQLite update/delete triggers.
  - Bcrypt hashing, secure httpOnly sameSite cookies, rate limiting, and negative testing.

---

## Entries

### 2026-10-24: Entry 1 — Core Schema, Central Authorization Engine & Security Skeleton
- **Asked:** Build the core TrustVault backend adhering strictly to GEMINI.md rules, with Node 22 built-in `node:sqlite`, TypeScript, Express, Helmet, and central authorization.
- **Produced:**
  - `src/db.ts`: SQLite database initialization with WAL mode, foreign keys, and safe schema migrations.
  - `src/authorize.ts`: Single centralized `authorize()` engine for all document actions (`read`, `download`, `edit_metadata`, `delete`, `manage_permissions`, `view_permissions`).
  - `src/audit.ts`: SHA-256 hash-chained audit logging function with verification.
  - `src/routes/auth.ts`: Authentication endpoints with bcrypt hashing (12 rounds), session cookies (`httpOnly`, `sameSite: strict`), and CSRF tokens.
- **What was wrong:** Initial implementation attempted to return 403 when document access was denied, which allows attackers to enumerate valid document IDs.
- **What I did instead:** Updated `authorize()` and route handlers so that nonexistent IDs and unauthorized access both return uniform `404 Not Found`, while logging the true granular deny reason in the audit table.
- **Commit:** `994a697`

---

### 2026-10-24: Entry 2 — Append-Only Hash-Chained Audit Log & DB Triggers
- **Asked:** Ensure the audit log cannot be modified, deleted, or cleared even if an attacker gains SQL execution or admin privileges.
- **Produced:**
  - Database triggers `audit_no_update` and `audit_no_delete` in SQLite schema.
  - Hash calculation linking each record: `row_hash = SHA256(prev_hash + timestamp + actor_id + action + outcome + ...)`.
  - Endpoint `GET /api/audit/verify` that traverses and validates the cryptographic hash chain.
- **What was wrong:** Triggers alone could still be dropped if an application used an unrestricted superuser connection; also needed verification that the chain could be programmatically checked.
- **What I did instead:** Added unit verification tests to check the whole chain and confirmed SQLite triggers raise abort on any attempted UPDATE or DELETE queries.
- **Commit:** `0f59324`

---

### 2026-10-25: Entry 3 — Password Management, Session Rotation & Concurrent Invalidation
- **Asked:** Implement account settings with password change, active sessions management, and negative security tests. Ensure password changes require the current password, rotate the session token, and invalidate all other sessions.
- **Produced:**
  - `POST /api/change-password`: Verifies current password with bcrypt, enforces strong password policies via Zod, updates hash, revokes other user sessions, rotates `tv_session` cookie, and audits `PASSWORD_CHANGED`.
  - `GET /api/sessions`: Returns active sessions for the authenticated user without leaking session tokens.
  - `DELETE /api/sessions/:id`: Revokes specific sessions immediately.
  - `tests/index.ts`: Comprehensive test suite verifying all 9 security invariants.
- **What was wrong:** A concurrent session could potentially linger after a password change if tokens were not invalidated in a single database transaction.
- **What I did instead:** Wrapped session deletion of `WHERE user_id = ? AND id != ?` and session rotation into an atomic SQLite transaction and verified it with automated tests.
- **Commit:** `0f59324`

---

### 2026-10-25: Entry 4 — Zero-Trust Frontend & Visual Design System
- **Asked:** Redesign the frontend to provide a professional, tactile, zero-trust visual experience without generic styles. Ensure role-specific badges, dark aesthetic, interactive node canvas background, and smooth tab switching.
- **Produced:**
  - `public/css/style.css`: Unified custom design system with custom CSS properties, glassmorphism, glowing role accents (`role-admin`, `role-owner`, `role-viewer`), and responsive grids.
  - `public/index.html` & `public/js/login.js`: Split sign-in layout with interactive constellation canvas, real-time password strength meter, and animated identity verification overlay.
  - `public/dashboard.html` & `public/settings.html`: Dynamic dashboard with audit log viewer, hash chain status indicator, document management, and permission modal.
- **What was wrong:** Role management controls were initially mixed into the main dashboard, confusing non-admin users.
- **What I did instead:** Moved administrative role management to a dedicated tab in Settings visible only to administrators, while giving viewers and owners role-specific readouts and guidance.
- **Commit:** `b939636`

---

### 2026-10-25: Entry 5 — Docker Containerization for Render Cloud Deployment
- **Asked:** Prepare TrustVault for Docker deployment on Render using Node 22+. Read PORT from environment, bind to `0.0.0.0`, trust proxy, make session cookies secure in production, auto-create storage and seed if empty, and block public access to `storage/`.
- **Produced:**
  - `Dockerfile`: Node 22 slim container with `ENV NODE_OPTIONS="--experimental-sqlite"`, `npm install --include=dev`, and local `ts-node` startup.
  - `.dockerignore`: Excluded `node_modules`, `storage`, `*.db*`, `.env`, and `.git`.
  - `src/server.ts`: Configured `app.set('trust proxy', 1)`, bound to `0.0.0.0:${PORT}`, added startup storage directory validation and automatic database seeding if the users table is empty, and blocked `/storage` route access with 404.
  - `src/routes/auth.ts`: Added `secure: process.env.NODE_ENV === 'production'` to all cookie generation and clearing handlers.
- **What was wrong:** In Render's build environment, setting `ENV NODE_ENV="production"` before `npm install` caused npm to skip `devDependencies` (`ts-node` and `typescript`), causing container crash at startup.
- **What I did instead:** Updated `Dockerfile` with `RUN npm install --include=dev` and used the locally installed binary `./node_modules/.bin/ts-node --transpile-only src/server.ts`.
- **Commit:** `e783352`, `c03ce22`