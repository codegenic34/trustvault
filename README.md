# TrustVault 🔐

> A zero-trust, security-graded document-sharing platform engineered with defense-in-depth, cryptographic audit integrity, and strictly enforced least-privilege access.

- 🌐 **Live Website:** [https://trustvault-a0dn.onrender.com](https://trustvault-a0dn.onrender.com)
- 📦 **GitHub Repository:** [https://github.com/codegenic34/trustvault](https://github.com/codegenic34/trustvault)


[![Security Graded](https://img.shields.io/badge/Security-Graded%20Hackathon-blueviolet.svg)](#security-architecture)
[![Node.js](https://img.shields.io/badge/Node.js-v22%2B%20(node%3Asqlite)-339933.svg)](#tech-stack)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.4-blue.svg)](#tech-stack)
[![Tests](https://img.shields.io/badge/Tests-9%20Passing-success.svg)](#test-suite)
[![Docker](https://img.shields.io/badge/Docker-Ready%20for%20Render-2496ED.svg)](#docker--production-deployment)

---

## Table of Contents
- [Project Overview](#project-overview)
- [Security Architecture & Principles](#security-architecture--principles)
- [Roles & Permissions Model](#roles--permissions-model)
- [Tech Stack](#tech-stack)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation & Setup](#installation--setup)
  - [Default Test Credentials](#default-test-credentials)
- [Running Tests](#running-tests)
- [Docker & Production Deployment (Render)](#docker--production-deployment-render)
- [API & Documentation](#api--documentation)

---

## Project Overview

TrustVault is built specifically for security-graded environments where confidentiality, integrity, and non-repudiation are paramount. It prevents common vulnerabilities by design (IDOR, session hijacking, tampering, privilege escalation, and bypasses) through architectural enforcement rather than ad-hoc middleware.

---

## Security Architecture & Principles

TrustVault adheres to strict security constraints (see [GEMINI.md](file:///c:/Users/dell/Desktop/trustvault%20CL/trustvault/GEMINI.md)):

1. **Centralized Authorization (`authorize()`):**
   Every document access request (read, download, edit, delete, manage permissions) routes through a single `authorize(user, action, documentId)` function. Handlers contain **no inline permission checks** and default to deny.
2. **Anti-Enumeration & Zero Client Trust:**
   Client-supplied identifiers are never trusted. Both ungranted documents and nonexistent documents return an identical `404 Not Found`, while the real internal rejection reason (`NO_PERMISSION`, `WRONG_ROLE`, etc.) is logged strictly to the tamper-proof audit log.
3. **Database-Checked Sessions & Immediate Revocation:**
   Sessions and permission grants are checked in SQLite on **every single request**. When permissions are revoked or a user is deactivated, access terminates on their very next request—no stale JWTs or cached credentials.
4. **Isolated Attachment Streaming:**
   Uploaded files are stored outside the public web root (`storage/`) under randomly generated UUID file names. Files are streamed only through authenticated, authorized endpoints with strict security headers:
   - `Content-Disposition: attachment; filename="..."`
   - `X-Content-Type-Options: nosniff`
   - Magic bytes and extension allowlists validation.
5. **Tamper-Evident, Hash-Chained Audit Log:**
   Every event (allowed or denied) is stored in an append-only `audit_log` table. Each row computes a SHA-256 hash containing the previous row's hash, forming a cryptographic blockchain. SQLite database triggers (`BEFORE UPDATE`, `BEFORE DELETE`) abort any modification attempts.
6. **Authentication & Session Hardening:**
   - Passwords hashed with `bcryptjs` (12 rounds).
   - Session tokens stored in `httpOnly`, `sameSite: 'strict'`, and `secure` (in production) cookies.
   - Comprehensive brute-force rate-limiting on sensitive authentication and credential endpoints.
   - Full session rotation and atomic invalidation of stale concurrent sessions upon password change.

---

## Roles & Permissions Model

| Role | Permissions & Scope |
| :--- | :--- |
| **`admin`** | System administrator. Can view tamper-proof audit logs, verify hash-chain integrity, and inspect anomaly detections. Has **no implicit access** to read or download documents unless explicitly granted by the document owner. |
| **`owner`** | Can upload documents, edit metadata of their own files, soft-delete, and grant/revoke granular `can_read` and `can_edit` permissions to other users. |
| **`viewer`** | Read-only collaborator. Can only list, search for, and download documents specifically shared with them. |

---

## Tech Stack

- **Runtime:** [Node.js 22 LTS](https://nodejs.org/) utilizing native `node:sqlite` (`DatabaseSync`).
- **Language:** [TypeScript](https://www.typescriptlang.org/) with `ts-node` (transpile-only runtime).
- **Backend:** [Express](https://expressjs.com/), [Helmet](https://helmetjs.github.io/), [cookie-parser](https://github.com/expressjs/cookie-parser), [express-rate-limit](https://github.com/express-rate-limit/express-rate-limit), [Zod](https://zod.dev/).
- **Frontend:** Responsive Zero-Trust UI built with Vanilla CSS & HTML5, interactive constellation canvas background, dynamic role themes, and SVG vectors.
- **Containerization:** Docker container (`node:22-slim`) optimized for one-click deployment on Render.

---

## Getting Started

### Prerequisites
- Node.js 22.5.0 or newer
- npm 10+

### Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/codegenic34/trustvault.git
   cd trustvault
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Seed the database:**
   ```bash
   npm run seed
   ```

4. **Start local development server:**
   ```bash
   npm run dev
   ```
   The application will be live at `http://localhost:3000`.

### Default Test Credentials

| Username | Password | Role | Description |
| :--- | :--- | :--- | :--- |
| `admin` | `Admin1234!` | `admin` | System auditor & security administrator |
| `owner1` | `Owner1234!` | `owner` | Document owner (owns sample financial & project docs) |
| `owner2` | `Owner5678!` | `owner` | Document owner (owns confidential internal docs) |
| `viewer1` | `Viewer123!` | `viewer` | Viewer (granted read access to owner1's financial report) |

---

## Running Tests

TrustVault includes a comprehensive automated test suite verifying password change mechanics, session rotation, CSRF defense, role boundaries, and audit chain cryptographic integrity:

```bash
npm test
```

Expected output:
```text
🔒 Starting TrustVault Security & Settings Test Suite...
  ✓ 1. Unauthenticated request to change-password returns 401
  ✓ 2. Wrong current password is refused and audited, and password is unchanged
  ✓ 3. Weak new password is rejected server-side even if UI is bypassed
  ✓ 4. Successful change: old fails, new works, other sessions revoked, PASSWORD_CHANGED audited
  ✓ 5. Request body containing another user ID/username cannot change that other user
  ✓ 6. Viewer, owner, and admin can each change their OWN password
  ✓ 7. Sessions endpoints never return other users sessions
  ✓ 8. Owner and viewer get 403 on role management endpoints
  ✓ 9. Audit chain still verifies after all operations

========================================
Results: 9 passed, 0 failed
========================================
```

---

## Docker & Production Deployment (Render)

TrustVault is fully configured for deployment on Render as a Web Service using Docker:

1. **Push your repository to GitHub.**
2. **Create a new Web Service** on Render and connect your GitHub repo.
3. **Select Runtime:** `Docker`.
4. **Environment Variables:**
   - `NODE_ENV`: `production`
   - `PORT`: Automatically set by Render.
5. **Persistent Disk (Optional):** Attach a persistent disk mounted at `/app/storage` to retain uploaded documents across container rebuilds.

---

## API & Documentation

For detailed architectural references, consult:
- [docs/API.md](file:///c:/Users/dell/Desktop/trustvault%20CL/trustvault/docs/API.md) — Comprehensive REST API endpoints and schemas.
- [docs/PERMISSIONS.md](file:///c:/Users/dell/Desktop/trustvault%20CL/trustvault/docs/PERMISSIONS.md) — Complete permission decision matrix and lifecycle.
- [THREATS.md](file:///c:/Users/dell/Desktop/trustvault%20CL/trustvault/THREATS.md) — Threat model and security mitigations.
- [PROMPTS.md](file:///c:/Users/dell/Desktop/trustvault%20CL/trustvault/PROMPTS.md) — Prompt engineering and iteration log.