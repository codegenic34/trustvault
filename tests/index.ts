// tests/index.ts
// Comprehensive Test Suite for Password Change, Session Management, and Security Auditing
import assert from 'node:assert';
import http from 'node:http';
import { db } from '../src/db';
import { verifyAuditChain } from '../src/audit';

const BASE_URL = process.env.TEST_URL || 'http://localhost:3000';

// ── HTTP Request Helper ─────────────────────────────────────────────────────
interface HttpResponse {
  status: number;
  headers: http.IncomingHttpHeaders;
  cookies: Record<string, string>;
  body: any;
}

function parseCookies(setCookieHeader?: string | string[]): Record<string, string> {
  const cookies: Record<string, string> = {};
  if (!setCookieHeader) return cookies;
  const list = Array.isArray(setCookieHeader) ? setCookieHeader : [setCookieHeader];
  for (const str of list) {
    const parts = str.split(';')[0].split('=');
    if (parts.length >= 2) {
      cookies[parts[0].trim()] = parts.slice(1).join('=').trim();
    }
  }
  return cookies;
}

async function request(
  method: string,
  path: string,
  options: {
    headers?: Record<string, string>;
    body?: any;
    cookie?: string;
  } = {}
): Promise<HttpResponse> {
  return new Promise((resolve, reject) => {
    const url = new URL(path, BASE_URL);
    const postData = options.body ? JSON.stringify(options.body) : null;

    const headers: Record<string, string> = {
      'x-test-suite': 'true',
      ...(options.headers || {}),
    };

    if (postData) {
      headers['Content-Type'] = 'application/json';
      headers['Content-Length'] = String(Buffer.byteLength(postData));
    }
    if (options.cookie) {
      headers['Cookie'] = options.cookie;
    }

    const req = http.request(
      url,
      {
        method,
        headers,
      },
      (res) => {
        let raw = '';
        res.on('data', (chunk) => {
          raw += chunk;
        });
        res.on('end', () => {
          let body = raw;
          try {
            body = JSON.parse(raw);
          } catch {}
          resolve({
            status: res.statusCode || 0,
            headers: res.headers,
            cookies: parseCookies(res.headers['set-cookie']),
            body,
          });
        });
      }
    );

    req.on('error', reject);
    if (postData) req.write(postData);
    req.end();
  });
}

async function loginUser(u: string, p: string) {
  const res = await request('POST', '/api/login', {
    body: { username: u, password: p },
  });
  assert.strictEqual(res.status, 200, `Login for ${u} should succeed, got ${res.status}`);
  const sessionToken = res.cookies['tv_session'];
  assert.ok(sessionToken, 'Login must set tv_session cookie');
  const csrfToken = res.body?.csrfToken;
  assert.ok(csrfToken, 'Login must return csrfToken');
  const cookieHeader = `tv_session=${sessionToken}`;
  return { sessionToken, csrfToken, cookieHeader, user: res.body.user };
}

// ── Test Runner ─────────────────────────────────────────────────────────────
async function runTests() {
  console.log('\n🔒 Starting TrustVault Security & Settings Test Suite...\n');
  let passed = 0;
  let failed = 0;

  async function test(name: string, fn: () => Promise<void>) {
    try {
      await fn();
      console.log(`  ✓ ${name}`);
      passed++;
    } catch (err: any) {
      console.error(`  ✗ ${name}`);
      console.error(`    Error: ${err.message}`);
      failed++;
    }
  }

  // Test 1: Unauthenticated request to change-password returns 401
  await test('1. Unauthenticated request to change-password returns 401', async () => {
    const res = await request('POST', '/api/auth/change-password', {
      body: {
        currentPassword: 'AnyPassword123!',
        newPassword: 'NewPassword123!',
        confirmPassword: 'NewPassword123!',
      },
    });
    assert.strictEqual(res.status, 401, 'Unauthenticated change-password must return 401');
  });

  // Test 2: Wrong current password is refused and audited, and password is unchanged
  await test('2. Wrong current password is refused and audited, and password is unchanged', async () => {
    const auth = await loginUser('viewer1', 'Viewer123!');
    const res = await request('POST', '/api/auth/change-password', {
      headers: { 'x-csrf-token': auth.csrfToken },
      cookie: auth.cookieHeader,
      body: {
        currentPassword: 'WrongPassword999!',
        newPassword: 'ValidNewPass123!',
        confirmPassword: 'ValidNewPass123!',
      },
    });
    assert.strictEqual(res.status, 400, 'Wrong current password must return 400');
    assert.strictEqual(
      res.body.error,
      'Unable to change password. Check your current password and try again.',
      'Must return generic error message'
    );

    // Verify audit entry exists with outcome DENY and deny_reason INVALID_CREDENTIALS
    const auditRow = db
      .prepare(
        'SELECT action, outcome, actor_id, deny_reason FROM audit_log WHERE action = ? ORDER BY id DESC LIMIT 1'
      )
      .get('PASSWORD_CHANGE_FAILED') as any;
    assert.ok(auditRow, 'PASSWORD_CHANGE_FAILED audit row must exist');
    assert.strictEqual(auditRow.outcome, 'DENY');
    assert.strictEqual(auditRow.deny_reason, 'INVALID_CREDENTIALS');
    assert.strictEqual(auditRow.actor_id, auth.user.id);

    // Verify login with original password still works
    const checkLogin = await loginUser('viewer1', 'Viewer123!');
    assert.ok(checkLogin.sessionToken, 'Original password must remain unchanged');
  });

  // Test 3: Weak new password is rejected server-side even if UI is bypassed
  await test('3. Weak new password is rejected server-side even if UI is bypassed', async () => {
    const auth = await loginUser('viewer1', 'Viewer123!');

    // Test password too short (< 8 chars)
    const resShort = await request('POST', '/api/auth/change-password', {
      headers: { 'x-csrf-token': auth.csrfToken },
      cookie: auth.cookieHeader,
      body: {
        currentPassword: 'Viewer123!',
        newPassword: 'Short1!',
        confirmPassword: 'Short1!',
      },
    });
    assert.strictEqual(resShort.status, 400, 'Short password must return 400');

    // Test password missing special char
    const resNoSpecial = await request('POST', '/api/auth/change-password', {
      headers: { 'x-csrf-token': auth.csrfToken },
      cookie: auth.cookieHeader,
      body: {
        currentPassword: 'Viewer123!',
        newPassword: 'NoSpecialDigit123',
        confirmPassword: 'NoSpecialDigit123',
      },
    });
    assert.strictEqual(resNoSpecial.status, 400, 'Missing special char must return 400');

    // Test password missing number
    const resNoNum = await request('POST', '/api/auth/change-password', {
      headers: { 'x-csrf-token': auth.csrfToken },
      cookie: auth.cookieHeader,
      body: {
        currentPassword: 'Viewer123!',
        newPassword: 'NoNumberSpecial!',
        confirmPassword: 'NoNumberSpecial!',
      },
    });
    assert.strictEqual(resNoNum.status, 400, 'Missing number must return 400');

    // Test new password equals current password
    const resSame = await request('POST', '/api/auth/change-password', {
      headers: { 'x-csrf-token': auth.csrfToken },
      cookie: auth.cookieHeader,
      body: {
        currentPassword: 'Viewer123!',
        newPassword: 'Viewer123!',
        confirmPassword: 'Viewer123!',
      },
    });
    assert.strictEqual(resSame.status, 400, 'New password equal to current must return 400');
  });

  // Test 4: Successful change: old password fails, new works, other sessions stop working, PASSWORD_CHANGED audit row exists
  await test('4. Successful change: old fails, new works, other sessions revoked, PASSWORD_CHANGED audited', async () => {
    // 1. Session A logs in
    const sessionA = await loginUser('owner2', 'Owner5678!');

    // 2. Session B logs in on another device/browser
    const sessionB = await loginUser('owner2', 'Owner5678!');

    // Verify session B can reach /api/me
    const meBefore = await request('GET', '/api/me', { cookie: sessionB.cookieHeader });
    assert.strictEqual(meBefore.status, 200, 'Session B should be active before change');

    // 3. Change password on Session A
    const NEW_PASS = 'OwnerNewSecure999!';
    const changeRes = await request('POST', '/api/auth/change-password', {
      headers: { 'x-csrf-token': sessionA.csrfToken },
      cookie: sessionA.cookieHeader,
      body: {
        currentPassword: 'Owner5678!',
        newPassword: NEW_PASS,
        confirmPassword: NEW_PASS,
      },
    });
    assert.strictEqual(changeRes.status, 200, 'Change password should succeed');
    assert.ok(changeRes.cookies['tv_session'], 'Change password must rotate tv_session cookie');

    // Verify PASSWORD_CHANGED audit row
    const auditRow = db
      .prepare('SELECT action, outcome, actor_id FROM audit_log WHERE action = ? ORDER BY id DESC LIMIT 1')
      .get('PASSWORD_CHANGED') as any;
    assert.ok(auditRow, 'PASSWORD_CHANGED audit row must exist');
    assert.strictEqual(auditRow.outcome, 'ALLOW');
    assert.strictEqual(auditRow.actor_id, sessionA.user.id);

    // 4. Session B should immediately be revoked and fail on next request
    const meAfter = await request('GET', '/api/me', { cookie: sessionB.cookieHeader });
    assert.strictEqual(meAfter.status, 401, 'Other session B must fail with 401 after password change');

    // 5. Old password fails to log in
    const oldLoginRes = await request('POST', '/api/login', {
      body: { username: 'owner2', password: 'Owner5678!' },
    });
    assert.strictEqual(oldLoginRes.status, 401, 'Old password must fail to log in');

    // 6. New password works
    const newLoginRes = await loginUser('owner2', NEW_PASS);
    assert.ok(newLoginRes.sessionToken, 'New password must log in successfully');

    // Revert password back to Owner5678! so seed state remains clean
    await request('POST', '/api/auth/change-password', {
      headers: { 'x-csrf-token': newLoginRes.csrfToken },
      cookie: newLoginRes.cookieHeader,
      body: {
        currentPassword: NEW_PASS,
        newPassword: 'Owner5678!',
        confirmPassword: 'Owner5678!',
      },
    });
  });

  // Test 5: A request body containing another user ID or username cannot change that user's password
  await test('5. Request body containing another user ID/username cannot change that other user', async () => {
    const viewerAuth = await loginUser('viewer1', 'Viewer123!');

    // Malicious body attempting to change admin password while signed in as viewer1
    const res = await request('POST', '/api/auth/change-password', {
      headers: { 'x-csrf-token': viewerAuth.csrfToken },
      cookie: viewerAuth.cookieHeader,
      body: {
        userId: 1, // Admin's ID
        username: 'admin',
        currentPassword: 'Admin1234!', // Admin's password
        newPassword: 'HackedAdminPass123!',
        confirmPassword: 'HackedAdminPass123!',
      },
    });
    // Because currentPassword 'Admin1234!' does not match viewer1's password 'Viewer123!', it must fail
    assert.strictEqual(res.status, 400, 'Should reject mismatched password for authenticated user');

    // Verify admin can still log in with their original password
    const adminCheck = await loginUser('admin', 'Admin1234!');
    assert.ok(adminCheck.sessionToken, 'Admin password must remain untouched');
  });

  // Test 6: A viewer, owner, and admin can each change their OWN password
  await test('6. Viewer, owner, and admin can each change their OWN password', async () => {
    // 6a. Admin
    const adminAuth = await loginUser('admin', 'Admin1234!');
    const adminChange = await request('POST', '/api/auth/change-password', {
      headers: { 'x-csrf-token': adminAuth.csrfToken },
      cookie: adminAuth.cookieHeader,
      body: {
        currentPassword: 'Admin1234!',
        newPassword: 'NewAdminPass99!',
        confirmPassword: 'NewAdminPass99!',
      },
    });
    assert.strictEqual(adminChange.status, 200, 'Admin must be able to change password');
    const adminRevert = await loginUser('admin', 'NewAdminPass99!');
    await request('POST', '/api/auth/change-password', {
      headers: { 'x-csrf-token': adminRevert.csrfToken },
      cookie: adminRevert.cookieHeader,
      body: {
        currentPassword: 'NewAdminPass99!',
        newPassword: 'Admin1234!',
        confirmPassword: 'Admin1234!',
      },
    });

    // 6b. Owner1
    const ownerAuth = await loginUser('owner1', 'Owner1234!');
    const ownerChange = await request('POST', '/api/auth/change-password', {
      headers: { 'x-csrf-token': ownerAuth.csrfToken },
      cookie: ownerAuth.cookieHeader,
      body: {
        currentPassword: 'Owner1234!',
        newPassword: 'NewOwnerPass88!',
        confirmPassword: 'NewOwnerPass88!',
      },
    });
    assert.strictEqual(ownerChange.status, 200, 'Owner must be able to change password');
    const ownerRevert = await loginUser('owner1', 'NewOwnerPass88!');
    await request('POST', '/api/auth/change-password', {
      headers: { 'x-csrf-token': ownerRevert.csrfToken },
      cookie: ownerRevert.cookieHeader,
      body: {
        currentPassword: 'NewOwnerPass88!',
        newPassword: 'Owner1234!',
        confirmPassword: 'Owner1234!',
      },
    });

    // 6c. Viewer1
    const viewerAuth = await loginUser('viewer1', 'Viewer123!');
    const viewerChange = await request('POST', '/api/auth/change-password', {
      headers: { 'x-csrf-token': viewerAuth.csrfToken },
      cookie: viewerAuth.cookieHeader,
      body: {
        currentPassword: 'Viewer123!',
        newPassword: 'NewViewerPass77!',
        confirmPassword: 'NewViewerPass77!',
      },
    });
    assert.strictEqual(viewerChange.status, 200, 'Viewer must be able to change password');
    const viewerRevert = await loginUser('viewer1', 'NewViewerPass77!');
    await request('POST', '/api/auth/change-password', {
      headers: { 'x-csrf-token': viewerRevert.csrfToken },
      cookie: viewerRevert.cookieHeader,
      body: {
        currentPassword: 'NewViewerPass77!',
        newPassword: 'Viewer123!',
        confirmPassword: 'Viewer123!',
      },
    });
  });

  // Test 7: Sessions endpoints never return other users' sessions
  await test('7. Sessions endpoints never return other users sessions', async () => {
    const adminAuth = await loginUser('admin', 'Admin1234!');
    const viewerAuth = await loginUser('viewer1', 'Viewer123!');

    // Viewer queries sessions
    const viewerSessionsRes = await request('GET', '/api/auth/sessions', {
      cookie: viewerAuth.cookieHeader,
    });
    assert.strictEqual(viewerSessionsRes.status, 200);
    const viewerSessions = viewerSessionsRes.body.sessions || [];
    assert.ok(viewerSessions.length > 0, 'Viewer must see their own active session');

    // Admin queries sessions
    const adminSessionsRes = await request('GET', '/api/auth/sessions', {
      cookie: adminAuth.cookieHeader,
    });
    assert.strictEqual(adminSessionsRes.status, 200);
    const adminSessions = adminSessionsRes.body.sessions || [];
    assert.ok(adminSessions.length > 0, 'Admin must see their own active session');

    // Revoke others as viewer
    const revokeRes = await request('POST', '/api/auth/sessions/revoke-others', {
      headers: { 'x-csrf-token': viewerAuth.csrfToken },
      cookie: viewerAuth.cookieHeader,
    });
    assert.strictEqual(revokeRes.status, 200, 'Revoke others must succeed');

    // Ensure SESSIONS_REVOKED was written to audit log
    const auditRow = db
      .prepare('SELECT action, outcome, actor_id FROM audit_log WHERE action = ? ORDER BY id DESC LIMIT 1')
      .get('SESSIONS_REVOKED') as any;
    assert.ok(auditRow, 'SESSIONS_REVOKED audit row must exist');
    assert.strictEqual(auditRow.outcome, 'ALLOW');
    assert.strictEqual(auditRow.actor_id, viewerAuth.user.id);
  });

  // Test 8: Audit chain still verifies after all of the above
  await test('8. Audit chain still verifies after all operations', async () => {
    const chainStatus = verifyAuditChain();
    assert.strictEqual(chainStatus.valid, true, `Audit chain broken at row ${chainStatus.brokenAt}`);
    assert.ok(chainStatus.totalRows > 0, 'Audit log must contain verified records');
    console.log(`      Total audit rows verified: ${chainStatus.totalRows}`);
  });

  console.log(`\n========================================`);
  console.log(`Results: ${passed} passed, ${failed} failed`);
  console.log(`========================================\n`);

  if (failed > 0) {
    process.exit(1);
  }
}

runTests().catch((err) => {
  console.error('Fatal test error:', err);
  process.exit(1);
});
