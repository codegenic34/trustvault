// public/js/settings.js
// SECURITY: Pure vanilla JS. Zero external libs.
// SECURITY: textContent only for dynamic data — never innerHTML with user data.
// SECURITY: Passwords never stored in localStorage, sessionStorage, cookies, or DOM.
'use strict';

let currentUser = null;
let csrfToken = sessionStorage.getItem('csrfToken');

// ── SVG Icon Definitions for Requirements Checklist ─────────────────────────
const SVG_CHECK = '<path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/>';
const SVG_CROSS = '<path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd"/>';

// ── CSRF and API Helpers ────────────────────────────────────────────────────
async function getCsrfToken() {
  if (csrfToken) return csrfToken;
  const r = await fetch('/api/csrf-token', { credentials: 'same-origin' });
  if (!r.ok) {
    window.location.replace('/');
    return null;
  }
  const d = await r.json();
  csrfToken = d.csrfToken;
  sessionStorage.setItem('csrfToken', csrfToken);
  return csrfToken;
}

async function apiFetch(url, options = {}) {
  const token = await getCsrfToken();
  const headers = { ...(options.headers || {}) };
  if (token && ['POST', 'PATCH', 'PUT', 'DELETE'].includes(options.method || '')) {
    headers['x-csrf-token'] = token;
  }
  return fetch(url, { ...options, headers, credentials: 'same-origin' });
}

function formatDate(iso) {
  if (!iso) return '—';
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

// ── Load Current User and Setup Profile ─────────────────────────────────────
async function loadMe() {
  const r = await fetch('/api/me', { credentials: 'same-origin' });
  if (!r.ok) {
    window.location.replace('/');
    return;
  }
  const data = await r.json();
  const user = data.user;
  currentUser = user;

  // Header display
  const hdrUser = document.getElementById('hdr-username');
  if (hdrUser) hdrUser.textContent = user.username;

  const hdrRole = document.getElementById('hdr-role');
  if (hdrRole) {
    hdrRole.textContent = user.role;
    hdrRole.className = 'role-' + user.role;
  }

  // Admin link in nav
  if (user.role === 'admin') {
    const navAdmin = document.getElementById('nav-admin');
    if (navAdmin) navAdmin.classList.remove('hidden');
  }

  // Populate Profile tab fields
  const fnInput = document.getElementById('prof-fullname-input');
  if (fnInput) fnInput.value = user.full_name || user.username;
  const unInput = document.getElementById('prof-username-input');
  if (unInput) unInput.value = user.username;
  const emInput = document.getElementById('prof-email-input');
  if (emInput) emInput.value = user.email || `${user.username}@trustvault.local`;
  const llInput = document.getElementById('prof-lastlogin-input');
  if (llInput) llInput.value = formatDate(user.last_login);
  const crEl = document.getElementById('prof-created');
  if (crEl) crEl.textContent = formatDate(user.created_at);

  const roleBadge = document.getElementById('prof-role-badge');
  if (roleBadge) {
    roleBadge.textContent = user.role.toUpperCase();
    if (user.role === 'admin') {
      roleBadge.className = 'badge-blocked';
    } else if (user.role === 'owner') {
      roleBadge.className = 'badge-warning';
    } else {
      roleBadge.className = 'badge-viewer';
    }
  }
}

// ── Profile Edit Handler ───────────────────────────────────────────────────
function initProfilePanel() {
  const saveBtn = document.getElementById('save-profile-btn');
  const alertEl = document.getElementById('prof-alert-banner');
  const alertText = document.getElementById('prof-alert-text');
  const alertIcon = document.getElementById('prof-alert-icon');
  const fnInput = document.getElementById('prof-fullname-input');
  const unInput = document.getElementById('prof-username-input');
  const emInput = document.getElementById('prof-email-input');
  const llInput = document.getElementById('prof-lastlogin-input');

  if (!saveBtn) return;

  function showAlert(msg, isSuccess) {
    if (!alertEl || !alertText) return;
    alertText.textContent = msg;
    if (isSuccess) {
      alertEl.className = 'alert-banner alert-success';
      if (alertIcon) alertIcon.textContent = '✓';
    } else {
      alertEl.className = 'alert-banner alert-danger';
      if (alertIcon) alertIcon.textContent = '⚠';
    }
    alertEl.style.display = 'flex';
  }

  saveBtn.addEventListener('click', async (e) => {
    e.preventDefault();
    if (alertEl) alertEl.style.display = 'none';

    const username = unInput ? unInput.value.trim() : '';
    const fullName = fnInput ? fnInput.value.trim() : '';
    const email = emInput ? emInput.value.trim() : '';
    const lastLogin = llInput ? llInput.value.trim() : '';

    if (!username) {
      showAlert('Username cannot be empty.', false);
      return;
    }

    saveBtn.disabled = true;
    saveBtn.textContent = 'Saving Changes...';

    try {
      const res = await apiFetch('/api/auth/profile', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ fullName, username, email, lastLogin }),
      });

      const data = await res.json().catch(() => ({}));

      if (res.ok) {
        showAlert('Profile updated successfully.', true);
        const hdrUser = document.getElementById('hdr-username');
        if (hdrUser) hdrUser.textContent = username;
        if (currentUser) {
          currentUser.username = username;
          currentUser.full_name = fullName;
          currentUser.email = email;
          currentUser.last_login = lastLogin;
        }
      } else {
        showAlert(data.error || 'Unable to update profile. Please check your inputs.', false);
      }
    } catch {
      showAlert('Unable to connect to server. Please try again.', false);
    } finally {
      saveBtn.disabled = false;
      saveBtn.textContent = 'Save Profile Changes';
    }
  });
}

// ── Tab Navigation ──────────────────────────────────────────────────────────
function initTabs() {
  const tabBtns = document.querySelectorAll('.settings-tab-btn');
  const panels = document.querySelectorAll('.settings-panel');

  function switchTab(tabId) {
    tabBtns.forEach(btn => {
      const active = btn.dataset.tab === tabId;
      btn.classList.toggle('active', active);
      btn.setAttribute('aria-selected', active ? 'true' : 'false');
    });

    panels.forEach(panel => {
      const active = panel.id === `panel-${tabId}`;
      panel.classList.toggle('active', active);
    });

    if (tabId === 'sessions') {
      loadSessions();
    }
  }

  tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const tabId = btn.dataset.tab;
      switchTab(tabId);
      window.location.hash = tabId;
    });
  });

  // Handle URL hash on load
  const initialHash = window.location.hash.replace('#', '');
  if (['profile', 'security', 'sessions', 'about'].includes(initialHash)) {
    switchTab(initialHash);
  }
}

// ── Show / Hide Password Toggles ───────────────────────────────────────────
function initPasswordToggles() {
  const toggleBtns = document.querySelectorAll('.pw-toggle-btn');
  toggleBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const targetId = btn.dataset.target;
      const input = document.getElementById(targetId);
      if (!input) return;

      const isPw = input.type === 'password';
      input.type = isPw ? 'text' : 'password';
      btn.setAttribute('aria-label', isPw ? 'Hide password' : 'Show password');
      btn.style.color = isPw ? '#3B82F6' : 'var(--text-muted)';
    });
  });
}

// ── Live Password Requirements & Strength Meter ─────────────────────────────
function initSecurityPanel() {
  const currInput = document.getElementById('curr-password');
  const newInput = document.getElementById('new-password');
  const confInput = document.getElementById('conf-password');
  const submitBtn = document.getElementById('btn-change-password');

  const strengthBar = document.getElementById('strength-bar');
  const strengthLabel = document.getElementById('strength-label');

  const reqLen = document.getElementById('req-len');
  const reqUpper = document.getElementById('req-upper');
  const reqLower = document.getElementById('req-lower');
  const reqNum = document.getElementById('req-num');
  const reqSpecial = document.getElementById('req-special');

  const matchErr = document.getElementById('match-error');
  const diffErr = document.getElementById('diff-error');

  const errorBanner = document.getElementById('pw-error-banner');
  const errorText = document.getElementById('pw-error-text');
  const successBanner = document.getElementById('pw-success-banner');
  const successText = document.getElementById('pw-success-text');

  function updateReqItem(liEl, met) {
    if (!liEl) return;
    liEl.classList.toggle('met', met);
    const svg = liEl.querySelector('.req-icon-svg');
    if (svg) {
      svg.innerHTML = met ? SVG_CHECK : SVG_CROSS;
      svg.style.color = met ? '#10B981' : 'var(--text-muted)';
    }
  }

  function validate() {
    const curr = currInput.value;
    const pwd = newInput.value;
    const conf = confInput.value;

    const hasLen = pwd.length >= 8;
    const hasUpper = /[A-Z]/.test(pwd);
    const hasLower = /[a-z]/.test(pwd);
    const hasNum = /[0-9]/.test(pwd);
    const hasSpecial = /[^A-Za-z0-9]/.test(pwd);

    updateReqItem(reqLen, hasLen);
    updateReqItem(reqUpper, hasUpper);
    updateReqItem(reqLower, hasLower);
    updateReqItem(reqNum, hasNum);
    updateReqItem(reqSpecial, hasSpecial);

    const allReqsMet = hasLen && hasUpper && hasLower && hasNum && hasSpecial;

    // Strength Meter
    let score = 0;
    if (pwd.length >= 8) score++;
    if (pwd.length >= 12) score++;
    if (hasUpper && hasLower) score++;
    if (hasNum) score++;
    if (hasSpecial) score++;

    strengthBar.className = 'strength-bar-fill';
    if (!pwd) {
      strengthLabel.textContent = 'None';
      strengthLabel.style.color = 'var(--text-muted)';
    } else if (score <= 2 || !allReqsMet) {
      strengthBar.classList.add('weak');
      strengthLabel.textContent = 'Weak';
      strengthLabel.style.color = '#EF4444';
    } else if (score <= 4) {
      strengthBar.classList.add('medium');
      strengthLabel.textContent = 'Medium';
      strengthLabel.style.color = '#F59E0B';
    } else {
      strengthBar.classList.add('strong');
      strengthLabel.textContent = 'Strong';
      strengthLabel.style.color = '#10B981';
    }

    // Match check
    const matches = pwd === conf;
    if (conf.length > 0 && !matches) {
      matchErr.style.display = 'block';
    } else {
      matchErr.style.display = 'none';
    }

    // Diff from current check
    const differs = pwd.length > 0 && curr.length > 0 && pwd !== curr;
    if (pwd.length > 0 && curr.length > 0 && pwd === curr) {
      diffErr.style.display = 'block';
    } else {
      diffErr.style.display = 'none';
    }

    // Submit button state
    const isValid =
      curr.trim().length > 0 &&
      allReqsMet &&
      matches &&
      differs;

    submitBtn.disabled = !isValid;
  }

  [currInput, newInput, confInput].forEach(inp => {
    inp.addEventListener('input', validate);
  });

  // Initial state check
  validate();

  // Form submission
  const form = document.getElementById('change-password-form');
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    errorBanner.style.display = 'none';
    successBanner.style.display = 'none';

    submitBtn.disabled = true;
    submitBtn.textContent = 'Updating...';

    const currentPassword = currInput.value;
    const newPassword = newInput.value;
    const confirmPassword = confInput.value;

    try {
      const res = await apiFetch('/api/auth/change-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ currentPassword, newPassword, confirmPassword }),
      });

      const data = await res.json();

      if (!res.ok) {
        errorText.textContent = data.error || 'Unable to change password. Check your current password and try again.';
        errorBanner.style.display = 'flex';
      } else {
        successText.textContent = data.message || 'Password changed successfully.';
        successBanner.style.display = 'flex';

        // Clear password fields immediately
        currInput.value = '';
        newInput.value = '';
        confInput.value = '';

        if (data.csrfToken) {
          csrfToken = data.csrfToken;
          sessionStorage.setItem('csrfToken', csrfToken);
        }

        validate();
      }
    } catch (err) {
      errorText.textContent = 'Unable to change password. Check your current password and try again.';
      errorBanner.style.display = 'flex';
    } finally {
      submitBtn.textContent = 'Change Password';
      validate();
    }
  });
}

// ── Sessions Management ────────────────────────────────────────────────────
async function loadSessions() {
  const container = document.getElementById('sessions-list');
  container.textContent = '';

  const loadingP = document.createElement('p');
  loadingP.textContent = 'Loading active sessions…';
  loadingP.className = 'text-muted';
  container.appendChild(loadingP);

  try {
    const r = await fetch('/api/auth/sessions', { credentials: 'same-origin' });
    if (!r.ok) {
      container.textContent = 'Failed to load active sessions.';
      return;
    }
    const data = await r.json();
    const sessions = data.sessions || [];

    container.textContent = '';

    if (!sessions.length) {
      const p = document.createElement('p');
      p.textContent = 'No active sessions found.';
      p.style.color = 'var(--text-muted)';
      container.appendChild(p);
      return;
    }

    sessions.forEach(sess => {
      const card = document.createElement('div');
      card.className = 'session-item';

      const info = document.createElement('div');
      info.className = 'session-info';

      const device = document.createElement('div');
      device.className = 'session-device';
      device.textContent = sess.device;

      if (sess.is_current) {
        const badge = document.createElement('span');
        badge.className = 'badge-current-session';
        const dot = document.createElement('span');
        dot.className = 'badge-current-dot';
        badge.appendChild(dot);
        badge.appendChild(document.createTextNode('Current Session'));
        device.appendChild(badge);
      }

      const meta = document.createElement('div');
      meta.className = 'session-meta';
      meta.textContent = `Signed in: ${formatDate(sess.created_at)}  ·  Last active: ${formatDate(sess.last_active)}`;

      info.appendChild(device);
      info.appendChild(meta);
      card.appendChild(info);

      container.appendChild(card);
    });
  } catch (err) {
    container.textContent = 'Error loading sessions.';
  }
}

function initSessionsRevoke() {
  const btn = document.getElementById('btn-revoke-others');
  const alertEl = document.getElementById('session-alert');

  btn.addEventListener('click', async () => {
    btn.disabled = true;
    btn.textContent = 'Signing out other sessions...';

    try {
      const res = await apiFetch('/api/auth/sessions/revoke-others', {
        method: 'POST',
      });
      const data = await res.json();

      if (res.ok) {
        alertEl.textContent = data.message || 'Other sessions signed out successfully.';
        alertEl.style.display = 'block';
        setTimeout(() => { alertEl.style.display = 'none'; }, 4000);
        await loadSessions();
      } else {
        alertEl.className = 'alert-banner alert-danger';
        alertEl.textContent = data.error || 'Failed to revoke other sessions.';
        alertEl.style.display = 'block';
      }
    } catch {
      alertEl.className = 'alert-banner alert-danger';
      alertEl.textContent = 'Failed to revoke other sessions.';
      alertEl.style.display = 'block';
    } finally {
      btn.disabled = false;
      btn.textContent = 'Sign out other sessions';
    }
  });
}

// ── Logout ─────────────────────────────────────────────────────────────────
function initLogout() {
  const btn = document.getElementById('logout-btn');
  if (!btn) return;
  btn.addEventListener('click', async () => {
    await apiFetch('/api/logout', { method: 'POST' });
    sessionStorage.removeItem('csrfToken');
    window.location.replace('/');
  });
}

// ── Bootstrap ──────────────────────────────────────────────────────────────
(async function init() {
  await loadMe();
  initProfilePanel();
  initTabs();
  initPasswordToggles();
  initSecurityPanel();
  initSessionsRevoke();
  initLogout();
})();
