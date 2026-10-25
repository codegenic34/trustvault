// public/js/dashboard.js
// SECURITY: All user-supplied strings rendered via textContent or setAttribute only.
// Never innerHTML with user data.
'use strict';

let currentUser = null;
let csrfToken   = sessionStorage.getItem('csrfToken');
let currentDocId = null; // for the permissions modal

// ── Helpers ────────────────────────────────────────────────────────────────

async function getCsrfToken() {
  if (csrfToken) return csrfToken;
  const r = await fetch('/api/csrf-token', { credentials: 'same-origin' });
  if (!r.ok) { window.location.replace('/'); return null; }
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

function formatBytes(b) {
  if (b < 1024) return b + ' B';
  if (b < 1048576) return (b / 1024).toFixed(1) + ' KB';
  return (b / 1048576).toFixed(2) + ' MB';
}

function formatDate(iso) {
  return new Date(iso).toLocaleString();
}

function setTextById(id, text) {
  const el = document.getElementById(id);
  if (el) el.textContent = text;
}

function showBanner(id, msg, isError) {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = msg; // safe — textContent
  el.className = el.className.replace(/hidden/, '').trim();
  if (isError) {
    el.classList.remove('bg-green-950', 'border-green-700', 'text-green-300');
    el.classList.add('bg-red-950', 'border-red-700', 'text-red-300');
  } else {
    el.classList.remove('bg-red-950', 'border-red-700', 'text-red-300');
    el.classList.add('bg-green-950', 'border-green-700', 'text-green-300');
  }
  setTimeout(() => el.classList.add('hidden'), 5000);
}

// ── Load current user ──────────────────────────────────────────────────────

async function loadMe() {
  const r = await fetch('/api/me', { credentials: 'same-origin' });
  if (!r.ok) { window.location.replace('/'); return; }
  const { user } = await r.json();
  currentUser = user;

  // textContent — never innerHTML
  setTextById('hdr-username', user.username);
  setTextById('hdr-role', user.role);
  const hdrRoleEl = document.getElementById('hdr-role');
  if (hdrRoleEl) {
    hdrRoleEl.className = 'role-' + user.role;
  }

  if (user.role === 'owner') {
    document.getElementById('upload-section').classList.remove('hidden');
  }
  if (user.role === 'admin') {
    // admins should be on admin.html
    window.location.replace('/admin.html');
    return;
  }

  loadDocuments();
}

// ── Document list ──────────────────────────────────────────────────────────

async function loadDocuments(params = {}) {
  const qs = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => { if (v) qs.set(k, v); });

  const r = await fetch(`/api/documents?${qs}`, { credentials: 'same-origin' });
  if (!r.ok) { renderDocs([]); return; }
  const { documents } = await r.json();
  renderDocs(documents || []);
}

function renderDocs(docs) {
  const container = document.getElementById('doc-list');
  container.textContent = ''; // clear safely

  if (!docs.length) {
    const p = document.createElement('p');
    p.textContent = 'No documents found.';
    p.className = 'text-gray-500 text-sm';
    container.appendChild(p);
    return;
  }

  docs.forEach(doc => {
    const card = buildDocCard(doc);
    container.appendChild(card);
  });
}

function buildDocCard(doc) {
  const card = document.createElement('div');
  card.className = 'bg-gray-900 border border-gray-800 rounded-2xl p-5 fade-in flex flex-wrap items-start gap-4';

  // Left: info
  const info = document.createElement('div');
  info.className = 'flex-1 min-w-0';

  const name = document.createElement('p');
  name.className = 'font-medium text-white truncate';
  name.textContent = doc.original_name; // textContent — safe
  info.appendChild(name);

  const meta = document.createElement('p');
  meta.className = 'text-xs text-gray-400 mt-1';
  // Build meta text using safe string methods
  const parts = [];
  if (doc.category) parts.push('Category: ' + doc.category);
  parts.push('Owner: ' + doc.owner_name);
  parts.push(formatBytes(doc.size));
  parts.push(formatDate(doc.created_at));
  meta.textContent = parts.join('  ·  ');
  info.appendChild(meta);

  // Badges
  const badges = document.createElement('div');
  badges.className = 'flex gap-2 mt-2';
  if (doc.is_owner) addBadge(badges, 'owner', 'bg-purple-900 text-purple-300');
  if (doc.can_read && !doc.is_owner) addBadge(badges, 'read', 'bg-blue-900 text-blue-300');
  if (doc.can_edit && !doc.is_owner) addBadge(badges, 'edit', 'bg-yellow-900 text-yellow-300');
  info.appendChild(badges);

  card.appendChild(info);

  // Right: actions
  const actions = document.createElement('div');
  actions.className = 'flex flex-wrap gap-2 shrink-0';

  if (doc.can_read || doc.is_owner) {
    const dlBtn = document.createElement('button');
    dlBtn.className = 'px-3 py-1.5 text-xs rounded-lg bg-blue-700 hover:bg-blue-600 text-white transition-colors';
    dlBtn.textContent = '⬇ Download';
    dlBtn.addEventListener('click', () => downloadDoc(doc.id));
    actions.appendChild(dlBtn);
  }

  if (doc.can_edit || doc.is_owner) {
    const editBtn = document.createElement('button');
    editBtn.className = 'px-3 py-1.5 text-xs rounded-lg bg-gray-700 hover:bg-gray-600 text-white transition-colors';
    editBtn.textContent = '✏ Edit';
    editBtn.addEventListener('click', () => openEditModal(doc));
    actions.appendChild(editBtn);
  }

  if (doc.is_owner) {
    const permBtn = document.createElement('button');
    permBtn.className = 'px-3 py-1.5 text-xs rounded-lg bg-gray-700 hover:bg-gray-600 text-white transition-colors';
    permBtn.textContent = '🔑 Permissions';
    permBtn.addEventListener('click', () => openPermModal(doc.id));
    actions.appendChild(permBtn);

    const delBtn = document.createElement('button');
    delBtn.className = 'px-3 py-1.5 text-xs rounded-lg bg-red-900 hover:bg-red-800 text-red-200 transition-colors';
    delBtn.textContent = '🗑 Delete';
    delBtn.addEventListener('click', () => deleteDoc(doc.id, name.textContent));
    actions.appendChild(delBtn);
  }

  card.appendChild(actions);
  return card;
}

function addBadge(parent, label, classes) {
  const span = document.createElement('span');
  span.className = 'text-xs px-2 py-0.5 rounded-full ' + classes;
  span.textContent = label; // safe
  parent.appendChild(span);
}

// ── Download ───────────────────────────────────────────────────────────────

function downloadDoc(id) {
  // Open download URL directly — browser handles the attachment header
  const a = document.createElement('a');
  a.href = '/api/documents/' + encodeURIComponent(id) + '/download';
  a.rel = 'noopener noreferrer';
  a.click();
}

// ── Delete ─────────────────────────────────────────────────────────────────

async function deleteDoc(id, displayName) {
  if (!confirm('Delete "' + displayName + '"? This cannot be undone.')) return;

  const r = await apiFetch('/api/documents/' + encodeURIComponent(id), { method: 'DELETE' });
  if (r.ok) {
    loadDocuments();
  } else {
    const d = await r.json().catch(() => ({}));
    alert(d.error || 'Delete failed');
  }
}

// ── Upload ─────────────────────────────────────────────────────────────────

document.getElementById('upload-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const fileInput = document.getElementById('file-input');
  const categoryInput = document.getElementById('category-input');
  const btn = document.getElementById('upload-btn');

  if (!fileInput.files.length) {
    showBanner('upload-error', 'Please select a file.', true);
    return;
  }

  const fd = new FormData();
  fd.append('file', fileInput.files[0]);
  fd.append('category', categoryInput.value.trim());

  btn.disabled = true;
  btn.textContent = 'Uploading…';

  try {
    const token = await getCsrfToken();
    const r = await fetch('/api/documents', {
      method: 'POST',
      headers: { 'x-csrf-token': token },
      body: fd,
      credentials: 'same-origin',
    });
    const d = await r.json();
    if (!r.ok) {
      showBanner('upload-error', d.error || 'Upload failed', true);
    } else {
      showBanner('upload-success', 'Uploaded successfully!', false);
      fileInput.value = '';
      categoryInput.value = '';
      loadDocuments();
    }
  } catch {
    showBanner('upload-error', 'Network error during upload.', true);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Upload';
  }
});

// ── Search ─────────────────────────────────────────────────────────────────

document.getElementById('search-btn').addEventListener('click', () => {
  loadDocuments({
    q:        document.getElementById('search-q').value.trim(),
    category: document.getElementById('filter-category').value.trim(),
  });
});

document.getElementById('clear-btn').addEventListener('click', () => {
  document.getElementById('search-q').value = '';
  document.getElementById('filter-category').value = '';
  loadDocuments();
});

document.getElementById('search-q').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') document.getElementById('search-btn').click();
});

// ── Edit Metadata Modal ─────────────────────────────────────────────────────

function openEditModal(doc) {
  currentDocId = doc.id;
  document.getElementById('edit-name').value = doc.original_name;
  document.getElementById('edit-category').value = doc.category || '';
  document.getElementById('edit-modal-backdrop').classList.remove('hidden');
}

document.getElementById('edit-modal-close').addEventListener('click', () => {
  document.getElementById('edit-modal-backdrop').classList.add('hidden');
});

document.getElementById('edit-save-btn').addEventListener('click', async () => {
  const name     = document.getElementById('edit-name').value.trim();
  const category = document.getElementById('edit-category').value.trim();
  const errEl    = document.getElementById('edit-error');

  const r = await apiFetch('/api/documents/' + encodeURIComponent(currentDocId), {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ original_name: name, category }),
  });
  const d = await r.json();

  if (!r.ok) {
    errEl.textContent = d.error || 'Update failed'; // textContent
    errEl.classList.remove('hidden');
  } else {
    document.getElementById('edit-modal-backdrop').classList.add('hidden');
    loadDocuments();
  }
});

// ── Permissions Modal ──────────────────────────────────────────────────────

async function openPermModal(docId) {
  currentDocId = docId;
  document.getElementById('modal-backdrop').classList.remove('hidden');
  await loadPerms(docId);
}

async function loadPerms(docId) {
  const r = await fetch('/api/documents/' + encodeURIComponent(docId) + '/permissions',
    { credentials: 'same-origin' });
  const container = document.getElementById('perms-list');
  container.textContent = '';

  if (!r.ok) {
    const p = document.createElement('p');
    p.textContent = 'Failed to load permissions.';
    p.className = 'text-red-400 text-xs';
    container.appendChild(p);
    return;
  }

  const { permissions } = await r.json();
  if (!permissions.length) {
    const p = document.createElement('p');
    p.textContent = 'No permissions granted yet.';
    p.className = 'text-gray-500 text-xs';
    container.appendChild(p);
    return;
  }

  permissions.forEach(perm => {
    const row = document.createElement('div');
    row.className = 'flex items-center justify-between p-2 rounded-lg ' +
      (perm.revoked_at ? 'bg-gray-800/50 opacity-50' : 'bg-gray-800');

    const left = document.createElement('div');

    const uname = document.createElement('span');
    uname.className = 'font-medium text-white text-sm';
    uname.textContent = perm.grantee_username; // textContent

    const rights = document.createElement('span');
    rights.className = 'text-xs text-gray-400 ml-2';
    const parts = [];
    if (perm.can_read) parts.push('read');
    if (perm.can_edit) parts.push('edit');
    rights.textContent = parts.join(', ') || 'none';
    if (perm.revoked_at) {
      const rv = document.createElement('span');
      rv.className = 'text-xs text-red-400 ml-2';
      rv.textContent = '(revoked)';
      rights.appendChild(rv);
    }

    left.appendChild(uname);
    left.appendChild(rights);

    row.appendChild(left);

    if (!perm.revoked_at) {
      const revokeBtn = document.createElement('button');
      revokeBtn.className = 'text-xs px-2 py-1 rounded bg-red-900 hover:bg-red-800 text-red-200 transition-colors';
      revokeBtn.textContent = 'Revoke';
      revokeBtn.addEventListener('click', async () => {
        const res = await apiFetch(
          '/api/documents/' + encodeURIComponent(currentDocId) + '/permissions/' + perm.grantee_id,
          { method: 'DELETE' }
        );
        if (res.ok) {
          loadPerms(currentDocId);
        } else {
          const errEl = document.getElementById('grant-error');
          const d = await res.json().catch(() => ({}));
          errEl.textContent = d.error || 'Revoke failed'; // textContent
          errEl.classList.remove('hidden');
        }
      });
      row.appendChild(revokeBtn);
    }

    container.appendChild(row);
  });
}

document.getElementById('modal-close').addEventListener('click', () => {
  document.getElementById('modal-backdrop').classList.add('hidden');
});

document.getElementById('grant-btn').addEventListener('click', async () => {
  const username = document.getElementById('grant-username').value.trim();
  const can_read = document.getElementById('grant-can-read').checked;
  const can_edit = document.getElementById('grant-can-edit').checked;
  const errEl    = document.getElementById('grant-error');
  errEl.classList.add('hidden');

  if (!username) {
    errEl.textContent = 'Enter a username.'; // textContent
    errEl.classList.remove('hidden');
    return;
  }

  const r = await apiFetch(
    '/api/documents/' + encodeURIComponent(currentDocId) + '/permissions',
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, can_read, can_edit }),
    }
  );
  const d = await r.json();

  if (!r.ok) {
    errEl.textContent = d.error || 'Grant failed'; // textContent
    errEl.classList.remove('hidden');
  } else {
    document.getElementById('grant-username').value = '';
    loadPerms(currentDocId);
  }
});

// ── Logout ─────────────────────────────────────────────────────────────────

document.getElementById('logout-btn').addEventListener('click', async () => {
  await apiFetch('/api/logout', { method: 'POST' });
  sessionStorage.removeItem('csrfToken');
  window.location.replace('/');
});

// ── Bootstrap ──────────────────────────────────────────────────────────────
loadMe();
