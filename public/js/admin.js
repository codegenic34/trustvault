// public/js/admin.js
// SECURITY: All user-supplied strings rendered with textContent only — never innerHTML.
'use strict';

let csrfToken = sessionStorage.getItem('csrfToken');
let page = 0;
const LIMIT = 50;

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

async function apiFetch(url, opts = {}) {
  const token = await getCsrfToken();
  const headers = { ...(opts.headers || {}) };
  if (token && ['POST', 'PATCH', 'PUT', 'DELETE'].includes(opts.method || '')) {
    headers['x-csrf-token'] = token;
  }
  return fetch(url, { ...opts, headers, credentials: 'same-origin' });
}

function td(text, extraClass) {
  const el = document.createElement('td');
  el.className = 'px-4 py-2.5 align-top ' + (extraClass || '');
  el.textContent = String(text ?? ''); // textContent — never innerHTML
  return el;
}

function formatDate(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleString();
}

// ── Auth guard ─────────────────────────────────────────────────────────────

async function guardAdmin() {
  const r = await fetch('/api/me', { credentials: 'same-origin' });
  if (!r.ok) { window.location.replace('/'); return false; }
  const { user } = await r.json();
  if (user.role !== 'admin') { window.location.replace('/dashboard.html'); return false; }
  const uEl = document.getElementById('hdr-username');
  if (uEl) uEl.textContent = user.username;
  return true;
}

// ── Audit log ──────────────────────────────────────────────────────────────

async function loadAudit() {
  const outcome = document.getElementById('filter-outcome').value;
  const action = document.getElementById('filter-action').value.trim();
  const actor_id = document.getElementById('filter-actor').value.trim();

  const qs = new URLSearchParams({ limit: LIMIT, offset: page * LIMIT });
  if (outcome) qs.set('outcome', outcome);
  if (action) qs.set('action', action);
  if (actor_id) qs.set('actor_id', actor_id);

  const r = await fetch(`/api/audit?${qs}`, { credentials: 'same-origin' });
  const tbody = document.getElementById('audit-tbody');
  tbody.textContent = '';

  if (!r.ok) {
    const tr = document.createElement('tr');
    const cell = document.createElement('td');
    cell.colSpan = 8;
    cell.className = 'px-4 py-6 text-center text-red-400';
    cell.textContent = 'Failed to load audit log.';
    tr.appendChild(cell);
    tbody.appendChild(tr);
    return;
  }

  const { logs, total } = await r.json();

  if (!logs.length) {
    const tr = document.createElement('tr');
    const cell = document.createElement('td');
    cell.colSpan = 8;
    cell.className = 'px-4 py-6 text-center text-gray-500';
    cell.textContent = 'No log entries match the filter.';
    tr.appendChild(cell);
    tbody.appendChild(tr);
  }

  logs.forEach(log => {
    const tr = document.createElement('tr');
    tr.className = 'border-t border-gray-800/50 hover:bg-gray-800/30 transition-colors log-' + log.outcome;

    tr.appendChild(td(log.id, 'text-gray-500 text-xs'));
    tr.appendChild(td(formatDate(log.timestamp), 'text-gray-300 text-xs whitespace-nowrap'));

    const actorCell = td('', 'text-gray-200');
    const actorSpan = document.createElement('span');
    actorSpan.textContent = log.actor_username || ('ID:' + (log.actor_id ?? 'anon'));
    actorCell.appendChild(actorSpan);
    tr.appendChild(actorCell);

    tr.appendChild(td(log.action, 'font-mono text-xs text-yellow-300'));

    const outcomeCell = document.createElement('td');
    outcomeCell.className = 'px-4 py-2.5 text-xs font-semibold';
    const badge = document.createElement('span');
    badge.className = log.outcome === 'DENY'
      ? 'px-2 py-0.5 rounded-full bg-red-900 text-red-300'
      : 'px-2 py-0.5 rounded-full bg-green-900 text-green-300';
    badge.textContent = log.outcome;
    outcomeCell.appendChild(badge);
    tr.appendChild(outcomeCell);

    tr.appendChild(td(log.deny_reason || '—', 'text-xs text-gray-400'));
    tr.appendChild(td(log.detail || '—', 'text-xs text-gray-300 max-w-xs truncate'));
    tr.appendChild(td(log.resource_id || '—', 'font-mono text-xs text-gray-500 truncate max-w-32'));

    tbody.appendChild(tr);
  });

  // Pagination info
  const start = page * LIMIT + 1;
  const end = Math.min(start + logs.length - 1, total);
  const info = document.getElementById('page-info');
  info.textContent = total
    ? `Showing ${start}–${end} of ${total} entries`
    : 'No entries';

  document.getElementById('prev-btn').disabled = (page === 0);
  document.getElementById('next-btn').disabled = (end >= total);
}

document.getElementById('audit-search-btn').addEventListener('click', () => {
  page = 0;
  loadAudit();
});

document.getElementById('prev-btn').addEventListener('click', () => {
  if (page > 0) { page--; loadAudit(); }
});

document.getElementById('next-btn').addEventListener('click', () => {
  page++;
  loadAudit();
});

// ── Verify chain ───────────────────────────────────────────────────────────

document.getElementById('verify-btn').addEventListener('click', async () => {
  const r = await fetch('/api/audit/verify', { credentials: 'same-origin' });
  const d = await r.json();
  const banner = document.getElementById('chain-banner');
  banner.classList.remove('hidden', 'bg-green-950', 'border-green-700', 'text-green-300',
    'bg-red-950', 'border-red-700', 'text-red-300');

  if (d.valid) {
    banner.className = 'p-4 rounded-xl border text-sm font-medium bg-green-950 border-green-700 text-green-300';
    banner.textContent = `✔ Chain verified — ${d.totalRows} entries, all hashes valid.`;
  } else {
    banner.className = 'p-4 rounded-xl border text-sm font-medium bg-red-950 border-red-700 text-red-300';
    banner.textContent = `✘ Chain BROKEN at row #${d.brokenAt} (out of ${d.totalRows} entries). Possible tampering detected.`;
  }
});

// ── Suspicious ─────────────────────────────────────────────────────────────

async function loadSuspicious() {
  const r = await fetch('/api/audit/suspicious', { credentials: 'same-origin' });
  const container = document.getElementById('suspicious-container');
  container.textContent = '';

  if (!r.ok) {
    const p = document.createElement('p');
    p.textContent = 'Failed to load suspicious activity.';
    p.className = 'text-red-400 text-sm col-span-3';
    container.appendChild(p);
    return;
  }

  const { repeatedDenials, postRevocation, disabledAttempts } = await r.json();

  container.appendChild(buildSuspiciousCard(
    '🚨 Repeated Denials (24h)',
    repeatedDenials,
    (item) => `${item.username || ('ID:' + item.actor_id)} — ${item.deny_count} denials`,
    'border-red-800'
  ));

  container.appendChild(buildSuspiciousCard(
    '🔒 Post-Revocation Attempts',
    postRevocation,
    (item) => `${item.actor_username || ('ID:' + item.actor_id)} → ${item.resource_id?.slice(0, 8) + '…'}`,
    'border-yellow-800'
  ));

  container.appendChild(buildSuspiciousCard(
    '🚫 Disabled User Attempts',
    disabledAttempts,
    (item) => `${item.actor_username || ('ID:' + item.actor_id)}`,
    'border-orange-800'
  ));
}

function buildSuspiciousCard(title, items, labelFn, borderClass) {
  const card = document.createElement('div');
  card.className = `bg-gray-900 border ${borderClass} rounded-2xl p-4 fade-in flex flex-col justify-start h-full`;

  const heading = document.createElement('h3');
  heading.className = 'text-sm font-semibold text-white mb-3';
  heading.textContent = title; // textContent
  card.appendChild(heading);

  if (!items.length) {
    const p = document.createElement('p');
    p.className = 'text-gray-500 text-xs';
    p.textContent = 'None detected.';
    card.appendChild(p);
    return card;
  }

  const ul = document.createElement('ul');
  ul.className = 'space-y-1.5';
  items.slice(0, 10).forEach(item => {
    const li = document.createElement('li');
    li.className = 'text-xs text-gray-300 flex items-start gap-1.5';
    const dot = document.createElement('span');
    dot.className = 'mt-1 shrink-0 w-1.5 h-1.5 rounded-full bg-red-500';
    const text = document.createElement('span');
    text.textContent = labelFn(item); // textContent — labelFn returns plain string
    li.appendChild(dot);
    li.appendChild(text);
    ul.appendChild(li);
  });
  card.appendChild(ul);

  if (items.length > 10) {
    const more = document.createElement('p');
    more.className = 'text-xs text-gray-500 mt-2';
    more.textContent = `…and ${items.length - 10} more`;
    card.appendChild(more);
  }

  return card;
}

document.getElementById('refresh-suspicious-btn').addEventListener('click', loadSuspicious);

// ── Logout ─────────────────────────────────────────────────────────────────

document.getElementById('logout-btn').addEventListener('click', async () => {
  const token = await getCsrfToken();
  await fetch('/api/logout', {
    method: 'POST',
    headers: { 'x-csrf-token': token },
    credentials: 'same-origin',
  });
  sessionStorage.removeItem('csrfToken');
  window.location.replace('/');
});

// ── Bootstrap ──────────────────────────────────────────────────────────────

(async function init() {
  if (!(await guardAdmin())) return;
  loadAudit();
  loadSuspicious();
}());
