// public/js/login.js
// SECURITY: No innerHTML with user data — textContent only throughout

(function () {
  'use strict';

  const form       = document.getElementById('login-form');
  const submitBtn  = document.getElementById('submit-btn');
  const errorBanner = document.getElementById('error-banner');
  const errorText  = document.getElementById('error-text');

  function showError(msg) {
    // textContent — never innerHTML — safe against XSS
    errorText.textContent = msg;
    errorBanner.classList.remove('hidden');
  }

  function hideError() {
    errorBanner.classList.add('hidden');
    errorText.textContent = '';
  }

  // If already authenticated, skip login
  fetch('/api/me', { credentials: 'same-origin' })
    .then(r => r.ok ? r.json() : null)
    .then(data => {
      if (data?.user) {
        window.location.replace(
          data.user.role === 'admin' ? '/admin.html' : '/dashboard.html'
        );
      }
    })
    .catch(() => {});

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    hideError();
    submitBtn.disabled = true;
    submitBtn.textContent = 'Signing in…';

    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;

    try {
      const res = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
        credentials: 'same-origin',
      });

      const data = await res.json();

      if (!res.ok) {
        showError(data.error || 'Login failed');
        return;
      }

      // Store CSRF token in sessionStorage (cleared on tab close)
      // Not in localStorage; not in a readable cookie
      sessionStorage.setItem('csrfToken', data.csrfToken);

      window.location.replace(
        data.user.role === 'admin' ? '/admin.html' : '/dashboard.html'
      );
    } catch {
      showError('Network error — please try again.');
    } finally {
      submitBtn.disabled = false;
      submitBtn.textContent = 'Sign In';
    }
  });
}());
