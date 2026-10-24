// public/js/login.js
// SECURITY: All dynamic text uses textContent exclusively. Never innerHTML.
'use strict';

(function () {
  // ── Elements ───────────────────────────────────────────────────────────────
  const introOverlay   = document.getElementById('intro-overlay');
  const tabSignIn      = document.getElementById('tab-signin');
  const tabRegister    = document.getElementById('tab-register');
  const panelSignIn    = document.getElementById('panel-signin');
  const panelRegister  = document.getElementById('panel-register');

  const errorBanner    = document.getElementById('error-banner');
  const errorText      = document.getElementById('error-text');
  const successBanner  = document.getElementById('success-banner');
  const successText    = document.getElementById('success-text');

  const signInForm     = document.getElementById('signin-form');
  const signInUserEl   = document.getElementById('signin-username');
  const signInPassEl   = document.getElementById('signin-password');
  const signInBtn      = document.getElementById('signin-submit-btn');

  const demoAdminBtn   = document.getElementById('demo-admin-btn');
  const demoOwnerBtn   = document.getElementById('demo-owner-btn');
  const demoViewerBtn  = document.getElementById('demo-viewer-btn');

  const regForm        = document.getElementById('register-form');
  const regFullNameEl  = document.getElementById('reg-fullname');
  const regUsernameEl  = document.getElementById('reg-username');
  const regEmailEl     = document.getElementById('reg-email');
  const regPassEl      = document.getElementById('reg-password');
  const regConfirmEl   = document.getElementById('reg-confirm-password');
  const regBtn         = document.getElementById('register-submit-btn');

  const strengthSection = document.getElementById('strength-section');
  const strengthLabel   = document.getElementById('strength-label-text');
  const strengthBar     = document.getElementById('strength-meter-bar');

  const ruleLength     = document.getElementById('rule-length');
  const ruleUpper      = document.getElementById('rule-upper');
  const ruleLower      = document.getElementById('rule-lower');
  const ruleNumber     = document.getElementById('rule-number');
  const ruleSpecial    = document.getElementById('rule-special');

  const iconLength     = document.getElementById('icon-length');
  const iconUpper      = document.getElementById('icon-upper');
  const iconLower      = document.getElementById('icon-lower');
  const iconNumber     = document.getElementById('icon-number');
  const iconSpecial    = document.getElementById('icon-special');

  const confirmMatchEl = document.getElementById('confirm-match-status');
  const canvas         = document.getElementById('nodes-canvas');

  // In-memory demo credentials only — NEVER written to localStorage
  const DEMO_CREDENTIALS = {
    admin:  { u: 'admin',   p: 'Admin1234!' },
    owner:  { u: 'owner1',  p: 'Owner1234!' },
    viewer: { u: 'viewer1', p: 'Viewer123!' },
  };

  // ── Error & Success Helpers (textContent only) ─────────────────────────────
  function showError(msg) {
    if (successBanner) successBanner.style.display = 'none';
    if (errorText) errorText.textContent = msg;
    if (errorBanner) errorBanner.style.display = 'flex';
  }

  function hideError() {
    if (errorBanner) errorBanner.style.display = 'none';
    if (errorText) errorText.textContent = '';
  }

  function showSuccess(msg) {
    hideError();
    if (successText) successText.textContent = msg;
    if (successBanner) successBanner.style.display = 'flex';
  }

  function hideSuccess() {
    if (successBanner) successBanner.style.display = 'none';
    if (successText) successText.textContent = '';
  }

  // ── 5-Second Intro on First Load Only (Rule 3) ─────────────────────────────
  function setupIntro() {
    if (!introOverlay) return;

    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const introAlreadySeen = sessionStorage.getItem('tv_intro_seen');

    if (prefersReducedMotion || introAlreadySeen) {
      introOverlay.style.display = 'none';
      return;
    }

    sessionStorage.setItem('tv_intro_seen', '1');

    let dismissed = false;
    function dismissIntro() {
      if (dismissed) return;
      dismissed = true;
      introOverlay.classList.add('fade-out');
      setTimeout(() => {
        introOverlay.style.display = 'none';
      }, 850);
    }

    // Auto-dismiss after 5 seconds
    const timer = setTimeout(dismissIntro, 5000);

    // Skippable by clicking anywhere
    introOverlay.addEventListener('click', () => {
      clearTimeout(timer);
      dismissIntro();
    });
  }

  // ── Connected Nodes Animated Canvas (Rule 4) ───────────────────────────────
  function setupCanvasAnimation() {
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let width = 0;
    let height = 0;
    let animationFrameId = null;

    function resize() {
      const parent = canvas.parentElement;
      if (!parent) return;
      width = canvas.width = parent.clientWidth;
      height = canvas.height = parent.clientHeight;
    }

    resize();
    window.addEventListener('resize', resize);

    const nodeCount = 38;
    const maxDist = 110;
    const nodes = [];

    for (let i = 0; i < nodeCount; i++) {
      nodes.push({
        x: Math.random() * (width || 400),
        y: Math.random() * (height || 600),
        vx: (Math.random() - 0.5) * 0.55,
        vy: (Math.random() - 0.5) * 0.55,
        radius: Math.random() * 1.5 + 1.2,
      });
    }

    function render() {
      if (width === 0 || height === 0) {
        animationFrameId = requestAnimationFrame(render);
        return;
      }

      ctx.clearRect(0, 0, width, height);

      // Update positions
      for (let i = 0; i < nodes.length; i++) {
        const n = nodes[i];
        n.x += n.vx;
        n.y += n.vy;

        if (n.x <= 0 || n.x >= width) n.vx *= -1;
        if (n.y <= 0 || n.y >= height) n.vy *= -1;
      }

      // Draw lines
      ctx.lineWidth = 0.8;
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const dx = nodes[i].x - nodes[j].x;
          const dy = nodes[i].y - nodes[j].y;
          const dist = Math.hypot(dx, dy);

          if (dist < maxDist) {
            const alpha = (1 - dist / maxDist) * 0.22;
            ctx.strokeStyle = `rgba(202, 228, 219, ${alpha})`;
            ctx.beginPath();
            ctx.moveTo(nodes[i].x, nodes[i].y);
            ctx.lineTo(nodes[j].x, nodes[j].y);
            ctx.stroke();
          }
        }
      }

      // Draw nodes
      for (let i = 0; i < nodes.length; i++) {
        const n = nodes[i];
        ctx.fillStyle = i % 4 === 0 ? 'rgba(220, 174, 29, 0.7)' : 'rgba(122, 157, 150, 0.75)';
        ctx.beginPath();
        ctx.arc(n.x, n.y, n.radius, 0, Math.PI * 2);
        ctx.fill();
      }

      animationFrameId = requestAnimationFrame(render);
    }

    render();

    // Pause when tab is inactive to preserve resources
    document.addEventListener('visibilitychange', () => {
      if (document.hidden) {
        if (animationFrameId) cancelAnimationFrame(animationFrameId);
      } else {
        render();
      }
    });
  }

  // ── Tab Switching (Rule 5) ─────────────────────────────────────────────────
  function switchTab(target) {
    hideError();
    hideSuccess();

    if (target === 'signin') {
      tabSignIn.classList.add('active');
      tabSignIn.setAttribute('aria-selected', 'true');
      tabRegister.classList.remove('active');
      tabRegister.setAttribute('aria-selected', 'false');

      panelSignIn.style.display = 'block';
      panelRegister.style.display = 'none';
      if (signInUserEl) signInUserEl.focus();
    } else {
      tabRegister.classList.add('active');
      tabRegister.setAttribute('aria-selected', 'true');
      tabSignIn.classList.remove('active');
      tabSignIn.setAttribute('aria-selected', 'false');

      panelRegister.style.display = 'block';
      panelSignIn.style.display = 'none';
      if (regFullNameEl) regFullNameEl.focus();
    }
  }

  tabSignIn.addEventListener('click', () => switchTab('signin'));
  tabRegister.addEventListener('click', () => switchTab('register'));

  // ── Demo Access Handlers (Rule 6) ──────────────────────────────────────────
  function applyDemoLogin(role) {
    const creds = DEMO_CREDENTIALS[role];
    if (!creds) return;

    switchTab('signin');
    signInUserEl.value = creds.u;
    signInPassEl.value = creds.p;
    hideError();
    hideSuccess();
    signInBtn.focus();
  }

  demoAdminBtn.addEventListener('click', () => applyDemoLogin('admin'));
  demoOwnerBtn.addEventListener('click', () => applyDemoLogin('owner'));
  demoViewerBtn.addEventListener('click', () => applyDemoLogin('viewer'));

  // ── Live Password Requirements & Strength (Rule 5) ────────────────────────
  function validatePasswordCriteria(pwd) {
    return {
      length:  pwd.length >= 8,
      upper:   /[A-Z]/.test(pwd),
      lower:   /[a-z]/.test(pwd),
      number:  /[0-9]/.test(pwd),
      special: /[^A-Za-z0-9]/.test(pwd),
    };
  }

  function updateChecklistUI(results) {
    function setItem(el, iconEl, ok) {
      if (!el || !iconEl) return;
      if (ok) {
        el.classList.add('met');
        iconEl.textContent = '●';
      } else {
        el.classList.remove('met');
        iconEl.textContent = '○';
      }
    }

    setItem(ruleLength, iconLength, results.length);
    setItem(ruleUpper, iconUpper, results.upper);
    setItem(ruleLower, iconLower, results.lower);
    setItem(ruleNumber, iconNumber, results.number);
    setItem(ruleSpecial, iconSpecial, results.special);
  }

  function updateStrengthUI(pwd) {
    if (!strengthSection || !strengthLabel || !strengthBar) return;

    if (!pwd) {
      strengthSection.className = 'strength-section';
      strengthLabel.textContent = '—';
      strengthBar.style.width = '0%';
      return;
    }

    const results = validatePasswordCriteria(pwd);
    updateChecklistUI(results);

    const score = Object.values(results).filter(Boolean).length;

    strengthSection.classList.remove('strength-weak', 'strength-medium', 'strength-strong');

    if (score <= 2) {
      strengthSection.classList.add('strength-weak');
      strengthLabel.textContent = 'Weak';
    } else if (score <= 4) {
      strengthSection.classList.add('strength-medium');
      strengthLabel.textContent = 'Medium';
    } else {
      strengthSection.classList.add('strength-strong');
      strengthLabel.textContent = 'Strong';
    }
  }

  function updateConfirmMatchUI() {
    if (!confirmMatchEl || !regConfirmEl) return;
    const p1 = regPassEl.value;
    const p2 = regConfirmEl.value;

    if (!p2) {
      confirmMatchEl.style.display = 'none';
      confirmMatchEl.textContent = '';
      return;
    }

    confirmMatchEl.style.display = 'block';
    if (p1 === p2) {
      confirmMatchEl.className = 'confirm-match-hint matched';
      confirmMatchEl.textContent = '✓ Passwords match';
    } else {
      confirmMatchEl.className = 'confirm-match-hint mismatched';
      confirmMatchEl.textContent = '✕ Passwords do not match';
    }
  }

  regPassEl.addEventListener('input', () => {
    updateStrengthUI(regPassEl.value);
    updateConfirmMatchUI();
  });

  regConfirmEl.addEventListener('input', updateConfirmMatchUI);

  // ── Existing Session Check ────────────────────────────────────────────────
  fetch('/api/me', { credentials: 'same-origin' })
    .then((r) => (r.ok ? r.json() : null))
    .then((data) => {
      if (data?.user) {
        window.location.replace(
          data.user.role === 'admin' ? '/admin.html' : '/dashboard.html'
        );
      }
    })
    .catch(() => {});

  // ── Sign In Form Submission (Rule 7) ───────────────────────────────────────
  signInForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    hideError();
    hideSuccess();

    const username = signInUserEl.value.trim();
    const password = signInPassEl.value;

    if (!username || !password) {
      // Failed login always says "Invalid username or password." with the same response regardless of cause (Rule 7)
      showError('Invalid username or password.');
      return;
    }

    signInBtn.disabled = true;
    signInBtn.textContent = 'Signing in…';

    try {
      const res = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
        credentials: 'same-origin',
      });

      const data = await res.json().catch(() => ({}));

      if (!res.ok) {
        // Rule 7: Failed login always says "Invalid username or password." with the same response regardless of cause
        showError('Invalid username or password.');
        return;
      }

      sessionStorage.setItem('csrfToken', data.csrfToken);

      window.location.replace(
        data.user.role === 'admin' ? '/admin.html' : '/dashboard.html'
      );
    } catch {
      // Network or unexpected failure — still unified error message
      showError('Invalid username or password.');
    } finally {
      signInBtn.disabled = false;
      signInBtn.textContent = 'Sign In';
    }
  });

  // ── Create Account Form Submission (Rule 5) ────────────────────────────────
  regForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    hideError();
    hideSuccess();

    const fullName = regFullNameEl.value.trim();
    const username = regUsernameEl.value.trim();
    const email    = regEmailEl.value.trim();
    const password = regPassEl.value;
    const confirm  = regConfirmEl.value;

    if (!fullName || !username || !email || !password || !confirm) {
      showError('All fields are required.');
      return;
    }

    if (password !== confirm) {
      showError('Passwords do not match.');
      return;
    }

    const criteria = validatePasswordCriteria(password);
    const score = Object.values(criteria).filter(Boolean).length;
    if (score < 5) {
      showError('Password does not meet all complexity requirements.');
      return;
    }

    regBtn.disabled = true;
    regBtn.textContent = 'Creating Account…';

    try {
      // NO role field sent: server always creates accounts as 'viewer'
      const res = await fetch('/api/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ fullName, username, email, password }),
        credentials: 'same-origin',
      });

      const data = await res.json().catch(() => ({}));

      if (!res.ok) {
        showError(data.error || 'Failed to create account.');
        return;
      }

      // Switch to Sign In tab and pre-fill username
      switchTab('signin');
      signInUserEl.value = username;
      signInPassEl.value = '';
      showSuccess('Account created successfully. Please sign in.');
    } catch {
      showError('Network error while creating account. Please try again.');
    } finally {
      regBtn.disabled = false;
      regBtn.textContent = 'Create Account';
    }
  });

  // ── Initialize ─────────────────────────────────────────────────────────────
  setupIntro();
  setupCanvasAnimation();
})();
