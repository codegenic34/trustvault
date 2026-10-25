// public/js/login.js
// SECURITY: All dynamic text uses textContent exclusively. Never innerHTML.
'use strict';

(function () {
  // ── Elements ───────────────────────────────────────────────────────────────
  const tabSignIn = document.getElementById('tab-signin');
  const tabRegister = document.getElementById('tab-register');
  const panelSignIn = document.getElementById('panel-signin');
  const panelRegister = document.getElementById('panel-register');

  const errorBanner = document.getElementById('error-banner');
  const errorText = document.getElementById('error-text');
  const successBanner = document.getElementById('success-banner');
  const successText = document.getElementById('success-text');

  const signInForm = document.getElementById('signin-form');
  const signInUserEl = document.getElementById('signin-username');
  const signInPassEl = document.getElementById('signin-password');
  const signInBtn = document.getElementById('signin-submit-btn');

  const demoAdminBtn = document.getElementById('demo-admin-btn');
  const demoOwnerBtn = document.getElementById('demo-owner-btn');
  const demoViewerBtn = document.getElementById('demo-viewer-btn');

  const regForm = document.getElementById('register-form');
  const regFullNameEl = document.getElementById('reg-fullname');
  const regUsernameEl = document.getElementById('reg-username');
  const regEmailEl = document.getElementById('reg-email');
  const regPassEl = document.getElementById('reg-password');
  const regConfirmEl = document.getElementById('reg-confirm-password');
  const regBtn = document.getElementById('register-submit-btn');

  const strengthSection = document.getElementById('strength-section');
  const strengthLabel = document.getElementById('strength-label-text');
  const strengthBar = document.getElementById('strength-meter-bar');

  const ruleLength = document.getElementById('rule-length');
  const ruleUpper = document.getElementById('rule-upper');
  const ruleLower = document.getElementById('rule-lower');
  const ruleNumber = document.getElementById('rule-number');
  const ruleSpecial = document.getElementById('rule-special');

  const iconLength = document.getElementById('icon-length');
  const iconUpper = document.getElementById('icon-upper');
  const iconLower = document.getElementById('icon-lower');
  const iconNumber = document.getElementById('icon-number');
  const iconSpecial = document.getElementById('icon-special');

  const confirmMatchEl = document.getElementById('confirm-match-status');

  // In-memory demo credentials only — NEVER written to localStorage
  const DEMO_CREDENTIALS = {
    admin: { u: 'admin', p: 'Admin1234!' },
    owner: { u: 'owner1', p: 'Owner1234!' },
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



  // ── Connected Nodes Animated Canvas with Interactive Physics & Sonar (Rule 4) ──
  function setupCanvasAnimation() {
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let width = 0;
    let height = 0;
    let animationFrameId = null;

    // Mouse tracking for interactive constellation attraction
    const mouse = { x: -1000, y: -1000, active: false };

    function resize() {
      width = canvas.width = window.innerWidth;
      height = canvas.height = window.innerHeight;
    }

    resize();
    window.addEventListener('resize', resize);

    window.addEventListener('mousemove', (e) => {
      mouse.x = e.clientX;
      mouse.y = e.clientY;
      mouse.active = true;
    });

    window.addEventListener('mouseleave', () => {
      mouse.active = false;
      mouse.x = -1000;
      mouse.y = -1000;
    });

    // 1. Constellation Nodes
    const nodeCount = 75;
    const maxDist = 135;
    const mouseMaxDist = 175;
    const nodes = [];

    for (let i = 0; i < nodeCount; i++) {
      nodes.push({
        x: Math.random() * (width || window.innerWidth || 1200),
        y: Math.random() * (height || window.innerHeight || 800),
        vx: (Math.random() - 0.5) * 0.6,
        vy: (Math.random() - 0.5) * 0.6,
        radius: Math.random() * 1.8 + 1.2,
        baseColor: i % 5 === 0 ? '#DCAE1D' : (i % 2 === 0 ? '#FFFFFF' : '#CAE4DB'),
        pulse: Math.random() * Math.PI,
        flash: 0,
      });
    }

    // 2. Ambient Floating Micro-Sparks
    const sparkCount = 45;
    const sparks = [];
    for (let i = 0; i < sparkCount; i++) {
      sparks.push({
        x: Math.random() * (width || window.innerWidth || 1200),
        y: Math.random() * (height || window.innerHeight || 800),
        vy: -0.2 - Math.random() * 0.35,
        vx: (Math.random() - 0.5) * 0.2,
        size: Math.random() * 1.2 + 0.4,
        alpha: Math.random() * 0.5 + 0.2,
      });
    }

    // 3. Vault Sonar Waves
    const sonarRings = [];
    let lastRingTime = performance.now();

    function render(currentTime) {
      if (width === 0 || height === 0) {
        animationFrameId = requestAnimationFrame(render);
        return;
      }

      ctx.clearRect(0, 0, width, height);

      // Periodically trigger a Sonar Wave
      if (currentTime - lastRingTime > 4000) {
        lastRingTime = currentTime;
        sonarRings.push({
          x: width * 0.5,
          y: height * 0.45,
          radius: 10,
          maxRadius: Math.max(width, height) * 0.9,
          alpha: 0.4,
        });
      }

      // Draw and expand sonar waves
      for (let i = sonarRings.length - 1; i >= 0; i--) {
        const ring = sonarRings[i];
        ring.radius += 1.8;
        ring.alpha *= 0.985;

        ctx.beginPath();
        ctx.arc(ring.x, ring.y, ring.radius, 0, Math.PI * 2);
        ctx.strokeStyle = `rgba(255, 255, 255, ${ring.alpha * 0.35})`;
        ctx.lineWidth = 1.5;
        ctx.stroke();

        // Illuminate nodes hit by sonar wave
        for (let j = 0; j < nodes.length; j++) {
          const n = nodes[j];
          const distToCenter = Math.hypot(n.x - ring.x, n.y - ring.y);
          if (Math.abs(distToCenter - ring.radius) < 15) {
            n.flash = 1.0;
          }
        }

        if (ring.radius >= ring.maxRadius || ring.alpha < 0.01) {
          sonarRings.splice(i, 1);
        }
      }

      // Render Ambient Micro-Sparks
      for (let i = 0; i < sparks.length; i++) {
        const sp = sparks[i];
        sp.y += sp.vy;
        sp.x += sp.vx;

        if (sp.y < 0) {
          sp.y = height + 5;
          sp.x = Math.random() * width;
        }

        ctx.fillStyle = `rgba(255, 255, 255, ${sp.alpha * 0.4})`;
        ctx.beginPath();
        ctx.arc(sp.x, sp.y, sp.size, 0, Math.PI * 2);
        ctx.fill();
      }

      // Update Node Positions & Interactive Mouse Spring
      for (let i = 0; i < nodes.length; i++) {
        const n = nodes[i];
        n.pulse += 0.03;
        if (n.flash > 0) n.flash -= 0.02;

        n.x += n.vx;
        n.y += n.vy;

        // Bounce off canvas boundaries
        if (n.x <= 0 || n.x >= width) n.vx *= -1;
        if (n.y <= 0 || n.y >= height) n.vy *= -1;

        // Gentle interactive attraction toward cursor
        if (mouse.active) {
          const dx = mouse.x - n.x;
          const dy = mouse.y - n.y;
          const dist = Math.hypot(dx, dy);

          if (dist < mouseMaxDist) {
            const force = (1 - dist / mouseMaxDist) * 0.4;
            n.x += (dx / dist) * force;
            n.y += (dy / dist) * force;
          }
        }
      }

      // Draw Inter-Node Constellation Lines
      ctx.lineWidth = 0.85;
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const dx = nodes[i].x - nodes[j].x;
          const dy = nodes[i].y - nodes[j].y;
          const dist = Math.hypot(dx, dy);

          if (dist < maxDist) {
            const alpha = (1 - dist / maxDist) * 0.28;
            ctx.strokeStyle = `rgba(255, 255, 255, ${alpha})`;
            ctx.beginPath();
            ctx.moveTo(nodes[i].x, nodes[i].y);
            ctx.lineTo(nodes[j].x, nodes[j].y);
            ctx.stroke();
          }
        }
      }

      // Draw Interactive Mouse Connection Lines
      if (mouse.active) {
        for (let i = 0; i < nodes.length; i++) {
          const n = nodes[i];
          const dx = mouse.x - n.x;
          const dy = mouse.y - n.y;
          const dist = Math.hypot(dx, dy);

          if (dist < mouseMaxDist) {
            const alpha = (1 - dist / mouseMaxDist) * 0.55;
            ctx.strokeStyle = `rgba(255, 255, 255, ${alpha})`;
            ctx.lineWidth = 1.2;
            ctx.beginPath();
            ctx.moveTo(n.x, n.y);
            ctx.lineTo(mouse.x, mouse.y);
            ctx.stroke();
          }
        }
      }

      // Draw Glowing Nodes
      for (let i = 0; i < nodes.length; i++) {
        const n = nodes[i];
        const pulseFactor = 0.85 + Math.sin(n.pulse) * 0.2;
        const currentRadius = n.radius * pulseFactor;

        // Radiant glow
        if (n.flash > 0) {
          ctx.beginPath();
          ctx.arc(n.x, n.y, currentRadius * 3, 0, Math.PI * 2);
          ctx.fillStyle = `rgba(255, 255, 255, ${n.flash * 0.5})`;
          ctx.fill();
        }

        ctx.beginPath();
        ctx.arc(n.x, n.y, currentRadius, 0, Math.PI * 2);
        ctx.fillStyle = n.flash > 0 ? '#FFFFFF' : n.baseColor;
        ctx.shadowColor = '#FFFFFF';
        ctx.shadowBlur = 6;
        ctx.fill();
        ctx.shadowBlur = 0; // reset
      }

      animationFrameId = requestAnimationFrame(render);
    }

    animationFrameId = requestAnimationFrame(render);

    // Pause when tab is inactive to preserve CPU
    document.addEventListener('visibilitychange', () => {
      if (document.hidden) {
        if (animationFrameId) cancelAnimationFrame(animationFrameId);
      } else {
        lastRingTime = performance.now();
        animationFrameId = requestAnimationFrame(render);
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

  // ── Demo Access Handlers (Rule 6 & User Request) ───────────────────────────
  function applyDemoLogin(role) {
    const creds = DEMO_CREDENTIALS[role];
    if (!creds) return;

    switchTab('signin');
    // ONLY username and password get entered
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
      length: pwd.length >= 8,
      upper: /[A-Z]/.test(pwd),
      lower: /[a-z]/.test(pwd),
      number: /[0-9]/.test(pwd),
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
    .catch(() => { });

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

      const targetUrl = data.user.role === 'admin' ? '/admin.html' : '/dashboard.html';
      window.location.replace(targetUrl);
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
    const email = regEmailEl.value.trim();
    const password = regPassEl.value;
    const confirm = regConfirmEl.value;

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

})();
