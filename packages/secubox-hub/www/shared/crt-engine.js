/**
 * CRT ENGINE v1.0 — SecuBox Edition
 * ASR-33 Teletype simulation · VT100 cursor · PDP-1 boot
 * Baudot timing: 110 baud = ~10 chars/sec = 100ms/char
 * With mechanical jitter: ±30ms random variance per keystroke
 */

const CRT = (() => {

  /* ── TIMING ── */
  const BAUD_ASR33 = 100;   // ms per char at 110 baud
  const BAUD_VT100 = 12;    // ms per char at 9600 baud (fast mode)
  const JITTER     = 0.35;  // ±35% mechanical jitter (ASR-33 is old)

  function jitter(base) {
    return base * (1 - JITTER/2 + Math.random() * JITTER);
  }

  /* ── TYPEWRITER ── */
  async function type(el, text, opts = {}) {
    const {
      speed    = BAUD_ASR33,
      delay    = 0,
      onChar   = null,
      cursor   = true,
      preserve = false,
    } = opts;

    if (delay > 0) await sleep(delay);
    if (!preserve) el.textContent = '';

    // add cursor placeholder
    const cur = cursor ? makeCursor() : null;
    if (cur) el.appendChild(cur);

    for (const ch of text) {
      const span = document.createElement('span');
      span.textContent = ch;
      if (cur) el.insertBefore(span, cur);
      else el.appendChild(span);
      if (onChar) onChar(ch);
      // Space is faster (no mechanical key travel)
      const t = ch === ' ' ? jitter(speed * 0.6) : jitter(speed);
      await sleep(t);
    }

    if (cur && !cursor) cur.remove();
    return el;
  }

  /* ── LINE-BY-LINE TYPEWRITER ── */
  async function typeLines(container, lines, opts = {}) {
    const { speed = BAUD_ASR33, lineDelay = 200, initialDelay = 0 } = opts;
    if (initialDelay > 0) await sleep(initialDelay);

    for (const line of lines) {
      const el = document.createElement('div');
      el.className = 'crt-line';
      container.appendChild(el);
      await type(el, line, { speed, cursor: false });
      await sleep(lineDelay + jitter(80));
    }
  }

  /* ── BOOT SEQUENCE ── */
  async function boot(container, lines, opts = {}) {
    const { speed = BAUD_VT100, baseDelay = 60, onComplete = null } = opts;
    container.innerHTML = '';

    for (const line of lines) {
      const row = document.createElement('div');
      row.className = 'boot-line';
      container.appendChild(row);

      if (line.startsWith('---')) {
        // separator — instant
        row.innerHTML = '<span class="p-ghost">' + line + '</span>';
        await sleep(baseDelay);
      } else if (line.includes('...')) {
        // progress line — type dots live
        const parts = line.split('...');
        const pre = parts[0];
        const dots = '...';
        const post = parts[parts.length - 1];

        row.innerHTML = '<span class="p-dim">' + pre + '</span>';
        await sleep(jitter(baseDelay));

        // animate dots
        const dotSpan = document.createElement('span');
        dotSpan.className = 'p-ghost';
        dotSpan.textContent = '';
        row.appendChild(dotSpan);

        const dotCount = (line.match(/\./g) || []).length;
        for (let i = 0; i < dotCount; i++) {
          dotSpan.textContent += '.';
          await sleep(jitter(30));
        }

        if (post) {
          const postSpan = document.createElement('span');
          postSpan.className = post.includes('OK') ? 'p-on' :
                               post.includes('FAIL') ? 'p-amber' : 'p-dim';
          postSpan.textContent = post;
          row.appendChild(postSpan);
        }
        await sleep(jitter(baseDelay * 0.5));

      } else if (line === 'READY.' || line === 'READY') {
        row.innerHTML = '<span class="p-hot">' + line + '</span>';
        await sleep(200);
      } else {
        // normal line — type it
        row.innerHTML = '';
        const span = document.createElement('span');
        span.className = line.startsWith('**') ? 'p-on' :
                         line.startsWith('!!') ? 'p-amber' : 'p-dim';
        span.textContent = line.replace(/^\*\*|^!!/,'');
        row.appendChild(span);
        await sleep(jitter(baseDelay * 0.8));
      }
    }

    if (onComplete) onComplete();
  }

  /* ── CURSOR ── */
  function makeCursor() {
    const c = document.createElement('span');
    c.className = 'cursor-inline';
    c.setAttribute('aria-hidden', 'true');
    return c;
  }

  /* ── LIVE CLOCK ── */
  function startClock(el, opts = {}) {
    const { format = '24h', showDate = false } = opts;
    function tick() {
      const d = new Date();
      const H = pad(d.getHours());
      const M = pad(d.getMinutes());
      const S = pad(d.getSeconds());
      const dateStr = showDate
        ? `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())} `
        : '';
      el.textContent = dateStr + H + ':' + M + ':' + S;
    }
    tick();
    return setInterval(tick, 1000);
  }

  /* ── UPTIME ── */
  function startUptime(el) {
    const start = Date.now();
    function tick() {
      const s = Math.floor((Date.now() - start) / 1000);
      const h = Math.floor(s / 3600);
      const m = Math.floor((s % 3600) / 60);
      const sec = s % 60;
      el.textContent = pad(h) + ':' + pad(m) + ':' + pad(sec);
    }
    tick();
    return setInterval(tick, 1000);
  }

  /* ── RANDOM SCANLINE GLITCH ── */
  function startGlitch(el, opts = {}) {
    const { interval = 8000, duration = 80 } = opts;
    function glitch() {
      el.style.transform = `translateY(${(Math.random()-0.5)*2}px)`;
      el.style.filter = `brightness(${1.05 + Math.random()*0.1})`;
      setTimeout(() => {
        el.style.transform = '';
        el.style.filter = '';
      }, duration);
      // schedule next
      setTimeout(glitch, interval + (Math.random() - 0.5) * interval * 0.6);
    }
    setTimeout(glitch, interval);
  }

  /* ── SCROLL REVEAL ── */
  function initReveal(selector = '.crt-reveal') {
    const io = new IntersectionObserver(entries => {
      entries.forEach(e => {
        if (e.isIntersecting) {
          e.target.classList.add('visible');
          io.unobserve(e.target);
        }
      });
    }, { threshold: 0.1 });
    document.querySelectorAll(selector).forEach(el => io.observe(el));
  }

  /* ── BAR ANIMATE ── */
  function animateBars() {
    document.querySelectorAll('[data-bar]').forEach(fill => {
      const w = fill.getAttribute('data-bar');
      setTimeout(() => { fill.style.width = w; }, 200);
    });
  }

  /* ── KEYBOARD BEEP (Web Audio) ── */
  let audioCtx = null;
  function initAudio() {
    try { audioCtx = new (window.AudioContext || window.webkitAudioContext)(); }
    catch(e) { audioCtx = null; }
  }
  function beep(freq = 800, dur = 12, vol = 0.04) {
    if (!audioCtx) return;
    try {
      const osc = audioCtx.createOscillator();
      const gain = audioCtx.createGain();
      osc.connect(gain); gain.connect(audioCtx.destination);
      osc.type = 'square';
      osc.frequency.value = freq;
      gain.gain.setValueAtTime(vol, audioCtx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.0001, audioCtx.currentTime + dur/1000);
      osc.start(audioCtx.currentTime);
      osc.stop(audioCtx.currentTime + dur/1000);
    } catch(e) {}
  }
  function keyClick() { beep(1100, 8, 0.03); }
  function lineReturn() { beep(600, 30, 0.05); }
  function bell() { beep(800, 200, 0.08); }

  /* ── TOAST NOTIFICATIONS ── */
  let toastContainer = null;

  function initToasts() {
    if (!toastContainer) {
      toastContainer = document.createElement('div');
      toastContainer.id = 'crt-toasts';
      toastContainer.style.cssText = `
        position: fixed; bottom: 20px; right: 20px; z-index: 10001;
        display: flex; flex-direction: column; gap: 10px;
      `;
      document.body.appendChild(toastContainer);
    }
  }

  function toast(message, type = 'info', duration = 3000) {
    initToasts();

    const colors = {
      info:    { border: '#33ff66', text: '#33ff66' },
      success: { border: '#33ff66', text: '#66ffaa' },
      warning: { border: '#ffb347', text: '#ffb347' },
      error:   { border: '#ff4466', text: '#ff4466' }
    };

    const c = colors[type] || colors.info;

    const el = document.createElement('div');
    el.style.cssText = `
      background: #080d05; border: 1px solid ${c.border}; color: ${c.text};
      padding: 0.75rem 1.25rem; font-family: 'Courier Prime', monospace;
      font-size: 0.85rem; letter-spacing: 0.05em; box-shadow: 0 0 15px ${c.border}44;
      animation: toast-in 0.3s ease; max-width: 400px;
    `;
    el.textContent = message;
    toastContainer.appendChild(el);

    setTimeout(() => {
      el.style.animation = 'toast-out 0.3s ease forwards';
      setTimeout(() => el.remove(), 300);
    }, duration);
  }

  // Inject toast animations
  if (!document.getElementById('crt-toast-styles')) {
    const style = document.createElement('style');
    style.id = 'crt-toast-styles';
    style.textContent = `
      @keyframes toast-in { from { transform: translateX(100%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }
      @keyframes toast-out { from { transform: translateX(0); opacity: 1; } to { transform: translateX(100%); opacity: 0; } }
    `;
    document.head.appendChild(style);
  }

  /* ── UTILS ── */
  function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
  function pad(n) { return n < 10 ? '0' + n : String(n); }

  /* ── INIT ── */
  function init(opts = {}) {
    document.body.classList.add('crt-body');
    if (opts.scanlines !== false) document.body.classList.add('crt-scanlines');
    if (opts.flicker !== false) document.body.classList.add('crt-screen');
    if (opts.bloom) {
      const b = document.createElement('div');
      b.className = 'crt-bloom';
      document.body.appendChild(b);
    }
    if (opts.noise) {
      const n = document.createElement('div');
      n.className = 'crt-noise';
      document.body.appendChild(n);
    }
    if (opts.audio) initAudio();
  }

  return {
    type, typeLines, boot, makeCursor,
    startClock, startUptime, startGlitch,
    initReveal, animateBars,
    initAudio, beep, keyClick, lineReturn, bell,
    toast, sleep, init
  };
})();
