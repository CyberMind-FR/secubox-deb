// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// SecuBox Companion :: core/app — the shell (boot, auth gate, routing, dashboard)

import { store } from './store.js';
import { api } from './api.js';
import { registry, CANONICAL } from './registry.js';
import { pairingScreen, unlockScreen } from './auth.js';
import { el, esc, toast, ago, clear, confirmAction } from './ui.js';

const app = document.getElementById('app');
const view = () => document.getElementById('view');

// shared context handed to every module's mount()
const uiKit = { el, esc, toast, ago, clear, confirmAction };
function moduleCtx(m, params) {
  return {
    root: view(), api, module: m, ui: uiKit, base: m.api_base || '',
    navigate: (hash) => { location.hash = hash; },
  };
}

// ── shell chrome ──────────────────────────────────────────────────
function chrome() {
  const q = el('span.badge.pending', { id: 'q-badge', style: 'display:none' }, ['0 queued']);
  const net = el('span.badge', { id: 'net-badge' }, [navigator.onLine ? 'online' : 'offline']);
  const bar = el('div.app', {}, [
    el('div.offline-bar', { text: 'Offline — showing cached data; writes will sync when you reconnect.' }),
    el('div.queued-bar', { id: 'queued-bar' }, ['Pending changes will sync…']),
    el('div.topbar', {}, [
      el('span.brand', { onclick: () => location.hash = '#/', style: 'cursor:pointer' },
        ['SecuBox ', el('small', { text: 'Companion' })]),
      el('span.spacer'),
      net, q,
      el('a.btn.sm', { href: './secubox-companion.apk', download: '', title: 'Installer l’app Android (APK)', text: '📲' }),
      el('button.btn.sm', { title: 'Installer sur iOS (écran d’accueil)', text: '🍎', onclick: iosInstallHint }),
      el('button.btn.sm', { id: 'theme-btn', title: 'Thème clair / sombre', text: themeIcon(), onclick: toggleTheme }),
      el('button.btn.sm', { title: 'Lock', text: '🔒', onclick: lock }),
    ]),
    el('main.main', { id: 'view' }),
  ]);
  app.replaceChildren(bar);
  api.onChange(refreshChrome);
  window.addEventListener('online', refreshChrome);
  window.addEventListener('offline', refreshChrome);
  refreshChrome();
}
async function refreshChrome() {
  const net = document.getElementById('net-badge');
  if (net) { net.textContent = navigator.onLine ? 'online' : 'offline'; net.className = 'badge ' + (navigator.onLine ? 'ok' : 'warn'); }
  const n = await api.queueSize().catch(() => 0);
  const q = document.getElementById('q-badge');
  if (q) { q.style.display = n ? '' : 'none'; q.textContent = `${n} queued`; }
}

function lock() { location.hash = '#/'; boot(true); }

// iOS can't be prompted to install a PWA programmatically — Safari's "Add to
// Home Screen" is manual. This overlay walks the user through it (the iOS
// equivalent of the Android 📲 APK button). No-op is fine on other platforms.
function iosInstallHint() {
  const old = document.getElementById('ios-hint');
  if (old) { old.remove(); return; }
  const close = () => { const n = document.getElementById('ios-hint'); if (n) n.remove(); };
  const card = el('div', { id: 'ios-hint', style: 'position:fixed;inset:0;z-index:9999;display:grid;place-items:center;background:rgba(0,0,0,.55);backdrop-filter:blur(3px)', onclick: (e) => { if (e.target.id === 'ios-hint') close(); } }, [
    el('div', { style: 'max-width:22rem;margin:1rem;background:var(--surf,#12121a);color:var(--text,#e8e6d9);border:1px solid var(--border,#2a2a3a);border-radius:12px;padding:1.1rem 1.2rem;box-shadow:0 12px 40px rgba(0,0,0,.6)' }, [
      el('div', { style: 'font-size:1.05rem;font-weight:700;margin-bottom:.5rem', text: '🍎 Installer sur iOS' }),
      el('p', { style: 'font-size:.85rem;margin:.2rem 0 .6rem;opacity:.85', text: 'Ouvre cette page dans Safari, puis :' }),
      el('ol', { style: 'font-size:.86rem;line-height:1.5;padding-left:1.1rem;margin:0 0 .8rem' }, [
        el('li', { text: 'Touche le bouton Partager ⎋ (barre du bas)' }),
        el('li', { text: 'Choisis « Sur l’écran d’accueil » ➕' }),
        el('li', { text: 'Valide « Ajouter » — l’app apparaît sur l’écran d’accueil' }),
      ]),
      el('button.btn.sm.primary', { style: 'width:100%', text: 'Compris', onclick: close }),
    ]),
  ]);
  document.body.appendChild(card);
}

// ── theme (light default, opt-in dark, persisted) ──────────────────
function currentTheme() { try { return localStorage.getItem('sbx-theme') || 'light'; } catch (e) { return 'light'; } }
function themeIcon() { return currentTheme() === 'dark' ? '☀️' : '🌙'; }
function toggleTheme() {
  const next = currentTheme() === 'dark' ? 'light' : 'dark';
  if (next === 'dark') document.documentElement.dataset.theme = 'dark';
  else delete document.documentElement.dataset.theme;
  try { localStorage.setItem('sbx-theme', next); } catch (e) { /* noop */ }
  const btn = document.getElementById('theme-btn');
  if (btn) btn.textContent = themeIcon();
}

// ── favourites (parameterizable, localStorage) ─────────────────────
// Default = the current base modules + photoprism (peertube is already in).
const DEFAULT_FAVS = ['waf', 'system', 'billets', 'podcasteur', 'peertube', 'torrent', 'ytsas', 'exposure', 'wireguard', 'photoprism', 'jellyfin'];
function getFavs() {
  try { const f = JSON.parse(localStorage.getItem('sbx-favs')); if (Array.isArray(f)) return new Set(f); } catch (e) { /* noop */ }
  return new Set(DEFAULT_FAVS);
}
function saveFavs(set) { try { localStorage.setItem('sbx-favs', JSON.stringify([...set])); } catch (e) { /* noop */ } }
function getView() { try { return localStorage.getItem('sbx-view') || 'favs'; } catch (e) { return 'favs'; } }
function setViewPref(v) { try { localStorage.setItem('sbx-view', v); } catch (e) { /* noop */ } }

// ── type signalling (emoji per service category) ──────────────────
// The big tile emoji is the module's own identity; this is the *type* badge —
// which family the service belongs to (WALL security, MIND media/apps, …).
const TYPE_EMOJI = { AUTH: '🔑', WALL: '🛡️', BOOT: '⚙️', MIND: '🧠', ROOT: '🚀', MESH: '🔗' };
function typeLabel(mod) { return `${TYPE_EMOJI[mod] || '🔷'} ${mod}`; }

// ── dashboard ─────────────────────────────────────────────────────
async function dashboard() {
  const root = clear(view());
  const mods = registry.all().filter(m => m.module !== 'AUTH');   // the gate is not a tile
  if (!mods.length) { root.append(el('div.empty', { text: 'Aucun module. Dépose un dossier dans www/modules/ et ajoute son id à index.json.' })); return; }

  const favs = getFavs();
  let vw = getView();

  const seg = el('div.seg', {}, [
    el('button', { dataset: { view: 'favs' }, text: '⭐ Favoris', class: vw === 'favs' ? 'on' : '' }),
    el('button', { dataset: { view: 'all' }, text: '⊞ Tout', class: vw === 'all' ? 'on' : '' }),
  ]);
  const grid = el('div.grid.cardlets');
  const empty = el('div.empty', { style: 'display:none', text: '⭐ Aucun favori — passe en « Tout » et clique l’étoile d’une carte pour l’épingler.' });
  root.append(el('div.panel-head', {}, [el('h2', { text: 'Tableau de bord' }), el('span.spacer'), seg]), grid, empty);

  function applyFilter() {
    let shown = 0;
    grid.querySelectorAll('.card').forEach(c => {
      const vis = (vw === 'all') || favs.has(c.dataset.id);
      c.style.display = vis ? '' : 'none';
      if (vis) shown++;
    });
    empty.style.display = (vw === 'favs' && shown === 0) ? '' : 'none';
  }
  seg.querySelectorAll('button').forEach(b => b.addEventListener('click', () => {
    vw = b.dataset.view; setViewPref(vw);
    seg.querySelectorAll('button').forEach(x => x.classList.toggle('on', x.dataset.view === vw));
    applyFilter();
  }));

  for (const m of mods) {
    const pill = el('span.pill.idle', {}, [el('span.dot'), ' …']);
    const star = el('button.fav', { title: 'Favori', text: favs.has(m.id) ? '★' : '☆', class: favs.has(m.id) ? 'fav on' : 'fav' });
    star.addEventListener('click', (ev) => {
      ev.stopPropagation();
      if (favs.has(m.id)) favs.delete(m.id); else favs.add(m.id);
      star.textContent = favs.has(m.id) ? '★' : '☆';
      star.classList.toggle('on', favs.has(m.id));
      saveFavs(favs); applyFilter();
    });
    const card = el('div.card.link.cardlet', {
      dataset: { module: m.module, id: m.id },
      onclick: () => { location.hash = `#/m/${m.id}`; },
    }, [
      star,
      el('div.cardlet-top', {}, [
        el('span.emoji', { text: m.icon || '🔷' }),
        el('div.cardlet-id', {}, [el('div.kicker', { text: typeLabel(m.module) }), el('h3', { text: m.name })]),
      ]),
      el('div.muted', { style: 'font-size:.74rem;min-height:2em', text: m.description || '' }),
      el('div.cardlet-metrics'),
      el('div.row', { style: 'margin-top:8px' }, [pill]),
    ]);
    grid.append(card);
    const metricsEl = card.querySelector('.cardlet-metrics');
    if (m.status_endpoint) {
      api.get(m.status_endpoint)
        .then(s => { setPill(pill, s); fillMetrics(metricsEl, m.metrics, s); })
        .catch(() => setPill(pill, null));
    } else setPill(pill, { status: 'ready' });
  }
  applyFilter();
}

// Render the module's declared metrics from its live status response. Only
// numbers/strings the status actually returns are shown — no fabricated data;
// a module without a `metrics` manifest (or an unreachable status) shows just
// the pill.
function fillMetrics(host, defs, s) {
  if (!host || !Array.isArray(defs) || !s || typeof s !== 'object') return;
  const cells = [];
  for (const d of defs) {
    // dotted keys ("services.total") walk into nested status objects;
    // a plain key is just a one-segment path.
    const raw = String(d.key).split('.').reduce((o, k) => (o == null ? o : o[k]), s);
    if (raw == null) continue;
    const val = typeof raw === 'number' ? raw.toLocaleString('fr-FR')
      : (raw === true ? '✓' : raw === false ? '✕' : String(raw));
    cells.push(el('div.cmetric', {}, [el('div.cv', { text: val }), el('div.ck', { text: d.label })]));
  }
  if (cells.length) host.replaceChildren(...cells);
}

// Three-state service signal. A module that answered /status with no explicit
// failure is online — most modules report health via their own fields, not a
// uniform "status:ok", so treating "answered & not-failed" as up is what keeps
// wireguard/podcaster/system green instead of a false idle.
function pillState(s) {
  if (s == null || typeof s !== 'object') return 'down';
  const st = String(s.status || '').toLowerCase();
  if (s.error || s.installed === false || s.active === false
    || ['stopped', 'down', 'error', 'dead', 'failed', 'inactive'].includes(st)) return 'down';
  if (s.sleeping || ['idle', 'sleeping', 'veille', 'paused', 'asleep'].includes(st)) return 'idle';
  return 'up';
}
const PILL_EMOJI = { up: '🟢', idle: '🟡', down: '🔴' };
const PILL_LABEL = { up: 'en ligne', idle: 'veille', down: 'hors-ligne' };
function setPill(pill, s) {
  const state = pillState(s);
  const txt = (s == null && !navigator.onLine) ? 'offline'
    : (s == null ? 'injoignable' : PILL_LABEL[state]);
  pill.className = 'pill ' + state;
  pill.replaceChildren(document.createTextNode(`${PILL_EMOJI[state]} ${txt}`));
}

// ── module view ───────────────────────────────────────────────────
async function openModule(id, params) {
  const m = registry.get(id);
  const root = clear(view());
  if (!m) { root.append(el('div.empty', { text: 'Unknown module: ' + esc(id) })); return; }
  const panel = el('div.panel', { dataset: { module: m.module } }, [
    el('div.panel-head', {}, [
      el('button.btn.sm', { text: '←', title: 'Back', onclick: () => location.hash = '#/' }),
      el('span.dot'),
      el('h2', {}, [m.icon ? m.icon + ' ' : '', esc(m.name)]),
      el('span.spacer'),
      el('span.badge', { text: m.module }),
    ]),
    el('div', { id: 'module-root' }),
  ]);
  root.append(panel);
  const host = panel.querySelector('#module-root');
  try {
    const mount = await registry.view(id);
    await mount({ ...moduleCtx(m, params), root: host });
  } catch (e) {
    host.append(el('div.empty', { text: 'Failed to load module: ' + esc(e.message) }));
    console.error(e);
  }
}

// ── router ────────────────────────────────────────────────────────
function route() {
  const h = location.hash.replace(/^#/, '') || '/';
  const mm = h.match(/^\/m\/([\w-]+)(?:\/(.*))?$/);
  if (mm) return openModule(mm[1], mm[2] || '');
  return dashboard();
}

// ── boot ──────────────────────────────────────────────────────────
async function boot(forceLock = false) {
  // Box tokens live 24h; the sealed one goes stale and every authed call then
  // 401s. Re-login in place (the URL is prefilled) and re-render, so an expired
  // session is a prompt rather than a dead end — api.js replays the request that
  // hit the 401, so an in-progress write is not lost.
  api.onUnauthorized(async () => {
    const creds = await pairingScreen(app);
    if (!creds || !creds.token) return false;
    api.init(creds);
    chrome();
    await registry.discover();
    route();
    return true;
  });

  if (!store.isPaired()) {
    const creds = await pairingScreen(app);
    api.init(creds);
  } else {
    const creds = await unlockScreen(app, { onForget: () => location.reload() });
    api.init(creds);
  }
  chrome();
  await registry.discover();
  api.flush().then(refreshChrome);
  window.addEventListener('hashchange', route);
  route();
}

// service worker (offline shell + read cache)
if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('./sw.js').catch(() => {});
}
document.addEventListener('visibilitychange', () => { if (!document.hidden) api.flush().then(refreshChrome); });

boot();
