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

// ── dashboard ─────────────────────────────────────────────────────
async function dashboard() {
  const root = clear(view());
  const mods = registry.all();
  if (!mods.length) { root.append(el('div.empty', { text: 'No modules installed. Drop a folder in www/modules/ and add its id to index.json.' })); return; }

  const grid = el('div.grid');
  root.append(el('div.panel-head', {}, [el('h2', { text: 'Modules' })]), grid);

  for (const m of mods) {
    const status = el('span.status', { text: '…' });
    const card = el('div.card.link', {
      dataset: { module: m.module },
      onclick: () => { location.hash = `#/m/${m.id}`; },
    }, [
      el('div.kicker', { text: m.module }),
      el('h3', {}, [m.icon ? el('span', { text: m.icon }) : null, esc(m.name)]),
      el('div.muted', { style: 'font-size:.78rem;min-height:2.2em', text: m.description || '' }),
      el('div.row', { style: 'margin-top:8px' }, [status]),
    ]);
    grid.append(card);
    // best-effort live status
    if (m.status_endpoint) {
      api.get(m.status_endpoint).then(s => {
        status.textContent = statusText(s);
      }).catch(() => { status.textContent = navigator.onLine ? 'unreachable' : 'offline'; });
    } else status.textContent = 'ready';
  }
}
function statusText(s) {
  if (!s || typeof s !== 'object') return 'ok';
  return s.status || (s.ok ? 'ok' : null) || Object.entries(s).slice(0, 2).map(([k, v]) => `${k}:${v}`).join(' · ') || 'ok';
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
