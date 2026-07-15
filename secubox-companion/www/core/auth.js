// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// SecuBox Companion :: core/auth — pairing + PIN unlock
//
// Pairing: the user enters the box URL + credentials; we obtain a bearer token
// from the box AUTH API and seal {url, token} in the PIN-encrypted vault.
// Subsequent launches only ask for the PIN (the token never leaves the device
// in clear). Everything is outbound-only to the box — no third party.

import { store } from './store.js';
import { el, toast } from './ui.js';

// The box login endpoint. Adjust to the real AUTH route if it differs.
const LOGIN_PATH = '/api/v1/auth/login';   // TODO(api): confirm exact AUTH login route/shape

async function login(url, username, password) {
  const base = url.replace(/\/+$/, '');
  const r = await fetch(base + LOGIN_PATH, {
    method: 'POST', headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
    credentials: 'include', body: JSON.stringify({ username, password }),
  });
  if (!r.ok) throw new Error(r.status === 401 ? 'Invalid credentials' : `Login failed (HTTP ${r.status})`);
  // secubox-auth is SSO-cookie based (#400): on success it sets the parent-domain
  // `secubox_session` cookie, which require_jwt accepts on every module — so no
  // bearer token is needed. Some builds ALSO return a token in the body; keep it
  // if present, otherwise rely on the cookie (the browser sends it, credentials:
  // 'include'). "No token" is NOT an error here.
  const d = await r.json().catch(() => ({}));
  return d.token || d.access_token || d.jwt || d.sbx_token || '';
}

function field(label, input) { return el('div', {}, [el('label', { text: label }), input]); }

/** Render the pairing screen; resolves with {url, token} once sealed. */
export function pairingScreen(root) {
  return new Promise((resolve) => {
    const url = el('input', { type: 'url', placeholder: 'https://box.example.in', value: store.pairedUrl() || location.origin, inputmode: 'url' });
    const user = el('input', { type: 'text', placeholder: 'username', autocomplete: 'username' });
    const pass = el('input', { type: 'password', placeholder: 'password', autocomplete: 'current-password' });
    const pin = el('input', { type: 'password', placeholder: 'choose a local PIN (unlocks this app)', inputmode: 'numeric', autocomplete: 'off' });
    const btn = el('button.btn.primary', { type: 'submit', text: 'Pair with box' });

    const form = el('form.card', {
      style: 'max-width:420px;margin:8vh auto;',
      onsubmit: async (e) => {
        e.preventDefault();
        if (!url.value || !user.value || !pass.value) return toast('URL + credentials required', 'err');
        if (store.hasCrypto() && (pin.value || '').length < 4) return toast('PIN must be ≥ 4 characters', 'err');
        btn.disabled = true; btn.textContent = 'Pairing…';
        try {
          const token = await login(url.value, user.value, pass.value);
          await store.pair({ url: url.value.replace(/\/+$/, ''), token, pin: pin.value });
          toast('Paired ✓');
          resolve({ url: url.value.replace(/\/+$/, ''), token });
        } catch (err) {
          toast(err.message || 'Pairing failed', 'err');
          btn.disabled = false; btn.textContent = 'Pair with box';
        }
      },
    }, [
      el('div.panel-head', {}, [el('span.dot'), el('h2', { text: 'Pair SecuBox Companion' })]),
      el('p.muted', { style: 'font-size:.8rem;margin-top:-4px', text: 'Outbound-only. Works over LAN, WAN, or WireGuard/MESH. Credentials are exchanged once for a token, then sealed under your PIN.' }),
      field('Box URL', url), field('Username', user), field('Password', pass),
      store.hasCrypto() ? field('Local PIN', pin) : el('p.muted', { text: 'WebCrypto unavailable — token kept in memory only (session).' }),
      el('div.row', { style: 'margin-top:14px' }, [btn]),
    ]);
    root.replaceChildren(form);
    setTimeout(() => url.focus(), 50);
  });
}

/** Render the PIN unlock screen for an already-paired vault; resolves {url, token}. */
export function unlockScreen(root, { onForget } = {}) {
  return new Promise((resolve) => {
    const pin = el('input', { type: 'password', placeholder: 'PIN', inputmode: 'numeric', autocomplete: 'off' });
    const btn = el('button.btn.primary', { type: 'submit', text: 'Unlock' });
    const form = el('form.card', {
      style: 'max-width:340px;margin:12vh auto;text-align:center',
      onsubmit: async (e) => {
        e.preventDefault(); btn.disabled = true;
        try { resolve(await store.unlock(pin.value)); }
        catch { toast('Bad PIN', 'err'); btn.disabled = false; pin.value = ''; pin.focus(); }
      },
    }, [
      el('div.panel-head', { style: 'justify-content:center' }, [el('span.dot'), el('h2', { text: 'SecuBox Companion' })]),
      el('p.muted', { style: 'font-size:.8rem', text: store.pairedUrl() || '' }),
      pin, el('div.row', { style: 'margin-top:12px;justify-content:center' }, [btn]),
      el('button.btn.sm', { type: 'button', style: 'margin-top:16px;border:none;color:var(--muted)', text: 'Forget this box', onclick: async () => { await store.wipe(); onForget && onForget(); } }),
    ]);
    root.replaceChildren(form);
    setTimeout(() => pin.focus(), 50);
  });
}
