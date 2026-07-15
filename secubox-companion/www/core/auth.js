// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// SecuBox Companion :: core/auth — pairing + PIN unlock
//
// Pairing: the user enters the box URL + credentials; we obtain a bearer token
// from the box AUTH API and seal {url, token} in the PIN-encrypted vault.
// Subsequent launches only ask for the PIN (the token never leaves the device
// in clear). Everything is outbound-only to the box — no third party.

import { store } from './store.js';
import { el, toast } from './ui.js';

// The canonical AUTH routes (must hit auth.sock — the companion vhost proxies
// /api/v1/auth there — so the session jti is written to sessions.json and
// require_jwt accepts the token/cookie).
const LOGIN_PATH = '/api/v1/auth/login';
const MFA_PATH = '/api/v1/auth/login/mfa';

/** Step 1 — password. Returns the raw box response:
 *   {access_token} | {mfa_required, mfa_token} | {enrollment_required} | {setup_required} */
async function loginPassword(base, username, password) {
  const r = await fetch(base + LOGIN_PATH, {
    method: 'POST', headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
    credentials: 'include', body: JSON.stringify({ username, password }),
  });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(d.detail || (r.status === 401 ? 'Invalid credentials' : `Login failed (HTTP ${r.status})`));
  return d;
}

/** Step 2 — verify a TOTP code for an enrolled account → access_token. */
async function loginMfa(base, mfaToken, code) {
  const r = await fetch(base + MFA_PATH, {
    method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + mfaToken },
    credentials: 'include', body: JSON.stringify({ code }),
  });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(d.detail || 'Invalid code');
  return d.access_token;
}

function field(label, input) { return el('div', {}, [el('label', { text: label }), input]); }

/** Render the pairing screen; resolves with {url, token} once sealed. */
export function pairingScreen(root) {
  return new Promise((resolve) => {
    const url = el('input', { type: 'url', placeholder: 'https://box.example.in', value: store.pairedUrl() || location.origin, inputmode: 'url' });
    const user = el('input', { type: 'text', placeholder: 'username', autocomplete: 'username' });
    const pass = el('input', { type: 'password', placeholder: 'password', autocomplete: 'current-password' });
    const mfa = el('input', { type: 'text', placeholder: '000000', inputmode: 'numeric', autocomplete: 'one-time-code' });
    const mfaField = field('2FA code', mfa); mfaField.style.display = 'none';
    const pin = el('input', { type: 'password', placeholder: 'choose a local PIN (unlocks this app)', inputmode: 'numeric', autocomplete: 'off' });
    const btn = el('button.btn.primary', { type: 'submit', text: 'Pair with box' });
    let mfaToken = null;

    const base = () => url.value.replace(/\/+$/, '');
    async function finalize(token) {
      // token is the box access_token; api uses it as Bearer (+ the SSO cookie
      // the login also set). Sealed with the PIN.
      await store.pair({ url: base(), token: token || '', pin: pin.value });
      toast('Paired ✓');
      resolve({ url: base(), token: token || '' });
    }

    const form = el('form.card', {
      style: 'max-width:420px;margin:8vh auto;',
      onsubmit: async (e) => {
        e.preventDefault();
        if (!url.value || !user.value || !pass.value) return toast('URL + credentials required', 'err');
        if (store.hasCrypto() && (pin.value || '').length < 4) return toast('PIN must be ≥ 4 characters', 'err');
        btn.disabled = true; btn.textContent = mfaToken ? 'Verifying…' : 'Pairing…';
        try {
          if (mfaToken) {                                    // step 2: TOTP code
            const token = await loginMfa(base(), mfaToken, mfa.value.trim());
            return finalize(token);
          }
          const d = await loginPassword(base(), user.value, pass.value);
          if (d.access_token) return finalize(d.access_token);   // password-only
          if (d.mfa_required && d.mfa_token) {                   // enrolled → ask code
            mfaToken = d.mfa_token;
            mfaField.style.display = ''; mfa.value = ''; mfa.focus();
            btn.textContent = 'Verify code'; btn.disabled = false;
            return toast('Enter your 2FA code');
          }
          if (d.enrollment_required) throw new Error('Enroll 2FA in the SecuBox web UI first, then pair here.');
          if (d.setup_required) throw new Error('Password change required — use the SecuBox web UI first.');
          throw new Error(d.detail || 'Login failed');
        } catch (err) {
          toast(err.message || 'Pairing failed', 'err');
          btn.disabled = false; btn.textContent = mfaToken ? 'Verify code' : 'Pair with box';
        }
      },
    }, [
      el('div.panel-head', {}, [el('span.dot'), el('h2', { text: 'Pair SecuBox Companion' })]),
      el('p.muted', { style: 'font-size:.8rem;margin-top:-4px', text: 'Outbound-only. Works over LAN, WAN, or WireGuard/MESH. One SecuBox login (with 2FA if enabled), sealed under your PIN.' }),
      field('Box URL', url), field('Username', user), field('Password', pass), mfaField,
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
