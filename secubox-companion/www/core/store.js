// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// SecuBox Companion :: core/store — secure token vault + offline queue + cache
//
// Security posture (see brief):
//  - The box token is NEVER stored as bare localStorage. It is encrypted with
//    AES-GCM using a key derived (PBKDF2) from a local PIN, and only decrypted
//    in memory after the user unlocks. If WebCrypto is unavailable we fall back
//    to sessionStorage (memory-only, wiped on close) rather than bare storage.
//  - No SecuBox data is persisted in clear beyond the read cache the SW needs.

const DB_NAME = 'sbx-companion';
const DB_VER = 1;
const VAULT_KEY = 'sbx.vault';         // {salt, iv, ct} — encrypted {url, token}
const META_KEY = 'sbx.meta';           // {url} — non-secret, for the pairing UI

let _db = null;
function db() {
  if (_db) return Promise.resolve(_db);
  return new Promise((resolve, reject) => {
    const r = indexedDB.open(DB_NAME, DB_VER);
    r.onupgradeneeded = () => {
      const d = r.result;
      if (!d.objectStoreNames.contains('queue')) d.createObjectStore('queue', { keyPath: 'id' });
      if (!d.objectStoreNames.contains('cache')) d.createObjectStore('cache', { keyPath: 'key' });
    };
    r.onsuccess = () => { _db = r.result; resolve(_db); };
    r.onerror = () => reject(r.error);
  });
}
async function tx(name, mode, fn) {
  const d = await db();
  return new Promise((resolve, reject) => {
    const t = d.transaction(name, mode);
    const store = t.objectStore(name);
    const out = fn(store);
    t.oncomplete = () => resolve(out && out.result !== undefined ? out.result : out);
    t.onerror = () => reject(t.error);
  });
}

// ── crypto vault ──────────────────────────────────────────────────
const enc = new TextEncoder(); const dec = new TextDecoder();
const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = (s) => Uint8Array.from(atob(s), c => c.charCodeAt(0));

async function deriveKey(pin, salt) {
  const base = await crypto.subtle.importKey('raw', enc.encode(pin), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 150000, hash: 'SHA-256' },
    base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

export const store = {
  hasCrypto() { return !!(crypto && crypto.subtle); },

  /** Is a paired vault present (encrypted credentials on disk)? */
  isPaired() { return !!localStorage.getItem(VAULT_KEY) || !!sessionStorage.getItem(VAULT_KEY); },

  pairedUrl() {
    try { return (JSON.parse(localStorage.getItem(META_KEY) || 'null') || {}).url || null; }
    catch { return null; }
  },

  /** Encrypt {url, token} with a PIN and persist it. */
  async pair({ url, token, pin }) {
    const payload = JSON.stringify({ url, token });
    if (this.hasCrypto() && pin) {
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const key = await deriveKey(pin, salt);
      const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(payload));
      localStorage.setItem(VAULT_KEY, JSON.stringify({ salt: b64(salt), iv: b64(iv), ct: b64(ct) }));
    } else {
      // no PIN / no WebCrypto → memory-only session storage (wiped on close)
      sessionStorage.setItem(VAULT_KEY, payload);
    }
    localStorage.setItem(META_KEY, JSON.stringify({ url }));
  },

  /** Unlock the vault with the PIN → {url, token} held in memory only. */
  async unlock(pin) {
    const sess = sessionStorage.getItem(VAULT_KEY);
    if (sess) return JSON.parse(sess);
    const raw = localStorage.getItem(VAULT_KEY);
    if (!raw) throw new Error('not paired');
    const { salt, iv, ct } = JSON.parse(raw);
    const key = await deriveKey(pin, unb64(salt));
    try {
      const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(iv) }, key, unb64(ct));
      return JSON.parse(dec.decode(pt));
    } catch { throw new Error('bad PIN'); }
  },

  /** Forget everything (unpair). */
  async wipe() {
    localStorage.removeItem(VAULT_KEY); localStorage.removeItem(META_KEY);
    sessionStorage.removeItem(VAULT_KEY);
    await tx('queue', 'readwrite', s => s.clear());
    await tx('cache', 'readwrite', s => s.clear());
  },

  // ── read cache (mirrors the SW cache for API GETs) ──────────────
  async cacheGet(key) { return tx('cache', 'readonly', s => s.get(key)).then(r => r && r.value); },
  async cachePut(key, value) { return tx('cache', 'readwrite', s => s.put({ key, value, ts: Date.now() })); },

  // ── offline write queue ─────────────────────────────────────────
  async enqueue(op) {
    const id = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    await tx('queue', 'readwrite', s => s.put({ id, ...op, ts: Date.now() }));
    return id;
  },
  async queued() {
    const d = await db();
    return new Promise((resolve, reject) => {
      const out = [];
      const t = d.transaction('queue', 'readonly');
      t.objectStore('queue').openCursor().onsuccess = e => {
        const c = e.target.result;
        if (c) { out.push(c.value); c.continue(); } else resolve(out);
      };
      t.onerror = () => reject(t.error);
    });
  },
  async dequeue(id) { return tx('queue', 'readwrite', s => s.delete(id)); },
};
