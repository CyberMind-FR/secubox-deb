// SecuBox Companion — client-side session vault (#409).
// Cookies are encrypted IN THE BROWSER (AES-GCM, PBKDF2 key from the operator's
// passphrase) before upload; the avatar module stores only opaque ciphertext.
// The passphrase never leaves the browser. Nothing is published off-box.
const Vault = (() => {
  const api = globalThis.browser ?? globalThis.chrome;
  const td = new TextDecoder(), te = new TextEncoder();
  const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
  const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

  async function deriveKey(passphrase, salt) {
    const mat = await crypto.subtle.importKey("raw", te.encode(passphrase), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", salt, iterations: 200000, hash: "SHA-256" },
      mat, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  }
  async function encryptObj(obj, passphrase) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveKey(passphrase, salt);
    const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, te.encode(JSON.stringify(obj)));
    return { blob: b64(ct), iv: b64(iv), salt: b64(salt) };
  }
  async function decryptObj(blobB64, ivB64, saltB64, passphrase) {
    const key = await deriveKey(passphrase, unb64(saltB64));
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(ivB64) }, key, unb64(blobB64));
    return JSON.parse(td.decode(pt));
  }

  async function backup(hubBase, headers, passphrase, profile, domains) {
    let n = 0;
    for (const domain of domains) {
      const cookies = await api.cookies.getAll({ domain });
      if (!cookies.length) continue;
      const data = cookies.map((c) => ({
        name: c.name, value: c.value, domain: c.domain, path: c.path,
        secure: c.secure, httpOnly: c.httpOnly, sameSite: c.sameSite,
        expirationDate: c.expirationDate,
      }));
      const { blob, iv, salt } = await encryptObj(data, passphrase);
      const r = await fetch(`${hubBase}/api/v1/avatar/vault/backup`, {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json", ...headers },
        body: JSON.stringify({ profile, domain, blob, iv,
          meta: { salt, cookie_count: cookies.length, captured_at: new Date().toISOString() } }),
      });
      if (r.ok) n++;
    }
    return n;
  }

  async function list(hubBase, headers) {
    const r = await fetch(`${hubBase}/api/v1/avatar/vault/list`, {
      credentials: "include", headers,
    });
    if (!r.ok) throw new Error("list " + r.status);
    return r.json();
  }

  async function restore(hubBase, headers, passphrase, profile, domain) {
    const r = await fetch(`${hubBase}/api/v1/avatar/vault/restore/${encodeURIComponent(profile)}/${encodeURIComponent(domain)}`, {
      credentials: "include", headers,
    });
    if (!r.ok) throw new Error("restore " + r.status);
    const d = await r.json();
    const cookies = await decryptObj(d.blob, d.iv, (d.meta || {}).salt, passphrase);
    let n = 0;
    for (const c of cookies) {
      const host = c.domain.startsWith(".") ? c.domain.slice(1) : c.domain;
      const url = (c.secure ? "https://" : "http://") + host + (c.path || "/");
      try {
        await api.cookies.set({
          url, name: c.name, value: c.value, path: c.path || "/",
          secure: c.secure, httpOnly: c.httpOnly, sameSite: c.sameSite,
          expirationDate: c.expirationDate,
          domain: c.domain.startsWith(".") ? c.domain : undefined,
        });
        n++;
      } catch (e) { /* skip cookies the browser refuses */ }
    }
    return n;
  }

  return { backup, list, restore };
})();
