// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// SecuBox-Deb :: secubox-torrent :: engine.js — CyberMind https://cybermind.fr
//
// WebTorrent engine wrapper: lifecycle, metadata, stats, peer/wire inspection.

export class Engine {
  constructor({ WebTorrentCtor, downloadDir, maxActive, webrtc, onDone, maxConns = 20, seed = false, idleMs = 900000 }) {
    this.downloadDir = downloadDir; this.maxActive = maxActive;
    this.webrtc = webrtc; this.seed = seed; this.idleMs = idleMs;
    this.onDone = typeof onDone === 'function' ? onDone : () => {};
    // Cap peer connections. WebTorrent SEEDS a completed torrent to every peer
    // that wants it, with no limit by default — on a small ARM board a popular
    // movie pegs the single JS event loop (100% CPU, HTTP 503) indefinitely.
    // maxConns bounds the per-torrent wires so seeding can't monopolise a core.
    const opts = { maxConns };
    // webrtc=false (spike fallback) tells WebTorrent to skip the WebRTC transport.
    if (!webrtc) opts.tracker = { wrtc: false };
    this.client = new WebTorrentCtor(opts);
    // SAS, NOT a seedbox. Seeding policy (unless TORRENT_SEED=full): upload is
    // capped at HALF the current download bandwidth while downloading (enough
    // tit-for-tat to not get choked), and drops to ZERO once a torrent hits
    // 100% — so a completed movie never re-uploads and pegs the box. Start at 0;
    // tuneUpload() raises it during active downloads.
    if (typeof this.client.throttleUpload === 'function') this.client.throttleUpload(0);
    // A bad magnet/URL/.torrent (or a peer/tracker fault) makes WebTorrent
    // emit 'error' on the CLIENT — unhandled it crashes the whole process.
    // Swallow it here (per-add errors are surfaced by add()'s own handler).
    if (typeof this.client.on === 'function') this.client.on('error', () => {});
  }
  // Upload = 50% of the bandwidth we're currently DOWNLOADING with; 0 when
  // nothing is downloading (i.e. everything is complete → no seeding). Called
  // periodically. TORRENT_SEED=full disables the cap (real seedbox opt-in).
  tuneUpload() {
    if (this.seed === 'full' || !this.client.throttleUpload) return;
    let dl = 0;
    for (const t of this.client.torrents) if ((t.progress || 0) < 1) dl += (t.downloadSpeed || 0);
    this.client.throttleUpload(Math.max(0, Math.floor(dl * 0.5)));
  }
  // Note when a torrent was last actively used (streamed/loaded) so the idle
  // reaper can unload it — the "transit lounge" model: hold in the engine only
  // what is being watched; the library keeps the row + file for a later stream.
  touch(infohash) { const t = this.get(infohash); if (t) t._sbxAccess = Date.now(); }
  // Unload (KEEP data) COMPLETE torrents idle longer than idleMs so a
  // viewed-then-left movie stops occupying the engine. An INCOMPLETE download is
  // NEVER reaped — it must stay loaded to finish downloading (that was the bug
  // where added torrents silently stopped at 0% after 15min).
  reapIdle(idleMs = this.idleMs) {
    const now = Date.now();
    for (const t of [...this.client.torrents]) {
      const complete = (t.progress || 0) >= 1 || t.done;
      if (complete && now - (t._sbxAccess || 0) > idleMs) {
        try { t.destroy({ destroyStore: false }, () => {}); } catch (e) { /* noop */ }
      }
    }
  }
  // torrentId is anything WebTorrent's add() accepts: a magnet URI, an http(s)
  // URL to a .torrent file (fetched by WebTorrent), a .torrent Buffer, or an
  // infohash. The API layer decides which of those it received.
  add(torrentId) {
    if (this.client.torrents.length >= this.maxActive) {
      return Promise.reject(new Error('max active torrents reached'));
    }
    return new Promise((resolve, reject) => {
      let settled = false;
      // Resolve as soon as the torrent has an infohash — do NOT block the HTTP
      // request on the full metadata fetch (magnets can take tens of seconds,
      // longer than the WAF/proxy read timeout → the caller gets a gateway
      // error). Metadata + files populate in the background; /files and /stream
      // reflect them once ready. A short guard timeout only covers the rare
      // case where even the infohash never materialises.
      const to = setTimeout(() => {
        if (!settled) { settled = true; reject(new Error('torrent add timeout')); }
      }, 30000);
      const t = this.client.add(torrentId, { path: this.downloadDir }, () => {});
      const done = () => {
        if (settled) return;
        settled = true; clearTimeout(to);
        t._sbxAccess = Date.now();   // fresh add — don't let the idle reaper drop it
        resolve({
          infohash: t.infoHash, name: t.name || (t.infoHash || 'torrent'),
          // canonical magnet — stored by the library regardless of the source
          // (magnet / .torrent URL / uploaded file) so a kept torrent can be
          // re-added by resumeLibrary() after a restart.
          magnetURI: t.magnetURI || (t.infoHash ? 'magnet:?xt=urn:btih:' + t.infoHash : undefined),
          files: (t.files || []).map((f, i) => ({ idx: i, name: f.name, length: f.length, type: ext(f.name) })),
        });
      };
      t.on('error', (err) => {
        if (settled) return;
        settled = true; clearTimeout(to);
        reject(err instanceof Error ? err : new Error(String(err || 'torrent error')));
      });
      // WebTorrent sets t.infoHash a tick AFTER add() returns (in _onTorrentId),
      // then emits 'infoHash' — that is the earliest point we can answer the
      // add without waiting for the (slow) full metadata fetch. 'metadata' is
      // the fallback for sources that skip straight to it.
      t.on('infoHash', done);
      t.on('metadata', done);
      // Mark the library row complete when the download finishes → the restart
      // reconcile stops re-adding it (it becomes lazy). Already-complete files
      // fire 'done' shortly after add too, so re-adds also self-heal the flag.
      t.on('done', () => { try { this.onDone(t.infoHash); } catch (e) { /* noop */ } });
      // Fake torrents (tests) and .torrent Buffers expose infoHash/files
      // synchronously → resolve immediately.
      if (t.infoHash || (t.files && t.files.length)) done();
    });
  }
  // WebTorrent 2.x's client.get() is ASYNC (returns a Promise) — using it as if
  // it were sync makes every caller (stats/remove/files/stream) operate on a
  // Promise instead of a Torrent (t.destroy/t.files/t.progress → 500 or garbage).
  // client.torrents is a plain array, so match on it synchronously instead.
  get(infohash) { return this.client.torrents.find(t => t.infoHash === infohash) || null; }
  // Lazily bring a conserved torrent into the engine (from its magnet, reusing
  // whatever is already on disk in downloadDir) the first time it is streamed.
  // The sas keeps every torrent in the library but the engine holds only what
  // is actively viewed — so a restart never re-verifies N files at once.
  async ensureLoaded(infohash, magnet) {
    const existing = this.get(infohash);
    if (existing) { existing._sbxAccess = Date.now(); return existing; }
    if (!magnet) return null;
    await this.add(magnet);
    const t = this.get(infohash);
    if (t) t._sbxAccess = Date.now();
    return t;
  }
  stats(infohash) {
    const t = this.get(infohash); if (!t) return null;
    return { progress: t.progress, downloadSpeed: t.downloadSpeed, uploadSpeed: t.uploadSpeed,
             numPeers: t.numPeers, wires: (t.wires || []).map(w => ({ type: w.type })) };
  }
  remove(infohash, { deleteData } = {}) {
    const t = this.get(infohash); if (t) t.destroy({ destroyStore: !!deleteData }, () => {});
  }
}

function ext(name) { const m = /\.([A-Za-z0-9]+)$/.exec(name); return m ? m[1].toLowerCase() : ''; }
