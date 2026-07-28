// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// SecuBox-Deb :: secubox-torrent :: engine.js — CyberMind https://cybermind.fr
//
// WebTorrent engine wrapper: lifecycle, metadata, stats, peer/wire inspection.

export class Engine {
  constructor({ WebTorrentCtor, downloadDir, maxActive, webrtc }) {
    this.downloadDir = downloadDir; this.maxActive = maxActive;
    this.webrtc = webrtc;
    // webrtc=false (spike fallback) tells WebTorrent to skip the WebRTC transport.
    this.client = new WebTorrentCtor(webrtc ? {} : { tracker: { wrtc: false } });
    // A bad magnet/URL/.torrent (or a peer/tracker fault) makes WebTorrent
    // emit 'error' on the CLIENT — unhandled it crashes the whole process.
    // Swallow it here (per-add errors are surfaced by add()'s own handler).
    if (typeof this.client.on === 'function') this.client.on('error', () => {});
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
      // Fake torrents (tests) and .torrent Buffers expose infoHash/files
      // synchronously → resolve immediately.
      if (t.infoHash || (t.files && t.files.length)) done();
    });
  }
  get(infohash) { return this.client.get(infohash); }
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
