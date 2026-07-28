// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// SecuBox-Deb :: secubox-torrent :: fakes.js — CyberMind https://cybermind.fr
//
// Fake WebTorrent client + torrent objects for unit tests (no real network, no wrtc).

export class FakeFile {
  constructor(name, length) { this.name = name; this.length = length; }
}

export class FakeTorrent {
  constructor(infoHash, name, files, { failMeta = false, emitError = false } = {}) {
    this.infoHash = infoHash; this.name = name;
    this.magnetURI = 'magnet:?xt=urn:btih:' + infoHash;
    this.files = files.map((f, i) => Object.assign(new FakeFile(f.name, f.length), { idx: i }));
    this.progress = 0.1; this.downloadSpeed = 1000; this.uploadSpeed = 500;
    this.numPeers = 3; this.wires = [{ type: 'webrtc' }, { type: 'tcp' }];
    this._failMeta = failMeta; this._emitError = emitError; this._handlers = {}; this._client = null;
  }
  on(ev, cb) {
    this._handlers[ev] = cb;
    if (ev === 'error' && this._emitError) queueMicrotask(() => cb(new Error('bad torrent')));
    if (ev === 'metadata' && !this._failMeta && !this._emitError) queueMicrotask(cb);
  }
  destroy(_opts, cb) {
    if (this._client) {
      const idx = this._client.torrents.indexOf(this);
      if (idx !== -1) this._client.torrents.splice(idx, 1);
    }
    if (cb) cb();
  }
}

export class FakeWebTorrent {
  constructor() { this.torrents = []; this.added = []; }
  add(torrentId, _opts, cb) {
    this.added.push(torrentId); // record magnet / URL / Buffer for test assertions
    const t = this._next || new FakeTorrent('a'.repeat(40), 'Fake', [{ name: 'movie.mp4', length: 100 }]);
    t._client = this; this.torrents.push(t); if (cb) queueMicrotask(() => cb(t)); return t;
  }
  // Real WebTorrent 2.x client.get() is async (Promise) — model that so no code
  // may treat it as sync again. Engine matches on the sync `torrents` array.
  async get(infohash) { return this.torrents.find(t => t.infoHash === infohash) || null; }
  on() {} // real WebTorrent client is an EventEmitter; engine attaches 'error'
  destroy(cb) { if (cb) cb(); }
}
