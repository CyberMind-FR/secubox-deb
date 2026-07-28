// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// SecuBox-Deb :: secubox-torrent :: engine.js — CyberMind https://cybermind.fr
//
// WebTorrent engine wrapper: lifecycle, metadata, stats, peer/wire inspection.

import path from 'node:path';

export class Engine {
  constructor({ WebTorrentCtor, downloadDir, maxActive, webrtc }) {
    this.downloadDir = downloadDir; this.maxActive = maxActive;
    this.webrtc = webrtc;
    // webrtc=false (spike fallback) tells WebTorrent to skip the WebRTC transport.
    this.client = new WebTorrentCtor(webrtc ? {} : { tracker: { wrtc: false } });
  }
  add(magnet) {
    if (this.client.torrents.length >= this.maxActive) {
      return Promise.reject(new Error('max active torrents reached'));
    }
    return new Promise((resolve, reject) => {
      const to = setTimeout(() => reject(new Error('metadata timeout')), 60000);
      const t = this.client.add(magnet, { path: this.downloadDir }, () => {});
      const done = () => {
        clearTimeout(to);
        resolve({
          infohash: t.infoHash, name: t.name,
          files: t.files.map((f, i) => ({ idx: i, name: f.name, length: f.length, type: ext(f.name) })),
        });
      };
      t.on('metadata', done);
      if (t.files && t.files.length) done();
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
