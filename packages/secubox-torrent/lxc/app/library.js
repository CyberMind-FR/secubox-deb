// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// SecuBox-Deb :: secubox-torrent :: library.js — CyberMind https://cybermind.fr
//
// SQLite-backed torrent library: ephemeral (kept=0) vs. kept torrents, plus
// the selection query used by the purge job to find stale ephemeral entries.

import Database from 'better-sqlite3';

export class Library {
  constructor(dbPath) {
    this.db = new Database(dbPath);
    this.db.exec(`CREATE TABLE IF NOT EXISTS torrents (
      infohash TEXT PRIMARY KEY, name TEXT, magnet TEXT, path TEXT,
      added_at INTEGER, last_played_at INTEGER, kept INTEGER DEFAULT 0)`);
  }
  add({ infohash, name, magnet, path }) {
    const now = Math.floor(Date.now() / 1000);
    this.db.prepare(`INSERT OR REPLACE INTO torrents
      (infohash,name,magnet,path,added_at,last_played_at,kept)
      VALUES (?,?,?,?,?,?,0)`).run(infohash, name, magnet, path, now, now);
  }
  list() { return this.db.prepare('SELECT * FROM torrents ORDER BY added_at DESC').all(); }
  get(infohash) { return this.db.prepare('SELECT * FROM torrents WHERE infohash=?').get(infohash) || null; }
  touch(infohash) { this.touchAt(infohash, Math.floor(Date.now() / 1000)); }
  touchAt(infohash, ts) { this.db.prepare('UPDATE torrents SET last_played_at=? WHERE infohash=?').run(ts, infohash); }
  keep(infohash, newPath) { this.db.prepare('UPDATE torrents SET kept=1, path=? WHERE infohash=?').run(newPath, infohash); }
  remove(infohash) { this.db.prepare('DELETE FROM torrents WHERE infohash=?').run(infohash); }
  expiredEphemeral(ttlSeconds, now = Math.floor(Date.now() / 1000)) {
    const cutoff = now - ttlSeconds;
    return this.db.prepare('SELECT infohash FROM torrents WHERE kept=0 AND last_played_at < ?')
      .all(cutoff).map(r => r.infohash);
  }
}
