// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// SecuBox-Deb :: secubox-torrent :: library.js — CyberMind https://cybermind.fr
//
// SQLite-backed torrent library — the "sas" (staging area). A downloaded
// torrent is CONSERVED BY DEFAULT (nothing auto-disappears); purge is opt-in:
// set `ephemeral_until` and only then does the sweep delete it, at that time.
// A torrent can also be conserved permanently in PeerTube (peertube_* columns).

import Database from 'better-sqlite3';

export class Library {
  constructor(dbPath) {
    this.db = new Database(dbPath);
    // kept defaults to 1 now: conserve by default. `ephemeral_until` (unix ts,
    // nullable) is the opt-in purge marker — NULL means "never purge".
    this.db.exec(`CREATE TABLE IF NOT EXISTS torrents (
      infohash TEXT PRIMARY KEY, name TEXT, magnet TEXT, path TEXT,
      added_at INTEGER, last_played_at INTEGER, kept INTEGER DEFAULT 1,
      ephemeral_until INTEGER, peertube_status TEXT, peertube_url TEXT)`);
    this._migrate();
  }

  // Add columns that older DBs lack, and flip legacy ephemeral rows to conserved
  // so an upgrade never silently purges what the user already had.
  _migrate() {
    const cols = new Set(this.db.prepare(`PRAGMA table_info(torrents)`).all().map(c => c.name));
    const add = (name, decl) => { if (!cols.has(name)) this.db.exec(`ALTER TABLE torrents ADD COLUMN ${name} ${decl}`); };
    add('ephemeral_until', 'INTEGER');
    add('peertube_status', 'TEXT');
    add('peertube_url', 'TEXT');
    // Legacy rows were kept=0 (ephemeral-by-default). Under the sas model they
    // become conserved: keep them, no ephemeral_until → never auto-purged.
    this.db.exec(`UPDATE torrents SET kept=1 WHERE kept=0 AND ephemeral_until IS NULL`);
  }

  add({ infohash, name, magnet, path }) {
    const now = Math.floor(Date.now() / 1000);
    // Conserved by default (kept=1, ephemeral_until=NULL). ON CONFLICT touches
    // last_played_at only — re-adding a known infohash must NOT reset its purge
    // marker or PeerTube status.
    this.db.prepare(`INSERT INTO torrents
      (infohash,name,magnet,path,added_at,last_played_at,kept,ephemeral_until)
      VALUES (?,?,?,?,?,?,1,NULL)
      ON CONFLICT(infohash) DO UPDATE SET last_played_at=excluded.last_played_at`)
      .run(infohash, name, magnet, path, now, now);
  }

  list() { return this.db.prepare('SELECT * FROM torrents ORDER BY added_at DESC').all(); }
  get(infohash) { return this.db.prepare('SELECT * FROM torrents WHERE infohash=?').get(infohash) || null; }
  touch(infohash) { this.touchAt(infohash, Math.floor(Date.now() / 1000)); }
  touchAt(infohash, ts) { this.db.prepare('UPDATE torrents SET last_played_at=? WHERE infohash=?').run(ts, infohash); }

  // Conserve indefinitely: clear any purge marker (kept=1, ephemeral_until=NULL).
  keep(infohash, newPath) {
    this.db.prepare('UPDATE torrents SET kept=1, ephemeral_until=NULL, path=COALESCE(?,path) WHERE infohash=?')
      .run(newPath ?? null, infohash);
  }

  // Opt-in purge: mark this torrent to be deleted at `until` (unix ts). Pass a
  // null/0 `until` to cancel (same as keep).
  setEphemeral(infohash, until) {
    if (!until) return this.keep(infohash);
    this.db.prepare('UPDATE torrents SET kept=0, ephemeral_until=? WHERE infohash=?').run(until, infohash);
  }

  setPeertube(infohash, status, url) {
    this.db.prepare('UPDATE torrents SET peertube_status=?, peertube_url=COALESCE(?,peertube_url) WHERE infohash=?')
      .run(status, url ?? null, infohash);
  }

  remove(infohash) { this.db.prepare('DELETE FROM torrents WHERE infohash=?').run(infohash); }

  // Torrents whose opt-in purge time has passed — the ONLY rows the sweep deletes.
  expiredEphemeral(now = Math.floor(Date.now() / 1000)) {
    return this.db.prepare('SELECT infohash FROM torrents WHERE ephemeral_until IS NOT NULL AND ephemeral_until < ?')
      .all(now).map(r => r.infohash);
  }

  // All rows the user marked ephemeral (regardless of time) — used only as the
  // disk-floor safety valve (never touch conserved content).
  markedEphemeral() {
    return this.db.prepare('SELECT infohash FROM torrents WHERE ephemeral_until IS NOT NULL')
      .all().map(r => r.infohash);
  }
}
