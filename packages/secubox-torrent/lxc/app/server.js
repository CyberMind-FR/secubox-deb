// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// SecuBox-Deb :: secubox-torrent :: server.js — CyberMind https://cybermind.fr
//
// Wires env → Engine/Library/buildApi, serves the player webui, and schedules
// the ephemeral-torrent purge sweep. `webtorrent` and `@fastify/static` are
// imported dynamically inside start() — this keeps runPurge (and this whole
// module) importable in a plain `node --test` run with no native deps built
// (webtorrent needs @roamhq/wrtc, which only builds on the target LXC).

import fs from 'node:fs';
import { Engine } from './engine.js';
import { Library } from './library.js';
import { buildApi } from './api.js';

/**
 * Sweep ephemeral (kept=0) torrents that have outlived their TTL, plus —
 * if free disk has dropped below the configured floor — every remaining
 * ephemeral torrent regardless of age (kept torrents are NEVER swept).
 * Returns the list of infohashes removed.
 */
export function runPurge(engine, library, { ttlSeconds, diskFloorBytes, diskFreeBytes }) {
  const now = Math.floor(Date.now() / 1000);
  let victims = library.expiredEphemeral(ttlSeconds, now);
  if (diskFreeBytes() < diskFloorBytes) {
    const extra = library.list().filter(r => r.kept === 0).map(r => r.infohash);
    victims = [...new Set([...victims, ...extra])];
  }
  for (const ih of victims) {
    engine.remove(ih, { deleteData: true });
    library.remove(ih);
  }
  return victims;
}

/** Free bytes available on /data — the real disk-floor signal (not RAM). */
export function diskFreeBytesOnData() {
  try {
    const st = fs.statfsSync('/data');
    return st.bavail * st.bsize;
  } catch {
    return Infinity;
  }
}

/**
 * Re-sync the WebTorrent engine with the library DB at startup. Kept rows
 * survive a service/LXC restart only in the DB (the engine's in-memory
 * torrent list is empty on every process start) — re-add them so /stream
 * and purge see them again. Ephemeral (kept=0) rows can't be meaningfully
 * resumed (no seek/priority state was persisted) and would otherwise leak
 * their downloaded bytes forever once runPurge's engine.remove() becomes a
 * no-op for a torrent the engine never re-learned about — so they're
 * dropped from the library and their download dir is reclaimed here
 * instead of waiting on a purge sweep that can no longer see them.
 */
export function resumeLibrary(engine, library, { rmrf = defaultRmrf } = {}) {
  for (const row of library.list()) {
    if (row.kept) {
      try {
        // engine.add() is async in the real Engine (Promise) but the fake
        // used in tests may be sync — handle both without letting either
        // path abort the loop or leave an unhandled rejection.
        const result = engine.add(row.magnet);
        if (result && typeof result.catch === 'function') {
          result.catch((e) =>
            console.error(`secubox-torrent: resume failed for ${row.infohash}: ${e.message}`));
        }
      } catch (e) {
        console.error(`secubox-torrent: resume failed for ${row.infohash}: ${e.message}`);
      }
    } else {
      library.remove(row.infohash);
      try { rmrf(row.path); }
      catch (e) { console.error(`secubox-torrent: cleanup failed for ${row.path}: ${e.message}`); }
    }
  }
}

function defaultRmrf(p) {
  if (p) fs.rmSync(p, { recursive: true, force: true });
}

export async function start() {
  // WebTorrent can THROW synchronously deep in its tick handlers on some
  // malformed input (e.g. a bad magnet → arr2hex(undefined) in _onTorrentId),
  // which is NOT an emitted 'error' event so the engine's error listeners
  // cannot catch it. Without this net one bad /add crashes the whole process
  // (the user then sees 502). Log and keep serving. Installed here (not at
  // module scope) so `node --test` importing this file is unaffected.
  process.on('uncaughtException', (err) => {
    console.error('[torrent] uncaughtException (kept alive):', err && err.message);
  });
  process.on('unhandledRejection', (err) => {
    console.error('[torrent] unhandledRejection (kept alive):', err && (err.message || err));
  });

  const cfg = {
    downloadDir: process.env.TORRENT_DOWNLOAD_DIR || '/data/torrent',
    maxActive: Number(process.env.TORRENT_MAX_ACTIVE || 5),
    webrtc: process.env.TORRENT_WEBRTC !== 'false',
    port: Number(process.env.TORRENT_PORT || 8090),
    ttl: Number(process.env.TORRENT_EPHEMERAL_TTL_HOURS || 6) * 3600,
    floor: Number(process.env.TORRENT_DISK_FLOOR_GB || 5) * 1e9,
  };

  const { default: WebTorrent } = await import('webtorrent');
  const engine = new Engine({ WebTorrentCtor: WebTorrent, ...cfg });
  const library = new Library(`${cfg.downloadDir}/library.db`);
  const diskFreeBytes = diskFreeBytesOnData;

  resumeLibrary(engine, library);

  const app = buildApi({ engine, library, diskFreeBytes });

  const fastifyStatic = await import('@fastify/static');
  await app.register(fastifyStatic.default, { root: '/opt/secubox-torrent/www' });

  setInterval(() => {
    runPurge(engine, library, { ttlSeconds: cfg.ttl, diskFloorBytes: cfg.floor, diskFreeBytes });
  }, 300000);

  await app.listen({ host: '0.0.0.0', port: cfg.port });
  return app;
}

if (process.argv[1] && process.argv[1].endsWith('server.js')) {
  start().catch((err) => { console.error(err); process.exit(1); });
}
