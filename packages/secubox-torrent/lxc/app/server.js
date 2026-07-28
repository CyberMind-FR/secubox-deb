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

export async function start() {
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
