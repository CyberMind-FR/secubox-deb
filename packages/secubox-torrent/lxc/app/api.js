// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// SecuBox-Deb :: secubox-torrent :: api.js — CyberMind https://cybermind.fr
//
// Fastify control API: torrent lifecycle (add/list/keep/remove) + status/health,
// plus the /stream mount that hands off to the Range streaming handler.

import Fastify from 'fastify';
import path from 'node:path';
import { handleStream } from './stream.js';

// Uploaded .torrent files are small; cap the raw body well below anything that
// could be abused. 5 MiB comfortably covers even huge multi-file torrents.
const TORRENT_UPLOAD_LIMIT = 5 * 1024 * 1024;

export function buildApi({ engine, library, diskFreeBytes }) {
  const app = Fastify({ logger: false, bodyLimit: TORRENT_UPLOAD_LIMIT });

  // Raw .torrent upload: hand WebTorrent the untouched Buffer.
  app.addContentTypeParser('application/x-bittorrent', { parseAs: 'buffer' },
    (_req, body, done) => done(null, body));

  // Shared add path: engine.add accepts a magnet, a .torrent URL, or a
  // .torrent Buffer identically. The library always stores the canonical
  // magnetURI so a kept torrent resumes after a restart regardless of source.
  async function addTorrent(reply, torrentId) {
    let meta;
    try { meta = await engine.add(torrentId); }
    catch (e) { return reply.code(504).send({ error: e.message }); }
    // Never store an undefined/empty magnet: resumeLibrary() re-adds kept rows
    // via engine.add(row.magnet), and a bad value crashes WebTorrent on the
    // next restart. Fall back to a canonical magnet derived from the infohash.
    const magnet = meta.magnetURI || ('magnet:?xt=urn:btih:' + meta.infohash);
    library.add({ infohash: meta.infohash, name: meta.name, magnet,
      path: path.join(engine.downloadDir, meta.infohash) });
    return meta;
  }

  app.get('/api/v1/torrent/health', async () => ({ status: 'ok' }));
  app.get('/api/v1/torrent/status', async () => ({
    active: engine.client.torrents.length, disk_free: diskFreeBytes(), webrtc: engine.webrtc !== false }));

  // Add by magnet URI or by http(s) URL to a .torrent file.
  app.post('/api/v1/torrent/add', async (req, reply) => {
    const { magnet, torrentUrl } = req.body || {};
    const torrentId = magnet || torrentUrl;
    if (!torrentId) return reply.code(400).send({ error: 'magnet or torrentUrl required' });
    return addTorrent(reply, torrentId);
  });

  // Add by uploaded .torrent file (raw application/x-bittorrent body).
  app.post('/api/v1/torrent/add-file', async (req, reply) => {
    const buf = req.body;
    if (!Buffer.isBuffer(buf) || buf.length === 0) {
      return reply.code(400).send({ error: '.torrent file body required' });
    }
    return addTorrent(reply, buf);
  });

  app.get('/api/v1/torrent/list', async () =>
    library.list().map(r => ({ ...r, stats: engine.stats(r.infohash) })));

  app.get('/api/v1/torrent/files/:infohash', async (req, reply) => {
    const t = engine.get(req.params.infohash);
    if (!t) return reply.code(404).send({ error: 'not found' });
    return t.files.map((f, i) => ({ idx: i, name: f.name, length: f.length }));
  });

  app.post('/api/v1/torrent/keep/:infohash', async (req, reply) => {
    const ih = req.params.infohash;
    if (!library.get(ih)) return reply.code(404).send({ error: 'not found' });
    library.keep(ih, path.join(engine.downloadDir, ih));
    return { status: 'kept' };
  });

  app.post('/api/v1/torrent/remove/:infohash', async (req) => {
    engine.remove(req.params.infohash, { deleteData: true });
    library.remove(req.params.infohash);
    return { status: 'removed' };
  });

  app.get('/stream/:infohash/:fileIdx', (req, reply) => {
    library.touch(req.params.infohash);
    return handleStream(engine, req, reply.raw)
      .then(() => { reply.hijack(); });
  });

  return app;
}
