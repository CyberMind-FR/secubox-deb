// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// SecuBox-Deb :: secubox-torrent :: api.js — CyberMind https://cybermind.fr
//
// Fastify control API: torrent lifecycle (add/list/keep/remove) + status/health,
// plus the /stream mount that hands off to the Range streaming handler.

import Fastify from 'fastify';
import path from 'node:path';
import { handleStream } from './stream.js';

export function buildApi({ engine, library, diskFreeBytes }) {
  const app = Fastify({ logger: false });

  app.get('/api/v1/torrent/health', async () => ({ status: 'ok' }));
  app.get('/api/v1/torrent/status', async () => ({
    active: engine.client.torrents.length, disk_free: diskFreeBytes(), webrtc: engine.webrtc !== false }));

  app.post('/api/v1/torrent/add', async (req, reply) => {
    const magnet = (req.body || {}).magnet;
    if (!magnet) return reply.code(400).send({ error: 'magnet required' });
    let meta;
    try { meta = await engine.add(magnet); }
    catch (e) { return reply.code(504).send({ error: e.message }); }
    library.add({ infohash: meta.infohash, name: meta.name, magnet,
      path: path.join(engine.downloadDir, meta.infohash) });
    return meta;
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
