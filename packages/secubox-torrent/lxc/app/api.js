// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// SecuBox-Deb :: secubox-torrent :: api.js — CyberMind https://cybermind.fr
//
// Fastify control API: torrent lifecycle (add/list/keep/remove) + status/health,
// plus the /stream mount that hands off to the Range streaming handler.

import Fastify from 'fastify';
import path from 'node:path';
import fs from 'node:fs';
import { handleStream } from './stream.js';
import { isValidInfohash, safeFilePath, buildZipArchive } from './zip.js';
import { sanitizeFilename, contentDispositionHeader } from './filenames.js';

// Uploaded .torrent files are small; cap the raw body well below anything that
// could be abused. 5 MiB comfortably covers even huge multi-file torrents.
const TORRENT_UPLOAD_LIMIT = 5 * 1024 * 1024;

const VIDEO_RE = /\.(mp4|mkv|webm|avi|mov|m4v|ts|flv)$/i;

// Conserve-to-PeerTube uses a file-drop queue on the shared /data volume: the
// LXC drops a request, a HOST timer (secubox-torrent-conserve) runs the upload
// with the PeerTube admin creds it holds, then drops a result the LXC reads.
// Keeping the creds host-side is the whole point of the split.
function conserveDirs(downloadDir) {
  return { queue: path.join(downloadDir, '.conserve-queue'),
           results: path.join(downloadDir, '.conserve-results') };
}

// Fold any host-written upload results into the library (called on /list so the
// panel picks up completions without a second poller in the LXC).
function drainConserveResults(library, downloadDir) {
  const { results } = conserveDirs(downloadDir);
  let files = [];
  try { files = fs.readdirSync(results).filter(f => f.endsWith('.json')); } catch { return; }
  for (const f of files) {
    const ih = f.replace(/\.json$/, '');
    try {
      const r = JSON.parse(fs.readFileSync(path.join(results, f), 'utf8'));
      library.setPeertube(ih, r.status || 'done', r.url || null);
    } catch { /* ignore malformed result */ }
    try { fs.unlinkSync(path.join(results, f)); } catch { /* ignore */ }
  }
}

export function buildApi({ engine, library, diskFreeBytes }) {
  const app = Fastify({ logger: false, bodyLimit: TORRENT_UPLOAD_LIMIT });

  // Raw .torrent upload: hand WebTorrent the untouched Buffer.
  app.addContentTypeParser('application/x-bittorrent', { parseAs: 'buffer' },
    (_req, body, done) => done(null, body));

  // Tolerate an EMPTY application/json body: several POSTs (keep/remove/conserve)
  // carry no body, and Fastify's default json parser 400s on an empty body
  // (FST_ERR_CTP_EMPTY_JSON_BODY) whenever a client still sends the header.
  app.addContentTypeParser('application/json', { parseAs: 'string' },
    (_req, body, done) => {
      if (!body || !body.trim()) return done(null, {});
      try { done(null, JSON.parse(body)); }
      catch (e) { e.statusCode = 400; done(e); }
    });

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
    status: 'ok', active: engine.client.torrents.length, disk_free: diskFreeBytes(), webrtc: engine.webrtc !== false,
    ...library.counts() }));

  // Add by magnet URI or by http(s) URL to a .torrent file.
  app.post('/api/v1/torrent/add', async (req, reply) => {
    // Tolerant input: the webui's source selector posts under different field
    // names (magnet / url / .torrent link), and a client may send a bare string
    // body — accept them all so a valid magnet/URL never 400s on a field-name
    // mismatch. WebTorrent's add() takes a magnet URI, an http(s) .torrent URL,
    // or an infohash.
    let b = req.body;
    if (typeof b === 'string') b = { magnet: b };
    const { magnet, torrentUrl, url, link } = b || {};
    const torrentId = (magnet || torrentUrl || url || link || '').toString().trim();
    if (!torrentId) return reply.code(400).send({ error: 'magnet or torrent URL required' });
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

  app.get('/api/v1/torrent/list', async () => {
    drainConserveResults(library, engine.downloadDir);  // pick up host upload results
    // Keep the `complete` flag in sync with reality for engine-loaded torrents,
    // so the restart reconcile resumes only what is still downloading.
    for (const t of engine.client.torrents) {
      try { library.setComplete(t.infoHash, (t.progress >= 1 || t.done) ? 1 : 0); } catch (e) { /* noop */ }
    }
    return library.list().map(r => ({ ...r, stats: engine.stats(r.infohash) }));
  });

  // Resume / load a torrent into the engine on demand. For an incomplete
  // download this restarts it; for a conserved-lazy one it just loads it (so it
  // can be streamed). Also corrects the `complete` flag from observed progress.
  app.post('/api/v1/torrent/resume/:infohash', async (req, reply) => {
    const ih = req.params.infohash;
    const row = library.get(ih);
    if (!row) return reply.code(404).send({ error: 'not found' });
    const t = await engine.ensureLoaded(ih, row.magnet);
    if (!t) return reply.code(409).send({ error: 'could not load torrent' });
    const complete = (t.progress >= 1 || t.done);
    library.setComplete(ih, complete ? 1 : 0);
    return { status: complete ? 'loaded' : 'resuming', progress: t.progress || 0 };
  });

  // Conserve to PeerTube: drop an upload request for the HOST processor. The
  // download must be complete (no partial/corrupt uploads). We resolve the
  // actual video file path here (from the loaded torrent) since only the engine
  // knows where WebTorrent laid the files down.
  app.post('/api/v1/torrent/conserve/:infohash', async (req, reply) => {
    const ih = req.params.infohash;
    const row = library.get(ih);
    if (!row) return reply.code(404).send({ error: 'not found' });
    const t = await engine.ensureLoaded(ih, row.magnet);
    if (!t || !t.files || !t.files.length) return reply.code(409).send({ error: 'torrent not ready' });
    if (typeof t.progress === 'number' && t.progress < 1) {
      return reply.code(409).send({ error: 'download not complete' });
    }
    const vids = t.files.filter(f => VIDEO_RE.test(f.name));
    const pick = (vids.length ? vids : t.files).slice().sort((a, b) => b.length - a.length)[0];
    const abs = path.join(engine.downloadDir, pick.path);
    const { queue } = conserveDirs(engine.downloadDir);
    try {
      fs.mkdirSync(queue, { recursive: true });
      fs.writeFileSync(path.join(queue, ih + '.json'),
        JSON.stringify({ infohash: ih, name: row.name || t.name || ih, file: abs }));
    } catch (e) {
      return reply.code(500).send({ error: 'queue write failed: ' + e.message });
    }
    library.setPeertube(ih, 'queued', null);
    return { status: 'queued', file: pick.name };
  });

  app.get('/api/v1/torrent/files/:infohash', async (req, reply) => {
    const ih = req.params.infohash;
    const row = library.get(ih);
    // Lazy-load: a conserved torrent isn't in the engine until it's first
    // touched (the sas keeps everything in the library, the engine holds only
    // what's actively viewed). Re-add it from its magnet (reusing on-disk data).
    const t = await engine.ensureLoaded(ih, row && row.magnet);
    if (!t) return reply.code(404).send({ error: 'not found' });
    return t.files.map((f, i) => ({ idx: i, name: f.name, length: f.length }));
  });

  // Conserve indefinitely (default state, but also cancels an opt-in purge).
  app.post('/api/v1/torrent/keep/:infohash', async (req, reply) => {
    const ih = req.params.infohash;
    if (!library.get(ih)) return reply.code(404).send({ error: 'not found' });
    library.keep(ih, path.join(engine.downloadDir, ih));
    return { status: 'kept' };
  });

  // Opt-in purge: POST {seconds} → auto-delete this torrent after `seconds`.
  // seconds<=0 (or absent) cancels the purge (conserve).
  app.post('/api/v1/torrent/ephemeral/:infohash', async (req, reply) => {
    const ih = req.params.infohash;
    if (!library.get(ih)) return reply.code(404).send({ error: 'not found' });
    const s = Number((req.body || {}).seconds);
    if (!Number.isFinite(s) || s <= 0) {
      library.keep(ih);
      return { status: 'conserved' };
    }
    const until = Math.floor(Date.now() / 1000) + s;
    library.setEphemeral(ih, until);
    return { status: 'ephemeral', ephemeral_until: until };
  });

  app.post('/api/v1/torrent/remove/:infohash', async (req) => {
    engine.remove(req.params.infohash, { deleteData: true });
    library.remove(req.params.infohash);
    return { status: 'removed' };
  });

  app.get('/stream/:infohash/:fileIdx', async (req, reply) => {
    const ih = req.params.infohash;
    library.touch(ih);
    const row = library.get(ih);
    await engine.ensureLoaded(ih, row && row.magnet);  // lazy-load before streaming
    return handleStream(engine, req, reply.raw)
      .then(() => { reply.hijack(); });
  });

  // Download a completed torrent's whole folder as one ZIP archive. Built
  // and sent AS A STREAM (archiver pipes each file's fs.createReadStream
  // straight into the response) — a torrent can be many GB, and this box has
  // already gone down from disk saturation, so the archive is never
  // materialised on disk nor held whole in memory.
  //
  // store:true (no deflate): torrent payloads are almost always already
  // -compressed media (mp4/mkv/mp3/...), so spending CPU on deflate buys
  // ~0% size reduction while burning cycles this board doesn't have to
  // spare (load average regularly 45-90). STORE just frames+CRCs the bytes.
  app.get('/api/v1/torrent/zip/:infohash', async (req, reply) => {
    const ih = req.params.infohash;
    if (!isValidInfohash(ih)) return reply.code(400).send({ error: 'invalid infohash' });
    const row = library.get(ih);
    if (!row) return reply.code(404).send({ error: 'not found' });
    const t = await engine.ensureLoaded(ih, row.magnet);
    if (!t) return reply.code(404).send({ error: 'not found' });
    if (!t.files || !t.files.length) return reply.code(409).send({ error: 'no files to archive' });
    // Same completeness gate as /conserve — no partial/corrupt archives.
    if (typeof t.progress === 'number' && t.progress < 1) {
      return reply.code(409).send({ error: 'download not complete' });
    }

    // The REAL path-traversal gate: each file.path comes from the torrent's
    // own metadata (remote/untrusted), not from this request's infohash. A
    // hostile torrent could declare a file outside downloadDir; refuse the
    // whole archive rather than silently drop or follow it.
    //
    // The ZIP entry name is derived from the SAME resolved+validated abs
    // path (path.relative back against downloadDir), not re-used verbatim
    // from the untrusted f.path string. It's still the real torrent
    // tree/name — resolve() only normalises it (e.g. collapses a harmless
    // "sub/../file" down to "file") — but never contains a literal ".."
    // segment, which also rules out zip-slip on whatever tool the user later
    // extracts the archive with.
    const base = path.resolve(engine.downloadDir);
    const resolved = [];
    for (const f of t.files) {
      const abs = safeFilePath(engine.downloadDir, f.path || f.name);
      if (!abs) return reply.code(500).send({ error: 'unsafe file path in torrent data' });
      const entryName = path.relative(base, abs).split(path.sep).join('/');
      resolved.push({ abs, name: entryName });
    }

    // Confirm the data is actually still on disk — library/engine state can
    // drift from reality (purged out-of-band, moved, etc). Stat only (no
    // reads), so this stays cheap even for a torrent with many files.
    const stats = await Promise.all(resolved.map((f) => fs.promises.stat(f.abs).catch(() => null)));
    if (stats.every((s) => !s)) return reply.code(404).send({ error: 'no data on disk' });
    if (stats.some((s) => !s)) return reply.code(409).send({ error: 'torrent data incomplete on disk' });

    const zipName = sanitizeFilename(row.name || t.name, ih) + '.zip';
    reply.header('Content-Type', 'application/zip');
    reply.header('Content-Disposition', contentDispositionHeader(zipName));
    reply.header('X-Content-Type-Options', 'nosniff');

    return buildZipArchive(resolved, {
      onError: (err) => req.log.error({ err }, 'zip archive stream failed'),
    });
  });

  return app;
}
