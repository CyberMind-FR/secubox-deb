// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

/**
 * SecuBox-Deb :: secubox-torrent HTTP Range streaming handler
 * CyberMind — https://cybermind.fr
 */

import { sanitizeFilename, contentDispositionHeader } from './filenames.js';

const MIME = { mp4: 'video/mp4', webm: 'video/webm', mkv: 'video/x-matroska',
  m4v: 'video/mp4', mp3: 'audio/mpeg', m4a: 'audio/mp4', ogg: 'audio/ogg',
  flac: 'audio/flac', wav: 'audio/wav' };

export async function handleStream(engine, req, res) {
  const t = engine.get(req.params.infohash);
  const idx = Number(req.params.fileIdx);
  const file = t && t.files && t.files[idx];
  if (!file) { res.writeHead(404); res.end('not found'); return; }
  const type = mimeOf(file.name);
  const total = file.length;
  const range = req.headers.range;
  // The suggested filename for a save/download action. `file.name` is the
  // torrent's own metadata (from a remote peer/tracker) — untrusted, so it
  // goes through sanitizeFilename before ever reaching an HTTP header.
  // disposition-type is 'inline' (not 'attachment'): this same endpoint also
  // backs <video>/<audio> src for in-page playback, and 'attachment' would
  // force a download there instead of playing. The filename hint still
  // applies whenever the browser DOES save (explicit download click, or
  // "Save video as…").
  const fallbackName = `${req.params.infohash}-${idx}`;
  const dispo = contentDispositionHeader(sanitizeFilename(file.name, fallbackName), { type: 'inline' });
  if (!range) {
    res.writeHead(200, { 'Content-Length': total, 'Content-Type': type, 'Accept-Ranges': 'bytes',
      'Content-Disposition': dispo });
    const stream = file.createReadStream({ start: 0, end: total - 1 });
    stream.on('error', () => { try { res.destroy(); } catch {} });
    stream.pipe(res);
    return;
  }
  const m = /bytes=(\d+)-(\d*)/.exec(range);
  let start = m ? Number(m[1]) : 0;
  let end = m && m[2] ? Number(m[2]) : total - 1;
  if (end >= total) end = total - 1;
  if (start >= total || start > end) {
    res.writeHead(416, { 'Content-Range': `bytes */${total}` }); res.end(); return;
  }
  res.writeHead(206, { 'Content-Range': `bytes ${start}-${end}/${total}`,
    'Content-Length': end - start + 1, 'Content-Type': type, 'Accept-Ranges': 'bytes',
    'Content-Disposition': dispo });
  const stream = file.createReadStream({ start, end });
  stream.on('error', () => { try { res.destroy(); } catch {} });
  stream.pipe(res);
}

function mimeOf(name) { const e = (/\.([A-Za-z0-9]+)$/.exec(name) || [])[1]; return MIME[(e || '').toLowerCase()] || 'application/octet-stream'; }
