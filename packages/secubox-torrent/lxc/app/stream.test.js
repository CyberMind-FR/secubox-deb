// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

/**
 * SecuBox-Deb :: secubox-torrent stream handler tests
 * CyberMind — https://cybermind.fr
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Readable } from 'node:stream';
import { handleStream } from './stream.js';

function fakeRes() {
  const listeners = {};
  return { statusCode: 200, headers: {}, ended: false, body: '',
    setHeader(k, v) { this.headers[k.toLowerCase()] = v; },
    writeHead(c, h) { this.statusCode = c; Object.assign(this.headers, lower(h || {})); },
    end(s) { if (s) this.body += s; this.ended = true; },
    on(event, listener) { if (!listeners[event]) listeners[event] = []; listeners[event].push(listener); return this; },
    once(event, listener) { const wrapped = (...args) => { listener(...args); const idx = listeners[event].indexOf(wrapped); if (idx >= 0) listeners[event].splice(idx, 1); }; if (!listeners[event]) listeners[event] = []; listeners[event].push(wrapped); return this; },
    write(chunk, encoding, cb) { this.body += chunk; if (cb) cb(); return true; },
    emit(event, data) { if (listeners[event]) listeners[event].forEach(l => l(data)); } };
}
const lower = o => Object.fromEntries(Object.entries(o).map(([k, v]) => [k.toLowerCase(), v]));
function fakeEngine(len = 100, name = 'movie.mp4') {
  const file = { name, length: len,
    createReadStream: ({ start, end }) => Readable.from([`bytes[${start}-${end}]`]) };
  return { get: () => ({ files: [file] }) };
}

test('full request returns 200 with content-length and type', async () => {
  const res = fakeRes();
  await handleStream(fakeEngine(100), { params: { infohash: 'a', fileIdx: '0' }, headers: {} }, res);
  assert.equal(res.statusCode, 200);
  assert.equal(res.headers['content-length'], 100);
  assert.match(res.headers['content-type'], /mp4/);
});

test('range request returns 206 with content-range', async () => {
  const res = fakeRes();
  await handleStream(fakeEngine(100), { params: { infohash: 'a', fileIdx: '0' }, headers: { range: 'bytes=10-19' } }, res);
  assert.equal(res.statusCode, 206);
  assert.equal(res.headers['content-range'], 'bytes 10-19/100');
  assert.equal(res.headers['content-length'], 10);
});

test('unsatisfiable range returns 416', async () => {
  const res = fakeRes();
  await handleStream(fakeEngine(100), { params: { infohash: 'a', fileIdx: '0' }, headers: { range: 'bytes=200-300' } }, res);
  assert.equal(res.statusCode, 416);
});

test('unknown infohash returns 404', async () => {
  const res = fakeRes();
  await handleStream({ get: () => null }, { params: { infohash: 'z', fileIdx: '0' }, headers: {} }, res);
  assert.equal(res.statusCode, 404);
});

test('range clamping: bytes=50-999999 on 100-byte file returns 206 with clamped end', async () => {
  const res = fakeRes();
  await handleStream(fakeEngine(100), { params: { infohash: 'a', fileIdx: '0' }, headers: { range: 'bytes=50-999999' } }, res);
  assert.equal(res.statusCode, 206);
  assert.equal(res.headers['content-range'], 'bytes 50-99/100');
  assert.equal(res.headers['content-length'], 50);
});

test('out-of-range fileIdx returns 404', async () => {
  const res = fakeRes();
  await handleStream(fakeEngine(100), { params: { infohash: 'a', fileIdx: '5' }, headers: {} }, res);
  assert.equal(res.statusCode, 404);
});

// --- Content-Disposition: the DOWNLOADED FILE'S NAME -----------------------
// Historical bug: /stream never set Content-Disposition at all. With the
// download anchor using a bare `download` attribute (no explicit value —
// see www/torrent/index.html), a browser with no Content-Disposition header
// falls back to the URL's own path segment for the suggested filename —
// which for /stream/:infohash/:fileIdx is the numeric fileIdx, NOT the
// torrent's real file name. That's the "generic/index name" the user saw.

test('the real file name is proposed, never the numeric fileIdx or the infohash', async () => {
  const res = fakeRes();
  await handleStream(fakeEngine(100, 'movie.mp4'), { params: { infohash: 'deadbeef', fileIdx: '0' }, headers: {} }, res);
  assert.ok(res.headers['content-disposition'], 'expected a Content-Disposition header to be set');
  assert.match(res.headers['content-disposition'], /filename="movie\.mp4"/);
  // Must NOT fall back to the URL's own segments.
  assert.doesNotMatch(res.headers['content-disposition'], /filename="0"/);
  assert.doesNotMatch(res.headers['content-disposition'], /filename="deadbeef/);
});

test('Content-Disposition is also set on a 206 range response (same filename)', async () => {
  const res = fakeRes();
  await handleStream(fakeEngine(100, 'movie.mp4'),
    { params: { infohash: 'a', fileIdx: '0' }, headers: { range: 'bytes=10-19' } }, res);
  assert.equal(res.statusCode, 206);
  assert.match(res.headers['content-disposition'], /filename="movie\.mp4"/);
});

test('Content-Disposition uses "inline" so <video>/<audio> playback via /stream keeps working', async () => {
  const res = fakeRes();
  await handleStream(fakeEngine(100, 'movie.mp4'), { params: { infohash: 'a', fileIdx: '0' }, headers: {} }, res);
  assert.match(res.headers['content-disposition'], /^inline;/);
});

test('a file name with accents/non-Latin characters is preserved via the UTF-8 form', async () => {
  const res = fakeRes();
  const real = 'Amélie – Café ☕ フォルダ.mkv';
  await handleStream(fakeEngine(100, real), { params: { infohash: 'a', fileIdx: '0' }, headers: {} }, res);
  const star = /filename\*=UTF-8''([^;]+)/.exec(res.headers['content-disposition'])[1];
  assert.equal(decodeURIComponent(star), real);
});

test('a file name with CR/LF cannot inject a second header line', async () => {
  const res = fakeRes();
  await handleStream(fakeEngine(100, 'evil.mp4\r\nX-Injected: yes'),
    { params: { infohash: 'a', fileIdx: '0' }, headers: {} }, res);
  assert.ok(!/[\r\n]/.test(res.headers['content-disposition']));
});

test('a file name with a path separator cannot smuggle a directory into the header', async () => {
  const res = fakeRes();
  await handleStream(fakeEngine(100, '../../etc/movie.mp4'),
    { params: { infohash: 'a', fileIdx: '0' }, headers: {} }, res);
  assert.ok(!res.headers['content-disposition'].includes('/etc/'));
});

test('a file name with a quote does not break the quoted header parameter', async () => {
  const res = fakeRes();
  await handleStream(fakeEngine(100, 'my "movie".mp4'), { params: { infohash: 'a', fileIdx: '0' }, headers: {} }, res);
  const quoted = /filename="([^]*?)";\s*filename\*=/.exec(res.headers['content-disposition'])[1];
  assert.ok(!quoted.includes('"'));
});
