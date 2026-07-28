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
function fakeEngine(len = 100) {
  const file = { name: 'movie.mp4', length: len,
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
