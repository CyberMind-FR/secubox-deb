// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// SecuBox-Deb :: secubox-torrent :: api.test.js — CyberMind https://cybermind.fr
//
// Unit tests for the Fastify control API. Uses fastify .inject (no network),
// the Engine with FakeWebTorrent, and an in-memory Library.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildApi } from './api.js';
import { Library } from './library.js';
import { Engine } from './engine.js';
import { FakeWebTorrent } from './fakes.js';

function build() {
  const engine = new Engine({ WebTorrentCtor: FakeWebTorrent, downloadDir: '/tmp', maxActive: 5, webrtc: true });
  const library = new Library(':memory:');
  return buildApi({ engine, library, diskFreeBytes: () => 10 * 1e9 });
}

test('health returns ok', async () => {
  const app = build();
  const r = await app.inject({ method: 'GET', url: '/api/v1/torrent/health' });
  assert.equal(r.statusCode, 200);
  assert.equal(r.json().status, 'ok');
});

test('add then list returns the torrent', async () => {
  const app = build();
  await app.inject({ method: 'POST', url: '/api/v1/torrent/add',
    payload: { magnet: 'magnet:?xt=urn:btih:' + 'a'.repeat(40) } });
  const r = await app.inject({ method: 'GET', url: '/api/v1/torrent/list' });
  assert.equal(r.json().length, 1);
  assert.equal(r.json()[0].kept, 0);
});

test('keep flips kept=1', async () => {
  const app = build();
  await app.inject({ method: 'POST', url: '/api/v1/torrent/add',
    payload: { magnet: 'magnet:?xt=urn:btih:' + 'a'.repeat(40) } });
  const r = await app.inject({ method: 'POST', url: '/api/v1/torrent/keep/' + 'a'.repeat(40) });
  assert.equal(r.statusCode, 200);
  const list = await app.inject({ method: 'GET', url: '/api/v1/torrent/list' });
  assert.equal(list.json()[0].kept, 1);
});

function buildWith() {
  const engine = new Engine({ WebTorrentCtor: FakeWebTorrent, downloadDir: '/tmp', maxActive: 5, webrtc: true });
  const library = new Library(':memory:');
  return { app: buildApi({ engine, library, diskFreeBytes: () => 10 * 1e9 }), engine };
}

test('add by torrentUrl hands the URL to the engine', async () => {
  const { app, engine } = buildWith();
  const url = 'https://example.org/x.torrent';
  const r = await app.inject({ method: 'POST', url: '/api/v1/torrent/add', payload: { torrentUrl: url } });
  assert.equal(r.statusCode, 200);
  assert.ok(engine.client.added.includes(url));
  const list = await app.inject({ method: 'GET', url: '/api/v1/torrent/list' });
  assert.equal(list.json().length, 1);
});

test('add-file hands the raw .torrent Buffer to the engine', async () => {
  const { app, engine } = buildWith();
  const buf = Buffer.from('d8:announce...e'); // stand-in bencoded bytes
  const r = await app.inject({ method: 'POST', url: '/api/v1/torrent/add-file',
    headers: { 'content-type': 'application/x-bittorrent' }, payload: buf });
  assert.equal(r.statusCode, 200);
  const passed = engine.client.added[0];
  assert.ok(Buffer.isBuffer(passed) && passed.equals(buf));
});

test('add with neither magnet nor torrentUrl is 400', async () => {
  const app = build();
  const r = await app.inject({ method: 'POST', url: '/api/v1/torrent/add', payload: {} });
  assert.equal(r.statusCode, 400);
});

test('add-file with empty body is 400', async () => {
  const app = build();
  const r = await app.inject({ method: 'POST', url: '/api/v1/torrent/add-file',
    headers: { 'content-type': 'application/x-bittorrent' }, payload: Buffer.alloc(0) });
  assert.equal(r.statusCode, 400);
});
