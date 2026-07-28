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
