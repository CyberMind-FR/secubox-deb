// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// SecuBox-Deb :: secubox-torrent :: server.test.js — CyberMind https://cybermind.fr
//
// Unit tests for the purge sweep (runPurge) only. server.js's start() imports
// webtorrent/@fastify/static dynamically inside the function body, so this
// file never pulls those heavy/native deps in — no network, no real disk.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runPurge } from './server.js';
import { Library } from './library.js';

test('purge removes expired ephemeral and calls engine.remove', () => {
  const lib = new Library(':memory:');
  lib.add({ infohash: 'old', name: 'O', magnet: 'm', path: '/tmp/o' });
  lib.touchAt('old', 0);
  const removed = [];
  const engine = { remove: (ih) => removed.push(ih) };
  const swept = runPurge(engine, lib, { ttlSeconds: 10, diskFloorBytes: 0, diskFreeBytes: () => 1e12 });
  assert.deepEqual(swept, ['old']);
  assert.deepEqual(removed, ['old']);
  assert.equal(lib.get('old'), null);
});

test('purge keeps fresh ephemeral torrents under the disk floor', () => {
  const lib = new Library(':memory:');
  lib.add({ infohash: 'fresh', name: 'F', magnet: 'm', path: '/tmp/f' });
  const removed = [];
  const engine = { remove: (ih) => removed.push(ih) };
  const swept = runPurge(engine, lib, { ttlSeconds: 3600, diskFloorBytes: 0, diskFreeBytes: () => 1e12 });
  assert.deepEqual(swept, []);
  assert.deepEqual(removed, []);
  assert.ok(lib.get('fresh'));
});

test('purge never sweeps kept torrents even when stale', () => {
  const lib = new Library(':memory:');
  lib.add({ infohash: 'keeper', name: 'K', magnet: 'm', path: '/tmp/k' });
  lib.keep('keeper', '/tmp/k-kept');
  lib.touchAt('keeper', 0);
  const removed = [];
  const engine = { remove: (ih) => removed.push(ih) };
  const swept = runPurge(engine, lib, { ttlSeconds: 10, diskFloorBytes: 0, diskFreeBytes: () => 1e12 });
  assert.deepEqual(swept, []);
  assert.deepEqual(removed, []);
  assert.ok(lib.get('keeper'));
});

test('purge below the disk floor also sweeps fresh ephemeral entries (but never kept ones)', () => {
  const lib = new Library(':memory:');
  lib.add({ infohash: 'fresh', name: 'F', magnet: 'm', path: '/tmp/f' });
  lib.add({ infohash: 'keeper', name: 'K', magnet: 'm', path: '/tmp/k' });
  lib.keep('keeper', '/tmp/k-kept');
  const removed = [];
  const engine = { remove: (ih) => removed.push(ih) };
  const swept = runPurge(engine, lib, { ttlSeconds: 3600, diskFloorBytes: 10e9, diskFreeBytes: () => 1e9 });
  assert.deepEqual(swept, ['fresh']);
  assert.deepEqual(removed, ['fresh']);
  assert.equal(lib.get('fresh'), null);
  assert.ok(lib.get('keeper'));
});
