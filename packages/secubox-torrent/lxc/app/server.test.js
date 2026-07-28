// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// SecuBox-Deb :: secubox-torrent :: server.test.js — CyberMind https://cybermind.fr
//
// Unit tests for the purge sweep (runPurge) only. server.js's start() imports
// webtorrent/@fastify/static dynamically inside the function body, so this
// file never pulls those heavy/native deps in — no network, no real disk.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runPurge, resumeLibrary } from './server.js';
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

test('resumeLibrary re-adds kept torrents to the engine and reaps ephemeral ones', () => {
  const lib = new Library(':memory:');
  lib.add({ infohash: 'keeper', name: 'K', magnet: 'magnet:keeper', path: '/data/torrent/keeper' });
  lib.keep('keeper', '/data/torrent/keeper');
  lib.add({ infohash: 'eph', name: 'E', magnet: 'magnet:eph', path: '/data/torrent/eph' });

  const added = [];
  const engine = { add: (magnet) => { added.push(magnet); } };
  const rmrfCalls = [];
  const rmrf = (p) => rmrfCalls.push(p);

  resumeLibrary(engine, lib, { rmrf });

  assert.deepEqual(added, ['magnet:keeper']);
  assert.ok(lib.get('keeper'));
  assert.equal(lib.get('eph'), null);
  assert.deepEqual(rmrfCalls, ['/data/torrent/eph']);
});

test('resumeLibrary does not abort the loop if engine.add throws for one kept row', () => {
  const lib = new Library(':memory:');
  lib.add({ infohash: 'bad', name: 'B', magnet: 'magnet:bad', path: '/data/torrent/bad' });
  lib.keep('bad', '/data/torrent/bad');
  lib.add({ infohash: 'good', name: 'G', magnet: 'magnet:good', path: '/data/torrent/good' });
  lib.keep('good', '/data/torrent/good');

  const added = [];
  const engine = {
    add: (magnet) => {
      if (magnet === 'magnet:bad') throw new Error('boom');
      added.push(magnet);
    },
  };
  resumeLibrary(engine, lib, { rmrf: () => {} });
  assert.deepEqual(added, ['magnet:good']);
});
