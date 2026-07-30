// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// SecuBox-Deb :: secubox-torrent :: server.test.js — CyberMind https://cybermind.fr
//
// Unit tests for the sas purge sweep (runPurge) + restart reconcile
// (resumeLibrary). server.js's start() imports webtorrent/@fastify/static
// dynamically inside the function body, so this file never pulls those
// heavy/native deps in — no network, no real disk.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runPurge, resumeLibrary } from './server.js';
import { Library } from './library.js';

const now = () => Math.floor(Date.now() / 1000);

test('purge removes torrents whose opt-in purge time has passed', () => {
  const lib = new Library(':memory:');
  lib.add({ infohash: 'due', name: 'O', magnet: 'm', path: '/tmp/o' });
  lib.setEphemeral('due', now() - 10);  // already due
  const removed = [];
  const engine = { remove: (ih) => removed.push(ih) };
  const swept = runPurge(engine, lib, { diskFloorBytes: 0, diskFreeBytes: () => 1e12 });
  assert.deepEqual(swept, ['due']);
  assert.deepEqual(removed, ['due']);
  assert.equal(lib.get('due'), null);
});

test('purge keeps torrents marked for a FUTURE purge', () => {
  const lib = new Library(':memory:');
  lib.add({ infohash: 'later', name: 'F', magnet: 'm', path: '/tmp/f' });
  lib.setEphemeral('later', now() + 3600);
  const engine = { remove: () => { throw new Error('should not remove'); } };
  const swept = runPurge(engine, lib, { diskFloorBytes: 0, diskFreeBytes: () => 1e12 });
  assert.deepEqual(swept, []);
  assert.ok(lib.get('later'));
});

test('purge never sweeps conserved (default) torrents', () => {
  const lib = new Library(':memory:');
  lib.add({ infohash: 'keeper', name: 'K', magnet: 'm', path: '/tmp/k' });  // conserved by default
  const engine = { remove: () => { throw new Error('should not remove'); } };
  const swept = runPurge(engine, lib, { diskFloorBytes: 0, diskFreeBytes: () => 1e12 });
  assert.deepEqual(swept, []);
  assert.ok(lib.get('keeper'));
});

test('disk-floor safety sweeps ALL marked-ephemeral (even future) but never conserved', () => {
  const lib = new Library(':memory:');
  lib.add({ infohash: 'future-eph', name: 'F', magnet: 'm', path: '/tmp/f' });
  lib.setEphemeral('future-eph', now() + 99999);
  lib.add({ infohash: 'keeper', name: 'K', magnet: 'm', path: '/tmp/k' });  // conserved
  const removed = [];
  const engine = { remove: (ih) => removed.push(ih) };
  const swept = runPurge(engine, lib, { diskFloorBytes: 10e9, diskFreeBytes: () => 1e9 });
  assert.deepEqual(swept, ['future-eph']);
  assert.deepEqual(removed, ['future-eph']);
  assert.equal(lib.get('future-eph'), null);
  assert.ok(lib.get('keeper'));
});

test('resumeLibrary re-adds only INCOMPLETE torrents (complete stay lazy — no re-hash storm)', () => {
  const lib = new Library(':memory:');
  lib.add({ infohash: 'done', name: 'D', magnet: 'magnet:done', path: '/data/torrent/done' });
  lib.setComplete('done', 1);   // finished → stays lazy (loaded on stream)
  lib.add({ infohash: 'dl', name: 'L', magnet: 'magnet:dl', path: '/data/torrent/dl' });  // complete=0 → resume
  const added = [];
  const engine = { add: (magnet) => { added.push(magnet); } };
  const rmrfCalls = [];
  resumeLibrary(engine, lib, { rmrf: (p) => rmrfCalls.push(p) });
  assert.deepEqual(added, ['magnet:dl']);  // only the still-downloading one is re-added
  assert.ok(lib.get('done'));              // both survive the restart
  assert.ok(lib.get('dl'));
  assert.deepEqual(rmrfCalls, []);
});

test('resumeLibrary reclaims torrents whose opt-in purge time already passed', () => {
  const lib = new Library(':memory:');
  lib.add({ infohash: 'due', name: 'E', magnet: 'magnet:eph', path: '/data/torrent/due' });
  lib.setEphemeral('due', now() - 10);
  lib.add({ infohash: 'keeper', name: 'K', magnet: 'magnet:keeper', path: '/data/torrent/keeper' });
  const rmrfCalls = [];
  resumeLibrary({ add: () => {} }, lib, { rmrf: (p) => rmrfCalls.push(p) });
  assert.equal(lib.get('due'), null);
  assert.ok(lib.get('keeper'));
  assert.deepEqual(rmrfCalls, ['/data/torrent/due']);
});
