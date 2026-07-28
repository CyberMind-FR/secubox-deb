// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// SecuBox-Deb :: secubox-torrent :: library.test.js — CyberMind https://cybermind.fr
//
// Tests for the SQLite-backed torrent library + ephemeral purge selection.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Library } from './library.js';

const mk = () => new Library(':memory:');

test('add then list yields one ephemeral row', () => {
  const lib = mk();
  lib.add({ infohash: 'a', name: 'A', magnet: 'm', path: '/tmp/a' });
  const rows = lib.list();
  assert.equal(rows.length, 1);
  assert.equal(rows[0].kept, 0);
});

test('keep flips kept and updates path', () => {
  const lib = mk();
  lib.add({ infohash: 'a', name: 'A', magnet: 'm', path: '/tmp/a' });
  lib.keep('a', '/data/torrent/library/a');
  assert.equal(lib.get('a').kept, 1);
  assert.equal(lib.get('a').path, '/data/torrent/library/a');
});

test('re-adding an already-kept infohash does not un-keep it', () => {
  const lib = mk();
  lib.add({ infohash: 'a', name: 'A', magnet: 'm', path: '/tmp/a' });
  lib.touchAt('a', 1000);
  lib.keep('a', '/data/torrent/a');
  const addedAtBefore = lib.get('a').added_at;
  lib.add({ infohash: 'a', name: 'A', magnet: 'm', path: '/tmp/a' });
  const row = lib.get('a');
  assert.equal(row.kept, 1);
  assert.equal(row.added_at, addedAtBefore);
});

test('expiredEphemeral returns only stale unkept torrents', () => {
  const lib = mk();
  lib.add({ infohash: 'old', name: 'O', magnet: 'm', path: '/tmp/o' });
  lib.add({ infohash: 'fresh', name: 'F', magnet: 'm', path: '/tmp/f' });
  lib.add({ infohash: 'kept', name: 'K', magnet: 'm', path: '/tmp/k' });
  lib.touchAt('old', 1000); lib.touchAt('fresh', 9000); lib.touchAt('kept', 1000);
  lib.keep('kept', '/data/k');
  const exp = lib.expiredEphemeral(3600, 10000); // now=10000, ttl=3600 → cutoff 6400
  assert.deepEqual(exp, ['old']);
});
