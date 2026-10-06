// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// SecuBox-Deb :: secubox-torrent :: library.test.js — CyberMind https://cybermind.fr
//
// Tests for the SQLite-backed torrent library (the "sas"): conserved by
// default, opt-in purge via ephemeral_until.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Library } from './library.js';

const mk = () => new Library(':memory:');

test('add then list yields one conserved row (kept by default, no purge marker)', () => {
  const lib = mk();
  lib.add({ infohash: 'a', name: 'A', magnet: 'm', path: '/tmp/a' });
  const rows = lib.list();
  assert.equal(rows.length, 1);
  assert.equal(rows[0].kept, 1);
  assert.equal(rows[0].ephemeral_until, null);
});

test('keep clears any purge marker and updates path', () => {
  const lib = mk();
  lib.add({ infohash: 'a', name: 'A', magnet: 'm', path: '/tmp/a' });
  lib.setEphemeral('a', 5000);
  lib.keep('a', '/data/torrent/library/a');
  assert.equal(lib.get('a').kept, 1);
  assert.equal(lib.get('a').ephemeral_until, null);
  assert.equal(lib.get('a').path, '/data/torrent/library/a');
});

test('re-adding a known infohash does not reset its purge marker or added_at', () => {
  const lib = mk();
  lib.add({ infohash: 'a', name: 'A', magnet: 'm', path: '/tmp/a' });
  lib.setEphemeral('a', 5000);
  const addedAtBefore = lib.get('a').added_at;
  lib.add({ infohash: 'a', name: 'A', magnet: 'm', path: '/tmp/a' });
  const row = lib.get('a');
  assert.equal(row.ephemeral_until, 5000);
  assert.equal(row.added_at, addedAtBefore);
});

test('setEphemeral with 0/undefined conserves (cancels purge)', () => {
  const lib = mk();
  lib.add({ infohash: 'a', name: 'A', magnet: 'm', path: '/tmp/a' });
  lib.setEphemeral('a', 5000);
  lib.setEphemeral('a', 0);
  assert.equal(lib.get('a').ephemeral_until, null);
  assert.equal(lib.get('a').kept, 1);
});

test('expiredEphemeral returns only torrents whose opt-in purge time has passed', () => {
  const lib = mk();
  lib.add({ infohash: 'due', name: 'D', magnet: 'm', path: '/tmp/d' });
  lib.add({ infohash: 'later', name: 'L', magnet: 'm', path: '/tmp/l' });
  lib.add({ infohash: 'conserved', name: 'C', magnet: 'm', path: '/tmp/c' });
  lib.setEphemeral('due', 5000);
  lib.setEphemeral('later', 20000);
  assert.deepEqual(lib.expiredEphemeral(10000), ['due']);
});

test('markedEphemeral returns every opt-in-purge torrent regardless of time', () => {
  const lib = mk();
  lib.add({ infohash: 'a', name: 'A', magnet: 'm', path: '/tmp/a' });
  lib.add({ infohash: 'b', name: 'B', magnet: 'm', path: '/tmp/b' });
  lib.setEphemeral('a', 99999);
  assert.deepEqual(lib.markedEphemeral(), ['a']);
});

test('setPeertube records status + url', () => {
  const lib = mk();
  lib.add({ infohash: 'a', name: 'A', magnet: 'm', path: '/tmp/a' });
  lib.setPeertube('a', 'done', 'https://peertube/w/xyz');
  assert.equal(lib.get('a').peertube_status, 'done');
  assert.equal(lib.get('a').peertube_url, 'https://peertube/w/xyz');
});

test('setLyrion records status + library path, independently of peertube columns', () => {
  const lib = mk();
  lib.add({ infohash: 'a', name: 'A', magnet: 'm', path: '/tmp/a' });
  lib.setLyrion('a', 'done', '/data/music/conserve/a.mp3');
  const row = lib.get('a');
  assert.equal(row.lyrion_status, 'done');
  assert.equal(row.lyrion_path, '/data/music/conserve/a.mp3');
  // Untouched — an audio conserve must never look like a peertube result.
  assert.equal(row.peertube_status, null);
  assert.equal(row.peertube_url, null);
});
