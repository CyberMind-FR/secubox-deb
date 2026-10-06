// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// SecuBox-Deb :: secubox-torrent :: engine.test.js — CyberMind https://cybermind.fr
//
// Unit tests for Engine (WebTorrent wrap). Uses fakes, no real network.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Engine } from './engine.js';
import { FakeWebTorrent, FakeTorrent } from './fakes.js';

test('add returns infohash, name and typed file list', async () => {
  const eng = new Engine({ WebTorrentCtor: FakeWebTorrent, downloadDir: '/tmp/x', maxActive: 5, webrtc: true });
  const r = await eng.add('magnet:?xt=urn:btih:' + 'a'.repeat(40));
  assert.equal(r.infohash, 'a'.repeat(40));
  assert.equal(r.files[0].type, 'mp4');
  assert.equal(r.files[0].idx, 0);
});

test('stats returns wire types', () => {
  const eng = new Engine({ WebTorrentCtor: FakeWebTorrent, downloadDir: '/tmp/x', maxActive: 5, webrtc: true });
  return eng.add('magnet:?xt=urn:btih:' + 'a'.repeat(40)).then(r => {
    const s = eng.stats(r.infohash);
    assert.deepEqual(s.wires.map(w => w.type).sort(), ['tcp', 'webrtc']);
    assert.equal(s.numPeers, 3);
  });
});

test('maxActive cap rejects beyond limit', async () => {
  const eng = new Engine({ WebTorrentCtor: FakeWebTorrent, downloadDir: '/tmp/x', maxActive: 1, webrtc: true });
  await eng.add('magnet:?xt=urn:btih:' + 'a'.repeat(40));
  eng.client.torrents.push({ infoHash: 'b'.repeat(40) }); // simulate a second active
  await assert.rejects(() => eng.add('magnet:?xt=urn:btih:' + 'c'.repeat(40)), /max active/);
});

test('remove frees capacity for new add', async () => {
  const eng = new Engine({ WebTorrentCtor: FakeWebTorrent, downloadDir: '/tmp/x', maxActive: 1, webrtc: true });
  const r1 = await eng.add('magnet:?xt=urn:btih:' + 'a'.repeat(40));
  eng.remove(r1.infohash);
  // Set up FakeWebTorrent to return a different torrent for the second add
  eng.client._next = new FakeTorrent('b'.repeat(40), 'Fake2', [{ name: 'video.mp4', length: 200 }]);
  const r2 = await eng.add('magnet:?xt=urn:btih:' + 'b'.repeat(40));
  assert.equal(r2.infohash, 'b'.repeat(40));
});

test('get returns a torrent synchronously (not a Promise) so callers work', async () => {
  const eng = new Engine({ WebTorrentCtor: FakeWebTorrent, downloadDir: '/tmp/x', maxActive: 5, webrtc: true });
  const r = await eng.add('magnet:?xt=urn:btih:' + 'a'.repeat(40));
  const t = eng.get(r.infohash);
  // Regression: real webtorrent client.get() is async — engine must NOT return a
  // Promise here or stats/remove/files/stream all operate on the wrong object.
  assert.equal(typeof t.then, 'undefined');
  assert.equal(t.infoHash, 'a'.repeat(40));
  assert.ok(Array.isArray(t.files));
});

test('remove drops the torrent from the client without throwing', async () => {
  const eng = new Engine({ WebTorrentCtor: FakeWebTorrent, downloadDir: '/tmp/x', maxActive: 5, webrtc: true });
  const r = await eng.add('magnet:?xt=urn:btih:' + 'a'.repeat(40));
  assert.equal(eng.client.torrents.length, 1);
  eng.remove(r.infohash, { deleteData: true }); // must not throw (t.destroy on a Torrent, not a Promise)
  assert.equal(eng.client.torrents.length, 0);
  assert.equal(eng.get(r.infohash), null);
});

test('add rejects (never hangs/crashes) when the torrent emits error', async () => {
  const client = new FakeWebTorrent();
  const eng = new Engine({ WebTorrentCtor: function () { return client; },
    downloadDir: '/tmp', maxActive: 5, webrtc: true });
  // no infohash + no files → add() cannot resolve early and must reject on error
  client._next = new FakeTorrent(null, 'Bad', [], { emitError: true });
  await assert.rejects(() => eng.add('magnet:?xt=urn:btih:bad'), /bad torrent/);
});
