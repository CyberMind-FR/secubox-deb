// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// SecuBox-Deb :: secubox-torrent :: engine.test.js — CyberMind https://cybermind.fr
//
// Unit tests for Engine (WebTorrent wrap). Uses fakes, no real network.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Engine } from './engine.js';
import { FakeWebTorrent } from './fakes.js';

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
