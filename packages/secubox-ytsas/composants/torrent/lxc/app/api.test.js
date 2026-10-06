// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// SecuBox-Deb :: secubox-torrent :: api.test.js — CyberMind https://cybermind.fr
//
// Unit tests for the Fastify control API. Uses fastify .inject (no network),
// the Engine with FakeWebTorrent, and an in-memory Library.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { buildApi } from './api.js';
import { Library } from './library.js';
import { Engine } from './engine.js';
import { FakeWebTorrent, FakeTorrent } from './fakes.js';

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

test('add then list returns the torrent (conserved by default)', async () => {
  const app = build();
  await app.inject({ method: 'POST', url: '/api/v1/torrent/add',
    payload: { magnet: 'magnet:?xt=urn:btih:' + 'a'.repeat(40) } });
  const r = await app.inject({ method: 'GET', url: '/api/v1/torrent/list' });
  assert.equal(r.json().length, 1);
  assert.equal(r.json()[0].kept, 1);                 // sas: conserved by default
  assert.equal(r.json()[0].ephemeral_until, null);   // no opt-in purge marker
});

test('ephemeral sets a purge marker; ephemeral 0 conserves again', async () => {
  const app = build();
  const ih = 'a'.repeat(40);
  await app.inject({ method: 'POST', url: '/api/v1/torrent/add',
    payload: { magnet: 'magnet:?xt=urn:btih:' + ih } });
  const e = await app.inject({ method: 'POST', url: '/api/v1/torrent/ephemeral/' + ih,
    payload: { seconds: 3600 } });
  assert.equal(e.json().status, 'ephemeral');
  assert.ok(e.json().ephemeral_until > Math.floor(Date.now() / 1000));
  const back = await app.inject({ method: 'POST', url: '/api/v1/torrent/ephemeral/' + ih,
    payload: { seconds: 0 } });
  assert.equal(back.json().status, 'conserved');
  const list = await app.inject({ method: 'GET', url: '/api/v1/torrent/list' });
  assert.equal(list.json()[0].ephemeral_until, null);
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

// --- ZIP download route (/api/v1/torrent/zip/:infohash) ---------------------
// Uses a REAL temp directory for downloadDir (not FakeWebTorrent's in-memory
// bookkeeping) because the route reads real files from disk to build the
// archive — that's the whole point of what's under test.

function buildWithDisk() {
  const downloadDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sbx-torrent-api-zip-'));
  const engine = new Engine({ WebTorrentCtor: FakeWebTorrent, downloadDir, maxActive: 5, webrtc: true });
  const library = new Library(':memory:');
  const app = buildApi({ engine, library, diskFreeBytes: () => 10 * 1e9 });
  return { app, engine, library, downloadDir };
}

async function addFake(app, engine, torrent) {
  engine.client._next = torrent;
  await app.inject({ method: 'POST', url: '/api/v1/torrent/add',
    payload: { magnet: 'magnet:?xt=urn:btih:' + torrent.infoHash } });
}

test('zip: malformed infohash is rejected with 400 (not routed to the engine at all)', async () => {
  const { app } = buildWithDisk();
  const r = await app.inject({ method: 'GET', url: '/api/v1/torrent/zip/not-a-hash' });
  assert.equal(r.statusCode, 400);
});

test('zip: unknown infohash is 404', async () => {
  const { app } = buildWithDisk();
  const r = await app.inject({ method: 'GET', url: '/api/v1/torrent/zip/' + 'a'.repeat(40) });
  assert.equal(r.statusCode, 404);
});

test('zip: row exists but cannot be loaded (no magnet) is 404', async () => {
  const { app, library } = buildWithDisk();
  const ih = 'b'.repeat(40);
  library.add({ infohash: ih, name: 'Ghost', magnet: null, path: '/x' });
  const r = await app.inject({ method: 'GET', url: '/api/v1/torrent/zip/' + ih });
  assert.equal(r.statusCode, 404);
});

test('zip: torrent still downloading (incomplete) is 409, not a partial archive', async () => {
  const { app, engine } = buildWithDisk();
  const ih = 'c'.repeat(40);
  await addFake(app, engine, new FakeTorrent(ih, 'Downloading', [{ name: 'x.mp4', length: 10 }]));
  const r = await app.inject({ method: 'GET', url: '/api/v1/torrent/zip/' + ih });
  assert.equal(r.statusCode, 409);
  assert.match(r.json().error, /not complete/);
});

test('zip: torrent with zero files is 409, not a silently empty archive', async () => {
  const { app, engine } = buildWithDisk();
  const ih = 'd'.repeat(40);
  const t = new FakeTorrent(ih, 'Empty', []);
  t.progress = 1;
  await addFake(app, engine, t);
  const r = await app.inject({ method: 'GET', url: '/api/v1/torrent/zip/' + ih });
  assert.equal(r.statusCode, 409);
  assert.match(r.json().error, /no files/);
});

test('zip: complete torrent whose data is entirely absent from disk is 404', async () => {
  const { app, engine } = buildWithDisk();
  const ih = 'e'.repeat(40);
  const t = new FakeTorrent(ih, 'Ghost Files', [{ name: 'movie.mp4', length: 100 }]);
  t.progress = 1;
  await addFake(app, engine, t);
  // deliberately never write movie.mp4 to disk
  const r = await app.inject({ method: 'GET', url: '/api/v1/torrent/zip/' + ih });
  assert.equal(r.statusCode, 404);
  assert.match(r.json().error, /disk/);
});

test('zip: partial data on disk (some files missing) is 409, never a silently short archive', async () => {
  const { app, engine, downloadDir } = buildWithDisk();
  const ih = 'f'.repeat(40);
  const t = new FakeTorrent(ih, 'Partial', [
    { name: 'a.mp4', length: 5 },
    { name: 'b.mp4', length: 5 },
  ]);
  t.progress = 1;
  await addFake(app, engine, t);
  fs.writeFileSync(path.join(downloadDir, 'a.mp4'), 'aaaaa');
  // b.mp4 intentionally left missing
  const r = await app.inject({ method: 'GET', url: '/api/v1/torrent/zip/' + ih });
  assert.equal(r.statusCode, 409);
  assert.match(r.json().error, /incomplete/);
});

test('zip: complete torrent with data present streams a valid ZIP with sane headers', async () => {
  const { app, engine, downloadDir } = buildWithDisk();
  const ih = 'a1'.repeat(20);
  const t = new FakeTorrent(ih, 'My Movie (2024)', [
    { name: 'movie.mp4', length: 6, path: 'My Movie (2024)/movie.mp4' },
    { name: 'info.txt', length: 5, path: 'My Movie (2024)/info.txt' },
  ]);
  t.progress = 1;
  await addFake(app, engine, t);
  fs.mkdirSync(path.join(downloadDir, 'My Movie (2024)'), { recursive: true });
  fs.writeFileSync(path.join(downloadDir, 'My Movie (2024)', 'movie.mp4'), 'ABCDEF');
  fs.writeFileSync(path.join(downloadDir, 'My Movie (2024)', 'info.txt'), 'hello');

  const r = await app.inject({ method: 'GET', url: '/api/v1/torrent/zip/' + ih });
  assert.equal(r.statusCode, 200);
  assert.equal(r.headers['content-type'], 'application/zip');
  assert.match(r.headers['content-disposition'], /attachment; filename="My Movie \(2024\)\.zip"/);
  assert.match(r.headers['content-disposition'], /filename\*=UTF-8''/);
  const buf = r.rawPayload;
  assert.equal(buf.subarray(0, 4).toString('hex'), '504b0304'); // ZIP local-file-header magic
  assert.ok(buf.includes(Buffer.from('ABCDEF')));
  assert.ok(buf.includes(Buffer.from('movie.mp4')));
});

// --- Path traversal: the exigence this feature is not allowed to get wrong.
// A torrent's per-file path comes from the torrent's own (remote, untrusted)
// metadata, not from the request's infohash — so the attack is modelled here
// via a crafted FakeTorrent.files[].path, exercised through the REAL route.
// This must fail RED if api.js/zip.js's containment check is weakened —
// verified manually (see task report) by reproducing with the guard removed.

test('zip: refuses when torrent metadata declares a file path escaping downloadDir', async () => {
  const { app, engine } = buildWithDisk();
  const ih = 'b2'.repeat(20);
  const t = new FakeTorrent(ih, 'Evil', [
    { name: 'passwd', length: 4, path: '../../../../etc/passwd' },
  ]);
  t.progress = 1;
  await addFake(app, engine, t);
  const r = await app.inject({ method: 'GET', url: '/api/v1/torrent/zip/' + ih });
  assert.equal(r.statusCode, 500);
  assert.match(r.json().error, /unsafe file path/);
});

test('zip: one malicious entry aborts the WHOLE archive, never a partial zip of just the safe files', async () => {
  const { app, engine, downloadDir } = buildWithDisk();
  const ih = 'c3'.repeat(20);
  const t = new FakeTorrent(ih, 'Mixed', [
    { name: 'ok.txt', length: 2, path: 'ok.txt' },
    { name: 'evil', length: 4, path: '../outside.txt' },
  ]);
  t.progress = 1;
  await addFake(app, engine, t);
  fs.writeFileSync(path.join(downloadDir, 'ok.txt'), 'ok');
  const r = await app.inject({ method: 'GET', url: '/api/v1/torrent/zip/' + ih });
  assert.equal(r.statusCode, 500);
});
