// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// SecuBox-Deb :: secubox-torrent :: zip.test.js — CyberMind https://cybermind.fr
//
// Unit tests for the ZIP-download helpers, in particular the anti
// path-traversal gate (safeFilePath). A torrent's per-file path is untrusted
// (it comes from remote torrent metadata, not this request), so this is the
// real security boundary — see zip.js for the rationale.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import { isValidInfohash, safeFilePath, sanitizeFilename, contentDispositionHeader, buildZipArchive } from './zip.js';

test('isValidInfohash accepts a 40-char hex string, rejects everything else', () => {
  assert.equal(isValidInfohash('a'.repeat(40)), true);
  assert.equal(isValidInfohash('A1B2'.repeat(10)), true); // case-insensitive
  assert.equal(isValidInfohash('a'.repeat(39)), false);   // too short
  assert.equal(isValidInfohash('a'.repeat(41)), false);   // too long
  assert.equal(isValidInfohash('g'.repeat(40)), false);   // non-hex char
  assert.equal(isValidInfohash('../../../../etc/passwd'), false);
  assert.equal(isValidInfohash(''), false);
  assert.equal(isValidInfohash(undefined), false);
});

test('safeFilePath resolves an ordinary relative file under downloadDir', () => {
  const downloadDir = '/data/torrent';
  const abs = safeFilePath(downloadDir, 'My Movie/movie.mp4');
  assert.equal(abs, path.resolve('/data/torrent/My Movie/movie.mp4'));
});

test('safeFilePath REFUSES a traversal that would escape downloadDir', () => {
  const downloadDir = '/data/torrent';
  assert.equal(safeFilePath(downloadDir, '../../../../etc/passwd'), null);
  assert.equal(safeFilePath(downloadDir, '../secrets.json'), null);
  assert.equal(safeFilePath(downloadDir, 'sub/../../escape.txt'), null);
  // Absolute paths inside relPath must not be able to replace the base either.
  assert.equal(safeFilePath(downloadDir, '/etc/passwd'), null);
});

// This is the "prove the protection actually matters" test: it exercises
// the exact same escaping relPath through a NAIVE implementation (plain
// path.join, no resolve+containment check) to show that WITHOUT the guard
// the escape succeeds — i.e. this test fails red if safeFilePath's
// containment check is removed/weakened, and only passes because the guard
// is there. Kept in-repo (rather than only in a throwaway "prove it" run)
// so a future regression that guts the check is caught by CI, not review.
test('the containment check is load-bearing: a naive path.join WOULD escape', () => {
  const downloadDir = '/data/torrent';
  const naiveJoin = path.join(downloadDir, '../../../../etc/passwd');
  // The naive join genuinely leaves downloadDir — proving the scenario is real.
  assert.ok(!naiveJoin.startsWith(path.resolve(downloadDir) + path.sep));
  // The guarded helper must refuse the exact same input.
  assert.equal(safeFilePath(downloadDir, '../../../../etc/passwd'), null);
});

test('safeFilePath allows a relPath that merely LOOKS suspicious but stays inside', () => {
  const downloadDir = '/data/torrent';
  // "..hidden" is not a traversal segment ("..", exactly) — must be allowed.
  const abs = safeFilePath(downloadDir, '..hidden/file.txt');
  assert.equal(abs, path.resolve('/data/torrent/..hidden/file.txt'));
});

test('safeFilePath rejects empty/non-string input', () => {
  assert.equal(safeFilePath('/data/torrent', ''), null);
  assert.equal(safeFilePath('/data/torrent', undefined), null);
});

test('sanitizeFilename strips separators and control chars, falls back when empty', () => {
  assert.equal(sanitizeFilename('My Movie (2024)', 'x'), 'My Movie (2024)');
  assert.equal(sanitizeFilename('a/b\\c', 'x'), 'a_b_c');
  assert.equal(sanitizeFilename('evil\r\nX-Injected: 1', 'x'), 'evilX-Injected: 1');
  assert.equal(sanitizeFilename('', 'fallback-ih'), 'fallback-ih');
  assert.equal(sanitizeFilename(null, 'fallback-ih'), 'fallback-ih');
  assert.equal(sanitizeFilename('   ', 'fallback-ih'), 'fallback-ih');
});

test('sanitizeFilename caps length', () => {
  const long = 'x'.repeat(500);
  assert.equal(sanitizeFilename(long, 'x').length, 150);
});

test('contentDispositionHeader has no raw CR/LF and carries both ascii and utf-8 forms', () => {
  const h = contentDispositionHeader('Café Ünïcode.zip');
  assert.ok(!/[\r\n]/.test(h));
  assert.ok(h.includes('attachment; filename='));
  assert.ok(h.includes("filename*=UTF-8''"));
  assert.ok(h.includes(encodeURIComponent('Café Ünïcode.zip')));
});

// --- buildZipArchive: proves the archive STREAMS as it is consumed, rather
// than being fully constructed in memory/disk before anything is sent. This
// is the requirement that matters most: a torrent can be many GB, and the
// board has already gone down from disk saturation from a similar mistake
// elsewhere. If a future change replaced the streaming pipeline with
// "collect everything into a Buffer, then send" this test goes red.

function makeTmpFile(sizeBytes) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sbx-torrent-zip-'));
  const file = path.join(dir, 'payload.bin');
  fs.writeFileSync(file, Buffer.alloc(sizeBytes, 42));
  return { dir, file };
}

test('buildZipArchive does NOT materialise the archive synchronously on finalize', () => {
  const { file } = makeTmpFile(4 * 1024 * 1024); // 4 MiB — big enough to be conclusive
  const archive = buildZipArchive([{ abs: file, name: 'payload.bin' }]);
  // finalize() has already been called inside buildZipArchive. If the
  // implementation built the whole archive up front (e.g. buffered it into
  // one Buffer before returning), `pointer()` (bytes produced so far) would
  // already be close to the full input size. A lazily-streamed archive has
  // produced ~nothing yet because nothing has started reading it.
  assert.equal(archive.pointer(), 0);
  archive.destroy();
});

test('buildZipArchive delivers the payload across MULTIPLE chunks, not one block', async () => {
  const size = 4 * 1024 * 1024;
  const { file } = makeTmpFile(size);
  const archive = buildZipArchive([{ abs: file, name: 'payload.bin' }]);
  const chunkSizes = [];
  await new Promise((resolve, reject) => {
    archive.on('data', (chunk) => chunkSizes.push(chunk.length));
    archive.on('end', resolve);
    archive.on('error', reject);
  });
  // A single "block" delivery would show up as exactly one chunk covering
  // the whole payload. Real streaming shows many chunks, none anywhere near
  // the full size — proving the response is built incrementally.
  assert.ok(chunkSizes.length > 1, `expected multiple chunks, got ${chunkSizes.length}`);
  assert.ok(chunkSizes.every((n) => n < size), 'no single chunk should carry the whole payload');
  assert.equal(chunkSizes.reduce((a, b) => a + b, 0), archive.pointer());
});

test('buildZipArchive produces a structurally valid ZIP (store mode, no compression)', async () => {
  const content = Buffer.from('hello secubox torrent zip test\n'.repeat(100));
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sbx-torrent-zip-'));
  const file = path.join(dir, 'note.txt');
  fs.writeFileSync(file, content);

  const archive = buildZipArchive([{ abs: file, name: 'sub/note.txt' }]);
  const chunks = [];
  await new Promise((resolve, reject) => {
    archive.on('data', (c) => chunks.push(c));
    archive.on('end', resolve);
    archive.on('error', reject);
  });
  const zipBuf = Buffer.concat(chunks);
  // Local file header magic at the start of the archive.
  assert.equal(zipBuf.subarray(0, 4).toString('hex'), '504b0304');
  // End-of-central-directory magic must appear somewhere near the tail.
  assert.ok(zipBuf.subarray(-64).includes(Buffer.from('504b0506', 'hex')));
  // store:true → the entry's raw bytes appear verbatim in the archive
  // (no deflate framing to unpack for this assertion).
  assert.ok(zipBuf.includes(content));
  // The entry name (including our subfolder) is embedded in the archive.
  assert.ok(zipBuf.includes(Buffer.from('sub/note.txt')));
});

test('buildZipArchive surfaces a missing source file as an error event, not a silent short archive', async () => {
  const missing = path.join(os.tmpdir(), 'sbx-torrent-zip-does-not-exist', 'nope.bin');
  const archive = buildZipArchive([{ abs: missing, name: 'nope.bin' }]);
  let sawError = false;
  await new Promise((resolve) => {
    archive.on('error', () => { sawError = true; resolve(); });
    archive.on('end', resolve);
    archive.resume();
  });
  assert.equal(sawError, true);
});
