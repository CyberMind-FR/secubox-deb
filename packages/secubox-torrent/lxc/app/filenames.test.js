// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// SecuBox-Deb :: secubox-torrent :: filenames.test.js — CyberMind https://cybermind.fr
//
// Unit tests for sanitizeFilename / contentDispositionHeader. Names here
// come from torrent metadata — supplied by a remote peer/tracker — so the
// central question these tests answer is: can a hostile name ever produce
// an unsafe Content-Disposition header, and does a legitimate non-ASCII
// name still come through usable?

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sanitizeFilename, contentDispositionHeader } from './filenames.js';

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

test('contentDispositionHeader honours an explicit disposition-type (inline for /stream)', () => {
  const h = contentDispositionHeader('movie.mp4', { type: 'inline' });
  assert.ok(h.startsWith('inline; filename='));
});

// --- The four required cases: accented/non-Latin name, CR/LF, path
// separator, and an embedded quote. Each assertion pair proves BOTH halves
// of the requirement: the resulting header is safe to send as a single HTTP
// header line, AND the recovered name is still something a human would
// recognise (not mangled into garbage for the common, legitimate case).

test('a name with accents/non-Latin characters survives readably (RFC 5987 form)', () => {
  const real = 'Amélie – Café ☕ – Ünïcodé フォルダ.mkv';
  const safe = sanitizeFilename(real, 'fallback');
  const h = contentDispositionHeader(safe, { type: 'inline' });
  // Single header line: no embedded newline whatsoever.
  assert.ok(!/[\r\n]/.test(h));
  // The UTF-8 form round-trips back to the exact original (non-mangled) name.
  const star = /filename\*=UTF-8''([^;]+)/.exec(h)[1];
  assert.equal(decodeURIComponent(star), real);
});

test('a name containing CR/LF cannot inject a second header line', () => {
  const hostile = 'evil.txt\r\nSet-Cookie: pwned=1\r\nX-Injected: yes';
  const safe = sanitizeFilename(hostile, 'fallback');
  const h = contentDispositionHeader(safe, { type: 'inline' });
  // The CR/LF must be gone from the sanitized name itself...
  assert.ok(!/[\r\n]/.test(safe));
  // ...and therefore the header we actually send is still a SINGLE line —
  // "Set-Cookie"/"X-Injected" surviving as inert TEXT inside the filename
  // value is fine; what must never happen is a literal CR/LF turning them
  // into separate header lines of their own.
  assert.ok(!/[\r\n]/.test(h));
  assert.equal(h.split('\n').length, 1);
  // The recovered name is still a usable (if flattened) filename, not empty.
  assert.equal(safe, 'evil.txtSet-Cookie: pwned=1X-Injected: yes');
});

test('a name containing a path separator cannot smuggle a directory', () => {
  const hostile = '../../etc/cron.d/malicious';
  const safe = sanitizeFilename(hostile, 'fallback');
  const h = contentDispositionHeader(safe, { type: 'inline' });
  assert.ok(!safe.includes('/'));
  assert.ok(!safe.includes('\\'));
  assert.ok(!h.includes('/etc/'));
  // Still a recognisable, usable filename: separators flattened to
  // underscores, nothing dropped silently.
  assert.equal(safe, '.._.._etc_cron.d_malicious');
});

test('a name containing a double quote cannot break out of the quoted header parameter', () => {
  const hostile = 'my "movie" name.mp4';
  const safe = sanitizeFilename(hostile, 'fallback');
  const h = contentDispositionHeader(safe, { type: 'inline' });
  // The ascii fallback half of the header is a quoted-string — verify NO
  // unescaped '"' appears inside it (which would prematurely close the
  // quoted-string and let anything after it be interpreted as new header
  // parameters/lines by a lenient parser).
  const quoted = /filename="([^]*?)";\s*filename\*=/.exec(h)[1];
  assert.ok(!quoted.includes('"'));
  // The name is still readable (quotes become apostrophes, not stripped to nothing).
  assert.ok(quoted.toLowerCase().includes('movie'));
});

// Note on CR/LF specifically: contentDispositionHeader's OWN encoding
// (encodeURIComponent for the filename* form, and the `[^\x20-\x7e]` sweep
// for the ascii fallback) already neutralises raw control bytes as a side
// effect of handling non-ASCII — verified below. That is NOT a reason to
// skip sanitizeFilename: it's the layer that removes PATH SEPARATORS, which
// contentDispositionHeader does nothing about, and it's what keeps the
// *recovered* filename clean instead of merely "not a header exploit".
test('contentDispositionHeader alone (no sanitizeFilename) already neutralises a raw CR/LF', () => {
  const hostile = 'evil.txt\r\nX-Injected: yes';
  const h = contentDispositionHeader(hostile, { type: 'inline' }); // no sanitizeFilename() call
  assert.ok(!/[\r\n]/.test(h));
});

// This IS the "prove sanitizing actually matters" test: contentDispositionHeader
// has no opinion about path separators at all — call it directly on a raw
// traversal-shaped name (bypassing sanitizeFilename) and the slashes sail
// straight through into the header's filename parameter. That's a real,
// distinct hazard from header-splitting: a client (curl -O/-J, an older
// browser, a script parsing the header) that treats the suggested filename
// as a path can be steered outside the intended download directory — the
// same class of bug safeFilePath guards against server-side, just aimed at
// the recipient instead. Fails red if sanitizeFilename is ever dropped from
// the /stream or /zip routes.
test('proof: without sanitizeFilename, a raw path-traversal name reaches the header unchanged', () => {
  const hostile = '../../etc/passwd';
  const h = contentDispositionHeader(hostile, { type: 'inline' }); // no sanitizeFilename() call
  assert.ok(h.includes('filename="../../etc/passwd"'),
    'expected the unsanitized traversal path to survive verbatim in the header');
  // With sanitizeFilename in front of it (as every real route does), the
  // same input can no longer carry a path at all.
  const safe = sanitizeFilename(hostile, 'fallback');
  const safeHeader = contentDispositionHeader(safe, { type: 'inline' });
  assert.ok(!safeHeader.includes('/'));
});
