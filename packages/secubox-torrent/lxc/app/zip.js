// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// SecuBox-Deb :: secubox-torrent :: zip.js — CyberMind https://cybermind.fr
//
// Helpers for the ZIP-download route: infohash format validation, the real
// path-traversal gate, and filename sanitizing. Kept pure/synchronous (no fs,
// no network) so they're trivial to unit-test in isolation from Fastify and
// WebTorrent.

import path from 'node:path';
import archiver from 'archiver';

// WebTorrent infoHashes are always a 40-char lowercase hex SHA1 (btih hex).
// This is the first, cheap line of defense on the URL param itself.
const INFOHASH_RE = /^[0-9a-f]{40}$/i;

export function isValidInfohash(s) {
  return typeof s === 'string' && INFOHASH_RE.test(s);
}

// The REAL anti-traversal gate. A torrent's per-file `path` is NOT derived
// from this request — it comes from the torrent's own metadata, which is
// supplied by a remote peer/tracker and must be treated as untrusted input
// (a hostile .torrent can declare a file at "../../../etc/cron.d/x"). This
// resolves the candidate path against downloadDir and refuses anything that
// would land outside it — a `..` anywhere in relPath can never escape.
// Returns the absolute path, or null if it would escape downloadDir.
export function safeFilePath(downloadDir, relPath) {
  if (typeof relPath !== 'string' || !relPath) return null;
  const base = path.resolve(downloadDir);
  const target = path.resolve(base, relPath);
  if (target !== base && !target.startsWith(base + path.sep)) return null;
  return target;
}

// Suggested download filename, derived from the torrent name: no path
// separators (can't smuggle a directory), no control chars (no CR/LF header
// injection into Content-Disposition), trimmed, length-capped, and never
// empty (falls back to the infohash).
export function sanitizeFilename(name, fallback) {
  let n = String(name || '')
    .replace(/[/\\]/g, '_')
    .replace(/[\x00-\x1f\x7f]/g, '')
    .trim();
  if (!n) n = fallback || 'torrent';
  if (n.length > 150) n = n.slice(0, 150);
  return n;
}

// Build a Content-Disposition value that's safe even if the sanitized name
// still contains non-ASCII: an ASCII-only fallback for old clients plus the
// RFC 5987 filename* form for the real (UTF-8) name.
export function contentDispositionHeader(filename) {
  const ascii = filename.replace(/[^\x20-\x7e]/g, '_').replace(/"/g, "'");
  return `attachment; filename="${ascii}"; filename*=UTF-8''${encodeURIComponent(filename)}`;
}

// Build a ZIP archive stream from already-resolved+validated {abs, name}
// entries. store:true (no deflate) — torrent payloads are almost always
// already-compressed media, so deflate would spend CPU this board doesn't
// have to spare for close to 0% size benefit. Each entry is read from disk
// lazily (fs.createReadStream, opened only as archiver drains its queue) —
// finalize() does NOT synchronously produce the archive; bytes are only
// emitted as something reads/pipes the returned stream. See zip.test.js's
// "streams incrementally" test for a direct proof of that property.
export function buildZipArchive(entries, { onError } = {}) {
  const archive = archiver('zip', { store: true });
  // archiver treats a missing file matched by a glob/directory() scan as a
  // soft 'warning' (ENOENT) because an empty glob match is often expected.
  // That default is wrong for us: every entry here is an EXPLICIT file the
  // caller already verified exists (see the /zip route's pre-flight stat
  // pass). If one still vanishes (a race, e.g. purged mid-request), silently
  // dropping it would produce exactly the silently-truncated archive this
  // feature must never hand back — treat every warning as fatal.
  archive.on('warning', (err) => archive.emit('error', err));
  // Self-contained cleanup first (registering it before any caller-supplied
  // handler guarantees it always runs, and avoids a TDZ hazard where an
  // external handler would need to reference `archive` before this function
  // has returned it).
  archive.on('error', () => { try { archive.destroy(); } catch { /* noop */ } });
  if (onError) archive.on('error', onError);
  for (const e of entries) archive.file(e.abs, { name: e.name });
  archive.finalize();
  return archive;
}
