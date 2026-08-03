// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// SecuBox-Deb :: secubox-torrent :: filenames.js — CyberMind https://cybermind.fr
//
// Filename sanitizing + Content-Disposition building, shared by every route
// that hands a torrent-derived name back to the browser (/stream, /zip).
// These names come from the torrent's own metadata — supplied by a remote
// peer/tracker — and must never be trusted verbatim in an HTTP header: a
// CR/LF turns into response header injection, an unescaped quote breaks the
// header's own quoting, and a path separator has no business in a suggested
// filename. Non-ASCII (accents, CJK, Cyrillic, …) is routine in torrent
// names and must stay readable — see contentDispositionHeader's RFC 5987
// filename* form, rather than mangling it down to ASCII.

// Suggested filename, derived from a torrent/file name: no path separators
// (can't smuggle a directory), no control chars (blocks CR/LF header
// injection and stray control bytes), trimmed, length-capped, and never
// empty (falls back to the caller-supplied fallback, e.g. the infohash).
export function sanitizeFilename(name, fallback) {
  let n = String(name || '')
    .replace(/[/\\]/g, '_')
    .replace(/[\x00-\x1f\x7f]/g, '')
    .trim();
  if (!n) n = fallback || 'file';
  if (n.length > 150) n = n.slice(0, 150);
  return n;
}

// Build a Content-Disposition value that's safe even if the sanitized name
// still contains non-ASCII: an ASCII-only fallback for old clients (quotes
// stripped, since sanitizeFilename already removed CR/LF/control chars) plus
// the RFC 5987 filename* form carrying the real UTF-8 name for clients that
// understand it (virtually all modern browsers).
//
// `type` is the disposition-type: 'attachment' (default) forces a save
// dialog — right for a whole-folder ZIP. 'inline' tells the browser this may
// be rendered in place (needed for <video>/<audio> src on /stream — an
// unconditional 'attachment' there would force a download instead of
// playing); the filename hint still applies to an explicit save action.
export function contentDispositionHeader(filename, { type = 'attachment' } = {}) {
  const ascii = filename.replace(/[^\x20-\x7e]/g, '_').replace(/"/g, "'");
  return `${type}; filename="${ascii}"; filename*=UTF-8''${encodeURIComponent(filename)}`;
}
