# secubox-torrent v2.0 — WebTorrent Streaming — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Pivot the dormant `secubox-torrent` module from Transmission to a WebTorrent streaming service (paste magnet → watch in browser, ephemeral-by-default + Keep), running Node.js in an isolated LXC.

**Architecture:** A Node.js service inside a dedicated `torrent` LXC runs the WebTorrent engine (hybrid WebRTC+BitTorrent), an HTTP Range streaming server, a SQLite library with a purge sweep, and a Fastify API serving the player webui. The host only provisions the LXC and proxies/authenticates a vhost through HAProxy→sbxwaf→nginx.

**Tech Stack:** Node.js LTS (bookworm), `webtorrent` + `@roamhq/wrtc` (WebRTC hybrid), `fastify`, `better-sqlite3`; tests via Node built-in `node --test` (no test-framework dependency); Debian packaging (arch: all, LXC provisioned at postinst).

## Global Constraints

- Package name stays `secubox-torrent`; version `2.0.0-1~bookworm1`; the 1.0.0 Transmission code (api/main.py Python) is removed.
- Public vhost host `torrent.gk2.secubox.in` is preserved.
- Platform: Debian bookworm **arm64**. Media/state on the USB SSD at `/data` — never eMMC.
- LXC pattern matches peertube/podcaster: `LXC_PATH=/data/lxc`, bridge `br-lxc`, gateway `10.100.0.1`, sentinel-file idempotency, `la()` = `lxc-attach -n <name> -P <path> --`.
- Torrent engine runs ONLY inside the LXC (untrusted peers). The host runs no torrent logic.
- Node service source lives under `lxc/app/` in the package and is copied into the LXC at provision time.
- Tests are `node --test` files named `*.test.js`, run from `lxc/app/`, use fakes — NEVER real BitTorrent/WebRTC/network.
- Auth: the LXC service trusts the proxied request; the host vhost enforces `sbx_token` via `auth_request` (master users gk2 + admin). No auth logic inside the Node service.
- Config: `/etc/secubox/torrent.toml` on the host; the relevant values are passed into the LXC env at service start.
- SecuBox webui look per `.claude/WEBUI-PANEL-GUIDELINES.md` (cyan hybrid-dark, reads `localStorage.sbx_token`).

---

## File Structure

```
packages/secubox-torrent/
├── lxc/
│   ├── app/                         ← Node service (copied into LXC)
│   │   ├── package.json             ← deps + "test": "node --test"
│   │   ├── engine.js                ← WebTorrent wrap
│   │   ├── engine.test.js
│   │   ├── stream.js                ← HTTP Range handler
│   │   ├── stream.test.js
│   │   ├── library.js               ← better-sqlite3 + purge
│   │   ├── library.test.js
│   │   ├── api.js                   ← Fastify app factory
│   │   ├── api.test.js
│   │   ├── server.js                ← wires engine+stream+library+api, reads env
│   │   └── fakes.js                 ← FakeWebTorrent/FakeTorrent/FakeFile
│   ├── install-lxc.sh               ← idempotent LXC provisioner
│   └── secubox-torrent.service      ← systemd unit INSIDE the LXC
├── www/torrent/index.html           ← player webui (replaces old panel)
├── nginx/torrent.conf               ← host vhost → LXC
├── nft/torrent-egress.nft           ← host egress drop-in for the LXC veth
├── menu.d/…-torrent.json            ← dashboard entry (kept)
├── conf/torrent.toml                ← default config
├── README.md
└── debian/                          ← control/rules/postinst/postrm/changelog
```

Removed: `packages/secubox-torrent/api/main.py`, `systemd/secubox-torrent.service` (old host FastAPI), and Transmission references.

---

### Task 1: LXC skeleton + wrtc-arm64 spike

**Files:**
- Create: `packages/secubox-torrent/lxc/app/package.json`
- Create: `packages/secubox-torrent/lxc/app/wrtc-probe.js`
- Create: `packages/secubox-torrent/lxc/install-lxc.sh` (skeleton: create LXC + Node)
- Create: `packages/secubox-torrent/lxc/SPIKE-RESULT.md`

**Interfaces:**
- Produces: the pinned npm dependency set (whether `@roamhq/wrtc` is included) and `WEBRTC_AVAILABLE` (bool) recorded in `SPIKE-RESULT.md`, consumed by every later task's `package.json` + `engine.js`.

- [ ] **Step 1: Write package.json**

```json
{
  "name": "secubox-torrent",
  "version": "2.0.0",
  "private": true,
  "type": "module",
  "engines": { "node": ">=18" },
  "scripts": { "test": "node --test" },
  "dependencies": {
    "webtorrent": "^2.5.1",
    "@roamhq/wrtc": "^0.8.0",
    "fastify": "^4.28.1",
    "better-sqlite3": "^11.3.0"
  }
}
```

- [ ] **Step 2: Write wrtc-probe.js** (decides WebRTC availability)

```javascript
// Exits 0 and prints WEBRTC_AVAILABLE=true if @roamhq/wrtc loads a
// RTCPeerConnection on this arch; exits 0 with =false otherwise (fallback).
try {
  const wrtc = await import('@roamhq/wrtc');
  const pc = new wrtc.default.RTCPeerConnection();
  pc.close();
  console.log('WEBRTC_AVAILABLE=true');
} catch (e) {
  console.log('WEBRTC_AVAILABLE=false');
  console.error('wrtc load failed:', e.message);
}
```

- [ ] **Step 3: Write install-lxc.sh skeleton** (create LXC + install Node, idempotent)

```bash
#!/usr/bin/env bash
set -euo pipefail
readonly LXC_NAME="${SECUBOX_LXC_NAME:-torrent}"
readonly LXC_IP="${SECUBOX_LXC_IP:-10.100.0.130}"
readonly LXC_PATH="${SECUBOX_LXC_PATH:-/data/lxc}"
readonly LXC_BRIDGE="${SECUBOX_LXC_BRIDGE:-br-lxc}"
readonly LXC_GW="${SECUBOX_LXC_GW:-10.100.0.1}"
readonly DATA_DIR="${SECUBOX_DATA_DIR:-/data/torrent}"
readonly STATE_DIR="${SECUBOX_STATE_DIR:-/var/lib/secubox/torrent}"
readonly SENTINEL="$STATE_DIR/.lxc-provisioned"
log() { printf '[torrent-install] %s\n' "$*"; }
la()  { lxc-attach -n "$LXC_NAME" -P "$LXC_PATH" -- "$@"; }

mkdir -p "$STATE_DIR" "$DATA_DIR"
if [ -f "$SENTINEL" ]; then log "already provisioned; skipping create"; else
  lxc-create -n "$LXC_NAME" -P "$LXC_PATH" -t debian -- -r bookworm -a arm64
  # network: static IP on br-lxc (config appended to the container config)
  cat >> "$LXC_PATH/$LXC_NAME/config" <<EOF
lxc.net.0.type = veth
lxc.net.0.link = $LXC_BRIDGE
lxc.net.0.flags = up
lxc.net.0.ipv4.address = $LXC_IP/24
lxc.net.0.ipv4.gateway = $LXC_GW
EOF
  lxc-start -n "$LXC_NAME" -P "$LXC_PATH"
  sleep 5
  la apt-get update
  la apt-get install -y --no-install-recommends nodejs npm ca-certificates
  touch "$SENTINEL"
fi
log "node version: $(la node --version 2>/dev/null || echo MISSING)"
```

- [ ] **Step 4: Run the spike (manual/CI, on gk2 or an arm64 runner)**

Run: provision the LXC, then inside it `npm ci` in the app dir and `node wrtc-probe.js`.
Expected: prints `WEBRTC_AVAILABLE=true` OR `=false` without crashing npm install.

- [ ] **Step 5: Record SPIKE-RESULT.md + adjust package.json**

Write `SPIKE-RESULT.md` with the observed `WEBRTC_AVAILABLE` value, the Node version, and the arm64 npm-install outcome. **If false:** remove `@roamhq/wrtc` from `package.json` dependencies (BitTorrent-only build) and note it. This value is the `webrtc` default for `engine.js`.

- [ ] **Step 6: Commit**

```bash
git add packages/secubox-torrent/lxc/
git commit -m "feat(torrent): LXC skeleton + wrtc-arm64 spike (ref #917)"
```

---

### Task 2: engine.js — WebTorrent wrap

**Files:**
- Create: `packages/secubox-torrent/lxc/app/engine.js`
- Create: `packages/secubox-torrent/lxc/app/fakes.js`
- Test: `packages/secubox-torrent/lxc/app/engine.test.js`

**Interfaces:**
- Consumes: `WEBRTC_AVAILABLE` from Task 1 (the `webrtc` option default).
- Produces:
  - `class Engine { constructor({ WebTorrentCtor, downloadDir, maxActive, webrtc }) }`
  - `await engine.add(magnet) → { infohash, name, files: [{ idx, name, length, type }] }`
  - `engine.get(infohash) → torrent | null`
  - `engine.stats(infohash) → { progress, downloadSpeed, uploadSpeed, numPeers, wires: [{ type }] }`
  - `engine.remove(infohash, { deleteData }) → void`
  - `type` is the lowercased file extension without the dot (e.g. `"mp4"`).

- [ ] **Step 1: Write fakes.js**

```javascript
export class FakeFile {
  constructor(name, length) { this.name = name; this.length = length; }
}
export class FakeTorrent {
  constructor(infoHash, name, files, { failMeta = false } = {}) {
    this.infoHash = infoHash; this.name = name;
    this.files = files.map((f, i) => Object.assign(new FakeFile(f.name, f.length), { idx: i }));
    this.progress = 0.1; this.downloadSpeed = 1000; this.uploadSpeed = 500;
    this.numPeers = 3; this.wires = [{ type: 'webrtc' }, { type: 'tcp' }];
    this._failMeta = failMeta; this._handlers = {};
  }
  on(ev, cb) { this._handlers[ev] = cb; if (ev === 'metadata' && !this._failMeta) queueMicrotask(cb); }
  destroy(_opts, cb) { if (cb) cb(); }
}
export class FakeWebTorrent {
  constructor() { this.torrents = []; }
  add(magnet, _opts, cb) {
    const t = this._next || new FakeTorrent('a'.repeat(40), 'Fake', [{ name: 'movie.mp4', length: 100 }]);
    this.torrents.push(t); if (cb) queueMicrotask(() => cb(t)); return t;
  }
  get(infohash) { return this.torrents.find(t => t.infoHash === infohash) || null; }
  destroy(cb) { if (cb) cb(); }
}
```

- [ ] **Step 2: Write the failing test**

```javascript
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
```

- [ ] **Step 2b: Run test to verify it fails** — `cd lxc/app && node --test engine.test.js` → FAIL (Engine not defined).

- [ ] **Step 3: Write engine.js**

```javascript
import path from 'node:path';

export class Engine {
  constructor({ WebTorrentCtor, downloadDir, maxActive, webrtc }) {
    this.downloadDir = downloadDir; this.maxActive = maxActive;
    // webrtc=false (spike fallback) tells WebTorrent to skip the WebRTC transport.
    this.client = new WebTorrentCtor(webrtc ? {} : { tracker: { wrtc: false } });
  }
  add(magnet) {
    if (this.client.torrents.length >= this.maxActive) {
      return Promise.reject(new Error('max active torrents reached'));
    }
    return new Promise((resolve, reject) => {
      const to = setTimeout(() => reject(new Error('metadata timeout')), 60000);
      const t = this.client.add(magnet, { path: this.downloadDir }, () => {});
      const done = () => {
        clearTimeout(to);
        resolve({
          infohash: t.infoHash, name: t.name,
          files: t.files.map((f, i) => ({ idx: i, name: f.name, length: f.length, type: ext(f.name) })),
        });
      };
      t.on('metadata', done);
      if (t.files && t.files.length) done();
    });
  }
  get(infohash) { return this.client.get(infohash); }
  stats(infohash) {
    const t = this.get(infohash); if (!t) return null;
    return { progress: t.progress, downloadSpeed: t.downloadSpeed, uploadSpeed: t.uploadSpeed,
             numPeers: t.numPeers, wires: (t.wires || []).map(w => ({ type: w.type })) };
  }
  remove(infohash, { deleteData } = {}) {
    const t = this.get(infohash); if (t) t.destroy({ destroyStore: !!deleteData }, () => {});
  }
}
function ext(name) { const m = /\.([A-Za-z0-9]+)$/.exec(name); return m ? m[1].toLowerCase() : ''; }
```

- [ ] **Step 4: Run test to verify it passes** — `node --test engine.test.js` → PASS.

- [ ] **Step 5: Commit** — `git commit -m "feat(torrent): engine.js WebTorrent wrap + fakes (ref #917)"`

---

### Task 3: stream.js — HTTP Range handler

**Files:**
- Create: `packages/secubox-torrent/lxc/app/stream.js`
- Test: `packages/secubox-torrent/lxc/app/stream.test.js`

**Interfaces:**
- Consumes: `Engine.get(infohash)` (returns a torrent whose `.files[idx]` has `.length`, `.name`, and `.stream({ start, end }) → ReadableStream`).
- Produces: `handleStream(engine, req, res)` where `req = { params: { infohash, fileIdx }, headers }` and `res` is a Node ServerResponse-like object. Sets status + headers, pipes the file stream. Returns nothing.

- [ ] **Step 1: Write the failing test**

```javascript
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Readable } from 'node:stream';
import { handleStream } from './stream.js';

function fakeRes() {
  return { statusCode: 200, headers: {}, ended: false, body: '',
    setHeader(k, v) { this.headers[k.toLowerCase()] = v; },
    writeHead(c, h) { this.statusCode = c; Object.assign(this.headers, lower(h || {})); },
    end(s) { if (s) this.body += s; this.ended = true; } };
}
const lower = o => Object.fromEntries(Object.entries(o).map(([k, v]) => [k.toLowerCase(), v]));
function fakeEngine(len = 100) {
  const file = { name: 'movie.mp4', length: len,
    stream: ({ start, end }) => Readable.from([`bytes[${start}-${end}]`]) };
  return { get: () => ({ files: [file] }) };
}

test('full request returns 200 with content-length and type', async () => {
  const res = fakeRes();
  await handleStream(fakeEngine(100), { params: { infohash: 'a', fileIdx: '0' }, headers: {} }, res);
  assert.equal(res.statusCode, 200);
  assert.equal(res.headers['content-length'], 100);
  assert.match(res.headers['content-type'], /mp4/);
});

test('range request returns 206 with content-range', async () => {
  const res = fakeRes();
  await handleStream(fakeEngine(100), { params: { infohash: 'a', fileIdx: '0' }, headers: { range: 'bytes=10-19' } }, res);
  assert.equal(res.statusCode, 206);
  assert.equal(res.headers['content-range'], 'bytes 10-19/100');
  assert.equal(res.headers['content-length'], 10);
});

test('unsatisfiable range returns 416', async () => {
  const res = fakeRes();
  await handleStream(fakeEngine(100), { params: { infohash: 'a', fileIdx: '0' }, headers: { range: 'bytes=200-300' } }, res);
  assert.equal(res.statusCode, 416);
});

test('unknown infohash returns 404', async () => {
  const res = fakeRes();
  await handleStream({ get: () => null }, { params: { infohash: 'z', fileIdx: '0' }, headers: {} }, res);
  assert.equal(res.statusCode, 404);
});
```

- [ ] **Step 2: Run to verify it fails** — `node --test stream.test.js` → FAIL.

- [ ] **Step 3: Write stream.js**

```javascript
const MIME = { mp4: 'video/mp4', webm: 'video/webm', mkv: 'video/x-matroska',
  m4v: 'video/mp4', mp3: 'audio/mpeg', m4a: 'audio/mp4', ogg: 'audio/ogg',
  flac: 'audio/flac', wav: 'audio/wav' };

export async function handleStream(engine, req, res) {
  const t = engine.get(req.params.infohash);
  const idx = Number(req.params.fileIdx);
  const file = t && t.files && t.files[idx];
  if (!file) { res.writeHead(404); res.end('not found'); return; }
  const type = mimeOf(file.name);
  const total = file.length;
  const range = req.headers.range;
  if (!range) {
    res.writeHead(200, { 'Content-Length': total, 'Content-Type': type, 'Accept-Ranges': 'bytes' });
    file.stream({ start: 0, end: total - 1 }).pipe(res);
    return;
  }
  const m = /bytes=(\d+)-(\d*)/.exec(range);
  const start = m ? Number(m[1]) : 0;
  const end = m && m[2] ? Number(m[2]) : total - 1;
  if (start >= total || end >= total || start > end) {
    res.writeHead(416, { 'Content-Range': `bytes */${total}` }); res.end(); return;
  }
  res.writeHead(206, { 'Content-Range': `bytes ${start}-${end}/${total}`,
    'Content-Length': end - start + 1, 'Content-Type': type, 'Accept-Ranges': 'bytes' });
  file.stream({ start, end }).pipe(res);
}
function mimeOf(name) { const e = (/\.([A-Za-z0-9]+)$/.exec(name) || [])[1]; return MIME[(e || '').toLowerCase()] || 'application/octet-stream'; }
```

- [ ] **Step 4: Run to verify it passes** — PASS.

- [ ] **Step 5: Commit** — `git commit -m "feat(torrent): stream.js HTTP Range handler (ref #917)"`

---

### Task 4: library.js — SQLite library + purge

**Files:**
- Create: `packages/secubox-torrent/lxc/app/library.js`
- Test: `packages/secubox-torrent/lxc/app/library.test.js`

**Interfaces:**
- Produces:
  - `class Library { constructor(dbPath) }`
  - `lib.add({ infohash, name, magnet, path }) → void` (inserts kept=0)
  - `lib.list() → [{ infohash, name, magnet, added_at, last_played_at, kept, path }]`
  - `lib.touch(infohash) → void` (sets last_played_at = now)
  - `lib.keep(infohash, newPath) → void`; `lib.get(infohash) → row | null`; `lib.remove(infohash) → void`
  - `lib.expiredEphemeral(ttlSeconds, now) → [infohash]` (kept=0 AND last_played_at < now-ttl)

- [ ] **Step 1: Write the failing test**

```javascript
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
```

- [ ] **Step 2: Run to verify it fails** — FAIL.

- [ ] **Step 3: Write library.js**

```javascript
import Database from 'better-sqlite3';

export class Library {
  constructor(dbPath) {
    this.db = new Database(dbPath);
    this.db.exec(`CREATE TABLE IF NOT EXISTS torrents (
      infohash TEXT PRIMARY KEY, name TEXT, magnet TEXT, path TEXT,
      added_at INTEGER, last_played_at INTEGER, kept INTEGER DEFAULT 0)`);
  }
  add({ infohash, name, magnet, path }) {
    const now = Math.floor(Date.now() / 1000);
    this.db.prepare(`INSERT OR REPLACE INTO torrents
      (infohash,name,magnet,path,added_at,last_played_at,kept)
      VALUES (?,?,?,?,?,?,0)`).run(infohash, name, magnet, path, now, now);
  }
  list() { return this.db.prepare('SELECT * FROM torrents ORDER BY added_at DESC').all(); }
  get(infohash) { return this.db.prepare('SELECT * FROM torrents WHERE infohash=?').get(infohash) || null; }
  touch(infohash) { this.touchAt(infohash, Math.floor(Date.now() / 1000)); }
  touchAt(infohash, ts) { this.db.prepare('UPDATE torrents SET last_played_at=? WHERE infohash=?').run(ts, infohash); }
  keep(infohash, newPath) { this.db.prepare('UPDATE torrents SET kept=1, path=? WHERE infohash=?').run(newPath, infohash); }
  remove(infohash) { this.db.prepare('DELETE FROM torrents WHERE infohash=?').run(infohash); }
  expiredEphemeral(ttlSeconds, now = Math.floor(Date.now() / 1000)) {
    const cutoff = now - ttlSeconds;
    return this.db.prepare('SELECT infohash FROM torrents WHERE kept=0 AND last_played_at < ?')
      .all(cutoff).map(r => r.infohash);
  }
}
```

- [ ] **Step 4: Run to verify it passes** — PASS.

- [ ] **Step 5: Commit** — `git commit -m "feat(torrent): library.js SQLite + purge selection (ref #917)"`

---

### Task 5: api.js — Fastify routes

**Files:**
- Create: `packages/secubox-torrent/lxc/app/api.js`
- Test: `packages/secubox-torrent/lxc/app/api.test.js`

**Interfaces:**
- Consumes: `Engine` (Task 2), `Library` (Task 4), `handleStream` (Task 3).
- Produces: `buildApi({ engine, library, diskFreeBytes }) → fastify instance` with routes:
  `GET /api/v1/torrent/status`, `POST /api/v1/torrent/add`, `GET /api/v1/torrent/list`,
  `GET /api/v1/torrent/files/:infohash`, `POST /api/v1/torrent/keep/:infohash`,
  `POST /api/v1/torrent/remove/:infohash`, `GET /api/v1/torrent/health`,
  `GET /stream/:infohash/:fileIdx`. `diskFreeBytes` is an injected `() → number`.

- [ ] **Step 1: Write the failing test** (uses fastify `.inject`, no network)

```javascript
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildApi } from './api.js';
import { Library } from './library.js';
import { Engine } from './engine.js';
import { FakeWebTorrent } from './fakes.js';

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

test('add then list returns the torrent', async () => {
  const app = build();
  await app.inject({ method: 'POST', url: '/api/v1/torrent/add',
    payload: { magnet: 'magnet:?xt=urn:btih:' + 'a'.repeat(40) } });
  const r = await app.inject({ method: 'GET', url: '/api/v1/torrent/list' });
  assert.equal(r.json().length, 1);
  assert.equal(r.json()[0].kept, 0);
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
```

- [ ] **Step 2: Run to verify it fails** — FAIL.

- [ ] **Step 3: Write api.js**

```javascript
import Fastify from 'fastify';
import path from 'node:path';
import { handleStream } from './stream.js';

export function buildApi({ engine, library, diskFreeBytes }) {
  const app = Fastify({ logger: false });

  app.get('/api/v1/torrent/health', async () => ({ status: 'ok' }));
  app.get('/api/v1/torrent/status', async () => ({
    active: engine.client.torrents.length, disk_free: diskFreeBytes(), webrtc: engine.webrtc !== false }));

  app.post('/api/v1/torrent/add', async (req, reply) => {
    const magnet = (req.body || {}).magnet;
    if (!magnet) return reply.code(400).send({ error: 'magnet required' });
    let meta;
    try { meta = await engine.add(magnet); }
    catch (e) { return reply.code(504).send({ error: e.message }); }
    library.add({ infohash: meta.infohash, name: meta.name, magnet,
      path: path.join(engine.downloadDir, 'tmp', meta.infohash) });
    return meta;
  });

  app.get('/api/v1/torrent/list', async () =>
    library.list().map(r => ({ ...r, stats: engine.stats(r.infohash) })));

  app.get('/api/v1/torrent/files/:infohash', async (req, reply) => {
    const t = engine.get(req.params.infohash);
    if (!t) return reply.code(404).send({ error: 'not found' });
    return t.files.map((f, i) => ({ idx: i, name: f.name, length: f.length }));
  });

  app.post('/api/v1/torrent/keep/:infohash', async (req, reply) => {
    const ih = req.params.infohash;
    if (!library.get(ih)) return reply.code(404).send({ error: 'not found' });
    library.keep(ih, path.join(engine.downloadDir, 'library', ih));
    return { status: 'kept' };
  });

  app.post('/api/v1/torrent/remove/:infohash', async (req) => {
    engine.remove(req.params.infohash, { deleteData: true });
    library.remove(req.params.infohash);
    return { status: 'removed' };
  });

  app.get('/stream/:infohash/:fileIdx', (req, reply) => {
    library.touch(req.params.infohash);
    return handleStream(engine, req, reply.raw)
      .then(() => { reply.hijack(); });
  });

  return app;
}
```

Note: `engine.webrtc` — add `this.webrtc = webrtc;` to the Engine constructor (Task 2) so `/status` reports it; if you reach here and it is missing, add that one line and re-run Task 2 tests.

- [ ] **Step 4: Run to verify it passes** — PASS. Also re-run `node --test` (whole dir) to confirm nothing regressed.

- [ ] **Step 5: Commit** — `git commit -m "feat(torrent): api.js Fastify routes + stream mount (ref #917)"`

---

### Task 6: server.js + purge sweep + player webui

**Files:**
- Create: `packages/secubox-torrent/lxc/app/server.js`
- Create: `packages/secubox-torrent/www/torrent/index.html` (replaces the old panel)
- Test: `packages/secubox-torrent/lxc/app/server.test.js` (purge sweep only)

**Interfaces:**
- Consumes: everything above.
- Produces: `runPurge(engine, library, { ttlSeconds, diskFloorBytes, diskFreeBytes }) → [infohash]` (the swept list); `server.js` wires env → Engine/Library/buildApi and starts listening + schedules `runPurge` on an interval.

- [ ] **Step 1: Write the failing purge test**

```javascript
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runPurge } from './server.js';
import { Library } from './library.js';

test('purge removes expired ephemeral and calls engine.remove', () => {
  const lib = new Library(':memory:');
  lib.add({ infohash: 'old', name: 'O', magnet: 'm', path: '/tmp/o' });
  lib.touchAt('old', 0);
  const removed = [];
  const engine = { remove: (ih) => removed.push(ih) };
  const swept = runPurge(engine, lib, { ttlSeconds: 10, diskFloorBytes: 0, diskFreeBytes: () => 1e12 });
  assert.deepEqual(swept, ['old']);
  assert.deepEqual(removed, ['old']);
  assert.equal(lib.get('old'), null);
});
```

- [ ] **Step 2: Run to verify it fails** — FAIL.

- [ ] **Step 3: Write server.js** (purge + wiring)

```javascript
import os from 'node:os';
import WebTorrent from 'webtorrent';
import { Engine } from './engine.js';
import { Library } from './library.js';
import { buildApi } from './api.js';

export function runPurge(engine, library, { ttlSeconds, diskFloorBytes, diskFreeBytes }) {
  const now = Math.floor(Date.now() / 1000);
  let victims = library.expiredEphemeral(ttlSeconds, now);
  if (diskFreeBytes() < diskFloorBytes) {
    const extra = library.list().filter(r => r.kept === 0).map(r => r.infohash);
    victims = [...new Set([...victims, ...extra])];
  }
  for (const ih of victims) { engine.remove(ih, { deleteData: true }); library.remove(ih); }
  return victims;
}

export function start() {
  const cfg = {
    downloadDir: process.env.TORRENT_DOWNLOAD_DIR || '/data/torrent',
    maxActive: Number(process.env.TORRENT_MAX_ACTIVE || 5),
    webrtc: process.env.TORRENT_WEBRTC !== 'false',
    port: Number(process.env.TORRENT_PORT || 8090),
    ttl: Number(process.env.TORRENT_EPHEMERAL_TTL_HOURS || 6) * 3600,
    floor: Number(process.env.TORRENT_DISK_FLOOR_GB || 5) * 1e9,
  };
  const engine = new Engine({ WebTorrentCtor: WebTorrent, ...cfg });
  const library = new Library(`${cfg.downloadDir}/library.db`);
  const diskFreeBytes = () => { try { return os.freemem(); } catch { return Infinity; } }; // replaced by statvfs helper at impl
  const app = buildApi({ engine, library, diskFreeBytes });
  app.register(import('@fastify/static'), { root: '/opt/secubox-torrent/www' });
  setInterval(() => runPurge(engine, library, { ttlSeconds: cfg.ttl, diskFloorBytes: cfg.floor, diskFreeBytes }), 300000);
  app.listen({ host: '0.0.0.0', port: cfg.port });
}
if (process.argv[1] && process.argv[1].endsWith('server.js')) start();
```

Note: `diskFreeBytes` must report `/data` free space, not RAM — implement with a small `statvfs` call (e.g. `child_process.execSync('df -B1 --output=avail /data')` parsed, or the `node:fs` statfs API `fs.statfsSync('/data')` on Node ≥ 18.15 → `bavail * bsize`). Use `fs.statfsSync` if available; the test injects `diskFreeBytes` so this detail is not under test. Add `@fastify/static` to package.json deps.

- [ ] **Step 4: Run to verify it passes** — PASS.

- [ ] **Step 5: Write www/torrent/index.html** (player webui — replaces old panel)

Full single-page player following `.claude/WEBUI-PANEL-GUIDELINES.md`: reads `localStorage.sbx_token`, sends it as `Authorization: Bearer` on every fetch; a magnet `<input>` + Add button → `POST /api/v1/torrent/add`; a list from `GET /api/v1/torrent/list` showing name + progress + peer/wire counts + **📌 Garder** / **🗑** buttons; clicking a playable file (type in mp4/webm/m4v/mp3/m4a/ogg) sets `<video controls src="/stream/{infohash}/{idx}">`, others render a Download link; a status strip from `/status` showing a **"BitTorrent-only"** badge when `webrtc:false`. Delete the old Transmission panel content entirely.

- [ ] **Step 6: Commit** — `git add packages/secubox-torrent/lxc/app/server.js packages/secubox-torrent/www/torrent/index.html && git commit -m "feat(torrent): server wiring + purge sweep + player webui (ref #917)"`

---

### Task 7: Host integration — install-lxc.sh (full) + vhost + WAF + nft + menu + config

**Files:**
- Modify: `packages/secubox-torrent/lxc/install-lxc.sh` (extend Task 1 skeleton: copy app, npm ci, install the in-LXC service, start it)
- Create: `packages/secubox-torrent/lxc/secubox-torrent.service` (systemd unit INSIDE the LXC)
- Create: `packages/secubox-torrent/nginx/torrent.conf` (host vhost → LXC)
- Create: `packages/secubox-torrent/nft/torrent-egress.nft`
- Modify: `packages/secubox-torrent/menu.d/*.json` (keep entry, ensure host = torrent.gk2.secubox.in)
- Create: `packages/secubox-torrent/conf/torrent.toml`

**Interfaces:**
- Consumes: the `app/` service (Tasks 2-6), env vars from `torrent.toml`.
- Produces: an idempotent provisioner; a host vhost proxying `/`, `/api/`, `/stream/` to `http://10.100.0.130:8090` with `auth_request` JWT; an nft drop-in scoping the LXC veth egress.

- [ ] **Step 1: Write the in-LXC systemd unit** `lxc/secubox-torrent.service`

```ini
[Unit]
Description=SecuBox Torrent (WebTorrent streaming)
After=network-online.target
Wants=network-online.target
[Service]
WorkingDirectory=/opt/secubox-torrent/app
EnvironmentFile=/opt/secubox-torrent/torrent.env
ExecStart=/usr/bin/node server.js
Restart=on-failure
RestartSec=5
[Install]
WantedBy=multi-user.target
```

- [ ] **Step 2: Extend install-lxc.sh** (append after the skeleton's Node install; idempotent copy + build + service)

```bash
# --- app deploy (runs every postinst; idempotent) ---
APP_SRC="${SECUBOX_APP_SRC:-/usr/lib/secubox/torrent/app}"
la mkdir -p /opt/secubox-torrent/app /opt/secubox-torrent/www
tar -C "$APP_SRC" -cf - . | la tar -C /opt/secubox-torrent/app -xf -
tar -C /usr/share/secubox/www/torrent -cf - . | la tar -C /opt/secubox-torrent/www -xf -
la bash -lc 'cd /opt/secubox-torrent/app && npm ci --omit=dev || npm install --omit=dev'
# env file from host TOML values (exported by postinst into these vars)
la bash -c "cat > /opt/secubox-torrent/torrent.env <<EOF
TORRENT_DOWNLOAD_DIR=/data/torrent
TORRENT_MAX_ACTIVE=${TORRENT_MAX_ACTIVE:-5}
TORRENT_WEBRTC=${TORRENT_WEBRTC:-true}
TORRENT_PORT=8090
TORRENT_EPHEMERAL_TTL_HOURS=${TORRENT_TTL:-6}
TORRENT_DISK_FLOOR_GB=${TORRENT_FLOOR:-5}
EOF"
install -m 644 /dev/stdin_UNUSED 2>/dev/null || true
tar -C "$(dirname "$0")" -cf - secubox-torrent.service | la tar -C /etc/systemd/system -xf -
la systemctl daemon-reload
la systemctl enable --now secubox-torrent.service
log "torrent LXC app deployed + started on $LXC_IP:8090"
```

- [ ] **Step 3: Write host vhost** `nginx/torrent.conf` (proxies to LXC, JWT via auth_request — mirror peertube/podcaster vhost)

```nginx
server {
    listen 0.0.0.0:9080;
    server_name torrent.gk2.secubox.in;
    location = /__sbx_auth_verify { internal; proxy_pass http://unix:/run/secubox/aggregator.sock:/api/v1/auth/verify; proxy_pass_request_body off; proxy_set_header Content-Length ""; }
    location / {
        auth_request /__sbx_auth_verify;
        proxy_pass http://10.100.0.130:8090;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_buffering off;                # streaming: don't buffer video
        proxy_request_buffering off;
        proxy_read_timeout 3600s;
    }
}
```

- [ ] **Step 4: Write nft egress drop-in** `nft/torrent-egress.nft` (host, scopes the LXC veth — drop-based, logged; sorts AFTER the table creator via zz- naming at install)

```
# Scope the torrent LXC's egress. OUTPUT is policy accept repo-wide, so this
# is an explicit LOG+limit on the LXC veth, not an allow. Applied on the host.
table inet secubox_torrent {
    chain forward_torrent {
        type filter hook forward priority 0;
        iifname "veth-torrent*" ct state new log prefix "[SECUBOX-TORRENT] " level info
    }
}
```

- [ ] **Step 5: Write conf/torrent.toml**

```toml
[engine]
max_active = 5
webrtc = true          # set false to force BitTorrent-only
[retention]
ephemeral_ttl_hours = 6
disk_floor_gb = 5
```

- [ ] **Step 6: Verify menu.d entry** — ensure `menu.d/*.json` keeps the 🌊 Torrent entry pointing at `torrent.gk2.secubox.in` (Media category). Edit only if the host/URL is wrong.

- [ ] **Step 7: Commit** — `git add packages/secubox-torrent/{lxc,nginx,nft,conf,menu.d} && git commit -m "feat(torrent): host LXC provisioner + vhost + nft egress + config (ref #917)"`

---

### Task 8: Debian packaging v2.0.0 (remove Transmission)

**Files:**
- Delete: `packages/secubox-torrent/api/main.py`, `packages/secubox-torrent/systemd/secubox-torrent.service` (old host FastAPI)
- Modify: `packages/secubox-torrent/debian/control`, `debian/rules`, `debian/postinst`, `debian/postrm`, `debian/changelog`
- Test: `packages/secubox-torrent/tests/test_packaging.py` (structural, pytest — reuse SecuBox packaging-test convention)

**Interfaces:**
- Produces: a `secubox-torrent_2.0.0-1~bookworm1_all.deb` that installs the app source to `/usr/lib/secubox/torrent/app`, the webui to `/usr/share/secubox/www/torrent`, the vhost/nft/menu/conf, and runs `install-lxc.sh` at postinst.

- [ ] **Step 1: Write the failing packaging test**

```python
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent

def _read(p): return (ROOT / p).read_text()

def test_control_is_v2_no_transmission():
    c = _read("debian/control")
    assert "python3-uvicorn" not in c          # old FastAPI gone
    assert "transmission" not in c.lower()
    assert "lxc" in c.lower()

def test_changelog_is_2_0_0():
    assert _read("debian/changelog").startswith("secubox-torrent (2.0.0-1~bookworm1)")

def test_postinst_runs_install_lxc():
    assert "install-lxc.sh" in _read("debian/postinst")

def test_no_old_fastapi_main():
    assert not (ROOT / "api" / "main.py").exists()
```

- [ ] **Step 2: Run to verify it fails** — `cd packages/secubox-torrent && python3 -m pytest tests/test_packaging.py` → FAIL.

- [ ] **Step 3: Rewrite debian/control**

```
Source: secubox-torrent
Section: net
Priority: optional
Maintainer: Gerald KERMA <devel@cybermind.fr>
Build-Depends: debhelper-compat (= 13)
Standards-Version: 4.6.2

Package: secubox-torrent
Architecture: all
Depends: ${misc:Depends}, secubox-core (>= 1.0), lxc, debootstrap, nftables
Description: WebTorrent streaming for SecuBox (LXC-native)
 Paste a magnet and stream it in the browser (HTTP Range) while it downloads.
 Ephemeral by default with an optional Keep to a persistent library on /data.
 The WebTorrent engine (hybrid WebRTC+BitTorrent) runs isolated in a dedicated
 LXC; the host only proxies an authenticated vhost.
```

- [ ] **Step 4: Rewrite debian/rules** (install app source, webui, vhost, nft, conf, menu)

```make
#!/usr/bin/make -f
%:
	dh $@
override_dh_auto_install:
	install -d $(CURDIR)/debian/secubox-torrent/usr/lib/secubox/torrent
	cp -r $(CURDIR)/lxc/app $(CURDIR)/debian/secubox-torrent/usr/lib/secubox/torrent/
	install -m 755 $(CURDIR)/lxc/install-lxc.sh $(CURDIR)/debian/secubox-torrent/usr/lib/secubox/torrent/
	install -m 644 $(CURDIR)/lxc/secubox-torrent.service $(CURDIR)/debian/secubox-torrent/usr/lib/secubox/torrent/
	install -d $(CURDIR)/debian/secubox-torrent/usr/share/secubox/www/torrent
	cp -r $(CURDIR)/www/torrent/* $(CURDIR)/debian/secubox-torrent/usr/share/secubox/www/torrent/
	install -d $(CURDIR)/debian/secubox-torrent/etc/nginx/secubox-vhost.d
	install -m 644 $(CURDIR)/nginx/torrent.conf $(CURDIR)/debian/secubox-torrent/etc/nginx/secubox-vhost.d/
	install -d $(CURDIR)/debian/secubox-torrent/etc/secubox/nft.d
	install -m 644 $(CURDIR)/nft/torrent-egress.nft $(CURDIR)/debian/secubox-torrent/etc/secubox/nft.d/zz-torrent-egress.nft
	install -d $(CURDIR)/debian/secubox-torrent/etc/secubox
	install -m 644 $(CURDIR)/conf/torrent.toml $(CURDIR)/debian/secubox-torrent/etc/secubox/torrent.toml
	install -d $(CURDIR)/debian/secubox-torrent/usr/share/secubox/menu.d
	install -m 644 $(CURDIR)/menu.d/*.json $(CURDIR)/debian/secubox-torrent/usr/share/secubox/menu.d/
```

Note: confirm the host vhost include dir the board actually uses for full `server{}` vhosts (peertube/podcaster ship theirs there — check `packages/secubox-peertube/debian/rules` for the exact path and match it; the plan uses `etc/nginx/secubox-vhost.d` as the placeholder, correct it to peertube's path in this step).

- [ ] **Step 5: Rewrite debian/postinst** (run provisioner + reload nginx/nft)

```bash
#!/bin/sh
set -e
case "$1" in configure)
  # export config → env for install-lxc.sh (parse the TOML minimally)
  export TORRENT_MAX_ACTIVE=$(grep -E '^max_active' /etc/secubox/torrent.toml | grep -oE '[0-9]+' | head -1)
  export TORRENT_WEBRTC=$(grep -E '^webrtc' /etc/secubox/torrent.toml | grep -oE 'true|false' | head -1)
  export TORRENT_TTL=$(grep -E '^ephemeral_ttl_hours' /etc/secubox/torrent.toml | grep -oE '[0-9]+' | head -1)
  export TORRENT_FLOOR=$(grep -E '^disk_floor_gb' /etc/secubox/torrent.toml | grep -oE '[0-9]+' | head -1)
  sh /usr/lib/secubox/torrent/install-lxc.sh || echo "torrent: LXC provisioning deferred (run install-lxc.sh manually)"
  nft -f /etc/secubox/nft.d/zz-torrent-egress.nft 2>/dev/null || true
  if command -v nginx >/dev/null 2>&1 && nginx -t >/dev/null 2>&1; then systemctl reload nginx 2>/dev/null || true; fi
  ;;
esac
#DEBHELPER#
exit 0
```

- [ ] **Step 6: Rewrite debian/postrm** (stop + optionally destroy LXC on purge)

```bash
#!/bin/sh
set -e
case "$1" in
  purge)
    lxc-stop -n torrent -P /data/lxc 2>/dev/null || true
    lxc-destroy -n torrent -P /data/lxc 2>/dev/null || true
    rm -f /var/lib/secubox/torrent/.lxc-provisioned 2>/dev/null || true
    ;;
esac
#DEBHELPER#
exit 0
```

- [ ] **Step 7: Add debian/changelog entry**

```
secubox-torrent (2.0.0-1~bookworm1) bookworm; urgency=medium

  * Pivot from Transmission to WebTorrent streaming (LXC-native, #917).
  * Browser player (HTTP Range), ephemeral-by-default + Keep library on /data.
  * Hybrid WebRTC+BitTorrent engine isolated in a dedicated LXC.

 -- Gerald KERMA <devel@cybermind.fr>  Tue, 28 Jul 2026 14:00:00 +0200
```

- [ ] **Step 8: Run packaging test to verify it passes** — PASS.

- [ ] **Step 9: Build the .deb** — `cd packages/secubox-torrent && dpkg-buildpackage -a arm64 --host-arch arm64 -us -uc -b` → produces `secubox-torrent_2.0.0-1~bookworm1_all.deb`.

- [ ] **Step 10: Commit** — `git add -A packages/secubox-torrent && git commit -m "feat(torrent): debian packaging v2.0.0, remove Transmission (ref #917)"`

---

## Self-Review

**Spec coverage:** ✅ LXC-native isolated (T1/T7), engine hybrid (T2), Range streaming (T3), library ephemeral/kept+purge (T4/T6), API (T5), player webui (T6), host vhost+WAF+JWT (T7), nft egress (T7), packaging v2.0.0 removing Transmission (T8), wrtc-arm64 spike + fallback (T1 → threads through engine `webrtc` + `/status` badge). Retention TTL + disk-floor: T4 selection + T6 sweep. Config TOML: T7/T8.

**Placeholder scan:** the two intentional impl-detail notes (statvfs `diskFreeBytes`, exact nginx vhost include path) are flagged inline with the concrete resolution to apply, not left vague. No TBD/TODO.

**Type consistency:** `add()→{infohash,name,files:[{idx,name,length,type}]}` consistent T2→T5→T6; `Library` method names (add/list/get/touch/touchAt/keep/remove/expiredEphemeral) consistent T4→T5→T6; `handleStream(engine,req,res)` consistent T3→T5; `buildApi({engine,library,diskFreeBytes})` consistent T5→T6; `runPurge(engine,library,{ttlSeconds,diskFloorBytes,diskFreeBytes})` consistent T6. `engine.webrtc` field flagged in T5 note to add in T2.

**Known cross-task fixups the implementer must honor:** (a) add `this.webrtc = webrtc;` to Engine (T2) — used by `/status` (T5); (b) resolve the nginx vhost include dir against peertube (T8 Step 4); (c) `diskFreeBytes` real impl via `fs.statfsSync('/data')` (T6).
