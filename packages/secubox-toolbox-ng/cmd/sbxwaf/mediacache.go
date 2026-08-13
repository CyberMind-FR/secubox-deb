// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: sbxwaf — response media cache (Task 6.1)
//
// On-disk layout (mirrors media_cache.py):
//
//	<dir>/<key[:2]>/<key>       — raw response body (binary)
//	<dir>/<key[:2]>/<key>.m    — JSON sidecar: {"ct":"…","exp":unix,"url":"…"}
//
// where key = hex(sha256(url)).
//
// Eviction: when the in-memory total-bytes counter would exceed maxTotal after
// a new store, we evict by ascending atime (least-recently-used) until the
// total drops below the cap.  This mirrors the Python _evict_if_needed logic.
//
// TTL seam: nowFn is a replaceable clock function (default time.Now) injected
// by tests to make expiry deterministic without real-time sleeps.
//
// Fail-open: every cache error (disk I/O, JSON parse, …) is silently swallowed
// — the caller always receives the real upstream response.
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

// Cache constants — mirror media_cache.py.
const (
	mediaCacheMaxObj   int64 = 16 * 1024 * 1024       // 16 MiB per object
	mediaCacheMaxTotal int64 = 2 * 1024 * 1024 * 1024 // 2 GiB total
	mediaCacheTTL      int64 = 3600                   // default 1 h
)

// Cacheable content-type prefixes/substrings — exact port from _CACHEABLE tuple.
var mediaCacheableTypes = []string{
	"image/",
	"video/",
	"audio/",
	"font/",
	"text/css",
	"javascript",
	"ecmascript",
	"application/font",
	"application/vnd.ms-fontobject",
}

var mediaCacheMaxAgeRe = regexp.MustCompile(`(?i)max-age\s*=\s*(\d+)`)

// cacheEntry is the in-memory index record for one cached object.
type cacheEntry struct {
	size  int64
	exp   int64 // unix timestamp; 0 = never expire
	atime int64 // unix timestamp of last access (for LRU eviction)
	ct    string
	ce    string // Content-Encoding of the stored body ("" = identity)

	// Validateurs de l'amont, pour la revalidation conditionnelle (#1031).
	//
	// SANS EUX, LE CACHE NE SAIT QUE VIEILLIR. `Get` servait toute entree non
	// expiree, donc un fichier modifie sur disque restait masque jusqu'a la fin
	// de son heure de TTL — constate sur anibal-amiot.fr, ou un `app.js`
	// remplace par un `git pull` etait servi dans sa version d'avant. Une
	// synchronisation aux cinq minutes ne sert a rien si le cache repond
	// l'ancienne version pendant l'heure qui suit.
	etag    string
	lastMod string
}

// CacheStats is a snapshot of MediaCache counters.
type CacheStats struct {
	Hits        int64
	Misses      int64
	Stored      int64
	Evicted     int64
	BytesCached int64
	Objects     int64
}

// MediaCache is a disk-backed, LRU-evicting, TTL-aware response media cache.
// It is safe for concurrent use.
type MediaCache struct {
	dir      string
	maxObj   int64
	maxTotal int64

	mu    sync.Mutex
	index map[string]*cacheEntry // key → entry
	total int64                  // current total bytes on disk

	// Atomic stats counters (read without lock for Stats()).
	hits    atomic.Int64
	misses  atomic.Int64
	stored  atomic.Int64
	evicted atomic.Int64

	// nowFn is the clock seam — replaced by tests for deterministic TTL tests.
	nowFn func() time.Time
}

// NewMediaCache creates a MediaCache rooted at dir.
// maxObj and maxTotal default to mediaCacheMaxObj / mediaCacheMaxTotal.
// The on-disk index is rebuilt at construction time (mirrors _load_index).
func NewMediaCache(dir string) *MediaCache {
	mc := &MediaCache{
		dir:      dir,
		maxObj:   mediaCacheMaxObj,
		maxTotal: mediaCacheMaxTotal,
		index:    make(map[string]*cacheEntry),
		nowFn:    time.Now,
	}
	// Fail-open: ignore mkdir/scan errors.
	_ = os.MkdirAll(dir, 0o755)
	mc.loadIndex()
	return mc
}

// cacheKey returns hex(sha256(url)) — identical to Python _key().
func cacheKey(url string) string {
	h := sha256.Sum256([]byte(url))
	return fmt.Sprintf("%x", h)
}

// paths returns (bodyPath, metaPath) for a given cache key.
func (m *MediaCache) paths(key string) (string, string) {
	shard := key[:2]
	d := filepath.Join(m.dir, shard)
	return filepath.Join(d, key), filepath.Join(d, key+".m")
}

// loadIndex scans the cache directory and rebuilds the in-memory index.
// Mirrors Python _load_index; called once at construction.
func (m *MediaCache) loadIndex() {
	entries, err := os.ReadDir(m.dir)
	if err != nil {
		return
	}
	for _, sub := range entries {
		if !sub.IsDir() {
			continue
		}
		subDir := filepath.Join(m.dir, sub.Name())
		files, err := os.ReadDir(subDir)
		if err != nil {
			continue
		}
		for _, f := range files {
			if strings.HasSuffix(f.Name(), ".m") {
				continue // skip meta sidecars
			}
			key := f.Name()
			bodyPath := filepath.Join(subDir, key)
			info, err := os.Stat(bodyPath)
			if err != nil {
				continue
			}
			metaPath := bodyPath + ".m"
			var meta struct {
				CT      string `json:"ct"`
				CE      string `json:"ce"`
				Exp     int64  `json:"exp"`
				ETag    string `json:"etag"`
				LastMod string `json:"lm"`
			}
			if raw, err := os.ReadFile(metaPath); err == nil {
				_ = json.Unmarshal(raw, &meta)
			}
			e := &cacheEntry{
				size:    info.Size(),
				exp:     meta.Exp,
				etag:    meta.ETag,
				lastMod: meta.LastMod,
				// mtime is used deliberately as the LRU recency proxy.
				// atime is unreliable on most Linux filesystems (relatime
				// mount option suppresses most atime updates), so we use
				// mtime which is set explicitly via os.Chtimes on every
				// cache Get() hit — a reliable in-band atime surrogate.
				atime: info.ModTime().Unix(),
				ct:    meta.CT,
				ce:    meta.CE,
			}
			m.index[key] = e
			m.total += info.Size()
		}
	}
}

// isCacheable reports whether ct is a cacheable content-type.
// Mirrors Python _cacheable_ct.
func isCacheable(ct string) bool {
	ct = strings.ToLower(strings.SplitN(ct, ";", 2)[0])
	ct = strings.TrimSpace(ct)
	if ct == "" {
		return false
	}
	for _, prefix := range mediaCacheableTypes {
		if strings.Contains(ct, prefix) {
			return true
		}
	}
	return false
}

// hasGzipMagic reports whether b begins with the gzip magic number (0x1F 0x8B).
func hasGzipMagic(b []byte) bool {
	return len(b) >= 2 && b[0] == 0x1f && b[1] == 0x8b
}

// isCorruptIdentity reports whether a body recorded as identity (ce=="") is in
// fact compressed — a pre-fix legacy entry whose Content-Encoding was dropped.
// gzip is caught by magic. brotli/deflate/zstd have no reliable magic, so they
// are caught for text/script content-types: an identity JS/CSS body must be
// valid UTF-8, and a compressed one is (almost) never valid UTF-8. Binary media
// (images/video/fonts) is left alone — its identity form is legitimately
// non-UTF-8. Serving any such corrupt body as identity is the U+001F-class bug.
func isCorruptIdentity(ct string, data []byte) bool {
	if hasGzipMagic(data) {
		return true
	}
	ct = strings.ToLower(ct)
	if strings.Contains(ct, "javascript") ||
		strings.Contains(ct, "ecmascript") ||
		strings.Contains(ct, "css") {
		return !utf8.Valid(data)
	}
	return false
}

// encodingAccepted reports whether the client's Accept-Encoding header permits
// the given content coding. Identity (empty coding) is always acceptable. A
// token with an explicit q=0 is treated as "not acceptable" per RFC 7231.
func encodingAccepted(acceptEncoding, coding string) bool {
	coding = strings.TrimSpace(strings.ToLower(coding))
	if coding == "" || coding == "identity" {
		return true
	}
	for _, part := range strings.Split(strings.ToLower(acceptEncoding), ",") {
		tok := strings.TrimSpace(part)
		base := tok
		q := 1.0
		if i := strings.IndexByte(tok, ';'); i >= 0 {
			base = strings.TrimSpace(tok[:i])
			if j := strings.Index(tok[i+1:], "q="); j >= 0 {
				qstr := tok[i+1+j+2:]
				// stop at any further parameter (e.g. "q=0;x=y" → "0")
				if k := strings.IndexByte(qstr, ';'); k >= 0 {
					qstr = qstr[:k]
				}
				if v, err := strconv.ParseFloat(strings.TrimSpace(qstr), 64); err == nil {
					q = v
				}
			}
		}
		if (base == coding || base == "*") && q > 0 {
			return true
		}
	}
	return false
}

// Get returns the cached body + headers for url if a valid (non-expired) entry
// exists that the client can decode. ok=false means cache miss (or expired, or
// the stored representation is encoded in a way the client did not advertise via
// acceptEncoding). Fail-open: I/O errors → miss.
// Validateurs rend l'ETag et le Last-Modified memorises pour cette URL (#1031).
//
// A QUOI ILS SERVENT : construire une requete conditionnelle vers l'amont, pour
// lui demander si le fichier a change plutot que de le supposer. Sans reponse
// (entree absente, ou amont qui n'en pose aucun), on rend deux chaines vides et
// l'appelant traite le cas comme un cache a rafraichir — l'ignorance conduit a
// redemander, jamais a servir du perime.
func (m *MediaCache) Validateurs(url string) (etag, lastMod string) {
	if m == nil {
		return "", ""
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if e, ok := m.index[cacheKey(url)]; ok {
		return e.etag, e.lastMod
	}
	return "", ""
}

// Invalide retire une entree du cache (#1031). Appelee quand l'amont a repondu
// autre chose qu'un 304 : le contenu memorise n'est plus le bon, et le garder
// une seconde de plus ne peut que tromper.
func (m *MediaCache) Invalide(url string) {
	if m == nil {
		return
	}
	key := cacheKey(url)
	m.mu.Lock()
	if e, ok := m.index[key]; ok {
		m.total -= e.size
		delete(m.index, key)
	}
	m.mu.Unlock()
	bodyPath, metaPath := m.paths(key)
	_ = os.Remove(bodyPath)
	_ = os.Remove(metaPath)
}

func (m *MediaCache) Get(url, acceptEncoding string) (body []byte, hdr http.Header, ok bool) {
	key := cacheKey(url)
	now := m.nowFn().Unix()

	m.mu.Lock()
	e, found := m.index[key]
	m.mu.Unlock()

	if !found {
		m.misses.Add(1)
		return nil, nil, false
	}
	if e.exp != 0 && e.exp < now {
		// Expired: treat as miss (evict lazily on next store).
		m.misses.Add(1)
		return nil, nil, false
	}

	// If the stored representation is content-encoded, only serve it to a client
	// that advertised that coding — otherwise the browser would receive bytes it
	// cannot decode. Treat as a miss so the caller proxies upstream and negotiates
	// an acceptable encoding.
	if e.ce != "" && !encodingAccepted(acceptEncoding, e.ce) {
		m.misses.Add(1)
		return nil, nil, false
	}

	bodyPath, _ := m.paths(key)
	data, err := os.ReadFile(bodyPath)
	if err != nil {
		// File gone (evicted externally, disk error) — remove from index.
		m.mu.Lock()
		if ex, ok := m.index[key]; ok {
			m.total -= ex.size
			delete(m.index, key)
		}
		m.mu.Unlock()
		m.misses.Add(1)
		return nil, nil, false
	}

	// Defensive self-heal: an entry recorded as identity (ce=="") whose body is
	// actually compressed is a corrupt legacy entry (stored by the pre-fix cache
	// that dropped Content-Encoding — gzip, brotli, deflate or zstd). Serving it
	// as identity is exactly the U+001F bug — evict it and miss instead.
	if e.ce == "" && isCorruptIdentity(e.ct, data) {
		metaPath := bodyPath + ".m"
		m.mu.Lock()
		if ex, ok := m.index[key]; ok {
			m.total -= ex.size
			delete(m.index, key)
		}
		m.mu.Unlock()
		_ = os.Remove(bodyPath)
		_ = os.Remove(metaPath)
		m.misses.Add(1)
		return nil, nil, false
	}

	// Update atime in index and on-disk (mirrors Python e["atime"] = time.time()).
	m.mu.Lock()
	if ex, ok := m.index[key]; ok {
		ex.atime = now
	}
	m.mu.Unlock()
	_ = os.Chtimes(bodyPath, time.Unix(now, 0), time.Unix(now, 0))

	h := http.Header{}
	if e.ct != "" {
		h.Set("Content-Type", e.ct)
	}
	if e.ce != "" {
		h.Set("Content-Encoding", e.ce)
	}

	m.hits.Add(1)
	return data, h, true
}

// MaybeStore conditionally stores the response body to disk.
// The cacheURL parameter must be the full per-vhost URL composed by the caller
// as "https://" + r.Host + r.URL.RequestURI() so that assets with the same
// path on different vhosts get distinct cache keys (vhost isolation).
// Checks: method==GET, status==200, no no-store/private/set-cookie, cacheable
// content-type, size < maxObj, ttl > 0.
// Evicts oldest-by-atime entries when total would exceed maxTotal.
// Fail-open: any I/O error is silently ignored.
func (m *MediaCache) MaybeStore(req *http.Request, resp *http.Response, body []byte, cacheURL string) {
	if req == nil || resp == nil {
		return
	}
	if req.Method != http.MethodGet {
		return
	}
	if resp.StatusCode != http.StatusOK {
		return
	}
	// Skip Range requests and authenticated responses (mirrors Python).
	if req.Header.Get("Range") != "" || req.Header.Get("Authorization") != "" {
		return
	}

	cc := strings.ToLower(resp.Header.Get("Cache-Control"))
	if strings.Contains(cc, "no-store") || strings.Contains(cc, "private") {
		return
	}
	if resp.Header.Get("Set-Cookie") != "" {
		return
	}

	ct := resp.Header.Get("Content-Type")
	if !isCacheable(ct) {
		return
	}

	// Size gate: reject oversized objects.
	if int64(len(body)) > m.maxObj {
		return
	}
	if len(body) == 0 {
		return
	}

	// Parse max-age; fall back to DEFAULT_TTL.
	var ttl int64 = mediaCacheTTL
	if m := mediaCacheMaxAgeRe.FindStringSubmatch(cc); m != nil {
		if v, err := strconv.ParseInt(m[1], 10, 64); err == nil {
			ttl = v
		}
	}
	if ttl <= 0 {
		return
	}

	rawURL := cacheURL
	key := cacheKey(rawURL)
	bodyPath, metaPath := m.paths(key)

	// Strip params from ct for storage.
	ctClean := strings.TrimSpace(strings.SplitN(ct, ";", 2)[0])
	// Preserve the body's Content-Encoding so a HIT can replay it. Without this,
	// a gzip body would be served as identity → the client reads 0x1F as text and
	// the asset is corrupted (dead JS/CSS).
	ceClean := strings.TrimSpace(resp.Header.Get("Content-Encoding"))

	now := m.nowFn().Unix()
	exp := now + ttl

	// Write body atomically via tmp → rename (mirrors Python tmp + os.replace).
	if err := os.MkdirAll(filepath.Dir(bodyPath), 0o755); err != nil {
		return
	}
	tmp := bodyPath + ".tmp"
	if err := os.WriteFile(tmp, body, 0o644); err != nil {
		_ = os.Remove(tmp)
		return
	}
	if err := os.Rename(tmp, bodyPath); err != nil {
		_ = os.Remove(tmp)
		return
	}
	// LES VALIDATEURS SONT CE QUI PERMET DE NE PAS SERVIR DU PERIME. nginx pose
	// un ETag et un Last-Modified sur tout fichier statique ; les garder permet
	// de demander a l'amont « a-t-il change ? » plutot que de le supposer.
	etagClean := strings.TrimSpace(resp.Header.Get("ETag"))
	lmClean := strings.TrimSpace(resp.Header.Get("Last-Modified"))

	meta := struct {
		CT      string `json:"ct"`
		CE      string `json:"ce"`
		Exp     int64  `json:"exp"`
		ETag    string `json:"etag,omitempty"`
		LastMod string `json:"lm,omitempty"`
		URL     string `json:"url"`
	}{
		CT:      ctClean,
		CE:      ceClean,
		Exp:     exp,
		ETag:    etagClean,
		LastMod: lmClean,
		URL: func() string {
			if len(rawURL) > 300 {
				return rawURL[:300]
			}
			return rawURL
		}(),
	}
	metaBytes, err := json.Marshal(meta)
	if err == nil {
		_ = os.WriteFile(metaPath, metaBytes, 0o644)
	}

	// Update index + total under lock.
	newSize := int64(len(body))
	m.mu.Lock()
	old := int64(0)
	if ex, ok := m.index[key]; ok {
		old = ex.size
	}
	m.total += newSize - old
	m.index[key] = &cacheEntry{
		size:    newSize,
		exp:     exp,
		atime:   now,
		ct:      ctClean,
		ce:      ceClean,
		etag:    etagClean,
		lastMod: lmClean,
	}
	m.evictIfNeeded()
	m.mu.Unlock()

	m.stored.Add(1)
}

// evictIfNeeded removes least-recently-used entries until total ≤ maxTotal.
// Must be called with m.mu held.
func (m *MediaCache) evictIfNeeded() {
	if m.total <= m.maxTotal {
		return
	}

	// Build a sorted slice of (key, atime) pairs.
	type kv struct {
		key   string
		atime int64
	}
	pairs := make([]kv, 0, len(m.index))
	for k, e := range m.index {
		pairs = append(pairs, kv{k, e.atime})
	}
	sort.Slice(pairs, func(i, j int) bool {
		return pairs[i].atime < pairs[j].atime
	})

	for _, p := range pairs {
		if m.total <= m.maxTotal {
			break
		}
		e, ok := m.index[p.key]
		if !ok {
			continue
		}
		bodyPath, metaPath := m.paths(p.key)
		_ = os.Remove(bodyPath)
		_ = os.Remove(metaPath)
		m.total -= e.size
		delete(m.index, p.key)
		m.evicted.Add(1)
	}
}

// cachingResponseWriter wraps an http.ResponseWriter to tee the response body
// to an in-memory buffer (up to maxCapture bytes) so the handler can store the
// response in the media cache after proxying.
//
// The client always receives the FULL response — we only buffer up to maxCapture
// bytes for the cache decision.  If the response body exceeds maxCapture, we
// stop buffering and set captured=false; the client stream is not truncated.
type cachingResponseWriter struct {
	http.ResponseWriter
	statusCode int
	respHeader http.Header
	body       []byte
	captured   bool // true when body was fully buffered (len ≤ maxCapture)
	maxCapture int64
	written    int64
	overflow   bool
}

func (c *cachingResponseWriter) WriteHeader(code int) {
	c.statusCode = code
	// Snapshot the response headers at the point WriteHeader is called.
	// This captures Content-Type, Cache-Control etc. set by the upstream proxy.
	c.respHeader = c.ResponseWriter.Header().Clone()
	c.ResponseWriter.WriteHeader(code)
}

func (c *cachingResponseWriter) Write(b []byte) (int, error) {
	n, err := c.ResponseWriter.Write(b)
	if c.overflow {
		return n, err
	}
	if c.statusCode == 0 {
		// WriteHeader was not called explicitly — Go sets 200 implicitly.
		c.statusCode = http.StatusOK
		c.respHeader = c.ResponseWriter.Header().Clone()
	}
	c.written += int64(n)
	if c.written > c.maxCapture {
		// Body too large to cache — discard buffer, mark overflow.
		c.body = nil
		c.overflow = true
		c.captured = false
		return n, err
	}
	c.body = append(c.body, b[:n]...)
	c.captured = true
	return n, err
}

// Flush implements http.Flusher so that httputil.ReverseProxy can flush
// chunks incrementally to the client (important for progressive video /
// PeerTube streaming).  It is a pure pass-through to the underlying
// ResponseWriter's Flush method; it does not affect what bytes are
// captured for the cache buffer.
func (c *cachingResponseWriter) Flush() {
	if f, ok := c.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack forwards to the underlying ResponseWriter so httputil.ReverseProxy can
// tunnel WebSocket upgrades through this cache wrapper (#796). Without it, the
// media-cache tee shadows the underlying Hijacker and WS upgrades return 503
// ("can't switch protocols using non-Hijacker ResponseWriter"). A hijacked
// connection is raw-tunnelled, so nothing is cached — correct for a WS.
func (c *cachingResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := c.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, fmt.Errorf("cachingResponseWriter: underlying ResponseWriter does not support Hijack")
}

// Stats returns a point-in-time snapshot of cache counters.
func (m *MediaCache) Stats() CacheStats {
	m.mu.Lock()
	objects := int64(len(m.index))
	bytes := m.total
	m.mu.Unlock()
	return CacheStats{
		Hits:        m.hits.Load(),
		Misses:      m.misses.Load(),
		Stored:      m.stored.Load(),
		Evicted:     m.evicted.Load(),
		BytesCached: bytes,
		Objects:     objects,
	}
}
