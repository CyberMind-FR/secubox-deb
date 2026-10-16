// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: sbxmitm — cache de réponses des CDN statiques (#2804, proxypac étape 2, cf. #2752)
//
// Les appareils derrière le MITM redemandent sans cesse les mêmes fichiers statiques (polices, bibliothèques JS). Pour une LISTE FERMÉE de CDN
// statiques que l'opérateur a ACCEPTÉS, la réponse GET/200 est gardée sur disque et resservie sans retourner chez l'origine.
//
// Garde-fous (tous requis) :
//   - l'hôte est dans cdnStatiques (noms EXACTS, écrits en dur : jamais une API, jamais un sous-domaine, jamais cloudfront qui sert du contenu
//     client arbitraire) ET dans le fichier des hôtes acceptés par l'opérateur ;
//   - GET sans Range ni Authorization ; réponse 200 sans Set-Cookie, sans no-store/private, sans Vary:*, avec un Content-Type, ≤ cdnMaxEntree ;
//   - durée bornée (1 h – 7 j), taille totale bornée (éviction des plus anciens).
//
// Absent (dir vide) ou en erreur : transparent, la requête suit son cours normal.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/reload"
)

const (
	cdnMaxEntree    = 4 << 20   // 4 Mio par fichier
	cdnMaxTotal     = 512 << 20 // 512 Mio au total
	cdnTTLPlancher  = time.Hour
	cdnTTLPlafond   = 7 * 24 * time.Hour
	cdnTTLDefaut    = 24 * time.Hour
	cdnNettoyerTous = 50 // un nettoyage toutes les N écritures
)

// cdnStatiques : noms EXACTS. Les API (googleapis hors fonts/ajax, *-pa.*) n'y figurent volontairement pas.
var cdnStatiques = map[string]bool{
	"fonts.googleapis.com":       true,
	"fonts.gstatic.com":          true,
	"ajax.googleapis.com":        true,
	"cdnjs.cloudflare.com":       true,
	"cdn.jsdelivr.net":           true,
	"unpkg.com":                  true,
	"code.jquery.com":            true,
	"maxcdn.bootstrapcdn.com":    true,
	"stackpath.bootstrapcdn.com": true,
	"ajax.aspnetcdn.com":         true,
}

// Google adapte le CSS des polices à l'agent utilisateur : la clé en tient compte pour ce seul hôte.
const cdnHoteParAgent = "fonts.googleapis.com"

type cdnCache struct {
	dir      string
	mu       sync.RWMutex
	hotes    map[string]bool
	watcher  *reload.Watcher
	now      func() time.Time
	maxTotal int64

	wmu     sync.Mutex
	ecrites int
}

type cdnEntree struct {
	header http.Header
	body   []byte
}

type cdnMeta struct {
	Expire int64               `json:"expire"`
	Header map[string][]string `json:"header"`
}

// newCDNCache rend nil (cache désactivé) si dir est vide.
func newCDNCache(dir, listePath string) *cdnCache {
	if dir == "" {
		return nil
	}
	c := &cdnCache{dir: dir, hotes: reload.LoadLines(listePath, true), now: time.Now, maxTotal: cdnMaxTotal}
	c.watcher = reload.NewWatcher(reload.DefaultReloadThrottle, reload.Target{
		Path:      listePath,
		LastMtime: reload.StatMtime(listePath),
		Load:      func(p string) any { return reload.LoadLines(p, true) },
		Apply: func(v any) {
			m := v.(map[string]bool)
			c.mu.Lock()
			c.hotes = m
			c.mu.Unlock()
		},
	})
	return c
}

// Maybe relit la liste si elle a changé (un stat).
func (c *cdnCache) Maybe() {
	if c != nil && c.watcher != nil {
		c.watcher.Maybe()
	}
}

func (c *cdnCache) accepte(host string) bool {
	h := strings.Trim(strings.ToLower(host), ".")
	if !cdnStatiques[h] {
		return false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.hotes[h]
}

// Eligible : cache actif, hôte statique ET accepté, GET simple.
func (c *cdnCache) Eligible(host string, req *http.Request) bool {
	if c == nil || req == nil || req.Method != http.MethodGet {
		return false
	}
	if req.Header.Get("Range") != "" || req.Header.Get("Authorization") != "" {
		return false
	}
	return c.accepte(host)
}

func (c *cdnCache) cle(host string, req *http.Request) string {
	h := strings.Trim(strings.ToLower(host), ".")
	ua := ""
	if h == cdnHoteParAgent {
		ua = req.Header.Get("User-Agent")
	}
	s := sha256.Sum256([]byte(h + "\n" + req.URL.RequestURI() + "\nae=" + req.Header.Get("Accept-Encoding") + "\nua=" + ua))
	return hex.EncodeToString(s[:])
}

func (c *cdnCache) chemin(cle string) string { return filepath.Join(c.dir, cle[:2], cle) }

// Get rend l'entrée si elle existe et n'est pas expirée (une entrée expirée est supprimée).
func (c *cdnCache) Get(host string, req *http.Request) (*cdnEntree, bool) {
	if c == nil {
		return nil, false
	}
	p := c.chemin(c.cle(host, req))
	raw, err := os.ReadFile(p)
	if err != nil {
		return nil, false
	}
	nl := strings.IndexByte(string(raw), '\n')
	if nl < 0 {
		return nil, false
	}
	var m cdnMeta
	if json.Unmarshal(raw[:nl], &m) != nil {
		return nil, false
	}
	if c.now().Unix() >= m.Expire {
		_ = os.Remove(p)
		return nil, false
	}
	return &cdnEntree{header: http.Header(m.Header), body: raw[nl+1:]}, true
}

func ttlDe(cc string) time.Duration {
	for _, d := range strings.Split(cc, ",") {
		d = strings.TrimSpace(strings.ToLower(d))
		if strings.HasPrefix(d, "max-age=") {
			if n, err := strconv.Atoi(strings.TrimPrefix(d, "max-age=")); err == nil && n >= 0 {
				t := time.Duration(n) * time.Second
				if t < cdnTTLPlancher {
					t = cdnTTLPlancher
				}
				if t > cdnTTLPlafond {
					t = cdnTTLPlafond
				}
				return t
			}
		}
	}
	return cdnTTLDefaut
}

func stockable(resp *http.Response, taille int) bool {
	if resp == nil || resp.StatusCode != http.StatusOK || taille > cdnMaxEntree {
		return false
	}
	if len(resp.Header.Values("Set-Cookie")) > 0 || resp.Header.Get("Content-Type") == "" || strings.TrimSpace(resp.Header.Get("Vary")) == "*" {
		return false
	}
	cc := strings.ToLower(resp.Header.Get("Cache-Control"))
	return !strings.Contains(cc, "no-store") && !strings.Contains(cc, "private")
}

// Store garde la réponse si elle est stockable. Erreur d'E/S : on n'enregistre rien (jamais d'échec visible).
func (c *cdnCache) Store(host string, req *http.Request, resp *http.Response, body []byte) {
	if c == nil || !stockable(resp, len(body)) {
		return
	}
	garde := http.Header{}
	for _, k := range []string{"Content-Type", "Content-Encoding", "Cache-Control", "Etag", "Last-Modified", "Access-Control-Allow-Origin", "Vary"} {
		if v := resp.Header.Values(k); len(v) > 0 {
			garde[http.CanonicalHeaderKey(k)] = v
		}
	}
	meta, _ := json.Marshal(cdnMeta{Expire: c.now().Add(ttlDe(resp.Header.Get("Cache-Control"))).Unix(), Header: garde})
	p := c.chemin(c.cle(host, req))
	if os.MkdirAll(filepath.Dir(p), 0o755) != nil {
		return
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), ".w-")
	if err != nil {
		return
	}
	_, e1 := tmp.Write(append(append(meta, '\n'), body...))
	e2 := tmp.Close()
	if e1 != nil || e2 != nil || os.Chmod(tmp.Name(), 0o644) != nil || os.Rename(tmp.Name(), p) != nil {
		_ = os.Remove(tmp.Name())
		return
	}
	c.wmu.Lock()
	c.ecrites++
	faire := c.ecrites%cdnNettoyerTous == 0
	c.wmu.Unlock()
	if faire {
		c.nettoyer()
	}
}

// nettoyer ramène la taille totale sous 90 % du plafond en supprimant les plus anciens.
func (c *cdnCache) nettoyer() {
	type f struct {
		p string
		t time.Time
		n int64
	}
	var fs []f
	var total int64
	_ = filepath.Walk(c.dir, func(p string, i os.FileInfo, err error) error {
		if err == nil && !i.IsDir() && !strings.HasPrefix(i.Name(), ".w-") {
			fs = append(fs, f{p, i.ModTime(), i.Size()})
			total += i.Size()
		}
		return nil
	})
	if total <= c.maxTotal {
		return
	}
	sort.Slice(fs, func(a, b int) bool { return fs[a].t.Before(fs[b].t) })
	cible := c.maxTotal * 9 / 10
	for _, x := range fs {
		if total <= cible {
			break
		}
		if os.Remove(x.p) == nil {
			total -= x.n
		}
	}
}

// reponse reconstitue la réponse servie depuis le cache (le corps est passé à writeResponse).
func (e *cdnEntree) reponse() *http.Response {
	h := e.header.Clone()
	h.Set("X-SecuBox-Cache", "HIT")
	return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Header: h}
}

type cdnCorps struct {
	io.Reader
	io.Closer
}

// capturer lit la réponse d'origine (200 d'un hôte éligible) pour la mettre en cache, puis rend au client un corps IDENTIQUE : si le fichier
// dépasse cdnMaxEntree, ce qui a déjà été lu est rejoué devant le reste du flux (rien n'est perdu). Le corps d'origine reste fermé une seule fois.
func (c *cdnCache) capturer(host string, req *http.Request, resp *http.Response) {
	if c == nil || resp == nil || resp.StatusCode != http.StatusOK || resp.Body == nil {
		return
	}
	orig := resp.Body
	tete, err := io.ReadAll(io.LimitReader(orig, cdnMaxEntree+1))
	if err != nil || len(tete) > cdnMaxEntree {
		resp.Body = cdnCorps{Reader: io.MultiReader(bytes.NewReader(tete), orig), Closer: orig}
		return
	}
	resp.Body = cdnCorps{Reader: bytes.NewReader(tete), Closer: orig}
	c.Store(host, req, resp, tete)
}
