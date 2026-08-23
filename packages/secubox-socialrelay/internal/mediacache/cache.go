// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Package mediacache : télécharge et CACHE localement les médias des posts, pour
// que le navigateur ne contacte jamais le réseau social (vie privée). Servis
// ensuite en local par hash.
package mediacache

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-socialrelay/internal/linker"
	"github.com/CyberMind-FR/secubox-deb/secubox-socialrelay/internal/store"
)

const maxMedia = 25 << 20 // 25 Mio

var extParType = map[string]string{
	"image/jpeg": "jpg", "image/jpg": "jpg", "image/png": "png", "image/webp": "webp",
	"image/gif": "gif", "image/avif": "avif", "video/mp4": "mp4", "video/webm": "webm",
}

// Cache : dossier + client + magasin + garde SSRF.
type Cache struct {
	dir   string
	cli   *http.Client
	st    *store.Store
	garde func(string) error
}

// New crée le cache (crée le dossier).
func New(dir string, st *store.Store, garde func(string) error) *Cache {
	_ = os.MkdirAll(dir, 0o750)
	return &Cache{dir: dir, cli: &http.Client{Timeout: 25 * time.Second}, st: st, garde: garde}
}

// Cacher télécharge le média s'il n'est pas déjà là. Retourne le hash (nom
// local) ou "" en cas d'échec (un média manquant ne casse pas le post).
func (c *Cache) Cacher(m linker.Media) string {
	if m.URL == "" {
		return ""
	}
	hash := linker.EmpreinteURL(m.URL)
	if _, ok := c.st.MediaConnu(hash); ok {
		return hash // déjà caché
	}
	if c.garde != nil {
		if u := hoteDe(m.URL); u == "" || c.garde(u) != nil {
			return ""
		}
	}
	req, _ := http.NewRequest("GET", m.URL, nil)
	req.Header.Set("Accept", "image/*,video/*")
	req.Header.Set("User-Agent", "secubox-socialrelay/relais")
	resp, err := c.cli.Do(req)
	if err != nil || resp.StatusCode != 200 {
		if resp != nil {
			resp.Body.Close()
		}
		return ""
	}
	defer resp.Body.Close()
	ct := strings.ToLower(strings.TrimSpace(strings.SplitN(resp.Header.Get("Content-Type"), ";", 2)[0]))
	ext := extParType[ct]
	if ext == "" {
		return "" // type non accepté
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxMedia+1))
	if err != nil || len(b) > maxMedia || len(b) == 0 {
		return ""
	}
	if err := os.WriteFile(filepath.Join(c.dir, hash+"."+ext), b, 0o640); err != nil {
		return ""
	}
	kind := "image"
	if strings.HasPrefix(ct, "video") {
		kind = "video"
	}
	_ = c.st.AddMedia(hash, kind, ext, int64(len(b)), time.Now().Unix(), m.URL)
	return hash
}

// Servir renvoie le média caché (par hash).
func (c *Cache) Servir(w http.ResponseWriter, r *http.Request, hash string) {
	ext, ok := c.st.MediaConnu(hash)
	if !ok || strings.ContainsAny(hash, "/.\\") {
		http.NotFound(w, r)
		return
	}
	f := filepath.Join(c.dir, hash+"."+ext)
	w.Header().Set("Cache-Control", "public, max-age=604800")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	http.ServeFile(w, r, f)
}

func hoteDe(u string) string {
	i := strings.Index(u, "://")
	if i < 0 {
		return ""
	}
	rest := u[i+3:]
	end := strings.IndexAny(rest, "/:?")
	if end >= 0 {
		rest = rest[:end]
	}
	return rest
}
