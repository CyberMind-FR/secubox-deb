// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.
//
// SecuBox-Deb :: sbxwaf — page d'explication pour les appareils isolés par secubox-garde (#3800).
//
// Un appareil en quarantaine d'infection voit toutes ses résolutions DNS pointer vers la box : ses requêtes HTTP
// arrivent ici avec un Host inconnu. Si son adresse figure dans /run/secubox/garde-isoles.json (écrit par
// secubox-garde-passage), on lui sert une page qui explique l'isolement au lieu du 421, et la requête ne compte
// pas comme signal d'attaque. Fichier absent ou invalide → ensemble vide : le 421 reste la réponse, jamais d'erreur.
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"html"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const defaultGardeIsoles = "/run/secubox/garde-isoles.json"

// isoleEntree : une adresse isolée, telle que l'écrit secubox-garde.
type isoleEntree struct {
	IP     string `json:"ip"`
	Nom    string `json:"nom"`
	Depuis int64  `json:"depuis"`
	Motif  string `json:"motif"`
}

// ListeIsoles relit le fichier quand son mtime ou sa taille change, au plus un stat par seconde.
type ListeIsoles struct {
	chemin string
	mu     sync.RWMutex
	ens    map[string]isoleEntree
	mtime  time.Time
	taille int64
	vu     time.Time // dernier stat
	now    func() time.Time
}

func NewListeIsoles(chemin string) *ListeIsoles {
	return &ListeIsoles{chemin: chemin, ens: map[string]isoleEntree{}, now: time.Now}
}

func (l *ListeIsoles) maybe() {
	t := l.now()
	l.mu.RLock()
	frais := !l.vu.IsZero() && t.Sub(l.vu) < time.Second
	l.mu.RUnlock()
	if frais {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.vu.IsZero() && t.Sub(l.vu) < time.Second {
		return
	}
	l.vu = t
	fi, err := os.Stat(l.chemin)
	if err != nil || !fi.Mode().IsRegular() {
		l.ens, l.mtime, l.taille = map[string]isoleEntree{}, time.Time{}, -1
		return
	}
	if fi.ModTime().Equal(l.mtime) && fi.Size() == l.taille {
		return
	}
	l.mtime, l.taille = fi.ModTime(), fi.Size()
	l.ens = lireIsoles(l.chemin)
}

func lireIsoles(chemin string) map[string]isoleEntree {
	ens := map[string]isoleEntree{}
	f, err := os.Open(chemin)
	if err != nil {
		return ens
	}
	defer f.Close()
	var doc struct {
		Isoles []isoleEntree `json:"isoles"`
	}
	if err := json.NewDecoder(io.LimitReader(f, 1<<20)).Decode(&doc); err != nil {
		return ens
	}
	for _, e := range doc.Isoles {
		if ip := normaliserIP(strings.TrimSpace(e.IP)); ip != "" {
			ens[ip] = e
		}
	}
	return ens
}

// Cherche rend l'entrée de l'adresse cliente (déjà dérivée par clientIP), si elle est isolée. Nil-safe.
func (l *ListeIsoles) Cherche(ip string) (isoleEntree, bool) {
	if l == nil || ip == "" {
		return isoleEntree{}, false
	}
	l.maybe()
	l.mu.RLock()
	defer l.mu.RUnlock()
	e, ok := l.ens[normaliserIP(ip)]
	return e, ok
}

// Même texte que packages/secubox-garde/www/garde/isole.html, plus l'heure et le motif (échappés).
const isoleStyle = `
  body{margin:0;min-height:100vh;display:grid;place-items:center;background:#e9edf5;color:#1b2333;font:16px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;padding:16px;box-sizing:border-box}
  main{max-width:34rem;background:#f4f6fb;border-radius:14px;padding:28px 24px;display:grid;gap:12px;text-align:center;box-shadow:0 2px 18px rgba(0,0,0,.08)}
  h1{margin:0;font-size:1.4rem;color:#b3261e}
  p{margin:0}
  small{color:#5b6475}
`

var isoleCSP = func() string {
	h := sha256.Sum256([]byte(isoleStyle))
	return "default-src 'none'; style-src 'sha256-" + base64.StdEncoding.EncodeToString(h[:]) +
		"'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
}()

const isolePage = `<!DOCTYPE html>
<html lang="fr">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>Appareil isolé</title>
<style>` + isoleStyle + `</style>
<body>
<main>
  <h1>Cet appareil est isolé</h1>
  <p>Il a contacté un serveur de pirates connu, ou montré plusieurs signes d'infection.</p>
  <p>Le propriétaire de la box a été prévenu. Seuls l'heure, les mises à jour et la box restent joignables.</p>
  <p><small>{{NOM}}{{DEPUIS}}{{MOTIF}}</small></p>
  <small>SecuBox</small>
</main>
</body>
</html>
`

// writeIsole sert la page d'explication (200, jamais mise en cache) ; toutes les valeurs sont échappées.
func writeIsole(w http.ResponseWriter, e isoleEntree) {
	var nom, depuis, motif string
	if s := strings.TrimSpace(e.Nom); s != "" {
		nom = "Appareil : " + html.EscapeString(s) + ". "
	}
	if e.Depuis > 0 {
		depuis = "Isolé depuis le " + time.Unix(e.Depuis, 0).Local().Format("02/01/2006 à 15:04") + ". "
	}
	if s := strings.TrimSpace(e.Motif); s != "" {
		motif = "Motif : " + html.EscapeString(s) + "."
	}
	page := strings.NewReplacer("{{NOM}}", nom, "{{DEPUIS}}", depuis, "{{MOTIF}}", motif).Replace(isolePage)
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Security-Policy", isoleCSP)
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, page)
}

func nouvelleListeIsoles(chemin string) *ListeIsoles {
	if strings.TrimSpace(chemin) == "" {
		return nil
	}
	return NewListeIsoles(chemin)
}
