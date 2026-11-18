// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.
//
// SecuBox-Deb :: sbxwaf — page d'explication pour les appareils isolés par secubox-garde (#3800).
//
// Un appareil en quarantaine d'infection voit toutes ses résolutions DNS pointer vers la box : ses requêtes HTTP
// arrivent ici avec un Host inconnu. Si son adresse figure dans /run/secubox/garde/isoles.json (écrit par
// secubox-garde-passage), on lui sert une page qui explique l'isolement au lieu du 421, et la requête ne compte
// pas comme signal d'attaque. Fichier absent ou invalide → ensemble vide : le 421 reste la réponse, jamais d'erreur.
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	defaultGardeIsoles = "/run/secubox/garde/isoles.json"
	compteGarde        = "secubox-garde"
	isolesPerimee      = 600 * time.Second // le minuteur de Garde tourne toutes les 60 s
)

// isoleEntree : une adresse isolée, telle que l'écrit secubox-garde.
type isoleEntree struct {
	IP     string `json:"ip"`
	Nom    string `json:"nom"`
	Depuis int64  `json:"depuis"`
	Motif  string `json:"motif"`
}

// ListeIsoles relit le fichier quand son mtime ou sa taille change, au plus un stat par seconde.
// Le fichier n'est cru que s'il est sûr : dossier et fichier non liens, à secubox-garde ou root, sans écriture
// de groupe ni d'autres ; il est ignoré s'il est périmé (genere_le). Une entrée publique n'est jamais exemptée.
type ListeIsoles struct {
	chemin string
	mu     sync.RWMutex
	ens    map[string]isoleEntree
	genere time.Time
	mtime  time.Time
	taille int64
	vu     time.Time // dernier stat
	now    func() time.Time
	// uidGarde rend l'uid du compte secubox-garde (injectable pour les tests).
	uidGarde func() (uint32, bool)
	logf     func(format string, args ...any)

	journalMu sync.Mutex
	refusLog  time.Time
	servisLog map[string]time.Time
}

func NewListeIsoles(chemin string) *ListeIsoles {
	return &ListeIsoles{chemin: chemin, ens: map[string]isoleEntree{}, taille: -1, now: time.Now,
		uidGarde: uidCompteGarde(), logf: log.Printf, servisLog: map[string]time.Time{}}
}

// uidCompteGarde résout l'uid une fois, et réessaie tant que la résolution échoue.
func uidCompteGarde() func() (uint32, bool) {
	var mu sync.Mutex
	var uid uint32
	var ok bool
	return func() (uint32, bool) {
		mu.Lock()
		defer mu.Unlock()
		if !ok {
			if u, err := user.Lookup(compteGarde); err == nil {
				if n, err := strconv.ParseUint(u.Uid, 10, 32); err == nil {
					uid, ok = uint32(n), true
				}
			}
		}
		return uid, ok
	}
}

func (l *ListeIsoles) proprietaireAdmis(uid uint32) bool {
	if uid == 0 {
		return true
	}
	g, ok := l.uidGarde()
	return ok && uid == g
}

// refuse vide l'ensemble et journalise au plus une ligne par minute.
func (l *ListeIsoles) refuse(t time.Time, motif string) {
	l.ens = map[string]isoleEntree{}
	l.genere = time.Time{}
	l.journalMu.Lock()
	defer l.journalMu.Unlock()
	if t.Sub(l.refusLog) >= time.Minute {
		l.refusLog = t
		l.logf("sbxwaf: liste des isolées %s ignorée : %s", l.chemin, motif)
	}
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
	fi, err := os.Lstat(l.chemin)
	if err != nil {
		l.ens, l.genere, l.mtime, l.taille = map[string]isoleEntree{}, time.Time{}, time.Time{}, -1
		return
	}
	if fi.ModTime().Equal(l.mtime) && fi.Size() == l.taille {
		return
	}
	l.mtime, l.taille = fi.ModTime(), fi.Size()
	if err := l.verifierDossier(); err != nil {
		l.refuse(t, err.Error())
		return
	}
	ens, genere, err := l.lire()
	if err != nil {
		l.refuse(t, err.Error())
		return
	}
	l.ens, l.genere = ens, genere
}

func (l *ListeIsoles) verifierDossier() error {
	di, err := os.Lstat(filepath.Dir(l.chemin))
	if err != nil {
		return err
	}
	if !di.IsDir() {
		return errors.New("dossier lien ou non-dossier")
	}
	st, ok := di.Sys().(*syscall.Stat_t)
	if !ok || !l.proprietaireAdmis(st.Uid) {
		return errors.New("dossier d'un autre propriétaire")
	}
	if di.Mode().Perm()&0o022 != 0 {
		return errors.New("dossier inscriptible par d'autres")
	}
	return nil
}

func (l *ListeIsoles) lire() (map[string]isoleEntree, time.Time, error) {
	fd, err := syscall.Open(l.chemin, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("ouverture : %w", err)
	}
	f := os.NewFile(uintptr(fd), l.chemin)
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, time.Time{}, err
	}
	if !fi.Mode().IsRegular() {
		return nil, time.Time{}, errors.New("pas un fichier ordinaire")
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || !l.proprietaireAdmis(st.Uid) {
		return nil, time.Time{}, errors.New("fichier d'un autre propriétaire")
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return nil, time.Time{}, errors.New("fichier inscriptible par d'autres")
	}
	var doc struct {
		GenereLe int64         `json:"genere_le"`
		Isoles   []isoleEntree `json:"isoles"`
	}
	if err := json.NewDecoder(io.LimitReader(f, 1<<20)).Decode(&doc); err != nil {
		return nil, time.Time{}, fmt.Errorf("JSON invalide : %w", err)
	}
	ens := map[string]isoleEntree{}
	for _, e := range doc.Isoles {
		a, err := netip.ParseAddr(strings.TrimSpace(e.IP))
		if err != nil {
			continue
		}
		a = a.Unmap()
		// Jamais une adresse publique : seules celles du réseau local peuvent être des appareils isolés.
		if !a.IsPrivate() && !a.IsLinkLocalUnicast() {
			continue
		}
		ens[normaliserIP(a.String())] = e
	}
	return ens, time.Unix(doc.GenereLe, 0), nil
}

// Cherche rend l'entrée de l'adresse cliente (déjà dérivée par clientIP), si elle est isolée. Nil-safe.
func (l *ListeIsoles) Cherche(ip string) (isoleEntree, bool) {
	if l == nil || ip == "" {
		return isoleEntree{}, false
	}
	l.maybe()
	t := l.now()
	l.mu.RLock()
	defer l.mu.RUnlock()
	if t.Sub(l.genere) > isolesPerimee {
		return isoleEntree{}, false // Garde ne publie plus : liste périmée, plus personne n'est exempté
	}
	e, ok := l.ens[normaliserIP(ip)]
	return e, ok
}

// Trace garde une ligne « isolé-servi ip host » par adresse et par minute : ni score ni ban.
func (l *ListeIsoles) Trace(ip, host string) {
	if l == nil {
		return
	}
	t := l.now()
	l.journalMu.Lock()
	defer l.journalMu.Unlock()
	if d, ok := l.servisLog[ip]; ok && t.Sub(d) < time.Minute {
		return
	}
	if len(l.servisLog) > 4096 {
		l.servisLog = map[string]time.Time{}
	}
	l.servisLog[ip] = t
	l.logf("sbxwaf: isolé-servi ip=%s host=%q", ip, host)
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
	h.Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, page)
}

func nouvelleListeIsoles(chemin string) *ListeIsoles {
	if strings.TrimSpace(chemin) == "" {
		return nil
	}
	return NewListeIsoles(chemin)
}
