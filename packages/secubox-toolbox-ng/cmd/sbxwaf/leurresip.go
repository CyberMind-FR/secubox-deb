// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.
//
// SecuBox-Deb :: sbxwaf — geste `leurre` de SecuBox AI (#3723) : une adresse d'attaquant redirigée vers le théâtre.
//
// Le compte ai-ban pose une adresse PUBLIQUE dans /var/lib/secubox/waf/leurres-ip.json par `wafctl leurre <ip> <N>s`
// (root, écriture atomique, 0644). Tant que l'entrée n'est pas échue, chaque requête de cette adresse reçoit une scène
// du théâtre (#1290 : constantes compilées, rien n'est lu sur disque ni exécuté pour répondre), jamais le vhost réel,
// quel que soit l'hôte demandé. La requête est journalisée en `leurre_redirige`, gravité d'état (« audit ») et sans
// émission vers sbx-actord : ce n'est PAS un signal d'attaque, ni ban, ni compteur d'escalade, ni anomalie d'hôte.
//
// Patron : isoles.go. Fichier absent, illisible ou pas sûr → ensemble vide (la requête suit son cours normal), jamais
// une erreur au client. Le fichier n'est cru que s'il est ordinaire, non lien (ni symbolique ni dur), à root, sans
// écriture de groupe ni d'autres. Le dossier appartient à secubox-waf (il porte aussi bans.jsonl) : on ne l'exige pas
// à root, c'est le propriétaire du FICHIER qui fait foi — aucun autre compte que root ne peut y créer un fichier à root.
// Relecture sur changement de mtime ou de taille, au plus un stat toutes les 5 s ; 2 048 entrées gardées au plus.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	defaultLeurresIP  = "/var/lib/secubox/waf/leurres-ip.json"
	leurresMax        = 2048
	leurresRelecture  = 5 * time.Second
	leurresTailleMax  = 4 << 20
	leurresMotifMax   = 64
	categorieLeurreIP = "leurre_redirige"
)

// leurreEntree : une adresse redirigée vers le théâtre jusqu'à `Fin` (epoch).
type leurreEntree struct {
	Fin   int64  `json:"fin"`
	Motif string `json:"motif"`
}

// ListeLeurres relit leurres-ip.json quand son mtime ou sa taille change, au plus un stat toutes les 5 s.
type ListeLeurres struct {
	chemin string
	mu     sync.RWMutex
	ens    map[string]leurreEntree
	mtime  time.Time
	taille int64
	vu     time.Time // dernier stat
	now    func() time.Time
	// proprietaireAdmis : root seul (injectable pour les tests).
	proprietaireAdmis func(uid uint32) bool
	logf              func(format string, args ...any)
}

func NewListeLeurres(chemin string) *ListeLeurres {
	return &ListeLeurres{chemin: chemin, ens: map[string]leurreEntree{}, taille: -1, now: time.Now,
		proprietaireAdmis: func(uid uint32) bool { return uid == 0 }, logf: log.Printf}
}

func nouvelleListeLeurres(chemin string) *ListeLeurres {
	if strings.TrimSpace(chemin) == "" {
		return nil
	}
	return NewListeLeurres(chemin)
}

func (l *ListeLeurres) maybe() {
	t := l.now()
	l.mu.RLock()
	frais := !l.vu.IsZero() && t.Sub(l.vu) < leurresRelecture
	l.mu.RUnlock()
	if frais {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.vu.IsZero() && t.Sub(l.vu) < leurresRelecture {
		return
	}
	l.vu = t
	fi, err := os.Lstat(l.chemin)
	if err != nil {
		l.ens, l.mtime, l.taille = map[string]leurreEntree{}, time.Time{}, -1
		return
	}
	if fi.ModTime().Equal(l.mtime) && fi.Size() == l.taille {
		return
	}
	// Un refus n'est journalisé qu'une fois par version du fichier : mtime et taille sont retenus même en échec.
	l.mtime, l.taille = fi.ModTime(), fi.Size()
	ens, err := l.lire()
	if err != nil {
		l.ens = map[string]leurreEntree{}
		l.logf("sbxwaf: liste des leurres %s ignorée : %s", l.chemin, err)
		return
	}
	l.ens = ens
}

func (l *ListeLeurres) lire() (map[string]leurreEntree, error) {
	fd, err := syscall.Open(l.chemin, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("ouverture : %w", err)
	}
	f := os.NewFile(uintptr(fd), l.chemin)
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, errors.New("pas un fichier ordinaire")
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || !l.proprietaireAdmis(st.Uid) {
		return nil, errors.New("fichier d'un autre propriétaire que root")
	}
	if st.Nlink != 1 {
		return nil, errors.New("fichier à plusieurs liens")
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("fichier inscriptible par d'autres")
	}
	return decoderLeurres(io.LimitReader(f, leurresTailleMax))
}

// decoderLeurres lit le document en flux pour garder les 2 048 PREMIÈRES entrées admises, dans l'ordre du fichier
// (une table Go n'a pas d'ordre). Tout le document doit être valide et porter `format` 1.
func decoderLeurres(r io.Reader) (map[string]leurreEntree, error) {
	dec := json.NewDecoder(r)
	if err := attendreDelim(dec, '{'); err != nil {
		return nil, err
	}
	format := 0
	ens := map[string]leurreEntree{}
	for dec.More() {
		cle, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("JSON invalide : %w", err)
		}
		switch cle {
		case "format":
			if err := dec.Decode(&format); err != nil {
				return nil, fmt.Errorf("format illisible : %w", err)
			}
		case "entrees":
			if err := attendreDelim(dec, '{'); err != nil {
				return nil, err
			}
			for dec.More() {
				ipTok, err := dec.Token()
				if err != nil {
					return nil, fmt.Errorf("JSON invalide : %w", err)
				}
				var e leurreEntree
				if err := dec.Decode(&e); err != nil {
					return nil, fmt.Errorf("entrée illisible : %w", err)
				}
				ip, _ := ipTok.(string)
				if len(ens) >= leurresMax {
					continue
				}
				if cle, ok := cleLeurre(ip); ok && e.Fin > 0 {
					if len(e.Motif) > leurresMotifMax {
						e.Motif = e.Motif[:leurresMotifMax]
					}
					ens[cle] = e
				}
			}
			if err := attendreDelim(dec, '}'); err != nil {
				return nil, err
			}
		default:
			var ignore json.RawMessage
			if err := dec.Decode(&ignore); err != nil {
				return nil, fmt.Errorf("JSON invalide : %w", err)
			}
		}
	}
	if err := attendreDelim(dec, '}'); err != nil {
		return nil, err
	}
	if format != 1 {
		return nil, fmt.Errorf("format %d inconnu", format)
	}
	return ens, nil
}

func attendreDelim(dec *json.Decoder, d json.Delim) error {
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("JSON invalide : %w", err)
	}
	if tok != d {
		return fmt.Errorf("JSON invalide : %q attendu", d)
	}
	return nil
}

// cleLeurre : forme normalisée d'une adresse PUBLIQUE ; jamais le LAN, la boucle locale, le lien local ni le
// multicast (les appareils internes restent l'affaire de secubox-garde, et la box ne se leurre pas elle-même).
func cleLeurre(texte string) (string, bool) {
	a, err := netip.ParseAddr(strings.TrimSpace(texte))
	if err != nil || a.Zone() != "" {
		return "", false
	}
	a = a.Unmap()
	if a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsMulticast() || a.IsUnspecified() || privateCIDR(a.String()) {
		return "", false
	}
	return normaliserIP(a.String()), true
}

// Cherche rend l'entrée de l'adresse cliente (déjà dérivée par clientIP) si elle est leurrée et non échue. Nil-safe.
func (l *ListeLeurres) Cherche(ip string) (leurreEntree, bool) {
	if l == nil || ip == "" {
		return leurreEntree{}, false
	}
	cle, ok := cleLeurre(ip)
	if !ok {
		return leurreEntree{}, false
	}
	l.maybe()
	t := l.now()
	l.mu.RLock()
	defer l.mu.RUnlock()
	e, ok := l.ens[cle]
	if !ok || e.Fin <= t.Unix() {
		return leurreEntree{}, false
	}
	return e, true
}

// Taille : entrées gardées (observabilité, tests).
func (l *ListeLeurres) Taille() int {
	if l == nil {
		return 0
	}
	l.maybe()
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.ens)
}

// leurrePourIP : le leurre du honeypot s'il est armé (même filigrane, même mémoire de scènes), sinon un leurre armé
// pour ce seul usage. Le geste `leurre` vaut décision : il sert même quand --honeypot n'arme pas l'espace non routé.
func leurrePourIP(base *LeurreHTTP, cheminSecret string) *LeurreHTTP {
	if base != nil && base.actif {
		return base
	}
	return NewLeurreHTTP(true, NewFiligrane(cheminSecret), journalSemis)
}

// servirLeurreIP répond à une adresse leurrée : une scène du théâtre, jamais le vhost réel. Une méthode que le
// théâtre ne joue pas reçoit un 405 banal. Une ligne `leurre_redirige` au journal des menaces, hors acteur.
func (s *Server) servirLeurreIP(w http.ResponseWriter, r *http.Request, host, cip string) {
	var famille familleSonde
	var alea string
	var marques []string
	servi := false
	if s.leurreIP != nil {
		servi, famille, alea, marques = s.leurreIP.Sert(w, r, host)
	}
	if !servi {
		w.Header().Set("Allow", "GET, HEAD, POST")
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
	if s.threatLog != nil {
		s.threatLog.Record(ThreatRecord{
			ClientIP:      cip,
			Host:          host,
			Method:        r.Method,
			Path:          r.URL.Path,
			Category:      categorieLeurreIP,
			Severity:      "audit",
			RuleID:        "ai-leurre",
			Action:        categorieLeurreIP,
			UA:            r.UserAgent(),
			EmpreinteHTTP: signatureEnTetes(r),
			Leurre:        string(famille),
			Filigrane:     alea,
			MarqueRevenue: marques,
			HorsActeur:    true,
		})
	}
}
