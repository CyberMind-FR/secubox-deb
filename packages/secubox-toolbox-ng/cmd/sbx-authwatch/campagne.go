// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

// SecuBox-Deb :: toolbox-ng :: sbx-authwatch — detection de campagne (#1220)
//
// LE PROBLEME QUE LES MESURES ONT REVELE. Un compteur par adresse suppose que
// l'attaquant revient. Sur gk2, il ne revient pas : sur sept jours, 339 des 388
// adresses d'une campagne SASL n'apparaissent qu'UNE SEULE FOIS, et six
// seulement atteignent trois tentatives. Un seuil par IP, quel qu'il soit,
// laisserait donc passer 87 % des participants. C'est un botnet : la charge est
// repartie precisement pour rester sous ce genre de seuil.
//
// LE PIVOT STABLE EST LE COMPTE VISE. Les memes sept jours montrent
// « gerald@gk2.net » tente 39 fois, « gerard@gk2.net » 38, « gege » 38 — des
// variantes du nom du proprietaire, essayees depuis des centaines de sources.
// L'adresse change a chaque coup ; la cible, jamais.
//
// D'OU LA REGLE. Quand un compte est vise depuis PLUSIEURS sources distinctes
// dans la fenetre, on considere la campagne etablie, et chaque source qui y
// participe devient bannissable des son premier echec. On ne punit pas la
// repetition d'un individu, on reconnait une action collective — c'est la
// correlation que l'ancien relais externe apportait et que son retrait avait emportee.
//
// LA RESERVE, qui compte autant. Un compte vise peut etre un compte REEL —
// « gerald@gk2.net » l'est. Son proprietaire qui se trompe de mot de passe
// pendant une campagne serait pris dans le filet. C'est pourquoi la liste
// blanche est consultee AVANT ce mecanisme, et pourquoi le bannissement reste
// temporaire.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/reseau"
)

// Campagnes suit, par compte vise, les sources distinctes qui l'ont attaque.
type Campagnes struct {
	fenetre time.Duration
	seuil   int // nombre de sources distinctes etablissant la campagne

	mu     sync.Mutex
	cibles map[string]map[string]time.Time // cible -> source -> dernier essai
}

func NewCampagnes(fenetre time.Duration, seuil int) *Campagnes {
	return &Campagnes{
		fenetre: fenetre,
		seuil:   seuil,
		cibles:  make(map[string]map[string]time.Time),
	}
}

// Note enregistre une tentative et dit si une campagne est etablie sur cette
// cible. Rend aussi le nombre de sources distinctes, pour le journal : une
// decision dont on ignore le fondement n'est pas auditable.
func (c *Campagnes) Note(cible, source string, maintenant time.Time) (sources int, campagne bool) {
	if c == nil || cible == "" || source == "" {
		return 0, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	m := c.cibles[cible]
	if m == nil {
		m = make(map[string]time.Time)
		c.cibles[cible] = m
	}
	m[source] = maintenant

	limite := maintenant.Add(-c.fenetre)
	for ip, t := range m {
		if t.Before(limite) {
			delete(m, ip)
		}
	}
	if len(m) == 0 {
		delete(c.cibles, cible)
		return 0, false
	}
	return len(m), len(m) >= c.seuil
}

// Elague retire les cibles dont plus aucune source n'est dans la fenetre.
func (c *Campagnes) Elague(maintenant time.Time) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	limite := maintenant.Add(-c.fenetre)
	for cible, m := range c.cibles {
		for ip, t := range m {
			if t.Before(limite) {
				delete(m, ip)
			}
		}
		if len(m) == 0 {
			delete(c.cibles, cible)
		}
	}
}

// Suivies rend le nombre de cibles en observation.
func (c *Campagnes) Suivies() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.cibles)
}

// EtatCampagne est ce que le relais publie d'une campagne établie (#3919) :
// jamais le compte en clair, jamais une adresse source.
type EtatCampagne struct {
	ID      string `json:"id"`
	Compte  string `json:"compte"`
	Sources int    `json:"sources"`
	Premier int64  `json:"premier"`
	Dernier int64  `json:"dernier"`
}

// IdentifiantCampagne : 8 premiers hex du SHA-256 du compte visé en minuscules.
func IdentifiantCampagne(cible string) string {
	h := sha256.Sum256([]byte(strings.ToLower(cible)))
	return hex.EncodeToString(h[:])[:8]
}

// IdentifiantSiEtablie rend l'identifiant de campagne de cette cible si elle
// compte au moins `seuil` sources dans la fenêtre, sinon "".
func (c *Campagnes) IdentifiantSiEtablie(cible string, maintenant time.Time) string {
	if c == nil || cible == "" {
		return ""
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	limite := maintenant.Add(-c.fenetre)
	n := 0
	for _, t := range c.cibles[cible] {
		if !t.Before(limite) {
			n++
		}
	}
	if n < c.seuil {
		return ""
	}
	return IdentifiantCampagne(cible)
}

// Etat rend les campagnes ÉTABLIES (compte masqué), triées par identifiant.
// Premier/Dernier : secondes Unix des tentatives les plus anciennes et récentes
// parmi les sources encore dans la fenêtre.
func (c *Campagnes) Etat(maintenant time.Time) []EtatCampagne {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	limite := maintenant.Add(-c.fenetre)
	var out []EtatCampagne
	for cible, m := range c.cibles {
		var n int
		var premier, dernier time.Time
		for _, t := range m {
			if t.Before(limite) {
				continue
			}
			n++
			if premier.IsZero() || t.Before(premier) {
				premier = t
			}
			if t.After(dernier) {
				dernier = t
			}
		}
		if n == 0 || n < c.seuil {
			continue
		}
		out = append(out, EtatCampagne{
			ID: IdentifiantCampagne(cible), Compte: reseau.MasquerCompte(cible),
			Sources: n, Premier: premier.Unix(), Dernier: dernier.Unix(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// EcrireEtat publie l'état des campagnes : fichier temporaire dans le même
// répertoire, puis renommage atomique — un lecteur ne voit jamais un fichier
// à moitié écrit.
func EcrireEtat(c *Campagnes, chemin string, maintenant time.Time) error {
	tab := c.Etat(maintenant)
	if tab == nil {
		tab = []EtatCampagne{}
	}
	data, err := json.Marshal(tab)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	f, err := os.CreateTemp(filepath.Dir(chemin), ".authwatch-campagnes-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Chmod(0644); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, chemin); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}
