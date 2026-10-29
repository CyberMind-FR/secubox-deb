// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Package notifs détecte, sur les relevés complets du modèle, les conditions
// à notifier au maître : boucle de relances d'un service, mémoire basse, swap
// saturé, démarrage de la box. Chaque condition n'est signalée qu'une fois tant
// qu'elle dure et se réarme quand elle cesse.
package notifs

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// Types d'événements émis.
const (
	TypeBoucle    = "X_SECUBOX_ServiceLoop"
	TypeMemoire   = "X_SECUBOX_MemoryLow"
	TypeSwap      = "X_SECUBOX_SwapHigh"
	TypeDemarrage = "X_SECUBOX_Boot"
	TypeAncre     = "X_SECUBOX_AnchorFailed" // émis par le canal : coupure faute d'ancre vérifiée (value = instant)
	// L2 : suivi d'une opération lancée par un Operate (job, étape, pourcentage), puis sa fin (job, rc, résumé).
	TypeOperationProgress = "X_SECUBOX_OperationProgress"
	TypeOperationDone     = "X_SECUBOX_OperationDone"
	seuilDemarrage        = 600 // secondes d'UpTime sous lesquelles la box vient de démarrer
)

// Seuils règle les détections.
type Seuils struct {
	MemoireMo      int
	SwapPct        int
	BoucleRelances int
	BoucleFenetre  time.Duration
}

// SeuilsParDefaut rend 200 Mo, 80 %, 3 relances en 10 minutes.
func SeuilsParDefaut() Seuils {
	return Seuils{MemoireMo: 200, SwapPct: 80, BoucleRelances: 3, BoucleFenetre: 10 * time.Minute}
}

// SeuilsDepuisEnv part des défauts et applique les variables PILOTAGE_*
// (valeur absente, illisible ou non positive : défaut conservé).
func SeuilsDepuisEnv() Seuils {
	s := SeuilsParDefaut()
	lire := func(nom string) (int, bool) {
		n, err := strconv.Atoi(strings.TrimSpace(os.Getenv(nom)))
		return n, err == nil && n > 0
	}
	if n, ok := lire("PILOTAGE_MEMOIRE_SEUIL_MO"); ok {
		s.MemoireMo = n
	}
	if n, ok := lire("PILOTAGE_SWAP_SEUIL_PCT"); ok {
		s.SwapPct = n
	}
	if n, ok := lire("PILOTAGE_BOUCLE_RELANCES"); ok {
		s.BoucleRelances = n
	}
	if n, ok := lire("PILOTAGE_BOUCLE_FENETRE_S"); ok {
		s.BoucleFenetre = time.Duration(n) * time.Second
	}
	return s
}

// Evenement est une notification à transmettre au maître. Les champs d'opération (L2) ne servent qu'à
// X_SECUBOX_OperationProgress {job, etape, pct} et X_SECUBOX_OperationDone {job, rc, resume} ; pct et rc sont des
// pointeurs pour que 0 parte quand même.
type Evenement struct {
	Type     string `json:"type"`
	Unite    string `json:"unit,omitempty"`
	Valeur   int64  `json:"value,omitempty"`
	Instant  int64  `json:"ts"`
	Job      string `json:"job,omitempty"`
	Etape    string `json:"etape,omitempty"`
	Pct      *int   `json:"pct,omitempty"`
	RC       *int   `json:"rc,omitempty"`
	Resume   string `json:"resume,omitempty"`
	ID       string `json:"id,omitempty"`
	Etat     string `json:"etat,omitempty"`
	Decision string `json:"decision,omitempty"`
	Fin      string `json:"fin,omitempty"`
}

type echantillon struct {
	quand    time.Time
	relances uint64
}

type suiviUnite struct {
	points  []echantillon
	enBoucl bool
}

// Detecteur garde l'état entre deux relevés ; non sûr en concurrence (un seul
// relevé à la fois, par construction de l'agent).
type Detecteur struct {
	seuils   Seuils
	horloge  func() time.Time
	unites   map[string]*suiviUnite
	memBasse bool
	swapHaut bool
	boot     bool
}

// NouveauDetecteur construit un détecteur ; horloge nil = time.Now.
func NouveauDetecteur(s Seuils, horloge func() time.Time) *Detecteur {
	if horloge == nil {
		horloge = time.Now
	}
	return &Detecteur{seuils: s, horloge: horloge, unites: map[string]*suiviUnite{}}
}

// entier convertit une valeur du relevé ; ok=false si absente ou mal typée.
func entier(v any) (uint64, bool) {
	switch n := v.(type) {
	case uint64:
		return n, true
	case uint32:
		return uint64(n), true
	case int:
		if n >= 0 {
			return uint64(n), true
		}
	case int64:
		if n >= 0 {
			return uint64(n), true
		}
	case float64:
		if n >= 0 {
			return uint64(n), true
		}
	}
	return 0, false
}

const (
	cUptime = "Device.DeviceInfo.UpTime"
	cMem    = "Device.DeviceInfo.MemoryStatus."
	cUnites = "Device.X_SECUBOX_Services."
)

// Chemins : ce qu'Observer examine ; la surveillance ne demande que cela au
// modèle (paquets, exposition, maillage ne sont pas relus toutes les 30 s).
func Chemins() []string { return []string{cUptime, cMem, cUnites} }

// Observer examine un relevé complet et rend les nouveaux événements.
func (d *Detecteur) Observer(params map[string]any) []Evenement {
	now := d.horloge()
	ts := now.Unix()
	var ev []Evenement

	// Démarrage : une seule fois par exécution de l'agent.
	if up, ok := entier(params[cUptime]); ok && up < seuilDemarrage && !d.boot {
		d.boot = true
		ev = append(ev, Evenement{Type: TypeDemarrage, Valeur: int64(up), Instant: ts})
	}

	// Mémoire basse : MemAvailable (Kio) contre le seuil (Mo).
	if kio, ok := entier(params[cMem+"X_SECUBOX_Available"]); ok {
		mo := int64(kio / 1024)
		basse := mo < int64(d.seuils.MemoireMo)
		if basse && !d.memBasse {
			ev = append(ev, Evenement{Type: TypeMemoire, Valeur: mo, Instant: ts})
		}
		d.memBasse = basse
	}

	// Swap : pourcentage utilisé ; sans swap, jamais d'alerte.
	if tot, ok := entier(params[cMem+"X_SECUBOX_SwapTotal"]); ok {
		haut := false
		var pct int64
		if used, ok2 := entier(params[cMem+"X_SECUBOX_SwapUsed"]); ok2 && tot > 0 {
			pct = int64(used * 100 / tot)
			haut = pct >= int64(d.seuils.SwapPct)
		}
		if haut && !d.swapHaut {
			ev = append(ev, Evenement{Type: TypeSwap, Valeur: pct, Instant: ts})
		}
		d.swapHaut = haut
	}

	ev = append(ev, d.boucles(params, now)...)
	return ev
}

// boucles suit NRestarts par nom d'unité (l'indice {i} peut changer d'un
// relevé à l'autre) sur la fenêtre glissante, et élague les unités disparues.
func (d *Detecteur) boucles(params map[string]any, now time.Time) []Evenement {
	var ev []Evenement
	vues := map[string]bool{}
	for cle, v := range params {
		if !strings.HasPrefix(cle, cUnites) || !strings.HasSuffix(cle, ".Name") {
			continue
		}
		nom, ok := v.(string)
		if !ok || nom == "" {
			continue
		}
		base := strings.TrimSuffix(cle, "Name")
		rel, ok := entier(params[base+"NRestarts"])
		if !ok {
			continue
		}
		vues[nom] = true
		u := d.unites[nom]
		if u == nil {
			u = &suiviUnite{}
			d.unites[nom] = u
		}
		// compteur remis à zéro (unité rechargée) : on repart de ce point
		if n := len(u.points); n > 0 && rel < u.points[n-1].relances {
			u.points = nil
			u.enBoucl = false
		}
		u.points = append(u.points, echantillon{now, rel})
		u.points = elaguer(u.points, now, d.seuils.BoucleFenetre)
		delta := rel - u.points[0].relances
		boucle := delta >= uint64(d.seuils.BoucleRelances)
		if boucle && !u.enBoucl {
			ev = append(ev, Evenement{Type: TypeBoucle, Unite: nom, Valeur: int64(delta), Instant: now.Unix()})
		}
		u.enBoucl = boucle
	}
	// Unités absentes de ce relevé : oubliées une fois hors fenêtre.
	for nom, u := range d.unites {
		if vues[nom] {
			continue
		}
		u.points = elaguer(u.points, now, d.seuils.BoucleFenetre)
		if len(u.points) == 0 {
			delete(d.unites, nom)
		}
	}
	return ev
}

// elaguer retire les échantillons plus vieux que la fenêtre.
func elaguer(p []echantillon, now time.Time, fenetre time.Duration) []echantillon {
	i := 0
	for i < len(p) && now.Sub(p[i].quand) > fenetre {
		i++
	}
	return p[i:]
}
