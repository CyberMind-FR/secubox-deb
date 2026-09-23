// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package audio

import (
	"fmt"
	"sync"
	"time"
)

// Navigateur : le micro est celui de la PERSONNE, pas celui de la board.
//
// C'est la source normale de ce module. La board n'a souvent aucune entrée son
// — celle de gk2 n'a qu'un `timer` dans `/dev/snd` — et surtout, le micro
// utile est celui de la machine devant laquelle on est assis. Le navigateur
// capture, envoie des blocs PCM par la WebSocket, et le traitement reste ici :
// l'audio traverse le réseau local et s'arrête sur la board. Rien ne sort.
//
// POURQUOI NE PAS TOUT FAIRE DANS LE NAVIGATEUR. Parce que l'analyse doit
// pouvoir durer, se comparer à un étalon constitué sur des heures, et survivre
// à la fermeture d'un onglet. Un `AnalyserNode` donne un joli spectre et rien
// d'autre : ni étalon personnel, ni historique, ni API que le reste de la box
// puisse interroger.
//
// UNE SESSION PAR PERSONNE, ET C'EST STRUCTUREL. L'étalon est CELUI D'UNE VOIX ;
// mélanger deux locuteurs dans le même ordinaire produirait un ordinaire qui
// n'est celui de personne, et des écarts imaginaires pour les deux. Chaque
// connexion a donc sa propre source, son propre VAD et son propre étalon.
type Navigateur struct {
	mu      sync.Mutex
	pret    *sync.Cond
	tampon  []float64
	ferme   bool
	origine string
	debut   time.Time
	recus   int64
	rejetes int64
	// PLAFOND DE TAMPON. Si l'analyse prend du retard, on jette les
	// échantillons les plus ANCIENS : sur un flux temps réel, du vieux son
	// n'a aucune valeur, et l'accumuler ferait grossir la mémoire jusqu'à ce
	// que le noyau tranche à notre place.
	plafond int
}

// NouveauNavigateur prépare la source d'une session. `plafond` est le nombre
// maximal d'échantillons gardés en attente — deux secondes suffisent largement.
func NouveauNavigateur(origine string, plafond int) *Navigateur {
	n := &Navigateur{origine: origine, plafond: plafond, debut: time.Now()}
	n.pret = sync.NewCond(&n.mu)
	return n
}

// Pousse ajoute un bloc reçu du navigateur.
func (n *Navigateur) Pousse(x []float64) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.ferme {
		return
	}
	n.tampon = append(n.tampon, x...)
	n.recus += int64(len(x))
	if trop := len(n.tampon) - n.plafond; trop > 0 {
		n.tampon = n.tampon[trop:]
		n.rejetes += int64(trop)
	}
	n.pret.Signal()
}

// Lis bloque jusqu'à avoir quelque chose, ou jusqu'à la fermeture.
func (n *Navigateur) Lis(dst []float64) (int, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for len(n.tampon) == 0 && !n.ferme {
		n.pret.Wait()
	}
	if len(n.tampon) == 0 && n.ferme {
		return 0, fmt.Errorf("session close : %w", ErrPasDEntree)
	}
	k := copy(dst, n.tampon)
	n.tampon = n.tampon[k:]
	return k, nil
}

// Ferme réveille le lecteur bloqué — sans quoi la goroutine d'analyse
// resterait à attendre un navigateur parti.
func (n *Navigateur) Ferme() error {
	n.mu.Lock()
	n.ferme = true
	n.mu.Unlock()
	n.pret.Broadcast()
	return nil
}

// Retard : le nombre d'échantillons en attente, c'est-à-dire la latence
// introduite par nous. Affiché dans le cockpit parce qu'un chiffre de latence
// qu'on ne mesure pas est un chiffre qu'on invente.
func (n *Navigateur) Retard() time.Duration {
	n.mu.Lock()
	defer n.mu.Unlock()
	return time.Duration(len(n.tampon)) * time.Second / Echantillonnage
}

// Perdus : les échantillons jetés faute d'avoir été traités à temps. Non nul
// veut dire que la board n'a pas suivi, et il vaut mieux le voir que le
// deviner.
func (n *Navigateur) Perdus() int64 {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.rejetes
}

func (n *Navigateur) Decrit() Description {
	n.mu.Lock()
	defer n.mu.Unlock()
	return Description{
		Genre: "navigateur",
		Detail: fmt.Sprintf("micro du client %s (%.1f s reçues)", n.origine,
			float64(n.recus)/Echantillonnage),
		Reelle: true, Perenne: true,
	}
}
