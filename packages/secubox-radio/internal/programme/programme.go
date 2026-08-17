// Package programme tient l'horloge de la radio : ce qui passe maintenant, et
// depuis combien de temps.
//
// C'EST CE PAQUET QUI FAIT UNE RADIO PLUTOT QU'UNE PLAYLIST. Une playlist,
// chacun la lit de son cote et personne n'est au meme endroit. Une radio a une
// position AUTORITAIRE, tenue par le serveur : le client demande « quoi, et a
// quel instant », se positionne, et se recale.
package programme

import (
	"errors"
	"math/rand"
	"sync"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-radio/internal/store"
	"github.com/CyberMind-FR/secubox-deb/secubox-radio/internal/tirage"
)

// ErrSilence : rien de jouable. Ce n'est PAS une panne — une radio sans piste
// validee et en cache doit le dire clairement plutot que rendre une erreur.
var ErrSilence = errors.New("aucune piste jouable")

// DureeParDefaut : quand une piste n'annonce pas sa duree.
//
// Sans borne, une duree inconnue (0) ferait avancer le programme a chaque
// appel — la radio changerait de titre plusieurs fois par seconde.
const DureeParDefaut = 4 * time.Minute

// SautMax : au-dela, on ne rattrape pas, on repart.
//
// LE CAS QUI MOTIVE CETTE BORNE : le demon s'arrete une nuit. Au reveil, un
// rattrapage honnete avancerait piste par piste — cent tirages, cent ecritures
// dans le journal des lectures, et un historique qui pretend que la radio a
// joue toute la nuit alors que personne n'ecoutait. UNE RADIO EST EN DIRECT :
// on ne rattrape pas le direct, on le rejoint.
const SautMax = 15 * time.Minute

// Etat : ce que le client recoit.
type Etat struct {
	Piste    store.Piste
	OffsetMS int64
	// Horloge : l'instant du serveur au moment de la reponse. Le client s'en
	// sert pour corriger la latence du reseau — sans elle, chaque auditeur
	// accumule son propre retard et la synchronisation derive.
	Horloge time.Time
	Graine  int64
	Silence bool
}

// Programmateur decide ce qui passe.
type Programmateur struct {
	mu      sync.Mutex
	st      Store
	reg     tirage.Reglages
	alea    *rand.Rand
	piste   store.Piste
	debut   time.Time
	graine  int64
	demarre bool
}

// Store : ce dont le programmateur a besoin. Une interface plutot que le type
// concret — les tests n'ont alors pas besoin d'une base.
type Store interface {
	PourTirage() ([]tirage.Piste, []store.Piste, error)
	NoteLecture(pisteID int64, debut time.Time, graine int64) error
}

func Nouveau(st Store, reg tirage.Reglages, graine int64) *Programmateur {
	return &Programmateur{st: st, reg: reg, alea: rand.New(rand.NewSource(graine)), graine: graine}
}

// Actuel rend ce qui passe a l'instant donne, en avancant si necessaire.
//
// APPELE PAR CHAQUE AUDITEUR, a chaque rafraichissement : deux appels au meme
// instant doivent rendre la MEME reponse, sinon deux auditeurs n'entendent pas
// la meme chose — ce qui est exactement ce qu'on cherche a eviter. D'ou le
// verrou, et l'etat tenu ici plutot que recalcule.
func (p *Programmateur) Actuel(maintenant time.Time) (Etat, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.demarre {
		if err := p.avance(maintenant); err != nil {
			return Etat{Silence: true, Horloge: maintenant}, err
		}
	}

	// ON NE RATTRAPE PAS LE DIRECT. Au-dela de `SautMax` sans etre interroge
	// (demon arrete, machine endormie), on repart d'un tirage neuf plutot que
	// de derouler cent pistes que personne n'a entendues.
	if maintenant.Sub(p.debut) > p.duree()+SautMax {
		if err := p.avance(maintenant); err != nil {
			return Etat{Silence: true, Horloge: maintenant}, err
		}
	}

	// Avancee normale, piste par piste. Bornee : une duree aberrante ne doit
	// pas faire boucler ici indefiniment.
	for i := 0; i < 64; i++ {
		ecoule := maintenant.Sub(p.debut)
		if ecoule < p.duree() {
			break
		}
		if err := p.avance(p.debut.Add(p.duree())); err != nil {
			return Etat{Silence: true, Horloge: maintenant}, err
		}
	}

	off := maintenant.Sub(p.debut).Milliseconds()
	if off < 0 {
		off = 0
	}
	return Etat{Piste: p.piste, OffsetMS: off, Horloge: maintenant, Graine: p.graine}, nil
}

func (p *Programmateur) duree() time.Duration {
	if p.piste.DureeMS > 0 {
		return time.Duration(p.piste.DureeMS) * time.Millisecond
	}
	return DureeParDefaut
}

// avance tire la piste suivante et l'inscrit au journal.
func (p *Programmateur) avance(quand time.Time) error {
	tp, pistes, err := p.st.PourTirage()
	if err != nil {
		return err
	}
	choisie, err := tirage.Suivante(tp, p.reg, quand, p.alea)
	if err != nil {
		p.demarre = false
		return ErrSilence
	}
	for _, x := range pistes {
		if x.ID == choisie.ID {
			p.piste = x
			break
		}
	}
	p.debut, p.demarre = quand, true
	// L'ECHEC DU JOURNAL N'INTERROMPT PAS L'ANTENNE : ne pas retenir une
	// lecture est un desagrement, s'arreter de jouer est une panne. Mais le
	// repos de cette piste sera alors mal calcule, d'ou la remontee de
	// l'erreur a l'appelant qui journalise.
	return p.st.NoteLecture(choisie.ID, quand, p.graine)
}

// Suivante force le passage au titre suivant. Reservee au sysop.
func (p *Programmateur) Suivante(maintenant time.Time) (Etat, error) {
	p.mu.Lock()
	if err := p.avance(maintenant); err != nil {
		p.mu.Unlock()
		return Etat{Silence: true, Horloge: maintenant}, err
	}
	p.mu.Unlock()
	return p.Actuel(maintenant)
}

// Oublie retire une piste de l'antenne si c'est elle qui passe.
//
// LE PROGRAMMATEUR TIENT SA PISTE EN MEMOIRE — c'est ce qui lui permet de
// repondre la meme chose a tous les auditeurs sans relire la base a chaque
// appel. Mais quand la piste est SUPPRIMEE, cette memoire devient un mensonge :
// il continue d'annoncer un identifiant qui ne designe plus rien, et les
// auditeurs recoivent un 404 sur le clip.
//
// On force donc un nouveau tirage au prochain appel. S'il n'y a plus rien de
// jouable, ce sera le silence — un etat que la page sait dire.
func (p *Programmateur) Oublie(id int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.piste.ID == id {
		p.piste, p.demarre = store.Piste{}, false
	}
}
