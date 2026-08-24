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

// ProfondeurFile : combien de titres on FIGE à l'avance. Une file figée est ce
// qui permet d'annoncer un « à venir » VRAI — l'UI montre exactement ce qui
// passera, dans l'ordre. Trop court, la file se redessine à chaque titre ; trop
// long, un nouveau titre validé attend trop pour entrer à l'antenne.
const ProfondeurFile = 5

// Programmateur decide ce qui passe.
type Programmateur struct {
	mu      sync.Mutex
	st      Store
	reg     tirage.Reglages
	alea    *rand.Rand
	piste   store.Piste
	file    []store.Piste // les prochains titres, FIGÉS et dans l'ordre de passage
	debut   time.Time
	graine  int64
	demarre bool

	// OnBroadcast avertit d'un VRAI changement de piste — jamais d'un simple
	// sondage. Invoque depuis `avance`, qui n'est appele que lorsque
	// l'antenne bascule reellement sur un nouveau titre (premier tirage,
	// fin de duree, rejointe apres SautMax, ou `Suivante` force par le
	// sysop) — jamais depuis `Actuel` quand la piste en cours dure encore.
	//
	// CE PAQUET NE SAIT RIEN DU BBS NI DE HTTP : c'est au layer web/main de
	// cabler ce hook vers contentbbs.Client.Event, en resolvant le
	// content_id de la piste. Optionnel (nil = pas de hook, garde avant
	// appel) : le demon ne le cable pas toujours (BBS non deploye).
	//
	// APPELE SOUS LE VERROU de ce Programmateur (voir `avance`, appele par
	// `Actuel`/`Suivante` qui tiennent `mu`) : un hook qui bloque bloquerait
	// tous les auditeurs qui sondent en meme temps. Le cablage doit donc
	// rester rapide — deporter tout appel reseau dans sa propre goroutine.
	OnBroadcast func(pisteID int64, at int64)
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

// remplir COMPLÈTE la file figée jusqu'à ProfondeurFile+1 (1 à jouer + ce qu'on
// annonce). Le tirage pondéré `tirage.Programme` choisit SANS REMISE, en tenant
// le repos ; on ne re-tire pas la file à chaque appel, on la prolonge.
func (p *Programmateur) remplir(quand time.Time) error {
	cible := ProfondeurFile + 1
	if len(p.file) >= cible {
		return nil
	}
	tp, pistes, err := p.st.PourTirage()
	if err != nil {
		return err
	}
	parID := make(map[int64]store.Piste, len(pistes))
	for _, x := range pistes {
		parID[x.ID] = x
	}
	// On abaisse le poids de ce qui va déjà passer (piste courante + file), pour
	// ne pas annoncer deux fois de suite le même titre — sans jamais VIDER le
	// vivier (une radio à un seul titre doit continuer à le jouer).
	dejaVu := map[int64]time.Time{}
	if p.piste.ID != 0 {
		dejaVu[p.piste.ID] = quand
	}
	for _, f := range p.file {
		dejaVu[f.ID] = quand
	}
	for i := range tp {
		if _, ok := dejaVu[tp[i].ID]; ok {
			tp[i].JoueeLe = quand // vient de passer → repos → poids minimal
		}
	}
	besoin := cible - len(p.file)
	for _, t := range tirage.Programme(tp, p.reg, quand, besoin, p.alea) {
		if x, ok := parID[t.ID]; ok {
			p.file = append(p.file, x)
		}
	}
	return nil
}

// avance prend la tête de la file figée et l'inscrit au journal.
func (p *Programmateur) avance(quand time.Time) error {
	if err := p.remplir(quand); err != nil {
		return err
	}
	if len(p.file) == 0 {
		p.demarre = false
		return ErrSilence
	}
	p.piste = p.file[0]
	p.file = p.file[1:]
	p.debut, p.demarre = quand, true
	// L'ECHEC DU JOURNAL N'INTERROMPT PAS L'ANTENNE : ne pas retenir une
	// lecture est un desagrement, s'arreter de jouer est une panne. Mais le
	// repos de cette piste sera alors mal calcule, d'ou la remontee de
	// l'erreur a l'appelant qui journalise.
	err := p.st.NoteLecture(p.piste.ID, quand, p.graine)
	// LE PASSAGE A L'ANTENNE EST REEL MEME SI LE JOURNAL A ECHOUE (meme
	// logique que ci-dessus) : le hook sonne dans tous les cas.
	if p.OnBroadcast != nil {
		p.OnBroadcast(p.piste.ID, quand.Unix())
	}
	return err
}

// File rend une copie de la file figée : ce qui va passer, dans l'ordre. C'est
// la source AUTORITAIRE du « à venir » de l'UI (fini l'ordre d'ajout inventé).
func (p *Programmateur) File() []store.Piste {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]store.Piste, len(p.file))
	copy(out, p.file)
	return out
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
	// La file figée peut ANNONCER un titre supprimé : le purger, sinon l'UI
	// promet un « à venir » qui rendra un 404, et l'antenne le tirerait.
	if len(p.file) > 0 {
		kept := p.file[:0]
		for _, f := range p.file {
			if f.ID != id {
				kept = append(kept, f)
			}
		}
		p.file = kept
	}
}

// MajDuree corrige EN MÉMOIRE la durée de la piste EN COURS quand un lecteur
// vient d'en apprendre la vraie longueur (#1131z). Sans cela, une durée inconnue
// (0) fait avancer le programme à `DureeParDefaut` (4 min) et COUPE tout titre
// plus long — c'est le « la radio perd la piste et saute à une autre ». On ne
// touche que la piste actuelle, et seulement si sa durée était inconnue : une
// durée déjà établie fait autorité.
func (p *Programmateur) MajDuree(id, dureeMS int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if dureeMS > 0 && p.piste.ID == id && p.piste.DureeMS == 0 {
		p.piste.DureeMS = dureeMS
	}
}
