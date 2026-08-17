package programme

import (
	"errors"
	"testing"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-radio/internal/store"
	"github.com/CyberMind-FR/secubox-deb/secubox-radio/internal/tirage"
)

var t0 = time.Date(2026, 8, 15, 20, 0, 0, 0, time.UTC)

// faux magasin : le programmateur ne doit pas exiger une base pour etre teste.
type faux struct {
	pistes   []store.Piste
	lectures []int64
}

func (f *faux) PourTirage() ([]tirage.Piste, []store.Piste, error) {
	var tp []tirage.Piste
	for _, p := range f.pistes {
		t := tirage.Piste{ID: p.ID, AjouteLe: time.Unix(p.AjouteLe, 0),
			Coeurs: p.Coeurs, Indisponible: p.Indisponible || !p.EnCache()}
		tp = append(tp, t)
	}
	return tp, f.pistes, nil
}
func (f *faux) NoteLecture(id int64, _ time.Time, _ int64) error {
	f.lectures = append(f.lectures, id)
	return nil
}

func piste(id int64, dureeMS int64) store.Piste {
	return store.Piste{ID: id, DureeMS: dureeMS, Fichier: "/data/x.opus",
		AjouteLe: t0.Add(-24 * time.Hour).Unix(), Titre: "T"}
}

// ── CE QUI FAIT UNE RADIO ───────────────────────────────────────────────────
//
// Deux appels au MEME instant doivent rendre la MEME reponse : sinon deux
// auditeurs n'entendent pas la meme chose, ce qui est exactement ce qu'on
// cherche a eviter.
func TestDeuxAuditeursAuMemeInstantEntendentLaMemeChose(t *testing.T) {
	f := &faux{pistes: []store.Piste{piste(1, 180000), piste(2, 200000)}}
	p := Nouveau(f, tirage.Defaut(), 42)
	a, err := p.Actuel(t0)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := p.Actuel(t0)
	if a.Piste.ID != b.Piste.ID || a.OffsetMS != b.OffsetMS {
		t.Errorf("deux reponses differentes au meme instant : %d@%d vs %d@%d",
			a.Piste.ID, a.OffsetMS, b.Piste.ID, b.OffsetMS)
	}
}

// L'offset avance avec le temps, sans changer de piste tant qu'elle dure.
func TestLOffsetAvanceSansChangerDePiste(t *testing.T) {
	f := &faux{pistes: []store.Piste{piste(1, 180000)}}
	p := Nouveau(f, tirage.Defaut(), 1)
	a, _ := p.Actuel(t0)
	b, _ := p.Actuel(t0.Add(30 * time.Second))
	if a.Piste.ID != b.Piste.ID {
		t.Error("la piste a change avant la fin")
	}
	if b.OffsetMS-a.OffsetMS != 30000 {
		t.Errorf("l'offset a avance de %d ms au lieu de 30000", b.OffsetMS-a.OffsetMS)
	}
}

func TestLaPisteChangeALaFin(t *testing.T) {
	f := &faux{pistes: []store.Piste{piste(1, 10000), piste(2, 10000)}}
	p := Nouveau(f, tirage.Defaut(), 7)
	a, _ := p.Actuel(t0)
	b, _ := p.Actuel(t0.Add(11 * time.Second))
	if a.Piste.ID == b.Piste.ID {
		t.Error("la piste n'a pas change apres sa duree")
	}
	if b.OffsetMS > 2000 {
		t.Errorf("la nouvelle piste demarre a %d ms au lieu du debut", b.OffsetMS)
	}
}

// ── ON NE RATTRAPE PAS LE DIRECT ────────────────────────────────────────────
//
// Le demon s'arrete une nuit. Au reveil, un rattrapage honnete avancerait
// piste par piste : cent tirages, cent ecritures au journal, et un historique
// qui pretend que la radio a joue toute la nuit alors que personne n'ecoutait.
func TestApresUneLongueAbsenceOnRejointLeDirect(t *testing.T) {
	f := &faux{pistes: []store.Piste{piste(1, 180000), piste(2, 180000), piste(3, 180000)}}
	p := Nouveau(f, tirage.Defaut(), 3)
	if _, err := p.Actuel(t0); err != nil {
		t.Fatal(err)
	}
	avant := len(f.lectures)

	// Huit heures plus tard.
	e, err := p.Actuel(t0.Add(8 * time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	apres := len(f.lectures) - avant
	if apres > 2 {
		t.Errorf("%d lectures inscrites pour rattraper huit heures — on a deroule le vide", apres)
	}
	if e.OffsetMS > 2000 {
		t.Errorf("on reprend a %d ms au lieu de repartir d'une piste neuve", e.OffsetMS)
	}
}

// Une duree inconnue ne doit pas faire avancer le programme a chaque appel :
// la radio changerait de titre plusieurs fois par seconde.
func TestUneDureeInconnueNeFaitPasDefilerLaRadio(t *testing.T) {
	f := &faux{pistes: []store.Piste{piste(1, 0), piste(2, 0)}}
	p := Nouveau(f, tirage.Defaut(), 5)
	a, _ := p.Actuel(t0)
	b, _ := p.Actuel(t0.Add(2 * time.Second))
	if a.Piste.ID != b.Piste.ID {
		t.Error("la piste change alors que deux secondes seulement se sont ecoulees")
	}
	if len(f.lectures) != 1 {
		t.Errorf("%d lectures pour deux appels rapproches", len(f.lectures))
	}
}

// ── SILENCE ─────────────────────────────────────────────────────────────────
//
// Rien de jouable n'est PAS une panne : la page doit pouvoir le dire.
func TestSansPisteJouableLaRadioDitLeSilence(t *testing.T) {
	f := &faux{} // rien
	p := Nouveau(f, tirage.Defaut(), 1)
	e, err := p.Actuel(t0)
	if !errors.Is(err, ErrSilence) {
		t.Errorf("erreur = %v, attendu ErrSilence", err)
	}
	if !e.Silence {
		t.Error("l'etat ne signale pas le silence")
	}
}

// Une piste non recuperee ne passe pas : elle donnerait un silence a l'ecoute.
func TestUnePisteSansFichierNePasseJamais(t *testing.T) {
	sans := store.Piste{ID: 9, DureeMS: 180000, AjouteLe: t0.Unix()} // Fichier vide
	f := &faux{pistes: []store.Piste{sans}}
	p := Nouveau(f, tirage.Defaut(), 1)
	if _, err := p.Actuel(t0); !errors.Is(err, ErrSilence) {
		t.Errorf("une piste sans fichier a ete programmee : %v", err)
	}
}

// L'horloge du serveur est rendue : sans elle, chaque auditeur accumule sa
// propre latence et la synchronisation derive.
func TestLHorlogeDuServeurEstRendue(t *testing.T) {
	f := &faux{pistes: []store.Piste{piste(1, 180000)}}
	p := Nouveau(f, tirage.Defaut(), 1)
	e, _ := p.Actuel(t0)
	if !e.Horloge.Equal(t0) {
		t.Errorf("horloge = %v, attendue %v", e.Horloge, t0)
	}
}

// Le sysop peut forcer le passage au suivant.
func TestLeSysopPeutPasserAuSuivant(t *testing.T) {
	f := &faux{pistes: []store.Piste{piste(1, 180000), piste(2, 180000), piste(3, 180000)}}
	p := Nouveau(f, tirage.Defaut(), 11)
	a, _ := p.Actuel(t0)
	b, err := p.Suivante(t0.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if a.Piste.ID == b.Piste.ID {
		t.Error("le passage force n'a pas change de piste")
	}
	if b.OffsetMS > 1500 {
		t.Errorf("la nouvelle piste demarre a %d ms", b.OffsetMS)
	}
}

// Chaque passage est inscrit au journal : c'est ce qui rend le tirage
// explicable apres coup.
func TestChaquePassageEstInscritAuJournal(t *testing.T) {
	f := &faux{pistes: []store.Piste{piste(1, 10000), piste(2, 10000)}}
	p := Nouveau(f, tirage.Defaut(), 2)
	_, _ = p.Actuel(t0)
	_, _ = p.Actuel(t0.Add(11 * time.Second))
	_, _ = p.Actuel(t0.Add(22 * time.Second))
	if len(f.lectures) != 3 {
		t.Errorf("%d lectures inscrites pour trois passages", len(f.lectures))
	}
}
