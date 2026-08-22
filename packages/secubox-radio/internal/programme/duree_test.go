package programme

import (
	"testing"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-radio/internal/store"
	"github.com/CyberMind-FR/secubox-deb/secubox-radio/internal/tirage"
)

// UNE DURÉE INCONNUE COUPE LE TITRE À 4 MIN — c'est le « la radio perd la piste
// et saute à une autre » (#1131z). Quand un lecteur rapporte la VRAIE durée
// (MajDuree), la piste doit jouer EN ENTIER : pas de saut à 4 min.
func TestUneDureeReporteeEmpecheLaCoupureA4Min(t *testing.T) {
	// Durées INCONNUES (0) : sans correction, coupe à DureeParDefaut (4 min).
	f := &faux{pistes: []store.Piste{piste(1, 0), piste(2, 0)}}
	p := Nouveau(f, tirage.Defaut(), 7)
	a, err := p.Actuel(t0)
	if err != nil {
		t.Fatal(err)
	}
	id := a.Piste.ID

	// Un lecteur a chargé les métadonnées : la vraie durée est 6 min.
	p.MajDuree(id, 6*60*1000)

	// À 5 min (> 4 min défaut, < 6 min réel) : la MÊME piste joue encore, en
	// continu (offset ≈ 5 min), pas un redémarrage.
	b, err := p.Actuel(t0.Add(5 * time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if b.Piste.ID != id {
		t.Fatalf("la piste a été coupée à 5 min : %d → %d", id, b.Piste.ID)
	}
	if b.OffsetMS < 4*60*1000 {
		t.Fatalf("offset retombé à %d ms : la piste a redémarré au lieu de continuer", b.OffsetMS)
	}
}

// GARDE-FOUS : MajDuree ne touche QUE la piste en cours, et jamais une durée
// déjà connue.
func TestMajDureeNeTouchePasUneAutreNiUneDureeConnue(t *testing.T) {
	f := &faux{pistes: []store.Piste{piste(1, 0)}}
	p := Nouveau(f, tirage.Defaut(), 1)
	a, _ := p.Actuel(t0)
	id := a.Piste.ID

	p.MajDuree(id+999, 6*60*1000) // autre piste → ignoré
	if b, _ := p.Actuel(t0.Add(5 * time.Minute)); b.Piste.ID == id && b.OffsetMS >= 4*60*1000 {
		t.Fatal("MajDuree sur une AUTRE piste a prolongé la piste en cours")
	}
}
