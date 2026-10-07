package store

import (
	"errors"
	"testing"
)

// « MOINS SOUVENT » : la poussée vers le bas se retient, se lit, se défait, et descend jusqu'au tirage.
func TestPousseeVersLeBasSeRetientEtSeDefait(t *testing.T) {
	s := banc(t)
	p, _, _ := s.Ajoute("https://youtu.be/AAA", "Titre", 1, t0)
	if p.Bas {
		t.Fatal("une piste neuve n'est pas poussée vers le bas")
	}
	if err := s.PoseBas(p.ID, true); err != nil {
		t.Fatal(err)
	}
	if q, _ := s.ParID(p.ID); !q.Bas {
		t.Fatal("la poussée vers le bas n'a pas été retenue")
	}
	if err := s.PoseBas(p.ID, false); err != nil {
		t.Fatal(err)
	}
	if q, _ := s.ParID(p.ID); q.Bas {
		t.Fatal("la poussée vers le bas n'a pas été défaite")
	}
}

func TestPousseeVersLeBasEstIdempotenteEtRefuseUneInconnue(t *testing.T) {
	s := banc(t)
	p, _, _ := s.Ajoute("https://youtu.be/AAA", "Titre", 1, t0)
	for i := 0; i < 2; i++ {
		if err := s.PoseBas(p.ID, true); err != nil {
			t.Fatalf("pose %d : %v", i, err)
		}
	}
	if err := s.PoseBas(99999, true); !errors.Is(err, ErrPisteInconnue) {
		t.Fatalf("piste inconnue : %v", err)
	}
}

func TestLaPousseeVersLeBasArriveAuTirage(t *testing.T) {
	s := banc(t)
	p, _, _ := s.Ajoute("https://youtu.be/AAA", "Titre", 1, t0)
	if err := s.PoseBas(p.ID, true); err != nil {
		t.Fatal(err)
	}
	pt, _, err := s.PourTirage()
	if err != nil {
		t.Fatal(err)
	}
	vu := false
	for _, x := range pt {
		if x.ID == p.ID {
			vu = true
			if !x.Bas {
				t.Fatal("le tirage ne voit pas la poussée vers le bas")
			}
		}
	}
	if !vu {
		t.Fatal("la piste n'est pas dans le tirage : le test ne prouve rien")
	}
}
