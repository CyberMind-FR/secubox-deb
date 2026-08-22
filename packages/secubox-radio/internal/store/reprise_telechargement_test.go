package store

import "testing"

// UN ÉCHEC DE TÉLÉCHARGEMENT EST SOUVENT PASSAGER. Un 403 de YouTube sur les
// octets vidéo (throttle/edge CDN) écarte la piste sur le moment ; mais la
// passerelle réussit au réessai suivant. Sans remise en jeu, la piste reste
// écartée POUR TOUJOURS, avec une erreur périmée sous les yeux (#1131f). La
// remise ne touche QUE les échecs de téléchargement — pas un blocage cookies,
// une géo-restriction, ni un refus du sysop.
func TestRemetEnJeuLesEchecsDeTelechargement(t *testing.T) {
	s := banc(t)
	dl, _, _ := s.Ajoute("https://youtu.be/DL403", "403 passager", 1, t0)
	ck, _, _ := s.Ajoute("https://youtu.be/COOK", "cookies", 1, t0)
	geo, _, _ := s.Ajoute("https://youtu.be/GEO", "géo", 1, t0)

	if err := s.MarqueIndisponible(dl.ID, "ERROR: unable to download video data: HTTP Error 403: Forbidden"); err != nil {
		t.Fatal(err)
	}
	if err := s.MarqueIndisponible(ck.ID, "auth requise — dépose tes cookies"); err != nil {
		t.Fatal(err)
	}
	if err := s.MarqueIndisponible(geo.ID, "géo-bloqué"); err != nil {
		t.Fatal(err)
	}

	n, err := s.RemetEnJeuEchecsTelechargement()
	if err != nil {
		t.Fatalf("remise en jeu : %v", err)
	}
	if n != 1 {
		t.Fatalf("attendu 1 piste remise en jeu, obtenu %d", n)
	}
	if q, _ := s.ParID(dl.ID); q.Indisponible {
		t.Error("l'échec de téléchargement (403) reste écarté")
	}
	if q, _ := s.ParID(ck.ID); !q.Indisponible {
		t.Error("un blocage cookies a été remis en jeu à tort")
	}
	if q, _ := s.ParID(geo.ID); !q.Indisponible {
		t.Error("une géo-restriction a été remise en jeu à tort")
	}
}
