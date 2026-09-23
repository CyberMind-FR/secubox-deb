// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

package ser

import (
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// service lève un faux moteur d'inférence sur une socket unix.
func service(t *testing.T, h http.HandlerFunc) string {
	t.Helper()
	chemin := filepath.Join(t.TempDir(), "inf.sock")
	l, err := net.Listen("unix", chemin)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close(); os.Remove(chemin) })
	return chemin
}

func traitsParlants() Traits {
	v := ordinaire()
	v.TramesVoisees = 60
	return v
}

// LE MODÈLE NE PEUT PAS CONTOURNER LA RÈGLE CARDINALE. Un service qui se dit
// sûr à 99,9 % doit être ramené au plafond comme n'importe quelle autre source.
func TestUnModeleTropSurDeLuiEstRabote(t *testing.T) {
	s := service(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(reponseExterne{
			Indices: map[string]float64{Colere: 0.999, Calme: 0.001},
			Modele:  "certitude-9000", Corpus: "acteurs",
		})
	})
	e := NouvelExterne(s, nil, time.Second)
	l := e.Evalue(traitsParlants())
	if l.Confiance > PlafondConfiance {
		t.Fatalf("confiance %.3f : le plafond a été contourné", l.Confiance)
	}
	if l.Reserve == "" {
		t.Error("la réserve a disparu en passant par le modèle externe")
	}
}

// UN CORPUS NON DÉCLARÉ EST UN BIAIS INCONNU : il faut que ça se voie.
func TestUnCorpusNonDeclareEstSignale(t *testing.T) {
	s := service(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(reponseExterne{
			Indices: map[string]float64{Joie: 0.8, Calme: 0.2}, Modele: "x",
		})
	})
	l := NouvelExterne(s, nil, time.Second).Evalue(traitsParlants())
	if !strings.Contains(strings.Join(l.Pourquoi, " "), "biais inconnus") {
		t.Fatalf("rien ne signale le corpus manquant : %v", l.Pourquoi)
	}
}

// UNE PANNE D'INFÉRENCE N'EST PAS UN CHANGEMENT D'HUMEUR. On retombe sur
// l'heuristique, et on le DIT dans la lecture.
func TestUneInferenceInjoignableReplieEtLeDit(t *testing.T) {
	_, h := etalonne(t)
	e := NouvelExterne(filepath.Join(t.TempDir(), "absente.sock"), h, 50*time.Millisecond)
	l := e.Evalue(traitsParlants())
	if l.Etat == "" {
		t.Fatal("aucune lecture rendue malgré le secours")
	}
	if !strings.Contains(strings.Join(l.Pourquoi, " "), "repli") {
		t.Fatalf("le repli n'est pas signalé : %v", l.Pourquoi)
	}
	if e.DerniereErreur() == nil {
		t.Error("l'erreur n'est pas retenue pour l'affichage")
	}
}

func TestSansSecoursUneInferenceMorteRendIndetermine(t *testing.T) {
	e := NouvelExterne(filepath.Join(t.TempDir(), "absente.sock"), nil, 50*time.Millisecond)
	if l := e.Evalue(traitsParlants()); l.Etat != Indetermine {
		t.Fatalf("état %q alors que rien ne répond", l.Etat)
	}
}

// Une étiquette inconnue du modèle ne doit pas entrer dans nos indices : on ne
// sait pas ce qu'elle désigne, et l'afficher reviendrait à l'endosser.
func TestUneEtiquetteInconnueEstIgnoree(t *testing.T) {
	s := service(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(reponseExterne{
			Indices: map[string]float64{Calme: 0.5, "mepris": 0.5, "extase": 9},
			Modele:  "m", Corpus: "c",
		})
	})
	l := NouvelExterne(s, nil, time.Second).Evalue(traitsParlants())
	for k := range l.Indices {
		if k == "mepris" || k == "extase" {
			t.Fatalf("étiquette inconnue reprise telle quelle : %v", l.Indices)
		}
	}
	somme := 0.0
	for _, v := range l.Indices {
		somme += v
	}
	if somme < 0.98 || somme > 1.02 {
		t.Fatalf("indices non renormalisés après filtrage : somme %.3f", somme)
	}
}

func TestUneReponseVideNEstPasUneLecture(t *testing.T) {
	s := service(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(reponseExterne{Indices: map[string]float64{}})
	})
	if l := NouvelExterne(s, nil, time.Second).Evalue(traitsParlants()); l.Etat != Indetermine {
		t.Fatalf("état %q sur une réponse vide", l.Etat)
	}
}

// Le service met trop de temps : on ne bloque pas le flux à 20 images/seconde
// pour attendre un modèle lent.
func TestUnServiceLentNeBloquePasLeFlux(t *testing.T) {
	s := service(t, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
	})
	_, h := etalonne(t)
	e := NouvelExterne(s, h, 30*time.Millisecond)
	debut := time.Now()
	e.Evalue(traitsParlants())
	if d := time.Since(debut); d > 200*time.Millisecond {
		t.Fatalf("l'évaluation a pris %v : le délai n'est pas tenu", d)
	}
}
