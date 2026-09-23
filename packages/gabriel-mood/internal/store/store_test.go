// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

package store

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func ouvrir(t *testing.T) *Store {
	t.Helper()
	s, err := Ouvre(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Ferme() })
	return s
}

// LE TEST QUI GARDE LA PROMESSE. Si quelqu'un ajoute un jour une colonne qui
// pourrait contenir du son — des échantillons, une forme d'onde, un extrait —
// ce test doit le réveiller. La promesse « aucun audio sur le disque » ne vaut
// que si elle est vérifiée quelque part.
func TestAucuneColonneNePeutContenirDuSon(t *testing.T) {
	s := ouvrir(t)
	lignes, err := s.db.Query(`PRAGMA table_info(resume)`)
	if err != nil {
		t.Fatal(err)
	}
	defer lignes.Close()
	var noms []string
	for lignes.Next() {
		var cid int
		var nom, typ string
		var notnull, pk int
		var def any
		if err := lignes.Scan(&cid, &nom, &typ, &notnull, &def, &pk); err != nil {
			t.Fatal(err)
		}
		noms = append(noms, nom)
		if typ == "BLOB" {
			t.Errorf("colonne %q de type BLOB : rien ne devrait pouvoir y tenir un extrait sonore", nom)
		}
		for _, interdit := range []string{"audio", "pcm", "sample", "echantillon", "onde", "wav", "extrait"} {
			if strings.Contains(strings.ToLower(nom), interdit) {
				t.Errorf("colonne %q : le schéma ne doit rien porter qui ressemble à du son", nom)
			}
		}
	}
	attendu := []string{"minute", "session", "f0", "f0_etendue", "energie", "debit",
		"jitter", "shimmer", "activation", "etat", "confiance", "part_voisee"}
	if !reflect.DeepEqual(noms, attendu) {
		t.Errorf("le schéma a changé :\n  %v\nattendu :\n  %v\n"+
			"Toute colonne ajoutée doit être relue à l'aune de la promesse de confidentialité.",
			noms, attendu)
	}
}

func TestEnregistreEtRelit(t *testing.T) {
	s := ouvrir(t)
	m := time.Now().Truncate(time.Minute)
	r := Resume{Minute: m.Unix(), Session: "s1", F0Median: 132.4, Energie: 0.61,
		Debit: 145, Etat: "calm", Confiance: 0.42}
	if err := s.Enregistre(r); err != nil {
		t.Fatal(err)
	}
	out, err := s.Depuis(m.Add(-time.Hour), 10)
	if err != nil || len(out) != 1 {
		t.Fatalf("%d lignes, %v", len(out), err)
	}
	if out[0].F0Median != 132.4 || out[0].Etat != "calm" {
		t.Fatalf("relu %+v", out[0])
	}
}

// Une minute ne doit exister qu'une fois par session : sinon un historique
// d'une heure compterait des milliers de lignes pour soixante minutes.
func TestUneMinuteNEstEcriteQuUneFois(t *testing.T) {
	s := ouvrir(t)
	m := time.Now().Truncate(time.Minute).Unix()
	for i := 0; i < 50; i++ {
		s.Enregistre(Resume{Minute: m, Session: "s1", Energie: float64(i)})
	}
	out, _ := s.Depuis(time.Unix(m, 0).Add(-time.Hour), 100)
	if len(out) != 1 {
		t.Fatalf("%d lignes pour une seule minute", len(out))
	}
	if out[0].Energie != 49 {
		t.Errorf("la dernière écriture doit gagner : énergie %v", out[0].Energie)
	}
}

// UN HISTORIQUE QUI NE S'EFFACE PAS EST UN DOSSIER.
func TestLaPurgeEfface(t *testing.T) {
	s := ouvrir(t)
	vieux := time.Now().Add(-48 * time.Hour).Truncate(time.Minute)
	recent := time.Now().Truncate(time.Minute)
	s.Enregistre(Resume{Minute: vieux.Unix(), Session: "s1"})
	s.Enregistre(Resume{Minute: recent.Unix(), Session: "s1"})
	n, err := s.Purge(time.Now().Add(-24 * time.Hour))
	if err != nil || n != 1 {
		t.Fatalf("purge : %d lignes, %v", n, err)
	}
	out, _ := s.Depuis(time.Time{}, 100)
	if len(out) != 1 || out[0].Minute != recent.Unix() {
		t.Fatalf("la purge a effacé la mauvaise ligne : %+v", out)
	}
}

// « Oubliez-moi » doit exister, et fonctionner.
func TestOublierUneSessionNEffacePasLesAutres(t *testing.T) {
	s := ouvrir(t)
	m := time.Now().Truncate(time.Minute).Unix()
	s.Enregistre(Resume{Minute: m, Session: "moi"})
	s.Enregistre(Resume{Minute: m, Session: "autre"})
	n, err := s.OublieSession("moi")
	if err != nil || n != 1 {
		t.Fatalf("oubli : %d, %v", n, err)
	}
	out, _ := s.Depuis(time.Time{}, 10)
	if len(out) != 1 || out[0].Session != "autre" {
		t.Fatalf("restant : %+v", out)
	}
}

func TestLaLimiteEstBornee(t *testing.T) {
	s := ouvrir(t)
	base := time.Now().Truncate(time.Minute).Unix()
	for i := 0; i < 50; i++ {
		s.Enregistre(Resume{Minute: base - int64(i*60), Session: "s"})
	}
	out, _ := s.Depuis(time.Time{}, -1) // limite absurde : doit être bornée
	if len(out) != 50 {
		t.Fatalf("%d lignes", len(out))
	}
	out, _ = s.Depuis(time.Time{}, 10)
	if len(out) != 10 {
		t.Fatalf("%d lignes pour une limite de 10", len(out))
	}
}
