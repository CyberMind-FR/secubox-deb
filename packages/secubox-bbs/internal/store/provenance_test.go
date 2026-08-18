// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package store

import (
	"strings"
	"testing"

	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/gateway"
)

// ── chaine ───────────────────────────────────────────────────────────────

func TestLePremierEvenementOuvreLaChaine(t *testing.T) {
	s := ouvre(t)
	c := contenuTest()
	if _, err := s.GatewayEnregistrer(c); err != nil {
		t.Fatal(err)
	}
	ev, err := s.GatewayProvenance(c.Empreinte)
	if err != nil {
		t.Fatal(err)
	}
	if len(ev) == 0 {
		t.Fatal("l'enregistrement d'un contenu ne laisse aucune trace")
	}
	if ev[0].Precedent != "" {
		t.Fatalf("le premier maillon devrait n'avoir aucun predecesseur, il porte %q", ev[0].Precedent)
	}
	if ev[0].Evenement != gateway.EvImporte {
		t.Fatalf("premier evenement = %q, attendu %q", ev[0].Evenement, gateway.EvImporte)
	}
}

func TestChaqueMaillonTientAuPrecedent(t *testing.T) {
	s := ouvre(t)
	c := contenuTest()
	s.GatewayEnregistrer(c)
	for _, e := range []string{gateway.EvEpingle, gateway.EvArchive, gateway.EvPurge} {
		if err := s.GatewayNoter(c.Empreinte, e, "gandalf", nil); err != nil {
			t.Fatal(err)
		}
	}
	ev, _ := s.GatewayProvenance(c.Empreinte)
	if len(ev) != 4 {
		t.Fatalf("%d evenements, attendu 4", len(ev))
	}
	for i := 1; i < len(ev); i++ {
		if ev[i].Precedent != ev[i-1].Somme {
			t.Fatalf("maillon %d detache de son predecesseur", i)
		}
	}
}

func TestLaChaineSeVerifie(t *testing.T) {
	s := ouvre(t)
	c := contenuTest()
	s.GatewayEnregistrer(c)
	s.GatewayNoter(c.Empreinte, gateway.EvEpingle, "gandalf", nil)
	if err := s.GatewayVerifierProvenance(); err != nil {
		t.Fatalf("chaine intacte declaree corrompue : %v", err)
	}
}

func TestUneFalsificationEstDetectee(t *testing.T) {
	// Toute la valeur de la chaine est la : quelqu'un qui reecrit l'histoire
	// d'un contenu — pour effacer d'ou il vient, par exemple — doit laisser
	// une trace impossible a masquer sans recalculer TOUTE la suite.
	s := ouvre(t)
	c := contenuTest()
	s.GatewayEnregistrer(c)
	s.GatewayNoter(c.Empreinte, gateway.EvEpingle, "gandalf", nil)
	s.GatewayNoter(c.Empreinte, gateway.EvArchive, "gandalf", nil)

	// Les declencheurs protegent l'APPLICATION ; ils n'arretent pas quelqu'un
	// qui tient le fichier de base. C'est precisement contre celui-la que la
	// chaine existe, alors on se met a sa place : on retire les garde-fous
	// avant de reecrire l'histoire.
	sansGardeFous(t, s)
	if _, err := s.db.Exec(
		`UPDATE gateway_provenance SET acteur='sauron' WHERE evenement=?`,
		gateway.EvEpingle); err != nil {
		t.Fatalf("reecriture impossible, le test ne prouve rien : %v", err)
	}
	if err := s.GatewayVerifierProvenance(); err == nil {
		t.Fatal("une reecriture de l'histoire passe inapercue")
	}
}

func TestLaSuppressionDUnMaillonEstDetectee(t *testing.T) {
	// La chaine est GLOBALE, pas par contenu : effacer tout l'historique d'un
	// objet — donc son origine — casse aussi la chaine commune.
	s := ouvre(t)
	c := contenuTest()
	s.GatewayEnregistrer(c)
	s.GatewayNoter(c.Empreinte, gateway.EvEpingle, "gandalf", nil)
	s.GatewayNoter(c.Empreinte, gateway.EvArchive, "gandalf", nil)

	sansGardeFous(t, s)
	if _, err := s.db.Exec(`DELETE FROM gateway_provenance WHERE evenement=?`,
		gateway.EvEpingle); err != nil {
		t.Fatalf("suppression impossible, le test ne prouve rien : %v", err)
	}
	if err := s.GatewayVerifierProvenance(); err == nil {
		t.Fatal("la disparition d'un maillon passe inapercue")
	}
}

func TestLaChaineEstCommuneATousLesContenus(t *testing.T) {
	s := ouvre(t)
	a := contenuTest()
	b := contenuTest(func(c *gateway.Contenu) {
		c.SourceURL = "https://exemple.org/autre"
		c.RefNative = "autre"
	})
	s.GatewayEnregistrer(a)
	s.GatewayEnregistrer(b)

	var n int
	s.db.QueryRow(`SELECT count(DISTINCT precedent) FROM gateway_provenance`).Scan(&n)
	// Deux maillons distincts : la chaine ouverte, puis accrochee au premier.
	if n != 2 {
		t.Fatalf("%d predecesseurs distincts : les contenus n'entrent pas dans une chaine commune", n)
	}
	if err := s.GatewayVerifierProvenance(); err != nil {
		t.Fatal(err)
	}
}

// ── append-only ──────────────────────────────────────────────────────────

func TestLeJournalRefuseLaModification(t *testing.T) {
	// Append-only impose par la base elle-meme : meme un defaut de code ne
	// doit pas pouvoir reecrire une ligne deja posee.
	s := ouvre(t)
	c := contenuTest()
	s.GatewayEnregistrer(c)
	if _, err := s.db.Exec(`UPDATE gateway_provenance SET acteur='sauron'`); err == nil {
		t.Fatal("le journal accepte une modification")
	}
}

func TestLeJournalRefuseLaSuppression(t *testing.T) {
	s := ouvre(t)
	c := contenuTest()
	s.GatewayEnregistrer(c)
	if _, err := s.db.Exec(`DELETE FROM gateway_provenance`); err == nil {
		t.Fatal("le journal accepte une suppression")
	}
}

// ── contenu des evenements ───────────────────────────────────────────────

func TestUnEvenementInconnuEstRefuse(t *testing.T) {
	s := ouvre(t)
	c := contenuTest()
	s.GatewayEnregistrer(c)
	if err := s.GatewayNoter(c.Empreinte, "teleportation", "gandalf", nil); err == nil {
		t.Fatal("evenement hors vocabulaire accepte")
	}
}

func TestLesDetailsSontConserves(t *testing.T) {
	s := ouvre(t)
	c := contenuTest()
	s.GatewayEnregistrer(c)
	if err := s.GatewayNoter(c.Empreinte, gateway.EvReplique, "gandalf",
		map[string]string{"cible": "peertube"}); err != nil {
		t.Fatal(err)
	}
	ev, _ := s.GatewayProvenance(c.Empreinte)
	dernier := ev[len(ev)-1]
	if dernier.Details["cible"] != "peertube" {
		t.Fatalf("details perdus : %+v", dernier.Details)
	}
}

func TestLaPurgeDesMediasLaisseLHistoireIntacte(t *testing.T) {
	// Le ramasse-miettes retire des fichiers ; l'histoire du contenu, elle,
	// ne se purge jamais.
	s := ouvre(t)
	c := contenuTest(func(c *gateway.Contenu) {
		c.Medias = []gateway.Media{{Chemin: "a/1.jpg", Mime: "image/jpeg", Taille: 1, Somme: "11"}}
	})
	s.GatewayEnregistrer(c)
	avant, _ := s.GatewayProvenance(c.Empreinte)
	if err := s.GatewayPurgerMedias(c.Empreinte); err != nil {
		t.Fatal(err)
	}
	apres, _ := s.GatewayProvenance(c.Empreinte)
	if len(apres) < len(avant) {
		t.Fatalf("l'histoire a retreci : %d -> %d", len(avant), len(apres))
	}
	if err := s.GatewayVerifierProvenance(); err != nil {
		t.Fatal(err)
	}
}

func TestUnReImportNAjoutePasUnImport(t *testing.T) {
	// Revoir un contenu n'est pas l'importer : sinon l'histoire se remplirait
	// d'un evenement toutes les demi-heures, pour rien.
	s := ouvre(t)
	c := contenuTest()
	s.GatewayEnregistrer(c)
	s.GatewayEnregistrer(c)
	s.GatewayEnregistrer(c)
	ev, _ := s.GatewayProvenance(c.Empreinte)
	var imports int
	for _, e := range ev {
		if e.Evenement == gateway.EvImporte {
			imports++
		}
	}
	if imports != 1 {
		t.Fatalf("%d evenements d'import pour un seul contenu", imports)
	}
}

func TestLaSommeEstDuBlake2bHexadecimal(t *testing.T) {
	s := ouvre(t)
	c := contenuTest()
	s.GatewayEnregistrer(c)
	ev, _ := s.GatewayProvenance(c.Empreinte)
	somme := ev[0].Somme
	if len(somme) != 64 || strings.ToLower(somme) != somme {
		t.Fatalf("somme inattendue : %q", somme)
	}
}

// sansGardeFous retire les declencheurs d'immuabilite, pour se placer dans la
// peau de qui accede directement au fichier de base.
func sansGardeFous(t *testing.T, s *Store) {
	t.Helper()
	for _, d := range []string{
		"gateway_provenance_immuable_maj",
		"gateway_provenance_immuable_suppr",
	} {
		if _, err := s.db.Exec("DROP TRIGGER IF EXISTS " + d); err != nil {
			t.Fatalf("retrait du declencheur %s : %v", d, err)
		}
	}
}
