// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package store

import (
	"path/filepath"
	"sync"
	"testing"

	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/gateway"
)

func contenuTest(modif ...func(*gateway.Contenu)) gateway.Contenu {
	c := gateway.Contenu{
		Genre:        gateway.GenreTexte,
		Titre:        "Le puits de la ferme",
		Corps:        "Une note sur la remise en eau du puits.",
		Auteur:       "@gandalf@mastodon.example",
		SourceURL:    "https://mastodon.example/@gandalf/123",
		Connecteur:   "mastodon",
		RefNative:    "123",
		Propriete:    gateway.ProprieteSoi,
		NoeudOrigine: "gk2",
	}
	for _, m := range modif {
		m(&c)
	}
	_ = c.Valider()
	return c
}

// ── enregistrement et deduplication ──────────────────────────────────────

func TestUnContenuEnregistreSeRelit(t *testing.T) {
	s := ouvre(t)
	c := contenuTest()
	if _, err := s.GatewayEnregistrer(c); err != nil {
		t.Fatal(err)
	}
	lu, err := s.GatewayContenu(c.Empreinte)
	if err != nil {
		t.Fatal(err)
	}
	if lu.Titre != c.Titre || lu.SourceURL != c.SourceURL {
		t.Fatalf("relecture divergente : %+v", lu)
	}
	if lu.Propriete != gateway.ProprieteSoi {
		t.Fatalf("propriete perdue a la relecture : %q", lu.Propriete)
	}
}

func TestUnSecondImportNeCreeAucunDoublon(t *testing.T) {
	// Un collecteur repasse toutes les demi-heures sur le meme flux. Sans
	// cette garantie, la timeline se remplirait de repetitions.
	s := ouvre(t)
	c := contenuTest()
	if _, err := s.GatewayEnregistrer(c); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GatewayEnregistrer(c); err != nil {
		t.Fatal(err)
	}
	if n := s.gatewayCompte(t); n != 1 {
		t.Fatalf("%d contenus enregistres, attendu 1", n)
	}
}

func TestUnSecondImportEnrichitSansEcraser(t *testing.T) {
	// Le re-import est un no-op ENRICHISSANT : il complete ce qui manquait
	// sans effacer ce qu'on savait deja.
	s := ouvre(t)
	premier := contenuTest(func(c *gateway.Contenu) {
		c.Metadonnees = map[string]string{"langue": "fr"}
	})
	if _, err := s.GatewayEnregistrer(premier); err != nil {
		t.Fatal(err)
	}
	second := contenuTest(func(c *gateway.Contenu) {
		c.Metadonnees = map[string]string{"licence": "CC-BY"}
		c.Auteur = ""
	})
	if _, err := s.GatewayEnregistrer(second); err != nil {
		t.Fatal(err)
	}

	lu, err := s.GatewayContenu(premier.Empreinte)
	if err != nil {
		t.Fatal(err)
	}
	if lu.Metadonnees["langue"] != "fr" {
		t.Error("metadonnee du premier import perdue")
	}
	if lu.Metadonnees["licence"] != "CC-BY" {
		t.Error("metadonnee du second import ignoree")
	}
	if lu.Auteur == "" {
		t.Error("un champ vide du second import a efface une valeur connue")
	}
}

func TestLaRetentionAcquiseSurvitAUnReImport(t *testing.T) {
	// Un contenu epingle par l'utilisateur ne doit pas retomber en cache
	// parce que le collecteur l'a revu.
	s := ouvre(t)
	c := contenuTest()
	if _, err := s.GatewayEnregistrer(c); err != nil {
		t.Fatal(err)
	}
	if err := s.GatewayRetention(c.Empreinte, gateway.RetentionEpingle); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GatewayEnregistrer(contenuTest()); err != nil {
		t.Fatal(err)
	}
	lu, _ := s.GatewayContenu(c.Empreinte)
	if lu.Retention != gateway.RetentionEpingle {
		t.Fatalf("retention retombee a %q apres re-import", lu.Retention)
	}
}

func TestDeuxContenusDistinctsCoexistent(t *testing.T) {
	s := ouvre(t)
	if _, err := s.GatewayEnregistrer(contenuTest()); err != nil {
		t.Fatal(err)
	}
	autre := contenuTest(func(c *gateway.Contenu) {
		c.SourceURL = "https://mastodon.example/@gandalf/456"
		c.RefNative = "456"
		c.Corps = "Autre chose."
	})
	if _, err := s.GatewayEnregistrer(autre); err != nil {
		t.Fatal(err)
	}
	if n := s.gatewayCompte(t); n != 2 {
		t.Fatalf("%d contenus, attendu 2", n)
	}
}

// ── medias ───────────────────────────────────────────────────────────────

func TestLesMediasSuiventLeContenu(t *testing.T) {
	s := ouvre(t)
	c := contenuTest(func(c *gateway.Contenu) {
		c.Medias = []gateway.Media{
			{Chemin: "ab/x/photo.jpg", Mime: "image/jpeg", Taille: 4096, Somme: "aa"},
		}
	})
	if _, err := s.GatewayEnregistrer(c); err != nil {
		t.Fatal(err)
	}
	lu, err := s.GatewayContenu(c.Empreinte)
	if err != nil {
		t.Fatal(err)
	}
	if len(lu.Medias) != 1 || lu.Medias[0].Chemin != "ab/x/photo.jpg" {
		t.Fatalf("medias non relus : %+v", lu.Medias)
	}
}

func TestLaPurgeDesMediasGardeLeContenu(t *testing.T) {
	// Le ramasse-miettes libere de la place ; il ne doit jamais faire perdre
	// la trace d'un contenu, dont l'adresse source reste la seule facon de le
	// retrouver.
	s := ouvre(t)
	c := contenuTest(func(c *gateway.Contenu) {
		c.Medias = []gateway.Media{{Chemin: "a/1.jpg", Mime: "image/jpeg", Taille: 1, Somme: "11"}}
	})
	if _, err := s.GatewayEnregistrer(c); err != nil {
		t.Fatal(err)
	}
	if err := s.GatewayPurgerMedias(c.Empreinte); err != nil {
		t.Fatal(err)
	}
	lu, err := s.GatewayContenu(c.Empreinte)
	if err != nil {
		t.Fatalf("contenu perdu avec ses medias : %v", err)
	}
	if len(lu.Medias) != 0 {
		t.Fatalf("medias encore presents : %+v", lu.Medias)
	}
	if lu.SourceURL == "" {
		t.Error("adresse source perdue : le contenu est devenu introuvable")
	}
}

// ── recherche ────────────────────────────────────────────────────────────

func TestLaRechercheTrouveParTitreEtParCorps(t *testing.T) {
	s := ouvre(t)
	if _, err := s.GatewayEnregistrer(contenuTest()); err != nil {
		t.Fatal(err)
	}
	for _, mot := range []string{"puits", "remise"} {
		r, err := s.GatewayRechercher(mot, 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(r) != 1 {
			t.Fatalf("recherche %q : %d resultats, attendu 1", mot, len(r))
		}
	}
}

func TestLaRechercheIgnoreLesAccents(t *testing.T) {
	// « ferme » doit trouver « fermé » : sur un BBS local on tape vite.
	s := ouvre(t)
	c := contenuTest(func(c *gateway.Contenu) { c.Corps = "Le puits est fermé." })
	if _, err := s.GatewayEnregistrer(c); err != nil {
		t.Fatal(err)
	}
	r, err := s.GatewayRechercher("ferme", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(r) != 1 {
		t.Fatalf("%d resultats, attendu 1", len(r))
	}
}

func TestLaRechercheNeRendPasLesAutresTypes(t *testing.T) {
	// L'index est partage avec le reste du BBS : la recherche de la passerelle
	// ne doit pas ramener des fils de forum.
	s := ouvre(t)
	if _, err := s.GatewayEnregistrer(contenuTest()); err != nil {
		t.Fatal(err)
	}
	s.db.Exec(`INSERT INTO search(title, body, kind, ref_id, visibility)
	           VALUES('Le puits du voisin', 'autre chose', 'thread', '999', 'local')`)
	r, err := s.GatewayRechercher("puits", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(r) != 1 {
		t.Fatalf("%d resultats, attendu 1 (fuite d'un autre type)", len(r))
	}
}

func TestUnReImportNeDupliquePasLIndex(t *testing.T) {
	s := ouvre(t)
	c := contenuTest()
	for i := 0; i < 3; i++ {
		if _, err := s.GatewayEnregistrer(c); err != nil {
			t.Fatal(err)
		}
	}
	r, err := s.GatewayRechercher("puits", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(r) != 1 {
		t.Fatalf("%d resultats pour un seul contenu", len(r))
	}
}

// ── migration et concurrence ─────────────────────────────────────────────

func TestLaMigrationDeLaPasserelleEstAppliquee(t *testing.T) {
	s := ouvre(t)
	var n int
	err := s.db.QueryRow(
		`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='gateway_contenu'`).Scan(&n)
	if err != nil || n != 1 {
		t.Fatalf("table absente (n=%d, err=%v)", n, err)
	}
}

func TestDeuxEcrivainsSimultanesNEchouentPas(t *testing.T) {
	// WAL plus busy_timeout : deux collecteurs qui ecrivent en meme temps
	// doivent s'attendre, pas echouer.
	s := ouvre(t)
	var wg sync.WaitGroup
	erreurs := make(chan error, 20)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c := contenuTest(func(c *gateway.Contenu) {
				c.SourceURL = "https://exemple.org/article/" + string(rune('a'+i))
				c.RefNative = string(rune('a' + i))
			})
			if _, err := s.GatewayEnregistrer(c); err != nil {
				erreurs <- err
			}
		}(i)
	}
	wg.Wait()
	close(erreurs)
	for err := range erreurs {
		t.Fatalf("ecriture concurrente refusee : %v", err)
	}
	if n := s.gatewayCompte(t); n != 10 {
		t.Fatalf("%d contenus, attendu 10", n)
	}
}

func TestLaBaseSurviTAUneReouverture(t *testing.T) {
	dir := t.TempDir()
	chemin := filepath.Join(dir, "bbs.db")
	s1, err := Open(chemin)
	if err != nil {
		t.Fatal(err)
	}
	c := contenuTest()
	if _, err := s1.GatewayEnregistrer(c); err != nil {
		t.Fatal(err)
	}
	s1.Close()

	s2, err := Open(chemin)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if _, err := s2.GatewayContenu(c.Empreinte); err != nil {
		t.Fatalf("contenu perdu apres reouverture : %v", err)
	}
}

// gatewayCompte rend le nombre de contenus enregistrés.
func (s *Store) gatewayCompte(t *testing.T) int {
	t.Helper()
	var n int
	if err := s.db.QueryRow(`SELECT count(*) FROM gateway_contenu`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
