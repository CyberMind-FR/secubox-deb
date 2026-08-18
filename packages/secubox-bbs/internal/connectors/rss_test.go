// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package connectors

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/gateway"
)

const fluxRSS = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"><channel>
  <title>Le journal de la vallée</title>
  <item>
    <title>La foire aux plants revient dimanche</title>
    <link>https://exemple.org/foire-aux-plants</link>
    <guid>foire-2026-08</guid>
    <description>Comme chaque printemps, la place se couvre d'étals.</description>
    <pubDate>Wed, 13 Aug 2026 08:00:00 +0200</pubDate>
  </item>
  <item>
    <title>Le pont de la Cluse enfin rouvert</title>
    <link>https://exemple.org/pont-cluse</link>
    <guid>pont-2026-08</guid>
    <description>Après six mois de travaux.</description>
    <pubDate>Mon, 11 Aug 2026 17:30:00 +0200</pubDate>
  </item>
</channel></rss>`

const fluxAtom = `<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>Carnet d'atelier</title>
  <entry>
    <title>Affûter une plane</title>
    <link href="https://exemple.org/affuter-plane"/>
    <id>urn:atelier:affuter-plane</id>
    <summary>Le geste, l'angle, la pierre.</summary>
    <updated>2026-08-12T10:00:00Z</updated>
  </entry>
</feed>`

// serveur rend un flux depuis une fixture, sans jamais toucher au réseau.
func serveur(t *testing.T, corps string) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rss+xml")
		w.Write([]byte(corps))
	}))
	t.Cleanup(s.Close)
	return s
}

func rss(t *testing.T) *RSS {
	t.Helper()
	// Garde réseau permissif : ces tests éprouvent le PARSING, et httptest sert
	// forcément sur 127.0.0.1 que le garde réel refuserait. Le test anti-SSRF
	// ci-dessous, lui, construit un connecteur au garde réel.
	c, err := NewRSS(Config{NoeudOrigine: "gk2",
		GardeReseau: func(string) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// ── manifeste ────────────────────────────────────────────────────────────

func TestLeManifesteRSSEstValideEtSaitLire(t *testing.T) {
	m := rss(t).Manifeste()
	if err := m.Valider(); err != nil {
		t.Fatalf("manifeste RSS invalide : %v", err)
	}
	if !m.SaitFaire(gateway.CapResoudre) || !m.SaitFaire(gateway.CapTirer) {
		t.Fatal("le RSS devrait savoir résoudre et tirer")
	}
	if m.SaitFaire(gateway.CapPousser) {
		t.Fatal("un flux RSS ne publie rien")
	}
}

func TestLeConnecteurRSSNePubliePas(t *testing.T) {
	// Le contrat le garantit déjà (pas de Sortie), on le vérifie côté produit :
	// on ne republie pas VERS un flux qu'on ne fait que lire.
	c := gateway.Contenu{Genre: gateway.GenreLien, SourceURL: "https://exemple.org/a",
		Connecteur: "rss", Propriete: gateway.ProprieteSoi, NoeudOrigine: "gk2"}
	if _, err := rss(t).Publier(c); err != gateway.ErrPasDePublication {
		t.Fatalf("erreur attendue ErrPasDePublication, obtenu %v", err)
	}
}

// ── résolution ───────────────────────────────────────────────────────────

func TestResoudreUnFluxRSSDonneSonPremierArticle(t *testing.T) {
	s := serveur(t, fluxRSS)
	c, err := rss(t).Resoudre(s.URL)
	if err != nil {
		t.Fatal(err)
	}
	if c.Titre != "La foire aux plants revient dimanche" {
		t.Fatalf("titre inattendu : %q", c.Titre)
	}
	if c.Connecteur != "rss" || c.NoeudOrigine != "gk2" {
		t.Fatalf("champs de contexte manquants : %+v", c)
	}
	if err := c.Valider(); err != nil {
		t.Fatalf("contenu résolu invalide : %v", err)
	}
}

func TestResoudreRenseigneLaProprieteTiers(t *testing.T) {
	// Un flux d'actualité n'est pas le vôtre : par défaut c'est du tiers, donc
	// non republiable. Ne jamais présumer l'inverse.
	s := serveur(t, fluxRSS)
	c, _ := rss(t).Resoudre(s.URL)
	if c.Propriete != gateway.ProprieteTiers {
		t.Fatalf("propriété par défaut = %q, attendu tiers", c.Propriete)
	}
	if c.EstRepubliable() {
		t.Fatal("un article de flux tiers ne doit pas être republiable")
	}
}

func TestUnFluxDeclareCommeSienEstAMoi(t *testing.T) {
	// Si le flux est celui de l'utilisateur (déclaré en conf), ses articles
	// lui appartiennent et redeviennent republiables.
	s := serveur(t, fluxRSS)
	c, err := NewRSS(Config{NoeudOrigine: "gk2", FluxPropres: []string{"le journal"},
		GardeReseau: func(string) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := c.ResoudreFlux(s.URL)
	if len(got) == 0 || got[0].Propriete != gateway.ProprieteSoi {
		t.Fatalf("un flux déclaré sien devrait donner du contenu à moi : %+v", got)
	}
}

// ── tirage ───────────────────────────────────────────────────────────────

func TestTirerRendTousLesArticles(t *testing.T) {
	s := serveur(t, fluxRSS)
	c := rss(t)
	c.Ajouter(s.URL)
	items, err := c.Tirer(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 {
		t.Fatalf("%d articles, attendu 2", len(items))
	}
}

func TestTirerLitAussiLAtom(t *testing.T) {
	s := serveur(t, fluxAtom)
	c := rss(t)
	c.Ajouter(s.URL)
	items, err := c.Tirer(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Titre != "Affûter une plane" {
		t.Fatalf("Atom mal lu : %+v", items)
	}
}

func TestTirerDepuisNeRendQueLePlusRecent(t *testing.T) {
	// Tirage incrémental : on ne rapatrie que ce qui a paru APRÈS le dernier
	// passage, sinon chaque collecte relit tout le flux.
	s := serveur(t, fluxRSS)
	c := rss(t)
	c.Ajouter(s.URL)
	// entre les deux articles (11 août < seuil < 13 août)
	seuil := int64(1786500000) // entre le 11 (pont) et le 13 (foire) aout 2026
	items, err := c.Tirer(seuil)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Titre != "La foire aux plants revient dimanche" {
		t.Fatalf("filtrage incrémental faux : %+v", items)
	}
}

func TestDeuxTiragesIdentiquesDonnentLesMemesReferences(t *testing.T) {
	// Idempotence : la référence native d'un article ne bouge pas d'un tirage
	// à l'autre, c'est ce qui permet à la déduplication de faire son travail.
	s := serveur(t, fluxRSS)
	c := rss(t)
	c.Ajouter(s.URL)
	a, _ := c.Tirer(0)
	b, _ := c.Tirer(0)
	if a[0].RefNative != b[0].RefNative || a[0].RefNative == "" {
		t.Fatalf("référence instable : %q vs %q", a[0].RefNative, b[0].RefNative)
	}
}

func TestUnArticleSansGuidUtiliseSonLien(t *testing.T) {
	flux := strings.Replace(fluxRSS, "<guid>foire-2026-08</guid>", "", 1)
	s := serveur(t, flux)
	c := rss(t)
	c.Ajouter(s.URL)
	items, _ := c.Tirer(0)
	if items[0].RefNative != "https://exemple.org/foire-aux-plants" {
		t.Fatalf("sans guid, la référence devrait être le lien : %q", items[0].RefNative)
	}
}

// ── robustesse ───────────────────────────────────────────────────────────

func TestUnFluxIllisibleEchoueSansPaniquer(t *testing.T) {
	s := serveur(t, "<ceci n'est pas du xml")
	if _, err := rss(t).Resoudre(s.URL); err == nil {
		t.Fatal("un flux illisible devrait donner une erreur, pas un contenu vide")
	}
}

func TestUnFluxVideNeRienResoudre(t *testing.T) {
	s := serveur(t, `<rss version="2.0"><channel><title>vide</title></channel></rss>`)
	if _, err := rss(t).Resoudre(s.URL); err == nil {
		t.Fatal("résoudre un flux sans article devrait échouer clairement")
	}
}

// ── garde réseau ─────────────────────────────────────────────────────────

func TestUnFluxSurLeReseauInterneEstRefuse(t *testing.T) {
	// Un flux ajouté par un membre ne doit pas servir à sonder le réseau
	// interne (SSRF). Le garde vit dans internal/reseau, partagé avec Mastodon.
	// Ici, connecteur au garde RÉEL — c'est lui qu'on met à l'épreuve.
	c, err := NewRSS(Config{NoeudOrigine: "gk2"})
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range []string{
		"http://127.0.0.1:8091/x", "http://10.100.0.1/x",
		"http://169.254.169.254/latest/meta-data", "file:///etc/passwd",
	} {
		if _, err := c.Resoudre(u); err == nil {
			t.Fatalf("adresse interne/locale acceptée : %s", u)
		}
	}
}

func TestLeConnecteurRSSResteSain(t *testing.T) {
	if !rss(t).Sante().Utilisable() {
		t.Fatal("un connecteur RSS neuf devrait être sain")
	}
}
