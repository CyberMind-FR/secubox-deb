package web

import (
	"strings"
	"testing"
)

// La banniere de sante injecte une <style>. Tant que son empreinte manquait de
// `style-src`, le navigateur refusait la feuille et la banniere tombait en bas
// de page — sans que rien, cote serveur, ne signale quoi que ce soit.
func TestEmpreinteDeStyleDansStyleSrc(t *testing.T) {
	s := &Serveur{BanniereStyle: "sha256-cDIMF0VHleQj8Or2kSnnBba00DygyPImvtNVZIuif5I="}
	p := s.politique()
	if !strings.Contains(p, "style-src 'self' 'sha256-cDIMF0VHleQj8Or2kSnnBba00DygyPImvtNVZIuif5I") {
		t.Fatalf("empreinte de style absente de style-src : %s", p)
	}
	// ET SURTOUT PAS AILLEURS : une empreinte de feuille qui autoriserait un
	// script porterait bien plus loin que ce qu'on a voulu ouvrir.
	av := p[:strings.Index(p, "style-src")]
	if strings.Contains(av, "cDIMF0VHleQj8Or2kSnnBba00DygyPImvtNVZIuif5I") {
		t.Fatalf("empreinte de style repandue dans script-src : %s", p)
	}
}

// Une valeur incorrecte ne doit pas produire de politique bancale : mieux vaut
// une banniere non stylee qu'une politique qu'un navigateur jette en entier.
func TestEmpreinteDeStyleInvalideIgnoree(t *testing.T) {
	for _, mauvais := range []string{"n importe quoi", "'; script-src *", "sha256-", ""} {
		p := (&Serveur{BanniereStyle: mauvais}).politique()
		if !strings.Contains(p, "style-src 'self';") {
			t.Fatalf("%q a altere style-src : %s", mauvais, p)
		}
	}
}
