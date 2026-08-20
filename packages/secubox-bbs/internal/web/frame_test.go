package web

import (
	"strings"
	"testing"
)

// Incorporer un service lui donne un contexte d'execution dans notre page.
// La liste est donc ce qui borne ce droit — et elle doit etre revalidee : une
// entree contenant un point-virgule couperait la politique en deux, et un
// navigateur qui n'arrive pas a la lire peut l'ignorer ENTIEREMENT.
func TestFrameSrcNAdmetQueDesOriginesSaines(t *testing.T) {
	s := &Server{opt: Options{
		PeerTubeOrigine: "https://peertube.gk2.secubox.in",
		FrameOrigines: []string{
			"https://radio.gk2.secubox.in/", // la barre finale est retiree
			"https://podcaster.gk2.secubox.in",
			"https://peertube.gk2.secubox.in", // doublon
			"https://mal.example; script-src *",
			"https://espace .example",
			"",
		},
	}}
	f := s.frameSrc()
	for _, bon := range []string{"peertube.gk2", "radio.gk2", "podcaster.gk2"} {
		if !strings.Contains(f, bon) {
			t.Errorf("origine saine absente (%s) : %s", bon, f)
		}
	}
	if strings.ContainsAny(f, ";'\"") {
		t.Fatalf("POLITIQUE COUPABLE EN DEUX : %s", f)
	}
	if strings.Count(f, "peertube.gk2") != 1 {
		t.Errorf("doublon conserve : %s", f)
	}
	if strings.Contains(f, "/ ") || strings.HasSuffix(f, "/") {
		t.Errorf("barre finale conservee : %s", f)
	}
}

// #1056 : la board integre YouTube, donc frame-src n'est plus jamais 'none' —
// il vaut au minimum l'hote cookieless. Aucune AUTRE origine sans configuration.
func TestFrameSrcFermeParDefaut(t *testing.T) {
	f := (&Server{}).frameSrc()
	if f != "https://www.youtube-nocookie.com" {
		t.Fatalf("frame-src par defaut inattendu : %s", f)
	}
}
