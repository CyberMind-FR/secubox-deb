// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

package web

import (
	"strings"
	"testing"
)

const pt = "https://peertube.gk2.secubox.in"

func avecPeertube(t *testing.T) func() {
	t.Helper()
	ancien := peertubeOrigine
	peertubeOrigine = pt
	ConfigurerFiches([]string{pt, "https://radio.gk2.secubox.in"})
	return func() { peertubeOrigine = ancien; ConfigurerFiches(nil) }
}

// LE CAS SIGNALÉ : coller l'adresse d'une vidéo donnait une PASTILLE avec
// l'adresse en toutes lettres, alors qu'il faut un lecteur.
func TestUnLienVideoDevientUnLecteur(t *testing.T) {
	defer avecPeertube(t)()
	out := string(Render(pt + "/w/oVapJgCPJDQbMVvgYF8scf"))
	if !strings.Contains(out, "sbx-embed") {
		t.Fatalf("pas de lecteur :\n%s", out)
	}
	if strings.Contains(out, "fiche-sbx") {
		t.Errorf("une pastille subsiste alors qu'un lecteur a été posé :\n%s", out)
	}
	// L'iframe doit viser /videos/embed/… : PeerTube refuse le cadrage de ses
	// pages /w/, et un cadre qui refuse de s'afficher est pire qu'un lien.
	if !strings.Contains(out, "/videos/embed/") {
		t.Errorf("le cadre ne vise pas l'URL d'intégration :\n%s", out)
	}
}

// ET L'ORDRE PORTE LA RÈGLE : ce qui se regarde devient un lecteur, le reste
// garde sa pastille. Un lien vers la radio n'est pas une vidéo.
func TestUnLienDeServiceGardeSaPastille(t *testing.T) {
	defer avecPeertube(t)()
	out := string(Render("https://radio.gk2.secubox.in/emissions"))
	if !strings.Contains(out, "fiche-sbx") {
		t.Fatalf("la pastille a disparu :\n%s", out)
	}
	if strings.Contains(out, "sbx-embed") {
		t.Error("un lecteur a été posé sur un lien qui n'est pas une vidéo")
	}
}

// DÉDOUBLONNAGE. Le même lien collé deux fois — une fois nu, une fois en lien
// Markdown — arrivait en deux ancres. Personne ne veut deux fois le même
// lecteur ; c'est exactement ce que montrait la capture signalée.
func TestLaMemeVideoDeuxFoisNeDonneQuUnLecteur(t *testing.T) {
	defer avecPeertube(t)()
	u := pt + "/w/kRyUjJk5V9DUhNhTLac4kJ"
	out := string(Render(u + "\n[url](" + u + ")"))
	if n := strings.Count(out, "sbx-embed"); n != 1 {
		t.Fatalf("%d lecteurs pour une seule vidéo :\n%s", n, out)
	}
	// La seconde occurrence reste visible, en pastille : on ne fait pas
	// disparaître ce que quelqu'un a écrit.
	if !strings.Contains(out, "fiche-sbx") {
		t.Error("la seconde occurrence a disparu au lieu de redevenir une pastille")
	}
}

// UN MESSAGE QUI CITE DIX VIDÉOS N'EN VEUT PAS DIX LECTEURS : la page
// deviendrait illisible, et dix cadres en vol coûtent cher au navigateur comme
// à l'instance.
func TestLeNombreDeLecteursEstBorne(t *testing.T) {
	defer avecPeertube(t)()
	var b strings.Builder
	for i := 0; i < 8; i++ {
		b.WriteString(pt + "/w/video" + string(rune('a'+i)) + "\n")
	}
	out := string(Render(b.String()))
	if n := strings.Count(out, "sbx-embed"); n != MaxLecteursParMessage {
		t.Fatalf("%d lecteurs, veut %d", n, MaxLecteursParMessage)
	}
	// Les autres restent atteignables.
	if n := strings.Count(out, "fiche-sbx"); n != 8-MaxLecteursParMessage {
		t.Errorf("%d pastilles pour les vidéos restantes, veut %d",
			n, 8-MaxLecteursParMessage)
	}
}

// SANS INSTANCE DÉCLARÉE, RIEN NE S'INTÈGRE. C'est le bon défaut : une autre
// installation n'a pas notre PeerTube, et cadrer une instance inconnue lui
// donnerait un contexte d'exécution dans la page.
func TestSansInstanceDeclareeRienNeSIntegre(t *testing.T) {
	ancien := peertubeOrigine
	peertubeOrigine = ""
	ConfigurerFiches(nil)
	defer func() { peertubeOrigine = ancien }()
	out := string(Render(pt + "/w/abc"))
	if strings.Contains(out, "sbx-embed") {
		t.Fatalf("lecteur posé sans instance déclarée :\n%s", out)
	}
}

// Le texte ordinaire n'est pas touché, et l'échappement tient : c'est la
// première chose qu'une passe de rendu peut casser.
func TestLeTexteOrdinaireEtLEchappementTiennent(t *testing.T) {
	defer avecPeertube(t)()
	out := string(Render(`bonjour <script>alert(1)</script> et ` + pt + `/w/xyz`))
	if strings.Contains(out, "<script>") {
		t.Fatalf("échappement cassé :\n%s", out)
	}
	if !strings.Contains(out, "sbx-embed") {
		t.Error("le lecteur n'est plus posé quand le message contient autre chose")
	}
}
