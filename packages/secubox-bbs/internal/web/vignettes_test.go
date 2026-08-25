// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
package web

import (
	"bytes"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/store"
)

func imagePNG(t *testing.T, l, h int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, l, h))
	for y := 0; y < h; y++ {
		for x := 0; x < l; x++ {
			// Moitie gauche noire, moitie droite blanche : une moyenne correcte
			// doit conserver ce contraste, un echantillonnage rate le brouille.
			c := color.RGBA{A: 255}
			if x >= l/2 {
				c = color.RGBA{R: 255, G: 255, B: 255, A: 255}
			}
			img.Set(x, y, c)
		}
	}
	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		t.Fatalf("encodage : %v", err)
	}
	return b.Bytes()
}

func TestVignetteBorneLeGrandCote(t *testing.T) {
	jpg, err := vignetteJPEG(bytes.NewReader(imagePNG(t, 800, 400)), 160)
	if err != nil {
		t.Fatalf("vignetteJPEG : %v", err)
	}
	cfg, err := jpeg.DecodeConfig(bytes.NewReader(jpg))
	if err != nil {
		t.Fatalf("relecture : %v", err)
	}
	if cfg.Width != 160 || cfg.Height != 80 {
		t.Errorf("dimensions = %dx%d, veut 160x80", cfg.Width, cfg.Height)
	}
}

func TestVignetteAllegeReellement(t *testing.T) {
	// Le but de tout l'exercice : ne pas faire descendre 2 Mo pour un carre de
	// cent-soixante pixels. Un test qui verifierait seulement les dimensions
	// laisserait passer une vignette aussi lourde que l'original.
	src := imagePNG(t, 2000, 1500)
	jpg, err := vignetteJPEG(bytes.NewReader(src), 160)
	if err != nil {
		t.Fatalf("vignetteJPEG : %v", err)
	}
	if len(jpg) >= len(src)/10 {
		t.Errorf("vignette = %d o pour une source de %d o — trop lourde",
			len(jpg), len(src))
	}
}

func TestVignetteConserveLeContraste(t *testing.T) {
	jpg, _ := vignetteJPEG(bytes.NewReader(imagePNG(t, 640, 640)), 160)
	img, err := jpeg.Decode(bytes.NewReader(jpg))
	if err != nil {
		t.Fatalf("decodage : %v", err)
	}
	gauche, _, _, _ := img.At(10, 80).RGBA()
	droite, _, _, _ := img.At(150, 80).RGBA()
	if gauche > 0x4000 || droite < 0xC000 {
		t.Errorf("contraste perdu : gauche=%x droite=%x", gauche, droite)
	}
}

func TestPetiteImageNonAgrandie(t *testing.T) {
	// L'etirer ne rendrait aucun detail qu'elle n'a pas, et la vignette
	// finirait plus lourde que l'original.
	jpg, err := vignetteJPEG(bytes.NewReader(imagePNG(t, 40, 30)), 160)
	if err != nil {
		t.Fatalf("vignetteJPEG : %v", err)
	}
	cfg, _ := jpeg.DecodeConfig(bytes.NewReader(jpg))
	if cfg.Width != 40 || cfg.Height != 30 {
		t.Errorf("dimensions = %dx%d, veut 40x30", cfg.Width, cfg.Height)
	}
}

func TestSourceIllisibleRefuseeSansPanique(t *testing.T) {
	if _, err := vignetteJPEG(strings.NewReader("ceci n'est pas une image"), 160); err == nil {
		t.Error("une source illisible doit etre refusee")
	}
}

func TestSourceTropLourdeRefusee(t *testing.T) {
	// La borne s'applique AVANT le decodage : sans elle, un envoi de cent
	// megaoctets epuiserait la memoire de la board pendant qu'un lecteur attend.
	gros := bytes.Repeat([]byte{0}, tailleMaxSource+1024)
	if _, err := vignetteJPEG(bytes.NewReader(gros), 160); err == nil {
		t.Error("une source hors borne doit etre refusee")
	}
}

func TestGlyphes(t *testing.T) {
	for genre, veut := range map[string]string{
		"image": "🖼", "son": "🎧", "vidéo": "🎬", "autre chose": "📄",
	} {
		if got := glypheDe(genre); got != veut {
			t.Errorf("glypheDe(%q) = %q, veut %q", genre, got, veut)
		}
	}
	for genre, veut := range map[string]string{
		"video/mp4": "🎬", "audio/mpeg": "🎧", "podcast": "🎧",
		"Épisode": "🎧", "": "📡",
	} {
		if got := glypheDeSource(genre); got != veut {
			t.Errorf("glypheDeSource(%q) = %q, veut %q", genre, got, veut)
		}
	}
}

// La vignette suit EXACTEMENT le droit du fichier, ce que l'entete de
// servirVignette annonce. Le garde precedent etait plus strict que sa propre
// documentation : il exigeait une session sans regarder la visibilite, donc il
// refusait aussi la vignette d'un fichier PUBLIC. La Bibliotheque, qui liste
// des fichiers publics, rendait 403 sur chacune de ses vignettes a un visiteur
// sans compte — 94 medias casses sur /biblio.
func TestVignetteDunFichierPublicEstServieAuxAnonymes(t *testing.T) {
	srv, st := banc(t)
	u, _ := st.CreateUser("bob", "Bob", store.RoleMember)

	var img bytes.Buffer
	if err := png.Encode(&img, image.NewRGBA(image.Rect(0, 0, 24, 24))); err != nil {
		t.Fatal(err)
	}
	f, err := st.DeposeFichier(u, "photo.png", "image/png", bytes.NewReader(img.Bytes()))
	if err != nil {
		t.Fatalf("depot: %v", err)
	}
	if err := st.MarqueFichiersPublics([]int64{f.ID}); err != nil {
		t.Fatalf("marquage public: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/vignette/"+strconv.FormatInt(f.ID, 10)+".jpg", nil)
	srv.Handler().ServeHTTP(rec, req) // aucun cookie : visiteur anonyme

	if rec.Code == http.StatusForbidden {
		t.Fatalf("403 sur la vignette d'un fichier PUBLIC : le garde trop strict est revenu")
	}
}

// L'inverse doit rester vrai : la vignette d'un fichier 'local' ne fuit pas. Une
// reproduction reduite reste la meme image, et `/vignette/NN` est un numero
// devinable.
func TestVignetteDunFichierLocalResteFermee(t *testing.T) {
	srv, st := banc(t)
	u, _ := st.CreateUser("bob", "Bob", store.RoleMember)

	var img bytes.Buffer
	if err := png.Encode(&img, image.NewRGBA(image.Rect(0, 0, 24, 24))); err != nil {
		t.Fatal(err)
	}
	f, err := st.DeposeFichier(u, "prive.png", "image/png", bytes.NewReader(img.Bytes()))
	if err != nil {
		t.Fatalf("depot: %v", err)
	} // pas de MarqueFichiersPublics : reste 'local'

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/vignette/"+strconv.FormatInt(f.ID, 10)+".jpg", nil)
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("vignette d'un fichier local servie a un anonyme : code %d", rec.Code)
	}
}

// La Bibliotheque n'annonce que ce qu'elle sert : sans session, elle ne liste
// que les fichiers publics. Lister un fichier 'local' donnerait une carte dont
// le lien /f/NN et la vignette /vignette/NN repondent 403 — 60 medias casses
// sur la seule /biblio avant ce filtre.
func TestBiblioNeListeQueLePublicAuxAnonymes(t *testing.T) {
	srv, st := banc(t)
	u, _ := st.CreateUser("bob", "Bob", store.RoleMember)

	var img bytes.Buffer
	if err := png.Encode(&img, image.NewRGBA(image.Rect(0, 0, 12, 12))); err != nil {
		t.Fatal(err)
	}
	pubF, err := st.DeposeFichier(u, "publique.png", "image/png", bytes.NewReader(img.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.MarqueFichiersPublics([]int64{pubF.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DeposeFichier(u, "privee.png", "image/png", bytes.NewReader(img.Bytes())); err != nil {
		t.Fatal(err)
	}

	anon := srv.cartesBiblio(true)
	for _, c := range anon {
		if strings.Contains(c.Title, "privee") {
			t.Fatalf("un fichier 'local' est annoncé à un anonyme : %q", c.Title)
		}
	}
	if len(anon) != 1 {
		t.Fatalf("attendu 1 carte publique, obtenu %d", len(anon))
	}

	// Un membre voit les deux : le filtre ne doit pas amputer la vue connectée.
	if membre := srv.cartesBiblio(false); len(membre) != 2 {
		t.Fatalf("un membre doit voir les 2 fichiers, obtenu %d", len(membre))
	}
}
