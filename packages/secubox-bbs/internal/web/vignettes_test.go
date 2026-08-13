// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
package web

import (
	"bytes"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"strings"
	"testing"
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
