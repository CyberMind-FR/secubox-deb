// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package sbxobj

// Aperçus (#1395) : des captures d'écran VOYAGENT DANS le .sbx, sous
// apercu-1.jpg … apercu-4.jpg. Chacune est listée dans `integrite` — donc
// couverte par la signature de l'éditeur — et décrite dans `apercus`.
//
// Une capture brute du shotter pèse ~230 Ko (PNG 1280×657) : on la réduit à
// 640 px de large en JPEG, ~40 Ko — 164 paquets ne doivent pas doubler de
// poids pour une vignette.

import (
	"bytes"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/jpeg"
	_ "image/png"
	"os"
	"regexp"
)

const (
	ApercusMax     = 4
	apercuLargeur  = 640
	apercuPixelMax = 4096      // ni à l'entrée, ni dans un paquet reçu
	apercuOctets   = 512 << 10 // un aperçu embarqué ne dépasse pas cette taille
)

var reApercu = regexp.MustCompile(`^apercu-[1-4]\.jpg$`)

func membreApercu(n int) string { return fmt.Sprintf("apercu-%d.jpg", n) }

// Vignette lit un PNG ou un JPEG et rend un JPEG de 640 px de large au plus.
func Vignette(src string) ([]byte, int, int, error) {
	b, err := os.ReadFile(src)
	if err != nil {
		return nil, 0, 0, err
	}
	// Dimensions AVANT de décoder : une bombe de pixels ne passe pas.
	cfg, _, err := image.DecodeConfig(bytes.NewReader(b))
	if err != nil {
		return nil, 0, 0, fmt.Errorf("%s : image illisible (PNG ou JPEG attendu)", src)
	}
	if cfg.Width < 1 || cfg.Height < 1 || cfg.Width > apercuPixelMax || cfg.Height > apercuPixelMax {
		return nil, 0, 0, fmt.Errorf("%s : %d×%d hors bornes", src, cfg.Width, cfg.Height)
	}
	img, _, err := image.Decode(bytes.NewReader(b))
	if err != nil {
		return nil, 0, 0, fmt.Errorf("%s : %v", src, err)
	}
	if img.Bounds().Dx() > apercuLargeur {
		img = reduit(img, apercuLargeur)
	}
	var out bytes.Buffer
	if err := jpeg.Encode(&out, img, &jpeg.Options{Quality: 80}); err != nil {
		return nil, 0, 0, err
	}
	if out.Len() > apercuOctets {
		return nil, 0, 0, fmt.Errorf("%s : aperçu de %d octets, trop lourd", src, out.Len())
	}
	return out.Bytes(), img.Bounds().Dx(), img.Bounds().Dy(), nil
}

// reduit : moyenne de zone — chaque pixel de sortie moyenne le rectangle
// source qu'il couvre (lisse, sans dépendance ; le texte reste lisible).
func reduit(src image.Image, largeur int) image.Image {
	sb := src.Bounds()
	sw, sh := sb.Dx(), sb.Dy()
	hauteur := sh * largeur / sw
	if hauteur < 1 {
		hauteur = 1
	}
	dst := image.NewRGBA(image.Rect(0, 0, largeur, hauteur))
	for y := 0; y < hauteur; y++ {
		y0, y1 := y*sh/hauteur, (y+1)*sh/hauteur
		if y1 <= y0 {
			y1 = y0 + 1
		}
		for x := 0; x < largeur; x++ {
			x0, x1 := x*sw/largeur, (x+1)*sw/largeur
			if x1 <= x0 {
				x1 = x0 + 1
			}
			var r, g, b, n uint64
			for yy := y0; yy < y1; yy++ {
				for xx := x0; xx < x1; xx++ {
					cr, cg, cb, _ := src.At(sb.Min.X+xx, sb.Min.Y+yy).RGBA()
					r, g, b, n = r+uint64(cr), g+uint64(cg), b+uint64(cb), n+1
				}
			}
			dst.Set(x, y, color.RGBA64{uint16(r / n), uint16(g / n), uint16(b / n), 0xffff})
		}
	}
	return dst
}

// verifieApercu : ce qu'un navigateur recevra est bien un JPEG borné.
func verifieApercu(chemin string) error {
	st, err := os.Stat(chemin)
	if err != nil {
		return err
	}
	if st.Size() > apercuOctets {
		return errors.New("aperçu trop lourd")
	}
	f, err := os.Open(chemin)
	if err != nil {
		return err
	}
	defer f.Close()
	cfg, format, err := image.DecodeConfig(f)
	if err != nil || format != "jpeg" {
		return errors.New("aperçu : JPEG attendu")
	}
	if cfg.Width > apercuPixelMax || cfg.Height > apercuPixelMax {
		return errors.New("aperçu hors bornes")
	}
	return nil
}
