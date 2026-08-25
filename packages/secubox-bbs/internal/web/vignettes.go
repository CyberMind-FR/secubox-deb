// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

// Vignettes des medias de la bibliotheque (#1020).
//
// POURQUOI ON NE SERT PAS L'ORIGINAL RETRECI PAR LE NAVIGATEUR. Deux des
// images deposees sur gk2 pesent 2 Mo. Une grille de douze cartes ferait donc
// descendre vingt-cinq megaoctets pour afficher des carres de cent-vingt
// pixels — sur une liaison domestique et une board a quatre coeurs, la page
// serait inutilisable, et la lenteur passerait pour un defaut du BBS.
//
// AUCUNE DEPENDANCE EXTERNE. Le redimensionnement tient en trente lignes de
// bibliotheque standard ; ajouter golang.org/x/image pour cela aurait charge
// la chaine de construction d'un paquet a suivre, a auditer et a mettre a
// jour, pour une moyenne de pixels.
package web

import (
	"bytes"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/gif"
	"image/jpeg"
	"image/png"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Cote maximal d'une vignette, en pixels. Cent-soixante suffit a une carte et
// tient en quelques kilooctets une fois encode.
const coteVignette = 160

// tailleMaxSource borne ce qu'on accepte de decoder. Une image de cent
// megaoctets — ou une "bombe de decompression" annoncant 50 000 × 50 000 —
// epuiserait la memoire de la board pendant que la requete d'un lecteur
// attend. On refuse alors la vignette : l'appelant montre un glyphe, ce qui
// est un degre de service, pas une panne.
const tailleMaxSource = 24 << 20

// pixelsMaxSource borne la surface decodee, independamment du poids du
// fichier : c'est la surface qui coute la memoire, pas les octets sur disque.
const pixelsMaxSource = 40_000_000

// vignetteJPEG lit une image et rend une vignette JPEG bornee a `cote`.
func vignetteJPEG(src io.Reader, cote int) ([]byte, error) {
	// LimitReader et non ReadAll : la borne s'applique AVANT que les octets
	// n'entrent en memoire, sans quoi elle ne protegerait de rien.
	cfgBuf, err := io.ReadAll(io.LimitReader(src, tailleMaxSource+1))
	if err != nil {
		return nil, err
	}
	if len(cfgBuf) > tailleMaxSource {
		return nil, fmt.Errorf("source trop lourde pour une vignette")
	}

	// La CONFIGURATION est lue avant l'image : elle donne les dimensions sans
	// allouer la trame, ce qui permet de refuser une bombe de decompression
	// avant de lui avoir cede la memoire.
	cfg, _, err := image.DecodeConfig(bytes.NewReader(cfgBuf))
	if err != nil {
		return nil, err
	}
	if cfg.Width <= 0 || cfg.Height <= 0 ||
		cfg.Width*cfg.Height > pixelsMaxSource {
		return nil, fmt.Errorf("dimensions hors bornes (%dx%d)", cfg.Width, cfg.Height)
	}

	img, _, err := image.Decode(bytes.NewReader(cfgBuf))
	if err != nil {
		return nil, err
	}

	petite := reduire(img, cote)
	var out bytes.Buffer
	if err := jpeg.Encode(&out, petite, &jpeg.Options{Quality: 78}); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// reduire ramene l'image dans un carre de `cote` en MOYENNANT les pixels
// source de chaque pixel destination.
//
// Prendre le pixel le plus proche serait plus court, et donnerait ce grain
// caracteristique des reductions bacleees : sur une capture d'ecran, le texte
// devient illisible et les traits fins disparaissent selon qu'ils tombent ou
// non sur un point d'echantillonnage. La moyenne coute une boucle de plus.
func reduire(src image.Image, cote int) image.Image {
	b := src.Bounds()
	l, h := b.Dx(), b.Dy()
	if l <= 0 || h <= 0 {
		return src
	}
	// UNE IMAGE DEJA PETITE N'EST PAS AGRANDIE : l'etirer ne rend aucun detail
	// qu'elle n'a pas, et alourdit la vignette au-dela de l'original.
	if l <= cote && h <= cote {
		return src
	}
	nl, nh := cote, cote
	if l > h {
		nh = max(1, h*cote/l)
	} else {
		nl = max(1, l*cote/h)
	}

	// L'image est d'abord ramenee en RGBA : `src.At()` sur un format exotique
	// (YCbCr, Paletted) convertit a chaque appel, et on l'appelle une fois par
	// pixel source.
	rgba := image.NewRGBA(image.Rect(0, 0, l, h))
	draw.Draw(rgba, rgba.Bounds(), src, b.Min, draw.Src)

	dst := image.NewRGBA(image.Rect(0, 0, nl, nh))
	for y := 0; y < nh; y++ {
		y0, y1 := y*h/nh, (y+1)*h/nh
		if y1 <= y0 {
			y1 = y0 + 1
		}
		for x := 0; x < nl; x++ {
			x0, x1 := x*l/nl, (x+1)*l/nl
			if x1 <= x0 {
				x1 = x0 + 1
			}
			var sr, sg, sb, n uint32
			for yy := y0; yy < y1; yy++ {
				for xx := x0; xx < x1; xx++ {
					i := rgba.PixOffset(xx, yy)
					sr += uint32(rgba.Pix[i])
					sg += uint32(rgba.Pix[i+1])
					sb += uint32(rgba.Pix[i+2])
					n++
				}
			}
			if n == 0 {
				n = 1
			}
			dst.Set(x, y, color.RGBA{
				R: uint8(sr / n), G: uint8(sg / n), B: uint8(sb / n), A: 255})
		}
	}
	return dst
}

// servirVignette rend la vignette d'une piece jointe, en la fabriquant au
// premier appel.
//
// LA FABRICATION EST PARESSEUSE, pas faite au depot. Produire la vignette a
// l'envoi ferait attendre celui qui depose pour un service dont il n'a pas
// besoin, et laisserait sans vignette les milliers de fichiers deja presents.
//
// LE MEME DROIT QUE LE FICHIER LUI-MEME. Une vignette est une reproduction
// reduite, pas une donnee moins sensible : la servir plus largement rendrait
// lisible l'image d'un fil prive a qui devine un numero.
func (s *Server) servirVignette(w http.ResponseWriter, r *http.Request) {
	v := s.qui(r)
	brut := strings.TrimPrefix(r.URL.Path, "/vignette/")
	if i := strings.IndexByte(brut, '.'); i >= 0 {
		brut = brut[:i]
	}
	id, err := strconv.ParseInt(brut, 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	f, err := s.st.Fichier(id)
	if err != nil || !f.EstImage() {
		http.NotFound(w, r)
		return
	}

	// EXACTEMENT le droit du fichier lui-meme (cf. /f/ dans fichiers.go), ce que
	// l'entete de cette fonction annonce depuis toujours. Le garde precedent
	// etait PLUS STRICT que ce qu'il documentait : `!v.Connecte` sans regarder
	// la visibilite refusait aussi la vignette d'un fichier PUBLIC. La
	// Bibliotheque, qui liste des fichiers publics, rendait donc 403 sur chacune
	// de ses vignettes a un visiteur sans compte — pages publiques sans images.
	//
	// Le controle vient APRES le chargement : c'est la visibilite du fichier qui
	// decide, et elle n'est connue qu'ici.
	if !v.Connecte && f.Visibility != "public" {
		http.Error(w, "reserve aux membres", http.StatusForbidden)
		return
	}

	cache := s.st.CheminVignette(id)
	if _, err := os.Stat(cache); err != nil {
		src, err := os.Open(s.st.CheminFichier(f))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		jpg, err := vignetteJPEG(src, coteVignette)
		src.Close()
		if err != nil {
			// PAS DE 500 : l'appelant affiche un glyphe. Une image qu'on ne
			// sait pas reduire n'est pas une panne du BBS, et repondre 500
			// remplirait le journal d'alertes pour un defaut d'agrement.
			http.NotFound(w, r)
			return
		}
		if err := os.MkdirAll(filepath.Dir(cache), 0o750); err == nil {
			// Ecriture par fichier temporaire puis renommage : deux lecteurs
			// peuvent demander la meme vignette en meme temps, et un fichier
			// a moitie ecrit servirait une image tronquee au second.
			tmp := cache + ".partiel"
			if os.WriteFile(tmp, jpg, 0o640) == nil {
				os.Rename(tmp, cache)
			}
		}
		w.Header().Set("Content-Type", "image/jpeg")
		// nosniff MANQUAIT SUR CE CHEMIN, alors qu'il est pose sur celui du
		// cache. La toute PREMIERE vue de chaque vignette — la seule que voit
		// celui qui vient de deposer — partait donc sans, et c'est exactement
		// celle d'un fichier qu'on n'a pas encore vu reduit.
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "private, max-age=604800, immutable")
		w.Write(jpg)
		return
	}

	w.Header().Set("Content-Type", "image/jpeg")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "private, max-age=604800, immutable")
	http.ServeFile(w, r, cache)
}

// Enregistre les decodeurs. `image.Decode` ne connait que les formats dont le
// paquet a ete importe — sans ces trois lignes, toute image serait « format
// inconnu », y compris les PNG.
var _ = []any{png.Decode, jpeg.Decode, gif.Decode}
