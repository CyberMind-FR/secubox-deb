// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package web

import (
	"html"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"
)

// ── Cartes de liens (#3713) ─────────────────────────────────────────────────
//
// Un lien collé SEUL dans son paragraphe devient une carte : une icône, un
// titre lisible, le domaine. Sur téléphone, l'adresse brute (150 caractères de
// jetons LinkedIn ou Facebook) débordait de l'écran et ne disait rien.
//
// AUCUNE REQUÊTE VERS LE SITE DISTANT : le titre est déduit de l'adresse seule.
// Aller chercher l'aperçu chez LinkedIn ou Facebook annoncerait à ces sites qui
// lit le fil, et quand. Ce qu'on perd en richesse, on le garde en discrétion.
//
// On ne touche qu'au balisage EXACT que produit `adressesNues` pour un lien nu
// resté nu : une pièce jointe, une fiche de service SecuBox ou un lecteur vidéo
// ont déjà changé ce balisage et ne correspondent plus. Un lien Markdown nommé
// ([texte](adresse)) garde son texte : le texte ≠ l'adresse, il ne correspond pas.
var lienSeulRe = regexp.MustCompile(`<p><a href="([^"]+)" rel="noopener noreferrer">([^<]+)</a></p>\n?`)

func cartesDeLiens(s string) string {
	if !strings.Contains(s, `rel="noopener noreferrer">`) {
		return s
	}
	return lienSeulRe.ReplaceAllStringFunc(s, func(tout string) string {
		m := lienSeulRe.FindStringSubmatch(tout)
		if m == nil || m[1] != m[2] {
			return tout
		}
		// m[1] est DÉJÀ échappé (inline échappe d'abord) : on le remet tel quel
		// dans l'attribut ; on ne déséchappe que pour analyser l'adresse.
		u, err := url.Parse(html.UnescapeString(m[1]))
		if err != nil || u.Host == "" {
			return tout
		}
		classe, ico, titre, sous := decrireLien(u)
		return `<a class="carte-lien ` + classe + `" href="` + m[1] + `" rel="noopener noreferrer">` +
			`<span class="carte-ico" aria-hidden="true">` + html.EscapeString(ico) + `</span>` +
			`<span class="carte-txt"><b>` + html.EscapeString(titre) + `</b><small>` +
			html.EscapeString(sous) + `</small></span></a>` + "\n"
	})
}

// hoteCourt retire les préfixes qui n'apprennent rien au lecteur.
func hoteCourt(h string) string {
	h = strings.ToLower(h)
	for _, p := range []string{"www.", "m.", "mobile.", "web."} {
		h = strings.TrimPrefix(h, p)
	}
	return h
}

func segments(u *url.URL) []string {
	var out []string
	for _, s := range strings.Split(u.Path, "/") {
		if s == "" {
			continue
		}
		if d, err := url.PathUnescape(s); err == nil {
			s = d
		}
		out = append(out, s)
	}
	return out
}

// decrireLien rend la classe de couleur, le texte de l'icône, le titre et la
// ligne de domaine d'une adresse.
func decrireLien(u *url.URL) (classe, ico, titre, sous string) {
	hote := hoteCourt(u.Hostname())
	seg := segments(u)
	chemin := "/" + strings.Join(seg, "/") + "/"
	switch {
	case hote == "linkedin.com" || strings.HasSuffix(hote, ".linkedin.com"):
		titre = "LinkedIn"
		switch {
		case strings.Contains(chemin, "/feed/update/") || strings.Contains(chemin, "/posts/"):
			titre = "Publication LinkedIn"
		case len(seg) >= 2 && seg[0] == "in":
			titre = "Profil LinkedIn"
		}
		return "carte-li", "in", titre, "linkedin.com"

	case hote == "facebook.com" || hote == "fb.watch" || strings.HasSuffix(hote, ".facebook.com"):
		titre = "Publication Facebook"
		switch {
		case strings.HasPrefix(chemin, "/stories/"):
			titre = "Story Facebook"
		case strings.HasPrefix(chemin, "/share/v/") || strings.Contains(chemin, "/videos/") ||
			strings.HasPrefix(chemin, "/watch/") || strings.HasPrefix(chemin, "/reel/") || hote == "fb.watch":
			titre = "Vidéo Facebook"
		}
		return "carte-fb", "f", titre, "facebook.com"

	case hote == "x.com" || hote == "twitter.com":
		titre = "X"
		switch {
		case len(seg) >= 3 && seg[1] == "status":
			titre = "Post de @" + seg[0]
		case len(seg) == 1:
			titre = "@" + seg[0]
		}
		return "carte-x", "𝕏", titre, hote

	case hote == "github.com":
		sous = "github.com"
		switch {
		case len(seg) >= 5 && (seg[2] == "blob" || seg[2] == "tree"):
			titre = seg[len(seg)-1]
			dossier := append([]string{seg[1]}, seg[4:len(seg)-1]...)
			sous += " · " + strings.Join(dossier, "/")
		case len(seg) >= 2:
			titre = seg[0] + " / " + seg[1]
		case len(seg) == 1:
			titre = seg[0]
		default:
			titre = "GitHub"
		}
		return "carte-gh", "GH", borne(titre), sous
	}

	// Cas général : le dernier segment parlant, sinon le domaine.
	titre = hote
	if n := len(seg); n > 0 {
		dernier := seg[n-1]
		if parlant(dernier) {
			titre = strings.NewReplacer("-", " ", "_", " ").Replace(dernier)
		}
	}
	ico = strings.ToUpper(string([]rune(hote)[:1]))
	return "carte-autre", ico, borne(titre), hote
}

// parlant : un segment qui se lit (des lettres, pas un identifiant opaque).
func parlant(s string) bool {
	if utf8.RuneCountInString(s) > 80 || !strings.ContainsAny(s, "-_") && utf8.RuneCountInString(s) > 30 {
		return false
	}
	lettres := 0
	for _, r := range s {
		if r >= '0' && r <= '9' {
			continue
		}
		lettres++
	}
	return lettres*2 > utf8.RuneCountInString(s)
}

func borne(s string) string {
	if utf8.RuneCountInString(s) <= 70 {
		return s
	}
	return string([]rune(s)[:69]) + "…"
}
