// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"net/http"
	"strings"
)

// Ce que le détecteur de rotation (#3919, rotation.go) lit d'une requête. Fonctions PURES, sans allocation : elles tournent sur chaque requête.
//
// Règle de lecture : le doute profite au client. Une requête n'est COMPTÉE et JUGÉE que si elle ressemble en tout point à la navigation d'un
// navigateur interactif ; n'importe quel indice d'un vrai navigateur, sur n'importe quelle requête de l'adresse, est une PREUVE qui l'épargne.

const (
	rotationUAMax   = 1024
	rotationJA4Max  = 128
	rotationHoteMax = 253
)

// RotationRequete : les seuls champs que le détecteur regarde. Aucune chaîne n'est gardée telle quelle.
type RotationRequete struct {
	IP, UA, JA4, Hote string
	Navigation        bool // GET d'une page (estNavigation)
	Preuve            bool // indice d'un vrai navigateur (preuveNavigateur)
}

// contientPli : sous-chaîne sans tenir compte de la casse ASCII ; `motif` est en minuscules.
func contientPli(s, motif string) bool {
	n := len(motif)
	for i := 0; i+n <= len(s); i++ {
		j := 0
		for j < n {
			c := s[i+j]
			if c >= 'A' && c <= 'Z' {
				c += 'a' - 'A'
			}
			if c != motif[j] {
				break
			}
			j++
		}
		if j == n {
			return true
		}
	}
	return false
}

// navigateurInteractif : le client SE DIT navigateur interactif. Tout le reste (git, apt, curl, sonde, agrégateur de flux, application, robot
// déclaré) n'est jamais suivi : il n'a ni ressources à charger ni cookie à rendre, son silence ne prouve rien. Un agent qui donne une adresse de
// contact (« +https://… ») se déclare automate.
func navigateurInteractif(ua string) bool {
	if len(ua) > rotationUAMax || !strings.HasPrefix(ua, "Mozilla/") {
		return false
	}
	if !strings.Contains(ua, "Chrome/") && !strings.Contains(ua, "Firefox/") && !strings.Contains(ua, "Safari/") && !strings.Contains(ua, "Edg/") {
		return false
	}
	return !strings.Contains(ua, "://") && !automateDeclare(ua)
}

// automateDeclare : « compatible; », « bot », « spider » ou « crawler », sans tenir compte de la casse, en UNE lecture (chemin chaud).
func automateDeclare(ua string) bool {
	for i := 0; i < len(ua); i++ {
		switch ua[i] | 0x20 {
		case 'b':
			if debutPli(ua[i:], "bot") {
				return true
			}
		case 's':
			if debutPli(ua[i:], "spider") {
				return true
			}
		case 'c':
			if debutPli(ua[i:], "compatible;") || debutPli(ua[i:], "crawler") {
				return true
			}
		}
	}
	return false
}

func debutPli(s, motif string) bool {
	return len(s) >= len(motif) && contientPli(s[:len(motif)], motif)
}

// extensionsRessource : ressources qu'un navigateur charge pour afficher une page. Distinct de staticAsset (inspect.go), qui sert à l'inspection et
// compte aussi « /health » et « /status » : ici ce serait une échappatoire.
var extensionsRessource = []string{".js", ".mjs", ".css", ".map", ".webmanifest", ".wasm",
	".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif", ".bmp", ".ico", ".svg",
	".woff", ".woff2", ".ttf", ".otf", ".eot",
	".mp4", ".webm", ".ogv", ".mp3", ".ogg", ".oga", ".m4a", ".aac", ".flac", ".wav", ".m3u8", ".m4s", ".vtt"}

func ressourceDePage(chemin string) bool {
	i := strings.LastIndexByte(chemin, '.')
	if i < 0 || len(chemin)-i > len(".webmanifest") {
		return false
	}
	ext := chemin[i:]
	for _, e := range extensionsRessource {
		if len(ext) == len(e) && contientPli(ext, e) {
			return true
		}
	}
	return false
}

// cheminSansPage : clients légitimes sans page (ACME et autres /.well-known/, git par HTTP, robots.txt).
func cheminSansPage(chemin string) bool {
	return strings.HasPrefix(chemin, "/.well-known/") || strings.HasSuffix(chemin, "/info/refs") || strings.HasSuffix(chemin, "/git-upload-pack") ||
		strings.HasSuffix(chemin, "/git-receive-pack") || strings.Contains(chemin, "/info/lfs/") || chemin == "/robots.txt"
}

func presente(h http.Header, nom string) bool {
	v := h[nom]
	return len(v) > 0 && v[0] != ""
}

// estNavigation : GET d'une page par une personne. Un préchargement (Sec-Purpose, Purpose, X-Moz) n'affiche rien et ne charge aucune ressource : le
// juger bannirait quelqu'un pour une page qu'il n'a pas ouverte.
func estNavigation(methode, chemin string, h http.Header) bool {
	if methode != http.MethodGet || cheminSansPage(chemin) || ressourceDePage(chemin) {
		return false
	}
	if v := h["Sec-Fetch-Dest"]; len(v) > 0 && v[0] != "" && v[0] != "document" {
		return false
	}
	if presente(h, "Sec-Purpose") || presente(h, "Purpose") || presente(h, "X-Purpose") || presente(h, "X-Moz") {
		return false
	}
	return !isWebSocketUpgrade(h)
}

// preuveNavigateur : indice qu'un vrai navigateur (ou un client authentifié) tient cette adresse. Vaut sur TOUTE requête, quels que soient la méthode,
// l'hôte et le navigateur déclaré.
func preuveNavigateur(chemin string, h http.Header) bool {
	if presente(h, "Cookie") || presente(h, "Referer") || presente(h, "Authorization") || presente(h, "If-None-Match") || presente(h, "If-Modified-Since") {
		return true
	}
	if v := h["Sec-Fetch-Dest"]; len(v) > 0 && v[0] != "" && v[0] != "document" {
		return true
	}
	if v := h["Sec-Fetch-Site"]; len(v) > 0 && (v[0] == "same-origin" || v[0] == "same-site") {
		return true // un lien suivi DANS le site, même sous une politique « no-referrer »
	}
	return ressourceDePage(chemin)
}

// hoteRotation : minuscules, sans port ni point final ; "" = non suivi (vide ou plus long qu'un nom DNS).
func hoteRotation(hote string) string {
	if i := strings.LastIndexByte(hote, ':'); i >= 0 && !strings.Contains(hote[i:], "]") && strings.IndexByte(hote, ':') == i {
		hote = hote[:i]
	}
	hote = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(hote), "."))
	if len(hote) > rotationHoteMax {
		return ""
	}
	return hote
}
