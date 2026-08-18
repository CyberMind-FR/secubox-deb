// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Capture de session (#1058) — le chemin OPPOSÉ à l'anti-pistage.
//
// relay.go n'émet que des NOMS de cookies, jamais les valeurs : c'est la règle
// vie-privée, et elle ne bouge pas. Ce fichier ajoute, EN PARALLÈLE et jamais à
// sa place, la capture des VALEURS — pour rejouer une session choisie.
//
// Trois garde-fous, tenus ici même :
//   - rien n'est capturé hors d'une fenêtre d'armement explicite, signalée par
//     un fichier-marqueur que le module cookies écrit (opt-in de l'utilisateur) ;
//   - la fenêtre peut se limiter à une liste d'hôtes : le périmètre suit ce que
//     l'utilisateur relie, pas tout ce qu'il visite en même temps ;
//   - le marqueur porte une échéance : une fenêtre oubliée se referme seule.
package main

import (
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// capturedCookie : un cookie avec sa VALEUR, prêt pour le magasin chiffré.
type capturedCookie struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Domain   string `json:"domain"`
	Path     string `json:"path"`
	Expires  int64  `json:"expires"`
	Secure   bool   `json:"secure"`
	HTTPOnly bool   `json:"httponly"`
}

// marqueur : ce que le module cookies écrit pour ouvrir une fenêtre.
type marqueur struct {
	Deadline int64    `json:"deadline"`
	Profil   string   `json:"profil"`
	Hotes    []string `json:"hotes"`
}

// captureArm lit le marqueur à bas coût. Le résultat est mis en cache une
// seconde : la capture ne doit pas relire un fichier à chaque requête du proxy.
type captureArm struct {
	chemin string
	mu     sync.Mutex
	lu     time.Time
	cache  *marqueur // nil = pas de fenêtre
}

func (c *captureArm) charger() *marqueur {
	c.mu.Lock()
	defer c.mu.Unlock()
	if time.Since(c.lu) < time.Second {
		return c.cache
	}
	c.lu = time.Now()
	c.cache = nil
	raw, err := os.ReadFile(c.chemin)
	if err != nil {
		return nil
	}
	var m marqueur
	if json.Unmarshal(raw, &m) != nil {
		return nil
	}
	// Une fenêtre échue est comme absente : on ne se fie jamais à un marqueur
	// que personne n'a rafraîchi.
	if m.Deadline <= time.Now().Unix() {
		return nil
	}
	c.cache = &m
	return c.cache
}

// arme dit si l'hôte doit être capturé maintenant.
func (c *captureArm) arme(hote string) bool {
	m := c.charger()
	if m == nil {
		return false
	}
	if len(m.Hotes) == 0 {
		return true // liste vide : le périmètre est la navigation
	}
	h := strings.ToLower(hote)
	for _, permis := range m.Hotes {
		p := strings.ToLower(strings.TrimSpace(permis))
		// « youtube.com » couvre « www.youtube.com » : on autorise le domaine
		// et ses sous-domaines, jamais au-delà.
		if h == p || strings.HasSuffix(h, "."+p) {
			return true
		}
	}
	return false
}

func (c *captureArm) profil() string {
	if m := c.charger(); m != nil && m.Profil != "" {
		return m.Profil
	}
	return "defaut"
}

// ── extraction ────────────────────────────────────────────────────────────

// valeursCookieEnvoye lit les paires nom=valeur de l'en-tête Cookie de la
// requête : c'est le bocal du client tel qu'il l'envoie, la matière du rejeu.
func valeursCookieEnvoye(req *http.Request) []capturedCookie {
	var out []capturedCookie
	for _, ligne := range req.Header.Values("Cookie") {
		for _, part := range strings.Split(ligne, ";") {
			eq := strings.IndexByte(part, '=')
			if eq < 0 {
				continue
			}
			nom := strings.TrimSpace(part[:eq])
			if nom == "" {
				continue
			}
			out = append(out, capturedCookie{
				Name:  nom,
				Value: strings.TrimSpace(part[eq+1:]),
				Path:  "/",
			})
		}
	}
	return out
}

// valeurSetCookie lit un Set-Cookie complet : nom, valeur ET attributs.
func valeurSetCookie(ligne string) *capturedCookie {
	parts := strings.Split(ligne, ";")
	if len(parts) == 0 {
		return nil
	}
	eq := strings.IndexByte(parts[0], '=')
	if eq < 0 {
		return nil
	}
	nom := strings.TrimSpace(parts[0][:eq])
	if nom == "" {
		return nil
	}
	c := &capturedCookie{
		Name:  nom,
		Value: strings.TrimSpace(parts[0][eq+1:]),
		Path:  "/",
	}
	for _, attr := range parts[1:] {
		attr = strings.TrimSpace(attr)
		bas := strings.ToLower(attr)
		switch {
		case bas == "secure":
			c.Secure = true
		case bas == "httponly":
			c.HTTPOnly = true
		case strings.HasPrefix(bas, "domain="):
			c.Domain = strings.TrimSpace(attr[len("domain="):])
		case strings.HasPrefix(bas, "path="):
			c.Path = strings.TrimSpace(attr[len("path="):])
		case strings.HasPrefix(bas, "max-age="):
			if s, err := strconv.Atoi(strings.TrimSpace(attr[len("max-age="):])); err == nil {
				c.Expires = time.Now().Unix() + int64(s)
			}
		case strings.HasPrefix(bas, "expires="):
			if t, err := http.ParseTime(strings.TrimSpace(attr[len("expires="):])); err == nil {
				c.Expires = t.Unix()
			}
		}
	}
	return c
}

// capturerFlux réunit l'envoi et la réponse en un jeu de cookies à valeur.
//
// L'en-tête Cookie donne la valeur COURANTE (ce qui compte pour le rejeu), le
// Set-Cookie donne les attributs propres (domaine, échéance). Quand les deux
// portent le même nom, on garde la valeur envoyée et on l'enrichit des
// attributs posés — jamais l'un sans l'autre.
func capturerFlux(hote string, req *http.Request, resp *http.Response) []capturedCookie {
	parNom := map[string]*capturedCookie{}
	ordre := []string{}

	add := func(c capturedCookie) {
		if ex, ok := parNom[c.Name]; ok {
			if c.Value != "" {
				ex.Value = c.Value
			}
			if c.Domain != "" {
				ex.Domain = c.Domain
			}
			if c.Secure {
				ex.Secure = true
			}
			if c.HTTPOnly {
				ex.HTTPOnly = true
			}
			if c.Expires != 0 {
				ex.Expires = c.Expires
			}
			return
		}
		cp := c
		parNom[c.Name] = &cp
		ordre = append(ordre, c.Name)
	}

	if req != nil {
		for _, c := range valeursCookieEnvoye(req) {
			add(c)
		}
	}
	if resp != nil {
		for _, ligne := range resp.Header.Values("Set-Cookie") {
			if c := valeurSetCookie(ligne); c != nil {
				add(*c)
			}
		}
	}

	out := make([]capturedCookie, 0, len(ordre))
	for _, nom := range ordre {
		c := parNom[nom]
		if c.Domain == "" {
			// Sans attribut Domain, le cookie vaut pour l'hôte exact : on le
			// lui rattache, sinon le cookies.txt ne se lierait à rien.
			c.Domain = hote
		}
		out = append(out, *c)
	}
	return out
}

// ── émission ──────────────────────────────────────────────────────────────

// captureEvent : ce que sbxmitm poste au magasin quand une fenêtre est armée.
type captureEvent struct {
	Profil  string           `json:"profil"`
	Hote    string           `json:"hote"`
	Cookies []capturedCookie `json:"cookies"`
}

// emitCapture poste les VALEURS au magasin, uniquement si la fenêtre est armée
// pour cet hôte. Tourne à côté de emitCookies (noms), jamais à sa place.
func (px *Proxy) emitCapture(req *http.Request, resp *http.Response) {
	if px.capture == nil || req == nil || req.URL == nil {
		return
	}
	hote := req.URL.Hostname()
	if !px.capture.arme(hote) {
		return
	}
	cookies := capturerFlux(hote, req, resp)
	if len(cookies) == 0 {
		return
	}
	payload, _ := json.Marshal(captureEvent{
		Profil: px.capture.profil(), Hote: hote, Cookies: cookies,
	})
	// Même transport que les autres relais : best-effort, un magasin lent ou
	// absent n'affecte jamais le proxy.
	px.relayEmit(cookiesSocket, captureRoute, payload)
}

// newCaptureArm rend un lecteur de marqueur, ou nil si aucun chemin n'est
// fourni. nil vaut « capture jamais active » : emitCapture devient un no-op
// total, et le proxy se comporte exactement comme sans cette fonctionnalite.
func newCaptureArm(chemin string) *captureArm {
	if chemin == "" {
		return nil
	}
	return &captureArm{chemin: chemin}
}
