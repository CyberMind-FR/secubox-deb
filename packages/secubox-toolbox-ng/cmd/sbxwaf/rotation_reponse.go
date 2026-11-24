// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

// OUVERTURE DU VERDICT (#3919). Le silence d'une adresse ne prouve quelque chose que si elle a REÇU une page qui demande des ressources. Le verdict
// différé ne s'ouvre donc qu'à la FIN d'une réponse 2xx text/html, et le délai de 10 s court à partir de là : une page lente, un client qui coupe, une
// redirection, une erreur, l'écran de réveil, un leurre, un téléchargement, du JSON ou du XML n'ouvrent aucun verdict. Une page qui n'appelle aucune
// ressource de son propre hôte (ou dont le corps n'est pas lisible) non plus : un vrai navigateur n'aurait rien à charger ici.
//
// N'enveloppe QUE les candidats (adresse neuve portant la signature d'une campagne établie) ; toutes les autres requêtes passent sans surcoût.

const (
	rotationCorpsMax = 64 << 10 // octets de page gardés (tels qu'envoyés)
	rotationClairMax = 64 << 10 // octets de page en clair analysés
	rotationSuivis   = 64       // réponses candidates suivies à la fois ; au-delà, pas de verdict (compté)
	rotationAnalyses = 8        // pages déposées ou en cours d'analyse ; au-delà, pas de verdict (compté)
	rotationExamen   = 10 * time.Minute
	rotationExamens  = 20000 // adresses examinées retenues
)

type cleRotationReponse struct{}

type rotationReponse struct {
	http.ResponseWriter
	statut int
	html   bool
	gzip   bool
	corps  []byte
	echec  bool // écriture vers le client impossible
	exclu  bool // réveil ou leurre : ce n'est pas la page demandée
}

// exclureDuVerdict : la réponse en cours n'est pas celle du service demandé (écran de réveil, leurre). Sans effet hors candidat.
func exclureDuVerdict(ctx context.Context) {
	if x, ok := ctx.Value(cleRotationReponse{}).(*rotationReponse); ok {
		x.exclu = true
	}
}

func (x *rotationReponse) noterEntete(code int) {
	if x.statut != 0 || code < 200 && code != http.StatusSwitchingProtocols {
		return // 1xx : réponse intermédiaire
	}
	x.statut = code
	h := x.ResponseWriter.Header()
	ct := h.Get("Content-Type")
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	x.html = strings.EqualFold(strings.TrimSpace(ct), "text/html") && !strings.HasPrefix(strings.ToLower(h.Get("Content-Disposition")), "attachment")
	switch enc := strings.ToLower(strings.TrimSpace(h.Get("Content-Encoding"))); enc {
	case "", "identity":
	case "gzip", "x-gzip":
		x.gzip = true
	default:
		x.html = false // illisible ici : pas de verdict
	}
}

func (x *rotationReponse) WriteHeader(code int) {
	x.noterEntete(code)
	x.ResponseWriter.WriteHeader(code)
}

func (x *rotationReponse) Write(b []byte) (int, error) {
	x.noterEntete(http.StatusOK)
	n, err := x.ResponseWriter.Write(b)
	if err != nil {
		x.echec = true
	}
	if libre := rotationCorpsMax - len(x.corps); x.html && libre > 0 && n > 0 {
		x.corps = append(x.corps, b[:min(n, libre)]...)
	}
	return n, err
}

// Flush, Hijack, Unwrap : transparents pour httputil.ReverseProxy et les enveloppes du handler (#796).
func (x *rotationReponse) Flush() {
	if f, ok := x.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (x *rotationReponse) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	x.exclu = true
	if hj, ok := x.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, errors.New("rotationReponse: Hijack indisponible")
}

func (x *rotationReponse) Unwrap() http.ResponseWriter { return x.ResponseWriter }

// servie : la page demandée est partie en entier (2xx text/html lisible). Reste à savoir si elle appelle des ressources (rotationAnalyse).
func (x *rotationReponse) servie() bool {
	return !x.exclu && !x.echec && x.html && x.statut >= 200 && x.statut <= 299
}

// ANALYSE DE LA PAGE : hors du chemin de la réponse. Le handler dépose la page et rend la main (la fin de la réponse n'attend pas) ; UN travailleur la
// lit. Au plus rotationAnalyses pages déposées ou en cours : au-delà, pas de verdict (compté). Une adresse examinée ne l'est plus pendant 10 min.
type rotationAnalyse struct {
	corps []byte
	gzip  bool
	x     *rotCandidat
	t     time.Time // fin de la réponse
}

// clair : les 64 premiers Kio de la page, décompressés au besoin (jamais plus : une bombe de décompression ne coûte rien). nil : illisible.
func (a *rotationAnalyse) clair() []byte {
	if !a.gzip {
		return a.corps
	}
	z, err := gzip.NewReader(bytes.NewReader(a.corps))
	if err != nil {
		return nil
	}
	c, _ := io.ReadAll(io.LimitReader(z, rotationClairMax)) // corps tronqué : on lit ce qu'on a
	return c
}

// pageUtile : la page appelle au moins une ressource de son hôte.
func (a *rotationAnalyse) pageUtile() bool { return pageAvecRessource(a.clair(), a.x.hote) }

// Analyser dépose la page d'un candidat ; le verdict s'ouvrira, daté de `t`, si elle appelle des ressources.
func (r *Rotation) Analyser(x *rotationReponse, c *rotCandidat, t time.Time) {
	if r == nil || x == nil || c == nil || !x.servie() {
		return
	}
	if r.analyses.Add(1) > rotationAnalyses {
		r.analyses.Add(-1)
		r.abandonnees.Add(1)
		return
	}
	r.examinees.noter(c.h, t.Unix())
	r.unTravailleur.Do(func() { go r.travailler() })
	r.aAnalyser <- rotationAnalyse{corps: x.corps, gzip: x.gzip, x: c, t: t} // jamais bloquant : la file a rotationAnalyses places
}

func (r *Rotation) travailler() {
	for a := range r.aAnalyser {
		r.traiter(a)
	}
}

func (r *Rotation) traiter(a rotationAnalyse) {
	defer r.analyses.Add(-1)
	defer func() { // hors d'un handler, rien ne rattrape une panique : elle arrêterait tout le WAF
		if e := recover(); e != nil {
			r.abandonnees.Add(1)
			log.Printf("sbxwaf: rotation — analyse d'une page abandonnée : %v", e)
		}
	}()
	if r.avantAnalyse != nil {
		r.avantAnalyse()
	}
	if a.pageUtile() {
		r.Servie(a.x, a.t)
	}
}

// pageAvecRessource : la page appelle une feuille de style ou une image (non différée) de son propre hôte, ce que tout navigateur charge dans la
// seconde. Un script seul ne suffit pas : certains visiteurs les bloquent. UNE lecture, sans retour en arrière ; au plus rotationClairMax octets. Au
// moindre doute (commentaire, guillemet ou élément jamais fermé) : non.
func pageAvecRessource(c []byte, hote string) bool {
	if len(c) > rotationClairMax {
		c = c[:rotationClairMax]
	}
	for {
		i := bytes.IndexByte(c, '<')
		if i < 0 {
			return false
		}
		c = c[i:]
		if bytes.HasPrefix(c, []byte("<!--")) {
			if i = bytes.Index(c[4:], []byte("-->")); i < 0 {
				return false
			}
			c = c[4+i+3:]
			continue
		}
		n := 1
		for n < len(c) && n < 16 && (c[n]|0x20 >= 'a' && c[n]|0x20 <= 'z' || c[n] >= '0' && c[n] <= '9') {
			n++
		}
		if n == 1 {
			c = c[1:] // « < » isolé, balise fermante, déclaration
			continue
		}
		b := baliseHTML{nom: strings.ToLower(string(c[1:n]))}
		var ok bool
		if c, ok = b.lire(c[n:]); !ok {
			return false
		}
		switch b.nom {
		case "base":
			if !adresseLocale(b.href, hote) {
				return false // toutes les adresses relatives partent ailleurs
			}
		case "link":
			if b.feuille && adresseLocale(b.href, hote) {
				return true
			}
		case "img":
			if !b.differee && adresseLocale(b.src, hote) {
				return true
			}
		case "script", "style", "noscript", "template", "textarea", "title", "iframe", "xmp", "noembed", "noframes":
			if c, ok = apresFermeture(c, b.nom); !ok {
				return false
			}
		}
	}
}

// baliseHTML : les seuls attributs utiles. rel et media sont réduits à `feuille` (feuille de style appliquée à l'écran).
type baliseHTML struct {
	nom, href, src string
	feuille        bool
	differee       bool
}

// lire consomme les attributs jusqu'à « > » et rend la suite ; faux si la balise ne se ferme pas.
func (b *baliseHTML) lire(c []byte) ([]byte, bool) {
	utile := b.nom == "link" || b.nom == "img" || b.nom == "base"
	rel, media := "", ""
	for i := 0; i < len(c); {
		switch ch := c[i]; {
		case ch == '>':
			media = strings.ToLower(media)
			b.feuille = contientPli(" "+rel+" ", " stylesheet ") && !contientPli(rel, "alternate") && (media == "" || media == "all" || media == "screen")
			return c[i+1:], true
		case ch <= ' ' || ch == '/':
			i++
			continue
		}
		deb := i
		for i < len(c) && c[i] > ' ' && c[i] != '=' && c[i] != '>' && c[i] != '/' {
			i++
		}
		nom := c[deb:i]
		if i == deb {
			i++ // « = » sans nom
			continue
		}
		for i < len(c) && c[i] <= ' ' {
			i++
		}
		if i >= len(c) || c[i] != '=' {
			continue
		}
		for i++; i < len(c) && c[i] <= ' '; i++ {
		}
		if i >= len(c) {
			return nil, false
		}
		var val []byte
		if q := c[i]; q == '"' || q == '\'' {
			k := bytes.IndexByte(c[i+1:], q)
			if k < 0 {
				return nil, false
			}
			val = c[i+1 : i+1+k]
			i += k + 2
		} else {
			deb = i
			for i < len(c) && c[i] > ' ' && c[i] != '>' {
				i++
			}
			val = c[deb:i]
		}
		if !utile || len(nom) > 7 || len(val) > 2048 {
			continue
		}
		switch v := strings.TrimSpace(string(val)); strings.ToLower(string(nom)) {
		case "href":
			b.href = v
		case "src":
			b.src = v
		case "rel":
			rel = v
		case "media":
			media = v
		case "loading":
			b.differee = strings.EqualFold(v, "lazy")
		}
	}
	return nil, false
}

// apresFermeture saute le contenu d'un élément dont rien n'est affiché ni chargé, jusqu'après « </nom ».
func apresFermeture(c []byte, nom string) ([]byte, bool) {
	for {
		i := bytes.Index(c, []byte("</"))
		if i < 0 {
			return nil, false
		}
		c = c[i+2:]
		if len(c) >= len(nom) && strings.EqualFold(string(c[:len(nom)]), nom) {
			return c[len(nom):], true
		}
	}
}

// adresseLocale : adresse relative, ou absolue vers le même hôte.
func adresseLocale(u, hote string) bool {
	if u == "" || u[0] == '#' {
		return false
	}
	if strings.HasPrefix(u, "//") {
		u = "https:" + u
	}
	i := strings.IndexAny(u, ":/?#")
	if i < 0 || u[i] != ':' {
		return true // relative
	}
	s := strings.ToLower(u[:i])
	if (s != "http" && s != "https") || !strings.HasPrefix(u[i:], "://") {
		return false // data:, blob:…
	}
	reste := u[i+3:]
	if j := strings.IndexAny(reste, "/?#"); j >= 0 {
		reste = reste[:j]
	}
	return hoteRotation(reste) == hote
}
