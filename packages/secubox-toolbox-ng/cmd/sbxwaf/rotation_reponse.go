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
	"net"
	"net/http"
	"regexp"
	"strings"
)

// OUVERTURE DU VERDICT (#3919). Le silence d'une adresse ne prouve quelque chose que si elle a REÇU une page qui demande des ressources. Le verdict
// différé ne s'ouvre donc qu'à la FIN d'une réponse 2xx text/html, et le délai de 10 s court à partir de là : une page lente, un client qui coupe, une
// redirection, une erreur, l'écran de réveil, un leurre, un téléchargement, du JSON ou du XML n'ouvrent aucun verdict. Une page qui n'appelle aucune
// ressource de son propre hôte (ou dont le corps n'est pas lisible) non plus : un vrai navigateur n'aurait rien à charger ici.
//
// N'enveloppe QUE les candidats (adresse neuve portant la signature d'une campagne établie) ; toutes les autres requêtes passent sans surcoût.

const (
	rotationCorpsMax = 64 << 10  // octets de page gardés (tels qu'envoyés)
	rotationClairMax = 256 << 10 // octets de page décompressés
	rotationSuivis   = 64        // réponses candidates suivies à la fois ; au-delà, pas de verdict
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

// servie : la page demandée est partie en entier et appelle au moins une ressource de son hôte.
func (x *rotationReponse) servie(hote string) bool {
	if x.exclu || x.echec || !x.html || x.statut < 200 || x.statut > 299 {
		return false
	}
	corps := x.corps
	if x.gzip {
		z, err := gzip.NewReader(bytes.NewReader(corps))
		if err != nil {
			return false
		}
		corps, _ = io.ReadAll(io.LimitReader(z, rotationClairMax)) // tronqué : on lit ce qu'on a
	}
	return pageAvecRessource(corps, hote)
}

var (
	reRotScript  = regexp.MustCompile(`(?is)(<script\b[^>]*>).*?(?:</script|\z)`)
	reRotInerte  = regexp.MustCompile(`(?is)<!--.*?(?:-->|\z)|<noscript\b.*?(?:</noscript|\z)|<template\b.*?(?:</template|\z)`)
	reRotBalise  = regexp.MustCompile(`(?is)<(link|img|base)\b([^>]*)>`)
	reRotAttribu = regexp.MustCompile(`(?is)([a-z-]+)\s*=\s*("[^"]*"|'[^']*'|[^\s"'>]+)`)
)

// pageAvecRessource : la page appelle une feuille de style ou une image (non différée) de son propre hôte, ce que tout navigateur charge dans la
// seconde. Un script seul ne suffit pas : certains visiteurs les bloquent.
func pageAvecRessource(corps []byte, hote string) bool {
	corps = reRotScript.ReplaceAll(corps, []byte("$1"))
	corps = reRotInerte.ReplaceAll(corps, nil)
	trouve := false
	for _, m := range reRotBalise.FindAllSubmatch(corps, 2000) {
		att := map[string]string{}
		for _, a := range reRotAttribu.FindAllSubmatch(m[2], 32) {
			att[strings.ToLower(string(a[1]))] = strings.TrimSpace(strings.Trim(string(a[2]), `"'`))
		}
		switch strings.ToLower(string(m[1])) {
		case "base":
			if !adresseLocale(att["href"], hote) {
				return false // toutes les adresses relatives partent ailleurs
			}
		case "link":
			media := strings.ToLower(att["media"])
			if contientPli(" "+att["rel"]+" ", " stylesheet ") && !contientPli(att["rel"], "alternate") && (media == "" || media == "all" || media == "screen") &&
				adresseLocale(att["href"], hote) {
				trouve = true
			}
		case "img":
			if !strings.EqualFold(att["loading"], "lazy") && adresseLocale(att["src"], hote) {
				trouve = true
			}
		}
	}
	return trouve
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
