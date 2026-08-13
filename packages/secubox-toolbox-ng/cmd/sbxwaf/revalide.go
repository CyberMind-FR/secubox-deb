// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: sbxwaf — revalidation conditionnelle du cache média (#1031)
//
// LE CACHE NE SAVAIT QUE VIEILLIR. `MediaCache.Get` servait toute entrée non
// expirée : un fichier remplacé sur disque restait donc masqué jusqu'à la fin
// de son TTL. Constaté sur anibal-amiot.fr — un `app.js` mis à jour par
// `git pull` était servi dans sa version d'avant, sur les six domaines à la
// fois, pendant que le disque et nginx portaient déjà le bon.
//
// Une synchronisation aux cinq minutes ne sert à rien si le cache répond
// l'ancienne version pendant l'heure qui suit.
package main

import (
	"net"
	"net/http"
	"strconv"
	"time"
)

// delaiRevalidation borne l'attente. L'amont est un nginx local : au-delà de
// deux secondes il ne répond pas, et faire patienter le visiteur pour décider
// de la fraîcheur d'une image serait un mauvais échange.
const delaiRevalidation = 2 * time.Second

// amontInchange demande à l'amont si sa version est toujours celle qu'on a.
//
// Rend true UNIQUEMENT sur un 304 franc. Tout le reste — 200, erreur, délai
// dépassé, amont muet — rend false, donc « je ne sais pas », donc on
// réinterroge. C'EST LE SENS DE LA PRUDENCE ICI : servir du périmé est
// invisible et dure des heures ; un aller-retour de trop coûte une milliseconde.
func amontInchange(ip string, port int, r *http.Request, etag, lastMod string) bool {
	if etag == "" && lastMod == "" {
		return false
	}
	cible := "http://" + net.JoinHostPort(ip, strconv.Itoa(port)) + r.URL.RequestURI()
	req, err := http.NewRequest(http.MethodGet, cible, nil)
	if err != nil {
		return false
	}
	// L'hote est repris tel quel : l'amont sert plusieurs vhosts sur le meme
	// port, et sans cet en-tete il repondrait pour un autre site — on
	// revaliderait alors contre le mauvais fichier.
	req.Host = r.Host
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	if lastMod != "" {
		req.Header.Set("If-Modified-Since", lastMod)
	}
	// Pas de compression : on ne veut qu'un code de statut, et negocier un
	// encodage exposerait a recevoir un corps qu'il faudrait lire pour rien.
	req.Header.Set("Accept-Encoding", "identity")

	cl := &http.Client{
		Timeout: delaiRevalidation,
		// ON NE SUIT PAS LES REDIRECTIONS. Un 301 vers un autre chemin n'est
		// pas « ce fichier n'a pas change » : c'est autre chose, et le suivre
		// masquerait le changement qu'on cherche justement a detecter.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := cl.Do(req)
	if err != nil {
		return false
	}
	// Le corps d'un 304 est vide ; celui d'un 200 ne nous interesse pas ici —
	// le chemin normal du proxy le retransmettra. On ferme sans lire.
	_ = resp.Body.Close()
	return resp.StatusCode == http.StatusNotModified
}
