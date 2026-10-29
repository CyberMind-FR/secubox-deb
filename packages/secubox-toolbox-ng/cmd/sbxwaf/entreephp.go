// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// SecuBox-Deb :: toolbox-ng :: sbxwaf — entrée PHP d'une requête (#3273)
//
// UNE ENTRÉE, TOUTES LES SIGNATURES. Les signatures structurelles de #3257 ne
// lisaient que le résultat de l'analyseur multipart. Celles de #3273
// (Roundcube, Nextcloud, PHP générique) lisent aussi la méthode, le chemin, la
// chaîne de requête et le corps urlencoded, LUS COMME PHP (nomsphp.go). Tout
// cela tient dans EntreePHP, construite une fois par requête d'un vhost PHP et
// évaluée après la réponse, dans le defer du gestionnaire.
//
// MODE DETECT SEULEMENT, comme #3257 : l'analyse a lieu après le relais, ne
// bannit jamais, ne touche ni nft ni l'escalade, et le journal ne porte que
// des compteurs, des booléens et des étiquettes : jamais un corps, un nom de
// fichier ni la valeur d'un paramètre.
//
// AUCUNE LECTURE DE PLUS. Le corps urlencoded passe par la même capture en
// flux que le multipart (capture.go) : même fenêtre (fenetreCapture), même
// sémaphore de capturesMultipartMax jetons. Une requête sans corps ne prend
// aucun jeton : ses contrôles (méthode, chemin, requête) restent évalués.

package main

import (
	"log"
	"net/http"
	"runtime/debug"
	"strings"
)

// genreCorps dit quel corps la capture retient pour l'entrée PHP.
type genreCorps int

const (
	corpsAucun      genreCorps = iota
	corpsMultipart             // multipart/form-data : analyserMultipart (#3257)
	corpsUrlencoded            // application/x-www-form-urlencoded : lireParametresPHP
	corpsXML                   // branche ajoutée par la tâche 5
	corpsDebut                 // branche ajoutée par la tâche 4 (64 premiers octets d'un PUT)
)

// EntreePHP : ce que les signatures structurelles lisent d'une requête PHP.
type EntreePHP struct {
	Service   string             // servicePHP ; "" = hôte par motif : toutes les familles s'appliquent
	Methode   string             // r.Method tel quel
	Chemin    string             // r.URL.Path (décodé)
	Requete   ParametresPHP      // r.URL.RawQuery, lue dans analyserRequetePHP
	Corps     *ParametresPHP     // corps urlencoded capturé, sinon nil
	Multipart *ResultatMultipart // corps multipart analysé, sinon nil

	requeteBrute string // r.URL.RawQuery, lue par lireRequete après la réponse
	// les tâches 3 à 7 ajoutent leurs champs ici
}

// estUrlencodedPHP reproduit le test de SAPI.c, comme estMultipartPHP :
// minuscules, coupure au premier `;`, `,` ou espace, comparaison au type
// application/x-www-form-urlencoded.
func estUrlencodedPHP(contentType string) bool {
	ct := minusculesASCII(contentType)
	if i := strings.IndexAny(ct, ";, "); i >= 0 {
		ct = ct[:i]
	}
	return ct == "application/x-www-form-urlencoded"
}

// nouvelleEntreePHP retient ce qui ne demande pas le corps : méthode, chemin
// et chaîne de requête BRUTE. Rien n'est lu ici, avant le relais (relecture
// I2) : la lecture a lieu dans analyserRequetePHP, après la réponse.
func (s *Server) nouvelleEntreePHP(r *http.Request, service string) *EntreePHP {
	return &EntreePHP{
		Service:      service,
		Methode:      r.Method,
		Chemin:       r.URL.Path,
		requeteBrute: r.URL.RawQuery,
	}
}

// lireRequete lit la chaîne de requête gardée brute (au plus
// parametresRetenusMax paramètres retenus). Appelée par analyserRequetePHP,
// sous son recover, après la réponse, et seulement si une signature chargée
// lit la requête (relecture I2).
func (e *EntreePHP) lireRequete() { e.Requete = lireRequetePHP(e.requeteBrute) }

// Crochets de test (relecture I2) : les tests les remplacent par des
// compteurs pour prouver qu'un GET sans ligne ne les appelle pas.
var (
	etiquetteOutilPHP = étiquetteOutil
	lireRequetePHP    = lireParametresPHP
)

// corpsACapturer choisit le corps à capturer, son plafond, et s'il prend un
// jeton du sémaphore. Sans corps : rien, et aucun jeton.
func (s *Server) corpsACapturer(r *http.Request, e *EntreePHP) (genre genreCorps, plafond int, jeton bool) {
	if r.Body == nil || r.Body == http.NoBody {
		return corpsAucun, 0, false
	}
	ct := r.Header.Get("Content-Type")
	switch {
	case estMultipartPHP(ct):
		return corpsMultipart, s.fenetreCapture(), true
	case estUrlencodedPHP(ct):
		return corpsUrlencoded, s.fenetreCapture(), true
	}
	return corpsAucun, 0, false
}

// completerCorps lit le préfixe capturé selon son genre. complet : le corps
// entier tient dans le préfixe (sinon le multipart est dit tronqué).
func completerCorps(e *EntreePHP, genre genreCorps, prefixe []byte, contentType string, complet bool) {
	switch genre {
	case corpsMultipart:
		res := analyserMultipart(prefixe, contentType, !complet, LimitesMultipart{})
		e.Multipart = &res
	case corpsUrlencoded:
		p := lireParametresPHP(string(prefixe))
		// La fenêtre a coupé le corps : le dernier segment peut être partiel.
		p.Tronque = !complet
		e.Corps = &p
	}
}

// valeurs rend toutes les valeurs retenues du nom normalisé : la requête,
// puis le corps urlencoded, puis les champs multipart. Rien n'est lu de plus.
func (e *EntreePHP) valeurs(nom string) []string {
	r := e.Requete.Valeurs(nom)
	if e.Corps != nil {
		r = append(r, e.Corps.Valeurs(nom)...)
	}
	if e.Multipart != nil {
		for _, c := range e.Multipart.Champs {
			if c.Nom == nom {
				r = append(r, c.Valeur)
			}
		}
	}
	return r
}

// valeursRequete rend les valeurs du nom dans la chaîne de requête seulement
// (PHP lit _from en GET seulement, spécification § 3.1).
func (e *EntreePHP) valeursRequete(nom string) []string { return e.Requete.Valeurs(nom) }

// Signaux : les compteurs journalisés avec chaque détection (jamais une valeur).
// from_bang vaut 1 si un _from de la requête est invalide et commence par « ! »
// (R-RC1) : un booléen, jamais la valeur.
func (e *EntreePHP) Signaux() map[string]int {
	var m map[string]int
	if e.Multipart != nil {
		m = e.Multipart.Signaux()
	}
	for _, v := range e.valeursRequete("_from") {
		if inv, bang := fromInvalideRoundcube(v); inv && bang {
			if m == nil {
				m = map[string]int{}
			}
			m["from_bang"] = 1
			break
		}
	}
	return m
}

// analyserRequetePHP fige la capture, complète l'entrée, l'évalue et
// journalise. Appelée par defer dans le gestionnaire, donc après le relais et
// la réponse. relaye dit que le corps a été confié au proxy : faux (403, ban,
// cache média), la capture est figée et le jeton rendu, sans analyse ni ligne.
// jeton : un jeton du sémaphore a été pris pour cette requête.
//
// MODE DETECT SEULEMENT : aucun appel au ban, à nft ni à l'escalade. La
// gravité journalisée est celle de la signature ; elle part vers actord comme
// toute ligne du journal (une adresse privée reste « local », R12). Une ligne
// d'état (tronque, malforme, limite) est d'une gravité « audit », qui ne
// compte pas comme hostile.
//
// Le jeton est rendu APRÈS l'analyse : le préfixe vit jusque-là, et la borne
// mémoire couvre aussi les allocations de l'analyseur. Son defer est posé
// avant tout le reste : il est rendu quoi qu'il arrive.
func (s *Server) analyserRequetePHP(capt *captureCorps, genre genreCorps, e *EntreePHP, rm requeteMultipart, relaye, jeton bool) {
	rmp := &rm
	if jeton {
		defer s.rendreCapture(genre)
	}
	// Une panique de l'analyse ne doit pas casser une réponse déjà relayée :
	// en detect, l'analyse n'a pas le droit d'empêcher quoi que ce soit. Ce
	// recover est différé PAR CETTE FONCTION : il ne rattrape que ses propres
	// paniques, jamais celle du gestionnaire (http.ErrAbortHandler) qui
	// traverserait ce defer.
	defer func() {
		if p := recover(); p != nil {
			log.Printf("sbxwaf: ERREUR analyse PHP host=%s path=%s ip=%s : %v\n%s",
				rm.host, rm.path, rm.ip, p, debug.Stack())
		}
	}()
	var (
		prefixe []byte
		lus     int64
		complet bool
	)
	if capt != nil {
		prefixe, lus, complet = capt.figer()
	}
	// Non relayé : un chemin texte a pu lire la fenêtre au travers de la
	// capture avant un 403 ; cette requête n'a jamais atteint le backend.
	if !relaye || s.rules == nil {
		return
	}
	if s.rules.litLaRequete() {
		e.lireRequete()
	}
	// lus == 0 : le proxy n'a rien lu (backend muet, erreur de connexion) ;
	// les contrôles sans corps restent évalués.
	if capt != nil && lus > 0 {
		completerCorps(e, genre, prefixe, rm.contentType, complet)
	}
	signaux := e.Signaux()
	for _, d := range s.rules.EvaluerPHP(e) {
		s.journaliserMultipart(rmp, ThreatRecord{
			Category: d.Categorie, Severity: d.Severity, RuleID: d.RuleID,
			Action: "detect", Mode: modeDetect, Signaux: signaux,
		})
		log.Printf("sbxwaf: DETECT %s rule=%s host=%s path=%s ip=%s",
			d.Categorie, d.RuleID, rm.host, rm.path, rm.ip)
	}
	if e.Multipart != nil && e.Multipart.Statut != MultipartAnalyse {
		statut := "multipart-" + string(e.Multipart.Statut)
		s.journaliserMultipart(rmp, ThreatRecord{
			Category: statut, Severity: "audit", Action: statut, Signaux: signaux,
		})
	}
}
