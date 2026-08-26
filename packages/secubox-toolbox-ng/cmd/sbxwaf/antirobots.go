// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// SecuBox-Deb :: toolbox-ng :: sbxwaf — anti-robots par vhost (#1216)
//
// LE PROBLÈME. Un robot d'indexation n'est pas un attaquant : il est poli, il
// s'annonce, il respecte souvent robots.txt. Mais sur un service à pages
// COÛTEUSES il devient une panne. Cas vécu sur gk2 : les robots parcouraient
// les liens `/compare/vX..vY` de gitea — chaque lien reconstruit un diff sur
// tout l'historique. Gitea a dépassé son plafond mémoire, s'est fait tuer par
// le noyau, a redémarré, a été re-parcouru : dix morts, treize redémarrages,
// et des 504 pour les humains.
//
// CE QUE CE N'EST PAS. Ce n'est PAS de la détection de menace. On ne bannit
// pas, on ne signale pas à CrowdSec, on n'incrémente aucun compteur de
// sévérité : bannir l'adresse de Googlebot serait une faute. C'est une
// décision de CHARGE, prise tôt et à bas coût, et journalisée à part
// (`action: "robot"`) pour rester auditable.
//
// OPT-IN STRICT (contrainte CSPN — jamais un défaut qui change le trafic).
// Rien ne se déclenche tant qu'un vhost n'est pas explicitement coché dans
// `anti_robots` de vhost_profiles.json. Vhost non coché → comportement
// rigoureusement inchangé.
//
// LA PORTE RESTE ENTROUVERTE. `/robots.txt` passe TOUJOURS, même pour un
// robot refusé sur un vhost coché : c'est par là qu'un robot conforme apprend
// à ne plus revenir. Fermer cette porte, c'est se condamner à refuser les
// mêmes requêtes indéfiniment.
package main

import (
	"io"
	"net/http"
	"regexp"
	"strings"
)

// robotSig associe un nom lisible au motif qui l'identifie dans l'User-Agent.
// Le nom sert au journal : « pourquoi cette requête a-t-elle été refusée ? »
// doit toujours avoir une réponse nommée.
type robotSig struct {
	nom string
	ua  *regexp.Regexp
}

// robotsConnus — robots qui s'annoncent. Trois familles, séparées pour rester
// lisibles à la relecture : moteurs de recherche, moissonneurs d'IA, outils
// SEO/commerciaux. Un robot d'ici est nommé avec certitude.
var robotsConnus = []robotSig{
	// Moteurs de recherche
	{"googlebot", reI(`googlebot`)},
	{"bingbot", reI(`bingbot|msnbot`)},
	{"duckduckbot", reI(`duckduckbot|duckduckgo-favicons-bot`)},
	{"yandexbot", reI(`yandex(bot|images|mobilebot)`)},
	{"baiduspider", reI(`baiduspider`)},
	{"slurp", reI(`\bslurp\b`)},
	{"sogou", reI(`sogou (web|inst) spider`)},
	{"exabot", reI(`exabot`)},
	{"seznambot", reI(`seznambot`)},
	{"qwantbot", reI(`qwantify|qwantbot`)},
	{"naver", reI(`yeti/|naverbot`)},
	{"petalbot", reI(`petalbot`)},
	{"applebot", reI(`applebot`)},
	{"ia_archiver", reI(`ia_archiver|archive\.org_bot`)},

	// Moissonneurs pour modèles de langage
	{"gptbot", reI(`gptbot`)},
	{"chatgpt-user", reI(`chatgpt-user`)},
	{"oai-searchbot", reI(`oai-searchbot`)},
	{"claudebot", reI(`claudebot|claude-web|anthropic-ai`)},
	{"perplexitybot", reI(`perplexity(bot|-user)`)},
	{"ccbot", reI(`ccbot`)},
	{"google-extended", reI(`google-extended`)},
	{"bytespider", reI(`bytespider`)},
	{"amazonbot", reI(`amazonbot`)},
	{"meta-externalagent", reI(`meta-external(agent|fetcher)|facebookbot`)},
	{"cohere-ai", reI(`cohere-(ai|training-data-crawler)`)},
	{"diffbot", reI(`diffbot`)},
	{"imagesiftbot", reI(`imagesiftbot`)},
	{"youbot", reI(`youbot`)},
	{"timpibot", reI(`timpibot`)},
	{"omgilibot", reI(`omgili(bot)?`)},
	{"webzio", reI(`webzio-extended`)},
	{"mistralai", reI(`mistralai-user`)},

	// SEO, veille commerciale, moissonnage de masse
	{"ahrefsbot", reI(`ahrefs(bot|siteaudit)`)},
	{"semrushbot", reI(`semrushbot`)},
	{"mj12bot", reI(`mj12bot`)},
	{"dotbot", reI(`\bdotbot\b`)},
	{"blexbot", reI(`blexbot`)},
	{"dataforseobot", reI(`dataforseobot`)},
	{"barkrowler", reI(`barkrowler`)},
	{"serpstatbot", reI(`serpstatbot`)},
	{"zoominfobot", reI(`zoominfobot`)},
	{"screamingfrog", reI(`screaming frog`)},
	{"linkdexbot", reI(`linkdexbot`)},
	{"megaindex", reI(`megaindex`)},
	{"sitebot", reI(`sitebot|site-shot`)},
	{"turnitinbot", reI(`turnitinbot`)},
	{"bytedance", reI(`bytedance`)},
}

// robotGenerique — un robot non listé qui se déclare quand même. Deux signaux,
// tous deux volontairement étroits :
//
//   - un jeton se TERMINANT par bot / crawler / spider / scraper et suivi
//     d'un séparateur ou de la fin (« NewSpider/0.1 », « Xbot; ») — jamais au
//     milieu d'un mot, sinon les téléphones CUBOT_X19 passeraient pour des
//     robots ; c'est exactement ce que la frontière de mot \b ne sait pas
//     faire ici, « NewSpider » n'ayant pas de frontière avant « Spider » ;
//   - l'URL de contact « +http… » que presque tout robot poli embarque.
//
// Ces motifs ne NOMMENT pas : ils rendent « robot ».
var robotGenerique = []*regexp.Regexp{
	reI(`(^|[ (;/])[a-z0-9._-]*(bot|crawler|spider|scraper)([/ ;)]|$)`),
	reI(`\+https?://`),
}

// identifierRobot nomme le robot derrière un User-Agent.
//
//	robot listé   → (nom, true)
//	robot déclaré → ("robot", true)
//	sinon         → ("", false)
//
// Un UA VIDE n'est pas traité comme un robot : c'est le fait de bibliothèques
// et de sondes internes ; les refuser ici casserait du trafic légitime sans
// rapport avec la charge de parcours.
func identifierRobot(ua string) (string, bool) {
	if strings.TrimSpace(ua) == "" {
		return "", false
	}
	for _, r := range robotsConnus {
		if r.ua.MatchString(ua) {
			return r.nom, true
		}
	}
	for _, re := range robotGenerique {
		if re.MatchString(ua) {
			return "robot", true
		}
	}
	return "", false
}

// cheminToujoursPermis liste ce qu'un robot peut obtenir même sur un vhost
// coché. `/robots.txt` d'abord : c'est la réponse à « comment le robot
// apprend-il à s'arrêter ? ». Les défis ACME passent aussi — un vhost ne doit
// jamais perdre son certificat parce qu'un client ACME ressemble à un robot.
var cheminToujoursPermis = regexp.MustCompile(`^/(robots\.txt|favicon\.ico|\.well-known/)`)

// doitRefuserRobot décide du refus. Les trois conditions sont cumulatives et
// dans l'ordre le moins coûteux d'abord : vhost coché, chemin non exempté,
// UA de robot. Récepteur nil-safe : sans profils chargés, jamais de refus.
func (v *VhostProfiles) doitRefuserRobot(host, chemin, ua string) (string, bool) {
	if !v.antiRobots(host) {
		return "", false
	}
	if cheminToujoursPermis.MatchString(chemin) {
		return "", false
	}
	return identifierRobot(ua)
}

// refuserRobot répond au robot. 403 et non 429 : « reviens plus tard » ferait
// revenir : on veut un refus DÉFINITIF sur ce vhost. `X-Robots-Tag` double le
// message pour les robots qui lisent les en-têtes avant le corps, et le corps
// dit où frapper à la place — un robot refusé sans explication est un robot
// qui insiste.
func refuserRobot(w http.ResponseWriter, nom string) {
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if nom != "" {
		w.Header().Set("X-SecuBox-Robot", nom)
	}
	w.WriteHeader(http.StatusForbidden)
	_, _ = io.WriteString(w,
		"403 — ce service n'est pas ouvert aux robots d'indexation.\n"+
			"Voir /robots.txt, qui reste accessible.\n")
}
