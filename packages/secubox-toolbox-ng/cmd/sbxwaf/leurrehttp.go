// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

// LEURRE HTTP — connaître l'outil sans jamais en subir les effets (#1290).
//
// CE QU'ON CHERCHE. Un vhost inconnu reçoit aujourd'hui un 421 muet. Le
// scanner en déduit « rien ici » et s'en va : on n'aura vu que sa PREMIÈRE
// sonde. Or c'est la suite qui trahit l'outil — l'ordre des chemins, ce qu'il
// tente après un 200, s'il suit une redirection, s'il relit ce qu'on lui donne.
// Un 421 coupe la conversation juste avant qu'elle devienne informative.
//
// TROIS INVARIANTS, ET ILS NE SE NÉGOCIENT PAS :
//
//  1. AUCUN SERVICE RÉEL N'EST EN JEU. Le leurre ne s'engage QUE sur un hôte
//     non routé — un nom que la box ne sert à personne. Il ne proxifie rien, ne
//     touche à aucun backend. Un scanner qui entre ici est détourné du vrai :
//     il s'occupe avec du vide pendant qu'il croit progresser.
//
//  2. RIEN N'EST EXÉCUTÉ, RIEN N'EST LU SUR LE DISQUE. Les réponses sont des
//     constantes compilées. Pas de gabarit avec des données de l'attaquant, pas
//     d'accès fichier, pas de sous-processus. La seule valeur venue de lui qui
//     réapparaît est le nom d'hôte, échappé. On ne peut pas exploiter une
//     chaîne littérale.
//
//  3. ON N'IMITE AUCUN PROTOCOLE. C'est la règle déjà posée par les leurres
//     réseau (`sbx-authwatch/leurre.go`) : imiter une poignée de main, c'est
//     écrire un serveur, donc écrire des failles. Ici la nuance qui rend la
//     chose sûre : sbxwaf TERMINE DÉJÀ le HTTP — il a parsé la requête bien
//     avant d'arriver ici. Servir un corps statique n'ajoute pas une ligne de
//     surface d'analyse. On ne parle pas un nouveau protocole ; on écrit un
//     corps différent dans celui qu'on parlait déjà.
//
// APPRENTISSAGE SEUL. Ce fichier ne bannit pas, ne bloque pas, ne ralentit pas.
// Il observe et il marque. La politique de sanction reste où elle est, décidée
// ailleurs — un leurre qui bannit devient un piège à faux positifs, et l'on a
// déjà banni un vrai visiteur derrière un CGNAT.
//
// FILIGRANE. Chaque contenu servi porte une marque vérifiable (voir
// filigrane.go). Si une de nos fausses clés revient — tentative d'authentification,
// corps de requête, autre vhost, trois semaines plus tard — on saura que c'est
// la nôtre, et de quel semis elle vient.

import (
	"html"
	"log"
	"net/http"
	"strings"
)

// familleSonde classe ce que la sonde CHERCHE. On répond dans le registre de
// sa demande : un outil qui reçoit une réponse hors-sujet s'arrête, et l'on
// perd la séquence qu'on voulait observer.
type familleSonde string

const (
	sondeSecret     familleSonde = "secret" // .env, credentials, clés
	sondeGit        familleSonde = "git"    // dépôt exposé
	sondeCMS        familleSonde = "cms"    // WordPress & co
	sondeAdmin      familleSonde = "admin"  // consoles, phpmyadmin
	sondeInfo       familleSonde = "info"   // phpinfo, status, debug
	sondeSauvegarde familleSonde = "backup" // .sql, .zip, dumps
	sondeRacine     familleSonde = "racine" // « / » et le reste
)

// classeSonde déduit la famille du chemin demandé. Ordre volontaire : du plus
// spécifique au plus général.
func classeSonde(chemin string) familleSonde {
	p := strings.ToLower(chemin)
	switch {
	case strings.Contains(p, ".git"):
		return sondeGit
	case strings.Contains(p, ".env") || strings.Contains(p, "credential") ||
		strings.Contains(p, ".aws") || strings.Contains(p, "id_rsa") ||
		strings.Contains(p, "secret") || strings.Contains(p, ".npmrc"):
		return sondeSecret
	case strings.Contains(p, "wp-") || strings.Contains(p, "wordpress") ||
		strings.Contains(p, "xmlrpc"):
		return sondeCMS
	case strings.Contains(p, "phpmyadmin") || strings.Contains(p, "/admin") ||
		strings.Contains(p, "manager/html") || strings.Contains(p, "/console"):
		return sondeAdmin
	case strings.Contains(p, "phpinfo") || strings.Contains(p, "server-status") ||
		strings.Contains(p, "/debug") || strings.Contains(p, "actuator"):
		return sondeInfo
	case strings.HasSuffix(p, ".sql") || strings.HasSuffix(p, ".zip") ||
		strings.HasSuffix(p, ".bak") || strings.HasSuffix(p, ".tar.gz"):
		return sondeSauvegarde
	default:
		return sondeRacine
	}
}

// LeurreHTTP sert des réponses plausibles et inertes dans l'espace non routé.
type LeurreHTTP struct {
	fil   *Filigrane
	actif bool
	// journal reçoit ce qui a été semé : (hôte, chemin, famille, aléa du
	// filigrane). C'est la trace qui permettra, plus tard, de dire d'où vient
	// une marque qui revient.
	journal func(hote, chemin string, famille familleSonde, alea string)
}

// NewLeurreHTTP construit le leurre. `actif=false` → il ne sert jamais rien et
// le 421 d'origine est conservé. Le défaut est INACTIF : on n'arme pas un piège
// en silence sur la box de quelqu'un.
func NewLeurreHTTP(actif bool, fil *Filigrane,
	journal func(string, string, familleSonde, string)) *LeurreHTTP {
	return &LeurreHTTP{actif: actif, fil: fil, journal: journal}
}

// Sert répond à la place du 421 si le leurre est armé.
//
// Rend (servi, famille, alea) : `servi=false` laisse l'appelant écrire son 421
// habituel — ce qui reste le comportement par défaut de la box.
func (l *LeurreHTTP) Sert(w http.ResponseWriter, r *http.Request, hote string) (bool, familleSonde, string) {
	if l == nil || !l.actif {
		return false, "", ""
	}
	// GARDE-FOU DE MÉTHODE. On ne répond qu'aux lectures. Accepter un POST
	// reviendrait à encaisser un corps — donc à accepter de la donnée d'un
	// inconnu sans aucune raison de le faire.
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false, "", ""
	}

	famille := classeSonde(r.URL.Path)
	jeton, alea := "", ""
	if l.fil != nil {
		jeton, alea = l.fil.Marque()
	}

	corps, typeMIME := corpsLeurre(famille, hote, jeton)

	// En-têtes délibérément BANALS. Un serveur qui se signale « SecuBox » dirait
	// à l'outil qu'il a trouvé un produit de sécurité, et le plus soigné des
	// scanners changerait de comportement — on perdrait justement ce qu'on est
	// venu observer.
	w.Header().Set("Content-Type", typeMIME)
	w.Header().Set("Cache-Control", "no-store")
	// Un leurre n'a rien à faire dans un index de moteur.
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write([]byte(corps))
	}

	if l.journal != nil {
		l.journal(hote, r.URL.Path, famille, alea)
	}
	return true, famille, alea
}

// corpsLeurre rend un contenu PLAUSIBLE et STATIQUE pour la famille demandée.
//
// Tout est littéral. La seule interpolation est le nom d'hôte (échappé) et le
// filigrane (hexadécimal produit par nous). Aucune donnée de l'attaquant
// n'atteint le corps.
func corpsLeurre(f familleSonde, hote, jeton string) (string, string) {
	h := html.EscapeString(hote)
	if jeton == "" {
		// Sans secret de filigrane, on sert quand même — mais la marque est
		// vide plutôt que fausse. Une marque invérifiable tromperait l'analyse
		// bien plus qu'elle ne l'aiderait.
		jeton = "0000000000000000"
	}

	switch f {
	case sondeSecret:
		// Faux fichier d'environnement. Les valeurs sont inertes : aucun hôte
		// joignable, aucun format de clé réellement valide chez un fournisseur.
		// Le filigrane voyage DANS la fausse clé : c'est elle qu'un moissonneur
		// emportera.
		return "APP_ENV=production\n" +
			"APP_DEBUG=false\n" +
			"APP_KEY=base64:" + jeton + "\n" +
			"DB_CONNECTION=mysql\n" +
			"DB_HOST=127.0.0.1\n" +
			"DB_DATABASE=app\n" +
			"DB_USERNAME=app\n" +
			"DB_PASSWORD=" + jeton + "\n" +
			"AWS_ACCESS_KEY_ID=AKIA" + strings.ToUpper(jeton) + "\n" +
			"AWS_SECRET_ACCESS_KEY=" + jeton + jeton + "\n", "text/plain; charset=utf-8"

	case sondeGit:
		// HEAD DÉTACHÉ plutôt que « ref: refs/heads/main ». La forme reste
		// parfaitement normale pour git — et elle porte un identifiant de
		// commit, donc elle peut porter la marque. La version avec `ref:` n'a
		// nulle part où la loger : un leurre qu'on ne peut pas tracer ne sert
		// qu'à moitié.
		return jeton + jeton[:8] + "\n", "text/plain; charset=utf-8"

	case sondeCMS:
		return "<!DOCTYPE html><html lang=\"fr\"><head><meta charset=\"utf-8\">" +
			"<title>" + h + " &rsaquo; Connexion</title></head><body>" +
			"<form name=\"loginform\" id=\"loginform\" action=\"/wp-login.php\" method=\"post\">" +
			"<p><label>Identifiant<br><input type=\"text\" name=\"log\" id=\"user_login\"></label></p>" +
			"<p><label>Mot de passe<br><input type=\"password\" name=\"pwd\" id=\"user_pass\"></label></p>" +
			"<p><input type=\"submit\" id=\"wp-submit\" value=\"Se connecter\">" +
			"<input type=\"hidden\" name=\"redirect_to\" value=\"/wp-admin/\">" +
			"<input type=\"hidden\" name=\"nonce\" value=\"" + jeton + "\"></p>" +
			"</form></body></html>", "text/html; charset=utf-8"

	case sondeAdmin:
		return "<!DOCTYPE html><html><head><title>" + h + " — administration</title></head>" +
			"<body><h1>Authentification requise</h1>" +
			"<!-- build " + jeton + " -->" +
			"<form method=\"post\"><input name=\"user\"><input name=\"pass\" type=\"password\">" +
			"<button>Entrer</button></form></body></html>", "text/html; charset=utf-8"

	case sondeInfo:
		// Assez pour qu'un outil coche « phpinfo trouvé », rien qui décrive la
		// machine réelle : ni version exacte, ni chemin, ni module.
		return "<!DOCTYPE html><html><head><title>phpinfo()</title></head><body>" +
			"<h1>PHP Version 8.2.0</h1>" +
			"<table><tr><td>System</td><td>Linux " + h + "</td></tr>" +
			"<tr><td>Build ID</td><td>" + jeton + "</td></tr>" +
			"<tr><td>Server API</td><td>FPM/FastCGI</td></tr></table>" +
			"</body></html>", "text/html; charset=utf-8"

	case sondeSauvegarde:
		// Un en-tête de dump plausible, et rien derrière : assez pour que
		// l'outil note « archive accessible », trop peu pour nourrir qui que
		// ce soit.
		return "-- MySQL dump 10.13  Distrib 8.0.35\n" +
			"-- Host: localhost    Database: app\n" +
			"-- Dump id: " + jeton + "\n", "text/plain; charset=utf-8"

	default:
		return "<!DOCTYPE html><html lang=\"fr\"><head><meta charset=\"utf-8\">" +
			"<title>" + h + "</title></head><body><h1>" + h + "</h1>" +
			"<p>Ce site est en cours de configuration.</p>" +
			"<!-- ref " + jeton + " -->" +
			"</body></html>", "text/html; charset=utf-8"
	}
}

// construitLeurre assemble le leurre et annonce clairement son état au
// démarrage. Un piège silencieux est un piège qu'on oublie : l'opérateur doit
// lire dans son journal ce qui est armé, et si les marques sont vérifiables.
func construitLeurre(actif bool, cheminSecret string) *LeurreHTTP {
	if !actif {
		return NewLeurreHTTP(false, nil, nil)
	}
	fil := NewFiligrane(cheminSecret)
	if fil == nil {
		log.Printf("sbxwaf: leurre ARMÉ mais SANS filigrane (secret absent ou "+
			"trop court dans %s) — les contenus semés ne seront pas traçables",
			cheminSecret)
	} else {
		log.Printf("sbxwaf: leurre ARMÉ sur les hôtes non routés, filigrane actif " +
			"(apprentissage seul — aucun ban n'en découle)")
	}
	return NewLeurreHTTP(true, fil, func(hote, chemin string, f familleSonde, alea string) {
		// Journal du SEMIS : c'est lui qui, plus tard, dira d'où vient une
		// marque qui revient. L'aléa seul suffit — le jeton complet n'a pas à
		// traîner dans un fichier.
		log.Printf("sbxwaf: leurre semé host=%s path=%s famille=%s filigrane=%s",
			hote, chemin, f, alea)
	})
}
