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
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// corpsMaxLeurre borne ce qu'on accepte de lire d'un corps de requête. Assez
// pour un formulaire de connexion, trop peu pour servir de dépôt à qui que ce
// soit — et le plafond est appliqué à la LECTURE, pas après.
const corpsMaxLeurre = 8 << 10

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
	sondeEntree     familleSonde = "entree" // il a REJOUÉ une de nos marques
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
	// theatre retient les scènes en cours : c'est lui qui permet de
	// RECONNAÎTRE un visiteur déjà servi, et donc de SIMULER la suite au lieu
	// de lui rejouer une première visite.
	theatre *Theatre
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
	return &LeurreHTTP{actif: actif, fil: fil, journal: journal,
		theatre: NewTheatre(2048, 30*time.Minute)}
}

// Sert répond à la place du 421 si le leurre est armé.
//
// Rend (servi, famille, alea, marquesRejouees). `servi=false` laisse l'appelant
// écrire son 421 habituel — le comportement par défaut de la box.
//
// LES MARQUES REJOUÉES REMONTENT, et ce n'est pas décoratif : le rejeu arrive
// dans un CORPS POST, que seul ce niveau lit. Les garder ici ferait piloter la
// simulation par un événement dont le journal et l'enveloppe d'acteur
// n'entendraient jamais parler — c'est-à-dire perdre le signal le plus fort du
// dispositif au moment précis où il se produit.
func (l *LeurreHTTP) Sert(w http.ResponseWriter, r *http.Request, hote string) (bool, familleSonde, string, []string) {
	if l == nil || !l.actif {
		return false, "", "", nil
	}
	// LE POST EST ACCEPTÉ ICI, ET C'EST UN CHANGEMENT ASSUMÉ.
	//
	// On le refusait — « encaisser le corps d'un inconnu sans raison ». La
	// raison existe maintenant : REJOUER UNE FAUSSE CLÉ, C'EST UN POST. Sans
	// lui, le moment le plus instructif de toute la boucle — l'outil qui
	// essaie ce qu'il a moissonné — nous resterait invisible.
	//
	// Le risque est borné par la façon de lire : au plus `corpsMaxLeurre`
	// octets, JAMAIS analysés — on y cherche une marque par simple recherche de
	// sous-chaîne, puis on jette. Pas de parsing de formulaire, pas de JSON,
	// pas de multipart : rien qui puisse trébucher sur une entrée malveillante.
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodPost:
	default:
		return false, "", "", nil
	}
	var marquesRejouees []string
	if r.Method == http.MethodPost && l.fil != nil && r.Body != nil {
		corps, _ := io.ReadAll(io.LimitReader(r.Body, corpsMaxLeurre))
		_ = r.Body.Close()
		marquesRejouees = l.fil.Cherche(string(corps))
	}

	famille := classeSonde(r.URL.Path)
	jeton, alea := "", ""
	if l.fil != nil {
		jeton, alea = l.fil.Marque()
	}

	// RECONNAÎTRE, PUIS SIMULER. La clé associe l'adresse à la FORME des
	// requêtes : derrière un même NAT, deux outils ne partagent pas de scène.
	cle := l.theatre.Cle(clientIP(r), signatureEnTetes(r))
	etape, _ := l.theatre.Avance(cle, famille, alea)

	corps, typeMIME := corpsLeurre(famille, hote, jeton)
	// Si le visiteur REJOUE une valeur qu'on lui a donnée, on lui accorde ce
	// que cette valeur promet. Il croit être entré ; il va donc faire ce qu'il
	// fait UNE FOIS ENTRÉ — et c'est précisément ce qu'on veut voir. Rien
	// n'est ouvert pour autant : la « session » est une page de plus.
	if len(marquesRejouees) > 0 {
		corps, typeMIME = corpsApresEntree(hote, jeton)
		famille = sondeEntree
	}

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
	_ = etape
	return true, famille, alea, marquesRejouees
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

// marquesRevenues cherche, dans une requête ENTRANTE, une marque que nous avons
// nous-mêmes semée (#1290).
//
// C'EST LE MOMENT OÙ LE FILIGRANE PAIE. Le reste du dispositif observe ; ceci
// RELIE. Une de nos fausses clés qui revient prouve trois choses d'un coup :
// que le visiteur a moissonné notre leurre, qu'il exploite ce qu'il moissonne,
// et — puisque la marque est unique — de QUEL semis elle vient. Deux visites
// séparées par des semaines et par des adresses différentes se trouvent alors
// reliées par une preuve, pas par une ressemblance.
//
// OÙ L'ON REGARDE, ET POURQUOI PAS AILLEURS. L'URL complète et trois en-têtes.
// On NE LIT PAS le corps : sbxwaf est sur le chemin critique de toutes les
// requêtes de la box, et bufferiser chaque corps pour y chercher une aiguille
// coûterait à tout le trafic légitime le prix d'une minorité d'attaquants. Le
// corps sera inspecté là où c'est déjà le cas — l'authentification — quand on
// y branchera la même recherche.
func (s *Server) marquesRevenues(r *http.Request) []string {
	if s == nil || s.leurre == nil || s.leurre.fil == nil {
		return nil
	}
	f := s.leurre.fil
	var trouves []string
	ajoute := func(texte string) {
		if texte == "" {
			return
		}
		trouves = append(trouves, f.Cherche(texte)...)
	}
	ajoute(r.URL.RequestURI())
	ajoute(r.Header.Get("Authorization"))
	ajoute(r.Header.Get("Cookie"))
	ajoute(r.Header.Get("Referer"))
	if len(trouves) == 0 {
		return nil
	}
	// Un événement pareil ne doit pas se perdre dans le bruit du journal de
	// menaces : on le dit aussi en clair, tout de suite.
	log.Printf("sbxwaf: MARQUE REVENUE — une valeur semée par le leurre est "+
		"rejouée par %s sur %s%s (marques=%v)",
		clientIP(r), r.Host, r.URL.Path, trouves)
	return trouves
}

// corpsApresEntree — ce qu'on sert à qui REJOUE une marque qu'on lui a semée.
//
// L'outil croit avoir ouvert une porte. On lui montre donc ce qu'une porte
// ouverte montre : une liste de choses à prendre. Chaque nom est une INVITATION
// À SE DÉCRIRE — celui qui ira vers « /backup/db.sql » ne cherche pas la même
// chose que celui qui ira vers « /admin/users ». La séquence qui suit vaut plus
// que tout ce qu'on aurait appris d'un refus.
//
// Rien de tout cela n'existe. Ce sont des noms dans une page.
func corpsApresEntree(hote, jeton string) (string, string) {
	h := html.EscapeString(hote)
	return "<!DOCTYPE html><html lang=\"fr\"><head><meta charset=\"utf-8\">" +
		"<title>" + h + " — tableau de bord</title></head><body>" +
		"<h1>Bienvenue</h1><p>Session <code>" + jeton + "</code></p>" +
		"<ul>" +
		"<li><a href=\"/admin/users\">Utilisateurs</a></li>" +
		"<li><a href=\"/admin/settings\">Paramètres</a></li>" +
		"<li><a href=\"/backup/db.sql\">Sauvegarde base</a></li>" +
		"<li><a href=\"/files/\">Fichiers</a></li>" +
		"<li><a href=\"/api/v1/keys\">Clés d'API</a></li>" +
		"</ul></body></html>", "text/html; charset=utf-8"
}

// LeurrerLe404 remplace un 404 d'un vhost RÉEL par un contenu de leurre, quand
// — et seulement quand — le chemin demandé est un appât intrinsèque (#1290).
//
// POURQUOI C'EST LÉGITIME ICI AUSSI. « Répertoire inexistant » est le même
// espace négatif qu'un vhost non routé, vu d'un cran plus bas : la ressource
// n'existe pas, et personne ne la demande par accident. Un navigateur qui suit
// un lien périmé tombe sur une vraie 404 ; celui qui demande `/.env` ne suit
// aucun lien — il devine.
//
// TROIS GARDES, ET LA PREMIÈRE EST LA PLUS IMPORTANTE :
//
//  1. ON N'AGIT QU'APRÈS COUP. Le vhost réel a déjà répondu, et il a répondu
//
//  404. On ne pré-empte rien, on ne masque aucun chemin légitime : si le
//     service servait cette URL, on ne serait jamais entré ici. C'est ce qui
//     distingue ce remplacement d'une interception, qui elle pourrait faire
//     disparaître une page réelle le jour où quelqu'un en crée une.
//
//  2. SEULEMENT LES APPÂTS INTRINSÈQUES — `estHauteValeur`. Pas « toute 404 » :
//     transformer les liens morts d'un vrai site en fausses pages tromperait
//     ses visiteurs et pourrirait son référencement.
//
//  3. JAMAIS LE LAN. Nos propres outils sondent nos propres services ; leur
//     mentir ferait conclure n'importe quoi à un prober.
func (l *LeurreHTTP) LeurrerLe404(resp *http.Response) bool {
	if l == nil || !l.actif || resp == nil || resp.Request == nil {
		return false
	}
	if resp.StatusCode != http.StatusNotFound {
		return false
	}
	r := resp.Request
	if privateCIDR(clientIP(r)) {
		return false
	}
	if !estHauteValeur(strings.ToLower(r.URL.Path)) {
		return false
	}

	famille := classeSonde(r.URL.Path)
	jeton, alea := "", ""
	if l.fil != nil {
		jeton, alea = l.fil.Marque()
	}
	corps, typeMIME := corpsLeurre(famille, r.Host, jeton)

	if l.theatre != nil {
		l.theatre.Avance(l.theatre.Cle(clientIP(r), signatureEnTetes(r)), famille, alea)
	}

	resp.StatusCode = http.StatusOK
	resp.Status = "200 OK"
	resp.Body = io.NopCloser(strings.NewReader(corps))
	resp.ContentLength = int64(len(corps))
	resp.Header.Set("Content-Type", typeMIME)
	resp.Header.Set("Cache-Control", "no-store")
	resp.Header.Set("X-Robots-Tag", "noindex, nofollow")
	// L'en-tête de longueur DOIT suivre le corps : le laisser à la valeur du
	// 404 d'origine ferait tronquer ou attendre, et le client verrait une
	// réponse cassée là où on voulait une réponse plausible.
	resp.Header.Set("Content-Length", strconv.Itoa(len(corps)))
	resp.Header.Del("Content-Encoding") // le corps de remplacement est en clair

	if l.journal != nil {
		l.journal(r.Host, r.URL.Path, famille, alea)
	}
	return true
}

// fusionneMarques réunit les marques repérées par les deux chemins (en-têtes/URL
// d'un côté, corps POST de l'autre) sans doublon, et crie au journal si le
// second en a trouvé — le premier le fait déjà de son côté.
func fusionneMarques(base []string, autres ...[]string) []string {
	vus := make(map[string]bool, len(base))
	out := append([]string(nil), base...)
	for _, m := range base {
		vus[m] = true
	}
	for _, lot := range autres {
		for _, m := range lot {
			if m != "" && !vus[m] {
				vus[m] = true
				out = append(out, m)
				log.Printf("sbxwaf: MARQUE REVENUE — une valeur semée par le "+
					"leurre est rejouée dans un corps de requête (marque=%s)", m)
			}
		}
	}
	return out
}

// SertAuLieuDeBloquer remplace la PAGE d'un blocage par un contenu de leurre,
// sur les chemins-appâts uniquement (#1290).
//
// LE PROBLÈME QU'ON CORRIGE. La page de blocage du WAF annonce le produit :
// « SecuBox » quatre fois, « WAF » deux fois, « sbxwaf » une fois, dans un 403.
// Tout le reste du dispositif s'applique à ne rien révéler — bannières banales,
// corps sans marque de fabrique — et le chemin le plus fréquenté par les
// scanners criait le nom du pare-feu à chacun d'eux. Un outil soigné qui
// apprend qu'il est face à un WAF change de comportement : on perdait
// exactement ce qu'on était venu observer, et on lui offrait en prime
// l'information la plus utile de sa reconnaissance.
//
// CE QUI NE CHANGE ABSOLUMENT PAS — ET C'EST L'ESSENTIEL :
//
//   - LA REQUÊTE RESTE BLOQUÉE. Elle n'atteint pas le backend, ni avant ni
//     après ce changement. On ne « laisse pas passer » : on répond autre chose.
//   - LA DÉCISION EST DÉJÀ PRISE quand on arrive ici. Le comptage, le verdict
//     de ban, l'application nft et l'écriture au journal de menaces ont eu lieu
//     en amont et ne sont pas touchés. Ce code ne décide de rien ; il écrit.
//   - LE PÉRIMÈTRE EST ÉTROIT. Uniquement les chemins-appâts intrinsèques
//     (`estHauteValeur` : .env, .git, credentials…). Une injection SQL ou un
//     XSS gardent leur 403 : ce sont des attaques contre une ressource RÉELLE,
//     et répondre 200 y serait un mensonge sans contrepartie — l'attaquant
//     croirait sa charge passée sur une page qui existe.
//   - JAMAIS LE LAN, comme partout ailleurs dans ce fichier.
//
// Rend false si rien n'a été écrit : l'appelant garde alors sa page d'origine.
func (l *LeurreHTTP) SertAuLieuDeBloquer(w http.ResponseWriter, r *http.Request) bool {
	if l == nil || !l.actif || r == nil {
		return false
	}
	if privateCIDR(clientIP(r)) {
		return false
	}
	if !estHauteValeur(strings.ToLower(r.URL.Path)) {
		return false
	}

	famille := classeSonde(r.URL.Path)
	jeton, alea := "", ""
	if l.fil != nil {
		jeton, alea = l.fil.Marque()
	}
	corps, typeMIME := corpsLeurre(famille, r.Host, jeton)

	if l.theatre != nil {
		l.theatre.Avance(l.theatre.Cle(clientIP(r), signatureEnTetes(r)), famille, alea)
	}

	// AUCUN EN-TÊTE NE DOIT TRAHIR LE PRODUIT. `X-SecuBox-WAF` est posé par les
	// pages de blocage ; ici il annulerait tout le bénéfice du remplacement.
	w.Header().Del("X-SecuBox-WAF")
	w.Header().Set("Content-Type", typeMIME)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write([]byte(corps))
	}

	if l.journal != nil {
		l.journal(r.Host, r.URL.Path, famille, alea)
	}
	return true
}
