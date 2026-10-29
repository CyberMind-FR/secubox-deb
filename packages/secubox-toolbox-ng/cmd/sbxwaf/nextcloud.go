// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// SecuBox-Deb :: toolbox-ng :: sbxwaf — signatures Nextcloud (#3273, R-NC1, R-NC2, R-IMG2)
//
// TROIS SONDES À REPÉRER, MODE DETECT SEULEMENT (spécification § 3.3 à 3.5) :
//
//   - R-NC1 (CVE-2026-77167) : POST anonyme sur le point d'entrée de partage
//     fédéré. Sans fédération, chaque appel est un signal ; avec, plus de 5
//     appels par 1 200 s et par IP (seuil du correctif nextcloud/server#62091).
//   - R-NC2 (CVE-2026-45281) : PROPPATCH sur calendar-proxy-read|write ; haut
//     si l'utilisateur Basic n'est pas le propriétaire du principal.
//   - R-IMG2 (CVE-2026-104190) : PUT WebDAV d'un fichier nommé en raster dont
//     les 64 premiers octets désignent PS, EPS, PDF, SVG ou MVG.
//
// Les fonctions de ce fichier lisent la méthode, le chemin et des en-têtes ;
// aucune ne garde ni ne rend une valeur sensible : l'identifiant Basic, l'uid
// et le nom de fichier servent à comparer, puis sont oubliés. Le journal n'en
// porte que des booléens et des compteurs, et le chemin d'une ligne WebDAV y
// est masqué (cheminJournalNextcloud).

package main

import (
	"encoding/base64"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// federationPeriode : fenêtre de R-NC1, celle du correctif
// (nextcloud/server#62091, FederationRateLimit(limit: 5, period: 1200)).
const federationPeriode = 1200 * time.Second

// federationIPMax : IP suivies au plus par le compteur de R-NC1.
// Provisoire, non sourcé (2026-10-29).
const federationIPMax = 4096

// federationGarde : horodatages gardés par IP (le compte rendu plafonne à
// cette valeur). Provisoire, non sourcé (2026-10-29).
const federationGarde = 64

// compteurFenetre compte, par IP, les appels d'une fenêtre glissante. Partagé
// entre goroutines (un seul verrou, tenu le temps d'un calcul en mémoire).
// MÉMOIRE BORNÉE : au plus ipMax IP et garde horodatages par IP ; les tranches
// ne dépassent jamais garde en capacité (décalage sur place, pas de ré-allocation).
// Horodatages en nanosecondes Unix (int64, R-W10) : 8 octets chacun, soit au
// pire 4096 × 64 × 8 o = 2 Mio, plus la carte.
type compteurFenetre struct {
	mu           sync.Mutex
	periode      time.Duration
	garde, ipMax int
	parIP        map[string][]int64
}

func nouveauCompteurFenetre(periode time.Duration, garde, ipMax int) *compteurFenetre {
	return &compteurFenetre{periode: periode, garde: garde, ipMax: ipMax, parIP: make(map[string][]int64)}
}

// noter ajoute t pour ip et rend le nombre d'appels de ip postérieurs à
// t-periode, plafonné à garde. Seule la borne basse filtre (R-W11, M1) :
// l'heure est lue par l'appelant HORS verrou, et un appel concurrent peut
// avoir noté une heure plus tardive que t ; elle reste comptée, jamais perdue.
// Carte pleine : purge des IP sans horodatage récent (les plus anciennes) ;
// encore pleine, l'IP n'est pas suivie et noter rend 1.
func (c *compteurFenetre) noter(ip string, t time.Time) int {
	if c.garde < 1 || c.ipMax < 1 {
		return 1
	}
	maintenant := t.UnixNano()
	debut := t.Add(-c.periode).UnixNano()
	c.mu.Lock()
	defer c.mu.Unlock()
	ts, suivie := c.parIP[ip]
	if !suivie && len(c.parIP) >= c.ipMax {
		c.purger(debut)
		if len(c.parIP) >= c.ipMax {
			return 1
		}
	}
	// Garder, sur place, les horodatages postérieurs à debut.
	n := 0
	for _, x := range ts {
		if x > debut {
			ts[n] = x
			n++
		}
	}
	ts = ts[:n]
	if len(ts) >= c.garde {
		// Plein : le plus ancien sort (décalage sur place).
		copy(ts, ts[len(ts)-c.garde+1:])
		ts = ts[:c.garde-1]
	}
	ts = append(ts, maintenant)
	c.parIP[ip] = ts
	return len(ts)
}

// purger retire les IP dont le dernier horodatage (ajouté en dernier, donc le
// plus récent à un croisement de quelques microsecondes près) n'est pas
// postérieur à debut. Sous verrou ; O(ipMax), un seul horodatage lu par IP.
func (c *compteurFenetre) purger(debut int64) {
	for ip, ts := range c.parIP {
		if len(ts) == 0 || ts[len(ts)-1] <= debut {
			delete(c.parIP, ip)
		}
	}
}

// cheminPartageFedere : chemin exact d'une des deux actions limitées par le
// correctif (RequestHandler#addShare : /ocm/shares, aussi sous /index.php ;
// RequestHandler#createShare : route OCS POST /cloud/shares, v1 et v2). Un
// seul « / » final est toléré ; les sous-chemins /{id}/… ne comptent pas.
// Sensible à la casse, comme le routeur de Nextcloud.
func cheminPartageFedere(chemin string) bool {
	switch strings.TrimSuffix(chemin, "/") {
	case "/ocm/shares", "/index.php/ocm/shares", "/ocs/v1.php/cloud/shares", "/ocs/v2.php/cloud/shares":
		return true
	}
	return false
}

// reProxyAgenda : principal d'agenda délégué, celui que le contournement de
// l'éditeur bloque (CVE-2026-45281).
var reProxyAgenda = regexp.MustCompile(`^/remote\.php/dav/principals/users/([^/]+)/calendar-proxy-(read|write)/?$`)

// proxyAgenda : PROPPATCH (sans casse) sur calendar-proxy-read|write ; rend
// l'uid du principal, lu dans le chemin déjà décodé.
func proxyAgenda(methode, chemin string) (uid string, ok bool) {
	if !strings.EqualFold(methode, "PROPPATCH") {
		return "", false
	}
	m := reProxyAgenda.FindStringSubmatch(chemin)
	if m == nil {
		return "", false
	}
	return m[1], true
}

// utilisateurBasic : schéma « Basic » (sans casse), identifiants en base64
// standard, utilisateur = partie avant le premier « : » (RFC 7617). Sans « : »
// ou base64 invalide : faux. Le mot de passe n'est jamais rendu.
func utilisateurBasic(authorization string) (string, bool) {
	schema, reste, ok := strings.Cut(strings.TrimSpace(authorization), " ")
	if !ok || !strings.EqualFold(schema, "Basic") {
		return "", false
	}
	brut, err := base64.StdEncoding.DecodeString(strings.TrimSpace(reste))
	if err != nil {
		return "", false
	}
	user, _, ok := strings.Cut(string(brut), ":")
	if !ok {
		return "", false
	}
	return user, true
}

// extensionRaster : extension jpg, jpeg, png, gif ou webp (sans casse).
func extensionRaster(nom string) bool {
	i := strings.LastIndexByte(nom, '.')
	if i < 0 {
		return false
	}
	switch strings.ToLower(nom[i+1:]) {
	case "jpg", "jpeg", "png", "gif", "webp":
		return true
	}
	return false
}

const (
	prefixeDAVFichiers = "/remote.php/dav/files/"
	prefixeDAVEnvois   = "/remote.php/dav/uploads/"
	// Anciens points d'entrée, toujours servis par Nextcloud 32 (R-W10) :
	// mono-fichier, le nom cible est le dernier segment du chemin.
	prefixeWebDAVAncien = "/remote.php/webdav/"
	prefixeWebDAVPublic = "/public.php/webdav/" // partage public en écriture
)

// putWebDAVPremierSegment : PUT (sans casse) sur /remote.php/dav/files/…,
// /remote.php/webdav/… ou /public.php/webdav/… (R-W10) → dernier segment du
// chemin (Destination ignorée) ; sur /remote.php/dav/uploads/<u>/<id>/<n> avec n
// décimal de valeur <= 1 (premier segment d'un envoi en morceaux : 0 en v1,
// 1 en v2, seul à porter l'en-tête du fichier) → dernier segment du chemin de
// Destination. Nom vide : faux.
func putWebDAVPremierSegment(methode, chemin, destination string) (nomCible string, ok bool) {
	if !strings.EqualFold(methode, "PUT") {
		return "", false
	}
	switch {
	case strings.HasPrefix(chemin, prefixeDAVFichiers),
		strings.HasPrefix(chemin, prefixeWebDAVAncien),
		strings.HasPrefix(chemin, prefixeWebDAVPublic):
		nomCible = dernierSegment(chemin)
	case strings.HasPrefix(chemin, prefixeDAVEnvois):
		parts := strings.Split(chemin[len(prefixeDAVEnvois):], "/")
		if len(parts) != 3 || parts[0] == "" || parts[1] == "" || !decimalAuPlusUn(parts[2]) {
			return "", false
		}
		if destination == "" {
			return "", false
		}
		u, err := url.Parse(destination)
		if err != nil {
			return "", false
		}
		nomCible = dernierSegment(u.Path)
	default:
		return "", false
	}
	return nomCible, nomCible != ""
}

// dernierSegment : ce qui suit le dernier « / » ("" si le chemin finit par « / »).
func dernierSegment(chemin string) string {
	return chemin[strings.LastIndexByte(chemin, '/')+1:]
}

// decimalAuPlusUn : chiffres ASCII seulement, non vide, valeur 0 ou 1 (zéros
// de tête admis, sans conversion : aucun débordement possible).
func decimalAuPlusUn(n string) bool {
	if n == "" {
		return false
	}
	for i := 0; i < len(n); i++ {
		if n[i] < '0' || n[i] > '9' {
			return false
		}
	}
	reste := strings.TrimLeft(n, "0")
	return reste == "" || reste == "1"
}

// cheminJournalNextcloud masque, dans le chemin journalisé, l'uid et le nom de
// fichier d'un chemin WebDAV (le journal ne porte jamais un nom de fichier ni
// ce qui sert à comparer). La décision se prend sur le chemin décodé et rend
// une forme fixe : rien du chemin d'origine n'en sort. ok faux : chemin hors
// WebDAV, à garder tel quel.
func cheminJournalNextcloud(chemin string) (masque string, ok bool) {
	if m := reProxyAgenda.FindStringSubmatch(chemin); m != nil {
		return "/remote.php/dav/principals/users/*/calendar-proxy-" + m[2], true
	}
	for _, p := range []string{prefixeDAVFichiers, prefixeDAVEnvois, "/remote.php/dav/principals/users/", prefixeWebDAVAncien, prefixeWebDAVPublic} {
		if strings.HasPrefix(chemin, p) {
			return p + "*", true
		}
	}
	return "", false
}
