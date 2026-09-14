// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

// BANNIÈRES DE LEURRE — faire parler l'outil sans rien implémenter (#1290).
//
// CE QU'ON AVAIT, ET SA LIMITE. Le leurre acceptait puis fermait, sans échanger
// un octet. Le signal était certain — personne ne se connecte légitimement à un
// service qu'on n'offre pas — mais il s'arrêtait là : on savait QU'ON avait été
// touché, jamais PAR QUOI. Un balayage de masse et un kit spécialisé laissaient
// exactement la même trace.
//
// CE QU'UNE BANNIÈRE CHANGE. Beaucoup de protocoles font parler le SERVEUR en
// premier : SSH, SMTP, FTP et VNC annoncent leur version dès la connexion. Un
// client qui reçoit cette annonce enchaîne avec SA première trame — et cette
// trame, elle, le décrit : version de bibliothèque, options demandées, ordre
// des champs. C'est la même idée que le leurre HTTP, transposée : on ne refuse
// plus la conversation, on la laisse commencer.
//
// ON N'IMPLÉMENTE TOUJOURS AUCUN PROTOCOLE, ET C'EST LA CLÉ.
// `leurre.go` avait posé la règle : « répondre, c'est entretenir une
// conversation avec un balayeur et s'exposer à ses propres failles
// d'implémentation ». Elle tient. Ce fichier ne l'enfreint pas, parce qu'il ne
// fait que deux choses, dont aucune n'est du parsing :
//
//   1. ÉCRIRE une suite d'octets CONSTANTE, compilée dans le binaire. Aucune
//      valeur du client n'y entre. Il n'y a rien à exploiter dans un littéral.
//   2. LIRE un nombre borné d'octets et ne JAMAIS les interpréter — ni
//      découpage en champs, ni décodage, ni allocation guidée par un
//      en-tête de longueur. On garde un extrait hexadécimal et on ferme.
//
// La faille d'implémentation qu'on refusait vient TOUJOURS de l'interprétation.
// Écrire une constante et jeter ce qu'on lit n'en produit aucune.
//
// TROIS BORNES, PARCE QU'UN PORT OUVERT EST UNE PROMESSE À TENIR :
//   * une échéance courte par connexion — un client muet ne mobilise rien ;
//   * un plafond d'octets lus — personne ne se sert du leurre comme d'un dépôt ;
//   * un plafond de connexions simultanées — sans lui, ouvrir mille sockets
//     suffirait à épuiser la box qu'on prétend protéger.

import (
	"encoding/hex"
	"net"
	"strings"
	"time"
)

const (
	// Assez pour la première trame d'un client, trop peu pour tout le reste.
	banniereLectureMax = 512
	// Un balayeur répond tout de suite ou pas du tout.
	banniereEcheance = 3 * time.Second
	// Au-delà, on ferme sans bannière : la connaissance ne vaut pas la RAM.
	banniereParallelisme = 64
)

// bannieres — annonces STATIQUES, par service. Choisies plausibles et banales :
// une version exotique ferait fuir un outil soigné, et l'on perdrait ce qu'on
// est venu voir. Les services absents de cette table n'obtiennent aucune
// bannière : on n'invente pas une annonce pour un protocole qu'on ne connaît
// pas, elle ne tromperait personne.
var bannieres = map[string][]byte{
	"ssh":      []byte("SSH-2.0-OpenSSH_9.2p1 Debian-2\r\n"),
	"smtp":     []byte("220 mail.local ESMTP Postfix\r\n"),
	"ftp":      []byte("220 (vsFTPd 3.0.3)\r\n"),
	"vnc":      []byte("RFB 003.008\n"),
	"telnet":   []byte("\r\nlogin: "),
	"mysql":    nil, // poignée binaire : on ne la fabrique pas
	"postgres": nil,
	"redis":    nil,
	"mongodb":  nil,
	"mssql":    nil,
	"rdp":      nil,
	"smb":      nil,
}

// Echange envoie la bannière du service (si l'on en a une) puis capture, sans
// l'interpréter, ce que le client répond.
//
// Rend un extrait lisible de la première trame — c'est lui qui, rapproché
// d'autres visites, désignera l'outil. Extrait VIDE si le client n'a rien dit :
// beaucoup de balayeurs ne font que tester l'ouverture du port.
func Echange(conn net.Conn, service string) (extrait string, octets int) {
	_ = conn.SetDeadline(time.Now().Add(banniereEcheance))

	if b := bannieres[service]; len(b) > 0 {
		// Écriture d'une CONSTANTE. Pas de formatage, donc pas d'injection
		// possible de quoi que ce soit venu du client.
		if _, err := conn.Write(b); err != nil {
			return "", 0
		}
	}

	tampon := make([]byte, banniereLectureMax)
	n, _ := conn.Read(tampon)
	if n <= 0 {
		return "", 0
	}
	return resumeTrame(tampon[:n]), n
}

// resumeTrame rend une représentation SÛRE de ce qu'on a lu.
//
// On ne remet jamais des octets bruts dans un journal : une trame contenant des
// séquences de contrôle ou une fin de ligne fabriquerait de fausses entrées —
// un attaquant écrirait dans notre journal. Les octets imprimables sont gardés
// tels quels, le reste devient du point ; en prime, l'hexadécimal des premiers
// octets, qui est ce qui distingue vraiment deux clients binaires.
func resumeTrame(b []byte) string {
	const lisibleMax = 64
	var sb strings.Builder
	for i, c := range b {
		if i >= lisibleMax {
			break
		}
		if c >= 0x20 && c < 0x7f {
			sb.WriteByte(c)
		} else {
			sb.WriteByte('.')
		}
	}
	tete := b
	if len(tete) > 16 {
		tete = tete[:16]
	}
	return sb.String() + " | " + hex.EncodeToString(tete)
}
