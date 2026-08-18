// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Package gateway porte la passerelle média du BBS : un objet unique pour tout
// ce qui entre, d'où qu'il vienne.
//
// Un billet Mastodon, une vidéo YouTube et un article de flux ne sont que des
// variantes du même objet. Les normaliser ici évite d'avoir, plus tard, autant
// de chemins de code que de plateformes — et de perdre la trace d'un contenu le
// jour où la plateforme d'où il vient ferme.
package gateway

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"golang.org/x/crypto/blake2b"
)

// Genre : la nature du contenu, indépendante de la plateforme.
const (
	GenreTexte = "texte"
	GenreImage = "image"
	GenreVideo = "video"
	GenreAudio = "audio"
	GenreLien  = "lien"
	GenreMixte = "mixte"
)

// Rétention : combien de temps on garde, et à quel titre.
const (
	RetentionCache   = "cache"   // périssable, purgé par le ramasse-miettes
	RetentionEpingle = "epingle" // gardé tant que l'utilisateur le veut
	RetentionArchive = "archive" // conservation durable
)

// Propriété : qui a fait ce contenu. Ce champ commande le droit de republier ;
// il n'a volontairement PAS de valeur par défaut.
const (
	ProprieteSoi   = "soi"
	ProprieteTiers = "tiers"
)

// Media est un fichier rapatrié dans le cache local. Le chemin est relatif au
// répertoire de cache : une base ne doit jamais porter de blob.
type Media struct {
	Chemin string `json:"chemin"`
	Mime   string `json:"mime"`
	Taille int64  `json:"taille"`
	Somme  string `json:"somme"`
}

// Replique dit où l'objet vit ailleurs : PeerTube, republication, archive.
type Replique struct {
	Cible    string `json:"cible"`
	CibleURL string `json:"cible_url,omitempty"`
	RefCible string `json:"ref_cible,omitempty"`
	PousseLe int64  `json:"pousse_le,omitempty"`
	Mode     string `json:"mode"`
}

// Contenu est l'objet universel de la passerelle.
type Contenu struct {
	ID           string            `json:"id"`
	Genre        string            `json:"genre"`
	Titre        string            `json:"titre,omitempty"`
	Corps        string            `json:"corps,omitempty"`
	Auteur       string            `json:"auteur,omitempty"`
	PublieLe     int64             `json:"publie_le,omitempty"`
	SourceURL    string            `json:"source_url"`
	Connecteur   string            `json:"connecteur"`
	RefNative    string            `json:"ref_native,omitempty"`
	Metadonnees  map[string]string `json:"metadonnees,omitempty"`
	Medias       []Media           `json:"medias,omitempty"`
	Empreinte    string            `json:"empreinte"`
	ExpireLe     int64             `json:"expire_le,omitempty"` // 0 = jamais
	Retention    string            `json:"retention"`
	Propriete    string            `json:"propriete"`
	NoeudOrigine string            `json:"noeud_origine"`
	Repliques    []Replique        `json:"repliques,omitempty"`
	CreeLe       int64             `json:"cree_le,omitempty"`
	MajLe        int64             `json:"maj_le,omitempty"`
}

// Paramètres d'adresse qui ne désignent pas un contenu mais celui qui l'a
// cliqué. Les garder ferait apparaître le même article autant de fois qu'il a
// été partagé.
var pistage = map[string]bool{
	"utm_source": true, "utm_medium": true, "utm_campaign": true,
	"utm_term": true, "utm_content": true, "utm_id": true, "utm_name": true,
	"fbclid": true, "gclid": true, "dclid": true, "msclkid": true, "twclid": true,
	"igshid": true, "mc_cid": true, "mc_eid": true, "ref_src": true,
	"ref_url": true, "s": true, "si": true, "spm": true, "yclid": true,
	"_openstat": true, "at_medium": true, "at_campaign": true,
}

// normaliserURL rend l'adresse comparable : c'est l'œuvre qu'on identifie, pas
// le chemin par lequel elle est arrivée.
func normaliserURL(brut string) string {
	u, err := url.Parse(strings.TrimSpace(brut))
	if err != nil {
		return strings.TrimSpace(brut)
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	u.Fragment = ""
	u.RawFragment = ""

	// Le port par défaut du schéma ne distingue rien.
	if (u.Scheme == "http" && strings.HasSuffix(u.Host, ":80")) ||
		(u.Scheme == "https" && strings.HasSuffix(u.Host, ":443")) {
		u.Host = u.Host[:strings.LastIndex(u.Host, ":")]
	}

	q := u.Query()
	for cle := range q {
		if pistage[strings.ToLower(cle)] {
			q.Del(cle)
		}
	}
	u.RawQuery = q.Encode() // Encode trie les clés : deux ordres donnent un seul texte

	// « /article » et « /article/ » sont la même page ; « / » seul reste « / ».
	if len(u.Path) > 1 {
		u.Path = strings.TrimRight(u.Path, "/")
	}
	return u.String()
}

// normaliserTexte absorbe les différences de mise en forme, qui ne changent pas
// le propos : un flux qui ré-indente son XML ne republie pas un article.
func normaliserTexte(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// FormeCanonique rend la représentation stable dont l'empreinte est tirée.
//
// N'y entrent QUE les traits qui font l'identité d'un contenu. En sont
// volontairement exclus la date de collecte, les métadonnées propres au
// connecteur et l'identifiant local : sans quoi le même article reviendrait
// comme un doublon à chaque passage du collecteur.
func FormeCanonique(c Contenu) string {
	var b strings.Builder
	b.WriteString("url=" + normaliserURL(c.SourceURL) + "\n")
	b.WriteString("connecteur=" + strings.ToLower(strings.TrimSpace(c.Connecteur)) + "\n")
	b.WriteString("ref=" + strings.TrimSpace(c.RefNative) + "\n")
	b.WriteString("genre=" + strings.TrimSpace(c.Genre) + "\n")
	b.WriteString("titre=" + normaliserTexte(c.Titre) + "\n")
	b.WriteString("corps=" + normaliserTexte(c.Corps) + "\n")

	// Les médias arrivent dans l'ordre où la collecte les a trouvés, qui n'a
	// rien à voir avec le contenu : on les trie.
	sommes := make([]string, 0, len(c.Medias))
	for _, m := range c.Medias {
		s := m.Somme
		if s == "" {
			s = fmt.Sprintf("%s:%d", m.Chemin, m.Taille)
		}
		sommes = append(sommes, s)
	}
	sort.Strings(sommes)
	b.WriteString("medias=" + strings.Join(sommes, ",") + "\n")
	return b.String()
}

// Empreinte identifie un contenu, quel que soit le moment où on le revoit.
func Empreinte(c Contenu) string {
	somme := blake2b.Sum256([]byte(FormeCanonique(c)))
	return hex.EncodeToString(somme[:])
}

var genres = map[string]bool{
	GenreTexte: true, GenreImage: true, GenreVideo: true,
	GenreAudio: true, GenreLien: true, GenreMixte: true,
}

var retentions = map[string]bool{
	RetentionCache: true, RetentionEpingle: true, RetentionArchive: true,
}

// Valider contrôle l'objet, pose les valeurs par défaut et calcule l'empreinte.
func (c *Contenu) Valider() error {
	if c.Retention == "" {
		// Au doute, périssable : un contenu qu'on garde par accident coûte de
		// la place et pose une question de droits ; un contenu purgé se
		// récupère auprès de sa source, dont l'adresse est conservée.
		c.Retention = RetentionCache
	}
	if !genres[c.Genre] {
		return fmt.Errorf("genre inconnu : %q", c.Genre)
	}
	if !retentions[c.Retention] {
		return fmt.Errorf("retention inconnue : %q", c.Retention)
	}
	// Pas de valeur par defaut ici, JAMAIS : ce champ commande le droit de
	// republier, et le silence ne vaut pas autorisation.
	if c.Propriete != ProprieteSoi && c.Propriete != ProprieteTiers {
		return errors.New("propriete non declaree : « soi » ou « tiers » exigé")
	}
	if strings.TrimSpace(c.Connecteur) == "" {
		return errors.New("connecteur non renseigné")
	}
	if strings.TrimSpace(c.NoeudOrigine) == "" {
		return errors.New("noeud d'origine non renseigné")
	}
	if err := validerAdresse(c.SourceURL); err != nil {
		return err
	}
	c.Empreinte = Empreinte(*c)
	return nil
}

// validerAdresse n'accepte que http(s). Un connecteur compromis ne doit pas
// pouvoir faire lire un fichier local ni parler un autre protocole.
func validerAdresse(brut string) error {
	brut = strings.TrimSpace(brut)
	if brut == "" {
		return errors.New("adresse source vide")
	}
	u, err := url.Parse(brut)
	if err != nil {
		return fmt.Errorf("adresse source illisible : %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("schéma d'adresse refusé : %q", u.Scheme)
	}
	if u.Host == "" {
		return errors.New("adresse source sans hôte")
	}
	return nil
}

// EstRepubliable dit si l'objet peut sortir de la boîte.
//
// La règle vit ici, et non dans chaque connecteur : un connecteur qui
// oublierait de la vérifier republierait le travail d'autrui.
func (c Contenu) EstRepubliable() bool { return c.Propriete == ProprieteSoi }
