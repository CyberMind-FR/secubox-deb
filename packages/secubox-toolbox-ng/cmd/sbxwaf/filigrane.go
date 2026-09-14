// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

// FILIGRANE — marquer ce qu'on donne au leurre, pour le reconnaître s'il revient.
//
// LE PROBLÈME QUE ÇA RÉSOUT. Un leurre qui sert un faux `/.env` apprend une
// chose : que quelqu'un a sondé `/.env`. C'est peu. La question intéressante
// vient après : ces fausses informations, qu'en fait-on ? Sont-elles rejouées
// chez nous ? Revendues ? Essayées sur un autre de nos noms trois semaines plus
// tard ? Sans marque, on ne saura jamais — une fausse clé ressemble à n'importe
// quelle chaîne.
//
// LA MARQUE EST AUTO-VÉRIFIABLE, ET C'EST TOUT L'INTÉRÊT. Le jeton porte sa
// propre preuve :
//
//     jeton = aléa(8 octets) ‖ HMAC-SHA256(secret, aléa)[:8 octets]
//
// Conséquences, toutes utiles :
//
//   * on RECONNAÎT un de nos jetons n'importe où — dans une tentative
//     d'authentification, un journal, un corps de requête — sans tenir aucune
//     table ni interroger quoi que ce soit. Un `Reconnait()` suffit ;
//   * un attaquant ne peut pas en FABRIQUER un : sans le secret, la moitié de
//     preuve est inatteignable. Une marque qui revient est donc forcément une
//     marque qu'on a semée, jamais une coïncidence ;
//   * la partie aléatoire reste journalisée à part avec son contexte (hôte,
//     chemin, acteur, date). Reconnaître le jeton dit « c'est le nôtre » ;
//     retrouver son aléa dans le journal dit « semé ici, ce jour-là, à
//     celui-là ».
//
// POURQUOI HMAC ET NON UN SIMPLE HACHAGE. Un SHA-256 sans clé se recalcule par
// n'importe qui : les jetons deviendraient forgeables, et un adversaire
// pourrait nous inonder de fausses « marques revenues » pour noyer les vraies.
// La clé est ce qui rend la reconnaissance digne de foi.
//
// Voir docs/POLITIQUE-CRYPTO.md — HMAC-SHA256 (RFC 2104, FIPS 198-1).

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"regexp"
	"strings"
)

const (
	// 8 octets d'aléa = 64 bits : assez pour que deux semis ne se croisent
	// jamais, court assez pour passer pour une valeur plausible dans un fichier
	// de configuration.
	filigraneAleaLen = 8
	filigranePreuve  = 8 // 64 bits de preuve — forger demande le secret, pas de la chance
	filigraneHexLen  = (filigraneAleaLen + filigranePreuve) * 2
)

// Filigrane appose et reconnaît les marques du leurre.
type Filigrane struct {
	secret []byte
}

// NewFiligrane lit le secret local. Secret absent ou trop court → nil : le
// leurre servira alors des contenus SANS marque plutôt que des marques
// forgeables, et le dira. Une marque qu'on ne peut pas vérifier est pire
// qu'aucune marque : elle donne une confiance qu'on n'a pas.
func NewFiligrane(chemin string) *Filigrane {
	if chemin == "" {
		return nil
	}
	b, err := os.ReadFile(chemin)
	if err != nil {
		return nil
	}
	s := []byte(strings.TrimSpace(string(b)))
	if len(s) < 16 {
		return nil
	}
	return &Filigrane{secret: s}
}

// Marque produit un jeton neuf. Rend aussi l'aléa seul, à journaliser avec le
// contexte : c'est lui qui, plus tard, dira OÙ la marque a été semée.
func (f *Filigrane) Marque() (jeton, alea string) {
	if f == nil {
		return "", ""
	}
	brut := make([]byte, filigraneAleaLen)
	if _, err := rand.Read(brut); err != nil {
		// L'aléa du système ne doit pas échouer ; s'il échoue, on n'invente
		// surtout pas de repli déterministe — on ne marque pas.
		return "", ""
	}
	m := hmac.New(sha256.New, f.secret)
	m.Write(brut)
	preuve := m.Sum(nil)[:filigranePreuve]
	return hex.EncodeToString(brut) + hex.EncodeToString(preuve), hex.EncodeToString(brut)
}

// Reconnait dit si `jeton` est une marque que NOUS avons produite.
// Comparaison en temps constant — un attaquant ne doit pas pouvoir approcher
// la preuve octet par octet en mesurant nos réponses.
func (f *Filigrane) Reconnait(jeton string) bool {
	if f == nil || len(jeton) != filigraneHexLen {
		return false
	}
	brut, err := hex.DecodeString(jeton[:filigraneAleaLen*2])
	if err != nil {
		return false
	}
	attendue, err := hex.DecodeString(jeton[filigraneAleaLen*2:])
	if err != nil {
		return false
	}
	m := hmac.New(sha256.New, f.secret)
	m.Write(brut)
	return hmac.Equal(m.Sum(nil)[:filigranePreuve], attendue)
}

// motifFiligrane repère les SUITES hexadécimales assez longues pour contenir
// une marque. On ne cherche pas un jeton isolé : une marque semée voyage
// NOYÉE dans une valeur plus grande — une fausse clé AWS de 64 signes, un faux
// SHA de commit de 40. Exiger des frontières de mot autour des 32 caractères
// laisserait passer exactement les cas qu'on a semés.
var motifFiligrane = regexp.MustCompile(`[0-9a-f]{32,}`)

// Cherche rend les marques authentiques présentes dans un texte : un corps de
// requête, un en-tête, une tentative d'authentification. C'est la porte par
// laquelle une marque semée revient à nous.
func (f *Filigrane) Cherche(texte string) []string {
	if f == nil || texte == "" {
		return nil
	}
	var trouves []string
	vus := map[string]bool{}
	for _, suite := range motifFiligrane.FindAllString(strings.ToLower(texte), 32) {
		// Fenêtre glissante sur la suite : la marque peut commencer n'importe
		// où dedans. Les suites sont bornées par la taille du texte inspecté,
		// et l'on s'arrête à 32 suites — un corps de requête n'est pas un
		// terrain de fouille illimité.
		for i := 0; i+filigraneHexLen <= len(suite); i++ {
			c := suite[i : i+filigraneHexLen]
			if !vus[c] && f.Reconnait(c) {
				vus[c] = true
				trouves = append(trouves, c)
			}
		}
	}
	return trouves
}
