// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Package audio — d'où viennent les échantillons.
//
// POURQUOI PAS UNE LIAISON ALSA. La libasound se lie par CGO ; le dépôt entier
// se construit en `CGO_ENABLED=0` et se croise vers arm64. On passe donc par
// `arecord`, qui est déjà là, qu'on peut confiner par systemd comme n'importe
// quel sous-processus, et qui parle un format brut sans ambiguïté. Le prix est
// un processus de plus et quelques millisecondes de tampon ; le gain est de ne
// pas troquer toute la chaîne de construction contre un appel de bibliothèque.
//
// L'ABSENCE DE MICRO EST UN ÉTAT, PAS UNE PANNE. Une board sans carte son est
// un cas ordinaire — c'est celui de gk2, dont le `/dev/snd` ne contient qu'un
// `timer`. Le module doit alors le DIRE, dans l'API comme à l'écran, au lieu
// de planter au démarrage ou, pire, d'afficher un cockpit animé par du vide.
package audio

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Format fixe : 48 kHz, mono, 16 bits signés petit-boutiste.
//
// 48 kHz parce que c'est la fréquence native de la quasi-totalité des cartes
// récentes : demander 16 kHz ferait rééchantillonner quelqu'un — le pilote ou
// nous — pour rien. Mono parce qu'on analyse une voix, pas une scène. 16 bits
// parce que 24 n'apporte rien sous un plancher de bruit de pièce.
const (
	Echantillonnage    = 48000
	Canaux             = 1
	BitsParEchantillon = 16
)

// Source : un robinet d'échantillons normalisés dans [-1, +1].
type Source interface {
	// Lis remplit `dst` et rend le nombre d'échantillons écrits. Une source
	// épuisée rend io.EOF ; une source vivante bloque jusqu'à avoir de quoi.
	Lis(dst []float64) (int, error)
	Ferme() error
	// Decrit : ce qu'on affiche à l'écran et dans /api/mood.
	Decrit() Description
}

// Description : l'identité d'une source, telle que l'interface la montre.
type Description struct {
	Genre   string `json:"genre"`   // "alsa" | "fichier" | "synthese" | "absente"
	Detail  string `json:"detail"`  // périphérique, chemin, ou motif d'absence
	Reelle  bool   `json:"reelle"`  // false pour la synthèse : RIEN de ce qui s'affiche n'est une vraie voix
	Perenne bool   `json:"perenne"` // false pour un fichier : ça finira
}

// ErrPasDEntree : aucune entrée audio n'est disponible. Ce n'est pas une
// erreur de programmation, c'est une réponse.
var ErrPasDEntree = errors.New("aucune entrée audio disponible")

// EntreesDisponibles inspecte la machine et rend ce qu'elle peut écouter.
//
// On regarde /dev/snd plutôt que d'appeler `arecord -l` : un binaire absent
// est indiscernable d'une absence de matériel dans le code de sortie, et on
// veut savoir LAQUELLE des deux, pour le dire.
func EntreesDisponibles() (peripheriques []string, motif string) {
	entrees, err := filepath.Glob("/dev/snd/pcm*c") // 'c' = capture
	if err == nil && len(entrees) > 0 {
		for _, e := range entrees {
			peripheriques = append(peripheriques, filepath.Base(e))
		}
		return peripheriques, ""
	}
	if _, err := os.Stat("/dev/snd"); os.IsNotExist(err) {
		return nil, "/dev/snd absent : pas de pilote son chargé, ou l'unité est confinée (PrivateDevices)"
	}
	// Le cas de gk2 : le répertoire existe, mais ne contient qu'un timer.
	tout, _ := filepath.Glob("/dev/snd/*")
	noms := make([]string, 0, len(tout))
	for _, t := range tout {
		noms = append(noms, filepath.Base(t))
	}
	return nil, fmt.Sprintf(
		"aucun périphérique de capture dans /dev/snd (présents : %s) — "+
			"cette machine n'a pas d'entrée micro", strings.Join(noms, ", "))
}

// Absente : la source qu'on obtient quand il n'y a rien à écouter. Elle ne
// rend AUCUN échantillon — surtout pas des zéros, qui se lisent comme du
// silence et donneraient un cockpit qui tourne, plat et parfaitement crédible,
// sur une machine sourde.
type Absente struct{ motif string }

// NouvelleAbsente construit la source vide.
func NouvelleAbsente(motif string) *Absente { return &Absente{motif: motif} }

func (a *Absente) Lis([]float64) (int, error) { return 0, ErrPasDEntree }
func (a *Absente) Ferme() error               { return nil }
func (a *Absente) Decrit() Description {
	return Description{Genre: "absente", Detail: a.motif, Reelle: false, Perenne: true}
}

// VersFlottants convertit du S16_LE en [-1, +1].
//
// La division est par 32768 et non 32767 : c'est la pleine échelle NÉGATIVE,
// et diviser par 32767 laisserait -32768 sortir à -1,00003 — assez pour faire
// déborder un affichage borné, et faux de toute façon.
func VersFlottants(brut []byte, dst []float64) int {
	n := len(brut) / 2
	if n > len(dst) {
		n = len(dst)
	}
	for i := 0; i < n; i++ {
		v := int16(uint16(brut[2*i]) | uint16(brut[2*i+1])<<8)
		dst[i] = float64(v) / 32768
	}
	return n
}
