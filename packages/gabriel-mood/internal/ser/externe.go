// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package ser

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"
)

// Externe : un classifieur qui vit DANS UN AUTRE PROCESSUS, joint par socket
// unix.
//
// C'EST LE CHEMIN ONNX, ET VOICI POURQUOI IL PASSE PAR LÀ. Faire tourner ONNX
// Runtime dans ce binaire demanderait CGO ; or tout le dépôt se construit en
// `CGO_ENABLED=0` et se croise vers arm64, et l'unité systemd porte
// `MemoryDenyWriteExecute=yes` — que le compilateur à la volée d'ONNX ne
// supporte pas. Lier ONNX ici, ce serait donc renoncer à la fois à la
// compilation croisée et à un durcissement qu'on a mis là pour de bonnes
// raisons.
//
// Le sortir dans son propre processus rend chaque contrainte locale : ce
// service-ci reste pur Go et durci, le service d'inférence assume CGO et son
// propre bac à sable. Et il rend le remplacement possible sans reconstruire
// quoi que ce soit — n'importe quel programme qui répond à ce contrat fait
// l'affaire, en Python comme en Rust.
//
// AUCUN MODÈLE N'EST LIVRÉ, et ce n'est pas un oubli. Les corpus publics
// d'émotion vocale sont joués par des acteurs : un modèle entraîné dessus rend
// des probabilités élevées et bien séparées sur de la parole spontanée où
// elles n'ont aucun fondement. Livrer un tel modèle par défaut contredirait
// tout ce que ce paquet affirme par ailleurs. Qui en branche un doit savoir
// sur quoi il a été entraîné — et le dire dans son interface.
type Externe struct {
	client   *http.Client
	secours  Classifieur
	delai    time.Duration
	chemin   string
	derniere error
}

// NouvelExterne joint le service d'inférence écoutant sur `socket`.
// `secours` est utilisé chaque fois que l'externe ne répond pas : un
// classifieur indisponible ne doit pas faire taire le module.
func NouvelExterne(socket string, secours Classifieur, delai time.Duration) *Externe {
	if delai <= 0 {
		delai = 40 * time.Millisecond
	}
	return &Externe{
		chemin: socket, secours: secours, delai: delai,
		client: &http.Client{
			Timeout: delai,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, "unix", socket)
				},
			},
		},
	}
}

func (e *Externe) Nom() string { return "externe:" + e.chemin }

// Contrat attendu du service : POST / avec les traits en JSON, réponse
//
//	{"indices": {"calm": .., "joy": .., …}, "modele": "nom", "corpus": "…"}
//
// Les clés absentes valent zéro. Le service N'A PAS à rendre d'état ni de
// confiance : ce paquet les dérive lui-même, en appliquant les mêmes garde-fous
// qu'à l'heuristique — plafond de confiance compris. Un modèle sûr de lui ne
// peut donc pas contourner la règle cardinale.
type reponseExterne struct {
	Indices map[string]float64 `json:"indices"`
	Modele  string             `json:"modele"`
	Corpus  string             `json:"corpus"`
}

// Evalue interroge le service, et retombe sur le secours à la moindre anicroche.
func (e *Externe) Evalue(t Traits) Lecture {
	if t.TramesVoisees < MinTramesVoisees {
		return LectureIndeterminee(
			fmt.Sprintf("pas assez de voix sur la fenêtre (%d trames voisées)",
				t.TramesVoisees), false)
	}
	corps, err := json.Marshal(t)
	if err != nil {
		return e.replie(t, err)
	}
	req, err := http.NewRequest(http.MethodPost, "http://inference/", bytesReader(corps))
	if err != nil {
		return e.replie(t, err)
	}
	req.Header.Set("Content-Type", "application/json")
	rep, err := e.client.Do(req)
	if err != nil {
		return e.replie(t, err)
	}
	defer rep.Body.Close()
	if rep.StatusCode != http.StatusOK {
		return e.replie(t, fmt.Errorf("inférence : HTTP %d", rep.StatusCode))
	}
	var r reponseExterne
	if err := json.NewDecoder(rep.Body).Decode(&r); err != nil {
		return e.replie(t, err)
	}
	if len(r.Indices) == 0 {
		return e.replie(t, fmt.Errorf("inférence : aucune sortie"))
	}
	e.derniere = nil

	// ON NE FAIT PAS CONFIANCE AUX CHIFFRES DU MODÈLE PLUS QU'AUX NÔTRES. On
	// ne garde que les étiquettes connues, on renormalise, et on applique le
	// même plafond : c'est ici que la règle cardinale devient impossible à
	// contourner par un modèle tiers.
	retenus := make(map[string]float64, len(Etats))
	for _, nom := range Etats {
		v := r.Indices[nom]
		if v < 0 {
			v = 0
		}
		retenus[nom] = v
	}
	indices := normalise(retenus)
	tete, second := deuxPremiers(indices)
	conf := (indices[tete] - indices[second]) * 2
	if conf > PlafondConfiance {
		conf = PlafondConfiance
	}
	if conf < 0.15 {
		l := LectureIndeterminee("aucune lecture ne se détache nettement des autres", true)
		l.Indices, l.Suffisant = indices, true
		return l
	}
	pourquoi := []string{"modèle externe : " + orDefault(r.Modele, "sans nom")}
	if r.Corpus != "" {
		pourquoi = append(pourquoi, "entraîné sur : "+r.Corpus)
	} else {
		// Un modèle dont on ignore le corpus est un modèle dont on ignore les
		// biais. On l'utilise, mais on le DIT, à chaque lecture.
		pourquoi = append(pourquoi, "corpus d'entraînement non déclaré : biais inconnus")
	}
	return Lecture{
		Etat: tete, Confiance: arrondi(conf, 3), Indices: indices,
		Pourquoi: pourquoi, Reserve: Reserve, Etalonne: true, Suffisant: true,
	}
}

// replie bascule sur le classifieur de secours. Le motif est joint à la
// lecture : une panne d'inférence ne doit pas se lire comme un changement
// d'humeur.
func (e *Externe) replie(t Traits, err error) Lecture {
	e.derniere = err
	if e.secours == nil {
		return LectureIndeterminee("service d'inférence injoignable : "+err.Error(), false)
	}
	l := e.secours.Evalue(t)
	l.Pourquoi = append([]string{"repli sur l'heuristique (" + err.Error() + ")"}, l.Pourquoi...)
	return l
}

// DerniereErreur : de quoi afficher l'état du service dans le cockpit.
func (e *Externe) DerniereErreur() error { return e.derniere }

func orDefault(v, d string) string {
	if v == "" {
		return d
	}
	return v
}
