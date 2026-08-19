// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package connectors

import (
	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/gateway"
)

// YouTube : connecteur souverain. Il ne télécharge rien lui-même — il DEMANDE à
// ytsas la meilleure source locale et garde toujours l'original comme failover.
type YouTube struct {
	gateway.Base
	cl    *ClientYtsas
	noeud string
}

// NouveauYouTube construit le connecteur (lecture seule : pas de Sortie).
func NouveauYouTube(cl *ClientYtsas, noeud string) *YouTube {
	return &YouTube{cl: cl, noeud: noeud}
}

func (y *YouTube) Manifeste() gateway.Manifeste {
	return gateway.Manifeste{
		Nom: "youtube", Version: "1.0",
		Capacites: []string{gateway.CapResoudre, gateway.CapTirer},
		AuthKind:  gateway.AuthCookies, // #1048/#1051 : ytsas détient le coffre
		MotifsURL: []string{`(?i)youtube\.com/watch`, `(?i)youtu\.be/`, `(?i)youtube\.com/shorts/`},
	}
}

// Resoudre demande l'état à ytsas et fabrique le Contenu. AU DOUTE, WAN : si
// ytsas est injoignable, on rend quand même la vidéo en pending (embed WAN),
// jamais un échec — l'utilisateur voit sa vidéo.
func (y *YouTube) Resoudre(u string) (gateway.Contenu, error) {
	res, err := y.cl.Resoudre(u)
	etat := res.Etat
	if err != nil || etat == "" || etat == "unsupported" {
		etat = "pending" // ytsas HS ou muet → WAN direct
	}
	c := gateway.Contenu{
		Genre:        gateway.GenreVideo,
		Titre:        res.Titre,
		SourceURL:    u, // failover : jamais jeté
		Connecteur:   "youtube",
		RefNative:    res.VideoID,
		Propriete:    gateway.ProprieteTiers,
		NoeudOrigine: y.noeud,
		Metadonnees: map[string]string{
			"source":   "youtube",
			"video_id": res.VideoID,
			"etat":     etat,
		},
	}
	if etat == "mirror" && res.PeertubeURL != "" {
		c.Repliques = []gateway.Replique{{
			Cible: "peertube", CibleURL: res.PeertubeURL, Mode: gateway.ModeMiroir,
		}}
	}
	if etat == "cache" && res.StreamURL != "" {
		c.Metadonnees["stream_url"] = res.StreamURL
	}
	return c, nil
}

func (y *YouTube) RecupererMedias(gateway.Contenu) ([]gateway.Media, error) { return nil, nil }
func (y *YouTube) Tirer(int64) ([]gateway.Contenu, error)                   { return nil, nil }
func (y *YouTube) Sante() gateway.Sante                                     { return gateway.Sante{Etat: gateway.EtatSain} }
