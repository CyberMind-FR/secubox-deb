// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// App Store fédéré (#1391) :
//
//	GET  /api/appstore/catalog[?type=metablog]   objets, éditeur re-vérifié, canal comparé au certificat
//	GET  /api/appstore/object/{id}                une fiche
//	GET  /api/appstore/object/{id}/sbx            le paquet signé
//	POST /api/appstore/install {id, nom}          ADMIN — installe, jamais par-dessus, non publié
package main

import (
	"context"
	"crypto/ed25519"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-federation/internal/ca"
	"github.com/CyberMind-FR/secubox-deb/secubox-federation/internal/sbxcert"
	"github.com/CyberMind-FR/secubox-deb/secubox-federation/internal/sbxobj"
)

func (s *serveur) routesAppStore(m *http.ServeMux) {
	m.HandleFunc("GET /api/appstore/catalog", s.catalogue)
	m.HandleFunc("GET /api/appstore/object/{id}", s.fiche)
	m.HandleFunc("GET /api/appstore/object/{id}/sbx", s.paquetBrut)
	m.HandleFunc("POST /api/appstore/install", s.installe)
}

// clesCA : la CA qui fait foi ici (la sienne pour l'autorité, épinglée sinon).
func (s *serveur) clesCA() (ed25519.PublicKey, map[string]bool) {
	if cfg, err := s.config(); err == nil && cfg.Role == "authority" {
		if a, err := ca.Charge(s.ch.CAKey, s.ch.DirCA(), sbxcert.DID); err == nil {
			if l, err := a.CRL(); err == nil {
				return a.Pub, l.Series()
			}
			return a.Pub, nil
		}
	}
	caPub, _ := s.ch.CAEpinglee()
	if caPub == nil {
		return nil, nil
	}
	if b, err := os.ReadFile(s.ch.CRL()); err == nil {
		if l, err := ca.VerifieCRL(b, caPub); err == nil {
			return caPub, l.Series()
		}
	}
	return caPub, nil
}

func (s *serveur) cat() sbxobj.Catalogue {
	cfg, _ := s.config()
	return sbxobj.Catalogue{Dir: s.ch.ObjetsDe(cfg)}
}

func (s *serveur) catalogue(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.config()
	if err != nil {
		erreur(w, 500, err.Error())
		return
	}
	caPub, rev, canaux := s.ch.Confiance(cfg, s.clesCA)
	es, err := s.cat().Liste(r.URL.Query().Get("type"), caPub, rev, canaux, time.Now())
	if err != nil {
		erreur(w, 500, err.Error())
		return
	}
	for i := range es {
		es[i].Fichier = ""
	}
	ecris(w, 200, map[string]any{"objets": es, "types": sbxobj.Types, "canaux_ouverts": canaux})
}

func (s *serveur) fiche(w http.ResponseWriter, r *http.Request) {
	e, _, err := s.cat().Trouve(r.PathValue("id"))
	if err != nil {
		erreur(w, 404, err.Error())
		return
	}
	e.Fichier, e.Certificat = "", ""
	ecris(w, 200, e)
}

func (s *serveur) paquetBrut(w http.ResponseWriter, r *http.Request) {
	e, chemin, err := s.cat().Trouve(r.PathValue("id"))
	if err != nil {
		erreur(w, 404, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+e.Name+"-"+e.Version+`.sbx"`)
	http.ServeFile(w, r, chemin)
}

// ── Installation : réservée à un administrateur confirmé par secubox-auth ────

const authSock = "/run/secubox/auth.sock"

func admin(r *http.Request) (string, bool) {
	jeton := ""
	if a := r.Header.Get("Authorization"); strings.HasPrefix(a, "Bearer ") {
		jeton = strings.TrimPrefix(a, "Bearer ")
	} else if c, err := r.Cookie("secubox_session"); err == nil {
		jeton = c.Value
	}
	if jeton == "" {
		return "", false
	}
	cl := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", authSock)
		}}}
	req, _ := http.NewRequest("GET", "http://auth/auth/verify", nil)
	req.Header.Set("Authorization", "Bearer "+jeton)
	rep, err := cl.Do(req)
	if err != nil {
		return "", false
	}
	defer rep.Body.Close()
	u := rep.Header.Get("Remote-User")
	return u, rep.StatusCode == 200 && u != "" && rep.Header.Get("Remote-Groups") == "admin"
}

func (s *serveur) installe(w http.ResponseWriter, r *http.Request) {
	qui, ok := admin(r)
	if !ok {
		erreur(w, 403, "réservé aux administrateurs")
		return
	}
	var c struct {
		ID  string `json:"id"`
		Nom string `json:"nom"`
	}
	if err := lit(r, &c); err != nil {
		erreur(w, 400, "requête illisible")
		return
	}
	_, chemin, err := s.cat().Trouve(c.ID)
	if err != nil {
		erreur(w, 404, err.Error())
		return
	}
	caPub, rev := s.clesCA()
	p, err := sbxobj.Ouvre(chemin, caPub, rev, time.Now())
	if err != nil {
		erreur(w, 422, "paquet refusé : "+err.Error())
		return
	}
	defer p.Ferme()
	// DEPUIS L'INTERFACE, PAS D'EXCEPTION : un éditeur non certifié ne
	// s'installe qu'en ligne de commande, en le disant (--accepte-non-certifie).
	if !p.Certifie {
		erreur(w, 403, "éditeur non certifié : "+p.Motif)
		return
	}
	nom := c.Nom
	if nom == "" {
		nom = p.Objet.Name
	}
	dossier, err := p.Installe(s.ch.Sites, nom, time.Now())
	if err != nil {
		erreur(w, 409, err.Error())
		return
	}
	logf("installation : %s@%s → %s (par %s)", p.Objet.ID, p.Objet.Version, dossier, qui)
	ecris(w, 201, map[string]string{"ok": "installé", "nom": nom, "dossier": dossier,
		"suite": "non publié — le publier depuis le metablogizer (/metablogizer/)"})
}
