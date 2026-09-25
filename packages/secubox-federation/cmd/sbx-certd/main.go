// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// sbx-certd — API de la fédération SBX (#1389), sur socket unix.
//
//	GET  /api/federation/status        état MESURÉ (toutes les boxes)
//	GET  /api/federation/ca            clé de la CA (autorité)
//	POST /api/federation/join          demande d'adhésion signée (autorité)
//	GET  /api/federation/join/{did}    certificat émis, ou « en attente » (autorité)
//	POST /api/cert/renew               renouvellement avec preuve de clé (autorité)
//	GET  /api/cert/crl                 liste de révocation signée (autorité)
//
// RIEN ICI N'ÉMET DE SA PROPRE INITIATIVE, sauf `ca.auto_join` explicitement
// posé : une demande reçue attend la décision de l'administrateur
// (`sbxctl cert issue`). Les routes d'écriture n'ont pas besoin de jeton :
// elles exigent une PREUVE — la signature de la clé dont le demandeur réclame
// l'identité.
package main

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-federation/internal/ca"
	"github.com/CyberMind-FR/secubox-deb/secubox-federation/internal/federation"
	"github.com/CyberMind-FR/secubox-deb/secubox-federation/internal/sbxcert"
)

var version = "dev"

type serveur struct {
	ch federation.Chemins
}

func main() {
	socket := flag.String("socket", "/run/secubox/federation.sock", "socket unix d'écoute")
	montre := flag.Bool("version", false, "afficher la version")
	flag.Parse()
	if *montre {
		fmt.Println("sbx-certd", version)
		return
	}
	ch := federation.CheminsParDefaut()
	for env, cible := range map[string]*string{"SBX_FEDERATION_ETAT": &ch.Etat,
		"SBX_FEDERATION_CONFIG": &ch.Config, "SBX_NODE_KEY": &ch.NodeKey, "SBX_CA_KEY": &ch.CAKey} {
		if v := os.Getenv(env); v != "" {
			*cible = v
		}
	}
	s := &serveur{ch: ch}
	os.Remove(*socket)
	l, err := net.Listen("unix", *socket)
	if err != nil {
		log.Fatalf("écoute %s : %v", *socket, err)
	}
	os.Chmod(*socket, 0o660)
	log.Printf("sbx-certd %s — %s", version, *socket)
	srv := &http.Server{Handler: s.routes(), ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(srv.Serve(l))
}

func (s *serveur) routes() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /api/federation/status", s.statut)
	m.HandleFunc("GET /api/federation/ca", s.caPublique)
	m.HandleFunc("POST /api/federation/join", s.adhesion)
	m.HandleFunc("GET /api/federation/join/{did}", s.suiviAdhesion)
	m.HandleFunc("POST /api/cert/renew", s.renouvelle)
	m.HandleFunc("GET /api/cert/crl", s.crl)
	m.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) { ecris(w, 200, map[string]any{"ok": true}) })
	return m
}

func ecris(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func erreur(w http.ResponseWriter, code int, msg string) {
	ecris(w, code, map[string]string{"erreur": msg})
}

func (s *serveur) config() (*federation.Config, error) { return federation.Charge(s.ch.Config) }

// autorite : la CA, si CETTE box l'est. Sinon 404 — une box membre n'émet rien.
func (s *serveur) autorite(w http.ResponseWriter) (*ca.Autorite, *federation.Config, bool) {
	cfg, err := s.config()
	if err != nil {
		erreur(w, 500, err.Error())
		return nil, nil, false
	}
	if cfg.Role != "authority" {
		erreur(w, 404, "cette box n'est pas une autorité de la fédération")
		return nil, nil, false
	}
	a, err := ca.Charge(s.ch.CAKey, s.ch.DirCA(), sbxcert.DID)
	if err != nil {
		erreur(w, 503, err.Error())
		return nil, nil, false
	}
	return a, cfg, true
}

func (s *serveur) statut(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.config()
	if err != nil {
		erreur(w, 500, err.Error())
		return
	}
	caPub, _ := s.ch.CAEpinglee()
	var revoques map[string]bool
	var nDem *int
	if cfg.Role == "authority" {
		if a, err := ca.Charge(s.ch.CAKey, s.ch.DirCA(), sbxcert.DID); err == nil {
			caPub = a.Pub
			if l, err := a.CRL(); err == nil {
				revoques = l.Series()
			}
			if ds, err := a.Demandes(); err == nil {
				n := len(ds)
				nDem = &n
			}
		}
	} else if b, err := os.ReadFile(s.ch.CRL()); err == nil && caPub != nil {
		if l, err := ca.VerifieCRL(b, caPub); err == nil {
			revoques = l.Series()
		}
	}
	// L'identité de la box : sa clé annuaire (le démon tourne en `secubox`,
	// propriétaire de node.key), à défaut le sujet de son certificat.
	boxDID := ""
	if k, err := ca.LitGraine(s.ch.NodeKey); err == nil {
		boxDID = sbxcert.DID(k.Public().(ed25519.PublicKey))
	} else if c, _ := s.ch.CertLocal(); c != nil {
		boxDID = c.BoxID
	}
	st := federation.Construit(cfg, s.ch, caPub, boxDID, revoques, time.Now())
	st.Demandes = nDem
	ecris(w, 200, st)
}

func (s *serveur) caPublique(w http.ResponseWriter, r *http.Request) {
	a, _, ok := s.autorite(w)
	if !ok {
		return
	}
	ecris(w, 200, map[string]string{"did": a.DID, "pubkey": sbxcert.FormatPub(a.Pub)})
}

const tailleMax = 16 << 10

func lit(r *http.Request, v any) error {
	b, err := io.ReadAll(io.LimitReader(r.Body, tailleMax+1))
	if err != nil {
		return err
	}
	if len(b) > tailleMax {
		return errors.New("corps trop grand")
	}
	return json.Unmarshal(b, v)
}

func (s *serveur) adhesion(w http.ResponseWriter, r *http.Request) {
	a, cfg, ok := s.autorite(w)
	if !ok {
		return
	}
	var d ca.Demande
	if err := lit(r, &d); err != nil {
		erreur(w, 400, "demande illisible : "+err.Error())
		return
	}
	if _, ok := cfg.Tiers[d.Tier]; !ok {
		erreur(w, 400, "tier inconnu : "+d.Tier)
		return
	}
	if err := a.Recoit(&d, time.Now()); err != nil {
		erreur(w, 400, err.Error())
		return
	}
	log.Printf("demande d'adhésion : %s (%s, tier %s)", d.BoxID, d.Owner, d.Tier)
	if !cfg.CA.AutoJoin {
		ecris(w, 202, map[string]string{"etat": "en_attente", "box_did": d.BoxID,
			"detail": "l'administrateur de la fédération doit l'accepter (sbxctl cert issue)"})
		return
	}
	t := cfg.Tiers[d.Tier]
	c, err := a.Emet(d.Pubkey, d.Owner, d.Tier, ca.Politique{Channels: t.Channels, Rights: t.Rights}, cfg.CA.DureeJours, time.Now())
	if err != nil {
		erreur(w, 500, err.Error())
		return
	}
	y, _ := c.YAML()
	ecris(w, 201, map[string]string{"etat": "emis", "certificat": string(y)})
}

func (s *serveur) suiviAdhesion(w http.ResponseWriter, r *http.Request) {
	a, _, ok := s.autorite(w)
	if !ok {
		return
	}
	did := r.PathValue("did")
	if !strings.HasPrefix(did, "did:plc:") || len(did) != len("did:plc:")+32 {
		erreur(w, 400, "did:plc attendu")
		return
	}
	if c, err := a.Courant(did); err == nil && c != nil {
		y, _ := c.YAML()
		ecris(w, 200, map[string]string{"etat": "emis", "certificat": string(y)})
		return
	}
	if _, err := a.Demande(did); err == nil {
		ecris(w, 202, map[string]string{"etat": "en_attente"})
		return
	}
	erreur(w, 404, "aucune demande ni certificat pour "+did)
}

func (s *serveur) renouvelle(w http.ResponseWriter, r *http.Request) {
	a, cfg, ok := s.autorite(w)
	if !ok {
		return
	}
	var req ca.Renouvellement
	if err := lit(r, &req); err != nil {
		erreur(w, 400, "requête illisible : "+err.Error())
		return
	}
	c0, err := sbxcert.Lit([]byte(req.Certificat))
	if err != nil {
		erreur(w, 400, err.Error())
		return
	}
	t, ok2 := cfg.Tiers[c0.Tier]
	if !ok2 {
		erreur(w, 409, "le tier "+c0.Tier+" n'existe plus : refaire une adhésion")
		return
	}
	l, err := a.CRL()
	if err != nil {
		erreur(w, 500, err.Error())
		return
	}
	c, err := a.Renouvelle(&req, ca.Politique{Channels: t.Channels, Rights: t.Rights}, cfg.CA.DureeJours, time.Now(), l.Series())
	if err != nil {
		erreur(w, 403, err.Error())
		return
	}
	log.Printf("renouvellement : %s → %s (%s)", c0.Serial, c.Serial, c.BoxID)
	y, _ := c.YAML()
	ecris(w, 200, map[string]string{"etat": "emis", "certificat": string(y)})
}

func (s *serveur) crl(w http.ResponseWriter, r *http.Request) {
	a, _, ok := s.autorite(w)
	if !ok {
		return
	}
	l, err := a.CRL()
	if err != nil {
		erreur(w, 500, err.Error())
		return
	}
	y, _ := l.YAML()
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Write(y)
}
