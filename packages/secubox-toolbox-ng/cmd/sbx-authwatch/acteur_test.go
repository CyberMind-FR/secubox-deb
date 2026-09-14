// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

package main

import (
	"bufio"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ecoute ouvre une socket unix jouant le rôle de sbx-actord et rend le canal des
// enveloppes reçues. Le test vaut ainsi pour le CHEMIN COMPLET — construction,
// sérialisation, écriture — et pas seulement pour l'intention du code.
func ecoute(t *testing.T) (string, <-chan map[string]any) {
	t.Helper()
	chemin := filepath.Join(t.TempDir(), "actord.sock")
	ln, err := net.Listen("unix", chemin)
	if err != nil {
		t.Fatalf("socket d'essai : %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	recu := make(chan map[string]any, 8)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				s := bufio.NewScanner(c)
				for s.Scan() {
					var m map[string]any
					if json.Unmarshal(s.Bytes(), &m) == nil {
						recu <- m
					}
				}
			}(c)
		}
	}()
	return chemin, recu
}

func attend(t *testing.T, c <-chan map[string]any) map[string]any {
	t.Helper()
	select {
	case m := <-c:
		return m
	case <-time.After(3 * time.Second):
		t.Fatal("aucune enveloppe reçue : l'émission ne part pas")
		return nil
	}
}

func TestActeur_EmetUneEnveloppeParSignal(t *testing.T) {
	chemin, recu := ecoute(t)
	a := NewActeur(chemin, filepath.Join(t.TempDir(), "absent"))
	if a == nil {
		t.Fatal("émission désactivée alors qu'une socket est fournie")
	}
	defer a.Close()

	a.Emet(Signal{IP: "203.0.113.7", Service: "ssh", Categorie: "leurre:vnc",
		Severite: "high", Cible: "root"}, true)

	m := attend(t, recu)
	if m["src_ip"] != "203.0.113.7" {
		t.Errorf("src_ip = %v", m["src_ip"])
	}
	if m["sensor"] != "authwatch" {
		t.Errorf("sensor = %v : la couche n'est pas identifiée", m["sensor"])
	}
	if m["action"] != "block" {
		t.Errorf("action = %v : la sanction doit se distinguer de l'observation", m["action"])
	}
}

func TestActeur_LeCompteViseNePartJamaisEnClair(t *testing.T) {
	chemin, recu := ecoute(t)
	secret := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secret, []byte("un-secret-local-de-test"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := NewActeur(chemin, secret)
	defer a.Close()

	a.Emet(Signal{IP: "203.0.113.8", Service: "smtp", Severite: "medium",
		Cible: "facture@exemple.fr"}, false)

	m := attend(t, recu)
	h, _ := m["credential_token_hash"].(string)
	if h == "" {
		t.Fatal("le compte visé n'est pas transmis : l'axe le plus lourd du barème reste mort")
	}
	if h == "facture@exemple.fr" {
		t.Fatal("le compte visé part EN CLAIR")
	}
	for k, v := range m {
		if s, ok := v.(string); ok && s == "facture@exemple.fr" {
			t.Fatalf("le compte visé apparaît en clair dans le champ %q", k)
		}
	}
}

func TestActeur_SansSecretOnPerdLAxePasLaCouche(t *testing.T) {
	// Un secret illisible ne doit pas faire taire le capteur : l'IP, le service
	// et la gravité valent déjà mieux que rien.
	chemin, recu := ecoute(t)
	a := NewActeur(chemin, "/inexistant/secret")
	defer a.Close()

	a.Emet(Signal{IP: "203.0.113.9", Service: "imap", Severite: "high", Cible: "root"}, false)

	m := attend(t, recu)
	if m["src_ip"] != "203.0.113.9" {
		t.Errorf("src_ip = %v", m["src_ip"])
	}
	if h, _ := m["credential_token_hash"].(string); h != "" {
		t.Error("un condensé a été produit sans secret")
	}
}

func TestActeur_SocketVideDesactiveSansPaniquer(t *testing.T) {
	a := NewActeur("", "")
	if a != nil {
		t.Fatal("socket vide devrait désactiver l'émission")
	}
	a.Emet(Signal{IP: "203.0.113.10"}, false) // ne doit pas paniquer sur nil
	a.Close()
}
