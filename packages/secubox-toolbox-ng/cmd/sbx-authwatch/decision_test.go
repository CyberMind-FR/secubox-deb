// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// banneurFaux capture les bannissements sans toucher a nft.
type banneurFaux struct{ bannies []string }

func (b *banneurFaux) run(ctx context.Context, args ...string) ([]byte, error) {
	if len(args) > 0 && args[0] == "add" {
		// « add element inet secubox waf_ban { IP timeout Ns } »
		for _, a := range args {
			if strings.HasPrefix(a, "{") {
				b.bannies = append(b.bannies, strings.Fields(strings.Trim(a, "{} "))[0])
			}
		}
	}
	return nil, nil
}

func banneurTest(t *testing.T) (*Banneur, *banneurFaux) {
	t.Helper()
	fx := &banneurFaux{}
	b := NewBanneur("nft", "secubox", "waf_ban", "waf_ban6", time.Hour, false)
	b.exec = fx.run
	return b, fx
}

func journalTest(t *testing.T) (*JournalMenaces, string) {
	t.Helper()
	chemin := filepath.Join(t.TempDir(), "threats.log")
	return NewJournalMenaces(chemin), chemin
}

func lignesJournal(t *testing.T, chemin string) []map[string]any {
	t.Helper()
	data, err := os.ReadFile(chemin)
	if err != nil {
		return nil
	}
	var out []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if l == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("ligne de journal illisible : %v", err)
		}
		out = append(out, m)
	}
	return out
}

// Un leurre est un signal CERTAIN : bannissement au premier contact, sans
// attendre la repetition. C'est toute la difference avec l'analyse de journaux.
func TestLeurreBannitDesLePremierContact(t *testing.T) {
	b, fx := banneurTest(t)
	j, chemin := journalTest(t)
	lb, _ := NewListeBlanche("")
	sig := Signal{IP: "203.0.113.5", Service: "rdp", Categorie: "leurre:rdp",
		Severite: "high", Detail: "connexion sur un service inexistant (port 3389)"}

	ctx, annule := context.WithCancel(context.Background())
	signaux := make(chan Signal, 1)
	signaux <- sig
	go traite(ctx, signaux, NewCompteur(time.Minute, 99, time.Minute), nil, b, j, lb, false)
	time.Sleep(80 * time.Millisecond)
	annule()

	if len(fx.bannies) != 1 || fx.bannies[0] != "203.0.113.5" {
		t.Fatalf("le leurre doit bannir immediatement, obtenu %v", fx.bannies)
	}
	lignes := lignesJournal(t, chemin)
	if len(lignes) != 1 || lignes[0]["action"] != "banned" {
		t.Fatalf("journal attendu action=banned, obtenu %v", lignes)
	}
	if lignes[0]["host"] != "rdp" || lignes[0]["tool"] != "authwatch" {
		t.Errorf("le journal doit porter le service et l'outil : %v", lignes[0])
	}
}

// L'analyse de journaux est PATIENTE : un echec isole ne bannit pas.
func TestJournalAttendLaRepetition(t *testing.T) {
	b, fx := banneurTest(t)
	j, chemin := journalTest(t)
	lb, _ := NewListeBlanche("")
	ctx, annule := context.WithCancel(context.Background())
	signaux := make(chan Signal, 8)
	sig := Signal{IP: "203.0.113.6", Service: "smtp", Categorie: "auth_smtp:sasl_failed",
		Severite: "high", Detail: "authentification SASL refusee"}
	signaux <- sig // poids 2, seuil 6 : insuffisant
	go traite(ctx, signaux, NewCompteur(time.Minute, 6, time.Minute), nil, b, j, lb, false)
	time.Sleep(80 * time.Millisecond)

	if len(fx.bannies) != 0 {
		t.Fatalf("un echec isole ne doit pas bannir, obtenu %v", fx.bannies)
	}
	if l := lignesJournal(t, chemin); len(l) != 1 || l[0]["action"] != "warning" {
		t.Fatalf("l'echec doit etre journalise en warning, obtenu %v", l)
	}
	// Deux de plus (2+2+2 = 6) franchissent le seuil.
	signaux <- sig
	signaux <- sig
	time.Sleep(120 * time.Millisecond)
	annule()
	if len(fx.bannies) != 1 || fx.bannies[0] != "203.0.113.6" {
		t.Fatalf("le seuil franchi doit bannir, obtenu %v", fx.bannies)
	}
}

// La liste blanche est une piece de securite : jamais de bannissement, mais
// une trace — « pourquoi cette adresse passe-t-elle toujours ? » doit avoir
// une reponse dans le journal.
func TestListeBlancheJamaisBannieMaisTracee(t *testing.T) {
	b, fx := banneurTest(t)
	j, chemin := journalTest(t)
	lb, _ := NewListeBlanche("203.0.113.7")
	ctx, annule := context.WithCancel(context.Background())
	signaux := make(chan Signal, 4)
	for i := 0; i < 3; i++ {
		signaux <- Signal{IP: "203.0.113.7", Service: "rdp", Categorie: "leurre:rdp",
			Severite: "high", Detail: "leurre"}
	}
	go traite(ctx, signaux, NewCompteur(time.Minute, 1, time.Minute), nil, b, j, lb, false)
	time.Sleep(120 * time.Millisecond)
	annule()

	if len(fx.bannies) != 0 {
		t.Fatalf("une adresse en liste blanche ne doit JAMAIS etre bannie, obtenu %v", fx.bannies)
	}
	lignes := lignesJournal(t, chemin)
	if len(lignes) != 3 {
		t.Fatalf("les tentatives doivent rester tracees, %d ligne(s)", len(lignes))
	}
	if lignes[0]["action"] != "detect" {
		t.Errorf("action attendue detect, obtenu %v", lignes[0]["action"])
	}
}

// En simulation, on detecte et on journalise, mais on ne touche jamais a nft.
func TestSimulationNeBannitJamais(t *testing.T) {
	b, fx := banneurTest(t)
	j, chemin := journalTest(t)
	lb, _ := NewListeBlanche("")
	ctx, annule := context.WithCancel(context.Background())
	signaux := make(chan Signal, 1)
	signaux <- Signal{IP: "203.0.113.8", Service: "vnc", Categorie: "leurre:vnc",
		Severite: "high", Detail: "leurre"}
	go traite(ctx, signaux, NewCompteur(time.Minute, 1, time.Minute), nil, b, j, lb, true)
	time.Sleep(80 * time.Millisecond)
	annule()

	if len(fx.bannies) != 0 {
		t.Fatalf("la simulation ne doit rien bannir, obtenu %v", fx.bannies)
	}
	if l := lignesJournal(t, chemin); len(l) != 1 || l[0]["action"] != "detect" {
		t.Fatalf("la simulation doit journaliser en detect, obtenu %v", l)
	}
}

// Le garde-fou du dernier moment : une adresse privee n'entre jamais dans le set.
func TestAdressePriveeRefuseeParLeBanneur(t *testing.T) {
	b, fx := banneurTest(t)
	for _, ip := range []string{"192.168.1.10", "10.100.0.40", "127.0.0.1", "172.16.0.5"} {
		if err := b.Bannit(context.Background(), ip); err == nil {
			t.Errorf("%s aurait du etre refusee", ip)
		}
	}
	if len(fx.bannies) != 0 {
		t.Fatalf("aucune commande nft ne doit partir, obtenu %v", fx.bannies)
	}
}
