// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func ecrireFiltres(t *testing.T, contenu string) string {
	t.Helper()
	f := filepath.Join(t.TempDir(), "services.json")
	if err := os.WriteFile(f, []byte(contenu), 0o644); err != nil {
		t.Fatal(err)
	}
	return f
}

// Les lignes ci-dessous sont PRELEVEES sur gk2, comme pour les motifs
// universels : un filtre valide contre une ligne inventee ne prouve rien.
func TestFiltresSurLignesReelles(t *testing.T) {
	f, err := ChargerFiltres(ecrireFiltres(t, `{"services":[
      {"id":"gitea","journal":"/tmp/j","motifs":[
        {"motif":"sshConnectionFailed.*Failed authentication attempt from\\s+(?P<ip>[0-9a-f.:]+):[0-9]+",
         "categorie":"auth_gitea:ssh_failed","severite":"high","detail":"clé SSH refusée"}]},
      {"id":"nextcloud","fichier":"/tmp/nc.log","motifs":[
        {"motif":"Login failed:\\s*'?(?P<cible>[^'()]*?)'?\\s*\\(Remote IP:\\s*'?(?P<ip>[0-9a-f.:]+)'?\\)",
         "categorie":"auth_nextcloud:login_failed","severite":"medium","detail":"connexion refusée"}]}]}`))
	if err != nil {
		t.Fatalf("chargement : %v", err)
	}
	if f.Nombre() != 2 {
		t.Fatalf("2 services attendus, %d chargés (%v)", f.Nombre(), f.Avertissements())
	}

	sig, ok := f.Reconnaitre("gitea[1]: modules/ssh/ssh.go:327:sshConnectionFailed() [W] Failed authentication attempt from 100.23.108.63:50784")
	if !ok || sig.IP != "100.23.108.63" || sig.Categorie != "auth_gitea:ssh_failed" {
		t.Fatalf("gitea : obtenu %+v", sig)
	}

	// Les DEUX formes réellement écrites par nextcloud.
	for _, cas := range []struct{ ligne, ip, cible string }{
		{`{"message":"Login failed: 'admin' (Remote IP: '203.0.113.9')"}`, "203.0.113.9", "admin"},
		{`{"message":"Login failed: gk2 (Remote IP: 198.51.100.7)"}`, "198.51.100.7", "gk2"},
	} {
		sig, ok := f.Reconnaitre(cas.ligne)
		if !ok || sig.IP != cas.ip || sig.Cible != cas.cible {
			t.Errorf("nextcloud %q : obtenu %+v", cas.ligne, sig)
		}
	}
}

// Un motif fautif ne doit pas condamner les autres : abandonner tout le fichier
// pour une virgule priverait de couverture des services bien declares.
func TestMotifFautifNeCondamnePasLeReste(t *testing.T) {
	f, err := ChargerFiltres(ecrireFiltres(t, `{"services":[
      {"id":"cassé","journal":"/tmp/j","motifs":[{"motif":"(?P<ip>[","categorie":"x"}]},
      {"id":"bon","journal":"/tmp/j","motifs":[{"motif":"echec depuis (?P<ip>[0-9.]+)","categorie":"auth_bon:failed"}]}]}`))
	if err != nil {
		t.Fatalf("un motif invalide ne doit pas faire echouer le chargement : %v", err)
	}
	if f.Nombre() != 1 {
		t.Fatalf("le service valide doit rester, %d charge(s)", f.Nombre())
	}
	if len(f.Avertissements()) == 0 {
		t.Error("le refus doit être DIT : silencieux, il ferait croire à une couverture")
	}
	if _, ok := f.Reconnaitre("echec depuis 203.0.113.1"); !ok {
		t.Error("le service valide doit reconnaître ses lignes")
	}
}

// Un motif qui ne capture pas l'adresse est inutilisable : sans elle, il n'y a
// personne a bannir. Il doit etre refuse au chargement, pas au premier usage.
func TestMotifSansAdresseRefuse(t *testing.T) {
	f, _ := ChargerFiltres(ecrireFiltres(t, `{"services":[
      {"id":"x","journal":"/tmp/j","motifs":[{"motif":"echec de connexion","categorie":"auth_x:failed"}]}]}`))
	if f.Nombre() != 0 {
		t.Fatal("un motif sans (?P<ip>…) ne doit pas etre retenu")
	}
}

func TestServiceInactifIgnore(t *testing.T) {
	f, _ := ChargerFiltres(ecrireFiltres(t, `{"services":[
      {"id":"dormant","journal":"/tmp/j","actif":false,"motifs":[
        {"motif":"x (?P<ip>[0-9.]+)","categorie":"auth_dormant:failed"}]}]}`))
	if f.Nombre() != 0 {
		t.Fatal("un service declare inactif ne doit pas etre charge")
	}
}

func TestFichierAbsentToleré(t *testing.T) {
	f, err := ChargerFiltres(filepath.Join(t.TempDir(), "nulle-part.json"))
	if err != nil {
		t.Fatalf("un fichier absent ne doit pas echouer : %v", err)
	}
	if f.Nombre() != 0 {
		t.Fatal("aucun service attendu")
	}
}

func TestSourcesJournalEtFichier(t *testing.T) {
	f, _ := ChargerFiltres(ecrireFiltres(t, `{"services":[
      {"id":"a","journal":"/rep/j","motifs":[{"motif":"(?P<ip>[0-9.]+)","categorie":"c"}]},
      {"id":"b","fichier":"/var/x.log","motifs":[{"motif":"(?P<ip>[0-9.]+)","categorie":"c"}]}]}`))
	src := f.Sources()
	if len(src) != 2 {
		t.Fatalf("2 sources attendues, %d", len(src))
	}
	if src[0].Repertoire != "/rep/j" || src[1].Fichier != "/var/x.log" {
		t.Fatalf("sources mal formées : %+v", src)
	}
}

func TestCapturePasUneAdresseIgnoree(t *testing.T) {
	f, _ := ChargerFiltres(ecrireFiltres(t, `{"services":[
      {"id":"x","journal":"/tmp/j","motifs":[
        {"motif":"echec pour (?P<ip>\\S+)","categorie":"auth_x:failed"}]}]}`))
	if _, ok := f.Reconnaitre("echec pour pas-une-adresse"); ok {
		t.Error("une capture non-IP ne doit pas produire de signal")
	}
	if _, ok := f.Reconnaitre("echec pour 203.0.113.4"); !ok {
		t.Error("une vraie adresse doit passer")
	}
}

// Une configuration qui ne surveille que des FICHIERS declares n'a aucune
// source journald : la specification vide doit etre acceptee, sinon le service
// refuse de demarrer sur une configuration parfaitement valable.
func TestSpecificationDeJournauxVideAcceptee(t *testing.T) {
	src, err := analyseSources("")
	if err != nil {
		t.Fatalf("une spécification vide doit être acceptée : %v", err)
	}
	if len(src) != 0 {
		t.Fatalf("aucune source attendue, %d", len(src))
	}
	// Une spécification NON vide mais fautive reste une erreur.
	if _, err := analyseSources("n-importe-quoi"); err == nil {
		t.Error("une spécification fautive doit rester refusée")
	}
}
