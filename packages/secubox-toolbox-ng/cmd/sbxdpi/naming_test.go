// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// nommeurNu : un nommeur sans aucune source déduite, pour tester la priorité
// sans dépendre de la machine qui fait tourner les tests (table ARP, adresses
// d'interfaces et base OUI varient d'un hôte à l'autre).
func nommeurNu(t *testing.T) *nommeur {
	t.Helper()
	return &nommeur{
		alias:   map[string]string{},
		soi:     map[string]bool{},
		observe: map[string]string{},
		voisins: map[string]string{},
		ptr:     map[string]string{},
		file:    make(chan string, ptrFileCap),
	}
}

// L'ORDRE DE PRIORITÉ EST UN CONTRAT. Un alias posé par l'opérateur doit battre
// tout ce que la box déduit : c'est le seul nom dont elle est sûre.
func TestNommePriorite(t *testing.T) {
	n := nommeurNu(t)
	n.alias["10.0.0.1"] = "la passerelle"
	n.soi["10.0.0.1"] = true
	n.observe["10.0.0.1"] = "observé.example"
	n.voisins["10.0.0.1"] = "Marque"

	if got := n.Nomme("10.0.0.1"); got.Nom != "la passerelle" || got.Source != "alias" {
		t.Fatalf("l'alias doit gagner, obtenu %+v", got)
	}

	delete(n.alias, "10.0.0.1")
	if got := n.Nomme("10.0.0.1"); got.Nom != "cette box" || got.Portee != "soi" {
		t.Fatalf("la box doit se reconnaître, obtenu %+v", got)
	}

	delete(n.soi, "10.0.0.1")
	if got := n.Nomme("10.0.0.1"); got.Nom != "observé.example" || got.Source != "observé" {
		t.Fatalf("le nom observé doit gagner sur le voisinage, obtenu %+v", got)
	}

	delete(n.observe, "10.0.0.1")
	// Le constructeur seul ne distingue pas deux appareils de la même marque :
	// le dernier octet est ce qui les sépare.
	if got := n.Nomme("10.0.0.1"); got.Nom != "Marque ·1" || got.Source != "voisin" {
		t.Fatalf("le voisin doit porter le dernier octet, obtenu %+v", got)
	}
}

// LE NOM OBSERVÉ BAT LE DNS INVERSE. Le PTR nomme le propriétaire de l'adresse,
// le SNI nomme ce que l'utilisateur voulait joindre — c'est le second qu'il
// reconnaît dans un tableau.
func TestObserveBatPTR(t *testing.T) {
	n := nommeurNu(t)
	n.ptr["82.67.100.75"] = "maegia.hd.free.fr"
	n.observe["82.67.100.75"] = "www.maegia.tv"
	if got := n.Nomme("82.67.100.75"); got.Nom != "www.maegia.tv" {
		t.Fatalf("le SNI doit primer sur le PTR, obtenu %+v", got)
	}
}

// UNE ADRESSE PRIVÉE N'EST JAMAIS SOUMISE À UN RÉSOLVEUR EXTERNE : lui demander
// le nom de 192.168.1.61 lui décrirait le plan du réseau interne, et n'obtiendrait
// rien en retour.
func TestPasDePTRSurPrive(t *testing.T) {
	n := nommeurNu(t)
	id := n.Nomme("192.168.1.61")
	if id.Nom != "192.168.1.61" || id.Portee != "local" {
		t.Fatalf("une adresse privée inconnue se rend telle quelle, obtenu %+v", id)
	}
	if len(n.file) != 0 {
		t.Fatalf("une adresse privée ne doit PAS être mise en file de résolution")
	}
	// Une adresse publique inconnue, elle, part en file.
	n.Nomme("1.2.3.4")
	if len(n.file) != 1 {
		t.Fatalf("une adresse publique inconnue doit être mise en file, file=%d", len(n.file))
	}
}

// UN ÉCHEC DE RÉSOLUTION EST MÉMORISÉ. Sans cela, une adresse sans PTR serait
// redemandée à chaque snapshot — une requête sortante par minute et par adresse.
func TestEchecPTRMemorise(t *testing.T) {
	n := nommeurNu(t)
	n.ptr["1.2.3.4"] = "" // résolu, sans résultat
	n.Nomme("1.2.3.4")
	if len(n.file) != 0 {
		t.Fatalf("un échec déjà connu ne doit pas être redemandé")
	}
}

func TestAbrege(t *testing.T) {
	cas := map[string]string{
		"Apple, Inc.":                 "Apple",
		"Samsung Electronics Co.,Ltd": "Samsung",
		"Espressif Inc.":              "Espressif",
		"Freebox SAS":                 "Freebox SAS",
	}
	for entree, veut := range cas {
		if got := abrege(entree); got != veut {
			t.Errorf("abrege(%q) = %q, veut %q", entree, got, veut)
		}
	}
}

func TestRelitAlias(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "ip-names.json")
	os.WriteFile(f, []byte(`{"__doc__":"documentation","10.0.0.9":"NAS","10.0.0.8":""}`), 0o644)
	n := &nommeur{alias: map[string]string{}, soi: map[string]bool{},
		observe: map[string]string{}, voisins: map[string]string{},
		ptr: map[string]string{}, aliasPath: f, file: make(chan string, 4)}
	n.relitAlias()
	if n.alias["10.0.0.9"] != "NAS" {
		t.Fatalf("alias non chargé : %+v", n.alias)
	}
	// Les clés de documentation et les valeurs vides ne sont pas des noms.
	if _, y := n.alias["__doc__"]; y {
		t.Error("la clé de documentation ne doit pas devenir un alias")
	}
	if _, y := n.alias["10.0.0.8"]; y {
		t.Error("un alias vide ne doit pas masquer les sources déduites")
	}
	// Fichier illisible → on garde ce qu'on avait, sans erreur.
	os.WriteFile(f, []byte("{ceci n'est pas du JSON"), 0o644)
	n.aliasMtime = 0
	n.relitAlias()
	if n.alias["10.0.0.9"] != "NAS" {
		t.Error("un fichier corrompu ne doit pas effacer les alias en place")
	}
}

func TestCoupeTalker(t *testing.T) {
	src, dst, ok := coupeTalker("192.168.1.254 → 192.168.1.200")
	if !ok || src != "192.168.1.254" || dst != "192.168.1.200" {
		t.Fatalf("coupe = %q / %q / %v", src, dst, ok)
	}
	if _, _, ok := coupeTalker("pas de flèche"); ok {
		t.Error("une clé sans séparateur ne se coupe pas")
	}
}

// LA RÉGRESSION DE #1342, VERROUILLÉE. Le snapshot écrivait hosts, ports,
// fingerprints et les octets directionnels ; le chargement ne les relisait pas.
// À chaque redémarrage, les détails d'appareils repartaient de zéro alors que
// la donnée était sur le disque, juste à côté de celle qu'on restaurait.
func TestSnapshotRestaureTout(t *testing.T) {
	a := newAggregator()
	a.nom = nommeurNu(t)
	a.totalFlows, a.totalBytes = 10, 4096
	a.outBytes, a.inBytes = 3000, 1096
	bump(a.hosts, "www.maegia.tv", 3, 2048)
	bump(a.ports, "443", 7, 4096)
	bump(a.fps, "t13d1516h2_8daaf6152771_b186095e22b6", 4, 1024)
	bump(a.talkers, "192.168.1.61"+sepTalker+"82.67.100.75", 3, 2048)
	a.nom.Observe("82.67.100.75", "www.maegia.tv")

	chemin := filepath.Join(t.TempDir(), "stats.json")
	a.writeSnapshot(chemin)

	b := newAggregator()
	b.nom = nommeurNu(t)
	b.loadSnapshot(chemin)

	for nom, got := range map[string]int{
		"hosts": len(b.hosts), "ports": len(b.ports),
		"fingerprints": len(b.fps), "talkers": len(b.talkers),
	} {
		if got == 0 {
			t.Errorf("%s perdu au rechargement — c'est exactement le bug de #1342", nom)
		}
	}
	if b.outBytes != 3000 || b.inBytes != 1096 {
		t.Errorf("octets directionnels perdus : out=%d in=%d", b.outBytes, b.inBytes)
	}
	// Le nom observé revient AVEC les talkers : sans cela, une conversation
	// reprise resterait anonyme jusqu'à ce que le même flux repasse.
	if id := b.nom.Nomme("82.67.100.75"); id.Nom != "www.maegia.tv" {
		t.Errorf("nom observé perdu au rechargement : %+v", id)
	}
}

// UN SNAPSHOT D'AVANT #1342 SE RELIT SANS TRANSITION : les talkers y sont des
// `kv` nus, sans identités. L'embarquement de `kv` dans `talkerKV` garde les
// champs à plat, donc l'ancien document reste lisible.
func TestSnapshotAncienFormat(t *testing.T) {
	ancien := map[string]any{
		"total_flows": 5, "total_bytes": 100,
		"talkers": []map[string]any{{"name": "a" + sepTalker + "b", "flows": 2, "bytes": 50}},
	}
	buf, _ := json.Marshal(ancien)
	chemin := filepath.Join(t.TempDir(), "vieux.json")
	os.WriteFile(chemin, buf, 0o644)

	a := newAggregator()
	a.nom = nommeurNu(t)
	a.loadSnapshot(chemin)
	if len(a.talkers) != 1 {
		t.Fatalf("ancien snapshot illisible : talkers=%d", len(a.talkers))
	}
	if c := a.talkers["a"+sepTalker+"b"]; c == nil || c.Bytes != 50 {
		t.Fatalf("compteur mal repris : %+v", c)
	}
}

// Les talkers sortent nommés des DEUX côtés, et chaque nom dit sa source.
func TestRankTalkersNomme(t *testing.T) {
	a := newAggregator()
	a.nom = nommeurNu(t)
	a.nom.alias["192.168.1.61"] = "le portable"
	a.nom.observe["82.67.100.75"] = "www.maegia.tv"
	bump(a.talkers, "192.168.1.61"+sepTalker+"82.67.100.75", 1, 1000)

	out := a.rankTalkers(1000, 1)
	if len(out) != 1 {
		t.Fatalf("attendu 1 talker, obtenu %d", len(out))
	}
	if out[0].Src.Nom != "le portable" || out[0].Src.Source != "alias" {
		t.Errorf("source mal nommée : %+v", out[0].Src)
	}
	if out[0].Dst.Nom != "www.maegia.tv" || out[0].Dst.Source != "observé" {
		t.Errorf("destination mal nommée : %+v", out[0].Dst)
	}
	// La clé brute reste disponible : l'adresse est la vérité, le nom est un
	// confort de lecture, et une enquête a besoin de l'adresse.
	if out[0].Name != "192.168.1.61"+sepTalker+"82.67.100.75" {
		t.Errorf("la clé brute doit être conservée, obtenu %q", out[0].Name)
	}
}
