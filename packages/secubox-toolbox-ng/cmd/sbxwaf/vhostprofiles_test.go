// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
package main

import "testing"

// Phase G (#1080) : une signature de scan est une ATTAQUE hors du vhost qui
// possède le chemin, mais LÉGITIME à l'intérieur du service qui le sert. Le
// profil par service déclare les chemins légitimes ; la suppression est
// scopée au vhost et ne touche QUE les catégories de reconnaissance.
const profilsTest = `{
  "services": {
    "gitea": { "legit_paths": [
      "^/[^/]+/[^/]+(\\.git)?/(info/refs|git-upload-pack|git-receive-pack|HEAD|objects/)",
      "^/api/v1/",
      "^/\\.well-known/"
    ] },
    "nextcloud": { "legit_paths": [
      "^/remote\\.php/",
      "^/\\.well-known/",
      "^/settings/"
    ] }
  },
  "vhosts": {
    "gitea.gk2.secubox.in": "gitea",
    "git.gk2.secubox.in": "gitea",
    "nc.gk2.secubox.in": "nextcloud"
  },
  "suppress_categories": ["scanners", "recon_crawler", "product_absent_probes"]
}`

func profilsDepuisTest(t *testing.T) *VhostProfiles {
	t.Helper()
	vp, err := chargerVhostProfilesDepuis([]byte(profilsTest))
	if err != nil {
		t.Fatalf("chargement des profils : %v", err)
	}
	return vp
}

func TestDoitSupprimer(t *testing.T) {
	vp := profilsDepuisTest(t)
	cas := []struct {
		nom, host, chemin, cat string
		want                   bool
	}{
		// Clone git réel chez gitea : le chemin contient .git/ mais c'est du
		// smart-http légitime → la catégorie scanners est supprimée POUR gitea.
		{"git clone légitime chez gitea", "gitea.gk2.secubox.in",
			"/gandalf/secubox.git/info/refs", "scanners", true},
		{"alias git.gk2 = gitea", "git.gk2.secubox.in",
			"/gandalf/secubox.git/git-upload-pack", "scanners", true},
		// Host normalisé (port présent).
		{"host avec port", "gitea.gk2.secubox.in:443",
			"/api/v1/repos/x", "scanners", true},
		// .well-known légitime dans nextcloud (caldav/webfinger).
		{"well-known chez nextcloud", "nc.gk2.secubox.in",
			"/.well-known/carddav", "recon_crawler", true},
		// MÊME chemin de sonde hors du service : PAS supprimé (attaque).
		{"dotfile probe hors service", "static.exemple.fr",
			"/.git/config", "scanners", false},
		{"actuator hors service", "vitrine.gk2.secubox.in",
			"/actuator/env", "scanners", false},
		// Chemin NON légitime À L'INTÉRIEUR du service : PAS supprimé.
		{"sonde wp-login dans gitea", "gitea.gk2.secubox.in",
			"/wp-login.php", "scanners", false},
		{"dotfile racine dans gitea (pas smart-http)", "gitea.gk2.secubox.in",
			"/.git/config", "scanners", false},
		// Catégorie NON supprimable (injection) : jamais supprimée, même sur
		// un chemin légitime du service.
		{"sqli sur chemin légitime jamais supprimée", "gitea.gk2.secubox.in",
			"/gandalf/secubox.git/info/refs", "sqli", false},
		// Host totalement inconnu : comportement Phase F inchangé.
		{"host inconnu", "rando.example", "/.well-known/security.txt",
			"recon_crawler", false},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			if got := vp.doitSupprimer(c.host, c.chemin, c.cat); got != c.want {
				t.Fatalf("doitSupprimer(%q,%q,%q)=%v ; attendu %v",
					c.host, c.chemin, c.cat, got, c.want)
			}
		})
	}
}

func TestDoitSupprimerNilSansPanique(t *testing.T) {
	// Sans profils chargés (--vhost-profiles absent), le récepteur nil doit
	// répondre « ne pas supprimer » sans paniquer : Phase G est opt-in.
	var vp *VhostProfiles
	if vp.doitSupprimer("gitea.gk2.secubox.in", "/api/v1/x", "scanners") {
		t.Fatal("un profil nil ne doit rien supprimer")
	}
}

func TestChargerRejetteRegexInvalide(t *testing.T) {
	_, err := chargerVhostProfilesDepuis([]byte(
		`{"services":{"x":{"legit_paths":["^(oops"]}},"vhosts":{"h":"x"},"suppress_categories":["scanners"]}`))
	if err == nil {
		t.Fatal("une regex invalide doit faire échouer le chargement, pas passer en silence")
	}
}
