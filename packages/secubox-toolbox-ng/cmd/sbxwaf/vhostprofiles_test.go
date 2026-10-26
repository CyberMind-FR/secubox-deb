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

// #3193 : la signalisation LiveKit de la Visio passe son jeton dans l'URL
// (`/rtc/v1?access_token=<JWT>`) — c'est le protocole, pas une fuite. La règle
// cred-003 (credential_harvest, critique) la prenait pour une moisson
// d'identifiants et le ban automatique coupait toute la box au téléphone du
// propriétaire. Parade : `suppress_categories` PAR SERVICE, appliqué aux seuls
// `legit_paths` de CE service. La liste globale ne gagne pas credential_harvest.
const profilsLivekitTest = `{
  "services": {
    "livekit": {
      "_note": "signalisation LiveKit : jeton dans l'URL par conception",
      "legit_paths": ["^/rtc(/v1)?(/validate)?$"],
      "suppress_categories": ["credential_harvest"]
    },
    "gitea": { "legit_paths": ["^/api/v1/"] }
  },
  "vhosts": {
    "livekit.gk1.secubox.in": "livekit",
    "gitea.gk2.secubox.in": "gitea"
  },
  "suppress_categories": ["scanners", "recon_crawler", "product_absent_probes"]
}`

func profilsLivekit(t *testing.T) *VhostProfiles {
	t.Helper()
	vp, err := chargerVhostProfilesDepuis([]byte(profilsLivekitTest))
	if err != nil {
		t.Fatalf("chargement des profils livekit : %v", err)
	}
	return vp
}

func TestDoitSupprimerCategorieParService_3193(t *testing.T) {
	vp := profilsLivekit(t)
	cas := []struct {
		nom, host, chemin, cat string
		want                   bool
	}{
		{"signalisation livekit", "livekit.gk1.secubox.in", "/rtc/v1", "credential_harvest", true},
		{"validation livekit", "livekit.gk1.secubox.in", "/rtc/v1/validate", "credential_harvest", true},
		{"ancienne signalisation sans version", "livekit.gk1.secubox.in", "/rtc", "credential_harvest", true},
		{"host avec port", "LiveKit.gk1.secubox.in:443", "/rtc/v1", "credential_harvest", true},
		// La liste GLOBALE reste valable pour ce service.
		{"catégorie globale sur chemin livekit", "livekit.gk1.secubox.in", "/rtc/v1", "scanners", true},
		// Hors des legit_paths du service : la règle tire.
		{"chemin hors profil dans livekit", "livekit.gk1.secubox.in", "/admin", "credential_harvest", false},
		{"préfixe seulement", "livekit.gk1.secubox.in", "/rtc/v1/autre", "credential_harvest", false},
		// Un autre vhost (hall) : aucune exemption.
		{"même chemin sur le hall", "hall.gk2.secubox.in", "/rtc/v1", "credential_harvest", false},
		// La catégorie propre à livekit ne fuit pas vers un autre service,
		// même sur un chemin légitime DE CE service.
		{"pas de fuite vers gitea", "gitea.gk2.secubox.in", "/api/v1/repos", "credential_harvest", false},
		// Une injection n'est jamais supprimée.
		{"sqli sur chemin livekit", "livekit.gk1.secubox.in", "/rtc/v1", "sqli", false},
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

func TestListeGlobaleSansCategorieDeService_3193(t *testing.T) {
	vp := profilsLivekit(t)
	if vp.catSupprimable("credential_harvest") {
		t.Fatal("credential_harvest déclarée par UN service ne doit pas entrer dans la liste globale")
	}
}

// La ré-vérification anti-contrebande (main.go, MatchDetail avec exclusion)
// doit exclure les catégories supprimables POUR CET HÔTE : l'exemption de
// livekit ne doit jamais affaiblir la détection des autres vhosts.
func TestCategoriesSupprimablesPourHote_3193(t *testing.T) {
	vp := profilsLivekit(t)
	lk := vp.categoriesSupprimablesPour("livekit.gk1.secubox.in:443")
	for _, cat := range []string{"credential_harvest", "scanners", "recon_crawler", "product_absent_probes"} {
		if !lk[cat] {
			t.Errorf("livekit : %q devrait être exclue de la ré-vérification", cat)
		}
	}
	for _, host := range []string{"gitea.gk2.secubox.in", "hall.gk2.secubox.in"} {
		set := vp.categoriesSupprimablesPour(host)
		if set["credential_harvest"] {
			t.Errorf("%s : credential_harvest ne doit pas être exclue (fuite de l'exemption livekit)", host)
		}
		if !set["scanners"] {
			t.Errorf("%s : la liste globale doit rester exclue", host)
		}
	}
	var nul *VhostProfiles
	if nul.categoriesSupprimablesPour("livekit.gk1.secubox.in") != nil {
		t.Fatal("un profil nil ne rend aucune catégorie")
	}
}

func TestServiceSansLegitPathsNeSupprimeRien_3193(t *testing.T) {
	// Un service qui supprime une catégorie SANS déclarer de chemin légitime
	// ne supprime rien (estLegitime faux) : le chargement l'accepte, la
	// détection reste entière. On le fige pour qu'un refactor n'en fasse pas
	// une exemption sur TOUT le vhost.
	vp, err := chargerVhostProfilesDepuis([]byte(`{
	  "services": {"lk": {"suppress_categories": ["credential_harvest"]}},
	  "vhosts": {"lk.example": "lk"}, "suppress_categories": []}`))
	if err != nil {
		t.Fatalf("chargement : %v", err)
	}
	if vp.doitSupprimer("lk.example", "/rtc/v1", "credential_harvest") {
		t.Fatal("sans legit_paths, aucune suppression")
	}
}
