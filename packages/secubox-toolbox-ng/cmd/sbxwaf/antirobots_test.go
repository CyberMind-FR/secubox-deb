// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

package main

import "testing"

// profilsAvecAntiRobots construit un jeu de profils minimal où seul
// gitea.gk2.secubox.in est coché.
func profilsAvecAntiRobots(t *testing.T) *VhostProfiles {
	t.Helper()
	vp, err := chargerVhostProfilesDepuis([]byte(`{
		"services": {"gitea": {"legit_paths": ["^/api/v1/"]}},
		"vhosts": {"gitea.gk2.secubox.in": "gitea", "bbs.gk2.secubox.in": "gitea"},
		"suppress_categories": ["recon_crawler"],
		"anti_robots": ["gitea.gk2.secubox.in"]
	}`))
	if err != nil {
		t.Fatalf("chargement : %v", err)
	}
	return vp
}

const uaNavigateur = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/128.0"

// L'opt-in est la propriété la plus importante : un vhost non coché doit se
// comporter exactement comme avant la fonctionnalité.
func TestAntiRobotsOptIn(t *testing.T) {
	vp := profilsAvecAntiRobots(t)
	ua := "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
	if _, refuse := vp.doitRefuserRobot("bbs.gk2.secubox.in", "/c/emissions", ua); refuse {
		t.Fatal("vhost NON coché : aucun refus ne doit se produire")
	}
	if _, refuse := vp.doitRefuserRobot("gitea.gk2.secubox.in", "/secubox/secubox-deb", ua); !refuse {
		t.Fatal("vhost coché : le robot doit être refusé")
	}
}

// Un fichier antérieur à la fonctionnalité (sans la clé) reste valide et ne
// filtre personne : pas d'erreur de chargement, pas de refus.
func TestAntiRobotsCleAbsente(t *testing.T) {
	vp, err := chargerVhostProfilesDepuis([]byte(`{
		"services": {"gitea": {"legit_paths": []}},
		"vhosts": {"gitea.gk2.secubox.in": "gitea"},
		"suppress_categories": []
	}`))
	if err != nil {
		t.Fatalf("un fichier sans anti_robots doit rester valide : %v", err)
	}
	if vp.antiRobots("gitea.gk2.secubox.in") {
		t.Fatal("clé absente : aucun vhost ne doit être coché")
	}
}

// Le refus ne doit jamais toucher un humain.
func TestAntiRobotsLaisssePasserLesNavigateurs(t *testing.T) {
	vp := profilsAvecAntiRobots(t)
	for _, ua := range []string{
		uaNavigateur,
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Version/17.0 Safari/605.1.15",
		"Mozilla/5.0 (Linux; Android 9; CUBOT_X19) AppleWebKit/537.36 Chrome/120",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Mobile/15E148",
		"", // UA vide : bibliothèques et sondes internes, pas un robot
	} {
		if _, refuse := vp.doitRefuserRobot("gitea.gk2.secubox.in", "/", ua); refuse {
			t.Errorf("faux positif sur un client légitime : %q", ua)
		}
	}
}

// La porte de sortie : un robot refusé doit pouvoir lire robots.txt, sinon il
// ne peut pas apprendre à s'arrêter.
func TestAntiRobotsRobotsTxtToujoursServi(t *testing.T) {
	vp := profilsAvecAntiRobots(t)
	ua := "Mozilla/5.0 (compatible; GPTBot/1.1; +https://openai.com/gptbot)"
	for _, chemin := range []string{"/robots.txt", "/favicon.ico", "/.well-known/acme-challenge/xyz"} {
		if _, refuse := vp.doitRefuserRobot("gitea.gk2.secubox.in", chemin, ua); refuse {
			t.Errorf("%s doit rester accessible aux robots", chemin)
		}
	}
	if _, refuse := vp.doitRefuserRobot("gitea.gk2.secubox.in", "/secubox/secubox-deb/compare/v1..v2", ua); !refuse {
		t.Error("le reste du vhost doit bien être refusé")
	}
}

// Le cas qui a motivé la fonctionnalité, et les familles de robots visées.
func TestAntiRobotsNommeLesRobotsConnus(t *testing.T) {
	cas := map[string]string{
		"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)": "googlebot",
		"Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)":  "bingbot",
		"Mozilla/5.0 (compatible; GPTBot/1.1; +https://openai.com/gptbot)":         "gptbot",
		"Mozilla/5.0 (compatible; ClaudeBot/1.0; +claudebot@anthropic.com)":        "claudebot",
		"Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)":       "ahrefsbot",
		"Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot)":   "semrushbot",
		"Mozilla/5.0 (compatible; PerplexityBot/1.0)":                              "perplexitybot",
		"Bytespider":                                                               "bytespider",
	}
	for ua, attendu := range cas {
		nom, ok := identifierRobot(ua)
		if !ok || nom != attendu {
			t.Errorf("UA %q : obtenu (%q,%v), attendu %q", ua, nom, ok, attendu)
		}
	}
}

// Un robot non listé qui se déclare doit quand même être arrêté — sans être
// nommé à tort.
func TestAntiRobotsGenerique(t *testing.T) {
	for _, ua := range []string{
		"SomeUnknownBot/1.0 (+http://example.com/bot)",
		"my-private-crawler v2",
		"Mozilla/5.0 (compatible; NewSpider/0.1)",
	} {
		nom, ok := identifierRobot(ua)
		if !ok {
			t.Errorf("robot déclaré non détecté : %q", ua)
		}
		if nom != "robot" {
			t.Errorf("un robot non listé ne doit pas être nommé : %q -> %q", ua, nom)
		}
	}
}

// L'en-tête Host arrive souvent avec un port ; la carte est indexée sans.
func TestAntiRobotsHoteAvecPort(t *testing.T) {
	vp := profilsAvecAntiRobots(t)
	if !vp.antiRobots("GITEA.GK2.Secubox.in:443") {
		t.Fatal("l'hôte doit être normalisé (casse et port)")
	}
}

// Opt-in jusqu'au bout : sans profils chargés, le récepteur est nil.
func TestAntiRobotsRecepteurNil(t *testing.T) {
	var vp *VhostProfiles
	if vp.antiRobots("gitea.gk2.secubox.in") {
		t.Fatal("récepteur nil : jamais coché")
	}
	if _, refuse := vp.doitRefuserRobot("gitea.gk2.secubox.in", "/", "Googlebot"); refuse {
		t.Fatal("récepteur nil : jamais de refus")
	}
}
