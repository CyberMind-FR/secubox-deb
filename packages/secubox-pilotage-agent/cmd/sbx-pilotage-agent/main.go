// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Commande sbx-pilotage-agent : agent de pilotage distant d'une box SecuBox
// (L1 « Voir », lecture seule). Connexion sortante vers le maître par le tunnel
// WireGuard ; l'agent n'ouvre aucun port d'écoute.
package main

import (
	"context"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-pilotage-agent/internal/canal"
	"github.com/CyberMind-FR/secubox-deb/secubox-pilotage-agent/internal/collecte"
	"github.com/CyberMind-FR/secubox-deb/secubox-pilotage-agent/internal/modele"
	"github.com/CyberMind-FR/secubox-deb/secubox-pilotage-agent/internal/notifs"
)

// version est posée à la construction (-ldflags -X main.version=...).
var version = "dev"

const (
	reverifMaitre = 300 * time.Second
	tailleEvents  = 64
)

func main() {
	log.SetFlags(0) // journald horodate
	ctx, arret := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer arret()

	m := modele.NouveauModele(
		collecte.NouvelleSourceSysteme(""),
		collecte.NouvelleSourceSystemd(lanceurSystemctl(cheminSystemctl, delaiSystemctl)),
		collecte.NouvelleSourcePaquets(""),
		collecte.NouvelleSourceExposition(""),
		collecte.NouvelleSourceMaillage(func() ([]net.Interface, error) { return net.Interfaces() }),
		collecte.NouvelleSourcePilotage("", version),
	)

	maitre, ipSource := attendreMaitre(ctx)
	if ctx.Err() != nil {
		log.Print("arrêt avant connexion")
		return
	}
	log.Printf("agent %s : maître %s, source %s", version, maitre, ipSource)

	ev := make(chan notifs.Evenement, tailleEvents)
	go surveiller(ctx, m, intervalleReleve(os.Getenv("PILOTAGE_RELEVE_INTERVALLE_S")), ev)

	cl := canal.NouveauClient(canal.Config{
		Maitre:   maitre,
		IPSource: ipSource,
		Version:  version,
		BootID:   bootID(),
	}, m, operateur("", nil))
	if err := cl.Tourner(ctx, ev); err != nil && ctx.Err() == nil {
		log.Fatalf("canal : %v", err)
	}
	log.Print("arrêt propre")
}

// attendreMaitre applique la règle de découverte, puis revérifie toutes les 300 s
// tant qu'aucun maître n'est utilisable ; rend la main à l'annulation de ctx.
func attendreMaitre(ctx context.Context) (maitre, ipSource string) {
	for {
		if mt, ip, ok := choisirMaitre(os.Getenv("PILOTAGE_MAITRE"), lireInterfaces()); ok {
			return mt, ip
		}
		log.Printf("aucune interface du maillage : nouvel essai dans %v", reverifMaitre)
		if attendreReel(ctx, reverifMaitre) != nil {
			return "", ""
		}
	}
}

// surveiller échantillonne le modèle à intervalle fixe et pousse les événements
// du détecteur ; si le canal est plein, l'événement est abandonné (jamais bloquant).
func surveiller(ctx context.Context, m *modele.Modele, intervalle time.Duration, ev chan<- notifs.Evenement) {
	det := notifs.NouveauDetecteur(notifs.SeuilsDepuisEnv(), nil)
	t := time.NewTicker(intervalle)
	defer t.Stop()
	for {
		plat := modele.Aplatir(m.Get(ctx, []string{"Device."}))
		for _, e := range det.Observer(plat) {
			select {
			case ev <- e:
			default:
				log.Printf("notification %s abandonnée (file pleine)", e.Type)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// bootID identifie le démarrage de la box (annoncé au maître à /bonjour).
func bootID() string {
	b, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
