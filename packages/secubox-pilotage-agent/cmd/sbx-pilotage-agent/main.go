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
	"sync"
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

	m := construireModele(lanceurSystemctl(cheminSystemctl, delaiSystemctl))

	maitre, ipSource := attendreMaitre(ctx, os.Getenv("PILOTAGE_MAITRE"), lireInterfaces, reverifMaitre)
	if ctx.Err() != nil {
		log.Print("arrêt avant connexion")
		return
	}
	log.Printf("agent %s : maître %s, source %s", version, maitre, ipSource)

	ev := make(chan notifs.Evenement, tailleEvents)
	var suivi sync.WaitGroup
	suivi.Add(1)
	go func() {
		defer suivi.Done()
		surveiller(ctx, m, intervalleReleve(os.Getenv("PILOTAGE_RELEVE_INTERVALLE_S")), ev)
	}()

	cl := canal.NouveauClient(canal.Config{
		Maitre:   maitre,
		IPSource: ipSource,
		Version:  version,
		BootID:   bootID(),
	}, m, operateur("", nil))
	if err := cl.Tourner(ctx, ev); err != nil && ctx.Err() == nil {
		log.Fatalf("canal : %v", err)
	}
	arret()
	suivi.Wait()
	log.Print("arrêt propre")
}

// construireModele assemble les six sources, lues sous la racine « / ».
func construireModele(lanceur func(ctx context.Context, args ...string) ([]byte, error)) *modele.Modele {
	return modele.NouveauModele(
		collecte.NouvelleSourceSysteme("/"),
		collecte.NouvelleSourceSystemd(lanceur),
		collecte.NouvelleSourcePaquets("/"),
		collecte.NouvelleSourceExposition("/"),
		collecte.NouvelleSourceMaillage(func() ([]net.Interface, error) { return net.Interfaces() }),
		collecte.NouvelleSourcePilotage("/", version),
	)
}

// attendreMaitre applique la règle de découverte, puis revérifie à chaque pause
// tant qu'aucune interface du maillage n'est utilisable ; rend la main à
// l'annulation de ctx (maître vide). Une valeur PILOTAGE_MAITRE refusée ne
// change qu'au redémarrage de l'unité : elle est journalisée une fois, puis
// l'agent attend l'arrêt (sortir en erreur ferait boucler Restart=on-failure).
func attendreMaitre(ctx context.Context, env string, interfaces func() []ifaceAdr, pause time.Duration) (maitre, ipSource string) {
	if err := validerMaitre(env); err != nil {
		log.Printf("PILOTAGE_MAITRE refusé : %v ; l'agent reste en attente (corriger puis redémarrer l'unité)", err)
		<-ctx.Done()
		return "", ""
	}
	for {
		if mt, ip, ok := choisirMaitre(env, interfaces()); ok {
			return mt, ip
		}
		log.Printf("aucune interface du maillage : nouvel essai dans %v", pause)
		if attendreReel(ctx, pause) != nil {
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
