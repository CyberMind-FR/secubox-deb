// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Commande sbx-pilotage-agent : agent de pilotage distant d'une box SecuBox
// (L1 « Voir » ; L2 « Agir » par le ctl root, via sudo). Connexion sortante vers
// le maître par le tunnel WireGuard ; l'agent n'ouvre aucun port d'écoute.
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
	"github.com/CyberMind-FR/secubox-deb/secubox-pilotage-agent/internal/lecture"
	"github.com/CyberMind-FR/secubox-deb/secubox-pilotage-agent/internal/modele"
	"github.com/CyberMind-FR/secubox-deb/secubox-pilotage-agent/internal/notifs"
)

// version est posée à la construction (-ldflags -X main.version=...).
var version = "dev"

const (
	reverifMaitre = 300 * time.Second
	tailleEvents  = 64
	// L5 : socket du relais local (activation systemd) et arbre root où le ctl projette ses drapeaux.
	cheminRelais    = "/run/secubox/pilotage-relais.sock"
	dossierPilotage = "/etc/secubox-pilotage"
)

func main() {
	log.SetFlags(0) // journald horodate
	// Réglages lus par l'agent, par descripteur, root:root seulement (R36) : jamais par EnvironmentFile.
	chargerReglages("/", lecture.Root, os.Setenv)
	ctx, arret := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer arret()

	m, cpu := construireModele(lanceurSystemctl(cheminSystemctl, delaiSystemctl))

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
		surveiller(ctx, m, cpu, intervalleReleve(os.Getenv("PILOTAGE_RELEVE_INTERVALLE_S")), ev)
	}()

	// L2 : Operate d'action par le ctl root (sudo), opérations suivies par systemctl, fins gardées jusqu'à leur remise.
	ex, resultats := executeur(lanceurSystemctl(cheminSudo, delaiCtl), lanceurEntree(cheminSudo, delaiCtl),
		lanceurSystemctl(cheminSystemctl, delaiSystemctl), ev)
	// L2, tâche 4 : bascules locales (mains liées, consentements, support) lues au ctl et notifiées au maître, toutes
	// les 5 min et juste après chaque Operate traité (R-L2-30).
	relire := make(chan struct{}, 1)
	suivi.Add(1)
	go func() {
		defer suivi.Done()
		veiller(ctx, lanceurSystemctl(cheminSudo, delaiCtl), pasVeille, relire, ev)
	}()
	cl := canal.NouveauClient(canal.Config{
		Maitre:   maitre,
		IPSource: ipSource,
		Version:  version,
		BootID:   bootID(),
		// D1 : au démarrage puis toutes les heures, par le ctl root ; échec → canal coupé.
		Ancre:     verifieurAncre(lanceurSystemctl(cheminSudo, delaiCtl), maitre),
		Agir:      apresOperate(ex.Operer, relire),
		Resultats: resultats,
		// I4 (R-L2-47) : à la première ancre vérifiée, les fins enregistrées par le ctl repartent vers le maître.
		ApresAncre: func(ctx context.Context) { ex.Rattraper(ctx) },
		// L5 tâche 3 : messages HTTP vers le relais local ; portée recalculée ICI à chaque message, d'après les
		// drapeaux root projetés par le ctl (mains liées, propriétaire, support ouvert), sans sudo (R-L5-21).
		CheminRelais: cheminRelais,
		PorteeAdmin:  canal.PorteeLocale(dossierPilotage, 0, time.Now),
	}, m, operateurBox(nil))
	if err := cl.Tourner(ctx, ev); err != nil && ctx.Err() == nil {
		log.Fatalf("canal : %v", err)
	}
	arret()
	ex.Attendre()
	suivi.Wait()
	log.Print("arrêt propre")
}

// construireModele assemble les six sources, lues sous la racine « / », et
// rend aussi l'échantillonneur CPU de la source système (fenêtre de la surveillance).
func construireModele(lanceur func(ctx context.Context, args ...string) ([]byte, error)) (*modele.Modele, collecte.EchantillonCPU) {
	sys := collecte.NouvelleSourceSysteme("/")
	return modele.NouveauModele(
		sys,
		collecte.NouvelleSourceSystemd(lanceur),
		collecte.NouvelleSourcePaquets("/"),
		collecte.NouvelleSourceExposition("/"),
		collecte.NouvelleSourceMaillage(func() ([]net.Interface, error) { return net.Interfaces() }),
		collecte.NouvelleSourcePilotage("/", version),
	), sys.(collecte.EchantillonCPU)
}

// attendreMaitre applique la règle de découverte, puis revérifie à chaque pause
// tant qu'aucune interface du maillage n'est utilisable ; rend la main à
// l'annulation de ctx (maître vide). Sur le maître lui-même (adresse de sortie
// = adresse du maître), il journalise une fois et attend l'arrêt (R35). Une valeur PILOTAGE_MAITRE refusée ne
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
			if estLeMaitre(mt, ip) {
				log.Printf("cette box porte l'adresse du maître (%s) : pas de pilotage par son propre canal en L1 (R35) ; "+
					"l'agent reste en attente, sans contacter le canal", ip)
				<-ctx.Done()
				return "", ""
			}
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
// Elle ne lit que les chemins du détecteur (M3) et fait avancer, seule, la
// fenêtre CPU que lisent les Get du maître (M1).
func surveiller(ctx context.Context, m *modele.Modele, cpu collecte.EchantillonCPU, intervalle time.Duration, ev chan<- notifs.Evenement) {
	det := notifs.NouveauDetecteur(notifs.SeuilsDepuisEnv(), nil)
	t := time.NewTicker(intervalle)
	defer t.Stop()
	chemins := notifs.Chemins()
	for {
		cpu.EchantillonnerCPU()
		plat := modele.Aplatir(m.Get(ctx, chemins))
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
