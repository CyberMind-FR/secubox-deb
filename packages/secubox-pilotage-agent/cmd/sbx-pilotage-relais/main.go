// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Commande sbx-pilotage-relais : relais local du pilotage délégué d'une box légère (#3126 L5, tâche 2).
//
//	sbx-pilotage-relais                 service (socket reçue de systemd, secubox-pilotage-relais.socket)
//	sbx-pilotage-relais cle-publique    crée la clé privée si absente, écrit la clé PUBLIQUE (PEM SPKI)
//	                                    sur la sortie standard ; lancé par le postinst sous le compte du
//	                                    relais (runuser), qui seul lit la clé privée. Root pose ensuite
//	                                    /etc/secubox-pilotage/relais.pub.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"syscall"

	"github.com/CyberMind-FR/secubox-deb/secubox-pilotage-agent/internal/relais"
)

// version est posée à la construction (-ldflags -X main.version=...).
var version = "dev"

const (
	cheminCle       = "/var/lib/secubox-pilotage-relais/relais.key"
	cheminPublique  = "/etc/secubox-pilotage/relais.pub"
	compteAgent     = "secubox-pilotage-agent"
	dossierSockets  = "/run/secubox"
	dossierMains    = "/etc/secubox-pilotage" // mains-liees projeté par le ctl root (R-L5-19)
	cheminAudit     = "/var/log/secubox/audit.log"
	premierFdSystem = 3
)

func main() {
	log.SetFlags(0) // journald horodate
	if len(os.Args) == 2 && os.Args[1] == "cle-publique" {
		cle, err := relais.CreerOuChargerCle(cheminCle)
		if err != nil {
			log.Fatalf("clé du relais : %v", err)
		}
		if _, err := os.Stdout.Write(relais.PEMPublique(cle)); err != nil {
			log.Fatalf("sortie : %v", err)
		}
		return
	}
	if len(os.Args) != 1 {
		log.Fatalf("usage : %s [cle-publique]", os.Args[0])
	}
	cle, err := relais.ChargerCle(cheminCle)
	if err != nil {
		log.Fatalf("clé du relais : %v (le postinst la crée : dpkg-reconfigure secubox-pilotage-agent)", err)
	}
	if err := relais.VerifierClePublique(cheminPublique, cle, 0); err != nil {
		log.Fatalf("clé publique : %v (le postinst la pose : dpkg-reconfigure secubox-pilotage-agent)", err)
	}
	uid, err := uidCompte(compteAgent)
	if err != nil {
		log.Fatalf("compte %s : %v", compteAgent, err)
	}
	ln, err := socketDeSystemd()
	if err != nil {
		log.Fatalf("socket : %v", err)
	}
	ctx, arret := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer arret()
	r := &relais.Relais{
		Cle: cle, UIDAgent: uid, DossierSockets: dossierSockets, DossierMainsLiees: dossierMains, UIDRoot: 0,
		CheminAudit: cheminAudit, NomBox: relais.NomBoxLocale, Delai: relais.DelaiDefaut,
	}
	log.Printf("relais %s : prêt (box %q, agent uid %d)", version, relais.NomBoxLocale(), uid)
	if err := r.Servir(ctx, ln); err != nil {
		log.Fatalf("relais : %v", err)
	}
}

func uidCompte(nom string) (uint32, error) {
	u, err := user.Lookup(nom)
	if err != nil {
		return 0, err
	}
	n, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, errors.New("compte root refusé")
	}
	return uint32(n), nil
}

// socketDeSystemd : la socket créée par secubox-pilotage-relais.socket (propriétaire, groupe et mode
// fixés par systemd : jamais de chmod/chgrp dans /run/secubox, partagé et collant). Exactement une.
func socketDeSystemd() (net.Listener, error) {
	pid, err := strconv.Atoi(os.Getenv("LISTEN_PID"))
	if err != nil || pid != os.Getpid() {
		return nil, errors.New("aucune socket transmise par systemd (LISTEN_PID)")
	}
	if os.Getenv("LISTEN_FDS") != "1" {
		return nil, fmt.Errorf("LISTEN_FDS=%q, une seule socket attendue", os.Getenv("LISTEN_FDS"))
	}
	for _, v := range []string{"LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"} {
		os.Unsetenv(v)
	}
	f := os.NewFile(premierFdSystem, "pilotage-relais.sock")
	ln, err := net.FileListener(f)
	f.Close()
	if err != nil {
		return nil, err
	}
	if _, ok := ln.(*net.UnixListener); !ok {
		ln.Close()
		return nil, errors.New("la socket transmise n'est pas une socket Unix")
	}
	return ln, nil
}
