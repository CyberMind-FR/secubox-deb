// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// See LICENCE-CMSD-1.0.md for terms.

// SecuBox-Deb :: toolbox-ng :: sbx-authwatch — lecture des journaux (#1220)
//
// Deux sources sur gk2, et c'est la raison de ce fichier :
//
//   - le journal de l'HOTE, pour sshd ;
//   - le journal du CONTENEUR mail, ou vivent postfix et dovecot. Il est
//     lisible depuis l'hote sans y entrer, par `journalctl --directory=` sur
//     /data/lxc/mail/rootfs/var/log/journal — verifie : 4670 lignes pour une
//     journee. On evite ainsi de deployer un agent par conteneur.
//
// On suit en flux (`-f`) plutot que d'interroger periodiquement : une rafale de
// tentatives doit etre vue pendant qu'elle a lieu, pas trente secondes apres.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"
)

// Source est un journal a suivre.
type Source struct {
	Nom        string // pour les messages : "hote", "mail"…
	Repertoire string // vide = journal local ; sinon --directory=
}

// entreeJournal ne retient que ce qui sert. journalctl -o json rend beaucoup
// de champs ; les decoder tous couterait sans rien apporter.
type entreeJournal struct {
	Message string `json:"MESSAGE"`
	Unite   string `json:"_SYSTEMD_UNIT"`
	Ident   string `json:"SYSLOG_IDENTIFIER"`
}

// Suivre lit une source en continu et pousse chaque ligne dans `lignes`.
//
// La fonction ne rend la main qu'a l'annulation du contexte. Si journalctl
// meurt (rotation, redemarrage de journald), on le relance apres une pause :
// un lecteur de securite qui s'arrete en silence est un lecteur inutile.
func Suivre(ctx context.Context, s Source, depuis string, lignes chan<- string) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if err := suivreUneFois(ctx, s, depuis, lignes); err != nil && ctx.Err() == nil {
			log.Printf("sbx-authwatch: source %s interrompue (%v) — reprise dans 5s", s.Nom, err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
		// A la reprise on ne rejoue pas l'historique : `depuis` ne sert qu'au
		// tout premier passage, sinon chaque redemarrage recompterait les
		// memes echecs et bannirait des adresses deja parties.
		depuis = "now"
	}
}

func suivreUneFois(ctx context.Context, s Source, depuis string, lignes chan<- string) error {
	args := []string{"-f", "-o", "json", "--no-pager"}
	if depuis != "" {
		args = append(args, "--since", depuis)
	}
	if s.Repertoire != "" {
		args = append(args, "--directory="+s.Repertoire)
	}
	cmd := exec.CommandContext(ctx, "journalctl", args...)
	sortie, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("journalctl %s : %w", strings.Join(args, " "), err)
	}
	sc := bufio.NewScanner(sortie)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		var e entreeJournal
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			continue // une ligne illisible n'interrompt pas le flux
		}
		if e.Message == "" {
			continue
		}
		select {
		case lignes <- e.Message:
		case <-ctx.Done():
			_ = cmd.Process.Kill()
			return ctx.Err()
		}
	}
	_ = cmd.Wait()
	return sc.Err()
}
