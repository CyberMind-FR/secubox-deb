// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package main

// ÉTAT DU CONTENEUR DE COURRIER (#3924). Une sonde ratée ne prouve pas un arrêt :
// conteneur gelé, pare-feu, démarrage en cours, adresse mal réglée. On ne prend
// sa place que s'il est CONNU arrêté et que l'adresse réglée est
// bien la sienne. Dans le doute, on ne fait rien. Lecture seule, sans lxc-info.

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

var nomConteneur = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

// EtatLXC lit ce que la box sait du conteneur.
type EtatLXC struct {
	Nom      string
	Adresse  string
	LxcPaths []string
	Cgroup   string // /sys/fs/cgroup
	ProcUnix string // /proc/net/unix
}

// Remplacable : nil si le conteneur est connu arrêté et que
// l'adresse est la sienne ; sinon la raison de ne rien faire.
func (e EtatLXC) Remplacable() error {
	if err := e.adresseDuConteneur(); err != nil {
		return err
	}
	if err := e.cgroupVide(); err != nil {
		return err
	}
	return e.sansCommande()
}

// adresseDuConteneur : chaque configuration trouvée doit porter l'adresse
// réglée, et il en faut une : sans elle, rien ne dit que l'adresse est la sienne.
func (e EtatLXC) adresseDuConteneur() error {
	lues := 0
	for _, p := range e.LxcPaths {
		brut, err := os.ReadFile(filepath.Join(p, e.Nom, "config"))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("configuration du conteneur %s illisible", e.Nom)
		}
		lues++
		trouvee := false
		for _, l := range strings.Split(string(brut), "\n") {
			cle, val, ok := strings.Cut(l, "=")
			if !ok || strings.TrimSpace(cle) != "lxc.net.0.ipv4.address" {
				continue
			}
			champs := strings.Fields(val)
			if len(champs) == 0 {
				continue
			}
			adr, _, _ := strings.Cut(champs[0], "/")
			trouvee = adr == e.Adresse
		}
		if !trouvee {
			return fmt.Errorf("l'adresse %s n'est pas celle du conteneur %s (%s)", e.Adresse, e.Nom, p)
		}
	}
	if lues == 0 {
		return fmt.Errorf("aucune configuration LXC du conteneur %s (%s)", e.Nom, strings.Join(e.LxcPaths, ", "))
	}
	return nil
}

// cgroupVide : aucun processus dans la charge ni le moniteur du conteneur
// (un conteneur GELÉ en garde ; LXC suffixe « -N » quand un reste traîne).
func (e EtatLXC) cgroupVide() error {
	if _, err := os.Stat(filepath.Join(e.Cgroup, "cgroup.controllers")); err != nil {
		return errors.New("cgroup v2 illisible")
	}
	for _, sorte := range []string{"lxc.payload.", "lxc.monitor."} {
		exact := regexp.MustCompile("^" + regexp.QuoteMeta(sorte+e.Nom) + `(-[0-9]+)?$`)
		for _, niveau := range []string{"", "*", "*/*"} {
			dossiers, err := filepath.Glob(filepath.Join(e.Cgroup, niveau, sorte+e.Nom+"*"))
			if err != nil {
				return err
			}
			for _, d := range dossiers {
				if !exact.MatchString(filepath.Base(d)) {
					continue
				}
				ev, err := os.ReadFile(filepath.Join(d, "cgroup.events"))
				if errors.Is(err, fs.ErrNotExist) {
					continue // disparu entre-temps
				}
				if err != nil || !strings.Contains(string(ev), "populated 0") {
					return fmt.Errorf("le conteneur %s est en marche", e.Nom)
				}
			}
		}
	}
	return nil
}

// sansCommande : le moniteur LXC tient la socket abstraite
// « @<lxcpath>/<nom>/command » tant que le conteneur vit.
func (e EtatLXC) sansCommande() error {
	brut, err := os.ReadFile(e.ProcUnix)
	if err != nil {
		return errors.New("sockets Unix illisibles")
	}
	for _, l := range strings.Split(string(brut), "\n") {
		c := strings.Fields(l)
		if len(c) > 0 && strings.HasPrefix(c[len(c)-1], "@/") && strings.HasSuffix(c[len(c)-1], "/"+e.Nom+"/command") {
			return fmt.Errorf("le conteneur %s est en marche", e.Nom)
		}
	}
	return nil
}

// ── réglages de l'opérateur ─────────────────────────────────────────────────

// reglagesMail : les seules clés lues. PAS d'EnvironmentFile= (R36) : systemd
// poserait n'importe quelle variable, LD_PRELOAD comprise, dans une unité root.
var reglagesMail = map[string]bool{"SBX_MAIL_CONTENEUR": true, "SBX_MAIL_NOM": true}

// lireReglages lit le fichier par descripteur, sans suivre de lien : fichier
// régulier appartenant à uid (root), sans écriture du groupe ni des autres ;
// sinon il est ignoré EN ENTIER. Absent : rien.
func lireReglages(chemin string, uid uint32) map[string]string {
	out := map[string]string{}
	if chemin == "" {
		return out
	}
	f, err := os.OpenFile(chemin, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return out
	}
	if err != nil {
		log.Printf("sbx-authwatch: réglages %s ignorés : %v", chemin, err)
		return out
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		log.Printf("sbx-authwatch: réglages %s ignorés : %v", chemin, err)
		return out
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || !st.Mode().IsRegular() || sys.Uid != uid || st.Mode().Perm()&0022 != 0 || st.Size() > 16<<10 {
		log.Printf("sbx-authwatch: réglages %s ignorés (attendu : fichier régulier de root, sans écriture groupe/autres)", chemin)
		return out
	}
	brut, err := io.ReadAll(io.LimitReader(f, 16<<10))
	if err != nil {
		log.Printf("sbx-authwatch: réglages %s ignorés : %v", chemin, err)
		return out
	}
	for _, l := range strings.Split(string(brut), "\n") {
		cle, val, ok := strings.Cut(strings.TrimSpace(l), "=")
		if ok && reglagesMail[cle] {
			out[cle] = strings.Trim(strings.TrimSpace(val), `"'`)
		}
	}
	return out
}
