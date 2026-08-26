// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// SecuBox-Deb :: toolbox-ng :: sbx-authwatch (#1220)
//
// CE QU'IL COMBLE. sbxwaf est place derriere HAProxy : il ne voit que le HTTP.
// La force brute SSH, les echecs SASL de postfix, les tentatives IMAP de
// dovecot et les balayages de ports lui sont invisibles. C'etait la surface
// couverte par CrowdSec, perdue en le retirant (#1218). sbx-authwatch la
// reprend, avec deux sources qui se completent :
//
//  1. ANALYSE DE JOURNAUX — ce que les services deja presents ont constate.
//     Patient : on compte, on ne bannit qu'a la repetition, parce qu'un echec
//     isole peut etre un humain.
//  2. LEURRES DE SERVICE — des ports ouverts sans rien derriere (RDP, VNC,
//     telnet…). Certain : personne ne se connecte a un service qu'on n'offre
//     pas. On bannit au premier contact.
//
// TOUT CONVERGE EN DEUX POINTS, et c'est le coeur du dispositif :
//   - le MEME ensemble nft que le WAF, `inet secubox waf_ban{,6}`, applique par
//     la meme chaine — un seul endroit ou regarder qui est banni ;
//   - le MEME journal de menaces, au format exact du WAF — d'ou une
//     correlation retrouvee sans qu'aucun consommateur (panneau, camembert des
//     pays, attaquants persistants, rapport PDF) ait a changer d'une ligne.
package main

import (
	"context"
	"flag"
	"log"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func main() {
	var (
		journaux = flag.String("journaux", "hote",
			"sources de journaux : `hote` et/ou nom:chemin séparés par des virgules "+
				"(ex. « hote,mail:/data/lxc/mail/rootfs/var/log/journal »)")
		depuis  = flag.String("depuis", "now", "point de départ de la première lecture (syntaxe journalctl)")
		seuil   = flag.Int("seuil", 6, "poids cumulé déclenchant le bannissement")
		fenetre = flag.Duration("fenetre", 10*time.Minute, "durée de la fenêtre glissante")
		duree   = flag.Duration("duree-ban", 4*time.Hour, "durée du bannissement nft")
		repit   = flag.Duration("repit", 30*time.Minute, "délai avant qu'une adresse déjà bannie puisse re-déclencher")
		table   = flag.String("nft-table", "secubox", "table nft alimentée")
		set4    = flag.String("nft-set4", "waf_ban", "ensemble IPv4 alimenté")
		set6    = flag.String("nft-set6", "waf_ban6", "ensemble IPv6 alimenté")
		nftPath = flag.String("nft-path", "nft", "chemin du binaire nft")
		menaces = flag.String("journal-menaces", "/var/log/secubox/waf/waf-threats.log",
			"journal de menaces du WAF, alimenté pour la corrélation")
		blanche  = flag.String("liste-blanche", "", "adresses et préfixes exemptés, séparés par des virgules")
		blancheF = flag.String("liste-blanche-fichier", "/etc/secubox/authwatch/liste-blanche",
			"fichier de liste blanche (absent = ignoré)")
		comptesF = flag.String("comptes",
			"/data/volumes/mail/config/users,/data/lxc/mail/rootfs/etc/postfix/vmailbox",
			"fichier(s) listant les comptes RÉELS, séparés par des virgules — "+
				"un échec sur un compte absent de cette liste est un signal certain")
		campSeuil = flag.Int("campagne-sources", 5,
			"nombre de sources distinctes visant un même compte établissant une campagne (0 = désactivé)")
		campFen = flag.Duration("campagne-fenetre", time.Hour,
			"fenêtre d'observation des campagnes par compte visé")
		leurres = flag.String("leurres", "",
			"ports leurres : `defaut` pour la liste connue, ou « 3389:rdp,5900:vnc »")
		simule    = flag.Bool("simulation", false, "détecter et journaliser sans jamais bannir")
		sansGarde = flag.Bool("sans-verification-nft", false,
			"démarrer même si aucune règle ne consulte l'ensemble (DANGEREUX : les bannissements seraient sans effet)")
	)
	flag.Parse()

	log.SetFlags(log.LstdFlags)
	log.SetPrefix("")

	lb, err := NewListeBlanche(*blanche)
	if err != nil {
		log.Fatalf("sbx-authwatch: %v", err)
	}
	if err := lb.ChargeFichier(*blancheF); err != nil {
		log.Fatalf("sbx-authwatch: %v", err)
	}

	banneur := NewBanneur(*nftPath, *table, *set4, *set6, *duree, *simule)
	ctx, arret := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer arret()

	// LA VERIFICATION QUI COMPTE (#1218). On refuse de demarrer si rien ne
	// consulte l'ensemble : compter des bannissements sans effet est pire que
	// ne rien faire, parce que ça se voit dans les journaux comme une reussite.
	if !*simule {
		if err := banneur.Verifie(ctx); err != nil {
			if !*sansGarde {
				log.Fatalf("sbx-authwatch: %v\n"+
					"  → corriger, ou lancer avec --simulation pour observer sans bannir,\n"+
					"    ou --sans-verification-nft si l'application est assurée autrement.", err)
			}
			log.Printf("sbx-authwatch: AVERTISSEMENT — %v (démarrage forcé)", err)
		}
	}

	comptes, err := NewComptes(strings.Split(*comptesF, ","))
	if err != nil {
		log.Fatalf("sbx-authwatch: %v", err)
	}
	if comptes.Charge() {
		log.Printf("sbx-authwatch: %d compte(s) réel(s) connus — un échec sur un compte "+
			"absent de la liste sera traité comme certain", comptes.Taille())
	} else {
		log.Printf("sbx-authwatch: AUCUN compte réel connu (%s) — on reste patient, "+
			"aucune certitude ne sera tirée du nom visé", *comptesF)
	}

	compteur := NewCompteur(*fenetre, *seuil, *repit)
	var campagnes *Campagnes
	if *campSeuil > 0 {
		campagnes = NewCampagnes(*campFen, *campSeuil)
	}
	journalMenaces := NewJournalMenaces(*menaces)
	signaux := make(chan Signal, 256)

	// ── sources de journaux ────────────────────────────────────────────────
	sources, err := analyseSources(*journaux)
	if err != nil {
		log.Fatalf("sbx-authwatch: %v", err)
	}
	lignes := make(chan string, 512)
	for _, s := range sources {
		go Suivre(ctx, s, *depuis, lignes)
		log.Printf("sbx-authwatch: source de journal « %s »%s", s.Nom, suffixeRepertoire(s))
	}
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case l := <-lignes:
				if sig, ok := Reconnaitre(l); ok {
					select {
					case signaux <- sig:
					case <-ctx.Done():
						return
					}
				}
			}
		}
	}()

	// ── leurres ────────────────────────────────────────────────────────────
	listeLeurres, err := AnalyseLeurres(*leurres)
	if err != nil {
		log.Fatalf("sbx-authwatch: %v", err)
	}
	for _, l := range listeLeurres {
		go func(l Leurre) {
			if err := EcouteLeurre(ctx, l, signaux); err != nil {
				log.Printf("sbx-authwatch: %v", err)
			}
		}(l)
	}

	log.Printf("sbx-authwatch: seuil %d sur %s, campagne à %d sources sur %s, ban %s, "+
		"liste blanche %d entrée(s), %d leurre(s)%s",
		*seuil, *fenetre, *campSeuil, *campFen, *duree, lb.Taille(), len(listeLeurres),
		map[bool]string{true: " — SIMULATION, aucun bannissement", false: ""}[*simule])

	// ── elagage periodique ─────────────────────────────────────────────────
	go func() {
		t := time.NewTicker(5 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				compteur.Elague(time.Now())
				campagnes.Elague(time.Now())
			}
		}
	}()

	traite(ctx, signaux, compteur, campagnes, comptes, banneur, journalMenaces, lb, *simule)
	log.Printf("sbx-authwatch: arrêt")
}

// traite est la boucle de decision. Isolee pour etre testable sans reseau ni
// journalctl : les tests y injectent des signaux et observent les bannissements.
func traite(ctx context.Context, signaux <-chan Signal, compteur *Compteur,
	campagnes *Campagnes, comptes *Comptes, banneur *Banneur,
	journal *JournalMenaces, lb *ListeBlanche, simule bool) {
	for {
		select {
		case <-ctx.Done():
			return
		case sig := <-signaux:
			if lb.Contient(sig.IP) {
				// Journalise quand meme : « pourquoi cette adresse n'est-elle
				// jamais bannie ? » doit avoir une reponse dans le journal.
				journal.Inscrit(sig, "detect", 0)
				continue
			}
			// Un leurre est un signal CERTAIN : pas de compteur, pas de
			// patience — personne ne se connecte a un service inexistant.
			if strings.HasPrefix(sig.Categorie, "leurre:") {
				appliquer(ctx, sig, 1, banneur, journal, simule)
				continue
			}
			maintenant := time.Now()

			// COMPTE INEXISTANT : LE SIGNAL LE PLUS SUR. La box heberge une
			// boite ; les campagnes en visent d'autres, qui n'existent pas.
			// Personne ne peut se tromper de mot de passe sur une boite
			// absente — il n'y a personne a tromper. On ne tire cette
			// certitude que si une liste a EFFECTIVEMENT ete chargee.
			if comptes.Inexistant(sig.Cible) {
				sig.Severite = "high"
				sig.Detail = sig.Detail + " — compte inexistant « " + sig.Cible + " »"
				appliquer(ctx, sig, 1, banneur, journal, simule)
				continue
			}

			// CAMPAGNE AVANT COMPTEUR. Une attaque distribuee ne repasse pas
			// par la meme adresse : sur gk2, 339 sources sur 388 n'apparaissent
			// qu'une fois. Le compteur par IP ne les verrait jamais. Si le
			// COMPTE vise est deja attaque depuis plusieurs sources, la source
			// du jour participe a une action collective, et une seule tentative
			// suffit.
			if campagnes != nil {
				if sources, campagne := campagnes.Note(sig.Cible, sig.IP, maintenant); campagne {
					sig.Detail = sig.Detail + " — campagne sur « " + sig.Cible + " »"
					appliquer(ctx, sig, sources, banneur, journal, simule)
					continue
				}
			}

			total, bannir := compteur.Ajoute(sig.IP, Poids(sig.Severite), maintenant)
			if !bannir {
				journal.Inscrit(sig, "warning", total)
				continue
			}
			appliquer(ctx, sig, total, banneur, journal, simule)
		}
	}
}

func appliquer(ctx context.Context, sig Signal, total int,
	banneur *Banneur, journal *JournalMenaces, simule bool) {
	if simule {
		journal.Inscrit(sig, "detect", total)
		log.Printf("sbx-authwatch: SIMULATION %s ← %s (%s)", sig.IP, sig.Categorie, sig.Detail)
		return
	}
	if err := banneur.Bannit(ctx, sig.IP); err != nil {
		log.Printf("sbx-authwatch: bannissement refusé pour %s : %v", sig.IP, err)
		journal.Inscrit(sig, "warning", total)
		return
	}
	journal.Inscrit(sig, "banned", total)
	log.Printf("sbx-authwatch: BAN %s ← %s (%s, total %d)", sig.IP, sig.Categorie, sig.Detail, total)
}

// analyseSources traduit « hote,mail:/chemin » en sources.
func analyseSources(spec string) ([]Source, error) {
	var out []Source
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if part == "hote" {
			out = append(out, Source{Nom: "hote"})
			continue
		}
		morceaux := strings.SplitN(part, ":", 2)
		if len(morceaux) != 2 || strings.TrimSpace(morceaux[1]) == "" {
			return nil, errSource(part)
		}
		out = append(out, Source{Nom: strings.TrimSpace(morceaux[0]),
			Repertoire: strings.TrimSpace(morceaux[1])})
	}
	if len(out) == 0 {
		return nil, errSource(spec)
	}
	return out, nil
}

type erreurSource string

func (e erreurSource) Error() string {
	return "source de journal invalide : " + string(e) +
		" (attendu « hote » ou « nom:/chemin/vers/journal »)"
}

func errSource(s string) error { return erreurSource(s) }

func suffixeRepertoire(s Source) string {
	if s.Repertoire == "" {
		return ""
	}
	return " (" + s.Repertoire + ")"
}
