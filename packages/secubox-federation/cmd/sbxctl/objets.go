// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Objets SBX (#1391) : publier un métablog au catalogue, le lister, l'installer.
package main

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-federation/internal/ca"
	"github.com/CyberMind-FR/secubox-deb/secubox-federation/internal/federation"
	"github.com/CyberMind-FR/secubox-deb/secubox-federation/internal/sbxobj"
)

// clesCA : la CA qui fait foi ici, et la liste de révocation connue.
func clesCA(ch federation.Chemins) func() (ed25519.PublicKey, map[string]bool) {
	return func() (ed25519.PublicKey, map[string]bool) {
		if a, _, err := autorite(ch); err == nil {
			if l, err := a.CRL(); err == nil {
				return a.Pub, l.Series()
			}
			return a.Pub, nil
		}
		caPub, _ := ch.CAEpinglee()
		if caPub == nil {
			return nil, nil
		}
		if b, err := os.ReadFile(ch.CRL()); err == nil {
			if l, err := ca.VerifieCRL(b, caPub); err == nil {
				return caPub, l.Series()
			}
		}
		return caPub, nil
	}
}

// app publish --site NOM : emballe, signe, vérifie, range au catalogue.
func publieApp(ch federation.Chemins, args []string) error {
	cfg, err := config(ch)
	if err != nil {
		return err
	}
	var site, canal, version, auteur, licence, wallet, support, descr string
	drapeaux("publish", args, func(f *flag.FlagSet) {
		f.StringVar(&site, "site", "", "métablog à publier (nom du site)")
		f.StringVar(&canal, "channel", "stable", "stable | beta | alpha")
		f.StringVar(&version, "version", "", "version (défaut : celle du site, sinon la date)")
		f.StringVar(&auteur, "author", cfg.Owner, "auteur")
		f.StringVar(&licence, "license", "tous-droits-reserves", "licence")
		f.StringVar(&wallet, "wallet", "", "rétribution : portefeuille (métadonnée)")
		f.StringVar(&support, "support-url", "", "rétribution : page de soutien (métadonnée)")
		f.StringVar(&descr, "description", "", "description")
	})
	if site == "" {
		return errors.New("--site requis")
	}
	dir := filepath.Join(ch.Sites, site)
	domaine := ""
	var sj map[string]any
	if b, err := os.ReadFile(filepath.Join(dir, "site.json")); err == nil && json.Unmarshal(b, &sj) == nil {
		domaine, _ = sj["domain"].(string)
		if version == "" {
			version, _ = sj["version"].(string)
			version = strings.TrimPrefix(version, "v")
		}
		if descr == "" {
			descr, _ = sj["description"].(string)
		}
	}
	if version == "" {
		version = time.Now().UTC().Format("2006.01.02")
	}
	priv, err := cleBox(ch)
	if err != nil {
		return err
	}
	certY, _ := os.ReadFile(ch.Cert())
	o := sbxobj.Objet{ID: "metablog." + site, Name: site, Type: "metablog", Version: version, Channel: canal,
		Author: auteur, License: licence, Wallet: wallet, SupportURL: support, Description: descr}
	tmp := filepath.Join(os.TempDir(), fmt.Sprintf("sbx-%s-%d.sbx", site, os.Getpid()))
	defer os.Remove(tmp)
	if _, err := sbxobj.Emballe(sbxobj.Emballage{SiteDir: dir, Objet: o, Domaine: domaine, Cle: priv,
		Certificat: string(certY), Sortie: tmp, Maintenant: time.Now()}); err != nil {
		return err
	}
	caPub, rev := clesCA(ch)()
	p, err := sbxobj.Ouvre(tmp, caPub, rev, time.Now())
	if err != nil {
		return fmt.Errorf("paquet produit invalide : %w", err)
	}
	defer p.Ferme()
	e, err := sbxobj.Catalogue{Dir: ch.Objets()}.Ajoute(tmp, p, time.Now())
	if err != nil {
		return err
	}
	cert := "✓ éditeur certifié"
	if !e.Certifie {
		cert = "⚠ " + e.Motif
	}
	fmt.Printf("publié      %s@%s (%s, %d Ko) — %s\n", e.ID, e.Version, e.Channel, e.Taille/1024, cert)
	return nil
}

func listeApps(ch federation.Chemins, args []string) error {
	cfg, err := config(ch)
	if err != nil {
		return err
	}
	var typ string
	drapeaux("list", args, func(f *flag.FlagSet) { f.StringVar(&typ, "type", "", "type d'objet") })
	caPub, rev, canaux := ch.Confiance(cfg, clesCA(ch))
	es, err := sbxobj.Catalogue{Dir: ch.Objets()}.Liste(typ, caPub, rev, canaux, time.Now())
	if err != nil {
		return err
	}
	if len(es) == 0 {
		fmt.Println("catalogue vide")
	}
	for _, e := range es {
		etat := "✓"
		if !e.Certifie {
			etat = "⚠"
		}
		if e.Verrouille {
			etat += " 🔒"
		}
		fmt.Printf("%s %-32s %-12s %-7s %-22s %s\n", etat, e.ID, e.Version, e.Channel, e.License, e.Author)
	}
	return nil
}

// install ID|FICHIER [--nom N] — vérifie tout, n'écrase jamais.
func installeObjet(ch federation.Chemins, args []string) error {
	if len(args) < 1 {
		return errors.New("objet ou fichier .sbx requis")
	}
	cible := args[0]
	var nom string
	var accepte bool
	drapeaux("install", args[1:], func(f *flag.FlagSet) {
		f.StringVar(&nom, "nom", "", "nom du site installé (défaut : celui du paquet)")
		f.BoolVar(&accepte, "accepte-non-certifie", false, "installer malgré un éditeur non certifié par la CA")
	})
	chemin := cible
	if !strings.HasSuffix(cible, ".sbx") {
		_, c, err := sbxobj.Catalogue{Dir: ch.Objets()}.Trouve(cible)
		if err != nil {
			return err
		}
		chemin = c
	}
	caPub, rev := clesCA(ch)()
	p, err := sbxobj.Ouvre(chemin, caPub, rev, time.Now())
	if err != nil {
		return fmt.Errorf("paquet refusé : %w", err)
	}
	defer p.Ferme()
	if !p.Certifie && !accepte {
		return fmt.Errorf("éditeur non certifié (%s) — --accepte-non-certifie pour passer outre", p.Motif)
	}
	if nom == "" {
		nom = p.Objet.Name
	}
	dossier, err := p.Installe(ch.Sites, nom, time.Now())
	if err != nil {
		return err
	}
	rendAuMetablogizer(dossier)
	fmt.Printf("installé    %s@%s → %s (non publié : le publier depuis le metablogizer)\n",
		p.Objet.ID, p.Objet.Version, dossier)
	return nil
}
