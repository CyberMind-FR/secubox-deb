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
	"html"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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

// options de publication, communes au site unique et à la publication en masse.
type optsPub struct {
	canal, version, auteur, licence, wallet, support, descr string
	force                                                   bool
	// poses : les options PASSÉES explicitement. Les autres héritent de la
	// version déjà au catalogue — republier en masse ne doit pas remettre la
	// licence ou le portefeuille choisis pour un site aux valeurs par défaut.
	poses map[string]bool
}

// app publish --site NOM | --tous : emballe, signe, vérifie, range au catalogue.
func publieApp(ch federation.Chemins, args []string) error {
	cfg, err := config(ch)
	if err != nil {
		return err
	}
	var site string
	var tous bool
	var o optsPub
	fs := drapeaux("publish", args, func(f *flag.FlagSet) {
		f.StringVar(&site, "site", "", "métablog à publier (nom du site)")
		f.BoolVar(&tous, "tous", false, "publier TOUS les métablogs de la box")
		f.BoolVar(&o.force, "force", false, "republier une version déjà au catalogue")
		f.StringVar(&o.canal, "channel", "stable", "stable | beta | alpha")
		f.StringVar(&o.version, "version", "", "version (défaut : celle du site, sinon la date)")
		f.StringVar(&o.auteur, "author", cfg.Owner, "auteur")
		f.StringVar(&o.licence, "license", "tous-droits-reserves", "licence")
		f.StringVar(&o.wallet, "wallet", "", "rétribution : portefeuille (métadonnée)")
		f.StringVar(&o.support, "support-url", "", "rétribution : page de soutien (métadonnée)")
		f.StringVar(&o.descr, "description", "", "description")
	})
	o.poses = map[string]bool{}
	fs.Visit(func(f *flag.Flag) { o.poses[f.Name] = true })
	if tous == (site != "") {
		return errors.New("--site NOM ou --tous (l'un ou l'autre)")
	}
	priv, err := cleBox(ch)
	if err != nil {
		return err
	}
	cat := sbxobj.Catalogue{Dir: ch.ObjetsDe(cfg)}
	if !tous {
		_, err := publieUn(ch, cat, priv, site, o)
		return err
	}
	// EN MASSE : un site en erreur n'arrête pas les autres ; le bilan dit tout.
	es, err := os.ReadDir(ch.Sites)
	if err != nil {
		return err
	}
	var publies, deja, vides, erreurs int
	for _, e := range es {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(ch.Sites, e.Name())
		if !dirExiste(filepath.Join(dir, ".git")) && !dirExiste(filepath.Join(dir, "public")) {
			vides++
			continue
		}
		etat, err := publieUn(ch, cat, priv, e.Name(), o)
		switch {
		case err != nil:
			erreurs++
			fmt.Printf("✗ %-28s %v\n", e.Name(), err)
		case etat == "deja":
			deja++
		default:
			publies++
		}
	}
	fmt.Printf("bilan       %d publié(s) · %d déjà à jour · %d vide(s) ignoré(s) · %d erreur(s)\n", publies, deja, vides, erreurs)
	if erreurs > 0 {
		return fmt.Errorf("%d site(s) en erreur", erreurs)
	}
	return nil
}

func dirExiste(p string) bool { st, err := os.Stat(p); return err == nil && st.IsDir() }

// publieUn rend "publie" ou "deja".
func publieUn(ch federation.Chemins, cat sbxobj.Catalogue, priv ed25519.PrivateKey, site string, o optsPub) (string, error) {
	dir := filepath.Join(ch.Sites, site)
	domaine, version, descr := "", o.version, o.descr
	var sj map[string]any
	if b, err := os.ReadFile(filepath.Join(dir, "site.json")); err == nil && json.Unmarshal(b, &sj) == nil {
		domaine, _ = sj["domain"].(string)
		if version == "" {
			version, _ = sj["version"].(string)
			version = strings.TrimPrefix(version, "v")
		}
		if descr == "" {
			descr, _ = sj["description"].(string)
			if descr == "" {
				descr, _ = sj["title"].(string)
			}
		}
	}
	if version == "" {
		version = time.Now().UTC().Format("2006.01.02")
	}
	if descr == "" {
		descr = titreAccueil(dir)
	}
	id := "metablog." + site
	if !o.force && cat.Contient(id, version) {
		return "deja", nil
	}
	if prec, _, err := cat.Trouve(id); err == nil {
		herite := func(nom string, courant *string, val string) {
			if !o.poses[nom] && val != "" {
				*courant = val
			}
		}
		herite("channel", &o.canal, prec.Channel)
		herite("license", &o.licence, prec.License)
		herite("author", &o.auteur, prec.Author)
		herite("wallet", &o.wallet, prec.Wallet)
		herite("support-url", &o.support, prec.SupportURL)
		// Une description déjà publiée l'emporte sur celle qu'on devine
		// (site.json, <title>) : elle a pu être écrite à la main.
		if !o.poses["description"] && prec.Description != "" {
			descr = prec.Description
		}
	}
	certY, _ := os.ReadFile(ch.Cert())
	obj := sbxobj.Objet{ID: id, Name: site, Type: "metablog", Version: version, Channel: o.canal,
		Author: o.auteur, License: o.licence, Wallet: o.wallet, SupportURL: o.support, Description: descr}
	tmp := filepath.Join(os.TempDir(), fmt.Sprintf("sbx-%s-%d.sbx", site, os.Getpid()))
	defer os.Remove(tmp)
	if _, err := sbxobj.Emballe(sbxobj.Emballage{SiteDir: dir, Objet: obj, Domaine: domaine, Cle: priv,
		Certificat: string(certY), Sortie: tmp, Maintenant: time.Now()}); err != nil {
		return "", err
	}
	caPub, rev := clesCA(ch)()
	p, err := sbxobj.Ouvre(tmp, caPub, rev, time.Now())
	if err != nil {
		return "", fmt.Errorf("paquet produit invalide : %w", err)
	}
	defer p.Ferme()
	e, err := cat.Ajoute(tmp, p, time.Now())
	if err != nil {
		return "", err
	}
	cert := "✓ éditeur certifié"
	if !e.Certifie {
		cert = "⚠ " + e.Motif
	}
	fmt.Printf("publié      %s@%s (%s, %d Ko) — %s\n", e.ID, e.Version, e.Channel, e.Taille/1024, cert)
	return "publie", nil
}

func listeApps(ch federation.Chemins, args []string) error {
	cfg, err := config(ch)
	if err != nil {
		return err
	}
	var typ string
	drapeaux("list", args, func(f *flag.FlagSet) { f.StringVar(&typ, "type", "", "type d'objet") })
	caPub, rev, canaux := ch.Confiance(cfg, clesCA(ch))
	es, err := sbxobj.Catalogue{Dir: ch.ObjetsDe(cfg)}.Liste(typ, caPub, rev, canaux, time.Now())
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
	cfg, _ := config(ch)
	chemin := cible
	if !strings.HasSuffix(cible, ".sbx") {
		_, c, err := sbxobj.Catalogue{Dir: ch.ObjetsDe(cfg)}.Trouve(cible)
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

var reTitre = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// titreAccueil : le <title> de la page d'accueil — sur le disque (public/)
// ou, pour un site qui ne vit que dans git, dans la révision courante.
// Une carte d'App Store sans description ne dit rien de ce qu'on installe.
func titreAccueil(dir string) string {
	var page []byte
	for _, p := range []string{"public/index.html", "index.html"} {
		if b, err := os.ReadFile(filepath.Join(dir, p)); err == nil {
			page = b
			break
		}
	}
	if page == nil && dirExiste(filepath.Join(dir, ".git")) {
		reel, _ := filepath.EvalSymlinks(dir)
		for _, p := range []string{"HEAD:public/index.html", "HEAD:index.html"} {
			if b, err := exec.Command("git", "-c", "safe.directory="+reel, "-C", reel, "show", p).Output(); err == nil {
				page = b
				break
			}
		}
	}
	m := reTitre.FindSubmatch(page)
	if m == nil {
		return ""
	}
	t := strings.Join(strings.Fields(html.UnescapeString(string(m[1]))), " ")
	if r := []rune(t); len(r) > 200 {
		t = string(r[:200])
	}
	return t
}
