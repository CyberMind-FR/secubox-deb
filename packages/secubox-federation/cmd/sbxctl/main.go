// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// sbxctl — la fédération SBX en ligne de commande (#1389, phase 1).
//
//	sbxctl ca init                               créer la clé de la CA (une fois)
//	sbxctl federation status [--json]            état mesuré de cette box
//	sbxctl federation join --url URL [--tier T] [--owner O] [--socket S]
//	sbxctl federation fetch [--url URL]          récupérer le certificat émis
//	sbxctl cert demandes                         demandes en attente (autorité)
//	sbxctl cert issue --did DID [--tier T] [--owner O] [--jours N]   (autorité)
//	sbxctl cert revoke SERIAL [--motif M]        (autorité)
//	sbxctl cert renew [--url URL]                renouveler le certificat de cette box
//	sbxctl cert export [--out FICHIER]           le certificat de cette box (YAML)
//	sbxctl cert verify FICHIER                   vérifier un certificat
//
// C'EST LA BOX QUI APPELLE. Aucune commande n'ouvre la box à l'extérieur :
// join, fetch et renew sont des requêtes SORTANTES, initiées ici.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-federation/internal/ca"
	"github.com/CyberMind-FR/secubox-deb/secubox-federation/internal/canon"
	"github.com/CyberMind-FR/secubox-deb/secubox-federation/internal/federation"
	"github.com/CyberMind-FR/secubox-deb/secubox-federation/internal/sbxcert"
)

var version = "dev"

func main() {
	if len(os.Args) < 2 {
		aide()
		os.Exit(2)
	}
	ch := federation.CheminsParDefaut()
	if v := os.Getenv("SBX_FEDERATION_ETAT"); v != "" {
		ch.Etat = v
	}
	if v := os.Getenv("SBX_FEDERATION_CONFIG"); v != "" {
		ch.Config = v
	}
	if v := os.Getenv("SBX_NODE_KEY"); v != "" {
		ch.NodeKey = v
	}
	if v := os.Getenv("SBX_CA_KEY"); v != "" {
		ch.CAKey = v
	}
	if v := os.Getenv("SBX_SITES"); v != "" {
		ch.Sites = v
	}
	var err error
	if os.Args[1] == "install" {
		err = installeObjet(ch, os.Args[2:])
		rendAuDemon(ch)
		if err != nil {
			fmt.Fprintln(os.Stderr, "sbxctl :", err)
			os.Exit(1)
		}
		return
	}
	switch strings.Join(os.Args[1:min(3, len(os.Args))], " ") {
	case "ca init":
		err = caInit(ch)
	case "federation status":
		err = statut(ch, os.Args[3:])
	case "federation join":
		err = adhere(ch, os.Args[3:])
	case "federation fetch":
		err = recupere(ch, os.Args[3:])
	case "cert demandes":
		err = demandes(ch)
	case "cert issue":
		err = emet(ch, os.Args[3:])
	case "cert revoke":
		err = revoque(ch, os.Args[3:])
	case "cert renew":
		err = renouvelle(ch, os.Args[3:])
	case "cert export":
		err = exporte(ch, os.Args[3:])
	case "cert verify":
		err = verifie(ch, os.Args[3:])
	case "app publish":
		err = publieApp(ch, os.Args[3:])
	case "app list":
		err = listeApps(ch, os.Args[3:])
	case "version", "--version":
		fmt.Println("sbxctl", version)
	default:
		aide()
		os.Exit(2)
	}
	// LANCÉ EN ROOT, sbxctl écrit des fichiers que le démon (compte
	// `secubox`) doit pouvoir relire — et, pour la clé de la CA, utiliser.
	rendAuDemon(ch)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sbxctl :", err)
		os.Exit(1)
	}
}

// rendAuMetablogizer : un site installé par root appartient au compte
// `secubox`, comme les 168 autres — sinon le metablogizer ne peut pas le publier.
func rendAuMetablogizer(dossier string) {
	if os.Geteuid() != 0 {
		return
	}
	u, err := user.Lookup("secubox")
	if err != nil {
		return
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	filepath.Walk(dossier, func(p string, _ os.FileInfo, err error) error {
		if err == nil {
			os.Lchown(p, uid, gid)
		}
		return nil
	})
}

func rendAuDemon(ch federation.Chemins) {
	if os.Geteuid() != 0 {
		return
	}
	u, err := user.Lookup("secubox")
	if err != nil {
		return
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	filepath.Walk(ch.Etat, func(p string, _ os.FileInfo, err error) error {
		if err == nil {
			os.Lchown(p, uid, gid)
		}
		return nil
	})
	for _, p := range []string{filepath.Dir(ch.CAKey), ch.CAKey} {
		if _, err := os.Stat(p); err == nil {
			os.Lchown(p, uid, gid)
		}
	}
}

func aide() {
	fmt.Fprint(os.Stderr, `sbxctl — fédération SBX (phase 1)
  ca init
  federation status [--json]
  federation join --url URL [--tier T] [--owner O] [--socket S]
  federation fetch [--url URL] [--socket S]
  cert demandes | issue --did DID [--tier T] [--owner O] [--jours N]
  cert revoke SERIAL [--motif M] | renew [--url URL] [--socket S]
  cert export [--out F] | verify FICHIER
  app publish --site NOM [--channel C] [--license L] [--wallet W] [--support-url U]
  app list [--type metablog]
  install ID|FICHIER.sbx [--nom N] [--accepte-non-certifie]
`)
}

// ── outils ──────────────────────────────────────────────────────────────────

func config(ch federation.Chemins) (*federation.Config, error) { return federation.Charge(ch.Config) }

func autorite(ch federation.Chemins) (*ca.Autorite, *federation.Config, error) {
	cfg, err := config(ch)
	if err != nil {
		return nil, nil, err
	}
	if cfg.Role != "authority" {
		return nil, nil, errors.New("cette box n'est pas l'autorité (role: authority dans " + ch.Config + ")")
	}
	a, err := ca.Charge(ch.CAKey, ch.DirCA(), sbxcert.DID)
	return a, cfg, err
}

func cleBox(ch federation.Chemins) (ed25519.PrivateKey, error) {
	k, err := ca.LitGraine(ch.NodeKey)
	if err != nil {
		return nil, fmt.Errorf("clé de la box (identité annuaire) : %w", err)
	}
	return k, nil
}

func empreinte(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	x := hex.EncodeToString(h[:])
	var p []string
	for i := 0; i < 24; i += 4 {
		p = append(p, x[i:i+4])
	}
	return strings.Join(p, " ")
}

// client : HTTPS vers l'URL de la fédération, ou socket unix local
// (`--socket`, l'autorité qui adhère à elle-même).
func client(url, socket string) (*http.Client, string) {
	if socket != "" {
		return &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socket)
			}}}, "http://federation"
	}
	return &http.Client{Timeout: 20 * time.Second}, strings.TrimRight(url, "/")
}

func appel(c *http.Client, methode, url string, corps any) (int, []byte, error) {
	var in io.Reader
	if corps != nil {
		b, _ := json.Marshal(corps)
		in = bytes.NewReader(b)
	}
	req, err := http.NewRequest(methode, url, in)
	if err != nil {
		return 0, nil, err
	}
	if corps != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rep, err := c.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer rep.Body.Close()
	b, err := io.ReadAll(io.LimitReader(rep.Body, 1<<20))
	return rep.StatusCode, b, err
}

func drapeaux(nom string, args []string, def func(*flag.FlagSet)) *flag.FlagSet {
	fs := flag.NewFlagSet(nom, flag.ExitOnError)
	def(fs)
	fs.Parse(args)
	return fs
}

func ecritAtomique(chemin string, b []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(chemin), 0o755); err != nil {
		return err
	}
	tmp := chemin + ".tmp"
	if err := os.WriteFile(tmp, b, mode); err != nil {
		return err
	}
	return os.Rename(tmp, chemin)
}

// installe : vérifie un certificat reçu contre la CA épinglée, PUIS l'écrit.
func installe(ch federation.Chemins, yamlCert string, pubBox ed25519.PublicKey) (*sbxcert.Certificat, error) {
	// La liste de révocation CONNUE compte : on n'installe pas un certificat
	// que l'autorité a déjà retiré.
	var rev map[string]bool
	caPub, err := ch.CAEpinglee()
	if err != nil || caPub == nil {
		return nil, errors.New("aucune CA épinglée — refaire `sbxctl federation join`")
	}
	if b, err := os.ReadFile(ch.CRL()); err == nil {
		if l, err := ca.VerifieCRL(b, caPub); err == nil {
			rev = l.Series()
		}
	}
	c, err := sbxcert.Lit([]byte(yamlCert))
	if err != nil {
		return nil, err
	}
	if e := c.Verification(caPub, time.Now(), rev); !e.Valide {
		return nil, errors.New("certificat reçu refusé : " + e.Motif)
	}
	if c.BoxID != sbxcert.DID(pubBox) {
		return nil, errors.New("certificat reçu pour une autre box")
	}
	return c, ecritAtomique(ch.Cert(), []byte(yamlCert), 0o644)
}

// ── commandes ───────────────────────────────────────────────────────────────

func caInit(ch federation.Chemins) error {
	if err := ca.Init(ch.CAKey); err != nil {
		return err
	}
	a, err := ca.Charge(ch.CAKey, ch.DirCA(), sbxcert.DID)
	if err != nil {
		return err
	}
	fmt.Printf("CA créée : %s\nempreinte : %s\nclé       : %s (0600)\n", a.DID, empreinte(a.Pub), ch.CAKey)
	return nil
}

func statut(ch federation.Chemins, args []string) error {
	var enJSON bool
	drapeaux("status", args, func(f *flag.FlagSet) { f.BoolVar(&enJSON, "json", false, "sortie JSON") })
	cfg, err := config(ch)
	if err != nil {
		return err
	}
	caPub, _ := ch.CAEpinglee()
	var rev map[string]bool
	if cfg.Role == "authority" {
		if a, err := ca.Charge(ch.CAKey, ch.DirCA(), sbxcert.DID); err == nil {
			caPub = a.Pub
			if l, err := a.CRL(); err == nil {
				rev = l.Series()
			}
		}
	} else if b, err := os.ReadFile(ch.CRL()); err == nil && caPub != nil {
		if l, err := ca.VerifieCRL(b, caPub); err == nil {
			rev = l.Series()
		}
	}
	boxDID := ""
	if k, err := cleBox(ch); err == nil {
		boxDID = sbxcert.DID(k.Public().(ed25519.PublicKey))
	}
	st := federation.Construit(cfg, ch, caPub, boxDID, rev, time.Now())
	if enJSON {
		b, _ := json.MarshalIndent(st, "", "  ")
		fmt.Println(string(b))
		return nil
	}
	fmt.Printf("rôle        %s\nbox         %s\n", st.Role, st.Box)
	if st.CA != "" {
		fmt.Printf("autorité    %s\n", st.CA)
	}
	if st.Certificat == nil {
		fmt.Printf("certificat  aucun — box autonome, hors fédération\n")
	} else {
		c := st.Certificat
		etat := "✓ valide"
		if !c.Etat.Valide {
			etat = "✗ " + c.Etat.Motif
		}
		fmt.Printf("certificat  %s · %s · canaux %s · expire %s\n            %s\n",
			c.Serial, c.Tier, strings.Join(c.Channels, ","), c.Expires, etat)
	}
	cert := ""
	if !st.TierCertifie {
		cert = " (non certifié)"
	}
	fmt.Printf("tier        %s%s\nsync        waf %s · appstore %s · metapack %s\n",
		st.Tier, cert, st.Sync["waf"], st.Sync["appstore"], st.Sync["metapack"])
	return nil
}

func adhere(ch federation.Chemins, args []string) error {
	cfg, err := config(ch)
	if err != nil {
		return err
	}
	var url, tier, owner, socket string
	var accepte bool
	drapeaux("join", args, func(f *flag.FlagSet) {
		f.StringVar(&url, "url", cfg.Federation.URL, "URL de la fédération")
		f.StringVar(&tier, "tier", cfg.Tier, "tier demandé")
		f.StringVar(&owner, "owner", cfg.Owner, "propriétaire")
		f.StringVar(&socket, "socket", "", "socket unix local (autorité qui adhère à elle-même)")
		f.BoolVar(&accepte, "accepte-ca", false, "accepter une clé de CA DIFFÉRENTE de celle épinglée")
	})
	if url == "" && socket == "" {
		return errors.New("--url requis (ou federation.url dans " + ch.Config + ")")
	}
	if owner == "" {
		return errors.New("--owner requis")
	}
	priv, err := cleBox(ch)
	if err != nil {
		return err
	}
	pub := priv.Public().(ed25519.PublicKey)
	c, base := client(url, socket)

	// 1. La clé de la CA — épinglée au premier usage, empreinte AFFICHÉE.
	code, b, err := appel(c, "GET", base+"/api/federation/ca", nil)
	if err != nil || code != 200 {
		return fmt.Errorf("clé de la CA : %d %s %v", code, b, err)
	}
	var cap struct{ DID, Pubkey string }
	json.Unmarshal(b, &cap)
	caPub, err := sbxcert.LitPub(cap.Pubkey)
	if err != nil || sbxcert.DID(caPub) != cap.DID {
		return errors.New("clé de CA incohérente (did ≠ empreinte)")
	}
	if ep, _ := ch.CAEpinglee(); ep != nil && !ep.Equal(caPub) && !accepte {
		return fmt.Errorf("la CA a CHANGÉ de clé (épinglée %s, présentée %s) — refus ; --accepte-ca si c'est voulu",
			sbxcert.DID(ep), cap.DID)
	}
	if err := ecritAtomique(ch.CAPub(), []byte(cap.Pubkey+"\n"), 0o644); err != nil {
		return err
	}
	fmt.Printf("autorité    %s\nempreinte   %s  ← à comparer avec celle annoncée par la fédération\n", cap.DID, empreinte(caPub))

	// 2. La demande, signée par la clé de la box.
	d := &ca.Demande{BoxID: sbxcert.DID(pub), Pubkey: sbxcert.FormatPub(pub), Owner: owner, Tier: tier,
		Horodatage: time.Now().UTC().Format(time.RFC3339)}
	msg, _ := canon.Encode(d.Charge())
	d.Signature = sbxcert.Signe(priv, msg)
	code, b, err = appel(c, "POST", base+"/api/federation/join", d)
	if err != nil {
		return err
	}
	var rep map[string]string
	json.Unmarshal(b, &rep)
	switch code {
	case 201:
		cert, err := installe(ch, rep["certificat"], pub)
		if err != nil {
			return err
		}
		fmt.Printf("certificat  %s émis (%s)\n", cert.Serial, cert.Tier)
	case 202:
		fmt.Printf("demande     envoyée pour %s — en attente de l'autorité ; ensuite : sbxctl federation fetch\n", d.BoxID)
	default:
		return fmt.Errorf("adhésion refusée (%d) : %s", code, rep["erreur"])
	}
	return nil
}

func recupere(ch federation.Chemins, args []string) error {
	cfg, err := config(ch)
	if err != nil {
		return err
	}
	var url, socket string
	drapeaux("fetch", args, func(f *flag.FlagSet) {
		f.StringVar(&url, "url", cfg.Federation.URL, "URL de la fédération")
		f.StringVar(&socket, "socket", "", "socket unix local")
	})
	priv, err := cleBox(ch)
	if err != nil {
		return err
	}
	pub := priv.Public().(ed25519.PublicKey)
	c, base := client(url, socket)
	// LA LISTE DE RÉVOCATION D'ABORD : c'est contre elle que le certificat
	// reçu sera vérifié.
	if code2, crl, err := appel(c, "GET", base+"/api/cert/crl", nil); err == nil && code2 == 200 {
		if caPub, _ := ch.CAEpinglee(); caPub != nil {
			if _, err := ca.VerifieCRL(crl, caPub); err == nil {
				ecritAtomique(ch.CRL(), crl, 0o644)
			}
		}
	}
	code, b, err := appel(c, "GET", base+"/api/federation/join/"+sbxcert.DID(pub), nil)
	if err != nil {
		return err
	}
	var rep map[string]string
	json.Unmarshal(b, &rep)
	switch code {
	case 200:
		cert, err := installe(ch, rep["certificat"], pub)
		if err != nil {
			return err
		}
		fmt.Printf("certificat  %s installé (%s, canaux %s, expire %s)\n", cert.Serial, cert.Tier,
			strings.Join(cert.Channels, ","), cert.Expires)
	case 202:
		fmt.Println("toujours en attente de l'autorité")
	default:
		return fmt.Errorf("%d : %s", code, rep["erreur"])
	}
	return nil
}

func demandes(ch federation.Chemins) error {
	a, _, err := autorite(ch)
	if err != nil {
		return err
	}
	ds, err := a.Demandes()
	if err != nil {
		return err
	}
	if len(ds) == 0 {
		fmt.Println("aucune demande en attente")
	}
	for _, d := range ds {
		pub, _ := sbxcert.LitPub(d.Pubkey)
		fmt.Printf("%s  %-10s %-24s reçue %s\n            empreinte %s\n", d.BoxID, d.Tier, d.Owner, d.Recue, empreinte(pub))
	}
	return nil
}

func emet(ch federation.Chemins, args []string) error {
	a, cfg, err := autorite(ch)
	if err != nil {
		return err
	}
	var did, tier, owner string
	var jours int
	drapeaux("issue", args, func(f *flag.FlagSet) {
		f.StringVar(&did, "did", "", "box à certifier (demande en attente)")
		f.StringVar(&tier, "tier", "", "tier (défaut : celui demandé)")
		f.StringVar(&owner, "owner", "", "propriétaire (défaut : celui déclaré)")
		f.IntVar(&jours, "jours", cfg.CA.DureeJours, "validité en jours")
	})
	d, err := a.Demande(did)
	if err != nil {
		return err
	}
	if tier == "" {
		tier = d.Tier
	}
	if owner == "" {
		owner = d.Owner
	}
	t, ok := cfg.Tiers[tier]
	if !ok {
		return errors.New("tier inconnu : " + tier)
	}
	c, err := a.Emet(d.Pubkey, owner, tier, ca.Politique{Channels: t.Channels, Rights: t.Rights}, jours, time.Now())
	if err != nil {
		return err
	}
	fmt.Printf("émis        %s pour %s (%s, canaux %s, expire %s)\n", c.Serial, c.BoxID, c.Tier, strings.Join(c.Channels, ","), c.Expires)
	return nil
}

func revoque(ch federation.Chemins, args []string) error {
	if len(args) < 1 {
		return errors.New("numéro de série requis")
	}
	a, _, err := autorite(ch)
	if err != nil {
		return err
	}
	var motif string
	drapeaux("revoke", args[1:], func(f *flag.FlagSet) { f.StringVar(&motif, "motif", "", "motif") })
	l, err := a.Revoque(args[0], motif, time.Now())
	if err != nil {
		return err
	}
	fmt.Printf("révoqué     %s — liste signée, %d entrée(s)\n", args[0], len(l.Revoked))
	return nil
}

func renouvelle(ch federation.Chemins, args []string) error {
	cfg, err := config(ch)
	if err != nil {
		return err
	}
	var url, socket string
	drapeaux("renew", args, func(f *flag.FlagSet) {
		f.StringVar(&url, "url", cfg.Federation.URL, "URL de la fédération")
		f.StringVar(&socket, "socket", "", "socket unix local")
	})
	cert, err := ch.CertLocal()
	if err != nil || cert == nil {
		return errors.New("aucun certificat à renouveler")
	}
	priv, err := cleBox(ch)
	if err != nil {
		return err
	}
	y, _ := os.ReadFile(ch.Cert())
	h := time.Now().UTC().Format(time.RFC3339)
	msg, _ := canon.Encode(ca.ChargeRenouvellement(cert.Serial, cert.BoxID, h))
	c, base := client(url, socket)
	code, b, err := appel(c, "POST", base+"/api/cert/renew", ca.Renouvellement{Certificat: string(y), Horodatage: h, Signature: sbxcert.Signe(priv, msg)})
	if err != nil {
		return err
	}
	var rep map[string]string
	json.Unmarshal(b, &rep)
	if code != 200 {
		return fmt.Errorf("renouvellement refusé (%d) : %s", code, rep["erreur"])
	}
	n, err := installe(ch, rep["certificat"], priv.Public().(ed25519.PublicKey))
	if err != nil {
		return err
	}
	fmt.Printf("renouvelé   %s → %s (expire %s)\n", cert.Serial, n.Serial, n.Expires)
	return nil
}

func exporte(ch federation.Chemins, args []string) error {
	var out string
	drapeaux("export", args, func(f *flag.FlagSet) { f.StringVar(&out, "out", "", "fichier de sortie") })
	b, err := os.ReadFile(ch.Cert())
	if err != nil {
		return errors.New("aucun certificat : cette box n'a pas adhéré")
	}
	if out == "" {
		os.Stdout.Write(b)
		return nil
	}
	return os.WriteFile(out, b, 0o644)
}

func verifie(ch federation.Chemins, args []string) error {
	if len(args) < 1 {
		return errors.New("fichier requis")
	}
	b, err := os.ReadFile(args[0])
	if err != nil {
		return err
	}
	c, err := sbxcert.Lit(b)
	if err != nil {
		return err
	}
	caPub, _ := ch.CAEpinglee()
	if a, _, err := autorite(ch); err == nil {
		caPub = a.Pub
	}
	if caPub == nil {
		return errors.New("aucune CA connue pour vérifier")
	}
	var rev map[string]bool
	if crl, err := os.ReadFile(ch.CRL()); err == nil {
		if l, err := ca.VerifieCRL(crl, caPub); err == nil {
			rev = l.Series()
		}
	}
	if a, _, err := autorite(ch); err == nil {
		if l, err := a.CRL(); err == nil {
			rev = l.Series()
		}
	}
	e := c.Verification(caPub, time.Now(), rev)
	if !e.Valide {
		return errors.New(e.Motif)
	}
	fmt.Printf("✓ %s valide — %s, %s, canaux %s, expire %s\n", c.Serial, c.BoxID, c.Tier, strings.Join(c.Channels, ","), c.Expires)
	return nil
}
