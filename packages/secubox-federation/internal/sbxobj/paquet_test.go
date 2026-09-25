package sbxobj

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-federation/internal/ca"
	"github.com/CyberMind-FR/secubox-deb/secubox-federation/internal/sbxcert"
)

type banc struct {
	ca      *ca.Autorite
	editeur ed25519.PrivateKey
	cert    string
	site    string
	sbx     string
	sites   string
}

func nouveauBanc(t *testing.T, droits map[string]bool) *banc {
	t.Helper()
	d := t.TempDir()
	cle := filepath.Join(d, "ca.key")
	if err := ca.Init(cle); err != nil {
		t.Fatal(err)
	}
	a, err := ca.Charge(cle, filepath.Join(d, "ca"), sbxcert.DID)
	if err != nil {
		t.Fatal(err)
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	c, err := a.Emet(sbxcert.FormatPub(priv.Public().(ed25519.PublicKey)), "CyberMind", "pro",
		ca.Politique{Channels: []string{"stable", "beta"}, Rights: droits}, 365, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	cy, _ := c.YAML()
	site := filepath.Join(d, "sites", "aletheia")
	os.MkdirAll(filepath.Join(site, "public", "img"), 0o755)
	os.WriteFile(filepath.Join(site, "public", "index.html"), []byte("<h1>Aletheia</h1>"), 0o644)
	os.WriteFile(filepath.Join(site, "public", "img", "a.txt"), []byte("image"), 0o644)
	return &banc{ca: a, editeur: priv, cert: string(cy), site: site,
		sbx: filepath.Join(d, "out", "aletheia.sbx"), sites: filepath.Join(d, "sites")}
}

func (b *banc) objet() Objet {
	return Objet{ID: "metablog.aletheia", Name: "aletheia", Type: "metablog", Version: "2026.09.25",
		Channel: "stable", Author: "CyberMind", License: "CC-BY-SA-4.0", Wallet: "cybermind"}
}

func (b *banc) emballe(t *testing.T) {
	t.Helper()
	if _, err := Emballe(Emballage{SiteDir: b.site, Objet: b.objet(), Domaine: "aletheia.gk2.secubox.in",
		Cle: b.editeur, Certificat: b.cert, Sortie: b.sbx, Maintenant: time.Now()}); err != nil {
		t.Fatal(err)
	}
}

func TestEmballerOuvrirInstaller(t *testing.T) {
	b := nouveauBanc(t, map[string]bool{"appstore": true, "metapack": true})
	b.emballe(t)
	p, err := Ouvre(b.sbx, b.ca.Pub, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer p.Ferme()
	if !p.Certifie {
		t.Fatalf("éditeur non certifié : %s", p.Motif)
	}
	dossier, err := p.Installe(b.sites, "aletheia-copie", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(dossier, "public", "index.html")); string(got) != "<h1>Aletheia</h1>" {
		t.Errorf("contenu installé : %q", got)
	}
	var site map[string]any
	sb, _ := os.ReadFile(filepath.Join(dossier, "site.json"))
	json.Unmarshal(sb, &site)
	if site["published"] != false || site["domain"] != "aletheia-copie.gk2.secubox.in" {
		t.Errorf("site.json : %v", site)
	}
	// JAMAIS PAR-DESSUS : ni l'original, ni la copie qu'on vient de poser.
	for _, nom := range []string{"aletheia", "aletheia-copie"} {
		if _, err := p.Installe(b.sites, nom, time.Now()); err == nil {
			t.Errorf("installation par-dessus %q acceptée", nom)
		}
	}
}

func TestSansDroitMetapackLEditeurNEstPasCertifie(t *testing.T) {
	b := nouveauBanc(t, map[string]bool{"appstore": true})
	b.emballe(t)
	p, err := Ouvre(b.sbx, b.ca.Pub, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer p.Ferme()
	if p.Certifie || !strings.Contains(p.Motif, "metapack") {
		t.Errorf("certifié=%v motif=%q", p.Certifie, p.Motif)
	}
}

func TestUnEditeurRevoqueNEstPlusCertifie(t *testing.T) {
	b := nouveauBanc(t, map[string]bool{"metapack": true})
	b.emballe(t)
	c, _ := sbxcert.Lit([]byte(b.cert))
	p, err := Ouvre(b.sbx, b.ca.Pub, map[string]bool{c.Serial: true}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer p.Ferme()
	if p.Certifie {
		t.Error("éditeur révoqué toujours certifié")
	}
}

// reecrit : ouvre le .sbx, applique f aux membres, le referme.
func reecrit(t *testing.T, chemin string, f func(map[string][]byte)) {
	t.Helper()
	fh, _ := os.Open(chemin)
	gz, _ := gzip.NewReader(fh)
	tr := tar.NewReader(gz)
	m := map[string][]byte{}
	var ordre []string
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		b, _ := io.ReadAll(tr)
		m[h.Name] = b
		ordre = append(ordre, h.Name)
	}
	fh.Close()
	f(m)
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for n := range m {
		if !contient(ordre, n) {
			ordre = append(ordre, n)
		}
	}
	for _, n := range ordre {
		if b, ok := m[n]; ok {
			tw.WriteHeader(&tar.Header{Name: n, Mode: 0o644, Size: int64(len(b)), Typeflag: tar.TypeReg})
			tw.Write(b)
		}
	}
	tw.Close()
	gw.Close()
	os.WriteFile(chemin, buf.Bytes(), 0o644)
}

func TestUnPaquetAltereEstRefuse(t *testing.T) {
	cas := map[string]func(map[string][]byte){
		"contenu modifié": func(m map[string][]byte) {
			c := m["content.tar"]
			c[len(c)/2] ^= 0xff
		},
		"licence changée": func(m map[string][]byte) {
			m["manifest.json"] = bytes.Replace(m["manifest.json"], []byte("CC-BY-SA-4.0"), []byte("MIT"), 1)
		},
		"membre ajouté":   func(m map[string][]byte) { m["repo.bundle"] = []byte("intrus") },
		"membre étranger": func(m map[string][]byte) { m["../evil.sh"] = []byte("#!/bin/sh") },
		"sans signature": func(m map[string][]byte) {
			var man map[string]any
			json.Unmarshal(m["manifest.json"], &man)
			delete(man, "signature")
			m["manifest.json"], _ = json.Marshal(man)
		},
	}
	for nom, f := range cas {
		t.Run(nom, func(t *testing.T) {
			b := nouveauBanc(t, map[string]bool{"metapack": true})
			b.emballe(t)
			reecrit(t, b.sbx, f)
			if p, err := Ouvre(b.sbx, b.ca.Pub, nil, time.Now()); err == nil {
				p.Ferme()
				t.Fatal("paquet altéré accepté")
			}
		})
	}
}

func TestUnContenuQuiSortDuSiteEstRefuse(t *testing.T) {
	b := nouveauBanc(t, map[string]bool{"metapack": true})
	// Un content.tar piégé, correctement signé par un éditeur malveillant.
	d := t.TempDir()
	var tb bytes.Buffer
	tw := tar.NewWriter(&tb)
	tw.WriteHeader(&tar.Header{Name: "public/../../pwn.txt", Mode: 0o644, Size: 2, Typeflag: tar.TypeReg})
	tw.Write([]byte("x\n"))
	tw.Close()
	site := filepath.Join(d, "piege")
	os.MkdirAll(filepath.Join(site, "public"), 0o755)
	b.site = site
	o := b.objet()
	o.ID, o.Name = "metablog.piege", "piege"
	if _, err := Emballe(Emballage{SiteDir: site, Objet: o, Cle: b.editeur, Certificat: b.cert,
		Sortie: b.sbx, Maintenant: time.Now()}); err != nil {
		t.Fatal(err)
	}
	// Remplacer le contenu PUIS re-signer, comme le ferait l'attaquant.
	reecrit(t, b.sbx, func(m map[string][]byte) { m["content.tar"] = tb.Bytes() })
	resigne(t, b.sbx, b.editeur)
	p, err := Ouvre(b.sbx, b.ca.Pub, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer p.Ferme()
	if _, err := p.Installe(b.sites, "piege", time.Now()); err == nil {
		t.Fatal("contenu qui sort du site installé")
	}
	if _, err := os.Stat(filepath.Join(b.sites, "..", "pwn.txt")); err == nil {
		t.Fatal("fichier écrit hors du site")
	}
}

// LE METABLOGIZER IMPORTE TOUJOURS NOS PAQUETS : pas de format de plus.
func TestLeMetablogizerImporteLeSbx(t *testing.T) {
	racine, _ := filepath.Abs("../../../secubox-metablogizer/api")
	if _, err := os.Stat(filepath.Join(racine, "publish", "backup.py")); err != nil {
		t.Skip("secubox-metablogizer absent")
	}
	b := nouveauBanc(t, map[string]bool{"metapack": true})
	b.emballe(t)
	dest := t.TempDir()
	script := `
import sys, importlib.util
spec = importlib.util.spec_from_file_location("backup", sys.argv[1])
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
from pathlib import Path
man = m.import_site(Path(sys.argv[2]), Path(sys.argv[3]))
assert (Path(sys.argv[3]) / "aletheia" / "public" / "index.html").exists(), "contenu absent"
print(man["name"], man["objet"]["license"])
`
	out, err := exec.Command("python3", "-c", script, filepath.Join(racine, "publish", "backup.py"), b.sbx, dest).CombinedOutput()
	if err != nil {
		t.Fatalf("%v : %s", err, out)
	}
	if !strings.Contains(string(out), "aletheia CC-BY-SA-4.0") {
		t.Errorf("sortie : %s", out)
	}
}

// resigne : recalcule l'intégrité et la signature (ce que ferait un éditeur).
func resigne(t *testing.T, chemin string, cle ed25519.PrivateKey) {
	t.Helper()
	reecrit(t, chemin, func(m map[string][]byte) {
		var man map[string]any
		json.Unmarshal(m["manifest.json"], &man)
		delete(man, "signature")
		s, _ := sha256Octets(m["content.tar"])
		man["integrite"] = map[string]any{"content.tar": "sha256:" + s}
		msg, err := canonDe(man)
		if err != nil {
			t.Fatal(err)
		}
		man["signature"] = sbxcert.Signe(cle, msg)
		m["manifest.json"], _ = json.Marshal(man)
	})
}
