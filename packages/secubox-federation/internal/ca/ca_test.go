package ca

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-federation/internal/canon"
	"github.com/CyberMind-FR/secubox-deb/secubox-federation/internal/sbxcert"
)

var pro = Politique{Channels: []string{"beta", "stable"}, Rights: map[string]bool{"appstore": true, "waf_pro": true}}

func nouvelleCA(t *testing.T) *Autorite {
	t.Helper()
	d := t.TempDir()
	cle := filepath.Join(d, "secrets", "ca.key")
	if err := Init(cle); err != nil {
		t.Fatal(err)
	}
	a, err := Charge(cle, filepath.Join(d, "ca"), sbxcert.DID)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

type box struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

func nouvelleBox(t *testing.T) box {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	return box{priv, pub}
}

func (b box) demande(t *testing.T, quand time.Time) *Demande {
	d := &Demande{BoxID: sbxcert.DID(b.pub), Pubkey: sbxcert.FormatPub(b.pub), Owner: "CyberMind",
		Tier: "pro", Horodatage: quand.UTC().Format(time.RFC3339)}
	msg, _ := canon.Encode(d.Charge())
	d.Signature = sbxcert.Signe(b.priv, msg)
	return d
}

func TestInitNEcrasePasUneCA(t *testing.T) {
	cle := filepath.Join(t.TempDir(), "ca.key")
	if err := Init(cle); err != nil {
		t.Fatal(err)
	}
	avant, _ := os.ReadFile(cle)
	if err := Init(cle); err == nil {
		t.Fatal("une seconde Init a été acceptée")
	}
	apres, _ := os.ReadFile(cle)
	if string(avant) != string(apres) {
		t.Fatal("la clé de la CA a changé")
	}
	if st, _ := os.Stat(cle); st.Mode().Perm() != 0o600 {
		t.Fatalf("clé en %o, attendu 600", st.Mode().Perm())
	}
}

func TestSansCleLaCANeSeCreePasToute(t *testing.T) {
	_, err := Charge(filepath.Join(t.TempDir(), "absente.key"), t.TempDir(), sbxcert.DID)
	if err == nil || !strings.Contains(err.Error(), "sbxctl ca init") {
		t.Fatalf("attendu un refus qui dit comment faire, pas %v", err)
	}
}

func TestParcoursDemandeEmissionVerification(t *testing.T) {
	a := nouvelleCA(t)
	b := nouvelleBox(t)
	now := time.Now()
	if err := a.Recoit(b.demande(t, now), now); err != nil {
		t.Fatal(err)
	}
	if ds, _ := a.Demandes(); len(ds) != 1 {
		t.Fatalf("%d demandes en file", len(ds))
	}
	c, err := a.Emet(sbxcert.FormatPub(b.pub), "CyberMind", "pro", pro, 365, now)
	if err != nil {
		t.Fatal(err)
	}
	if e := c.Verification(a.Pub, now, nil); !e.Valide {
		t.Fatalf("certificat émis invalide : %s", e.Motif)
	}
	if c.Channels[0] != "stable" || c.Channels[1] != "beta" {
		t.Errorf("canaux non normalisés : %v", c.Channels)
	}
	if ds, _ := a.Demandes(); len(ds) != 0 {
		t.Error("la demande est restée en file après émission")
	}
	// Relu depuis le disque, il se vérifie toujours : le YAML ne réordonne rien.
	relu, err := a.Courant(c.BoxID)
	if err != nil || relu.Serial != c.Serial {
		t.Fatalf("courant : %v %v", relu, err)
	}
	if e := relu.Verification(a.Pub, now, nil); !e.Valide {
		t.Fatalf("relu : %s", e.Motif)
	}
	// Numéros de série croissants, jamais réutilisés.
	c2, _ := a.Emet(sbxcert.FormatPub(b.pub), "CyberMind", "pro", pro, 365, now)
	if c2.Serial == c.Serial {
		t.Fatal("numéro de série réutilisé")
	}
}

func TestLaDemandeProuveLaCle(t *testing.T) {
	a := nouvelleCA(t)
	b, intrus := nouvelleBox(t), nouvelleBox(t)
	now := time.Now()

	d := b.demande(t, now)
	d.Owner = "Quelqu'un d'autre" // modifiée après signature
	if err := a.Recoit(d, now); err == nil {
		t.Error("demande falsifiée acceptée")
	}
	d = intrus.demande(t, now)
	d.BoxID = sbxcert.DID(b.pub) // l'intrus demande au nom de b
	if err := a.Recoit(d, now); err == nil {
		t.Error("demande au nom d'une autre box acceptée")
	}
	if err := a.Recoit(b.demande(t, now.Add(-time.Hour)), now); err == nil {
		t.Error("demande périmée (rejeu) acceptée")
	}
}

func TestUnCertificatAlterneEstRejete(t *testing.T) {
	a := nouvelleCA(t)
	b := nouvelleBox(t)
	c, _ := a.Emet(sbxcert.FormatPub(b.pub), "CyberMind", "community",
		Politique{Channels: []string{"stable"}, Rights: map[string]bool{"appstore": true}}, 365, time.Now())
	c.Tier = "premium"
	c.Channels = []string{"stable", "beta", "alpha"}
	if e := c.Verification(a.Pub, time.Now(), nil); e.Valide {
		t.Fatal("un certificat promu à la main passe la vérification")
	}
	autre := nouvelleCA(t)
	c2, _ := a.Emet(sbxcert.FormatPub(b.pub), "CyberMind", "pro", pro, 365, time.Now())
	if e := c2.Verification(autre.Pub, time.Now(), nil); e.Valide {
		t.Fatal("certificat accepté par une autre autorité")
	}
}

func TestExpirationEtRevocation(t *testing.T) {
	a := nouvelleCA(t)
	b := nouvelleBox(t)
	now := time.Now()
	c, _ := a.Emet(sbxcert.FormatPub(b.pub), "CyberMind", "pro", pro, 10, now)
	if e := c.Verification(a.Pub, now.AddDate(0, 0, 12), nil); e.Valide || !e.Expire {
		t.Errorf("après échéance : %+v", e)
	}
	l, err := a.Revoque(c.Serial, "clé compromise", now)
	if err != nil {
		t.Fatal(err)
	}
	if e := c.Verification(a.Pub, now, l.Series()); e.Valide || !e.Revoque {
		t.Errorf("après révocation : %+v", e)
	}
	// La liste publiée se vérifie, et une liste retouchée ne se vérifie pas.
	y, _ := l.YAML()
	if _, err := VerifieCRL(y, a.Pub); err != nil {
		t.Fatal(err)
	}
	falsifiee := strings.Replace(string(y), c.Serial, "SBX-2026-9999", 1)
	if _, err := VerifieCRL([]byte(falsifiee), a.Pub); err == nil {
		t.Fatal("liste de révocation falsifiée acceptée")
	}
	if _, err := a.Revoque("SBX-2026-4242", "", now); err == nil {
		t.Error("révocation d'un numéro jamais émis acceptée")
	}
}

func TestRenouvellementAvecPreuve(t *testing.T) {
	a := nouvelleCA(t)
	b, intrus := nouvelleBox(t), nouvelleBox(t)
	now := time.Now()
	c, _ := a.Emet(sbxcert.FormatPub(b.pub), "CyberMind", "pro", pro, 365, now)
	y, _ := c.YAML()
	h := now.UTC().Format(time.RFC3339)
	msg, _ := canon.Encode(ChargeRenouvellement(c.Serial, c.BoxID, h))

	if _, err := a.Renouvelle(&Renouvellement{Certificat: string(y), Horodatage: h,
		Signature: sbxcert.Signe(intrus.priv, msg)}, pro, 365, now, nil); err == nil {
		t.Error("renouvellement sans la clé de la box accepté")
	}
	n, err := a.Renouvelle(&Renouvellement{Certificat: string(y), Horodatage: h,
		Signature: sbxcert.Signe(b.priv, msg)}, pro, 365, now, nil)
	if err != nil {
		t.Fatal(err)
	}
	if n.Serial == c.Serial || n.BoxID != c.BoxID {
		t.Errorf("renouvelé : %s → %s", c.Serial, n.Serial)
	}
	if _, err := a.Renouvelle(&Renouvellement{Certificat: string(y), Horodatage: h,
		Signature: sbxcert.Signe(b.priv, msg)}, pro, 365, now, map[string]bool{c.Serial: true}); err == nil {
		t.Error("renouvellement d'un certificat révoqué accepté")
	}
}

// UNE SEULE AUTORITÉ DE CONFIANCE : ce que la CA Go signe, le code Python de
// secubox-annuaire (canonical_bytes + verify) doit le reconnaître.
func TestLAnnuairePythonVerifieLeCertificat(t *testing.T) {
	racine, _ := filepath.Abs("../../../secubox-annuaire")
	if _, err := os.Stat(filepath.Join(racine, "annuaire", "crypto.py")); err != nil {
		t.Skip("secubox-annuaire absent de l'arbre")
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 absent")
	}
	a := nouvelleCA(t)
	b := nouvelleBox(t)
	c, _ := a.Emet(sbxcert.FormatPub(b.pub), "CyberMind — GK2", "pro", pro, 365, time.Now())
	charge, _ := c.Octets()
	f := filepath.Join(t.TempDir(), "charge.json")
	os.WriteFile(f, charge, 0o600)
	script := `
import json, sys
sys.path.insert(0, sys.argv[1])
from annuaire.crypto import canonical_bytes, verify
brut = open(sys.argv[2], "rb").read()
obj = json.loads(brut)
assert canonical_bytes(obj) == brut, "canonicalisation divergente"
assert verify(sys.argv[3], brut, sys.argv[4]), "signature refusée par l'annuaire"
print("ok")
`
	out, err := exec.Command("python3", "-c", script, racine, f,
		strings.TrimPrefix(sbxcert.FormatPub(a.Pub), "ed25519:"),
		strings.TrimPrefix(c.Signature, "ed25519:")).CombinedOutput()
	if err != nil {
		if strings.Contains(string(out), "ModuleNotFoundError") {
			t.Skipf("dépendances Python absentes : %s", out)
		}
		t.Fatalf("%v : %s", err, out)
	}
}
