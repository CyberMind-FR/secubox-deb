package sbxobj

import (
	"bytes"
	"encoding/json"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-federation/internal/sbxcert"
)

// capture : un faux PNG du shotter (1280×657, comme sur gk2).
func capture(t *testing.T, dir string) string {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 1280, 657))
	for y := 0; y < 657; y++ {
		for x := 0; x < 1280; x++ {
			img.Set(x, y, color.RGBA{uint8(x), uint8(y), 0x80, 0xff})
		}
	}
	p := filepath.Join(dir, "screenshot.png")
	f, _ := os.Create(p)
	png.Encode(f, img)
	f.Close()
	return p
}

func (b *banc) emballeAvecApercu(t *testing.T) {
	t.Helper()
	src := capture(t, t.TempDir())
	if _, err := Emballe(Emballage{SiteDir: b.site, Objet: b.objet(), Domaine: "aletheia.gk2.secubox.in",
		Cle: b.editeur, Certificat: b.cert, Sortie: b.sbx, Maintenant: time.Now(), Apercus: []string{src}}); err != nil {
		t.Fatal(err)
	}
}

func TestApercuEmbarqueSigneEtServiParLeCatalogue(t *testing.T) {
	b := nouveauBanc(t, map[string]bool{"metapack": true})
	b.emballeAvecApercu(t)
	p, err := Ouvre(b.sbx, b.ca.Pub, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer p.Ferme()
	if len(p.Apercus) != 1 {
		t.Fatalf("aperçus : %v", p.Apercus)
	}
	jb, _ := os.ReadFile(p.Apercus[0])
	cfg, err := jpeg.DecodeConfig(bytes.NewReader(jb))
	if err != nil || cfg.Width != 640 || cfg.Height != 328 {
		t.Fatalf("aperçu %v : %d×%d", err, cfg.Width, cfg.Height)
	}
	cat := Catalogue{Dir: t.TempDir()}
	if _, err := cat.Ajoute(b.sbx, p, time.Now()); err != nil {
		t.Fatal(err)
	}
	es, _ := cat.Liste("", nil, nil, nil, time.Now())
	if len(es) != 1 || es[0].Apercus != 1 {
		t.Fatalf("catalogue : %+v", es)
	}
	chemin, err := cat.Apercu("metablog.aletheia", 1)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(chemin); !bytes.Equal(got, jb) {
		t.Error("l'aperçu servi n'est pas celui du paquet")
	}
	if _, err := cat.Apercu("metablog.aletheia", 2); err == nil {
		t.Error("aperçu 2 inexistant servi")
	}
}

func TestApercuAltereRefuse(t *testing.T) {
	b := nouveauBanc(t, map[string]bool{"metapack": true})
	b.emballeAvecApercu(t)
	reecrit(t, b.sbx, func(m map[string][]byte) {
		a := m["apercu-1.jpg"]
		a[len(a)/2] ^= 0xff
	})
	if _, err := Ouvre(b.sbx, b.ca.Pub, nil, time.Now()); err == nil || !strings.Contains(err.Error(), "altéré") {
		t.Fatalf("aperçu altéré accepté : %v", err)
	}
}

func TestApercuGlisseSansSignatureRefuse(t *testing.T) {
	b := nouveauBanc(t, map[string]bool{"metapack": true})
	b.emballe(t)
	var buf bytes.Buffer
	jpeg.Encode(&buf, image.NewRGBA(image.Rect(0, 0, 8, 8)), nil)
	reecrit(t, b.sbx, func(m map[string][]byte) { m["apercu-1.jpg"] = buf.Bytes() })
	if _, err := Ouvre(b.sbx, b.ca.Pub, nil, time.Now()); err == nil {
		t.Fatal("aperçu ajouté hors signature accepté")
	}
}

func TestApercuQuiNEstPasUnJPEGRefuse(t *testing.T) {
	b := nouveauBanc(t, map[string]bool{"metapack": true})
	b.emballeAvecApercu(t)
	// L'éditeur lui-même signe un « aperçu » HTML : signé, mais refusé.
	reecrit(t, b.sbx, func(m map[string][]byte) { m["apercu-1.jpg"] = []byte("<script>alert(1)</script>") })
	resigneTout(t, b)
	if _, err := Ouvre(b.sbx, b.ca.Pub, nil, time.Now()); err == nil || !strings.Contains(err.Error(), "JPEG") {
		t.Fatalf("aperçu non-JPEG accepté : %v", err)
	}
}

func TestTropDApercusRefuse(t *testing.T) {
	b := nouveauBanc(t, map[string]bool{"metapack": true})
	src := capture(t, t.TempDir())
	_, err := Emballe(Emballage{SiteDir: b.site, Objet: b.objet(), Cle: b.editeur, Sortie: b.sbx,
		Maintenant: time.Now(), Apercus: []string{src, src, src, src, src}})
	if err == nil {
		t.Fatal("5 aperçus acceptés")
	}
}

// resigneTout : l'éditeur recalcule l'intégrité de TOUS les membres et signe.
func resigneTout(t *testing.T, b *banc) {
	t.Helper()
	reecrit(t, b.sbx, func(m map[string][]byte) {
		var man map[string]any
		json.Unmarshal(m["manifest.json"], &man)
		delete(man, "signature")
		integ := map[string]any{}
		for n, c := range m {
			if n != "manifest.json" {
				s, _ := sha256Octets(c)
				integ[n] = "sha256:" + s
			}
		}
		man["integrite"] = integ
		msg, err := canonDe(man)
		if err != nil {
			t.Fatal(err)
		}
		man["signature"] = sbxcert.Signe(b.editeur, msg)
		m["manifest.json"], _ = json.Marshal(man)
	})
}
