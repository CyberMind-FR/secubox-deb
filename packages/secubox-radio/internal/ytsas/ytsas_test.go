package ytsas

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func passerelle(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c := Nouveau(srv.URL, 10<<20)
	return c
}

func TestUneEntreeIncompleteNestPasPrete(t *testing.T) {
	for _, e := range []Entree{
		{Complet: 0, Etat: "complete"},
		{Complet: 1, Etat: "downloading"},
		{Complet: 0, Etat: "downloading"},
	} {
		if e.Pret() {
			t.Errorf("%+v est declaree prete", e)
		}
	}
	if !(Entree{Complet: 1, Etat: "complete"}).Pret() {
		t.Error("une entree complete n'est pas prete")
	}
}

// LA RECUPERATION EN COURS N'EST PAS UNE ERREUR : la piste reste dans la file
// avec son etat, et l'on repassera.
func TestUnePisteAbsenteDeLaBibliothequeDitQuElleNestPasPrete(t *testing.T) {
	c := passerelle(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[{"id":"AUTRE","complete":1,"job_status":"complete"}]`))
	})
	if _, err := c.Etat(context.Background(), "MOI"); !errors.Is(err, ErrPasPrete) {
		t.Errorf("erreur = %v, attendu ErrPasPrete", err)
	}
}

// ON ACCEPTE LES DEUX FORMES DE REPONSE plutot que de casser au premier
// changement de la passerelle : une liste nue, ou une liste dans une enveloppe.
func TestLesDeuxFormesDeReponseSontLues(t *testing.T) {
	for nom, corps := range map[string]string{
		"liste nue": `[{"id":"ABC","title":"T","path":"/p","complete":1,"job_status":"complete"}]`,
		"enveloppe": `{"items":[{"id":"ABC","title":"T","path":"/p","complete":1,"job_status":"complete"}]}`,
	} {
		c := passerelle(t, func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(corps))
		})
		e, err := c.Etat(context.Background(), "ABC")
		if err != nil {
			t.Errorf("%s : %v", nom, err)
			continue
		}
		if e.Titre != "T" || !e.Pret() {
			t.Errorf("%s : entree mal lue %+v", nom, e)
		}
	}
}

// ── LE RAPATRIEMENT ─────────────────────────────────────────────────────────

// ON ECRIT DANS UN TEMPORAIRE PUIS ON RENOMME. Sans cela, une coupure en cours
// de route laisserait un fichier tronque que la base declarerait « en cache » :
// la piste passerait, et s'arreterait au milieu.
func TestLeFichierNapparaitQuUneFoisComplet(t *testing.T) {
	c := passerelle(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "video/mp4")
		w.Write([]byte("un clip complet"))
	})
	dir := t.TempDir()
	chemin, mime, n, err := c.Rapatrie(context.Background(), "ABC", dir)
	if err != nil {
		t.Fatal(err)
	}
	if mime != "video/mp4" {
		t.Errorf("mime = %q", mime)
	}
	if n != 15 {
		t.Errorf("%d octets", n)
	}
	if filepath.Base(chemin) != "ABC.mp4" {
		t.Errorf("nom = %q", filepath.Base(chemin))
	}
	// Aucun fichier partiel ne subsiste.
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".part-") {
			t.Errorf("un fichier partiel subsiste : %s", e.Name())
		}
	}
	// Et il n'est pas lisible par tout le monde.
	st, _ := os.Stat(chemin)
	if st.Mode().Perm()&0o007 != 0 {
		t.Errorf("permissions %v : le parc est lisible par tous", st.Mode().Perm())
	}
}

// LA BORNE PAR FICHIER EST DISTINCTE DE CELLE DU PARC : les deux repondent a
// deux questions differentes, et n'en avoir qu'une laisse toujours un trou.
func TestUnFichierTropGrosEstEcarteSansRemplirLeDisque(t *testing.T) {
	c := passerelle(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "video/mp4")
		w.Write(make([]byte, 2048))
	})
	c.OctetsMax = 1024
	dir := t.TempDir()
	_, _, _, err := c.Rapatrie(context.Background(), "GROS", dir)
	if !errors.Is(err, ErrTropGros) {
		t.Fatalf("erreur = %v, attendu ErrTropGros", err)
	}
	// RIEN N'EST LAISSE DERRIERE : c'est tout l'interet de la borne.
	ents, _ := os.ReadDir(dir)
	if len(ents) != 0 {
		t.Errorf("%d fichiers laisses apres un refus", len(ents))
	}
}

func TestUnePasserelleEnPanneRemonteUneErreurLisible(t *testing.T) {
	c := passerelle(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	})
	if _, _, _, err := c.Rapatrie(context.Background(), "X", t.TempDir()); err == nil {
		t.Fatal("une passerelle en panne a ete acceptee")
	} else if !strings.Contains(err.Error(), "502") {
		t.Errorf("erreur peu lisible : %v", err)
	}
}

func TestLExtensionSuitLeTypeAnnonce(t *testing.T) {
	cas := map[string]string{
		"video/mp4":                ".mp4",
		"audio/mpeg":               ".mp3",
		"audio/ogg; codecs=opus":   ".ogg",
		"video/webm":               ".webm",
		"application/octet-stream": ".bin",
		"":                         ".bin",
	}
	for mime, attendu := range cas {
		if got := extensionDe(mime); got != attendu {
			t.Errorf("extensionDe(%q) = %q, attendu %q", mime, got, attendu)
		}
	}
}

func TestLaDemandeEstTransmiseALaPasserelle(t *testing.T) {
	var recu string
	c := passerelle(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/ytsas/add" {
			t.Errorf("chemin = %q", r.URL.Path)
		}
		b := make([]byte, 256)
		n, _ := r.Body.Read(b)
		recu = string(b[:n])
		w.WriteHeader(http.StatusOK)
	})
	if err := c.Demande(context.Background(), "https://youtu.be/ABC"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(recu, "https://youtu.be/ABC") {
		t.Errorf("corps transmis = %q", recu)
	}
}

// LA BORNE DOIT ARRETER LA LECTURE, PAS SEULEMENT REFUSER APRES COUP.
//
// Le test precedent ne verifiait que « rien ne reste apres » — vrai dans les
// deux cas, puisque le temporaire est efface de toute facon. Or sans borne EN
// LECTURE, un fichier de dix gigaoctets serait integralement ecrit avant
// d'etre rejete : le disque se remplit, ce que la borne existe precisement
// pour empecher. C'est la difference entre refuser et ne pas subir.
func TestLaBorneArreteLaLectureEtNeSubitPasLeFichier(t *testing.T) {
	const borne = 4096
	envoye := make(chan int64, 1)
	c := passerelle(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "video/mp4")
		bloc := make([]byte, 4096)
		var total int64
		// Cent fois la borne : si le client lit tout, on le verra.
		for i := 0; i < 100; i++ {
			n, err := w.Write(bloc)
			total += int64(n)
			if err != nil {
				break // le client a coupe : c'est ce qu'on veut
			}
		}
		envoye <- total
	})
	c.OctetsMax = borne
	if _, _, _, err := c.Rapatrie(context.Background(), "GROS", t.TempDir()); !errors.Is(err, ErrTropGros) {
		t.Fatalf("erreur = %v", err)
	}
	select {
	case total := <-envoye:
		// On tolere la mise en tampon du reseau, pas la lecture integrale.
		if total > borne*8 {
			t.Errorf("%d octets consommes pour une borne de %d : le fichier est subi, pas borne",
				total, borne)
		}
	default:
		// Le serveur n'a pas fini d'ecrire : c'est bien que le client a coupe.
	}
}

// LA VERIFICATION QUI MANQUAIT. `/files/{id}` rend du JSON decrivant les
// fichiers, pas les fichiers. La premiere version a pris ces 65 octets pour un
// clip et a marque la piste « en cache » : la radio aurait joue du JSON.
func TestUnJSONNestPasUnMedia(t *testing.T) {
	for mime, media := range map[string]bool{
		"application/json":       false,
		"text/html":              false,
		"application/xml":        false,
		"":                       false,
		"video/mp4":              true,
		"audio/mpeg":             true,
		"audio/ogg; codecs=opus": true,
	} {
		if EstMedia(mime) != media {
			t.Errorf("EstMedia(%q) = %v", mime, !media)
		}
	}
}

// LA PLAGE EST TRANSMISE TELLE QUELLE : c'est elle qui permet de rejoindre le
// direct sans telecharger ce qui precede.
func TestLaPlageEstRelayeeALaPasserelle(t *testing.T) {
	var recue string
	c := passerelle(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/ytsas/stream/ABC" {
			t.Errorf("chemin = %q", r.URL.Path)
		}
		recue = r.Header.Get("Range")
		w.Header().Set("Content-Type", "video/mp4")
		w.Header().Set("Content-Range", "bytes 100-199/1000")
		w.WriteHeader(http.StatusPartialContent)
		w.Write(make([]byte, 100))
	})
	res, err := c.Flux(context.Background(), "ABC", "bytes=100-199")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if recue != "bytes=100-199" {
		t.Errorf("plage transmise = %q", recue)
	}
	if res.StatusCode != http.StatusPartialContent {
		t.Errorf("code relaye = %d", res.StatusCode)
	}
}

func TestUneErreurDeLaPasserelleNestPasRelayeeCommeUnFlux(t *testing.T) {
	c := passerelle(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	if res, err := c.Flux(context.Background(), "X", ""); err == nil {
		res.Body.Close()
		t.Error("un 404 a ete relaye comme un flux")
	}
}
