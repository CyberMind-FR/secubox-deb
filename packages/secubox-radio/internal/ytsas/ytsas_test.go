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
	"time"
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
	// On ne mesure PAS les octets « emis » par le serveur : ceux-ci partent
	// dans le tampon socket du noyau (jusqu'a plusieurs Mio, auto-ajuste), donc
	// un serveur peut avoir tout ecrit avant meme que la coupure du client ne
	// remonte — ce qui rendait ce test instable en CI (409600 octets « subis »
	// pour une borne de 4096, alors que le client n'en avait lu que 4097).
	//
	// On teste le comportement OBSERVABLE : le serveur envoie un court prelude
	// (deux fois la borne, qui tient dans n'importe quel tampon) puis BLOQUE en
	// gardant la connexion ouverte, sans jamais la clore ni envoyer d'EOF. Un
	// client BORNE lit borne+1 octets deja en tampon et rend ErrTropGros
	// aussitot. Un client NON borne ferait un io.Copy integral qui resterait
	// bloque a attendre la suite ; le contexte l'interromprait au bout de 5 s
	// et l'erreur ne serait alors PAS ErrTropGros. Borner, c'est ne pas subir.
	ctx, annule := context.WithTimeout(context.Background(), 5*time.Second)
	defer annule()
	c := passerelle(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "video/mp4")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(make([]byte, borne*2))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		<-r.Context().Done() // le client borne coupe : on debloque et on sort
	})
	c.OctetsMax = borne
	if _, _, _, err := c.Rapatrie(ctx, "GROS", t.TempDir()); !errors.Is(err, ErrTropGros) {
		t.Fatalf("erreur = %v (attendu ErrTropGros)", err)
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

// ENUMERER N'EST PAS RAPATRIER. La contrepartie exacte de `Demande` : l'une
// lance un telechargement, l'autre lit une table des matieres. Les confondre
// lancerait cinquante rapatriements la ou l'on voulait afficher une liste.
func TestEnumererLitLaListeSansRienTelecharger(t *testing.T) {
	var chemin, requete string
	c := passerelle(t, func(w http.ResponseWriter, r *http.Request) {
		chemin, requete = r.URL.Path, r.URL.RawQuery
		w.Write([]byte(`{"count":2,"items":[
			{"id":"A","url":"https://www.youtube.com/watch?v=A","title":"Un"},
			{"id":"B","url":"https://www.youtube.com/watch?v=B","title":"Deux"}]}`))
	})
	m, err := c.Enumere(context.Background(), "https://www.youtube.com/playlist?list=PL1", 50)
	if err != nil {
		t.Fatal(err)
	}
	if chemin != "/api/v1/ytsas/playlist" {
		t.Errorf("chemin = %q — ce n'est pas la route d'enumeration", chemin)
	}
	if !strings.Contains(requete, "limite=50") {
		t.Errorf("la borne n'est pas transmise : %q", requete)
	}
	if len(m) != 2 || m[0].Titre != "Un" {
		t.Errorf("morceaux mal lus : %+v", m)
	}
}

// UNE LISTE ILLISIBLE REMONTE SON MOTIF : « erreur » ferait chercher la panne
// du mauvais cote.
func TestUneListeIllisibleRemonteSonMotif(t *testing.T) {
	c := passerelle(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":"playlist vide ou illisible"}`))
	})
	_, err := c.Enumere(context.Background(), "https://www.youtube.com/playlist?list=X", 10)
	if err == nil {
		t.Fatal("une liste illisible a ete acceptee")
	}
	if !strings.Contains(err.Error(), "illisible") {
		t.Errorf("motif perdu : %v", err)
	}
}

// Une source retiree ne reviendra pas : la redemander toutes les vingt
// secondes remplissait le journal et laissait la piste en « recuperation… »
// pour toujours. Elle doit etre reconnue comme DEFINITIVE, donc ecartable.
func TestEchecDefinitifReconnu(t *testing.T) {
	for _, cas := range []struct {
		corps     string
		definitif bool
	}{
		{`{"error":"ERROR: [youtube] J8ftIn4F-2Q: Video unavailable"}`, true},
		{`{"error":"ERROR: [youtube:tab] list=PLX: Unable to download API page: HTTP Error 404: Not Found"}`, true},
		{`{"error":"ERROR: [youtube] abc: Private video. Sign in if you've been granted access"}`, true},
		{`{"error":"This video has been removed by the uploader"}`, true},
		// Passager : on repassera. Ecarter a tort une piste valide est plus
		// grave que de reessayer une fois de trop.
		{`{"error":"connection reset by peer"}`, false},
		{`{"error":"HTTP Error 503: Service Unavailable"}`, false},
		{`{"error":"read tcp: i/o timeout"}`, false},
		{``, false},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte(cas.corps))
		}))
		c := &Client{Base: srv.URL, HTTP: srv.Client()}
		err := c.Demande(context.Background(), "https://youtu.be/ABC")
		srv.Close()

		if err == nil {
			t.Fatalf("aucune erreur pour %q", cas.corps)
		}
		if got := errors.Is(err, ErrIntrouvable); got != cas.definitif {
			t.Errorf("%q : definitif=%v, attendu %v (err=%v)", cas.corps, got, cas.definitif, err)
		}
	}
}

// La raison doit remonter jusqu'a l'operateur : une piste ecartee sans motif
// lisible ne vaut pas mieux qu'une piste bloquee sans explication.
func TestLaRaisonAccompagneLErreur(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`{"error":"ERROR: [youtube] X: Video unavailable"}`))
	}))
	defer srv.Close()
	c := &Client{Base: srv.URL, HTTP: srv.Client()}
	err := c.Demande(context.Background(), "https://youtu.be/X")
	if err == nil || !strings.Contains(err.Error(), "Video unavailable") {
		t.Fatalf("la raison ne remonte pas : %v", err)
	}
}
