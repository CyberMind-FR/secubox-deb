package billets

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestUnFilLocalNEstJamaisPublie(t *testing.T) {
	// LA garde de ce paquet. Publier, c'est mettre sur internet ; le faire
	// depuis un fil local serait irrattrapable — c'est lu, indexe, archive.
	var appele bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		appele = true
		w.Write([]byte(`{"success":true,"id":"x","url":"/b/x"}`))
	}))
	defer srv.Close()

	c := &Client{Base: srv.URL, Session: "s", HTTP: srv.Client()}
	_, err := c.Publier(Fil{Titre: "Fil prive", Public: false,
		Messages: []Message{{Auteur: "gk2", Corps: "…", Public: true}}})
	if err == nil {
		t.Error("un fil local a ete publie")
	}
	if appele {
		t.Error("une requete a ete envoyee a billets pour un fil local")
	}
}

func TestSeulsLesMessagesPublicsSontEnvoyes(t *testing.T) {
	var recu string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		recu = string(b)
		w.Write([]byte(`{"success":true,"id":"abc","url":"/b/abc"}`))
	}))
	defer srv.Close()

	c := &Client{Base: srv.URL, HTTP: srv.Client()}
	res, err := c.Publier(Fil{Titre: "Fil public", Public: true,
		Retour: "https://bbs.gk2.secubox.in/t/42", Session: "s", Messages: []Message{
			{Auteur: "gk2", Corps: "ceci est public", Public: true},
			{Auteur: "thomas", Corps: "ADRESSE DE LA GRANGE", Public: false},
			{Auteur: "marie", Corps: "ceci aussi est public", Public: true},
		}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(recu, "ADRESSE DE LA GRANGE") {
		t.Error("un message local a ete transmis a billets")
	}
	if !strings.Contains(recu, "ceci est public") {
		t.Error("un message public n'a pas ete transmis")
	}
	// LE CONTRAT DE BILLETS : `body` et `ref_url`. Le premier jet envoyait
	// `title` et `url` — des champs que billets ignore. La requete passait, un
	// billet VIDE etait cree, et le BBS enregistrait fierement un lien vers
	// lui. billets est un micro-blog : il n'a PAS de champ titre.
	var charge map[string]any
	if err := json.Unmarshal([]byte(recu), &charge); err != nil {
		t.Fatalf("charge illisible : %v", err)
	}
	if _, ok := charge["body"]; !ok {
		t.Errorf("aucun champ `body` : billets refusera ou creera un billet vide — %v", charge)
	}
	if _, ok := charge["title"]; ok {
		t.Error("champ `title` envoye : billets n'en a pas, le titre doit vivre dans le corps")
	}
	if charge["ref_url"] == nil || charge["ref_url"] == "" {
		t.Errorf("aucun `ref_url` : le billet ne renverra pas vers le fil — %v", charge)
	}
	if s, _ := charge["body"].(string); !strings.Contains(s, "Fil public") {
		t.Errorf("le titre du fil n'apparait pas dans le corps : %q", s)
	}
	if res.Pris != 2 || res.Retenus != 1 {
		t.Errorf("comptes errones : %d pris, %d retenus", res.Pris, res.Retenus)
	}
}

func TestSansSessionDOperateurRienNEstPublie(t *testing.T) {
	// LE BBS N'A PAS D'IDENTITE PROPRE CHEZ BILLETS, et c'est voulu.
	//
	// Le noyau SecuBox exige d'un jeton qu'il porte un `jti` correspondant a
	// une session VIVANTE et un `sub` present dans l'annuaire. Un jeton de
	// service forge par le BBS ne peut donc pas passer — la garde est la pour
	// empecher exactement cela.
	//
	// La publication se fait sous l'autorite de L'OPERATEUR : sa propre
	// session SecuBox est relayee. Sans elle, on n'envoie rien.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("une requete a ete envoyee sans session d'operateur")
	}))
	defer srv.Close()
	c := &Client{Base: srv.URL, HTTP: srv.Client()}
	if _, err := c.Publier(Fil{Titre: "T", Public: true,
		Messages: []Message{{Auteur: "a", Corps: "b", Public: true}}}); err == nil {
		t.Error("publication acceptee sans session d'operateur")
	}
}

func TestLaSessionDeLOperateurEstRelayee(t *testing.T) {
	var recuCookie, recuAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recuCookie = r.Header.Get("Cookie")
		recuAuth = r.Header.Get("Authorization")
		w.Write([]byte(`{"success":true,"id":"x","url":"/b/x"}`))
	}))
	defer srv.Close()
	c := &Client{Base: srv.URL, HTTP: srv.Client()}
	_, err := c.Publier(Fil{Titre: "T", Public: true, Retour: "https://bbs/t/1",
		Session:  "jeton-de-session-secubox",
		Messages: []Message{{Auteur: "a", Corps: "b", Public: true}}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(recuCookie, "jeton-de-session-secubox") {
		t.Errorf("session non relayee : Cookie=%q", recuCookie)
	}
	if strings.Contains(recuAuth, "Bearer ") && !strings.Contains(recuAuth, "jeton-de-session-secubox") {
		t.Errorf("un jeton FORGE est encore envoye : %q", recuAuth)
	}
}

func TestUnEchecDeBilletsNEstPasSilencieux(t *testing.T) {
	// Si billets refuse, le BBS ne doit PAS enregistrer que le fil est publie :
	// il afficherait un lien vers une page inexistante.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		w.Write([]byte(`{"detail":"base indisponible"}`))
	}))
	defer srv.Close()
	c := &Client{Base: srv.URL, HTTP: srv.Client()}
	if _, err := c.Publier(Fil{Titre: "T", Public: true, Session: "s",
		Messages: []Message{{Auteur: "a", Corps: "b", Public: true}}}); err == nil {
		t.Error("un echec de billets est passe pour un succes")
	}
}

func TestParDefautLesPseudonymesNeSontPasPublies(t *testing.T) {
	// L'AUTORITE DE L'OPERATEUR EST ANONYMISANTE, et c'est le coeur de
	// l'interet du dispositif.
	//
	// Les membres discutent a l'interieur, sous leur pseudonyme, entre gens qui
	// se connaissent. Ce qui SORT est publie sous l'autorite de celui qui
	// publie — pas sous le nom de chaque intervenant. Sans cela, participer a
	// un fil qui pourrait un jour devenir public reviendrait a accepter d'etre
	// cite nominativement sur internet, ce que personne n'a demande en
	// repondant a une question dans un salon.
	var recu string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		recu = string(b)
		w.Write([]byte(`{"success":true,"id":"x","url":"/b/x"}`))
	}))
	defer srv.Close()

	c := &Client{Base: srv.URL, HTTP: srv.Client()}
	_, err := c.Publier(Fil{Titre: "Un sujet", Public: true, Session: "s",
		Retour: "https://bbs/t/1", Messages: []Message{
			{Auteur: "marie", Corps: "le premier point", Public: true},
			{Auteur: "thomas", Corps: "le second point", Public: true},
		}})
	if err != nil {
		t.Fatal(err)
	}
	for _, pseudo := range []string{"marie", "thomas"} {
		if strings.Contains(recu, pseudo) {
			t.Errorf("le pseudonyme %q a ete publie", pseudo)
		}
	}
	for _, texte := range []string{"le premier point", "le second point"} {
		if !strings.Contains(recu, texte) {
			t.Errorf("le texte %q a disparu de la publication", texte)
		}
	}
}

func TestLAttributionPeutEtreDemandeeExplicitement(t *testing.T) {
	// Nommer les auteurs reste possible — un texte collectif assume peut
	// vouloir ses signatures. Mais c'est une DECISION, jamais le defaut.
	var recu string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		recu = string(b)
		w.Write([]byte(`{"success":true,"id":"x","url":"/b/x"}`))
	}))
	defer srv.Close()

	c := &Client{Base: srv.URL, HTTP: srv.Client()}
	c.Publier(Fil{Titre: "Un sujet", Public: true, Session: "s", Attribuer: true,
		Retour: "https://bbs/t/1", Messages: []Message{
			{Auteur: "marie", Corps: "le premier point", Public: true},
		}})
	if !strings.Contains(recu, "marie") {
		t.Error("l'attribution demandee n'a pas ete appliquee")
	}
}

func TestLesMediasSuiventLeBilletEtLeCorpsEstReecrit(t *testing.T) {
	// Le corps citait `/f/12.png` — un chemin qui ne designe RIEN chez billets,
	// et que le BBS refuserait de toute facon a un lecteur anonyme. Le lecteur
	// voyait donc le chemin en texte, sans image.
	var recus []string
	var corpsFinal string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST" && r.URL.Path == "/admin/api/billets":
			w.Write([]byte(`{"id":"B1","url":"/b/essai"}`))
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/media"):
			r.ParseMultipartForm(1 << 20)
			f, h, err := r.FormFile("file")
			if err != nil {
				w.WriteHeader(400)
				return
			}
			defer f.Close()
			recus = append(recus, h.Filename)
			w.Write([]byte(`{"success":true,"url":"/media/AAA.png"}`))
		case r.Method == "PUT":
			var d map[string]any
			json.NewDecoder(r.Body).Decode(&d)
			corpsFinal, _ = d["body"].(string)
			w.Write([]byte(`{"success":true}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	c := &Client{Base: srv.URL, HTTP: srv.Client()}
	r, err := c.Publier(Fil{
		Session: "s", Titre: "Essai", Public: true, Retour: "/t/1",
		Messages: []Message{{Auteur: "gk2", Corps: "voir /f/12.png", Public: true}},
		Jointes:  []Jointe{{Ref: "/f/12.png", Nom: "photo.png", Mime: "image/png", Contenu: []byte("x")}},
	})
	if err != nil {
		t.Fatalf("publication : %v", err)
	}
	if r.Medias != 1 {
		t.Errorf("medias transferes = %d, attendu 1", r.Medias)
	}
	if len(recus) != 1 || recus[0] != "photo.png" {
		t.Errorf("fichiers recus par billets : %v", recus)
	}
	// LE CORPS EST REECRIT : sans cela le transfert ne servirait a rien, le
	// billet citant toujours une adresse morte.
	if !strings.Contains(corpsFinal, "/media/AAA.png") {
		t.Errorf("le corps n'a pas ete reecrit :\n%s", corpsFinal)
	}
	if strings.Contains(corpsFinal, "/f/12.png") {
		t.Error("l'ancienne adresse subsiste dans le corps")
	}
}

func TestUnMediaRefuseNAnnulePasLaPublication(t *testing.T) {
	// billets ne re-encode pas tous les formats : un son peut etre refuse en
	// 415. Perdre l'ecrit parce qu'une video n'a pas convenu serait un mauvais
	// echange — mais le refus doit se SAVOIR.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && r.URL.Path == "/admin/api/billets" {
			w.Write([]byte(`{"id":"B1","url":"/b/essai"}`))
			return
		}
		w.WriteHeader(415)
	}))
	defer srv.Close()

	c := &Client{Base: srv.URL, HTTP: srv.Client()}
	r, err := c.Publier(Fil{
		Session: "s", Titre: "Essai", Public: true, Retour: "/t/1",
		Messages: []Message{{Auteur: "gk2", Corps: "ecouter /f/7.ogg", Public: true}},
		Jointes:  []Jointe{{Ref: "/f/7.ogg", Nom: "son.ogg", Mime: "audio/ogg", Contenu: []byte("x")}},
	})
	if err != nil {
		t.Fatalf("la publication a echoue a cause d'un media : %v", err)
	}
	if r.BilletID != "B1" {
		t.Error("le billet n'a pas ete publie")
	}
	if r.MediasRefuses != 1 {
		t.Errorf("refus remontes = %d, attendu 1", r.MediasRefuses)
	}
}
