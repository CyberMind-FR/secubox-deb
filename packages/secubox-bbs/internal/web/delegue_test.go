package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/store"
)

func TestUnCompteSecuboxSeConnecteAvecSonMotDePasseSecubox(t *testing.T) {
	// UNE SEULE IDENTITE. Sans cela, quelqu'un qui a deja un compte SecuBox
	// devrait en creer un second ici, avec un second mot de passe, pour lire
	// les memes fils — et l'invitation deviendrait une formalite absurde.
	var recu map[string]string
	amont := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&recu)
		if recu["password"] == "le-bon" {
			w.Write([]byte(`{"access_token":"x","token_type":"bearer"}`))
			return
		}
		w.WriteHeader(401)
	}))
	defer amont.Close()

	srv, s := banc(t)
	srv.authAmont = clientAuthHTTP(amont.URL, amont.Client())
	s.SyncExternalUsers([]store.ExternalUser{{Handle: "cedre83", Display: "Cedre", Role: store.RoleMember}})

	if c := connexion(t, srv, "cedre83", "le-bon"); c == nil || c.Value == "" {
		t.Error("connexion refusee avec le mot de passe SecuBox")
	}
	if recu["username"] != "cedre83" {
		t.Errorf("pseudonyme transmis : %q", recu["username"])
	}
	if c := connexion(t, srv, "cedre83", "le-mauvais"); c != nil && c.Value != "" {
		t.Error("connexion acceptee avec un mauvais mot de passe")
	}
}

func TestLeMotDePasseSecuboxNEstJamaisConserve(t *testing.T) {
	// Le BBS transmet et oublie. Garder une empreinte creerait une seconde
	// copie qui deviendrait fausse au premier changement — et survivrait a une
	// revocation.
	amont := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"access_token":"x"}`))
	}))
	defer amont.Close()
	srv, s := banc(t)
	srv.authAmont = clientAuthHTTP(amont.URL, amont.Client())
	s.SyncExternalUsers([]store.ExternalUser{{Handle: "cedre83", Display: "C", Role: store.RoleMember}})
	connexion(t, srv, "cedre83", "un-secret-reconnaissable")

	if strings.Contains(dumpTout(t, s), "un-secret-reconnaissable") {
		t.Error("le mot de passe se trouve dans la base du BBS")
	}
	uid, _ := s.UserByHandle("cedre83")
	if srv.Auth().Verify(uid, "un-secret-reconnaissable") {
		t.Error("une empreinte locale a ete posee")
	}
}

func TestSiSecuboxEstInjoignableLaConnexionEchoueFerme(t *testing.T) {
	// Fermer, jamais retomber sur autre chose. Un service d'authentification
	// injoignable ne doit pas ouvrir la porte « en attendant ».
	srv, s := banc(t)
	srv.authAmont = clientAuthHTTP("http://127.0.0.1:1", nil)
	s.SyncExternalUsers([]store.ExternalUser{{Handle: "cedre83", Display: "C", Role: store.RoleMember}})
	if c := connexion(t, srv, "cedre83", "peu importe"); c != nil && c.Value != "" {
		t.Error("session ouverte alors que SecuBox est injoignable")
	}
}

func TestUnCompteLocalNInterrogeJamaisSecubox(t *testing.T) {
	// Un membre venu par invitation a son mot de passe ICI. L'envoyer a
	// secubox-auth le divulguerait a un service qui n'a rien a en faire.
	var appele bool
	amont := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		appele = true
		w.Write([]byte(`{"access_token":"x"}`))
	}))
	defer amont.Close()
	srv, s := banc(t)
	srv.authAmont = clientAuthHTTP(amont.URL, amont.Client())
	uid, _ := s.CreateUser("marie", "Marie", store.RoleMember)
	srv.Auth().SetPassword(uid, "une phrase de passe assez longue")

	connexion(t, srv, "marie", "une phrase de passe assez longue")
	if appele {
		t.Error("le mot de passe d'un membre local a ete transmis a secubox-auth")
	}
}

func dumpTout(t *testing.T, s *store.Store) string {
	t.Helper()
	c, _ := s.Users()
	var b strings.Builder
	for _, u := range c {
		b.WriteString(u.Handle + u.Display + string(u.Role))
	}
	return b.String()
}
