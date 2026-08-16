package web

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
)

var refStatique = regexp.MustCompile(`/static/radio\.(css|js)\?v=[0-9a-f]{12}"`)

// Le cache du WAF garde une URL une heure. Tant que l'accueil demandait
// `/static/radio.css` tout court, un deploiement servait la feuille de la
// version precedente : la page paraissait cassee alors que le paquet etait
// bon. L'empreinte est ce qui rend une nouvelle version demandable.
func TestAccueilEmpreintLesStatiques(t *testing.T) {
	rec := httptest.NewRecorder()
	(&Serveur{}).accueil(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("accueil = %d", rec.Code)
	}
	corps := rec.Body.String()
	if n := len(refStatique.FindAllString(corps, -1)); n != 2 {
		t.Fatalf("feuille et script devraient porter une empreinte, trouve %d", n)
	}
	// UNE URL NUE SUFFIT A RAMENER LE BUG : si l'une des deux y echappe,
	// c'est elle qui sera resservie perimee.
	for _, nu := range []string{`"/static/radio.css"`, `"/static/radio.js"`} {
		if contient(corps, nu) {
			t.Fatalf("%s reste sans empreinte", nu)
		}
	}
}

// Deux contenus differents doivent donner deux URL differentes, sinon
// l'empreinte est decorative.
func TestEmpreinteSuitLeContenu(t *testing.T) {
	rec := httptest.NewRecorder()
	(&Serveur{}).accueil(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	un := refStatique.FindAllString(rec.Body.String(), -1)
	if len(un) != 2 || un[0] == un[1] {
		t.Fatalf("la feuille et le script partagent une empreinte : %v", un)
	}
}

func contient(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
