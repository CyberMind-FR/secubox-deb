package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// UN LECTEUR SANS VOLUME EST INFIRME. La `<video id="ecran">` joue le clip mais
// n'expose aucun controle : l'auditeur ne peut ni baisser ni couper le son
// (#1131c). L'accueil DOIT porter un curseur de volume et un bouton muet, et le
// script les cabler sur l'element de lecture.
func TestAccueilPorteUnControleDeVolume(t *testing.T) {
	rec := httptest.NewRecorder()
	(&Serveur{}).accueil(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("accueil = %d", rec.Code)
	}
	corps := rec.Body.String()
	for _, attendu := range []string{`id="volume"`, `id="muet"`} {
		if !contient(corps, attendu) {
			t.Fatalf("le lecteur radio n'expose pas %s : contrôle de volume absent", attendu)
		}
	}
}

// LE CURSEUR DOIT AGIR SUR LE SON, pas rester décoratif : le script lit
// `ecran.volume` et retient le choix. Sans ce câblage, le curseur glisse sans
// effet.
func TestLeScriptCableLeVolume(t *testing.T) {
	src, err := statique.ReadFile("static/radio.js")
	if err != nil {
		t.Fatalf("lecture du script : %v", err)
	}
	js := string(src)
	if !contient(js, "ecran.volume") {
		t.Fatalf("le script ne câble pas le volume (ecran.volume absent)")
	}
}
