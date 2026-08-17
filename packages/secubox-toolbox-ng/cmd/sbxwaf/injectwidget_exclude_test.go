package main

import "testing"

// L'exclusion ne retire RIEN au WAF : l'hote reste inspecte. Elle arrete
// seulement l'injection du bandeau dans des applications qui servent leur
// propre politique de securite — laquelle refuse notre script et remplit la
// console de l'utilisateur d'erreurs qui designent notre injection.
func TestApplicationsTiercesExclues(t *testing.T) {
	exclus := []string{"social.gk2.secubox.in", "peertube.gk2.secubox.in"}

	for _, h := range []string{
		"social.gk2.secubox.in",
		"peertube.gk2.secubox.in",
		"media.peertube.gk2.secubox.in", // sous-domaine d'une application exclue
	} {
		if !widgetExcluded(h, exclus) {
			t.Errorf("%s devrait etre exclu de l'injection", h)
		}
	}

	for _, h := range []string{
		"admin.gk2.secubox.in",
		"bbs.gk2.secubox.in",
		"gk2.secubox.in",
		// FRONTIERE SUR LE POINT : un hote qui se TERMINE par le nom d'une
		// application exclue sans en etre un sous-domaine ne doit pas etre
		// exclu — sinon un tiers choisissant son nom nous priverait du bandeau.
		"notsocial.gk2.secubox.in",
	} {
		if widgetExcluded(h, exclus) {
			t.Errorf("%s ne devrait PAS etre exclu", h)
		}
	}
}

// Sans configuration, rien ne change : le comportement existant est preserve.
func TestSansExclusionRienNeChange(t *testing.T) {
	for _, h := range []string{"social.gk2.secubox.in", "admin.gk2.secubox.in"} {
		if widgetExcluded(h, nil) || widgetExcluded(h, []string{""}) {
			t.Errorf("%s exclu alors qu'aucune exclusion n'est configuree", h)
		}
	}
}

// Bout en bout : applyWidget ne doit pas modifier le corps d'une application
// exclue. C'est ce test qui protege le comportement, pas seulement le predicat.
func TestApplyWidgetNeTouchePasUneApplicationExclue(t *testing.T) {
	const page = "<html><body>bonjour</body></html>"
	faire := func(exclus []string) string {
		r := reponseHTML(page)
		applyWidget(r, "social.gk2.secubox.in", "https://admin.gk2.secubox.in",
			[]string{"gk2.secubox.in"}, exclus)
		return lireCorps(r)
	}
	if got := faire([]string{"social.gk2.secubox.in"}); got != page {
		t.Fatalf("corps modifie alors que l'hote est exclu :\n%s", got)
	}
	if got := faire(nil); got == page {
		t.Fatal("sans exclusion, le bandeau aurait du etre injecte — le test ne prouve rien")
	}
}
