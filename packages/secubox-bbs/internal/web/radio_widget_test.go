package web

import (
	"bytes"
	"html/template"
	"strings"
	"testing"

	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/store"
)

// LE WIDGET RADIO N'APPARAÎT QUE SI RadioBase EST CONFIGURÉ (#1131m). Sans lui,
// le rail ne porte AUCUN <iframe> radio — on n'incorpore pas un service dont on
// ne connaît pas l'adresse. Avec lui, le rail expose l'iframe /mini et le bouton
// de détachement.
func TestWidgetRadioConditionnelAuRadioBase(t *testing.T) {
	fn := template.FuncMap{
		"rendu": Render, "lien": LienApercu, "date": humain, "taille": octets,
		"glypheSalon": func(string, int) string { return "◆" },
		"vignette":    func(a int64, i string) map[string]any { return map[string]any{"A": a, "I": i} },
		"decalage":    func(n int) string { return "" }, "urlembed": func(s string) string { return s },
	}
	tpl, err := template.New("newsroom.html").Funcs(fn).ParseFS(assets, "templates/newsroom.html")
	if err != nil {
		t.Fatalf("parse : %v", err)
	}
	rend := func(p page) string {
		var b bytes.Buffer
		if err := tpl.ExecuteTemplate(&b, "avradio", p); err != nil {
			t.Fatalf("exécution : %v", err)
		}
		return b.String()
	}

	// SANS RadioBase : rien.
	if out := rend(page{}); strings.Contains(out, "<iframe") || strings.Contains(out, "radiowidget") {
		t.Errorf("widget radio rendu sans RadioBase : %s", out)
	}
	// AVEC RadioBase : le widget EST le micro-lecteur (#1131ae) — juste l'iframe,
	// sans en-tête ni bouton parent. Les boutons média ET le ⧉ « détacher »
	// vivent DANS le lecteur /micro (côté radio), pas dans ce fragment BBS.
	out := rend(page{RadioBase: "https://radio.gk2.secubox.in", Stats: store.Stats{}})
	if !strings.Contains(out, `src="https://radio.gk2.secubox.in/micro"`) {
		t.Errorf("l'iframe du rail ne pointe pas /micro : %s", out)
	}
	if strings.Contains(out, "radiopop") || strings.Contains(out, "<h3") {
		t.Errorf("le widget ne devrait plus porter d'en-tête ni de bouton parent : %s", out)
	}
	// CSP : pas de style ni d'onclick en ligne.
	if strings.Contains(out, "style=") || strings.Contains(out, "onclick") {
		t.Errorf("style/onclick en ligne — interdit par la CSP : %s", out)
	}
}
