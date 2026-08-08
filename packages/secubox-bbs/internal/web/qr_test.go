package web

import (
	"os/exec"
	"strings"
	"testing"
)

func TestUneDonneeHorsFormatEstRefusee(t *testing.T) {
	// La donnee finit dans les arguments d'un programme externe. Elle ne passe
	// pas par un shell — mais se reposer sur UN seul niveau de protection pour
	// une donnee venue du reseau est une habitude qui finit mal.
	for _, mauvais := range []string{
		"; rm -rf /", "$(whoami)", "`id`", "code avec espaces",
		"../../etc/passwd", "trop-court", "", strings.Repeat("a", 200),
		"https://ailleurs.example/piege",
	} {
		if _, err := qrSVG(mauvais); err == nil {
			t.Errorf("donnee acceptee : %q", mauvais)
		}
	}
}

func TestUnCodeDInvitationNormalPasse(t *testing.T) {
	if _, err := exec.LookPath("qrencode"); err != nil {
		t.Skip("qrencode absent de cette machine")
	}
	svg, err := qrSVG("aZ3_kd92LmQpX1yTnB7Uc0")
	if err != nil {
		t.Fatalf("code legitime refuse : %v", err)
	}
	if !strings.Contains(string(svg), "<svg") {
		t.Errorf("la sortie n'est pas un SVG : %.60s", svg)
	}
}
