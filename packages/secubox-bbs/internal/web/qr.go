package web

// Codes QR.
//
// Delegue a `qrencode`, present sur la board. Ecrire un encodeur QR a la main
// — masques, correction de Reed-Solomon, versions — represente plusieurs
// centaines de lignes qu'il faudrait ensuite tester et maintenir, pour un
// resultat identique.
//
// L'APPEL NE PASSE PAS PAR UN SHELL : exec.Command recoit des arguments
// separes. Un code d'invitation contenant `; rm -rf /` serait alors un
// argument, pas une commande — mais on le VALIDE quand meme avant, parce que
// se reposer sur un seul niveau de protection pour une donnee qui vient du
// reseau est une habitude qui finit mal.

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os/exec"
	"regexp"
	"time"
)

// Le jeu de caracteres accepte est celui que produit base64 URL-safe, qui est
// ce que nos invitations utilisent. Tout le reste est refuse.
var codeValide = regexp.MustCompile(`^[A-Za-z0-9_\-]{8,128}$`)

func qrSVG(donnee string) ([]byte, error) {
	if !codeValide.MatchString(donnee) {
		return nil, errors.New("donnee refusee pour un code QR")
	}
	ctx, annule := contexteBref()
	defer annule()
	// -t SVG : une image vectorielle, nette a toute taille et sans dependance
	// d'image dans la page. -m 2 : une marge minimale, sans quoi certains
	// lecteurs echouent.
	cmd := exec.CommandContext(ctx, "qrencode", "-t", "SVG", "-m", "2", "-o", "-", donnee)
	var out, errBuf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errBuf
	if err := cmd.Run(); err != nil {
		return nil, errors.New("qrencode indisponible : " + err.Error())
	}
	return out.Bytes(), nil
}

// qr sert le code QR d'une invitation.
//
// L'URL COMPLETE EST CONSTRUITE ICI, a partir du seul code. Accepter une URL
// entiere en parametre ferait de cette page un generateur de QR vers n'importe
// quelle adresse — commode pour qui voudrait faire scanner un lien piege
// depuis un domaine de confiance.
func (s *Server) qr(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.sysopOK(w, r); !ok {
		return
	}
	code := r.URL.Query().Get("code")
	svg, err := qrSVG(code)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Le QR porte une invitation a usage unique : il ne doit etre ni mis en
	// cache par un intermediaire, ni conserve par le navigateur.
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(svg)
}

// contexteBref borne l'appel externe : un qrencode qui ne rend pas la main
// immobiliserait une requete, et le service n'a qu'une poignee de travailleurs.
func contexteBref() (context.Context, func()) {
	return context.WithTimeout(context.Background(), 3*time.Second)
}
