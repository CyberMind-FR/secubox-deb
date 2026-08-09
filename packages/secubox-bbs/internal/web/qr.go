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
	return qrBrut(donnee)
}

// urlValide : une adresse de CE site, construite par nous. Le motif reste
// etroit — pas de fragment, pas de parametres, pas de caracteres inattendus.
var urlValide = regexp.MustCompile(`^https://[a-zA-Z0-9.\-]{3,80}/t/[0-9]{1,12}$`)

// qrTexte rend le code QR d'une adresse de fil.
func qrTexte(url string) ([]byte, error) {
	if !urlValide.MatchString(url) {
		return nil, errors.New("adresse refusee pour un code QR")
	}
	return qrBrut(url)
}

func qrBrut(donnee string) ([]byte, error) {
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
// IL PORTE UNE ADRESSE, PAS LE CODE NU. Un QR qui ne contient qu'un code est
// inutilisable : le telephone affiche une chaine inerte, sans rien a toucher.
// Il faudrait la recopier a la main dans la barre d'adresse en devinant le
// chemin — ce que personne ne fera.
//
// (Le premier jet encodait le code seul alors que ce commentaire affirmait
// deja construire l'adresse. Il decrivait une intention, pas le code.)
//
// L'ADRESSE EST ASSEMBLEE ICI a partir du seul code et de l'hote de la
// requete. Accepter une adresse entiere en parametre ferait de cette page un
// generateur de QR vers n'importe ou — commode pour faire scanner un lien
// piege depuis un domaine de confiance.
func (s *Server) qr(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.sysopOK(w, r); !ok {
		return
	}
	code := r.URL.Query().Get("code")
	if !codeValide.MatchString(code) {
		http.Error(w, "code refuse pour un code QR", http.StatusBadRequest)
		return
	}
	svg, err := s.encoder("https://" + r.Host + "/invite/" + code)
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

// encoder : l'encodeur effectif, remplacable en test.
//
// Sans ce point d'insertion, verifier CE QUE le QR contient imposerait de
// decoder une image — donc un outil de plus, et un test qui ne tournerait pas
// partout. Ici on verifie la donnee transmise, qui est justement ce qui etait
// faux.
func (s *Server) encoder(donnee string) ([]byte, error) {
	if s.encodeQR != nil {
		return s.encodeQR(donnee)
	}
	return qrBrut(donnee)
}
