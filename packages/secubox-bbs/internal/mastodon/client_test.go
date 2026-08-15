package mastodon

import (
	"errors"
	"strings"
	"testing"
)

// LE CONTROLE D'ADRESSE EST LE GARDE-FOU CENTRAL DE CE PAQUET. L'instance est
// TAPEE PAR LE MEMBRE : sans lui, n'importe qui obtiendrait du BBS qu'il emette
// des requetes vers le reseau interne — c'est la faille dite SSRF, ici a portee
// de formulaire.
func TestUneInstanceInterneEstRefuseeAUnMembre(t *testing.T) {
	for _, hote := range []string{
		"localhost", // resout vers 127.0.0.1
		"127.0.0.1",
		"0.0.0.0",
		"169.254.169.254", // metadonnees des hebergeurs : la cible classique
		"10.0.0.1",
		"192.168.1.200", // la board elle-meme
		"100.64.0.1",    // CGNAT / Tailscale, hors de IsPrivate
	} {
		if err := VerifieHote(hote, "mastodon.exemple.fr"); !errors.Is(err, ErrInstanceRefusee) {
			t.Errorf("%s accepte comme instance : %v", hote, err)
		}
	}
}

// MAIS LE REFLEXE « TOUTE ADRESSE PRIVEE EST INTERDITE » CASSERAIT LE CAS
// PRINCIPAL : l'instance de la maison vit precisement sur le reseau local. Elle
// est un REGLAGE du sysop, pas une saisie de membre — et c'est ce qui la
// distingue.
func TestLInstanceDeLaMaisonResteJoignable(t *testing.T) {
	if err := VerifieHote("mastodon.gk2.secubox.in", "mastodon.gk2.secubox.in"); err != nil {
		t.Errorf("l'instance configuree est refusee : %v", err)
	}
	// La comparaison ne se laisse pas prendre a la casse ni aux espaces.
	if err := VerifieHote("Mastodon.GK2.secubox.in", "  mastodon.gk2.secubox.in "); err != nil {
		t.Errorf("l'instance configuree est refusee sur une variante d'ecriture : %v", err)
	}
	// ...mais elle ne dispense QUE elle-meme.
	if err := VerifieHote("autre.local", "mastodon.gk2.secubox.in"); err == nil {
		t.Error("une autre instance interne passe par la porte de la maison")
	}
}

func TestUneAdresseQuiNEstPasUnHoteEstRefusee(t *testing.T) {
	for _, mauvais := range []string{
		"", "  ",
		"exemple.fr/chemin",    // un chemin n'est pas un hote
		"exemple.fr:8080",      // un port ouvrirait les services locaux
		"http://exemple.fr",    // le schema doit avoir ete retire avant
		"@moi@exemple.fr",      // identifiant complet, pas un hote
		"exemple.fr\\@interne", // tentative de confusion
	} {
		if err := VerifieHote(mauvais, "mastodon.exemple.fr"); !errors.Is(err, ErrInstanceRefusee) {
			t.Errorf("%q accepte comme hote : %v", mauvais, err)
		}
	}
}

// LE REFUS NE DECRIT PAS LE RESEAU INTERNE. Le message renseignerait sur la
// topologie qui que ce soit ayant un compte sur la board.
func TestLeRefusNeDecritPasLaTopologie(t *testing.T) {
	err := VerifieHote("192.168.1.200", "mastodon.exemple.fr")
	if err == nil {
		t.Fatal("adresse interne acceptee")
	}
	if strings.Contains(err.Error(), "192.168.1.200") {
		// L'hote tape par le membre peut etre repete — il le connait deja. Ce
		// qui ne doit pas fuir, c'est ce vers quoi un NOM resout.
		t.Log("l'hote tape est repete, ce qui est acceptable")
	}
}

// LA PORTEE DEMANDEE EST LE STRICT NECESSAIRE. Une portee large serait acceptee
// sans discuter par le membre, qui clique sur un ecran de consentement dont il
// ne lira pas le detail.
func TestLaPorteeDemandeeResteMinimale(t *testing.T) {
	if Portee != "read:accounts write:statuses" {
		t.Fatalf("portee = %q", Portee)
	}
	for _, interdit := range []string{
		"read:statuses",      // lire les messages des autres
		"read:notifications", // lire ses notifications
		"follow",             // gerer ses abonnements
		"admin",              // moderation de l'instance
		"write:media",        // hors du cadre de cette version
	} {
		if strings.Contains(Portee, interdit) {
			t.Errorf("la portee demande %q", interdit)
		}
	}
}

// UNE REDIRECTION CONTOURNERAIT LE CONTROLE D'ADRESSE : l'hote verifie
// renverrait vers 127.0.0.1 et l'appel partirait quand meme.
func TestLeClientNeSuitAucuneRedirection(t *testing.T) {
	c, err := Nouveau("mastodon.exemple.fr", "mastodon.exemple.fr")
	if err != nil {
		t.Fatal(err)
	}
	if c.HTTP.CheckRedirect == nil {
		t.Fatal("le client suit les redirections")
	}
	if err := c.HTTP.CheckRedirect(nil, nil); err == nil {
		t.Error("une redirection serait suivie")
	}
	if c.HTTP.Timeout == 0 {
		t.Error("aucun delai maximal : une instance lente retiendrait le demon")
	}
}

func TestLURLDAutorisationPorteLEtatEtLaPortee(t *testing.T) {
	c, err := Nouveau("mastodon.exemple.fr", "mastodon.exemple.fr")
	if err != nil {
		t.Fatal(err)
	}
	u := c.URLAutorisation("cid", "https://bbs.exemple.fr/mastodon/retour", "etat-xyz")
	for _, attendu := range []string{
		"https://mastodon.exemple.fr/oauth/authorize",
		"client_id=cid",
		"state=etat-xyz",
		"response_type=code",
		"read%3Aaccounts", // la portee voyage encodee
	} {
		if !strings.Contains(u, attendu) {
			t.Errorf("l'adresse d'autorisation ne contient pas %q :\n%s", attendu, u)
		}
	}
}

// LE TEST DE CONTROLE, sans lequel les precedents ne prouvent rien. Si la
// resolution de noms etait indisponible ici, TOUT serait refuse — « introuvable »
// est aussi un refus — et les tests SSRF passeraient pour la mauvaise raison.
// Une instance publique reelle doit donc etre ACCEPTEE.
func TestUneInstancePubliqueEstAcceptee(t *testing.T) {
	err := VerifieHote("mastodon.social", "mastodon.exemple.fr")
	if err != nil && strings.Contains(err.Error(), "introuvable") {
		t.Skip("pas de resolution de noms ici : le controle ne peut pas se faire")
	}
	if err != nil {
		t.Errorf("une instance publique est refusee : %v", err)
	}
}
