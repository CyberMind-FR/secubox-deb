package web

import (
	"strings"
	"testing"
)

// UNE EXTENSION QUI N'EST PAS RENDUE EST UNE PIECE JOINTE MORTE. Le magasin sert
// desormais l'audio WebM sous `.weba` ; si le rendu l'ignore, l'adresse reste un
// lien bleu et la note vocale ne se joue nulle part.
func TestUneNoteVocaleWebmDonneUnLecteurAudio(t *testing.T) {
	out := string(Render("/f/12.weba"))
	if !strings.Contains(out, "<audio") {
		t.Errorf("pas de lecteur audio pour .weba :\n%s", out)
	}
	if strings.Contains(out, "<video") {
		t.Errorf("une note vocale rend un lecteur video :\n%s", out)
	}
}

// UN PDF NE SE JOUE PAS : `<embed>` depend d'un greffon du navigateur et d'une
// CSP permissive — il rend une zone vide plus souvent qu'un document (#1114). Le
// repli FIABLE est une FICHE cliquable a icone generique, jamais un embed.
func TestUnPdfRendUneFicheFichierPasUnEmbed(t *testing.T) {
	out := string(Render("Voir /f/12.pdf"))
	if strings.Contains(out, "<embed") {
		t.Errorf("le PDF est rendu en <embed> (peu fiable) :\n%s", out)
	}
	if !strings.Contains(out, `class="jointe jointe-fichier"`) {
		t.Errorf("pas de fiche fichier pour le PDF :\n%s", out)
	}
	if !strings.Contains(out, "/f/12.pdf") {
		t.Errorf("la fiche ne pointe pas le fichier :\n%s", out)
	}
}

// UNE EXTENSION INCONNUE N'EST PAS DU TEXTE MORT : un `.zip`, un `.txt` joint
// doit au moins offrir une fiche a icone generique — pas rester une adresse nue.
func TestUneExtensionInconnueRendUneFicheFichier(t *testing.T) {
	out := string(Render("archive /f/9.zip"))
	if !strings.Contains(out, `class="jointe jointe-fichier"`) {
		t.Errorf("pas de fiche fichier pour une extension inconnue :\n%s", out)
	}
}

// LES DEUX FORMATS QUE LES ENREGISTREURS PRODUISENT, cote a cote — Firefox rend
// de l'Ogg, Chrome du WebM. Les deux doivent aboutir a un lecteur.
func TestLesDeuxFormatsDEnregistrementSePosentEnLecteur(t *testing.T) {
	for adr, balise := range map[string]string{
		"/f/1.ogg":  "<audio",
		"/f/2.weba": "<audio",
		"/f/3.webm": "<video",
	} {
		if out := string(Render(adr)); !strings.Contains(out, balise) {
			t.Errorf("%s ne rend pas %s :\n%s", adr, balise, out)
		}
	}
}

// UN SEUL CHEMIN D'ENVOI. L'enregistreur reutilise `/f/envoi` et `poser` comme
// le trombone. Un second chemin aurait double les garde-fous a tenir, et l'un
// des deux aurait fini par diverger — c'est le defaut que ce test interdit.
func TestLEnregistreurReutiliseLeCheminDuTrombone(t *testing.T) {
	src, err := assets.ReadFile("static/coquille.js")
	if err != nil {
		t.Fatalf("lecture du script : %v", err)
	}
	js := string(src)
	if !strings.Contains(js, "enregistrer") {
		t.Fatal("l'enregistreur est absent du script")
	}
	// Trois DECLENCHEURS d'envoi, UN SEUL endpoint. Le trombone, l'enregistreur
	// audio et l'enregistreur video posent tous vers `/f/envoi` : ce que le test
	// interdit, c'est un endpoint PARALLELE, pas un troisieme bouton. On verifie
	// donc que toutes les occurrences visent bien la meme adresse.
	if n := strings.Count(js, "'/f/envoi'"); n != 3 {
		t.Errorf("%d appels a /f/envoi, attendu 3 (trombone + audio + video)", n)
	}
	// LE MICRO SE RELACHE : sans `stop()` sur les pistes, la diode reste
	// allumee apres l'envoi.
	if !strings.Contains(js, "getTracks") || !strings.Contains(js, "t.stop()") {
		t.Error("les pistes du flux ne sont pas relachees apres l'enregistrement")
	}
	// LE FORMAT EST NEGOCIE : imposer un type que le navigateur ne sait pas
	// produire ferait echouer l'enregistrement en silence.
	if !strings.Contains(js, "isTypeSupported") {
		t.Error("le format n'est pas negocie avec le navigateur")
	}
}

// LES BOUTONS DOIVENT EXISTER DANS LES TROIS EDITEURS. Le script ne se branche
// que sur ce que le gabarit expose : un editeur oublie reste muet, et le defaut
// ne se voit que sur cette page-la.
func TestLesTroisEditeursPortentLesBoutonsDEnregistrement(t *testing.T) {
	for _, nom := range []string{
		"templates/thread.html",  // repondre dans un fil
		"templates/nouveau.html", // ouvrir un fil
		"templates/mp.html",      // message prive
	} {
		src, err := assets.ReadFile(nom)
		if err != nil {
			t.Fatalf("lecture de %s : %v", nom, err)
		}
		g := string(src)
		for _, attendu := range []string{
			`class="tool enregistrer"`,
			`data-mode="audio"`,
			`data-mode="video"`,
			`data-csrf="{{.V.CSRF}}"`, // sans jeton, l'envoi serait refuse
		} {
			if !strings.Contains(g, attendu) {
				t.Errorf("%s ne contient pas %s", nom, attendu)
			}
		}
	}
}
