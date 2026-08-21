package web

// Rendu des corps de messages.
//
// POURQUOI PAS DE BIBLIOTHEQUE MARKDOWN, ET PAS DE HTML STOCKE
//
// L'editeur de la maquette a l'air d'un traitement de texte, mais ce qu'il
// enregistre est du Markdown, pas du HTML. La difference decide de la surface
// d'attaque :
//
//   - stocker du HTML obligerait a l'ASSAINIR a l'affichage. Un assainisseur
//     est une liste de ce a quoi on a pense ; il vieillit mal et il faut le
//     suivre.
//
//   - stocker du Markdown permet de CONSTRUIRE le HTML. Ce qui n'est pas
//     explicitement produit ici n'existe pas dans la page. C'est une liste
//     blanche, pas une liste noire.
//
// Le rendu est volontairement pauvre : gras, italique, code, titres, listes,
// citations, liens. Ce que la grammaire ne comprend pas s'affiche tel quel.

import (
	"html/template"
	"regexp"
	"strings"
)

// schemasAutorises : la liste est BLANCHE.
//
// `[clic](javascript:…)` est la voie la plus courte entre « un membre peut
// ecrire » et « un membre peut agir a la place d'un autre ». Interdire
// javascript: ne suffirait pas — il faudrait aussi penser a data:, vbscript:,
// et aux prochains. Autoriser trois schemas connus ferme la question.
var schemasAutorises = []string{"http://", "https://", "mailto:"}

func lienSur(url string) bool {
	u := strings.ToLower(strings.TrimSpace(url))
	for _, s := range schemasAutorises {
		if strings.HasPrefix(u, s) {
			return true
		}
	}
	// Un chemin relatif interne reste acceptable : il ne peut pas changer
	// d'origine. Mais pas `//ailleurs.example` qui, lui, en change.
	return strings.HasPrefix(u, "/") && !strings.HasPrefix(u, "//")
}

// Render transforme un corps Markdown en HTML sur.
func Render(src string) template.HTML {
	var b strings.Builder
	lignes := strings.Split(strings.ReplaceAll(src, "\r\n", "\n"), "\n")

	enListe, enCitation := false, false
	fermer := func() {
		if enListe {
			b.WriteString("</ul>\n")
			enListe = false
		}
		if enCitation {
			b.WriteString("</blockquote>\n")
			enCitation = false
		}
	}

	for _, l := range lignes {
		t := strings.TrimRight(l, " \t")
		switch {
		case strings.TrimSpace(t) == "":
			fermer()

		case strings.HasPrefix(t, "## "):
			fermer()
			// h3 et non h1 : le titre du fil occupe deja le premier niveau de
			// la page. Un h1 dans un message casserait la structure du document
			// pour un lecteur d'ecran.
			b.WriteString("<h3>" + string(inline(t[3:])) + "</h3>\n")

		case strings.HasPrefix(t, "- "):
			if enCitation {
				b.WriteString("</blockquote>\n")
				enCitation = false
			}
			if !enListe {
				b.WriteString("<ul>\n")
				enListe = true
			}
			b.WriteString("<li>" + string(inline(t[2:])) + "</li>\n")

		case strings.HasPrefix(t, "> "):
			if enListe {
				b.WriteString("</ul>\n")
				enListe = false
			}
			if !enCitation {
				b.WriteString("<blockquote>\n")
				enCitation = true
			}
			b.WriteString("<p>" + string(inline(t[2:])) + "</p>\n")

		default:
			fermer()
			b.WriteString("<p>" + string(inline(t)) + "</p>\n")
		}
	}
	fermer()
	return template.HTML(b.String())
}

// inline echappe D'ABORD, puis reintroduit les seules balises produites ici.
//
// L'ordre n'est pas negociable : echapper apres aurait neutralise nos propres
// balises, et melanger les deux etapes est exactement l'erreur qui produit les
// failles d'injection.
func inline(s string) template.HTML {
	e := template.HTMLEscapeString(s)
	e = liens(e)
	e = adressesNues(e)
	e = mediasIntegres(e)
	// APRES mediasIntegres : une piece jointe devient un lecteur, elle n'a pas
	// a devenir une fiche. Ce qui reste ici est un lien vers un service.
	e = fichesSecuBox(e)
	e = paires(e, "**", "<strong>", "</strong>")
	e = paires(e, "`", "<code>", "</code>")
	e = paires(e, "*", "<em>", "</em>")
	return template.HTML(e)
}

func paires(s, marque, ouvre, ferme string) string {
	var b strings.Builder
	ouvert := false
	for {
		i := strings.Index(s, marque)
		if i < 0 {
			break
		}
		b.WriteString(s[:i])
		if ouvert {
			b.WriteString(ferme)
		} else {
			b.WriteString(ouvre)
		}
		ouvert = !ouvert
		s = s[i+len(marque):]
	}
	b.WriteString(s)
	out := b.String()
	// Marque impaire : on ne devine pas ou l'auteur voulait fermer, on rend le
	// texte tel qu'il l'a ecrit.
	if ouvert {
		return strings.Replace(out, ouvre, marque, 1)
	}
	return out
}

// mediasIntegres transforme une adresse de piece jointe en LECTEUR.
//
// N'agit que sur NOS adresses (`/f/<n>`) et sur les extensions que le magasin
// accepte. Integrer une adresse quelconque ferait charger une ressource
// distante depuis la page — c'est-a-dire signaler chaque lecteur au serveur
// d'en face, et donner un point d'entree a qui controle ce serveur.
//
// S'execute APRES `liens()` et `adressesNues()`, sur du HTML deja produit : on
// remplace le lien complet, pas l'adresse nue, pour ne pas laisser une ancre
// vide autour du lecteur.
func mediasIntegres(s string) string {
	// DEUX ECRITURES A COUVRIR. Un lien Markdown produit une ancre — c'est ce
	// que pose le bouton d'envoi. Mais on colle aussi l'adresse toute nue, et
	// `adressesNues` ne la transforme pas : elle ne reconnait que http(s).
	// N'en traiter qu'une laisserait la moitie des cas en texte mort.
	//
	// La forme nue est traitee EN PREMIER, en sautant ce qui est deja dans un
	// attribut — sinon on remplacerait l'adresse a l'interieur d'un `href`
	// qu'on vient soi-meme de produire.
	s = nuesIntegrees(s)
	for _, m := range lecteurRe.FindAllStringSubmatch(s, -1) {
		tout, adr := m[0], m[1]
		var balise string
		switch {
		case finitPar(adr, ".png", ".jpg", ".jpeg", ".gif", ".webp"):
			// `loading=lazy` : un fil peut porter vingt images, et les charger
			// toutes avant le premier paragraphe rend la page inutilisable sur
			// une liaison lente.
			balise = `<img class="jointe" src="` + adr + `" alt="" loading="lazy">`
		case finitPar(adr, ".mp3", ".ogg", ".wav", ".flac", ".weba"):
			balise = `<audio class="jointe" controls preload="none" src="` + adr + `"></audio>`
		case finitPar(adr, ".mp4", ".webm", ".ogv"):
			balise = `<video class="jointe" controls preload="none" src="` + adr + `"></video>`
		case finitPar(adr, ".pdf"):
			// PDF joint (#1102/#1114) : PAS d'`<embed>`. Il depend d'un greffon du
			// navigateur et d'une CSP permissive (`object-src`) ; en pratique il
			// rend une zone vide plus souvent qu'un document. Le repli FIABLE est
			// une fiche cliquable a icone generique — toujours visible, jamais
			// muette. Un instantane vaudrait mieux, mais demanderait un rendu PDF
			// cote serveur a l'envoi : a faire plus tard, l'icone tient d'ici la.
			balise = ficheFichier(adr, "📄", "Document PDF")
		case !strings.Contains(adr[3:], "."):
			// Adresse ecrite a la main, sans extension : on ne peut pas savoir.
			// L'image est le cas de loin le plus frequent, et le moins couteux
			// si l'on se trompe — une image cassee se voit, un lecteur audio
			// muet ne se remarque pas.
			balise = `<img class="jointe" src="` + adr + `" alt="" loading="lazy">`
		default:
			// Extension connue du magasin mais NON jouable (zip, txt, doc…) : ni
			// lecteur, ni texte mort. Une fiche a icone generique, comme le PDF.
			balise = ficheFichier(adr, "📎", "Fichier joint")
		}
		s = strings.Replace(s, tout, balise, 1)
	}
	return s
}

// ficheFichier rend une piece jointe NON JOUABLE en carte cliquable a icone
// generique : le repli fiable quand ni image, ni son, ni video ne s'applique
// (PDF, archive, document). L'adresse vient de `lecteurRe` — un `/f/<n>.<ext>`
// deja valide — donc sure a inserer telle quelle.
func ficheFichier(adr, icone, libelle string) string {
	return `<a class="jointe jointe-fichier" href="` + adr + `" target="_blank" rel="noopener">` +
		`<span class="jf-ic" aria-hidden="true">` + icone + `</span>` +
		`<span class="jf-tx"><b>` + libelle + `</b><small>` + adr + `</small></span></a>`
}

// nuesIntegrees transforme `/f/12.png` ecrit tel quel en ancre, pour que la
// suite du traitement la voie comme les autres.
func nuesIntegrees(s string) string {
	var b strings.Builder
	i := 0
	for {
		j := strings.Index(s[i:], "/f/")
		if j < 0 {
			b.WriteString(s[i:])
			break
		}
		deb := i + j
		b.WriteString(s[i:deb])
		if dansAttribut(s, deb) {
			b.WriteString("/f/")
			i = deb + 3
			continue
		}
		fin := deb
		for fin < len(s) && !estSeparateur(s[fin]) {
			fin++
		}
		adr := s[deb:fin]
		for len(adr) > 0 && strings.ContainsRune(".,;:!?)]}'\"", rune(adr[len(adr)-1])) {
			adr = adr[:len(adr)-1]
			fin--
		}
		if nueRe.MatchString(adr) {
			b.WriteString(`<a href="` + adr + `">` + adr + `</a>`)
		} else {
			b.WriteString(adr)
		}
		i = fin
	}
	return b.String()
}

// Une adresse de piece jointe : un NUMERO, avec au plus une extension. Rien
// d'autre ne passe — ni chemin remontant, ni caractere inattendu.
var nueRe = regexp.MustCompile(`^/f/\d+(\.[a-z0-9]{2,5})?$`)

// Une ancre produite par nos soins vers une piece jointe locale.
var lecteurRe = regexp.MustCompile(`<a href="(/f/\d+(?:\.[a-z0-9]+)?)"[^>]*>[^<]*</a>`)

func finitPar(s string, suffixes ...string) bool {
	b := strings.ToLower(s)
	for _, x := range suffixes {
		if strings.HasSuffix(b, x) {
			return true
		}
	}
	// Nos adresses n'ont pas toujours d'extension : `/f/12` est legitime. On
	// laisse alors `mediasIntegres` choisir sur le seul prefixe, en image par
	// defaut — le cas de loin le plus frequent, et le moins couteux s'il se
	// trompe (une image cassee, pas un lecteur muet).
	return false
}

func liens(s string) string {
	var b strings.Builder
	for {
		i := strings.Index(s, "[")
		if i < 0 {
			break
		}
		j := strings.Index(s[i:], "](")
		k := -1
		if j >= 0 {
			k = strings.Index(s[i+j:], ")")
		}
		if j < 0 || k < 0 {
			b.WriteString(s[:i+1])
			s = s[i+1:]
			continue
		}
		texte := s[i+1 : i+j]
		url := s[i+j+2 : i+j+k]
		b.WriteString(s[:i])
		if lienSur(url) {
			if emb, ok := embedYouTubeURL(url); ok {
				b.WriteString(emb)
			} else {
				// noopener : une page ouverte depuis un lien peut sinon manipuler
				// celle qui l'a ouverte. noreferrer : l'adresse d'un fil interne
				// n'a pas a etre transmise au site visite.
				b.WriteString(`<a href="` + template.HTMLEscapeString(url) +
					`" rel="noopener noreferrer">` + texte + `</a>`)
			}
		} else {
			// Ni lien, ni suppression : le lecteur voit ce qui etait ecrit et
			// peut juger lui-meme.
			b.WriteString(texte + " (" + url + ")")
		}
		s = s[i+j+k+1:]
	}
	b.WriteString(s)
	return b.String()
}

// adressesNues transforme « https://… » ecrit tel quel en lien.
//
// Les corps importes en sont pleins — « Retrouvez le podcast sur
// https://bit.ly/… ». Sans cela elles s'affichent en texte mort : il faut les
// selectionner et les recopier, ce qui sur un telephone revient a dire qu'elles
// n'existent pas.
//
// S'execute APRES `liens()`, et saute ce qui est deja dans un `href` : sans ce
// garde-fou, une adresse deja transformee serait reconnue une seconde fois et
// le lien se retrouverait imbrique dans lui-meme.
func adressesNues(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		j := indexSchema(s[i:])
		if j < 0 {
			b.WriteString(s[i:])
			break
		}
		deb := i + j
		b.WriteString(s[i:deb])
		// Deja dans un attribut : on laisse tel quel.
		if dansAttribut(s, deb) {
			fin := deb + 8
			b.WriteString(s[deb:min(fin, len(s))])
			i = min(fin, len(s))
			continue
		}
		fin := deb
		for fin < len(s) && !estSeparateur(s[fin]) {
			fin++
		}
		url := s[deb:fin]
		// La ponctuation finale termine la phrase, pas l'adresse.
		for len(url) > 0 && strings.ContainsRune(".,;:!?)]}'\"", rune(url[len(url)-1])) {
			url = url[:len(url)-1]
			fin--
		}
		if lienSur(url) && len(url) > 10 {
			if emb, ok := embedYouTubeURL(url); ok {
				b.WriteString(emb)
			} else {
				b.WriteString(`<a href="` + url + `" rel="noopener noreferrer">` + url + `</a>`)
			}
		} else {
			b.WriteString(url)
		}
		i = fin
	}
	return b.String()
}

// indexSchema trouve la prochaine adresse en schema autorise.
//
// SEULS http:// et https:// sont reconnus automatiquement. `mailto:` est admis
// quand il est ecrit explicitement, mais le deviner dans du texte produirait
// des liens la ou l'auteur citait simplement une adresse.
func indexSchema(s string) int {
	best := -1
	for _, sch := range []string{"https://", "http://"} {
		if i := strings.Index(s, sch); i >= 0 && (best < 0 || i < best) {
			best = i
		}
	}
	return best
}

func estSeparateur(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '<' || c == '"' || c == '\''
}

// dansAttribut : l'adresse suit-elle un `href="` ou `src="` ?
func dansAttribut(s string, i int) bool {
	deb := i - 12
	if deb < 0 {
		deb = 0
	}
	avant := s[deb:i]
	return strings.Contains(avant, `href="`) || strings.Contains(avant, `src="`)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// urlNueRe : une URL http(s) écrite telle quelle dans un texte.
var urlNueRe = regexp.MustCompile(`https?://[^\s<>"'` + "`" + `]+`)

// LienApercu rend un aperçu de carte en HTML SÛR : le texte est échappé, et les
// URL http(s) deviennent cliquables (#1092). Volontairement léger — pas de
// markdown ni d'embed lourd comme `Render`, juste le lien, pour une carte.
func LienApercu(s string) template.HTML {
	var b strings.Builder
	last := 0
	for _, loc := range urlNueRe.FindAllStringIndex(s, -1) {
		b.WriteString(template.HTMLEscapeString(s[last:loc[0]]))
		u := s[loc[0]:loc[1]]
		eu := template.HTMLEscapeString(u)
		b.WriteString(`<a href="` + eu + `" target="_blank" rel="noopener">` + eu + `</a>`)
		last = loc[1]
	}
	b.WriteString(template.HTMLEscapeString(s[last:]))
	return template.HTML(b.String())
}
