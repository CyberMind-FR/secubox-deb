package web

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/billets"
	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/ingest"
	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/store"
)

// Modules actifs. Un module eteint disparait du menu ET de ses routes : laisser
// la route repondre alors que l'entree a disparu, c'est la meme illusion que
// « la page d'administration n'est pas dans le menu ».
type Modules struct{ Media, Biblio, MP, Billets, Mastodon bool }

type page struct {
	Titre, Site, Hote, Vue, Q string
	Initiale                  string
	V                         visiteur
	Mod                       Modules
	Stats                     store.Stats
	Cats                      []store.Category
	Threads                   []store.Thread
	Cat                       store.Category
	T                         store.Thread
	Posts                     []postView
	Err, Invite               string
	Intro, Vide               string
	Note                      string
	Cards                     []card
	// Medias : la médiathèque du podcaster regroupée par flux (#1056) —
	// sous-dossiers ordonnés par type, épisodes jouables en ligne.
	Medias []PodFeed
	// News : le fil de la rédaction (accueil). Un item est SOIT un fil, SOIT un
	// FLUX groupé du podcaster — un podcast / un livre audio y apparaît une
	// seule fois, pas un dossier par épisode (#1056).
	News []NewsItem
	// Lecteur détaché (#1056) : le pop-out qui continue en fenêtre séparée.
	PlayerFeed                          *PodFeed
	PlayerSrc, PlayerEp, PlayerT, PlayerTitle string
	// « Déposer une source » (#1056 stage 2) : l'adresse déposée et son type
	// déduit, pour pré-remplir le composeur avec un aperçu.
	SourceURL string
	SrcType   SourceType
	// Article collaboratif (#1056 stage 3) : l'article ouvert (Art) et ses
	// contributions (Parts), ou la liste des brouillons (Articles) pour la
	// rédaction.
	Art      store.Article
	Parts    []store.ArticlePart
	Articles []store.Article
	// Edit : formulaire d'edition d'un message (#1091), nil hors de cette page.
	Edit *editForm
	// Billets : la vitrine REELLE du module billets (#1066 phase A) — titre,
	// extrait, date, lien de chaque billet, pas seulement les fils publies
	// depuis le BBS. BilletsErr distingue « le flux n'a pas pu etre lu » de
	// « aucun billet pour l'instant » : les confondre ferait chercher une
	// panne de publication la ou billets.gk2 est simplement injoignable.
	Billets    []billetVue
	BilletsErr string
	// Lu / non-lu des FILS (#1020). A ne pas confondre avec NonLus ci-dessous,
	// qui compte les messages prives — deux notions distinctes, et les nommer
	// pareil aurait garanti qu'on finisse par afficher l'une pour l'autre.
	//
	// FilsNonLus est un ENSEMBLE : un drapeau par fil aurait impose une requete
	// par ligne affichee, et c'est ainsi qu'une fonction de confort devient une
	// cause de lenteur.
	FilsNonLus      map[int64]bool
	FilsNonLusSalon map[int64]int
	TotalFilsNonLus int
	// Journal de moderation, affiche au sysop (#1020).
	Moderations []store.Moderation
	Code, Msg   string
	Integ       store.Integrity
	Sain        bool
	Runs        []store.IngestRun
	Comptes     []store.Compte
	Moi         store.Compte
	// Messagerie (#1008). Convs : la boite de reception ; Fil : la conversation
	// ouverte ; Avec : l'interlocuteur ; Corres : les comptes joignables.
	Convs      []store.ConversationResume
	Fil        []store.Message
	Avec       store.Compte
	AvecAvatar int64
	Corres     []store.Compte
	// Carnet et Annuaire (#1008) : le carnet nomme ce qu'on utilise, l'annuaire
	// est une recherche bornee. Voir internal/store/carnet.go.
	Carnet   []store.Contact
	Annuaire []store.Contact
	// NonLus alimente la pastille de navigation. Evalue a CHAQUE page : un
	// compteur calcule seulement sur /mp ne previendrait de rien, puisqu'il
	// faudrait deja etre sur la page pour le voir.
	NonLus int
	// Module Mastodon (#1008).
	MastoInstance, MastoInvite string
	// Passerelle Mastodon (#1044). MastoCompte porte l'identifiant tel que
	// L'INSTANCE le nomme — jamais un pseudonyme devine a partir du nom local.
	// Le jeton n'apparait pas ici : ce qui s'affiche et ce qui autorise ne
	// voyagent pas dans la meme structure.
	MastoCompte, MastoLieLe string
	MastoLie                bool
	MastoErr, MastoInfo     string
	// Fil distant du compte lie. `Texte` y est du TEXTE BRUT : le contenu
	// vient d'une instance tierce et n'est jamais rendu comme du HTML.
	MastoFil    []PublicationVue
	MastoFilErr string
	// Invites : qui a invite qui. Contrepartie de l'invitation sans quota.
	Invites []store.Invitation
	// VCSS : empreinte de la feuille de style, posee dans son adresse.
	//
	// LE WAF DE LA BOARD SUPPRIME `Cache-Control` ET `ETag` — verifie sur gk2 :
	// la socket et nginx les envoient, sbxwaf ne les transmet pas. Aucun module
	// ne peut donc demander une revalidation, et le navigateur garde ce qu'il a,
	// y compris une feuille d'une version anterieure — sans erreur, sans indice.
	//
	// L'adresse, elle, passe. Le fichier change, l'empreinte change, le
	// navigateur voit une autre ressource. Cela ne depend d'aucun en-tete.
	VCSS string
	// Base : origine publique du site, pour afficher une adresse partageable.
	Base string
}

type postView struct {
	store.Post
	Author, Initiales, Body string
	// Avatar de l'auteur, 0 s'il n'en a pas. Rendu par la MEME requete que le
	// pseudonyme : afficher un visage ne coute pas une lecture de plus.
	Avatar int64
	// Editable : le visiteur courant peut-il editer CE message (#1091) ? Calcule
	// par la meme regle que le magasin (PeutEditer), pour n'afficher le lien que
	// quand il aboutira. CorrigeMod : edite par quelqu'un d'autre que l'auteur.
	Editable   bool
	CorrigeMod bool
}

// editForm porte le formulaire d'edition d'un message (#1091) ; nil hors de
// cette page. Moderation = l'editeur n'est pas l'auteur (correction de sysop),
// pour prevenir en clair « vous corrigez le texte d'un autre ».
type editForm struct {
	PostID, ThreadID int64
	Body             string
	Moderation       bool
}

type card struct {
	Title, Sub, Link, LinkText string
	Pills                      []pill
	// Vignette : adresse d'une miniature, vide s'il n'y en a pas. Glyphe : ce
	// qu'on montre a sa place. LES DEUX EXISTENT parce qu'une video ou un son
	// n'a pas d'image a reduire — et qu'une carte sans rien a gauche casse
	// l'alignement de toute la grille.
	Vignette string
	Glyphe   string
}
type pill struct{ Class, Text string }

func (s *Server) routes() {
	s.mux.Handle("/static/", s.statique(http.FileServer(http.FS(assets))))
	s.mux.HandleFunc("/", s.accueil)
	ConfigurerFiches(s.opt.MediaOrigines)
	s.mux.HandleFunc("/media-vignette", s.servirMediaVignette)
	s.mux.HandleFunc("/media-cover/", s.servirCover)
	s.mux.HandleFunc("/media-fiche", s.servirMediaFiche)
	s.mux.HandleFunc("/lu/tout", s.toutLu)
	s.mux.HandleFunc("/mod/", s.moderer)
	s.mux.HandleFunc("/vignette/", s.servirVignette)
	s.mux.HandleFunc("/c/", s.salon)
	s.mux.HandleFunc("/t/", s.fil)
	s.mux.HandleFunc("/p/", s.edition) // #1091 — /p/{id}/edit
	s.mux.HandleFunc("/login", s.connexion)
	s.mux.HandleFunc("/logout", s.deconnexion)
	s.mux.HandleFunc("/invite/", s.invitation)
	s.mux.HandleFunc("/media", s.media)
	s.mux.HandleFunc("/media/archive/", s.mediaArchiver)
	s.mux.HandleFunc("/player", s.player)
	s.mux.HandleFunc("/article/", s.article)
	s.mux.HandleFunc("/biblio", s.simple("biblio"))
	s.mux.HandleFunc("/mp", s.mp)
	s.mux.HandleFunc("/mp/", s.mp)
	s.mux.HandleFunc("/mp/envoyer", s.mpEnvoyer)
	s.mux.HandleFunc("/mp/annuaire", s.mpAnnuaire)
	s.mux.HandleFunc("/mp/carnet", s.mpCarnet)
	s.mux.HandleFunc("/mastodon", s.mastodon)
	// Le sous-arbre porte les gestes de la passerelle : lier, retour, delier.
	s.mux.HandleFunc("/mastodon/", s.mastodonPasserelle)
	s.mux.HandleFunc("/billets", s.simple("billets"))
	s.mux.HandleFunc("/nouveau", s.nouveau)
	s.mux.HandleFunc("/sysop", s.sysop)
	s.mux.HandleFunc("/sysop/", s.sysopAction)
	s.mux.HandleFunc("/sysop/qr", s.qr)
	s.mux.HandleFunc("/salon/rejoindre", s.rejoindreSalon)
	s.mux.HandleFunc("/compte", s.compte)
	s.mux.HandleFunc("/compte/", s.compteAction)
	s.mux.HandleFunc("/media/ep/", s.mediaEpisode)
	s.mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})
}

// base prepare ce que toute page affiche. `publicOnly` decoule de la SEULE
// question qui compte : l'appelant est-il connecte ?
func (s *Server) base(r *http.Request, vue string) (page, bool) {
	v := s.qui(r)
	pub := !v.Connecte
	st, _ := s.st.Stats()
	cats, _ := s.st.Categories(pub)

	// LES SALONS PRIVES DISPARAISSENT ICI, ET NULLE PART AILLEURS (#1044).
	//
	// `base` alimente TOUTES les pages, et `salon()` cherche sa categorie dans
	// cette meme liste : filtrer a cet unique endroit ferme donc le rail ET
	// l'acces direct par adresse. Un salon retire de la liste fait tomber
	// `salon()` sur son `p.Cat.ID == 0`, donc sur un 404.
	//
	// 404 ET NON 403, ET C'EST LE POINT. Un 403 confirmerait que le salon
	// existe — c'est precisement ce qu'un salon prive ne doit pas laisser
	// deviner. Pour qui n'y a pas acces, il n'existe pas.
	//
	// SI LA REQUETE ECHOUE, ON CACHE TOUT CE QUI EST PRIVE plutot que rien :
	// `SalonsCachesPour` rend une liste d'exclusion, et l'erreur ignoree cache
	// trop, jamais trop peu.
	if caches, err := s.st.SalonsCachesPour(v.ID, v.Sysop()); err == nil {
		if len(caches) > 0 {
			gardes := cats[:0]
			for _, c := range cats {
				if !caches[c.ID] {
					gardes = append(gardes, c)
				}
			}
			cats = gardes
		}
	} else {
		visibles := cats[:0]
		for _, c := range cats {
			if !c.Prive {
				visibles = append(visibles, c)
			}
		}
		cats = visibles
	}
	site := s.opt.Titre
	ini := "B"
	if site != "" {
		ini = strings.ToUpper(site[:1])
	}
	nonLus := 0
	if v.Connecte {
		nonLus, _ = s.st.NonLus(v.ID)
	}
	return page{
		Site: site, Initiale: ini, Hote: r.Host, Vue: vue, V: v, VCSS: s.vCSS,
		Base:  "https://" + r.Host,
		Mod:   Modules{Media: true, Biblio: true, MP: true, Billets: true, Mastodon: true},
		Stats: st, Cats: cats, Titre: site,
		NonLus: nonLus,
	}, pub
}

// rend ecrit la page dans un TAMPON avant de l'envoyer.
//
// Ecrire directement dans la reponse parait plus economique, et c'est un piege :
// une erreur survenue au milieu du gabarit arrive APRES que l'en-tete 200 est
// parti. Le navigateur recoit alors un document tronque presente comme valide.
// C'est exactement ce qui s'est produit ici — une comparaison de types dans le
// gabarit coupait toutes les pages des membres connectes, en silence.
//
// Avec un tampon : soit la page entiere part, soit une erreur franche.
func (s *Server) rend(w http.ResponseWriter, r *http.Request, nom string, p page) {
	t, ok := s.tpl[nom]
	if !ok {
		log.Printf("gabarit inconnu : %s", nom)
		http.Error(w, "erreur interne", http.StatusInternalServerError)
		return
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "layout", p); err != nil {
		log.Printf("rendu de %s : %v", nom, err)
		http.Error(w, "erreur interne", http.StatusInternalServerError)
		return
	}
	s.poseCSRF(w, p.V.CSRF)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Le HTML doit TOUJOURS être revalidé : sans cela le navigateur garde la page
	// (avec son ancien `?v={{.VCSS}}`) par heuristique, et sert donc l'ancienne
	// feuille même après un déploiement — c'est ce qui fait « perdre » un skin
	// fraîchement posé en test à l'aveugle. `no-cache` = revalider avant usage ;
	// combiné à l'empreinte VCSS sur les assets, la page fraîche pointe la feuille
	// fraîche. `private` : jamais dans un cache partagé (contenu authentifié).
	w.Header().Set("Cache-Control", "private, no-cache")
	buf.WriteTo(w)
}

// rendDef rend un gabarit AUTONOME en exécutant un `define` nommé au lieu de
// "layout". L'accueil « rédaction » (#1056 stage 1) ne partage pas la coquille
// à trois colonnes ; il porte sa propre feuille et son propre script. Même
// discipline de tampon que rend : soit la page entière part, soit une erreur
// franche — jamais un document tronqué présenté comme valide.
func (s *Server) rendDef(w http.ResponseWriter, r *http.Request, nom, def string, p page) {
	t, ok := s.tpl[nom]
	if !ok {
		log.Printf("gabarit inconnu : %s", nom)
		http.Error(w, "erreur interne", http.StatusInternalServerError)
		return
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, def, p); err != nil {
		log.Printf("rendu de %s : %v", nom, err)
		http.Error(w, "erreur interne", http.StatusInternalServerError)
		return
	}
	s.poseCSRF(w, p.V.CSRF)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Le HTML doit TOUJOURS être revalidé : sans cela le navigateur garde la page
	// (avec son ancien `?v={{.VCSS}}`) par heuristique, et sert donc l'ancienne
	// feuille même après un déploiement — c'est ce qui fait « perdre » un skin
	// fraîchement posé en test à l'aveugle. `no-cache` = revalider avant usage ;
	// combiné à l'empreinte VCSS sur les assets, la page fraîche pointe la feuille
	// fraîche. `private` : jamais dans un cache partagé (contenu authentifié).
	w.Header().Set("Cache-Control", "private, no-cache")
	buf.WriteTo(w)
}

// poseNonLus renseigne l'etat lu/non-lu de la page (#1020).
//
// UNE SEULE REQUETE POUR TOUTE LA PAGE. Interroger fil par fil aurait produit
// cent aller-retours sur une liste de cent fils — la fonction censee faire
// gagner du temps en aurait coute.
//
// Une erreur de lecture n'est pas fatale : l'indicateur est un CONFORT, et
// perdre la page entiere parce qu'on ne sait pas dire « nouveau » serait un
// mauvais echange. On rend alors une page sans indicateur, ce qui se voit.
func (s *Server) poseNonLus(p *page) {
	if !p.V.Connecte {
		return
	}
	if nl, err := s.st.FilsNonLus(p.V.ID); err == nil {
		p.FilsNonLus = nl
		p.TotalFilsNonLus = len(nl)
	}
	if c, err := s.st.NonLusParSalon(p.V.ID); err == nil {
		p.FilsNonLusSalon = c
	}
}

// toutLu fait retomber le compteur d'un seul geste.
//
// SANS LUI L'INDICATEUR MEURT. Qui revient apres deux semaines a deux cents
// fils non-lus ; s'il faut les ouvrir un par un, il ne le fera pas, et cessera
// de regarder le compteur — qui n'aura plus servi a rien.

// moderer applique un geste de moderation.
//
// UN SEUL POINT D'ENTREE pour tous les gestes. Un handler par verbe aurait
// duplique cinq fois la meme sequence — sysop, POST, anti-rejeu, cible — et il
// aurait suffi d'en oublier une dans le sixieme pour ouvrir une breche.
//
// L'ordre des gardes n'est pas negociable : DROIT, puis METHODE, puis
// ANTI-REJEU. Verifier le jeton avant le droit dirait a un non-sysop si son
// jeton est valide ; verifier la cible avant le droit lui dirait si elle existe.
func (s *Server) moderer(w http.ResponseWriter, r *http.Request) {
	v, ok := s.sysopOK(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if err := s.verifieCSRF(r); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	geste := strings.TrimPrefix(r.URL.Path, "/mod/")
	cible, _ := strconv.ParseInt(r.FormValue("id"), 10, 64)
	var err error

	switch geste {
	case "renommer":
		err = s.st.RenommeFil(v.ID, cible, r.FormValue("titre"))
	case "deplacer":
		salon, _ := strconv.ParseInt(r.FormValue("salon"), 10, 64)
		err = s.st.DeplaceFil(v.ID, cible, salon)
	case "verrouiller":
		err = s.st.VerrouilleFil(v.ID, cible, r.FormValue("etat") == "1")
	case "epingler":
		err = s.st.EpingleFil(v.ID, cible, r.FormValue("etat") == "1")
	case "retirer":
		err = s.st.RetireMessage(v.ID, cible, r.FormValue("motif"))
	case "retablir":
		err = s.st.RetablitMessage(v.ID, cible)
	case "depublier":
		err = s.st.Depublie(v.ID, cible)
	case "salon":
		parent, _ := strconv.ParseInt(r.FormValue("parent"), 10, 64)
		_, err = s.st.CreeSousSalon(v.ID, r.FormValue("slug"),
			r.FormValue("titre"), r.FormValue("desc"), parent)
	case "salon-prive":
		// FERMER OU ROUVRIR UN SALON. Le rang (`min_role_read`) n'est pas
		// touche : les deux se cumulent.
		err = s.st.RendPrive(cible, r.FormValue("etat") == "1")
	case "salon-membre":
		membre, _ := strconv.ParseInt(r.FormValue("membre"), 10, 64)
		if r.FormValue("action") == "retirer" {
			err = s.st.RetireMembre(cible, membre)
		} else {
			err = s.st.AjouteMembre(cible, membre, v.ID)
		}
	case "salon-invite":
		// LE CODE N'EST MONTRE QU'UNE FOIS, ici, a celui qui l'a demande : la
		// base n'en garde que l'empreinte. Le perdre oblige a en emettre un
		// autre, ce qui est le comportement voulu.
		var code string
		code, err = s.st.NouvelleInvitationSalon(cible, v.ID)
		if err == nil {
			http.Redirect(w, r, "/sysop?msg="+url.QueryEscape(
				"invitation au salon : /salon/rejoindre?code="+code), http.StatusSeeOther)
			return
		}
	default:
		http.NotFound(w, r)
		return
	}

	// L'ERREUR EST DITE A L'OPERATEUR, pas seulement journalisee. Un geste de
	// moderation qui echoue en silence laisse croire qu'il a porte — et le
	// moderateur decouvre le contraire quand quelqu'un s'en plaint.
	retour := r.Referer()
	if retour == "" || !strings.HasPrefix(retour, "/") {
		retour = "/"
	}
	sep := "?"
	if strings.Contains(retour, "?") {
		sep = "&"
	}
	if err != nil {
		log.Printf("bbs: moderation %s sur %d par %d : %v", geste, cible, v.ID, err)
		http.Redirect(w, r, retour+sep+"err="+url.QueryEscape(err.Error()),
			http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, retour+sep+"msg="+url.QueryEscape("modération appliquée"),
		http.StatusSeeOther)
}

func (s *Server) toutLu(w http.ResponseWriter, r *http.Request) {
	v := s.qui(r)
	if !v.Connecte {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	// Meme protection anti-rejeu que les autres actions : marquer tout lu
	// efface un etat, et un lien piege ne doit pas pouvoir le declencher.
	if err := s.verifieCSRF(r); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	if err := s.st.MarqueToutLu(v.ID); err != nil {
		log.Printf("bbs: tout marquer lu (%d) : %v", v.ID, err)
	}
	retour := r.Referer()
	if retour == "" || !strings.HasPrefix(retour, "/") {
		retour = "/"
	}
	http.Redirect(w, r, retour, http.StatusSeeOther)
}

func (s *Server) accueil(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	p, pub := s.base(r, "forums")
	p.Threads, _ = s.st.Recent(30, pub)
	// #1056 : la rédaction GROUPE le podcaster par FLUX. Un fil « podcaster »
	// est un épisode ; les montrer tels quels ferait dix dossiers pour un seul
	// livre audio et noierait le reste. On les écarte du fil des fils et on
	// injecte à la place UN dossier par flux (un podcast / un livre audio =
	// un article), classé par son épisode le plus récent — dynamique façon RSS :
	// un nouveau mp3 remonte son flux en tête, sans le dupliquer.
	p.News = s.composerRedaction(p.Threads, pub)
	s.poseRail(&p)
	s.poseNonLus(&p)
	p.Titre = "AletheiaVox"
	s.rendDef(w, r, "newsroom", "newsroom", p)
}

// poseRail remplit la colonne DROITE de la rédaction (derniers billets + articles
// collaboratifs en cours). Partagée par l'accueil ET les salons (#1114) : sans
// elle, « Derniers billets » disparaissait dans les sous-forums et vues salon,
// qui rendent pourtant la même coquille newsroom que l'accueil.
func (s *Server) poseRail(p *page) {
	p.Articles, _ = s.st.Articles("draft", 8)
	if s.bil != nil {
		p.Billets, p.BilletsErr = s.vitrineBillets()
		if len(p.Billets) > 8 {
			p.Billets = p.Billets[:8]
		}
	}
}

// refsDunCorps extrait les identifiants de pièces jointes `/f/NN` cités dans un
// corps de message.
func refsDunCorps(body string) []int64 {
	var ids []int64
	for _, m := range refsJointes.FindAllStringSubmatch(body, -1) {
		if id, err := strconv.ParseInt(m[1], 10, 64); err == nil {
			ids = append(ids, id)
		}
	}
	return ids
}

// propagerPiecesPubliques rend PUBLICS les fichiers cités dans un corps de post
// PUBLIC (#1114) — à n'appeler QUE quand le post/fil est public. Le média
// devient alors aussi accessible qu'un anonyme peut lire le message.
func (s *Server) propagerPiecesPubliques(body string) {
	if ids := refsDunCorps(body); len(ids) > 0 {
		_ = s.st.MarqueFichiersPublics(ids)
	}
}

// backfillPiecesPubliques rattrape le contenu EXISTANT (#1114) : au démarrage,
// il marque publics les fichiers cités par les posts publics des fils publics —
// sans lui, un média déposé avant le correctif resterait 403 pour un anonyme
// alors que son message est public. Idempotent, lancé en tâche de fond.
func (s *Server) backfillPiecesPubliques() {
	fils, err := s.st.Recent(1000000, true) // fils PUBLICS uniquement
	if err != nil {
		return
	}
	var ids []int64
	for _, f := range fils {
		posts, _ := s.st.PublicPostsOf(f.ID)
		for _, p := range posts {
			body, _ := s.st.Body(p)
			ids = append(ids, refsDunCorps(body)...)
		}
	}
	if err := s.st.MarqueFichiersPublics(ids); err != nil {
		log.Printf("bbs: backfill pièces publiques : %v", err)
	}
}

// NewsItem : une entrée de la rédaction — SOIT un fil (discussion / source),
// SOIT un flux groupé du podcaster (podcast / livre audio / série).
type NewsItem struct {
	Feed *PodFeed      // non-nil : dossier de flux groupé (podcaster)
	Fil  *store.Thread // non-nil : dossier de fil ordinaire
	Date int64
	// Cartes de SALON (#1092/#1093) : aperçu du premier message et dernier
	// commentaire (auteur + extrait + date). Vides sur l'accueil.
	Apercu      string
	LastAuteur  string
	LastExtrait string
	LastAt      int64
	// Médias du fil (#1092) : mini-vignettes des pièces jointes du fil et de ses
	// messages, pour la 2ᵉ partie de la carte. Une image /f/12.png devient une
	// miniature, pas le chemin brut « /f/12.png » lu tel quel.
	Medias []cardMedia
}

// cardMedia : un média du fil résumé pour la vignette de carte. Ref est la
// référence telle qu'écrite dans le corps (`/f/12.png`) : elle sert de src.
type cardMedia struct {
	ID   int64
	Ref  string
	Kind string // image | audio | video | file
}

func kindDeMime(mime string) string {
	switch {
	case strings.HasPrefix(mime, "image/"):
		return "image"
	case strings.HasPrefix(mime, "audio/"):
		return "audio"
	case strings.HasPrefix(mime, "video/"):
		return "video"
	default:
		return "file"
	}
}

// sansRefsMedia retire les références de pièces jointes (`/f/12`, `/f/12.png`)
// d'un corps : dans un aperçu de carte, elles s'affichaient en TEXTE BRUT
// (« /f/15.png ») au lieu d'être la miniature rendue à côté (#1092).
func sansRefsMedia(s string) string {
	return strings.TrimSpace(refsJointes.ReplaceAllString(s, ""))
}

// lienMarkdownRe : `[texte](url)` — on garde le TEXTE, on jette l'URL.
var lienMarkdownRe = regexp.MustCompile(`\[([^\]]*)\]\([^)]*\)`)

// cheminMediaNu : une ligne qui n'est QU'un chemin de média (`/media/…`, `/f/…`).
var cheminMediaNu = regexp.MustCompile(`^(?:/media/|/f/)\S+$`)

// resumeDeCorps produit un aperçu PROPRE pour une carte de carrousel ou de flux.
//
// Les passerelles billets recopient le titre en tête du corps, y collent un
// chemin de média nu, un pied « Discuter ce billet sur le BBS » et un lien
// markdown « [Voir chez billets](…) ». Sans nettoyage, la carte affichait tout
// cela tel quel : le chemin brut d'une image et un lien tronqué au lieu d'une
// phrase (#1114). On retire la ligne-titre répétée, les chemins de média nus, le
// pied de passerelle, et on déplie les liens markdown pour n'en garder que le
// texte — puis on recompose une prose d'une seule ligne.
func resumeDeCorps(corps, titre string) string {
	titreN := strings.ToLower(strings.TrimSpace(titre))
	var lignes []string
	for _, ln := range strings.Split(corps, "\n") {
		t := strings.TrimSpace(ln)
		if t == "" {
			continue
		}
		if titreN != "" && strings.ToLower(t) == titreN {
			continue
		}
		if cheminMediaNu.MatchString(t) {
			continue
		}
		if strings.HasPrefix(t, "Discuter ce billet") || strings.HasPrefix(t, "[Voir chez") {
			continue
		}
		t = strings.TrimSpace(lienMarkdownRe.ReplaceAllString(t, "$1"))
		if t == "" {
			continue
		}
		lignes = append(lignes, t)
	}
	return strings.Join(lignes, " ")
}

// composerRedaction mêle les fils NON-podcaster et les flux groupés du
// podcaster en un seul fil trié par date décroissante — les épisodes d'un même
// flux se replient en un dossier unique.
func (s *Server) composerRedaction(fils []store.Thread, pub bool) []NewsItem {
	var out []NewsItem
	for i := range fils {
		if fils[i].Source == "podcaster" {
			continue // replié dans son flux ci-dessous
		}
		out = append(out, NewsItem{Fil: &fils[i], Date: fils[i].LastPostAt})
	}
	feeds, _ := s.mediatheque(2000)
	for i := range feeds {
		out = append(out, NewsItem{Feed: &feeds[i], Date: feeds[i].Date})
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Date > out[b].Date })
	if len(out) > 24 {
		out = out[:24]
	}
	// #1104 : enrichir les cartes RETENUES d'un aperçu (premier message), de ses
	// médias et du dernier commentaire — comme un salon (composerRedactionSalon).
	// Sans cela, une carte de DISCUSSION de l'accueil était vide (titre + auteur
	// seuls), ni vignette ni aperçu. Fait APRÈS tri + plafond : on ne lit que ce
	// qui s'affiche (≤ 24 fils), jamais tout l'accueil.
	for i := range out {
		if out[i].Fil != nil {
			ap, la, lx, lt, medias := s.apercuEtDernier(out[i].Fil.ID, out[i].Fil.Title, pub)
			// Les pièces `/f/NN` sont RÉSERVÉES AUX MEMBRES (servirFichier renvoie
			// 403 à un anonyme). Sur la surface publique on n'émet donc pas leurs
			// refs — sinon des <img> cassés. L'aperçu TEXTE, lui, est déjà filtré
			// public par apercuEtDernier et reste affiché.
			if pub {
				medias = nil
			}
			out[i].Apercu, out[i].LastAuteur = ap, la
			out[i].LastExtrait, out[i].LastAt, out[i].Medias = lx, lt, medias
		}
	}
	return out
}

func (s *Server) salon(w http.ResponseWriter, r *http.Request) {
	slug := strings.TrimPrefix(r.URL.Path, "/c/")
	p, pub := s.base(r, "forums")
	for _, c := range p.Cats {
		if c.Slug == slug {
			p.Cat = c
		}
	}
	if p.Cat.ID == 0 {
		http.NotFound(w, r)
		return
	}
	p.Threads, _ = s.st.Threads(p.Cat.ID, pub)
	// #1056 : un salon dont le contenu vient du podcaster (« émissions ») se
	// rend en MÉDIATHÈQUE — flux en sous-dossiers, épisodes ordonnés par type et
	// jouables — plutôt qu'en liste plate de fils par épisode.
	if podcasterDominant(p.Threads) {
		s.poseRail(&p)
		s.rendMediatheque(w, r, p)
		return
	}
	// #1092 : un salon se rend comme la GAZETTE — ses dossiers en cartes
	// newsroom (aperçu + dernier commentaire), pas en liste plate à trois
	// colonnes. La coquille « poste de travail » reste pour un fil ouvert, le
	// compte, la console ; les salons rejoignent la rédaction.
	p.News = s.composerRedactionSalon(p.Threads, pub)
	s.poseRail(&p)
	p.Titre = p.Cat.Title
	s.rendDef(w, r, "newsroom", "newsroom", p)
}

// composerRedactionSalon rend les fils d'UN salon en cartes de rédaction. À la
// différence de composerRedaction (l'accueil), il n'injecte PAS les flux
// podcaster globaux — ils n'appartiennent pas au salon, et un salon à dominante
// podcaster est déjà parti en médiathèque plus haut. Chaque carte porte son
// aperçu (premier message) et son dernier commentaire (#1092/#1093). `pub`
// force la vue publique : un aperçu ne doit jamais révéler un message local.
func (s *Server) composerRedactionSalon(fils []store.Thread, pub bool) []NewsItem {
	out := make([]NewsItem, 0, len(fils))
	for i := range fils {
		if fils[i].Source == "podcaster" {
			continue
		}
		ap, la, lx, lt, medias := s.apercuEtDernier(fils[i].ID, fils[i].Title, pub)
		out = append(out, NewsItem{
			Fil: &fils[i], Date: fils[i].LastPostAt,
			Apercu: ap, LastAuteur: la, LastExtrait: lx, LastAt: lt,
			Medias: medias,
		})
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Date > out[b].Date })
	return out
}

// apercuEtDernier lit l'aperçu (premier message) et le dernier commentaire d'un
// fil pour sa carte. En vue publique (`pub`), on ne considère QUE les messages
// publics — un aperçu ne doit pas divulguer un message local. Best-effort :
// tout échec de lecture rend des chaînes vides, jamais une panne de page.
func (s *Server) apercuEtDernier(threadID int64, titre string, pub bool) (apercu, lastAuteur, lastExtrait string, lastAt int64, medias []cardMedia) {
	var posts []store.Post
	if pub {
		posts, _ = s.st.PublicPostsOf(threadID)
	} else {
		posts, _ = s.st.PostsOf(threadID)
	}
	if len(posts) == 0 {
		return
	}
	seen := map[int64]bool{}
	for i, p := range posts {
		b, err := s.st.Body(p)
		if err != nil {
			continue
		}
		if i == 0 {
			apercu = extrait(resumeDeCorps(b, titre), 180)
		}
		if i == len(posts)-1 && len(posts) > 1 {
			lastExtrait = extrait(resumeDeCorps(b, titre), 120)
			lastAuteur, _ = s.st.AuteurEtAvatar(p.AuthorID)
			lastAt = p.CreatedAt
		}
		// Les médias sont référencés EN LIGNE dans le corps (`/f/12.png`), pas
		// comme pièces jointes tracées (la base n'en a AUCUNE) : c'est donc dans
		// le texte qu'on les trouve, pour les rendre en miniatures.
		for _, m := range refsJointes.FindAllStringSubmatch(b, -1) {
			id, _ := strconv.ParseInt(m[1], 10, 64)
			if id == 0 || seen[id] {
				continue
			}
			seen[id] = true
			if len(medias) < 8 {
				medias = append(medias, cardMedia{ID: id, Ref: m[0], Kind: kindDeRef(m[0])})
			}
		}
	}
	return
}

// kindDeRef devine le type d'un média à partir de son extension dans la
// référence `/f/12.png`. Sans extension, on parie sur l'image — le cas courant.
func kindDeRef(ref string) string {
	i := strings.LastIndex(ref, ".")
	if i < 0 {
		return "image"
	}
	switch strings.ToLower(ref[i+1:]) {
	case "png", "jpg", "jpeg", "gif", "webp", "avif", "svg":
		return "image"
	case "mp3", "ogg", "wav", "weba", "m4a", "opus":
		return "audio"
	case "mp4", "webm", "mov", "mkv":
		return "video"
	}
	return "file"
}

// media (/media) rend la médiathèque du podcaster en arborescence.
func (s *Server) media(w http.ResponseWriter, r *http.Request) {
	p, _ := s.base(r, "media")
	s.rendMediatheque(w, r, p)
}

// mediaArchiver (#1056 stage 3) : archive vers PeerTube la vidéo d'un fil, via
// ytsas. On résout l'adresse média en id ytsas (ce qui garantit aussi qu'elle
// est en cache), puis on demande la conservation (ytsas route vidéo→PeerTube).
// Membre + CSRF. Best-effort côté réseau, mais l'échec est DIT.
func (s *Server) mediaArchiver(w http.ResponseWriter, r *http.Request) {
	v := s.qui(r)
	if !v.Connecte {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if err := s.verifieCSRF(r); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	if s.ytsas == nil {
		http.Error(w, "raccord ytsas non configuré", http.StatusServiceUnavailable)
		return
	}
	id := idDe(r.URL.Path, "/media/archive/")
	if id == 0 {
		http.NotFound(w, r)
		return
	}
	u, err := s.st.SourceMediaFil(id)
	if err != nil || u == "" {
		http.Error(w, "ce fil n'a pas de vidéo à archiver", http.StatusBadRequest)
		return
	}
	res, err := s.ytsas.Resoudre(u)
	if err != nil || res.VideoID == "" {
		http.Error(w, "ytsas n'a pas pu résoudre la vidéo (réessayez quand le cache est prêt)",
			http.StatusBadGateway)
		return
	}
	if err := s.ytsas.Conserver(res.VideoID); err != nil {
		http.Error(w, "archivage PeerTube refusé : "+err.Error(), http.StatusBadGateway)
		return
	}
	http.Redirect(w, r, "/t/"+itoa64(id), http.StatusSeeOther)
}

// player (/player) est le LECTEUR DÉTACHÉ, destiné à une fenêtre séparée : il
// continue de jouer pendant qu'on navigue dans la fenêtre principale. Avec
// ?feed=<id> il joue tout un flux (playlist + précédent/suivant/continu) ; avec
// ?src=<url> une seule piste. ?ep et ?t reprennent l'épisode et sa position.
func (s *Server) player(w http.ResponseWriter, r *http.Request) {
	p, _ := s.base(r, "player")
	q := r.URL.Query()
	p.PlayerEp = q.Get("ep")
	p.PlayerT = q.Get("t")
	p.PlayerTitle = q.Get("title")
	if fid := q.Get("feed"); fid != "" {
		feeds, _ := s.mediatheque(2000)
		for i := range feeds {
			if strconv.FormatInt(feeds[i].ID, 10) == fid {
				p.PlayerFeed = &feeds[i]
				break
			}
		}
	}
	if p.PlayerFeed == nil {
		p.PlayerSrc = q.Get("src")
	}
	p.Titre = "Lecteur"
	s.rendDef(w, r, "player", "player", p)
}

// rendMediatheque charge les flux du podcaster et rend le gabarit autonome.
func (s *Server) rendMediatheque(w http.ResponseWriter, r *http.Request, p page) {
	p.Medias, _ = s.mediatheque(2000)
	p.Titre = "Médiathèque"
	s.rendDef(w, r, "mediatheque", "mediatheque", p)
}

// podcasterDominant : le salon est-il majoritairement alimenté par le
// podcaster ? On bascule alors sur la médiathèque. Seuil à la majorité stricte
// pour ne pas détourner un salon qui ne ferait que citer un épisode.
func podcasterDominant(ts []store.Thread) bool {
	if len(ts) == 0 {
		return false
	}
	n := 0
	for _, t := range ts {
		if t.Source == "podcaster" {
			n++
		}
	}
	return n*2 > len(ts)
}

func (s *Server) fil(w http.ResponseWriter, r *http.Request) {
	id := idDe(r.URL.Path, "/t/")
	switch {
	case strings.HasSuffix(r.URL.Path, "/reply"):
		s.repondre(w, r, id)
		return
	case strings.HasSuffix(r.URL.Path, "/publier"):
		s.publier(w, r, id)
		return
	case strings.HasSuffix(r.URL.Path, "/mastodon"):
		s.republierMastodon(w, r, id)
		return
	case strings.HasSuffix(r.URL.Path, "/qr"):
		s.qrFil(w, r, id)
		return
	}

	p, pub := s.base(r, "forums")
	t, err := s.st.ThreadByID(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	// LA GARDE DECISIVE. Masquer un fil dans une liste ne suffit pas :
	// l'adresse reste devinable, et un fil local doit repondre 404 — pas 403,
	// qui confirmerait son existence.
	if pub && t.Visibility != store.VisPublic {
		http.NotFound(w, r)
		return
	}

	// OUVRIR UN FIL LE MARQUE LU (#1020). Pose APRES la garde de visibilite :
	// marquer avant aurait laisse une trace de lecture sur un fil que le
	// visiteur n'a pas le droit de voir — et cette trace est un aveu, elle
	// confirmerait par la bande l'existence du fil.
	//
	// L'echec n'interrompt pas l'affichage : ne pas retenir une lecture est un
	// desagrement, ne pas afficher le fil demande est une panne.
	if p.V.Connecte {
		if err := s.st.MarqueLu(p.V.ID, id); err != nil {
			log.Printf("bbs: marquer lu (fil %d, membre %d) : %v", id, p.V.ID, err)
		}
	}

	var posts []store.Post
	if pub {
		posts, _ = s.st.PublicPostsOf(id)
	} else {
		posts, _ = s.st.PostsOf(id)
	}
	for _, po := range posts {
		body, err := s.st.Body(po)
		if err != nil {
			// Un corps divergent est SIGNALE, pas servi. Le lecteur doit savoir
			// que ce message ne correspond plus a ce qui a ete ecrit.
			body = "*(ce message diverge de l'index — prévenez le sysop)*"
		}
		a, av := s.st.AuteurEtAvatar(po.AuthorID)
		p.Posts = append(p.Posts, postView{Post: po, Author: a,
			Initiales: initiales(a), Body: body, Avatar: av,
			Editable:   store.PeutEditer(p.V.ID, p.V.Role, po.AuthorID),
			CorrigeMod: po.EditedAt > 0 && po.EditedBy != po.AuthorID})
	}
	for _, c := range p.Cats {
		if c.ID == t.CategoryID {
			p.Cat = c
		}
	}
	// #1092 : un fil ouvert se lit en GAZETTE — colonne d'article centrée
	// (.lecture), PAS coincée dans la 3ᵉ colonne étroite de la coquille. On
	// n'alimente donc plus la liste des fils voisins (elle forçait la disposition
	// trois colonnes) : la coquille tombe à rail + volet large, où .lecture
	// respire. Le repère de place est désormais la rédaction (accueil/salons).
	p.T, p.Titre = t, t.Title

	// LE BOUTON « REPUBLIER » NE S'AFFICHE QUE S'IL PEUT ABOUTIR (#1044). Un
	// bouton qui mene a « reliez d'abord votre compte » vaut moins que pas de
	// bouton : il promet un geste que la page ne peut pas tenir. La lecture est
	// une recherche par cle primaire — son cout ne se mesure pas ici.
	if p.V.Connecte {
		if c, err := s.st.CompteMastodonDe(p.V.ID); err == nil {
			p.MastoLie = true
			p.MastoCompte = "@" + c.Acct + "@" + c.Instance
		}
	}
	// #1114 : le fil porte désormais le skin newsroom (masthead + rail partagés),
	// pas l'ancienne coquille layout.html. poseRail alimente la colonne droite
	// (derniers billets), rendDef rend le gabarit autonome "fil" (thread.html
	// fournit le corps réutilisé).
	s.poseNonLus(&p)
	s.poseRail(&p)
	s.rendDef(w, r, "fil", "fil", p)
}

func (s *Server) repondre(w http.ResponseWriter, r *http.Request, id int64) {
	if r.Method != http.MethodPost {
		http.Error(w, "methode refusee", http.StatusMethodNotAllowed)
		return
	}
	v := s.qui(r)
	if !v.Connecte {
		http.Error(w, "connexion requise", http.StatusUnauthorized)
		return
	}
	if err := s.verifieCSRF(r); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	t, err := s.st.ThreadByID(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	vis := store.VisLocal
	// On ne peut poser un message public que dans un fil public. Autoriser
	// l'inverse creerait un message qui n'est visible nulle part — et le jour
	// ou le fil deviendrait public, il sortirait sans que personne ne l'ait
	// relu.
	if r.PostFormValue("visibility") == "public" && t.Visibility == store.VisPublic {
		vis = store.VisPublic
	}
	body := strings.TrimSpace(r.PostFormValue("body"))
	if body == "" {
		http.Error(w, "message vide", http.StatusBadRequest)
		return
	}
	if _, err := s.st.Reply(id, v.ID, body, vis); err != nil {
		http.Error(w, "enregistrement impossible", http.StatusInternalServerError)
		return
	}
	if vis == store.VisPublic {
		s.propagerPiecesPubliques(body) // #1114 : média public comme le message
	}
	http.Redirect(w, r, "/t/"+itoa64(id), http.StatusSeeOther)
}

// edition sert la page d'edition d'un message (#1091) : GET pre-remplit,
// POST applique. La regle de droit (auteur pour le sien, sysop pour les autres)
// est verifiee ICI ET dans le magasin — la vue n'est jamais la seule garde.
//
// Un visiteur sans droit reçoit 404, PAS 403 : confirmer l'existence d'un
// message qu'il ne peut pas toucher n'apporte rien et renseigne un curieux.
func (s *Server) edition(w http.ResponseWriter, r *http.Request) {
	if !strings.HasSuffix(r.URL.Path, "/edit") {
		http.NotFound(w, r)
		return
	}
	id := idDe(r.URL.Path, "/p/")
	if id == 0 {
		http.NotFound(w, r)
		return
	}
	v := s.qui(r)
	if !v.Connecte {
		http.Error(w, "connexion requise", http.StatusUnauthorized)
		return
	}
	po, err := s.st.PostByID(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if !store.PeutEditer(v.ID, v.Role, po.AuthorID) {
		http.NotFound(w, r)
		return
	}

	if r.Method == http.MethodPost {
		if err := s.verifieCSRF(r); err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		body := strings.TrimSpace(r.PostFormValue("body"))
		if body == "" {
			http.Error(w, "message vide", http.StatusBadRequest)
			return
		}
		if err := s.st.EditerPost(v.ID, v.Role, id, body); err != nil {
			if errors.Is(err, store.ErrDroitEdition) {
				http.NotFound(w, r)
				return
			}
			http.Error(w, "enregistrement impossible", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/t/"+itoa64(po.ThreadID), http.StatusSeeOther)
		return
	}

	corps, err := s.st.Body(po)
	if err != nil {
		corps = ""
	}
	p, _ := s.base(r, "forums")
	p.Titre = "Éditer un message"
	p.Edit = &editForm{
		PostID: id, ThreadID: po.ThreadID, Body: corps,
		Moderation: v.ID != po.AuthorID,
	}
	s.poseNonLus(&p)
	s.poseRail(&p)
	s.rendDef(w, r, "edition", "pagenr", p)
}

func (s *Server) connexion(w http.ResponseWriter, r *http.Request) {
	p, _ := s.base(r, "login")
	p.Titre = "Connexion"
	if r.Method != http.MethodPost {
		s.rend(w, r, "login", p)
		return
	}
	handle := strings.TrimSpace(r.PostFormValue("handle"))
	id, err := s.st.UserByHandle(handle)
	// MEME REPONSE pour un compte inconnu et un mot de passe faux. Distinguer
	// les deux transformerait le formulaire en annuaire des membres.
	if err != nil || !s.verifie(handle, id, r.PostFormValue("password")) {
		p.Err = "Pseudonyme ou mot de passe incorrect."
		w.WriteHeader(http.StatusUnauthorized)
		s.rend(w, r, "login", p)
		return
	}
	s.st.NoteLogin(id, r.RemoteAddr)
	jeton, err := s.st.NewSession(id, r.RemoteAddr, r.UserAgent())
	if err != nil {
		p.Err = "Session impossible."
		s.rend(w, r, "login", p)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: cookieSession, Value: jeton, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteLaxMode,
		Secure: s.opt.DerriereTLS, MaxAge: 30 * 24 * 3600,
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) deconnexion(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		if c, err := r.Cookie(cookieSession); err == nil {
			s.st.CloseSession(c.Value)
		}
	}
	http.SetCookie(w, &http.Cookie{Name: cookieSession, Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) invitation(w http.ResponseWriter, r *http.Request) {
	code := strings.TrimPrefix(r.URL.Path, "/invite/")
	p, _ := s.base(r, "login")
	p.Titre, p.Invite = "Invitation", code
	if r.Method != http.MethodPost {
		s.rend(w, r, "login", p)
		return
	}
	if err := s.verifieCSRF(r); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	handle := strings.TrimSpace(r.PostFormValue("handle"))
	pw := r.PostFormValue("password")
	// AUCUNE LONGUEUR MINIMALE — retiree sur demande de l'exploitant. Seul le
	// mot de passe vide reste refuse : ce n'est pas une limite de longueur mais
	// la difference entre avoir un mot de passe et ne pas en avoir.
	if pw == "" {
		p.Err = "Mot de passe vide."
		s.rend(w, r, "login", p)
		return
	}
	id, err := s.st.RedeemInvite(code, handle, strings.TrimSpace(r.PostFormValue("display")))
	if err != nil {
		p.Err = "Invitation invalide, expirée ou déjà utilisée."
		s.rend(w, r, "login", p)
		return
	}
	if err := s.auth.SetPassword(id, pw); err != nil {
		p.Err = "Enregistrement du mot de passe impossible."
		s.rend(w, r, "login", p)
		return
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// simple sert les vues encore descriptives. Elles annoncent ce que le module
// fera plutot que de simuler un fonctionnement qui n'existe pas : une page qui
// ment sur son etat coute plus cher qu'une page qui l'avoue.
func (s *Server) simple(vue string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, _ := s.base(r, vue)
		switch vue {
		case "media":
			p.Titre, p.Intro = "Média", "Ce qu'on écoute et regarde, au même endroit que ce qu'on en dit."
			p.Vide = "Aucune passerelle média raccordée pour l'instant."
			p.Note = "Le média n'est pas recopié : le module lit le flux du podcaster et le catalogue PeerTube là où ils sont déjà."
			p.Cards = s.cartesMedia()
		case "biblio":
			p.Titre, p.Intro = "Bibliothèque", "Les fichiers vivent à côté des messages ; le même rsync emporte les deux."
			p.Vide = "Aucun fichier déposé."
			p.Cards = s.cartesBiblio()
		case "billets":
			p.Titre, p.Intro = "Billets", "Le BBS est l'atelier, billets la vitrine."
			p.Vide = "Aucun billet publié pour l'instant."
			p.Billets, p.BilletsErr = s.vitrineBillets()
		}
		s.rend(w, r, "simple", p)
	}
}

// cartesMedia rend les fils deposes par les passerelles media (#1020).
//
// La page annoncait « aucune passerelle raccordee » alors que 222 fils y
// etaient : 122 emissions du podcaster et 100 videos PeerTube. Elle
// n'interrogeait pas la base — meme defaut que la Bibliotheque et les Billets,
// et meme consequence : un message vide en dur est indiscernable d'un vide
// reel, donc personne ne s'apercoit qu'il ment.
func (s *Server) cartesMedia() []card {
	fs, err := s.st.MediasParSource(60)
	if err != nil {
		return []card{{Title: "Lecture impossible",
			Sub: "Les médias n'ont pas pu être lus : " + err.Error()}}
	}
	out := make([]card, 0, len(fs))
	for _, f := range fs {
		// Le NOM DE LA SOURCE est affiche, pas seulement le salon : « podcaster »
		// dit d'ou vient le contenu et donc ou le corriger, ce qu'un titre de
		// salon ne dit pas.
		pills := []pill{{Class: "ok", Text: f.Source}}
		if f.MediaKind != "" {
			pills = append(pills, pill{Class: "", Text: f.MediaKind})
		}
		if f.Visibility == store.VisLocal {
			// Une emission locale ne sort pas de la maison. Le dire evite qu'on
			// s'etonne de ne pas la retrouver publiquement.
			pills = append(pills, pill{Class: "warn", Text: "local"})
		}
		lien, texte := "/t/"+strconv.FormatInt(f.ID, 10), "Ouvrir le fil"
		if f.MediaURL != "" {
			lien, texte = f.MediaURL, "Écouter / regarder"
		}
		out = append(out, card{
			Title:    f.Title,
			Sub:      f.Salon,
			Link:     lien,
			LinkText: texte,
			Pills:    pills,
			// LE GENRE VIENT DE LA SOURCE, pas d'un fichier qu'on aurait ici :
			// une emission du podcaster et une video PeerTube vivent chez eux.
			// On ne peut donc pas en reduire l'image — le glyphe dit au moins
			// de quoi il s'agit avant d'avoir clique.
			Glyphe: glypheDeSource(f.MediaKind),
		})
	}
	return out
}

// cartesBiblio rend la bibliothèque commune (#1020).
//
// La page annonçait « aucun fichier déposé » alors que neuf l'étaient : elle
// n'interrogeait tout simplement pas la base. Un message vide en dur est
// indiscernable d'un vide réel — c'est ce qui a laissé le défaut passer.
//
// UNE ERREUR DE LECTURE NE VIDE PAS LA PAGE EN SILENCE : elle est dite. Rendre
// une liste vide sur erreur reproduirait exactement le défaut qu'on corrige.
func (s *Server) cartesBiblio() []card {
	fs, err := s.st.TousFichiers(100)
	if err != nil {
		return []card{{Title: "Lecture impossible",
			Sub: "La bibliothèque n'a pas pu être lue : " + err.Error()}}
	}
	out := make([]card, 0, len(fs))
	for _, f := range fs {
		genre := "fichier"
		switch {
		case f.EstImage():
			genre = "image"
		case f.EstAudio():
			genre = "son"
		case f.EstVideo():
			genre = "vidéo"
		}
		c := card{
			Title:    f.Name,
			Sub:      "déposé par " + f.Deposant + " · " + tailleLisible(f.Size),
			Link:     "/f/" + strconv.FormatInt(f.ID, 10) + extensionDe(f.Mime),
			LinkText: "Ouvrir",
			Pills:    []pill{{Class: "ok", Text: genre}},
			Glyphe:   glypheDe(genre),
		}
		// SEULES LES IMAGES ONT UNE VIGNETTE. Extraire une image d'une video
		// demanderait ffmpeg — un decodeur complet lance sur un fichier
		// televerse, pour orner une carte. Le rapport n'y est pas.
		if f.EstImage() {
			c.Vignette = "/vignette/" + strconv.FormatInt(f.ID, 10) + ".jpg"
		}
		out = append(out, c)
	}
	return out
}

// billetVue est ce qu'affiche la vitrine des billets (#1066 phase A) : le
// CONTENU REEL du billet — titre, extrait, date, lien — et non plus
// seulement la carte « publié depuis le BBS » que rendait cartesBillets
// (qui ne disait jamais que « 6 message(s) repris »).
type billetVue struct {
	Titre, Resume, Lien string
	Date                int64
	// Medias : mini-vignettes des pièces jointes du billet (/f/NN), relayées via
	// l'origine PUBLIQUE de billets (admise) — plus le chemin brut « /f/23.png »
	// lu en texte dans la vitrine (#1092).
	Medias []string
	// DepuisFil : vrai quand ce billet correspond a un fil publie DEPUIS le
	// BBS — croise par BilletID (voir vitrineBillets), pas par URL, qui peut
	// manquer (#1024). Le lien vers la conversation d'origine n'a de sens que
	// dans ce cas.
	DepuisFil bool
	ThreadID  int64
	Repris    int
}

// vitrineBillets lit le flux REEL du module billets (#1066 phase A).
//
// cartesBillets ne rendait QUE les fils publies DEPUIS le BBS — une poignee
// de billets sur les dizaines que porte le module, puisque billets en reçoit
// aussi ecrits directement chez lui. La page « Billets » du BBS affichait
// donc deux cartes indigentes a la place d'une vitrine.
//
// UNE PANNE DU FLUX EST DITE, PAS MASQUEE. billets.gk2 injoignable et « zero
// billet publié » ne sont PAS le même état : les confondre ferait chercher un
// problème de publication là où le service est simplement injoignable — le
// même piège que documentait deja cartesMedia plus haut.
func (s *Server) vitrineBillets() ([]billetVue, string) {
	if s.opt.BilletsSocket == "" {
		return nil, "module billets non configuré."
	}
	items, err := ingest.DepuisBillets(s.opt.BilletsSocket, s.opt.BilletsBase)
	if err != nil {
		return nil, "le flux de billets n'a pas pu être lu : " + err.Error()
	}
	// CROISEMENT PAR BilletID, l'identifiant que billets a rendu a la
	// publication (voir internal/billets.Client.Publier -> Resultat.BilletID,
	// enregistre par store.MarkPublished) — jamais par URL, absente pour deux
	// billets de gk2 (#1024) : un croisement par URL les aurait donc ratés.
	origine := map[string]store.BilletPublie{}
	if locaux, err := s.st.Billets(500); err == nil {
		for _, b := range locaux {
			if b.BilletID != "" {
				origine[b.BilletID] = b
			}
		}
	}
	out := make([]billetVue, 0, len(items))
	for _, it := range items {
		v := billetVue{Titre: it.Titre, Resume: extrait(sansRefsMedia(it.Corps), 320),
			Lien: it.Lien, Date: it.Date}
		// Mini-vignettes : les /f/NN du billet, absolutisés sur l'origine PUBLIQUE
		// de billets (admise au relais) — plus le chemin brut en texte.
		if s.opt.BilletsBase != "" {
			for _, m := range refsJointes.FindAllString(it.Corps, 6) {
				v.Medias = append(v.Medias, vignetteRelayee(strings.TrimRight(s.opt.BilletsBase, "/")+m))
			}
		}
		if o, ok := origine[it.Ref]; ok {
			v.DepuisFil, v.ThreadID, v.Repris = true, o.ThreadID, o.Repris
		}
		out = append(out, v)
	}
	return out, ""
}

// extrait tronque un corps sur une frontiere de mot, pour ne pas terminer un
// résumé en plein milieu d'une syllabe.
func extrait(s string, n int) string {
	s = strings.TrimSpace(s)
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	coupe := string(r[:n])
	if i := strings.LastIndexAny(coupe, " \n"); i > n/2 {
		coupe = coupe[:i]
	}
	return strings.TrimRight(coupe, " \n") + "…"
}

// glypheDeSource traduit le genre annonce par une passerelle media.
//
// Les genres viennent de sources differentes (podcaster, PeerTube) et ne
// suivent aucune convention commune : on reconnait donc par MOTIF plutot que
// par egalite, sans quoi un « audio/mpeg » et un « podcast » se retrouveraient
// avec le glyphe generique alors qu'on sait tres bien ce qu'ils sont.
func glypheDeSource(genre string) string {
	g := strings.ToLower(genre)
	switch {
	case strings.Contains(g, "video") || strings.Contains(g, "vidéo"):
		return "🎬"
	case strings.Contains(g, "audio") || strings.Contains(g, "podcast") ||
		strings.Contains(g, "episode") || strings.Contains(g, "épisode"):
		return "🎧"
	}
	return "📡"
}

// glypheDe : ce qu'on montre quand il n'y a pas d'image a reduire.
func glypheDe(genre string) string {
	switch genre {
	case "image":
		return "🖼"
	case "son":
		return "🎧"
	case "vidéo":
		return "🎬"
	}
	return "📄"
}

// tailleLisible rend une taille d'octets sous forme courte.
func tailleLisible(n int64) string {
	switch {
	case n >= 1<<20:
		return strconv.FormatInt(n/(1<<20), 10) + " Mio"
	case n >= 1<<10:
		return strconv.FormatInt(n/(1<<10), 10) + " Kio"
	}
	return strconv.FormatInt(n, 10) + " o"
}

func initiales(h string) string {
	h = strings.TrimSpace(h)
	if h == "" {
		return "?"
	}
	if len(h) >= 2 {
		return strings.ToUpper(h[:2])
	}
	return strings.ToUpper(h)
}

func itoa64(i int64) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

// publier envoie un fil vers le module billets.
//
// TROIS GARDES, VOLONTAIREMENT REDONDANTES :
//  1. ici : seul un sysop declenche une publication ;
//  2. ici : le fil doit etre public ;
//  3. dans le client : il refuse de nouveau un fil local, et ne transmet que
//     les messages publics.
//
// La redondance n'est pas un oubli de nettoyage. Une garde d'interface se
// contourne en tapant l'adresse ; une garde de client protege aussi les
// appelants qui viendront plus tard.
func (s *Server) publier(w http.ResponseWriter, r *http.Request, id int64) {
	if r.Method != http.MethodPost {
		http.Error(w, "methode refusee", http.StatusMethodNotAllowed)
		return
	}
	v := s.qui(r)
	if !v.Connecte || v.Role != store.RoleSysop {
		http.Error(w, "reserve au sysop", http.StatusForbidden)
		return
	}
	if err := s.verifieCSRF(r); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	if s.bil == nil {
		http.Error(w, "module billets non configure", http.StatusServiceUnavailable)
		return
	}
	t, err := s.st.ThreadByID(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if t.Visibility != store.VisPublic {
		http.Error(w, "un fil local ne se publie pas : rendez-le public d'abord",
			http.StatusForbidden)
		return
	}

	posts, err := s.st.PostsOf(id)
	if err != nil {
		http.Error(w, "lecture du fil impossible", http.StatusInternalServerError)
		return
	}
	// La session SecuBox de l'operateur est relayee : le BBS n'a pas d'identite
	// propre chez billets, il transmet l'autorite qu'on lui a presentee.
	var session string
	if c, err := r.Cookie("secubox_session"); err == nil {
		session = c.Value
	}
	f := billets.Fil{ID: id, Titre: t.Title, Public: true, Session: session,
		// L'attribution nominative est une DECISION, jamais le defaut :
		// l'autorite de l'operateur est anonymisante.
		Attribuer: r.PostFormValue("attribuer") == "1",
		Retour:    "https://" + r.Host + "/t/" + itoa64(id)}
	for _, p := range posts {
		corps, err := s.st.Body(p)
		if err != nil {
			// Un corps divergent n'est PAS publie : on ne met pas sur internet
			// un texte dont on ne sait plus s'il est celui qui a ete ecrit.
			http.Error(w, "un message diverge de l'index — publication refusee",
				http.StatusConflict)
			return
		}
		f.Messages = append(f.Messages, billets.Message{
			Auteur: s.st.Author(p.AuthorID), Corps: corps,
			Public: p.Visibility == store.VisPublic,
		})
	}

	// LES PIECES JOINTES CITEES SONT RESOLUES ICI, pas dans le client : lui
	// n'a pas acces au magasin, et c'est bien ainsi — il parle a billets, il
	// ne lit pas nos fichiers.
	f.Jointes = s.jointesCitees(f.Messages)

	res, err := s.bil.Publier(f)
	if err != nil {
		// PAS 502. nginx intercepte 502/503/504 (`secubox-waking.conf`) et les
		// remplace par la page de reveil — qui n'accepte que GET et repond 405
		// a un POST. L'erreur reelle etait donc masquee par un « Method Not
		// Allowed » incomprehensible, et j'ai cherche du cote de billets un
		// defaut qui n'y etait pas. 409 dit la meme chose sans etre avale.
		http.Error(w, "publication refusee : "+err.Error(), http.StatusConflict)
		return
	}
	if err := s.st.MarkPublished(id, res.BilletID, res.URL, res.Pris, res.Retenus); err != nil {
		http.Error(w, "billet publie mais lien non enregistre : "+err.Error(),
			http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/t/"+itoa64(id), http.StatusSeeOther)
}

// nouveau : ouvrir un fil.
//
// LA ROUTE MANQUAIT. Le gabarit proposait « Nouveau fil » depuis le premier
// jour et menait a une page introuvable — un defaut que seule une visite de
// l'interface revele, et qu'aucun test ne couvrait puisque tous partaient de
// fils crees directement en base.
func (s *Server) nouveau(w http.ResponseWriter, r *http.Request) {
	v := s.qui(r)
	if !v.Connecte {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	p, _ := s.base(r, "forums")
	p.Titre = "Ouvrir un fil"
	if r.Method != http.MethodPost {
		// #1056 stage 2 : « Déposer une source ». ?src=<url> pré-remplit le
		// composeur avec un aperçu typé ; le fil naît LOCAL (privé) et ne devient
		// public qu'à la publication — les brouillons restent sur le BBS.
		if src, ok := adresseSource(r.URL.Query().Get("src")); ok {
			p.SourceURL = src
			p.SrcType = typerSource(src)
			p.Titre = "Déposer une source"
		}
		s.rend(w, r, "nouveau", p)
		return
	}
	if err := s.verifieCSRF(r); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	titre := strings.TrimSpace(r.PostFormValue("title"))
	corps := strings.TrimSpace(r.PostFormValue("body"))
	if titre == "" || corps == "" {
		p.Err = "Un titre et un premier message sont nécessaires."
		s.rend(w, r, "nouveau", p)
		return
	}
	var cat int64
	fmt.Sscanf(r.PostFormValue("categorie"), "%d", &cat)
	// Le salon doit exister ET etre visible de l'appelant : un identifiant
	// choisi au hasard ne doit pas permettre d'ecrire dans un salon qu'on ne
	// voit pas.
	valide := false
	for _, c := range p.Cats {
		if c.ID == cat {
			valide = true
		}
	}
	if !valide {
		p.Err = "Salon inconnu."
		s.rend(w, r, "nouveau", p)
		return
	}
	vis := store.VisLocal
	if r.PostFormValue("visibility") == "public" {
		vis = store.VisPublic
	}
	// #1056 stage 2 : si une source est déposée, son adresse ouvre le premier
	// message (le rendu la transforme en lien, ou en lecteur pour une vidéo
	// connue) et son type est posé sur le fil pour la rédaction.
	src, aSource := adresseSource(r.PostFormValue("src"))
	if aSource {
		corps = src + "\n\n" + corps
	}
	id, err := s.st.NewThread(cat, v.ID, titre, corps, vis)
	if err != nil {
		p.Err = "Enregistrement impossible : " + err.Error()
		s.rend(w, r, "nouveau", p)
		return
	}
	if vis == store.VisPublic {
		s.propagerPiecesPubliques(corps) // #1114 : média public comme le message
	}
	if aSource {
		st := typerSource(src)
		if st.Source == "video" {
			// #1056 stage 3 : une vidéo garde son adresse comme média (embarquable
			// dans la rédaction) ET est CONNECTÉE à ytsas — le tuyau souverain la
			// rapatrie/met en cache. Best-effort : ytsas HS ne casse pas le dépôt.
			if err := s.st.MarquerSourceMedia(id, "video", src, "video"); err != nil {
				log.Printf("marquage média du fil %d : %v", id, err)
			}
			if s.ytsas != nil {
				go func(u string, fil int64) {
					if _, err := s.ytsas.Resoudre(u); err != nil {
						log.Printf("raccord ytsas (fil %d) : %v", fil, err)
					}
				}(src, id)
			}
		} else if err := s.st.MarquerSource(id, st.Source); err != nil {
			log.Printf("marquage de source du fil %d : %v", id, err)
		}
	}
	http.Redirect(w, r, "/t/"+itoa64(id), http.StatusSeeOther)
}

// sysopOK : la console est fermee a tout ce qui n'est pas sysop.
//
// Le lien n'apparait que pour un sysop, mais l'ADRESSE est devinable.
// « Ce n'est pas dans le menu » n'a jamais ferme une porte.
func (s *Server) sysopOK(w http.ResponseWriter, r *http.Request) (visiteur, bool) {
	v := s.qui(r)
	if !v.Connecte || v.Role != store.RoleSysop {
		// 404 et non 403 : un 403 confirmerait que la page existe.
		http.NotFound(w, r)
		return v, false
	}
	return v, true
}

func (s *Server) sysop(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.sysopOK(w, r); !ok {
		return
	}
	p, _ := s.base(r, "sysop")
	p.Titre = "Console sysop"
	p.Code = r.URL.Query().Get("code")
	p.Msg = r.URL.Query().Get("msg")
	p.Integ, _ = s.st.Integrity()
	p.Sain = p.Integ.Diverging == 0 && p.Integ.Missing == 0 && p.Integ.Unreadable == 0
	p.Runs, _ = s.st.IngestRuns(12)
	p.Comptes, _ = s.st.Users()
	p.Err = r.URL.Query().Get("err")
	p.Invites, _ = s.st.Invites()
	p.MastoInstance, _ = s.st.Reglage(store.CleMastodonInstance)
	p.MastoInvite, _ = s.st.Reglage(store.CleMastodonInvite)
	// UN JOURNAL QUE PERSONNE NE LIT N'ENCADRE RIEN. Ecrire chaque geste de
	// moderation sans jamais l'afficher aurait donne la lettre de la
	// tracabilite sans l'usage : c'est la consultation qui rend le pouvoir
	// verifiable, pas l'ecriture.
	p.Moderations, _ = s.st.Moderations(50)
	s.rend(w, r, "sysop", p)
}

func (s *Server) sysopAction(w http.ResponseWriter, r *http.Request) {
	v, ok := s.sysopOK(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if err := s.verifieCSRF(r); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	switch strings.TrimPrefix(r.URL.Path, "/sysop/") {
	case "reglages":
		// LE LIEN EST VALIDE AVANT D'ENTRER EN BASE, pas seulement au rendu.
		// Il est colle par le sysop puis affiche dans un href visible de tous
		// les membres : un `javascript:` y deviendrait actif sur chaque page du
		// module. Une valeur invalide ne doit jamais etre stockee.
		for cle, champ := range map[string]string{
			store.CleMastodonInstance: "instance",
			store.CleMastodonInvite:   "invitation",
		} {
			val := strings.TrimSpace(r.PostFormValue(champ))
			if val != "" && !store.LienExterneValide(val) {
				http.Redirect(w, r, "/sysop?err="+url.QueryEscape(
					"lien refuse ("+champ+") : seuls http et https sont acceptes"),
					http.StatusSeeOther)
				return
			}
			if err := s.st.PoseReglage(cle, val); err != nil {
				http.Redirect(w, r, "/sysop?err="+url.QueryEscape(err.Error()),
					http.StatusSeeOther)
				return
			}
		}
		http.Redirect(w, r, "/sysop?msg="+url.QueryEscape("reglages enregistres"),
			http.StatusSeeOther)
	case "invite":
		code, err := s.st.NewInvite(v.ID)
		if err != nil {
			http.Redirect(w, r, "/sysop?msg="+url.QueryEscape("invitation impossible : "+err.Error()),
				http.StatusSeeOther)
			return
		}
		// Le code passe par l'adresse UNE fois, pour etre affiche. Il n'est
		// stocke nulle part en clair — ni en base, ni en session.
		http.Redirect(w, r, "/sysop?code="+url.QueryEscape(code), http.StatusSeeOther)
	case "compte":
		var id int64
		fmt.Sscanf(r.PostFormValue("id"), "%d", &id)
		var err error
		msg := ""
		switch r.PostFormValue("action") {
		case "disable":
			// SE DESACTIVER SOI-MEME est refuse : le dernier sysop se
			// fermerait la porte, et il faudrait alors passer par la ligne de
			// commande sur la board pour rouvrir.
			if id == v.ID {
				msg = "vous ne pouvez pas desactiver votre propre compte"
			} else {
				err, msg = s.st.DisableUser(id), "compte desactive"
			}
		case "enable":
			err, msg = s.st.EnableUser(id), "compte reactive"
		default:
			msg = "action inconnue"
		}
		if err != nil {
			msg = "echec : " + err.Error()
		}
		http.Redirect(w, r, "/sysop?msg="+url.QueryEscape(msg), http.StatusSeeOther)
	case "motdepasse":
		// REINITIALISATION PAR LE SYSOP — sans l'ancien mot de passe, c'est le
		// propre du geste : on l'emploie quand le titulaire ne peut plus entrer.
		var id int64
		fmt.Sscanf(r.PostFormValue("id"), "%d", &id)
		nouveau := r.PostFormValue("nouveau")
		if err := s.auth.ResetPassword(id, nouveau); err != nil {
			http.Redirect(w, r, "/sysop?err="+url.QueryEscape(err.Error()),
				http.StatusSeeOther)
			return
		}
		// TOUTES LES SESSIONS DU COMPTE SONT FERMEES. On reinitialise un mot de
		// passe soit parce qu'il a fuite, soit pour reprendre la main : laisser
		// vivre les sessions ouvertes ailleurs viderait le geste de son sens
		// dans les deux cas. `RevokeOtherSessions` avec un jeton vide ne
		// preserve rien — ce qui est bien l'intention ici.
		s.st.RevokeOtherSessions(id, "")
		http.Redirect(w, r, "/sysop?msg="+url.QueryEscape(
			"mot de passe reinitialise — les sessions du compte ont ete fermees"),
			http.StatusSeeOther)
	case "reindex":
		msg := "index reconstruit"
		if err := s.st.Reindex(); err != nil {
			msg = "reconstruction impossible : " + err.Error()
		}
		http.Redirect(w, r, "/sysop?msg="+url.QueryEscape(msg), http.StatusSeeOther)
	case "backup":
		dest := s.opt.BackupDir + "/bbs-" + time.Now().Format("20060102-150405") + ".tar.gz"
		msg := "archive écrite : " + dest
		if err := s.st.Backup(dest); err != nil {
			msg = "sauvegarde impossible : " + err.Error()
		}
		http.Redirect(w, r, "/sysop?msg="+url.QueryEscape(msg), http.StatusSeeOther)
	default:
		http.NotFound(w, r)
	}
}

// compte : la page d'un membre sur lui-meme.
func (s *Server) compte(w http.ResponseWriter, r *http.Request) {
	v := s.qui(r)
	if !v.Connecte {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	p, _ := s.base(r, "compte")
	p.Titre = "Mon compte"
	p.Msg = r.URL.Query().Get("msg")
	p.Err = r.URL.Query().Get("err")
	p.Code = r.URL.Query().Get("code")
	// On ne lit QUE son propre compte : la liste complete est reservee a la
	// console sysop.
	if cs, err := s.st.Users(); err == nil {
		for _, c := range cs {
			if c.ID == v.ID {
				p.Moi = c
			}
		}
	}
	s.poseNonLus(&p)
	s.poseRail(&p)
	s.rendDef(w, r, "compte", "pagenr", p)
}

func (s *Server) compteAction(w http.ResponseWriter, r *http.Request) {
	v := s.qui(r)
	if !v.Connecte {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if err := s.verifieCSRF(r); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	jeton := ""
	if c, err := r.Cookie(cookieSession); err == nil {
		jeton = c.Value
	}

	switch strings.TrimPrefix(r.URL.Path, "/compte/") {
	case "motdepasse":
		err := s.auth.ChangePassword(v.ID,
			r.PostFormValue("ancien"), r.PostFormValue("nouveau"))
		if err != nil {
			http.Redirect(w, r, "/compte?err="+url.QueryEscape(err.Error()),
				http.StatusSeeOther)
			return
		}
		// Le changement FERME les autres sessions. On change son mot de passe
		// surtout quand on craint qu'il ait fuite ; laisser vivre les sessions
		// ouvertes ailleurs viderait le geste de son sens.
		s.st.RevokeOtherSessions(v.ID, jeton)
		http.Redirect(w, r, "/compte?msg="+url.QueryEscape(
			"mot de passe change — vos autres sessions ont ete fermees"), http.StatusSeeOther)
	case "invite":
		// TOUT MEMBRE PEUT INVITER, SANS QUOTA — choix explicite de
		// l'exploitant (#1008). La contrepartie est la tracabilite : l'emetteur
		// est enregistre, et la console sysop montre qui a invite qui. Sans
		// cela, une inscription en cascade serait indebrouillable.
		//
		// Un compte ferme ne peut pas arriver ici : `DisableUser` supprime les
		// sessions, et `UserBySession` ecarte les comptes desactives. Le
		// verifier une seconde fois serait du code mort — mais si l'une de ces
		// deux barrieres tombait, ce chemin ouvrirait la porte. C'est
		// `TestUnCompteFermeNInvitePas` qui garde la propriete.
		code, err := s.st.NewInvite(v.ID)
		if err != nil {
			http.Redirect(w, r, "/compte?err="+url.QueryEscape("invitation impossible : "+err.Error()),
				http.StatusSeeOther)
			return
		}
		// Le code ne transite qu'UNE fois, pour etre affiche. Il n'est stocke
		// nulle part en clair — ni en base, ni en session.
		http.Redirect(w, r, "/compte?code="+url.QueryEscape(code), http.StatusSeeOther)
	case "sessions":
		s.st.RevokeOtherSessions(v.ID, jeton)
		http.Redirect(w, r, "/compte?msg="+url.QueryEscape("autres sessions fermees"),
			http.StatusSeeOther)
	default:
		http.NotFound(w, r)
	}
}

// statique sert les fichiers embarques avec une revalidation obligatoire.
//
// SANS EN-TETE DE CACHE, LE NAVIGATEUR DECIDE SEUL — ET IL GARDE. Une feuille
// de style servie une fois le reste longtemps, y compris apres plusieurs
// deploiements : la page s'affiche avec un CSS d'une version anterieure, sans
// erreur et sans indice. C'est arrive ici, et le temps perdu a chercher cote
// serveur un defaut qui vivait dans le cache d'un navigateur a ete
// considerable.
//
// `no-cache` ne signifie pas « ne pas mettre en cache » mais « revalider avant
// de reutiliser ». L'ETag, calcule sur le contenu, rend cette revalidation
// gratuite : tant que le fichier n'a pas change, la reponse est un 304 vide.
// jointesCitees rassemble les fichiers dont l'adresse apparait dans les corps.
//
// ON NE TRANSFERE QUE CE QUI EST CITE. Envoyer toute la bibliotheque de
// l'auteur serait une fuite : un fichier depose pour un fil local se
// retrouverait sur une page publique.
func (s *Server) jointesCitees(msgs []billets.Message) []billets.Jointe {
	vus := map[int64]bool{}
	var out []billets.Jointe
	for _, m := range msgs {
		for _, ref := range refsJointes.FindAllStringSubmatch(m.Corps, -1) {
			var id int64
			fmt.Sscanf(ref[1], "%d", &id)
			if id == 0 || vus[id] {
				continue
			}
			vus[id] = true
			fi, err := s.st.Fichier(id)
			if err != nil {
				continue // efface depuis : la reference restera en texte
			}
			b, err := os.ReadFile(s.st.CheminFichier(fi))
			if err != nil {
				continue
			}
			out = append(out, billets.Jointe{
				Ref: ref[0], Nom: fi.Name, Mime: fi.Mime, Contenu: b,
			})
		}
	}
	return out
}

// La reference telle qu'elle est ecrite dans un corps : `/f/12` ou `/f/12.png`.
var refsJointes = regexp.MustCompile(`/f/(\d+)(?:\.[a-z0-9]{2,5})?`)

func (s *Server) statique(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nom := strings.TrimPrefix(r.URL.Path, "/")
		if b, err := assets.ReadFile(nom); err == nil {
			sum := sha256.Sum256(b)
			etag := `"` + base64.RawURLEncoding.EncodeToString(sum[:9]) + `"`
			w.Header().Set("ETag", etag)
			if r.Header.Get("If-None-Match") == etag {
				w.WriteHeader(http.StatusNotModified)
				return
			}
		}
		w.Header().Set("Cache-Control", "no-cache")
		h.ServeHTTP(w, r)
	})
}

// qrFil rend le code QR d'un fil, pour passer sur un telephone sans recopier
// l'adresse.
//
// L'ADRESSE EST CONSTRUITE ICI a partir du seul identifiant. Accepter une
// adresse en parametre ferait de cette page un generateur de QR vers n'importe
// ou, commode pour faire scanner un lien piege depuis un domaine de confiance.
//
// LA VISIBILITE EST VERIFIEE : un fil local ne rend pas de code QR pour un
// visiteur qui n'a pas le droit de le lire. Sans cela, l'image confirmerait
// l'existence d'un fil que la page refuse d'afficher.
func (s *Server) qrFil(w http.ResponseWriter, r *http.Request, id int64) {
	v := s.qui(r)
	t, err := s.st.ThreadByID(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if !v.Connecte && t.Visibility != store.VisPublic {
		http.NotFound(w, r)
		return
	}
	svg, err := s.encoder("https://" + r.Host + "/t/" + itoa64(id))
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Cache-Control", "private, max-age=600")
	w.Write(svg)
}

// verifie choisit QUI valide le mot de passe, selon l'origine du compte.
//
// Un membre venu par invitation a son mot de passe ICI ; l'envoyer a
// secubox-auth le divulguerait a un service qui n'a rien a en faire. Un compte
// synchronise depuis SecuBox n'a AUCUNE empreinte locale : seule la delegation
// peut l'ouvrir.
//
// Aucun repli d'un mode sur l'autre : chaque compte a une origine, une seule.
func (s *Server) verifie(handle string, id int64, motDePasse string) bool {
	src, err := s.st.AuthSource(handle)
	if err != nil {
		return false
	}
	if src == "secubox" {
		if s.authAmont == nil {
			return false
		}
		return s.authAmont(handle, motDePasse)
	}
	return s.auth.Verify(id, motDePasse)
}
