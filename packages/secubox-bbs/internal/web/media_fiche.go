package web

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/CyberMind-FR/secubox-deb/secubox-bbs/internal/ytid"
)

// Fiche : ce qu'on sait dire d'un media de nos services.
type Fiche struct {
	Service  string `json:"service"`
	Titre    string `json:"titre,omitempty"`
	Auteur   string `json:"auteur,omitempty"`
	DureeMS  int64  `json:"duree_ms,omitempty"`
	Vignette string `json:"vignette,omitempty"` // deja passee par NOTRE relais
}

// ficheMax borne la reponse d'un service. Un service en panne peut repondre un
// flux sans fin ; la borne porte sur ce qu'on LIT.
const ficheMax = 256 << 10

// servirMediaFiche resout les metadonnees d'un lien vers un de NOS services.
//
// POURQUOI PASSER PAR LE DEMON plutot que d'interroger le service depuis la
// page : `connect-src` vaut `'self'`. Laisser le navigateur appeler
// peertube.gk2 obligerait a l'elargir — sur une page qui rend du contenu ecrit
// par des membres, c'est exactement ce qu'on evite. Le demon appelle, la
// politique reste fermee, et le service n'apprend rien sur qui regarde.
//
// APPELE PARESSEUSEMENT PAR LA PAGE, un lien a la fois : resoudre au rendu
// aurait fait trente requetes avant l'affichage d'un fil de trente liens.
func (s *Server) servirMediaFiche(w http.ResponseWriter, r *http.Request) {
	if v := s.qui(r); !v.Connecte {
		http.Error(w, "reserve aux membres", http.StatusForbidden)
		return
	}
	u, err := url.Parse(r.URL.Query().Get("u"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	// #1056 — YouTube N'EST PAS dans MediaOrigines (ce n'est pas UN DE NOS
	// services) : court-circuit explicite AVANT origineAdmise, sinon elle le
	// refuserait comme n'importe quelle origine tierce non admise.
	//
	// s.youtube PEUT ETRE NIL — un Server construit sans connecteur (tests,
	// ou --ytsas-origine absent) retombe silencieusement sur le comportement
	// existant plutot que de paniquer.
	if s.youtube != nil && ytid.VideoID(u.String()) != "" {
		c, _ := s.youtube.Resoudre(u.String())
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "private, max-age=3600")
		fmt.Fprint(w, embedYouTube(c))
		return
	}
	if !origineAdmise(u, s.opt.MediaOrigines) {
		http.NotFound(w, r)
		return
	}
	svc := strings.SplitN(u.Host, ".", 2)[0]

	var f Fiche
	switch svc {
	case "peertube":
		f, err = ficheOEmbed(r, u)
	case "radio":
		f, err = ficheRadio(r, u)
	default:
		// LE PODCASTER N'EST PAS AUTHENTIFIE — je l'avais cru sur un 401 qui
		// venait en realite du portail JWT de l'agregateur, interroge sur le
		// chemin prefixe. Mesure refaite : son vhost sert la PAGE PUBLIQUE en
		// HTML sur /episodes, et le JSON n'est expose que par sa socket. Le
		// brancher demande donc un autre chemin d'appel que les deux
		// precedents, et ce n'est pas une ligne a improviser.
		//
		// On rend 404 plutot qu'une fiche vide : une fiche sans titre
		// laisserait croire a un service muet, alors qu'il repond tres bien.
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "metadonnees indisponibles", http.StatusBadGateway)
		return
	}
	f.Service = svc
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "private, max-age=3600")
	_ = json.NewEncoder(w).Encode(f)
}

// lireJSON appelle un service et decode sa reponse, bornee.
func lireJSON(r *http.Request, adresse string, dst any) error {
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, adresse, nil)
	if err != nil {
		return err
	}
	// AUCUN EN-TETE DU MEMBRE : le service ne doit rien apprendre de qui regarde.
	req.Header.Set("Accept", "application/json")
	res, err := (&http.Client{Timeout: mediaDelai}).Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return errStatut
	}
	brut, err := io.ReadAll(io.LimitReader(res.Body, ficheMax))
	if err != nil {
		return err
	}
	return json.Unmarshal(brut, dst)
}

var errStatut = &erreurFiche{"le service a refuse"}

type erreurFiche struct{ m string }

func (e *erreurFiche) Error() string { return e.m }

// ficheOEmbed interroge PeerTube par oEmbed — mesure sur gk2 : il repond.
func ficheOEmbed(r *http.Request, u *url.URL) (Fiche, error) {
	var o struct {
		Titre    string  `json:"title"`
		Auteur   string  `json:"author_name"`
		Vignette string  `json:"thumbnail_url"`
		DureeSec float64 `json:"duration"`
	}
	adr := "https://" + u.Host + "/services/oembed?url=" + url.QueryEscape(u.String())
	if err := lireJSON(r, adr, &o); err != nil {
		return Fiche{}, err
	}
	return Fiche{
		Titre: o.Titre, Auteur: o.Auteur,
		DureeMS:  int64(o.DureeSec * 1000),
		Vignette: vignetteRelayee(o.Vignette),
	}, nil
}

// ficheRadio lit l'etat de la radio, qui porte la piste en cours.
func ficheRadio(r *http.Request, u *url.URL) (Fiche, error) {
	var o struct {
		Piste struct {
			Titre   string `json:"titre"`
			Auteur  string `json:"auteur"`
			DureeMS int64  `json:"duree_ms"`
		} `json:"piste"`
	}
	if err := lireJSON(r, "https://"+u.Host+"/current", &o); err != nil {
		return Fiche{}, err
	}
	return Fiche{Titre: o.Piste.Titre, Auteur: o.Piste.Auteur, DureeMS: o.Piste.DureeMS}, nil
}

// vignetteRelayee reecrit l'adresse d'une vignette vers NOTRE relais.
//
// La rendre telle quelle ferait charger l'image depuis le service par le
// navigateur du membre — precisement ce que le relais existe pour eviter, et
// `img-src 'self'` la refuserait de toute facon.
func vignetteRelayee(adr string) string {
	if adr == "" {
		return ""
	}
	return "/media-vignette?u=" + url.QueryEscape(adr)
}
