package web

import (
	"io"
	"net/http"
	"strconv"
	"strings"
)

// servirMedia rend le CLIP d'une piste.
//
// UN CLIP, PAS SEULEMENT UN SON. La passerelle yt-dlp rapatrie deja du `.mp4` :
// on le garde tel quel. C'etait d'abord percu comme du gaspillage pour une
// radio — c'est en fait la fonctionnalite, puisqu'elle sert aussi de television
// synchronisee. Et surtout cela evite un transcodage que le processeur de cette
// board ne peut pas payer : il est deja sature, et ffmpeg y prend un coeur
// entier quand il tourne.
//
// Le meme fichier sert les deux usages : le telephone n'affiche que le son,
// l'ecran montre le clip. Une seule copie, une seule horloge.
//
// `http.ServeContent` PLUTOT QU'UNE COPIE : il gere les requetes de PLAGE, et
// sans elles on ne peut pas se positionner dans un morceau. Or c'est
// exactement ce que fait un auditeur qui rejoint la radio en cours — il demande
// « a partir de 3 min 41 ». Sans plage, le navigateur telecharge tout depuis le
// debut avant de pouvoir jouer, et la synchronisation est perdue.
func (s *Serveur) servirMedia(w http.ResponseWriter, r *http.Request) {
	// LE MEDIA N'EST PAS PUBLIC. Une radio peut s'ecouter, mais servir les
	// clips a qui passe ferait de la board un miroir ouvert.
	if v := s.qui(r); !v.Connecte {
		erreur(w, http.StatusUnauthorized, "connectez-vous")
		return
	}
	brut := strings.TrimPrefix(r.URL.Path, "/media/")
	if i := strings.IndexByte(brut, '.'); i > 0 {
		brut = brut[:i]
	}
	id, err := strconv.ParseInt(brut, 10, 64)
	if err != nil || id <= 0 {
		http.NotFound(w, r)
		return
	}
	p, err := s.st.ParID(id)
	if err != nil || !p.EnCache() {
		http.NotFound(w, r)
		return
	}
	if s.Flux == nil {
		erreur(w, http.StatusServiceUnavailable, "passerelle non configuree")
		return
	}
	ytID := strings.TrimPrefix(p.Source, "yt:")
	if ytID == p.Source {
		http.NotFound(w, r)
		return
	}

	// ON RELAIE, ON NE RECOPIE PAS. Le deploiement l'a impose : un clip pese
	// 660 Mio, et le parc de la passerelle vit sur LE MEME disque que le
	// notre. Recopier revenait a ecrire 660 Mio a cote de 660 Mio identiques.
	res, err := s.Flux(r.Context(), ytID, r.Header.Get("Range"))
	if err != nil {
		// PAS 502 : nginx intercepte 502/503/504 et les remplace par la page de
		// reveil, qui n'accepte que GET.
		erreur(w, http.StatusServiceUnavailable, "clip indisponible")
		return
	}
	defer res.Body.Close()

	for _, cle := range []string{"Content-Type", "Content-Length", "Content-Range", "Accept-Ranges"} {
		if v := res.Header.Get(cle); v != "" {
			w.Header().Set(cle, v)
		}
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "private, max-age=3600")
	w.WriteHeader(res.StatusCode)
	io.Copy(w, res.Body)
}
