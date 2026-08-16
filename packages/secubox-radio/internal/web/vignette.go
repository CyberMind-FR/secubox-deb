package web

import (
	"context"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// servirVignette relaie la pochette d'une piste.
//
// ON LA RELAIE PLUTOT QUE DE LA LIER, pour la meme raison que les clips : une
// image chargee depuis `i.ytimg.com` ferait contacter Google par LE NAVIGATEUR
// DE CHAQUE AUDITEUR, a chaque affichage de la page. Sur un appareil qui vise
// la CSPN, c'est precisement ce qu'on evite.
//
// Et cela garde la politique de securite STRICTE : tout vient de nous, donc
// `img-src 'self'` suffit. Lier l'image aurait oblige a ouvrir la politique —
// c'est-a-dire a l'affaiblir pour une vignette.
func (s *Serveur) servirVignette(w http.ResponseWriter, r *http.Request) {
	if v := s.qui(r); !v.Connecte {
		erreur(w, http.StatusUnauthorized, "connectez-vous")
		return
	}
	brut := strings.TrimPrefix(r.URL.Path, "/vignette/")
	if i := strings.IndexByte(brut, '.'); i > 0 {
		brut = brut[:i]
	}
	id, err := strconv.ParseInt(brut, 10, 64)
	if err != nil || id <= 0 {
		http.NotFound(w, r)
		return
	}
	p, err := s.st.ParID(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	ytID := strings.TrimPrefix(p.Source, "yt:")
	if ytID == p.Source || ytID == "" {
		http.NotFound(w, r)
		return
	}

	ctx, annule := context.WithTimeout(r.Context(), 6*time.Second)
	defer annule()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://i.ytimg.com/vi/"+ytID+"/mqdefault.jpg", nil)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	res, err := s.HTTP.Do(req)
	if err != nil || res.StatusCode != http.StatusOK {
		if res != nil {
			res.Body.Close()
		}
		// PAS D'ERREUR BRUYANTE : une pochette manquante n'est pas une panne.
		// La page affiche alors son glyphe, et l'on n'a pas casse l'ecoute pour
		// une image.
		http.NotFound(w, r)
		return
	}
	defer res.Body.Close()

	w.Header().Set("Content-Type", "image/jpeg")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// Une pochette ne change jamais : le navigateur peut la garder.
	w.Header().Set("Cache-Control", "private, max-age=86400")
	// LECTURE BORNEE : une vignette pese quelques dizaines de kilo-octets ;
	// au-dela, ce n'est plus une vignette.
	io.Copy(w, io.LimitReader(res.Body, 512<<10))
}
