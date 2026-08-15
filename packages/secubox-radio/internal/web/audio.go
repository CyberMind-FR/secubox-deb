package web

import (
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// servirAudio rend le fichier d'une piste.
//
// `http.ServeContent` PLUTOT QU'UNE COPIE : il gere les requetes de PLAGE, et
// sans elles on ne peut pas se positionner dans un morceau. Or c'est
// exactement ce que fait un auditeur qui rejoint la radio en cours — il demande
// « a partir de 3 min 41 ». Sans plage, le navigateur telecharge tout depuis le
// debut avant de pouvoir jouer, et la synchronisation est perdue.
func (s *Serveur) servirAudio(w http.ResponseWriter, r *http.Request) {
	// L'AUDIO N'EST PAS PUBLIC. Une radio peut s'ecouter, mais servir les
	// fichiers a qui passe ferait de la board un miroir ouvert.
	if v := s.qui(r); !v.Connecte {
		erreur(w, http.StatusUnauthorized, "connectez-vous")
		return
	}
	brut := strings.TrimPrefix(r.URL.Path, "/audio/")
	// On coupe une eventuelle extension decorative : `/audio/12.ogg`.
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

	// LE CHEMIN VIENT DE LA BASE, PAS DE L'ADRESSE — c'est la garde qui compte.
	// On le confine malgre tout au repertoire du parc : si une ligne portait un
	// jour un chemin de travers (import, migration, edition a la main), il ne
	// doit pas devenir une lecture arbitraire du disque.
	chemin := filepath.Clean(p.Fichier)
	if s.Racine != "" {
		rel, err := filepath.Rel(s.Racine, chemin)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			http.NotFound(w, r)
			return
		}
	}
	f, err := os.Open(chemin)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.IsDir() {
		http.NotFound(w, r)
		return
	}
	if p.Mime != "" {
		w.Header().Set("Content-Type", p.Mime)
	}
	// `nosniff` : le fichier vient d'un tiers, le navigateur ne doit pas
	// decider lui-meme de ce qu'il est.
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// Le contenu d'une piste ne change jamais — son identifiant designe un
	// fichier fige. Le cache navigateur evite de retelecharger a chaque
	// passage, ce qui compte sur une radio qui repete.
	w.Header().Set("Cache-Control", "private, max-age=86400")
	http.ServeContent(w, r, filepath.Base(chemin), st.ModTime(), f)
}
