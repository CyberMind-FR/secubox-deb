package web

// Lecture des medias sur place.
//
// POURQUOI SERVIR L'AUDIO NOUS-MEMES
//
// Le podcaster a deja telecharge les episodes sur le disque de la board.
// Pointer l'enclosure d'origine ferait contacter un tiers — Radio France et
// consorts — par CHAQUE auditeur, depuis une page de la maison, avec son
// adresse et son navigateur. Le fichier est a un metre ; on le sert.
//
// LA VIDEO, ELLE, RESTE CHEZ PEERTUBE : c'est le meme domaine de confiance,
// l'integration est prevue pour, et rejouer un transcodage serait absurde.

import (
	"database/sql"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	_ "modernc.org/sqlite"
)

// resolveur : rend le chemin et le type d'un episode. Remplace en test.
type resolveur func(id int64) (chemin, mime string, ok bool)

// mediaEpisode sert un episode deja telecharge par le podcaster.
//
// LE CHEMIN NE VIENT PAS DE L'APPELANT — il vient de la base du podcaster, un
// module tiers. Lui faire confiance sans verifier reviendrait a servir
// n'importe quel fichier lisible par ce service des qu'une ligne de cette base
// serait fausse. Le chemin resolu est donc CONFINE au parc media, apres
// resolution des liens et des « .. ».
func (s *Server) mediaEpisode(w http.ResponseWriter, r *http.Request) {
	reste := strings.TrimPrefix(r.URL.Path, "/media/ep/")
	id, err := strconv.ParseInt(reste, 10, 64)
	if err != nil || id <= 0 || s.resoudreEpisode == nil {
		http.NotFound(w, r)
		return
	}
	chemin, mime, ok := s.resoudreEpisode(id)
	if !ok || chemin == "" {
		http.NotFound(w, r)
		return
	}
	if !sousUneRacine(chemin, s.opt.PodcastRacine) {
		// On ne dit PAS pourquoi : un message distinct apprendrait a
		// l'appelant qu'il a touche quelque chose d'interessant.
		http.NotFound(w, r)
		return
	}
	f, err := os.Open(chemin)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || fi.IsDir() {
		http.NotFound(w, r)
		return
	}
	if mime != "" {
		w.Header().Set("Content-Type", mime)
	}
	// nosniff : le navigateur ne doit pas requalifier un fichier d'apres son
	// contenu. Un episode reste un episode.
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "private, max-age=3600")
	// ServeContent gere les requetes par plages : sans elles, impossible de se
	// deplacer dans un episode d'une heure sans le retelecharger.
	http.ServeContent(w, r, filepath.Base(chemin), fi.ModTime(), f)
}

// sousUneRacine : le chemin est-il dans L'UN des parcs declares ?
//
// Le podcaster range ses medias a DEUX endroits sur cette board — l'eMMC pour
// les anciens episodes, le SSD pour les imports recents et les gros fichiers.
// N'en declarer qu'un refusait tout le second parc, et le refus etait correct :
// c'est la configuration qui etait incomplete, pas la garde.
//
// La liste est explicite et fermee. Elargir a « tout ce que la base indique »
// reviendrait a supprimer le confinement.
func sousUneRacine(chemin, racines string) bool {
	for _, r := range strings.Split(racines, ",") {
		if r = strings.TrimSpace(r); r != "" && sousRacine(chemin, r) {
			return true
		}
	}
	return false
}

// sousRacine verifie qu'un chemin reste DANS un repertoire, liens resolus.
//
// La comparaison porte sur les chemins REELS : sans cela, un lien symbolique
// place dans le parc suffirait a en sortir, et `filepath.Clean` seul ne le voit
// pas.
func sousRacine(chemin, racine string) bool {
	if racine == "" {
		return false
	}
	cr, err := filepath.EvalSymlinks(racine)
	if err != nil {
		cr = filepath.Clean(racine)
	}
	cc, err := filepath.EvalSymlinks(chemin)
	if err != nil {
		cc = filepath.Clean(chemin)
	}
	rel, err := filepath.Rel(cr, cc)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// resolveurPodcaster lit la base du podcaster EN LECTURE SEULE.
//
// `mode=ro` n'est pas une precaution de style : ce fichier appartient a un
// autre module, qui y ecrit. L'ouvrir en ecriture exposerait sa base a nos
// bogues et pourrait la verrouiller au mauvais moment.
func resolveurPodcaster(chemin string) resolveur {
	return func(id int64) (string, string, bool) {
		db, err := sql.Open("sqlite", "file:"+chemin+"?mode=ro&_pragma=busy_timeout(3000)")
		if err != nil {
			return "", "", false
		}
		defer db.Close()
		var local, mime sql.NullString
		err = db.QueryRow(
			`SELECT local_path, mime FROM episodes WHERE id = ?`, id).Scan(&local, &mime)
		if err != nil || !local.Valid || local.String == "" {
			return "", "", false
		}
		return local.String, mime.String, true
	}
}
