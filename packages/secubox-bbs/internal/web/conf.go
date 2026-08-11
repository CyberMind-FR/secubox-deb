package web

// Lecture du secret de signature partage.
//
// POURQUOI UN LECTEUR MINUSCULE PLUTOT QU'UNE BIBLIOTHEQUE TOML
//
// Une seule cle est lue dans tout le fichier : `[api] jwt_secret`. Embarquer un
// analyseur TOML complet pour cela ajouterait une dependance a vendorer, a
// suivre et a auditer, pour une valeur que trois lignes suffisent a extraire.
//
// Ce lecteur est deliberement STRICT : il ne comprend que ce qu'il lit ici. Il
// ne resout pas les tableaux, les chaines multi-lignes ni l'echappement. Si le
// fichier evolue au-dela de ce qu'il sait lire, il rend une valeur vide — donc
// une API FERMEE — plutot que de deviner.

import (
	"bufio"
	"os"
	"strings"
)

// SecretDepuisConf extrait api.jwt_secret d'un fichier de configuration SecuBox.
//
// Rend une chaine vide si le fichier est illisible ou la cle absente. L'appelant
// doit traiter ce vide comme « aucune authentification possible », jamais comme
// « aucune authentification requise ».
func SecretDepuisConf(chemin string) string {
	f, err := os.Open(chemin)
	if err != nil {
		return ""
	}
	defer f.Close()

	section := ""
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		if strings.HasPrefix(l, "[") && strings.HasSuffix(l, "]") {
			section = strings.Trim(l, "[]")
			continue
		}
		// La cle n'est acceptee QUE dans la section [api]. Une cle du meme nom
		// ailleurs dans le fichier ne doit pas etre prise pour celle-ci.
		if section != "api" {
			continue
		}
		k, v, ok := strings.Cut(l, "=")
		if !ok || strings.TrimSpace(k) != "jwt_secret" {
			continue
		}
		v = strings.TrimSpace(v)
		// Un commentaire en fin de ligne ne fait pas partie du secret.
		if i := strings.Index(v, " #"); i >= 0 {
			v = strings.TrimSpace(v[:i])
		}
		return strings.Trim(v, `"'`)
	}
	return ""
}
