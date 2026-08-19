package ingest

// Les trois sources reelles.
//
// Chacune se contente de LIRE et de normaliser en []Item. Aucune n'ecrit dans
// le BBS : l'ecriture est le travail d'Importer, et elle est identique pour
// toutes. C'est ce qui garantit qu'une passerelle ajoutee demain heritera de
// l'idempotence et du defaut « local » sans avoir a y penser.

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// clientSocket parle a un module par sa socket unix.
func clientSocket(socket string) *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socket)
			},
		},
	}
}

func lire(c *http.Client, url string) ([]byte, error) {
	resp, err := c.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%s : code %d", url, resp.StatusCode)
	}
	// Borne de lecture : une source qui deraille ne doit pas remplir la memoire
	// de la board.
	return io.ReadAll(io.LimitReader(resp.Body, 16<<20))
}

// ── billets : les archives ──────────────────────────────────────────────────

// DepuisBillets lit le flux JSON public du module billets.
//
// Ces billets sont DEJA PUBLIES : les importer en « public » ne divulgue rien
// qui ne le soit deja. C'est la seule source dont la visibilite publique est un
// constat plutot qu'une decision.
func DepuisBillets(socket, base string) ([]Item, error) {
	brut, err := lire(clientSocket(socket), "http://billets/feed.json")
	if err != nil {
		return nil, err
	}
	var flux struct {
		Items []struct {
			ID     string `json:"id"`
			Titre  string `json:"title"`
			URL    string `json:"url"`
			Resume string `json:"summary"`
			HTML   string `json:"content_html"`
			Publie string `json:"date_published"`
		} `json:"items"`
	}
	if err := json.Unmarshal(brut, &flux); err != nil {
		return nil, fmt.Errorf("flux billets illisible : %w", err)
	}
	var out []Item
	for _, b := range flux.Items {
		titre := strings.TrimSpace(b.Titre)
		if titre == "" {
			titre = bref(texteDepuisHTML(b.Resume))
		}
		// Le RESUME, pas le corps HTML complet : le fil sert a discuter le
		// billet, pas a le republier. Le lien renvoie a l'original, qui reste
		// la version qui fait foi.
		// content_html D'ABORD : le resume de ces billets est un entete
		// commercial identique pour tous, alors que le contenu porte le texte
		// reel. Les paragraphes sont conserves — ils servent a distinguer les
		// titres en double.
		corps := paragraphesDepuisHTML(b.HTML)
		if corps == "" {
			corps = texteDepuisHTML(b.Resume)
		}
		lien := b.URL
		if lien != "" && strings.HasPrefix(lien, "/") && base != "" {
			lien = strings.TrimRight(base, "/") + lien
		}
		out = append(out, Item{Ref: b.ID, Titre: titre, Corps: corps,
			Lien: lien, Date: dateRFC(b.Publie)})
	}
	return out, nil
}

// ── PeerTube : les videos ───────────────────────────────────────────────────

// DepuisPeerTube lit le catalogue public d'une instance.
//
// SEULES LES VIDEOS PUBLIQUES sont retenues. Une video « non listee » n'est pas
// secrete mais elle n'a pas ete mise en avant : lui ouvrir un fil dans le BBS
// la ferait apparaitre dans une liste, ce que son auteur n'a pas demande.
func DepuisPeerTube(base string, limite int) ([]Item, error) {
	if limite <= 0 || limite > 100 {
		limite = 100
	}
	c := &http.Client{Timeout: 30 * time.Second}
	brut, err := lire(c, fmt.Sprintf(
		"%s/api/v1/videos?count=%d&sort=-publishedAt&nsfw=false",
		strings.TrimRight(base, "/"), limite))
	if err != nil {
		return nil, err
	}
	var rep struct {
		Data []struct {
			UUID        string `json:"uuid"`
			ShortUUID   string `json:"shortUUID"`
			Nom         string `json:"name"`
			Description string `json:"description"`
			Duree       int    `json:"duration"`
			Publie      string `json:"publishedAt"`
			Thumbnail   string `json:"thumbnailPath"`
			Privacy     struct {
				ID int `json:"id"`
			} `json:"privacy"`
		} `json:"data"`
	}
	if err := json.Unmarshal(brut, &rep); err != nil {
		return nil, fmt.Errorf("reponse PeerTube illisible : %w", err)
	}
	var out []Item
	for _, v := range rep.Data {
		// privacy 1 = Public chez PeerTube. Tout le reste est ecarte, y compris
		// les valeurs inconnues : au doute, on n'importe pas.
		if v.Privacy.ID != 1 {
			continue
		}
		ref := v.UUID
		if ref == "" {
			ref = v.ShortUUID
		}
		corps := strings.TrimSpace(v.Description)
		if corps == "" {
			corps = "_(pas de description)_"
		}
		if v.Duree > 0 {
			corps = fmt.Sprintf("%s\n\n*Durée : %d min*", corps, v.Duree/60)
		}
		court := firstNonEmpty(v.ShortUUID, v.UUID)
		lien := strings.TrimRight(base, "/") + "/w/" + court
		// L'adresse d'INTEGRATION, pas celle de la page : on encadre le
		// lecteur, on n'ouvre pas PeerTube dans un cadre.
		vignette := ""
		if v.Thumbnail != "" {
			vignette = strings.TrimRight(base, "/") + v.Thumbnail
		}
		out = append(out, Item{Ref: ref, Titre: v.Nom, Corps: corps,
			Lien: lien, Date: dateRFC(v.Publie), Vignette: vignette,
			Media: strings.TrimRight(base, "/") + "/videos/embed/" + court,
			Kind:  "video"})
	}
	return out, nil
}

// ── podcaster : les episodes ────────────────────────────────────────────────

// DepuisPodcaster lit la base du module podcaster, EN LECTURE SEULE.
//
// Lire directement une base qui appartient a un autre module se defend mal en
// general. Ici c'est le moindre mal : l'API du podcaster exige un jeton de
// session, et forger un jeton pour lire un catalogue public ferait du BBS un
// porteur de secret dont il n'a pas besoin. La connexion est en mode `ro` :
// aucune ecriture n'est possible, meme par erreur de programmation.
func DepuisPodcaster(chemin string, limite int) ([]Item, error) {
	if limite <= 0 {
		limite = 200
	}
	db, err := sql.Open("sqlite", "file:"+chemin+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	defer db.Close()

	// `pubdate` est une CHAINE (format RFC des flux RSS), pas un entier : le
	// premier jet lisait une colonne `published` qui n'existe pas, et la
	// requete echouait entierement. Un nom de colonne se verifie contre le
	// schema reel, jamais contre celui qu'on imagine.
	rows, err := db.Query(`SELECT e.id, e.guid, e.title, COALESCE(e.description,''),
		COALESCE(e.pubdate,''), COALESCE(f.title,''), COALESCE(f.site,''),
		COALESCE(e.local_path,'')
		FROM episodes e LEFT JOIN feeds f ON f.id = e.feed_id
		ORDER BY e.id DESC LIMIT ?`, limite)
	if err != nil {
		return nil, fmt.Errorf("lecture des episodes : %w", err)
	}
	defer rows.Close()

	var out []Item
	for rows.Next() {
		var guid, titre, desc, pubdate, flux, site, local string
		var epID int64
		if err := rows.Scan(&epID, &guid, &titre, &desc, &pubdate, &flux, &site,
			&local); err != nil {
			return nil, err
		}
		corps := texteDepuisHTML(desc)
		if flux != "" {
			corps = "**" + flux + "**\n\n" + corps
		}
		it := Item{Ref: guid, Titre: titre, Corps: corps,
			Lien: site, Date: dateRFC(pubdate)}
		// SEULEMENT si le fichier a ete telecharge. Sans lui il n'y a rien a
		// jouer, et pointer l'enclosure d'origine enverrait chaque auditeur
		// chez un tiers depuis une page de la maison.
		if local != "" {
			it.Media = "/media/ep/" + strconv.FormatInt(epID, 10)
			it.Kind = "audio"
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

// ── aides ───────────────────────────────────────────────────────────────────

// texteDepuisHTML retire les balises. Les corps sont ensuite rendus comme du
// Markdown : y laisser du HTML le ferait echapper et afficher tel quel.
// paragraphesDepuisHTML garde la structure en paragraphes, contrairement a
// texteDepuisHTML qui aplatit tout : c'est cette structure qui permet de
// reperer l'entete repete d'un item a l'autre.
func paragraphesDepuisHTML(s string) string {
	for _, coupe := range []string{"</p>", "<br>", "<br/>", "<br />"} {
		s = strings.ReplaceAll(s, coupe, "\n")
	}
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if t := texteDepuisHTML(l); t != "" {
			out = append(out, t)
		}
	}
	return strings.Join(out, "\n")
}

func texteDepuisHTML(s string) string {
	var b strings.Builder
	dans := false
	for _, r := range s {
		switch {
		case r == '<':
			dans = true
		case r == '>':
			dans = false
			b.WriteByte(' ')
		case !dans:
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(strings.Join(strings.Fields(
		strings.ReplaceAll(b.String(), "&nbsp;", " ")), " "))
}

func dateRFC(s string) int64 {
	for _, f := range []string{time.RFC3339, time.RFC1123Z, time.RFC1123} {
		if t, err := time.Parse(f, s); err == nil {
			return t.Unix()
		}
	}
	return 0
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// Desambiguiser rend lisible une liste ou plusieurs items portent le meme titre.
//
// CAS REEL : trente billets auto-publies partagent le titre « Retrouvez
// l'integralite du podcast… ». Chaque fil est bien distinct en base — l'identite
// est la reference, pas le titre — mais une liste de trente lignes identiques
// est inutilisable.
//
// Seuls les titres EN DOUBLE sont retouches. Un titre unique est celui que
// l'auteur a voulu ; le reecrire serait presomptueux.
func Desambiguiser(items []Item) []Item {
	compte := map[string]int{}
	for _, it := range items {
		compte[strings.TrimSpace(it.Titre)]++
	}
	// Paragraphes communs a plusieurs items : c'est l'entete repete qui rend
	// les titres identiques, il ne peut donc pas servir a les distinguer.
	freq := map[string]int{}
	for _, it := range items {
		for _, p := range paragraphes(it.Corps) {
			freq[p]++
		}
	}

	out := make([]Item, len(items))
	copy(out, items)
	for i := range out {
		t := strings.TrimSpace(out[i].Titre)
		if compte[t] < 2 {
			continue
		}
		// 1. Le CORPS d'abord : il a garde ses accents, contrairement a
		//    l'adresse que la source a deja reduite en ASCII.
		if p := premierParagrapheDistinctif(out[i].Corps, freq); p != "" {
			out[i].Titre = tronque(p, 72)
			continue
		}
		// 2. Puis l'adresse.
		if suffixe := titreDepuisLien(out[i].Lien); suffixe != "" {
			out[i].Titre = suffixe
			continue
		}
		// 3. Sans rien d'exploitable, on GARDE le titre d'origine : mieux vaut
		//    un doublon lisible qu'un titre vide ou invente.
	}
	return out
}

func paragraphes(s string) []string {
	var out []string
	for _, p := range strings.Split(s, "\n") {
		p = strings.TrimSpace(strings.Trim(p, "*_# "))
		if len(p) >= 12 {
			out = append(out, p)
		}
	}
	return out
}

func premierParagrapheDistinctif(corps string, freq map[string]int) string {
	for _, p := range paragraphes(corps) {
		if freq[p] <= 1 {
			return p
		}
	}
	return ""
}

// tronque coupe sur une frontiere de mot : couper au milieu d'un mot donne des
// titres qui se terminent en plein milieu d'une syllabe.
func tronque(s string, n int) string {
	s = strings.TrimSpace(s)
	if len([]rune(s)) <= n {
		return s
	}
	r := []rune(s)[:n]
	if i := strings.LastIndexAny(string(r), " ,;:."); i > n/2 {
		return strings.TrimRight(string(r)[:i], " ,;:.") + "…"
	}
	return string(r) + "…"
}

// titreDepuisLien tire un titre du dernier segment d'une adresse.
// « /b/les-ovnis-existent-ils » donne « Les ovnis existent ils ».
func titreDepuisLien(lien string) string {
	lien = strings.TrimRight(lien, "/")
	i := strings.LastIndexByte(lien, '/')
	if i < 0 || i+1 >= len(lien) {
		return ""
	}
	seg := lien[i+1:]
	if seg == "" || !strings.ContainsAny(seg, "abcdefghijklmnopqrstuvwxyz") {
		return ""
	}
	mots := strings.ReplaceAll(strings.ReplaceAll(seg, "-", " "), "_", " ")
	mots = strings.TrimSpace(mots)
	if mots == "" {
		return ""
	}
	return strings.ToUpper(mots[:1]) + mots[1:]
}
