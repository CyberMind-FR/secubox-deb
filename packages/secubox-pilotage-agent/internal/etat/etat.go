// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Package etat écrit la page d'état locale d'une box légère (#3126, L5 tâche 7) : une page HTML statique,
// régénérée toutes les 60 s dans /run/secubox/pilotage/etat.html et servie par le gabarit nginx « etat »
// (LAN seulement). Elle ne porte QUE : le nom de la box, le maître joignable ou non, les mains liées, la
// mémoire et les noms des services en échec. Jamais d'adresse, de clé, de jeton, de numéro de série ni de nom
// d'utilisateur : l'état est construit champ par champ (Depuis), jamais en recopiant le relevé.
package etat

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"
)

// État du maître vu par l'agent.
const (
	MaitreInconnu     = "inconnu"     // aucun échange encore (démarrage, aucune interface du maillage)
	MaitreJoignable   = "joignable"   // dernier échange réussi
	MaitreInjoignable = "injoignable" // dernier échange en échec
)

// Intervalle : cadence de régénération de la page.
const Intervalle = 60 * time.Second

// temporaire : nom fixe du fichier de travail, dans le dossier de la page (renommé atomiquement).
const temporaire = ".etat.html.tmp"

// maxEchecs : au plus autant de services en échec affichés (la page reste petite).
const maxEchecs = 32

// Style : seule feuille de style de la page, autorisée par son empreinte dans la CSP du gabarit nginx (EmpreinteStyle).
const Style = "body{font:15px/1.5 system-ui,sans-serif;margin:0;padding:16px;background:#0f1419;color:#e6e6e6}" +
	"main{max-width:560px;margin:auto}h1{font-size:20px;margin:0 0 12px}dl{display:grid;grid-template-columns:auto 1fr;gap:6px 16px}" +
	"dt{color:#9aa5b1}dd{margin:0}.ok{color:#4caf50}.ko{color:#ef5350}ul{margin:0;padding-left:18px}small{color:#9aa5b1}"

// EmpreinteStyle : sha256 de Style, recopiée dans le gabarit nginx (secubox-profiles/nginx/etat.conf, vérifié par test).
const EmpreinteStyle = "sha256-BbU/zLNWiA6KAger+0RgJr7c2s5osYIWEX51N6vPbCQ="

// Etat : tout ce que la page montre, et rien d'autre.
type Etat struct {
	Nom         string
	Maitre      string
	MainsLiees  bool
	MemDispoMo  uint64
	MemTotaleMo uint64
	SwapPct     int
	Echecs      []string
	Instant     time.Time
}

var nomDNS = regexp.MustCompile(`^[a-z0-9-]{1,63}$`)

var uniteSure = regexp.MustCompile(`^[A-Za-z0-9@_.:-]{1,96}\.(service|timer|socket|mount|path)$`)

// Depuis construit l'état à partir du relevé aplati du modèle : seuls les chemins nommés ici sont lus.
func Depuis(nom, maitre string, plat map[string]any, instant time.Time) Etat {
	e := Etat{Nom: nom, Maitre: maitre, Instant: instant.UTC()}
	if v, ok := plat["Device.X_SECUBOX_Pilotage.MainsLiees"].(bool); ok {
		e.MainsLiees = v
	}
	e.MemDispoMo = kio(plat["Device.DeviceInfo.MemoryStatus.X_SECUBOX_Available"]) / 1024
	e.MemTotaleMo = kio(plat["Device.DeviceInfo.MemoryStatus.Total"]) / 1024
	if tot := kio(plat["Device.DeviceInfo.MemoryStatus.X_SECUBOX_SwapTotal"]); tot > 0 {
		e.SwapPct = int((kio(plat["Device.DeviceInfo.MemoryStatus.X_SECUBOX_SwapUsed"])*100 + tot/2) / tot)
	}
	for i := 1; i <= 200 && len(e.Echecs) < maxEchecs; i++ {
		base := fmt.Sprintf("Device.X_SECUBOX_Services.%d.", i)
		n, ok := plat[base+"Name"].(string)
		if !ok {
			break
		}
		if plat[base+"ActiveState"] == "failed" && uniteSure.MatchString(n) {
			e.Echecs = append(e.Echecs, n)
		}
	}
	sort.Strings(e.Echecs)
	return e
}

func kio(v any) uint64 {
	switch x := v.(type) {
	case uint64:
		return x
	case int:
		if x > 0 {
			return uint64(x)
		}
	case int64:
		if x > 0 {
			return uint64(x)
		}
	case float64:
		if x > 0 {
			return uint64(x)
		}
	}
	return 0
}

var gabarit = template.Must(template.New("etat").Parse(`<!doctype html>
<html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="60"><meta name="referrer" content="no-referrer">
<title>État de la box</title><style>{{.Style}}</style></head>
<body><main><h1>{{.E.Nom}}</h1><dl>
<dt>Maître</dt><dd class="{{if eq .E.Maitre "joignable"}}ok{{else}}ko{{end}}">{{.E.Maitre}}</dd>
<dt>Mains liées</dt><dd>{{if .E.MainsLiees}}oui (lecture seule pour le maître){{else}}non{{end}}</dd>
<dt>Mémoire disponible</dt><dd>{{.E.MemDispoMo}} Mo sur {{.E.MemTotaleMo}} Mo, swap {{.E.SwapPct}} %</dd>
<dt>Services en échec</dt><dd>{{if .E.Echecs}}<ul>{{range .E.Echecs}}<li class="ko">{{.}}</li>{{end}}</ul>{{else}}<span class="ok">aucun</span>{{end}}</dd>
</dl><small>Relevé {{.Quand}} (UTC), page régénérée toutes les 60 s. Administration : par le maître uniquement.</small></main></body></html>
`))

// Rendre produit la page (valeurs échappées par html/template).
func Rendre(e Etat) []byte {
	var b bytes.Buffer
	quand := ""
	if !e.Instant.IsZero() {
		quand = e.Instant.UTC().Format("2006-01-02 15:04:05")
	}
	if err := gabarit.Execute(&b, map[string]any{"E": e, "Style": template.CSS(Style), "Quand": quand}); err != nil {
		return []byte("<!doctype html><title>État</title>indisponible")
	}
	return b.Bytes()
}

// Ecrire remplace la page atomiquement : fichier de travail au nom fixe (jamais suivi s'il est un lien), 0644,
// synchronisé, puis renommé sur la page.
func Ecrire(chemin string, contenu []byte) error {
	tmp := filepath.Join(filepath.Dir(chemin), temporaire)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, 0o644)
	if err != nil {
		return err
	}
	_, err = f.Write(contenu)
	if err == nil {
		err = f.Chmod(0o644) // l'UMask de l'unité (0027) ne doit pas fermer la page à nginx
	}
	if err == nil {
		err = f.Sync()
	}
	if e := f.Close(); err == nil {
		err = e
	}
	if err == nil {
		err = os.Rename(tmp, chemin)
	}
	if err != nil {
		_ = os.Remove(tmp)
	}
	return err
}

// Tourner écrit la page tout de suite puis à chaque intervalle, jusqu'à l'annulation de ctx. Il ne dépend pas du
// maître : la page vit sans lui. Un échec d'écriture est journalisé une fois par cause, jamais fatal.
func Tourner(ctx context.Context, intervalle time.Duration, chemin string, lire func(context.Context) Etat) {
	t := time.NewTicker(intervalle)
	defer t.Stop()
	dernier := ""
	for {
		err := Ecrire(chemin, Rendre(lire(ctx)))
		msg := ""
		if err != nil {
			msg = err.Error()
		}
		if msg != dernier && msg != "" {
			log.Printf("page d'état non écrite : %v", err)
		}
		dernier = msg
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// NomSur : le nom de machine réduit à un libellé DNS sûr (affiché seul).
func NomSur(n string) string {
	n = strings.ToLower(strings.TrimSpace(n))
	if i := strings.IndexByte(n, '.'); i >= 0 {
		n = n[:i]
	}
	if !nomDNS.MatchString(n) {
		return "box"
	}
	return n
}
