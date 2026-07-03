# Design — Rapport kbin fidèle (PDF donut-grids + media types) + WebUI DPI types de données

- **Issue** : [#785](https://github.com/CyberMind-FR/secubox-deb/issues/785)
- **Date** : 2026-07-03
- **Auteur** : Claude Code (agent), pour Gérald Kerma
- **Licence** : LicenseRef-CMSD-1.0

## 1. Problème

La page web du rapport (`/report/me/html`, servie via le vhost `kbin.gk2.secubox.in`) est
la référence UX : trois onglets **🍪 Pistage / 🛰️ DPI-Exfil / 🌍 Overall**, chaque
onglet DPI affichant quatre donuts conic-gradient (Catégories de service, Protocoles,
Alertes exfil, Top destinations) plus une ligne de KPI.

Le **PDF** (`/report/me`, moteur fpdf2 + matplotlib) est en retard sur cette page :

1. La section DPI-Exfil du PDF est rendue en **puces texte** (`_donut_lines`,
   `reports.py:262-289`) au lieu des donuts de la page web.
2. L'onglet **Overall** n'est représenté dans le PDF que par **une seule puce**
   « Categories (global) » — pas de parité avec les 4 donuts de `#pane-overall`.
3. Aucune dimension **« types de médias »** : le rapport ne montre pas les
   Content-Type MIME réellement captés (vidéo / audio / manifests HLS·DASH / pages
   vidéo), alors que cette donnée existe déjà dans `/run/secubox/media-catch.jsonl`.

En parallèle, le **WebUI DPI** (`/dpi/`) classe le trafic par catégorie de service
(SNI → media/cloud/…) mais n'agrège **nulle part** un breakdown board-wide du « type
de données obtenues » ; `by_category` n'apparaît que comme micro-chips par device, et
aucune inspection MIME n'y est surfacée.

## 2. Objectif

Livraison « tout en un » :

- Rendre le **PDF fidèle** à la page web (donut grids DPI-Exfil **me** + **overall**).
- Ajouter la dimension **🎬 Types de médias** (catégorie DPI `media` **et** MIME réels
  captés) au rapport, côté PDF **et** page web, en **me + overall**.
- Enrichir le **WebUI DPI** avec deux nouvelles cards : agrégat des types de services
  (bytes par catégorie) et types de médias MIME captés.

Deux notions de « media » cohabitent délibérément (choix utilisateur « les 2 ») :
- **catégorie de service DPI `media`** : streaming par SNI (Netflix/YouTube/Spotify),
  déjà présente dans le donut « Catégories de service » ;
- **types MIME captés** : Content-Type réels vus par le MITM en R4 analyst
  (`video/*`, `audio/*`, `application/vnd.apple.mpegurl`, DASH `application/dash+xml`,
  pages `text/html` cloneables YouTube), depuis `media-catch.jsonl`.

## 3. Périmètre

Inclus (une seule itération) :

| Volet | Fichiers | Livrable |
|---|---|---|
| Core | `common/secubox_core/media_catch.py` (nouveau) | parseur/agrégateur partagé de `media-catch.jsonl` |
| V1 | `packages/secubox-toolbox/secubox_toolbox/api.py` | `_media_stats(mac_hash)` → `{me, all}` ; feed `report_me` + `report_me_html` |
| V2 | `packages/secubox-toolbox/secubox_toolbox/reports.py` | DPI-Exfil (me) + Overall (all) en donut grids matplotlib ; bloc 🎬 Types de médias |
| V2b | `packages/secubox-toolbox/conf/report-live.html.j2` | bloc 🎬 Types de médias (me + overall) — parité PDF↔web |
| V3A | `packages/secubox-dpi/www/dpi/index.html` | card « Types de services captés » (bytes ⬆️/⬇️ par catégorie) |
| V3B | `packages/secubox-dpi/api/main.py` + `www/dpi/index.html` | endpoint `GET /media_types` + card MIME + `loadMediaTypes` |

Hors périmètre :

- Aucune modification du moteur Go (`secubox-dpi/collector`, `secubox-toolbox-ng/sbxmitm`).
  `media-catch.jsonl` est déjà produit ; on ne fait que le **consommer**.
- Pas de nouvelle capture réseau, pas de nouveau champ collector.
- Pas de refonte du thème/CSS ; on réutilise la charte P31 existante.

## 4. Architecture

### 4.1 Source de vérité `media-catch.jsonl`

Fichier append-only JSONL, un `mediaRecord` par ligne, produit par les workers
`sbxmitm` (`packages/secubox-toolbox-ng/cmd/sbxmitm/mediacatch.go`) uniquement quand
`--media-catch` est actif (R3/R4 analyst). Champs pertinents :

```json
{ "ts": 1751500000, "client": "<mac_hash 16 hex>", "host": "…",
  "url": "…", "kind": "manifest|video|audio|page",
  "ctype": "video/mp4", "bytes": 123456 }
```

- **`client`** = `clientHashFromConn` = **le même `mac_hash` wg-persona** que le rapport
  (confirmé : `main.go:437` passe `clientHash`). Donc filtrage per-client fiable.
- Fichier en `/run` (tmpfs), `0644` → **lisible par l'utilisateur `secubox`** qui fait
  tourner toolbox et dpi. Aucun changement de permission requis.
- `/run/secubox` reste `1777 root:root` — on ne fait que **lire** un fichier dedans.

### 4.2 Helper partagé `common/secubox_core/media_catch.py`

Un seul point de lecture/agrégation, importé par les deux modules (DRY — les deux en
ont besoin, seule la découpe me/all diffère).

```
def aggregate(path="/run/secubox/media-catch.jsonl",
              mac_hash: str | None = None,
              max_lines: int = 50_000) -> dict
```

Comportement :

- Lit le JSONL en **best-effort**, tolère les lignes corrompues (skip), borne à
  `max_lines` (lecture par la fin — tail — pour rester O(fenêtre) sur un fichier long).
- Produit **deux vues** en un passage :
  - `all` : agrégat board-wide (tous clients) ;
  - `me` : agrégat filtré `record.client == mac_hash` (uniquement si `mac_hash` fourni).
- Chaque vue = `{present, flows, bytes, kinds[], ctypes[], top_hosts[]}` où :
  - `kinds[]` : `[{label, emoji, count}]` pour manifest/video/audio/page,
  - `ctypes[]` : top Content-Type MIME bruts par nombre de flux,
  - `top_hosts[]` : `[{host, kind, bytes}]` triés par bytes desc.
- **Ne renvoie PAS** les segments pct/start/end : le calcul donut (`_dpi_donut`) reste
  côté module consommateur, pour rester cohérent avec le style de chaque UI.
- Fail-empty : fichier absent/vide → `{me: {present:false…}, all: {present:false…}}`.

Emoji kinds : `video 📺`, `audio 🎵`, `manifest 🎞️`, `page ▶️`.

Le helper est **pur** (entrée = chemin + hash, sortie = dict), donc testable en
isolation avec un JSONL fixture.

### 4.3 V1 — `_media_stats(mac_hash)` (toolbox `api.py`)

Wrapper mince, sur le modèle exact de `_dpi_stats` (`api.py:2507`) :

```
def _media_stats(mac_hash):
    agg = secubox_core.media_catch.aggregate(mac_hash=mac_hash)
    # applique _dpi_donut() aux kinds + ctypes pour obtenir start/end/pct
    return {"me": _shape(agg["me"]), "all": _shape(agg["all"])}
```

- `_shape` transforme `kinds`/`ctypes` en donuts via le `_dpi_donut` existant (réutilisé,
  pas de nouvelle logique de pourcentage).
- Injecté dans :
  - `report_me_html` : nouvelle variable template `media_exfil=_media_stats(mac_hash)`
    (`api.py:2767`) ;
  - `report_me` : `data["media_exfil"] = _media_stats(mac_hash)` (`api.py:2806`).

### 4.4 V2 — PDF fidèle (`reports.py`)

Décision de rendu : **grilles 2×2 matplotlib → PNG** (`_mpl_donut_grid_png`, déjà
existant #703/#711/#714). Justification : les donuts vectoriels fpdf2 s'affichent en
blanc sur les viewers iOS/Chrome ; le PNG raster s'affiche partout. C'est déjà la
solution retenue pour le device-grid — on l'étend, on n'invente rien.

Remplacement dans `render_pdf` (section « DPI / EXFILTRATION », `reports.py:255-289`) :

- **Supprimer** `_donut_lines` (rendu texte).
- **DPI-Exfil (me)** : `_pdf_donut_grid` avec les 4 donuts
  `[Catégories, Protocoles, Alertes, Top destinations]` (source `data["dpi_exfil"]["me"]`)
  précédé de la ligne KPI `_kv` (flux / ⬆️ Mo / ⬇️ Mo / alertes). Miroir de `#pane-dpi`.
- **Overall (all)** : `_pdf_donut_grid` avec les mêmes 4 donuts agrégés
  (source `data["dpi_exfil"]["all"]`) + KPI `_kv` (appareils / flux / alertes).
  Miroir de `#pane-overall`.
- **Bloc 🎬 Types de médias** (nouveau `_section` « TYPES DE MÉDIAS CAPTÉS ») :
  - `_pdf_donut_grid` avec `[kinds(me), ctypes(me), kinds(all), ctypes(all)]`
    (2×2 : ligne 1 = cet appareil, ligne 2 = réseau) ;
  - `_emoji_table` top hôtes média (`host · kind · Mo`) à partir de `me.top_hosts`.
  - Si les deux vues sont vides → une puce « surfer via le tunnel R3 pour capter les
    médias », cohérent avec le fail-empty DPI.

`_pdf_donut_grid` accepte déjà une liste de `{title, hole, segments}` ; on lui passe les
segments issus de `_media_stats`. Aucun nouvel helper de dessin.

### 4.5 V2b — Parité web (`report-live.html.j2`)

La macro `donut(title, hole, items)` (`report-live.html.j2:126-143`) est réutilisée telle
quelle. Ajouts :

- Dans `#pane-dpi`, après le bloc DPI existant, une card **🎬 Types de médias captés**
  rendant `donut('📺 Types', 'médias', media.me.kinds)` +
  `donut('🏷️ Content-Type', 'MIME', media.me.ctypes)` + petite table top hôtes.
- Dans `#pane-overall`, la même card en version `media.all.*`.
- Variable template `media` = `media_exfil` passé par `report_me_html`.
- Fail-empty : `{% if media.me.present %}` … `{% else %}<div class="empty">…</div>`.

Ainsi le PDF ne montre jamais une dimension absente de la page web (et inversement).

### 4.6 V3 — WebUI DPI (`secubox-dpi`)

**Card A — 🏷️ Types de services captés (board-wide), frontend only.**
`loadExfil` (`www/dpi/index.html:548-645`) itère déjà `devices[]`. On somme
`devices[].services[]` par `category` en cumulant `up_bytes`/`down_bytes` (plus riche
que les chips `by_category` qui ne comptent que des flux). Rendu : une nouvelle card
(donut + barres) réutilisant la map `CATEGORY` d'icônes/badges (lignes 527-537). Aucun
changement backend.

**Card B — 🎬 Types de médias captés (MITM R4), nouvelle donnée MIME.**
- **Endpoint** `GET /media_types` sur `app` (pas `router`), **no-JWT**, fail-empty —
  exactement le pattern de `/exfil` (`api/main.py:68-82`). Il appelle
  `secubox_core.media_catch.aggregate()` **sans** `mac_hash` (vue board-wide `all`
  uniquement — le WebUI DPI est une vue opérateur, pas per-client) et renvoie
  `{kinds, ctypes, top_hosts, flows, bytes}`.
- **Frontend** : `loadMediaTypes()` fetch `/api/v1/dpi/media_types`, rend une card
  (donut kinds + top ctypes + top hôtes). Ajouté à `refreshAll()` (cycle 10 s).

Note couplage : `secubox-dpi` importe `secubox_core.media_catch`. `secubox-core` est
déjà une dépendance de tous les modules (lib partagée) — aucun nouveau paquet.

## 5. Flux de données

```
sbxmitm (R4) ──append──▶ /run/secubox/media-catch.jsonl (0644)
                                   │
                 secubox_core.media_catch.aggregate(path, mac_hash?)
                     │                                   │
         toolbox _media_stats(mac_hash)        dpi /media_types (all)
             │            │                              │
     report_me (PDF)  report_me_html (web)        loadMediaTypes()
     reports.py grids   donut() macro            card MIME dans /dpi/
```

Sources DPI service-catégorie (inchangées) :
`/var/lib/secubox/dpi/{state,cumulative}.json` → `_dpi_stats` (toolbox) et `/exfil` (dpi).

## 6. Gestion d'erreurs / dégradation

- **media-catch absent/vide** (cas nominal hors R3/R4) : toutes les vues renvoient
  `present:false` → cards/blocs affichent un message « surfer via le tunnel R3 » ;
  aucune exception ne remonte.
- **Ligne JSONL corrompue** : skip silencieux (best-effort), le reste est agrégé.
- **Fichier volumineux** : lecture bornée `max_lines` (tail) → coût O(fenêtre).
- **fpdf2/matplotlib absent** : `render_pdf` conserve son fallback texte existant ; les
  nouveaux blocs suivent les `_ensure_space`/try-except déjà en place.
- **Lecture concurrente** : lecture seule d'un fichier O_APPEND ; lignes < PIPE_BUF
  (garantie côté producteur) → pas de ligne torn.

## 7. Tests

- **Unitaire `secubox_core.media_catch.aggregate`** : fixture JSONL (mix
  video/audio/manifest/page, 2 clients + lignes corrompues) → vérifie `me` filtré par
  hash, `all` agrégé, `kinds`/`ctypes`/`top_hosts` triés, `present` flags, et cas
  fichier absent → fail-empty.
- **Unitaire `_media_stats`** : les donuts portent `pct`/`start`/`end` cohérents (somme
  des pct ≈ 100 par vue).
- **Rendu PDF** : `render_pdf` sur un `data` synthétique avec `dpi_exfil` + `media_exfil`
  peuplés produit un blob PDF non vide (smoke) ; et sur `data` vide ne lève pas.
- **Endpoint `/media_types`** : TestClient → 200 + schéma attendu quand le fichier
  existe (tmp path patché) ; 200 fail-empty quand absent.
- **Parité** : test template — les variables `media_exfil` rendues sans erreur Jinja
  (me + overall), fail-empty inclus.

## 8. Risques / points d'attention

- **`media` flag `exfil:false`** côté DPI : on n'y touche pas — les nouvelles cards sont
  informatives (« types de données »), pas des alertes d'exfil.
- **Volume media-catch** : sur une session vidéo longue, beaucoup de lignes ; le dedup
  producteur limite déjà (host+path sans query), et `max_lines` borne la lecture.
- **Deux notions de « media »** dans la même UI : titrer explicitement — « Catégories de
  service » (SNI) vs « Types de médias captés (MIME) » — pour éviter la confusion.
- **Déploiement** : 3 paquets touchés (toolbox, dpi, core). Rebuild + redeploy des 3 ;
  la page web report + WebUI DPI sont servis par nginx static → invalider le cache.
