<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# WebOS SBX / Hall Cardlets — Phase 0 : Discovery (read-only, aucun code)

**Issue** : #1175 · **Brief de conception** : `docs/dossiers/webos-sbx-hall-cardlets.md`
**Date** : 2026-08-24 · **Statut** : rapport de découverte — **porte de validation avant P1**

> Le brief (§20) impose **Phase 0 = Discovery ONLY**. Ce document rend les 9 livrables
> exigés (source servant all.gk2.net, registre, santé/latence, failover LAN/WAN, hooks
> auth, API/data cardlet Radio, code réutilisable, fichiers P1 exacts proposés, risques).
> **Aucun code n'a été écrit.** Rien n'est déployé.

---

## 1. Ce qui sert `all.gk2.net`

**Il n'existe PAS de paquet « catalogue » dédié.** `all.gk2.net` est un **alias de domaine
routé sur le même vhost nginx que le panel admin** — il sert le dashboard de
**`secubox-hub`**, pas une page publique distincte.

- Chaîne de service : `packages/secubox-hub`
  - Racine statique partagée (tous modules) : `/usr/share/secubox/www` — chaque paquet installe son `www/<id>/` (`packages/secubox-hub/debian/rules:8-9`).
  - Landing : `packages/secubox-hub/www/index.html`, servie par `location / { try_files … @fallback }` (`nginx/webui.conf:130-137`), dans le bloc `server_name admin.gk2.secubox.in 192.168.1.200 localhost;` (`webui.conf:52-411`).
  - API : `packages/secubox-hub/api/main.py`, FastAPI `root_path="/api/v1/hub"`, proxifiée `location /api/ → aggregator.sock` (`webui.conf:144-154`) — **servie in-process par l'agrégateur**, pas en uvicorn autonome.
- **L'alias n'est PAS complètement câblé** : `all.gk2.secubox.in` n'est pas encore dans `server_name` (`webui.conf:55`). Le `default_server` (`webui.conf:26-49`) attrape tout domaine inconnu → `/shared/wrong-domain.html`. Donc `all.gk2.net` tombe aujourd'hui sur la page « mauvais domaine ». (Cf. `.claude/WIP.md:56`, item encore ouvert : alias `all.gk2.net→all.gk2.secubox.in`, ACL HAProxy + route WAF + certs/DNS.)
- **La tranche RÉELLEMENT publique** du catalogue = `packages/secubox-hub/www/shared/sidebar.js` (`MENU_API=/api/v1/hub/public/menu`, `BATCH_HEALTH_API=/api/v1/hub/public/health-batch`) — script injecté dans chaque page module, seul composant qui rend menu + santé **sans JWT**.

**Conséquence de conception** : la prémisse du brief (« all.gk2.net = catalogue autoritatif »)
est **aspirationnelle**. Le catalogue autoritatif d'aujourd'hui = `menu.d` + endpoints publics
du Hub ; la surface publique = `sidebar.js`. `hall.gk2.net` sera une **surface blanche
publique NEUVE** consommant les MÊMES endpoints publics du Hub. Il ne faut pas « reprendre »
un all.gk2.net existant — il faut le finir de câbler (alias) puis poser Hall à côté.

---

## 2. Contrat registre — endpoints Hub à réutiliser

Tous dans `packages/secubox-hub/api/main.py`.

### `GET /api/v1/hub/public/menu` — `public_menu()` (`:196-221`) · **public, sans JWT**
Cache double-buffer mémoire → `/var/cache/secubox/menu.json` → placeholder cold-start ;
refresh 30 s (`_refresh_menu_cache` `:153-180`, build `_compute_menu_sync` `:77-150`).
```json
{"categories":[{"id":"wall","name":"Wall","icon":"🛡️","order":1,
  "items":[{"id":"waf","name":"WAF","category":"wall","icon":"🔥","path":"/waf/",
            "order":105,"description":"…","installed":true,"active":true}]}],
 "total_installed":42,"total_active":30,"cached_at":1234567890.1}
```
Cold-start : `{"categories":[],"total_installed":0,"total_active":0,"warming":true}`.

### `GET /api/v1/hub/public/health-batch` — `public_health_batch()` (`:311-326`) · **public**
Build `_refresh_health_batch()` (`:510-566`) : UN `systemctl list-units secubox-*` + scan
`/run/secubox/*.sock`, cache `_cache["health_batch"]`, TTL 5 s.
```json
{"modules":{"crowdsec":{"status":"ok","msg":"Running"},
            "dpi":{"status":"warn","msg":"reloading"},
            "auth":{"status":"error","msg":"Failed"}},"count":42}
```
`status ∈ ok|warn|error` — **pas de latence numérique ici**.

### `GET /api/v1/hub/dashboard` — `dashboard(user=Depends(require_jwt))` (`:792-817`) · **JWT requis**
(Le brief le listait à tort avec les deux publics.) board info + modules{active,socket,version}
+ cpu/mem/disk/load/uptime + build_info.

Autres : `GET /public/info` (version/auth_mode login), `GET /public/led_status` (LED matérielles, sans rapport avec la santé service).

---

## 3. Modèle de données service — existant vs. objet normalisé du brief (§8)

**Manifeste** = drop-ins JSON par paquet : `MENU_DIR=/usr/share/secubox/menu.d`
(`main.py:1981`), chargés par `_load_menu_definitions()` (`:2028-2048`), un fichier/module
(ex. `packages/secubox-radio/menu.d/60-radio.json`). Catégories = dict fixe 6 entrées
`CATEGORY_META` (`:2014-2025`). `installed`/`active` calculés à la requête
(`_check_module_installed` `:2051-2080` = existence de `www/<id>/index.html` ;
`_check_module_active` `:2083-2101` = socket + `systemctl is-active`).

| Champ brief | Existe ? | Où / écart |
|---|---|---|
| `id` | ✅ | `menu.d/*.json` — **c'est la clé de jointure** |
| `name` | ✅ | `menu.d` |
| `description` | ✅ (souvent vide) | `menu.d` |
| `category` | ✅ (enum fixe 6 : auth/wall/boot/mind/root/mesh) | `menu.d` + `CATEGORY_META` |
| `icon` | ✅ | `menu.d` |
| `urls.lan` / `urls.wan` | ❌ | seulement un `path` relatif same-origin. `secubox-vhost` a un registre **domaine**→url (`GET /vhosts` `packages/secubox-vhost/api/main.py:~220,342-378`), **sans clé de jointure vers l'`id` de `menu.d`** |
| `routing.mode/available` | ⚠️ | `secubox-exposure.ExposureSet.reach ∈ localhost\|lan\|wan` (`api/main.py:119-122`, par-vhost) — non câblé à l'`id` |
| `health.state` | ✅ | `public/health-batch` — vocabulaire `ok/warn/error` ≠ `online/degraded/offline/unknown` du brief |
| `health.latency_ms` | ⚠️ | `secubox-exposure.ServiceHealth.response_time_ms` (`api/main.py:91-97`, `GET /health/services :1138`) — **absent de health-batch**, clé service ≠ `id` |
| `cardlet{enabled,kind,endpoint,size}` | ❌ | inexistant dans le schéma `menu.d` |
| `auth.mode` | ⚠️ | seulement global (`public/info`), pas par-service |
| `capabilities[]` | ❌ | proche : `requires:[…]` ad-hoc dans `secubox-release/menu.d` (dépendance paquet, pas capacité) |

**Le vrai écart structurel n'est pas la collecte de données — c'est la JOINTURE.**
`menu.d` est clé par `id` ; santé/latence/reach (`exposure`) et domaine→URL (`vhost`) sont
clés par **vhost/domaine**. Réconcilier `id ↔ domaine` est le cœur de P1.

---

## 4. Santé & latence — trois mécanismes NON unifiés

Aucun n'émet aujourd'hui un enum unifié `online/degraded/offline/unknown` + `latency_ms`
pour un service arbitraire. Le plus proche = `secubox-exposure`.

| # | Source | Mécanisme | États | Latence | Refresh |
|---|---|---|---|---|---|
| a | Hub sidebar LED — `_refresh_health_batch` (`hub/api/main.py:510-566`) | 1× `systemctl list-units secubox-*` + scan `/run/secubox/*.sock` | `ok\|warn\|error` (+ « Asleep→ok » via `sleepable-modules.json`) | ❌ aucune | 5 s, public |
| b | health-doctor — `checks.py`+`runner.py` | REGISTRY de checks (systemctl / TCP `socket.create_connection` / UDS / lxc-info / mtime) | `ok:bool` (pas de degraded) | `elapsed_ms` par check | 60 s (timer) |
| c | **exposure — `check_service_health` (`exposure/api/main.py:354-405`)** | `asyncio.open_connection('127.0.0.1',port)` + `pgrep tor` | **`HEALTHY\|DEGRADED\|UNHEALTHY\|UNKNOWN`** (`:75-79`) | **`response_time_ms`** (`ServiceHealth :91-97`) | 300 s |

**Lacune** : `secubox-profiles/api/healthsync.py:14-26` documente que le **vrai prober HTTP
par-module** (`module_prober.py`/`prober.py` → `/var/cache/secubox/health/{modules,status}.json`,
lu par `hub` `/module-health/*` et `/health-monitor/*` `main.py:1311-1450`) **n'est pas dans
le repo** — seulement sur la board. Suivi : `.claude/TODO.md:415` **#393**.

---

## 5. Failover / reachability LAN/WAN

Pas de `urls{lan,wan}` aujourd'hui. La primitive réelle = un **niveau de reach**, propriété de
`secubox-exposure` :
- `packages/secubox-exposure/api/reach.py:9` — `REACH_LEVELS=("localhost","lan","wan")`,
  `LAN_CIDRS=("10.0.0.0/8","172.16.0.0/12","192.168.0.0/16")`, `MESH_CIDR="10.10.0.0/24"`.
- `reach_snippet()` (`:15-31`) génère un bloc nginx `allow/deny` par vhost →
  `/etc/nginx/snippets/exposure/<vhost>.conf`. `read_snippet_reach()` (`:48-62`) **infère** le
  reach depuis le snippet (snippet absent ⇒ `wan`). Accesseur canonique
  `load_record(vhost)` → `{vhost,reach,mesh,tor}`.
- API : `ExposureSet{reach,mesh,tor}` ; `GET/POST /exposure/{vhost}` (JWT, reload nginx + audit CSPN).
- **La reachability est INFÉRÉE de la grille en place, pas mesurée.** `check_service_health`
  ne sonde que `127.0.0.1:port` — il ne distingue pas un point de vue LAN d'un WAN.

Composer `urls{lan,wan}` + `routing{mode,available}` demandera de joindre : (1) domaine/URL de
`secubox-vhost`, (2) `reach/mesh/tor` d'`exposure` (via `secubox-vhost/api/exposure_read.py`),
(3) une sonde de reachability fraîche — aucun n'émet un objet `lan/wan` unique aujourd'hui.

---

## 6. Auth — `sbx_token` + `require_jwt` + public/authed

**Frontend** — `packages/secubox-hub/www/shared/api-utils.js` (à réutiliser **verbatim**) :
- `getToken()` (`:60-66`) → `localStorage.getItem('sbx_token')`.
- `buildHeaders()` (`:73-85`) → `Authorization: Bearer <token>` si présent.
- `safeFetch()` (`:96+`) → sur 401 (`:113-117`) redirige `/login.html?redirect=…`.

**Backend** — `common/secubox_core/auth.py` :
- `require_jwt(request, creds=Depends(_bearer))` (`:204-238`) — accepte **Bearer OU cookie
  `secubox_session`** (Bearer d'abord puis cookie, pour que le token périmé ne masque pas une
  session valide — #942) ; `_validate_token` (`:180-201`) : décode HS256 (secret obligatoire,
  **jamais de défaut**), rejette sans-`sub`, rejette scope-tokens, valide `jti`
  (fail-closed #942), re-vérifie `user_store.is_enabled(sub)` à chaque requête.
- Usage : `Depends(require_jwt)` par-endpoint.

**Public vs authed dans le Hub** (`hub/api/main.py:39-41`) :
```python
router = APIRouter()
public_router = APIRouter(prefix="/public", tags=["public"])
```
Tout sur `public_router` (`/public/menu|info|led_status|health-batch|firewall_summary`) =
**sans JWT** (shell pré-login). Tout sur `router` = `Depends(require_jwt)` par-route.
**Motif à suivre pour l'API WebOS** : `public_router` pour ce que le shell pré-auth doit voir
(minimal), `router` avec `require_jwt` pour tout endpoint sensible/mutation.

---

## 7. Radio = cardlet active de référence — API réelle + widget embarquable

**Serveur** : `packages/secubox-radio/internal/web/web.go` (Go net/http). Routes montées 2× :
`/api/v1/radio/<x>` (vhost public) et `/<x>` (agrégateur) — `routeur()` `:475`, `routes()` `:542`.

| Endpoint | M | Où | Forme |
|---|---|---|---|
| `/current` (now-playing + chat en 1 appel) | GET | `web.go:695 actuel()` | `{horloge_ms,silence,piste:vuePiste,offset_ms,chat:[phrase]}` (chat si connecté, `?depuis=<curseur>`) |
| `/playlist` | GET | `:730` | `{pistes,avenir(3),passe(8)}` |
| `/stats` | GET | `:516` | `{pistes,propositions,auditeurs,visites}` (`auditeurs`=cookie 45 s) |
| `/propositions` (+`/{id}/{coeur\|valider\|refuser}`) | GET/POST | `:758,:815` | file + réactions + modération sysop |
| `/chat` | POST | `:1062` | `{Corps}`→`{phrase}` ; relaie vers timeline BBS si `Bearer` (`diffuseChat :233`) |
| `/replay/{piste}/timeline` | GET | `:264` | `{comments:[Comment]}` (spine BBS, ordonné `offset_ms`) |
| `/vignette/{id}` | GET | `vignette.go:22` | miniature YouTube relayée `image/jpeg` (jamais de lien tiers, CSP `img-src 'self'`) |
| `/media/{id}` | GET | `media.go:27` | clip mp4/audio, Range, gated `v.Connecte` |
| `/mini`, `/micro` | GET | `web.go:361 miniPlayer()` | même bundle HTML/JS, classes CSS compactes |
| `/healthz` | GET | `:591` | `"ok"` |

**`vuePiste`** (`web.go:655`) : `{id,titre,auteur,duree_ms,coeurs,source,etat,lot,lot_titre,motif,
en_cache,ecarte,raison,aime,aimeurs:[{user_id,pseudo,mis_le}]}` — title/subtitle/artwork
(`/vignette/{id}`)/metrics(`coeurs`)/social(`aimeurs`) en une ligne = **exactement la forme
qu'un adaptateur cardlet doit normaliser** vers le payload `kind:"radio-now-playing"` du brief §6.

**Widget embarquable = le motif #1171/#1172, DÉJÀ EN PROD** :
- `Serveur.CadreParent` (`web.go:97`) whiteliste **une** origine autorisée à `frame-ancestors`
  `/mini`/`/micro` ; tout le reste `frame-ancestors 'none'` (`politiqueMini() :331`).
- Consommateur : `packages/secubox-bbs/internal/web/templates/newsroom.html:280-285`
  (`{{define "avradio"}}`) → `<iframe class="radioframe" src="{{.RadioBase}}/micro" allow="autoplay" loading="lazy">`, **sans chrome d'en-tête** — la page `/micro` EST la carte.
- Câblage : `bbs/internal/web/server.go:95-108` (`RadioBase`+`FrameOrigines`, appliqué `:444`),
  `routes.go:55-57,299`. `radio.js:9-25` détecte le mode via `location.pathname`.
- ⚠️ Une tentative de réduire encore le chrome (`feat/radio-cardlet-bar`, PR #1152) a été
  **revertée** (`9c39fb0e5`, « widget invisible »). C'est du chrome UI, pas le mécanisme
  iframe/CSP (qui est intact et live). À lire avant de retoucher la barre.

---

## 8. Frontend réutilisable (à préserver, ne PAS dupliquer)

- **`secubox-hub/www/shared/sidebar.js`** (~2590 l.) — nav santé-aware ; consomme
  `/public/menu`+`/public/health-batch` ; LED par-module (double-buffer shadow→swap→active,
  `:747-1100`). **Motifs cache-first réutilisables** (les plus propres du repo) :
  - menu `sbx_menu_cache` TTL 1 h (`:44-76`) ; HTML sidebar pré-rendu `sbx_sidebar_html_v1` (`:87-108`) ;
  - **stale-while-revalidate** métriques page `sbx_page_metrics_cache` TTL 30 s : rend le cache
    puis `setTimeout(loadPageMetrics(true),100)` (`:251-303`) — **exemple canonique** ;
  - status-bar `sbx_statusbar_cache` TTL 60 s ; sparkline `sbx_strip_history` ring 60 (`:787-817`).
- **`secubox-hub/www/shared/health-banner.js`** — `HealthCache` double-buffer distinct
  (`sbx_health_cache`, 30 s). ⚠️ **Deux implémentations de cache santé coexistent déjà**
  (sidebar + banner) — Hall ne doit pas en ajouter une 3ᵉ, mais consolider/réutiliser.
- **`secubox-hub/www/shared/api-utils.js`** — `getToken/buildHeaders/safeFetch` (§6).
- **`secubox-bbs/internal/web/templates/layout.html`** — coquille 3 colonnes
  (`.shell`→`header.bar`/`nav.rail`/`.liste?`/`main.vue`/`.etat`/`nav.basse`), le serveur
  décide quel panneau porte le contenu (`:69-80`) ; `{{define "vignette"}}` réutilisable ;
  JS `static/coquille.js`.

---

## 9. État : greenfield

**Aucun code `webos`/`hall`/adaptateur-cardlet n'existe.** Seul artefact = le brief
`docs/dossiers/webos-sbx-hall-cardlets.md` (commit `e2c16c560`). Les autres occurrences de
« cardlet » = convention UI générique préexistante et sans rapport (companion, radio compact,
newsroom BBS, dashboards torrent/ytsas). Trois branches `*cardlet-bar*` = itération revertée du
chrome radio (§7), bruit à ignorer. **On construit à partir de zéro**, sur : le motif iframe
`/micro`+`CadreParent`/`FrameOrigines` (§7) pour l'embarquable, et le stale-while-revalidate de
`sidebar.js` (§8) pour le cache.

---

## 10. Fichiers Phase 1 EXACTS proposés

P1 (brief §20) = **« Registre normalisé partagé »** uniquement (pas de shell, pas de cardlet).
Le brief §8 impose **d'étendre le Hub, pas de registre parallèle**. Donc P1 vit dans
`secubox-hub`, cache-first, **sans sonde live dans le chemin de requête** (l'agrégateur sert le
Hub in-process — cf. risque R4).

| Action | Fichier | Rôle |
|---|---|---|
| Créer | `packages/secubox-hub/api/webos/__init__.py` | package |
| Créer | `packages/secubox-hub/api/webos/registry.py` | `normalize_services()` : lit le cache `menu.d`/`public/menu` + `health-batch`, joint `id↔domaine` (via table de correspondance, R2), mappe `ok/warn/error`→`online/degraded/offline/unknown`, greffe `reach`+`latency_ms` depuis le cache exposure quand dispo (jamais de sonde synchrone), émet l'objet service normalisé §8. Flag `webos.enabled`. |
| Créer | `packages/secubox-hub/api/webos/idmap.py` | résolution `id↔vhost/domaine` (convention `<id>.gk2.secubox.in` + surcharges déclaratives) — le vrai point dur (R2) |
| Modifier | `packages/secubox-hub/api/main.py` | monter `public_router.get("/public/webos/services")` (liste normalisée, minimale sans auth) + `router.get("/webos/services")` (détail enrichi, `Depends(require_jwt)`) ; brancher le refresh dans `_background_cache_refresh` (pas de nouvelle boucle) |
| Créer | `packages/secubox-hub/api/webos/flags.py` | lecture `webos.*` feature flags (`webos.enabled` défaut off) |
| Créer | `tests/…/test_webos_registry.py` | normalisation registre, mapping santé (4 états), jointure `id↔domaine`, service offline rendu seul, cache stale visible, filtrage public-vs-authed |

**Non-P1 (rappel, phases ultérieures, NE PAS anticiper)** : `www/shared/webos/{webos-runtime,
webos-bar,webos-cardlets}.js` + `webos.css` (P2/P6), `www/hall/index.html` (P2),
`adapters/cardlets/{radio,bbs,metanews}` (P3/P4), `session_bridge` (P7), événements Cabine (P8).

---

## 11. Risques

- **R1 — `all.gk2.net` pas câblé.** La prémisse « catalogue autoritatif » est aspirationnelle ;
  aujourd'hui l'alias tombe sur wrong-domain (§1). `hall.gk2.net` est entièrement neuf →
  travail DNS/HAProxy/nginx `server_name`/certs (recoupe WIP ouvert + motif alias-domaines).
  *Ne pas bloquer P1 dessus* : P1 (registre) est servi par les endpoints Hub existants,
  indépendamment de l'alias.
- **R2 — La jointure `id↔domaine` (cœur du sujet).** Pas de clé commune entre `menu.d.id` et
  `vhost/exposure.domaine`. La convention `<id>.gk2.secubox.in` **n'est pas universelle**
  (LXC, alias, sous-vhosts). Sans table de correspondance fiable, `urls{lan,wan}`, `reach` et
  `latency_ms` seront faux/absents. → `idmap.py` déclaratif + tests.
- **R3 — Vocabulaire santé + latence.** `health-batch` = `ok/warn/error` sans latence ; le
  vrai prober HTTP est **hors repo (#393, on-board)**. Mapper vers 4 états est lossy ;
  la latence n'existe que dans exposure (300 s, par-vhost). P1 doit assumer « latency_ms
  best-effort / null » et l'afficher comme tel, pas inventer.
- **R4 — Congestion agrégateur.** Le Hub est servi **in-process par `aggregator.sock`**
  (SPOF/congestion connu). Toute composition lourde ou sonde live dans le endpoint WebOS
  risque de bloquer ~110 modules. → **strictement cache-first**, refresh en tâche de fond
  existante, endpoint = lecture mémoire. (Tension avec « composants vitaux indépendants de
  l'agrégateur » : si Hall devient vital, envisager un `secubox-webos.sock` dédié en P2,
  mais P1 reste dans le Hub par mandat du brief §8.)
- **R5 — Ne pas ajouter un 4ᵉ cache santé.** Deux coexistent déjà (sidebar + health-banner).
  Réutiliser, pas dupliquer (non-négociable brief §2).
- **R6 — Fuite d'inventaire en public.** `public/menu` expose déjà la liste des modules sans
  auth ; un `public/webos/services` exposant reach LAN/WAN + santé élargit la surface d'info
  pour un visiteur WAN non authentifié. → public = **minimal** (id/name/category/icon/état
  grossier) ; détail (reach, latency, URLs internes) réservé à `router` authentifié (§6, brief §7
  « count-before-content »).

---

## 12. Recommandation — porte de validation

Phase 0 rendue. **P1 recommandé = registre normalisé dans le Hub** (§10), cache-first,
avec `idmap.py` comme livrable central (R2) et un mapping santé 4-états explicitement
best-effort (R3). Aucune UI, aucune cardlet en P1.

**Décisions demandées avant d'écrire la spec P1 puis le plan :**
1. **Périmètre P1** — se limiter au registre normalisé + endpoint(s) (recommandé), ou inclure déjà le shell Hall vide (P2) ?
2. **Jointure id↔domaine (R2)** — convention `<id>.gk2.secubox.in` + fichier de surcharges déclaratif : OK comme base ?
3. **Emplacement** — rester dans `secubox-hub` (mandat brief §8) en P1, décision `secubox-webos` dédié repoussée à P2 (R4) : OK ?
4. **Alias `all.gk2.net`/`hall.gk2.net` (R1)** — traiter comme chantier infra séparé (hors P1) : OK ?
