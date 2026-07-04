# Design — SecuBox Media Buffer

- **Issue** : [#812](https://github.com/CyberMind-FR/secubox-deb/issues/812)
- **Date** : 2026-07-04
- **Licence** : LicenseRef-CMSD-1.0
- **Modules** : `packages/secubox-toolbox-ng/cmd/sbxmitm/` (capture) · `packages/secubox-dpi/` (API + UI) · `packages/secubox-toolbox/` (kbin report)

## 1. Problème

Aujourd'hui la plateforme voit passer les médias (R3/sbxmitm déchiffre le trafic client) mais n'en garde que des **métadonnées** : `mediacatch.go` écrit `media-catch.jsonl` = `{ts, mac_hash, host, url, kind, ctype, bytes}`. Aucun octet n'est conservé → impossible de **rejouer** un média. Séparément, `mediacache.go` (sbxwaf) met en cache des octets média sur disque (TTL+LRU) mais comme cache de perf transparent, côté réponse uniquement, non exposé.

L'utilisateur veut, pour sa « cabine numérique » : **capturer le média complet (upload + download), le présenter comme un média indépendant lisible via un lien, le garder un court instant, puis ne conserver que les métatags** une fois les octets purgés.

## 2. Objectif

Un tampon roulant type *dashcam* qui, pour chaque média up/down passant par R3 :
1. **capture** les octets complets (fichier direct ou flux HLS/DASH réassemblé) dans un buffer sur `/data` ;
2. **expose** un lien de relecture (fichier ou manifest HLS local réécrit), authentifié + audité ;
3. après la **fenêtre de rétention (~20 min, time-only)**, purge les octets mais **conserve le métatag** durablement ;
4. **affiche** les captures dans un onglet *Media* du dashboard DPI (galerie live) et en liens de relecture par persona dans le rapport kbin.

## 3. Décisions (brainstorm 2026-07-04)

| Axe | Décision |
|-----|----------|
| Portée | Upload **et** download, pipeline unifié |
| Déclencheur | **Tout**, fenêtre courte (dashcam roulant), éviction LRU sous pression disque |
| Flux | HLS/DASH **réassemblés** en manifest local rejouable |
| Rétention | **Time-only ~20 min** ; taille flottante sous un plafond de sécurité ; métatags toujours conservés |
| UI | Onglet DPI *Media* (galerie live) **+** liens kbin par persona ; **backend partagé** |
| Confidentialité | Admin voit tout ; vue kbin d'un device limitée à son `mac_hash` ; hôtes splice/passthrough **jamais** capturés ; chaque relecture auditée |

## 4. Architecture

### 4.1 Point de capture — sbxmitm (R3), pas sbxwaf

Les workers mitm `ng-worker@1..4` déchiffrent déjà le trafic client montant/descendant et émettent déjà les métadonnées media-catch (`mediacatch.go`). C'est **là** qu'on tee les octets — c'est le chemin sur lequel le persona wg (`mac_hash`) et le DPI-exfil sont déjà indexés. On ne touche **pas** `mediacache.go` (cache WAF public, réponse seule, autre chemin).

### 4.2 Composants

**A. `mediabuffer.go` (Go, sbxmitm)** — nouveau fichier à côté de `mediacatch.go`.
- Hook sur requête (upload) et réponse (download). Pour un `Content-Type` média sur un hôte **non-splice** :
  - **Fichier direct** (`video/*`, `audio/*`, `application/octet-stream` avec extension média, upload multipart) : tee le corps en streaming vers `sessionDir/object-<n>.<ext>`, borné par `perObjectCeil` (défaut 512 MiB ; au-delà → tronqué + flag `truncated`, métatag quand même).
  - **Manifest HLS/DASH** (`application/vnd.apple.mpegurl`, `application/dash+xml`) : ouvre/rattache une **session** clé = `(mac_hash, host, base-path)` ; stocke le manifest et chaque segment (`.ts`/`.m4s`) référencé, sous `sessionDir/`.
  - Écrit/complète un enregistrement **métatag** durable (voir 4.3), avec `session_id` + `buffer_ref`.
- Bornes : jamais bloquant pour le proxy (tee asynchrone via un writer intermédiaire + canal borné ; drop-si-plein plutôt que ralentir le flux). Interface :
  - `Consumes` : le flux corps requête/réponse + le contexte déjà calculé par `mediacatch.record(...)` (`client, host, url, path, ctype, size`).
  - `Produces` : fichiers sous `BUFFER_ROOT/<session_id>/`, lignes métatag sur `media-buffer.jsonl`.

**B. Janitor (Go, goroutine/timer dans sbxmitm ou un petit binaire `sbxmediabuf-janitor`)**
- Éviction **time-only** : supprime les octets d'un `session_id` dont le `first_ts` dépasse `RETENTION_SECS` (défaut 1200). Conserve la ligne métatag (marque `expired:true`, `buffer_ref:null`).
- Plafond de sécurité : si `BUFFER_ROOT` dépasse `SIZE_CEIL` (défaut p.ex. 24 GiB), évince en LRU (plus vieux `first_ts` d'abord) avant l'échéance.
- Idempotent, tourne toutes les ~30 s. `Consumes` : `media-buffer.jsonl` + l'état disque. `Produces` : suppression de `sessionDir`, réécriture de la ligne métatag en `expired`.

**C. API relecture/liste (Python, dans `secubox-dpi/api/main.py`)**
- `GET /media/buffer` → liste des métatags (récents d'abord). **Admin** = tous ; **persona** (JWT non-admin lié à un `mac_hash`) = seulement ses propres captures. Champs par item : `{id, session_id, ts, mac_hash, host, url, direction, kind, ctype, bytes, title, thumb_url?, playable, expired}`.
- `GET /media/replay/{id}` → sert les octets : fichier direct en streaming (`Content-Type` d'origine, `Content-Disposition` optionnel), **ou** un **manifest HLS réécrit** dont les URI segments pointent vers `/media/replay/{id}/seg/{n}` (proxy depuis le buffer). Renvoie **410 Gone** si `expired` (métatag seul). Chaque appel → **audit** (`/var/log/secubox/audit.log` : qui, quoi, quand, ip).
- `GET /media/replay/{id}/seg/{n}` → un segment HLS depuis le buffer (même gate).
- `GET /media/thumb/{id}` → vignette (générée à la capture pour la vidéo : 1 frame ; sinon icône par `kind`).
- Toutes en `def` (I/O disque bloquant → threadpool, cf. le SPOF agrégateur #808) ; gate `require_jwt` + dépendance `require_admin_or_owner`.

**D. Onglet DPI *Media* (frontend, `packages/secubox-dpi/www/`)**
- Galerie live : cartes `{vignette, host, device(mac_hash court), ⬆/⬇ direction, kind, taille, âge}` ; bouton **▶ Play** / **⬇ Download** tant que `playable` ; grisé « métatag seul » si `expired`. Rafraîchissement périodique (double-caching côté API, cf. règle CLAUDE.md).

**E. Rapport kbin (`packages/secubox-toolbox/secubox_toolbox/reports.py` + `api.py`)**
- Section « 🎬 Médias récents » par persona, via `_enrich_report_data(mac_hash, …)` déjà en place : liste les captures du `mac_hash` avec lien de relecture (HTML) — expirées affichées en métatag.

### 4.3 Enregistrement métatag durable

`media-buffer.jsonl` (append-only, comme media-catch), une ligne par média :
```json
{"id":"<hex>","session_id":"<hex>","first_ts":…,"last_ts":…,"mac_hash":"…","host":"…",
 "url":"…","direction":"up|down","kind":"video|audio|file|manifest","ctype":"video/mp4",
 "bytes":123,"title":"…","segments":N,"truncated":false,"buffer_ref":"<session_id>|null",
 "expired":false}
```
Le métatag survit à l'éviction (`buffer_ref:null, expired:true`). L'API lit ce fichier (tail borné, fail-empty — même pattern que `secubox_core/media_catch.py`).

### 4.4 Disposition disque

```
/data/secubox/media-buffer/           (0750 secubox:secubox)
├── media-buffer.jsonl                 métatags durables
└── <session_id>/                      octets (purgés à l'échéance)
    ├── manifest.m3u8                  (HLS) réécrit local à la relecture
    ├── seg-000.ts …                   (HLS) segments
    ├── object-0.mp4                   (fichier direct)
    └── thumb.jpg
```

## 5. Flux de données

```
client ──wg-toolbox──▶ sbxmitm (déchiffre)
   │  ctype média ? hôte non-splice ?
   ├─ non ─▶ (comme aujourd'hui : métatag media-catch, pas d'octets)
   └─ oui ─▶ tee corps ─▶ BUFFER_ROOT/<session>/  + ligne media-buffer.jsonl  ──▶ forward inchangé
                                   │
                    janitor (30 s) : first_ts > 20 min  ──▶ rm <session>/, métatag.expired=true
                                   │  ou BUFFER_ROOT > plafond ──▶ LRU evict
UI DPI /media/buffer ─▶ liste métatags (admin=tous / persona=mac_hash)
UI ▶ Play ─▶ /media/replay/{id} ─▶ octets si présents, sinon 410 Gone (+ audit)
```

## 6. Confidentialité / CSPN

- **Gate** : toutes les routes `require_jwt`. `require_admin_or_owner` : admin → tout ; sinon le JWT doit être lié au `mac_hash` de la capture (scoping persona kbin).
- **Exclusions** : hôtes **splice/passthrough** (banque, `anthropic.com`, cert-pinned) jamais capturés — ils sont opaques par conception, frontière naturelle. Deny-list opérateur optionnelle (phase ultérieure).
- **Octets bornés dans le temps** : ~20 min à demeure, `/data` (pas tmpfs — trop gros), 0750 `secubox`.
- **Audit immuable** : chaque relecture → `/var/log/secubox/audit.log` (append-only, RFC 3339), conforme au journal de décisions CSPN.
- **Pas de régression perms** : `/run/secubox` 1777 et `/etc/secubox` 0755 intacts ; nouveau tampon sous `/data/secubox/`.

## 7. Gestion d'erreurs / bornes

- Tee **jamais bloquant** : writer intermédiaire + canal borné ; si plein → on abandonne la capture de CET objet (le proxy n'est jamais ralenti), métatag marqué `truncated`/`dropped`.
- Écriture disque échoue → capture abandonnée, métatag best-effort, jamais d'échec du flux client.
- Réassemblage HLS partiel (segments manquants, éviction en cours) → la relecture sert ce qui existe ; manifest marque les segments manquants ; sinon 410.
- Fichier > `perObjectCeil` → tronqué + `truncated:true` (métatag présent, relecture partielle).
- `media-buffer.jsonl` corrompu/lignes partielles → ignorées (fail-empty).

## 8. Exclusions de portée (YAGNI)

- Pas de transcodage/normalisation des médias capturés (on sert tel-quel).
- Pas de déchiffrement de HTTP/3/QUIC non-rabaissé vers mitm → **non capturé** (caveat de couverture documenté).
- Pas de deny-list hôte/device opérateur en v1 (juste l'exclusion splice) — phase 3.
- Pas de rétention longue/export : c'est un tampon éphémère, volontairement.

## 9. Tests

- **`mediabuffer.go`** (Go) : détection média vs non-média ; hôte splice exclu ; tee fichier direct (borne `perObjectCeil` → `truncated`) ; groupement de session HLS (manifest + N segments) ; non-blocage (canal plein → drop, flux inchangé) ; écriture métatag.
- **Janitor** (Go) : éviction à l'échéance (octets supprimés, métatag `expired`) ; LRU sous plafond ; idempotence ; `nowFn` injectable (comme `mediacache.go`).
- **API** (`pytest`) : `/media/buffer` scoping admin vs persona (mac_hash) ; `/media/replay/{id}` fichier direct ; manifest HLS réécrit (URIs → `/seg/`) ; `410` si `expired` ; audit émis ; `require_admin_or_owner` refuse un persona étranger (403). Handlers en `def` (pas de blocage loop).
- **Frontend** : manuel (galerie, play/download, état grisé expiré).

## 10. Séquencement (un feature, phases livrables/testables)

1. **Buffer fichier-direct + janitor + métatag + API liste/relecture + onglet DPI** (pas de HLS). Livrable : capturer/rejouer un download MP4 & un upload, cycle octets→métatag.
2. **Réassemblage HLS/DASH** : détection manifest, groupement segments, manifest local réécrit + `/seg/`.
3. **Liens kbin par persona + scoping owner + peaufinage audit** (+ deny-list opérateur optionnelle).

## 11. Risques

- **Volume/IO** : capturer « tout » est lourd ; le tee non-bloquant + drop-si-plein protège le débit ; le plafond LRU protège `/data`. À valider live sur charge réelle.
- **Réassemblage HLS** : vrai travail d'ingénierie (parsing manifest variantes, ABR multi-résolution, segments chiffrés AES-128 HLS → clé nécessaire). En v1 des flux, se limiter au manifest média (pas les master playlists ABR) puis étendre.
- **Sensibilité** : stocker le média réel des utilisateurs, même brièvement, est un artefact sensible — atténué par time-bound + admin/owner + audit + exclusion splice + `/data` chiffré si activé.
- **QUIC/HTTP-3** : couverture partielle si non rabaissé ; documenté.
- **Perf agrégateur** : l'API DPI est montée in-process (SPOF partagé, cf. #808) → handlers `def` obligatoires + double-caching de la liste.
