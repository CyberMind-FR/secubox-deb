# Content Lifecycle / Media Object commun — Design (v1)

> Brique commune de contenu événementiel pour SecuBox/BBS. Réutilisable par
> Radio, MetaNews, PeerTube, Social Gateway, Mastodon, photos, échanges tribaux.
> Issue : #1166. Vulgarisation utilisateurs : artifact « AletheiaVox × Zanimalos ».

## Principe directeur

On ne construit **pas** une intégration Radio, une intégration MetaNews, une
intégration PeerTube et une intégration Mastodon indépendantes. On construit un
**objet de contenu commun** (`ContentObject`), puis chaque module devient une
**vue ou un acteur** de ce système. Le **BBS est la mémoire et le graphe de
discussion** ; les autres services restent spécialisés (Radio diffuse, PeerTube
rejoue, MetaNews agrège, Social publie) et **relient leurs objets au spine**.

**Règle d'or (invariant, jamais négociable) :** la source reste identifiable, le
cache reste un cache, la publication reste une représentation, et la conversation
peut rester commune à toutes ces formes. Le système ne présente **jamais** une
copie locale comme l'original.

## Décisions verrouillées (brainstorming 2026-08-23)

1. **Le spine vit dans le BBS.** `secubox-bbs` possède `content_object`, ses
   tables d'événements et la timeline. Les autres modules s'y lient via l'API
   BBS. Raison : le BBS tient déjà l'identité (pseudos, sessions), la base et les
   topics — dupliquer le graphe ailleurs créerait un SPOF et de la latence.
2. **v1 = noyau.** `ContentObject` + `provenance[]` + `representations[]` +
   `bbs_topic` + **timeline (chat temporel)** + les events du cycle
   propose→vote→valide→diffuse. Le **lifecycle/rétention** (expiration,
   archivage, cache auto-supprimable) et l'**application fine de la visibilité**
   sont **phase 2**.
3. **Adaptateurs incrémentaux.** radio/metanews/socialrelay **gardent leur base
   spécialisée** ; on ajoute un lien vers le `ContentObject` + l'émission
   d'events. Backfill progressif, zéro big-bang, déployable module par module.

## Règle d'identité ↔ persistance (chat radio → timeline)

C'est ce qui rend la conversation radio **fiable, cohérente et spécifique BBS** :

| Qui parle | Attribution | Persistance |
|-----------|-------------|-------------|
| **Membre BBS** (session BBS valide) | son **pseudo BBS** (identité du graphe) | **TimelineComment** rattaché à `(content_id, offset_ms)` → **rejouable** au replay |
| **Anonyme / public** | nom ad-hoc éphémère | message **live seulement**, **oublié** (jamais persisté) |

> *Être identifié = laisser une trace rejouable ; rester anonyme = rester
> éphémère.* Cohérent avec « une conversation reste… et parfois choisit de
> disparaître », et avec privacy-by-design.

Conséquence concrète pour la Radio : le chat conserve deux flux —
- un flux **volatil** (in-memory, borné, TTL court) pour l'ambiance du direct
  (membres + anonymes) ;
- une **persistance sélective** : quand l'auteur est un membre BBS, le message
  est **aussi** écrit comme `TimelineComment` sur le `ContentObject` du média en
  cours, avec l'offset. C'est le seul qui survit et se rejoue.

## Modèle de données (SQLite, dans le BBS)

### Objet central — stable

```
content_object
  id            TEXT PRIMARY KEY      -- "co_<date>_<rand>", opaque, stable à vie
  type          TEXT NOT NULL         -- video | audio | article | photo | post | topic | mixed
  title         TEXT NOT NULL
  metadata      TEXT DEFAULT '{}'     -- JSON libre (durée, auteur d'origine, langue…)
  bbs_topic_id  INTEGER DEFAULT 0     -- le fil de discussion (0 = pas encore ouvert)
  status        TEXT DEFAULT 'proposed' -- proposed | validated | live | cached | archived | withdrawn
  visibility    TEXT DEFAULT 'community' -- public|community|tribal|family|private (enforcement=phase 2)
  created_at    INTEGER NOT NULL
  updated_at    INTEGER NOT NULL
```

L'objet **ne porte pas** son histoire : il reste stable, les **events** la
racontent. `lifecycle_policy` (expires_at, delete_cache_at, archive_at,
redistribution_allowed, keep_original) est un **champ phase 2** (colonne
additive via migration `_migrations`).

### Provenance — d'où ça vient (append-only)

```
content_provenance
  id           INTEGER PRIMARY KEY AUTOINCREMENT
  content_id   TEXT NOT NULL REFERENCES content_object(id) ON DELETE CASCADE
  source_url   TEXT NOT NULL
  source_type  TEXT NOT NULL          -- youtube | rss | mastodon | pixelfed | upload | …
  is_original  INTEGER NOT NULL DEFAULT 0  -- 1 = LA source d'origine
  noted_at     INTEGER NOT NULL
  UNIQUE(content_id, source_url)
```

Au moins une ligne `is_original=1`. Jamais supprimée : la source reste la source.

### Représentations — les visages du même objet

```
content_representation
  id           INTEGER PRIMARY KEY AUTOINCREMENT
  content_id   TEXT NOT NULL REFERENCES content_object(id) ON DELETE CASCADE
  kind         TEXT NOT NULL          -- peertube | radio | social | cache | replay | bbs
  module       TEXT NOT NULL          -- "secubox-radio", "secubox-peertube", …
  ref          TEXT NOT NULL          -- id/opaque côté module (piste_id, video uuid, thread_id…)
  is_cache     INTEGER NOT NULL DEFAULT 0  -- 1 = copie reconstructible, JAMAIS l'original
  url          TEXT DEFAULT ''        -- adresse locale de la représentation (si servie)
  created_at   INTEGER NOT NULL
  UNIQUE(content_id, kind, module, ref)
```

`is_cache=1` marque une copie : l'UI l'affiche comme cache/replay, jamais comme
la source.

### Événements — l'histoire (append-only, une table par type)

v1 livre ce sous-ensemble ; les autres sont **phase 2**.

```
content_event                       -- table générique, discriminée par `kind`
  id           INTEGER PRIMARY KEY AUTOINCREMENT
  content_id   TEXT NOT NULL REFERENCES content_object(id) ON DELETE CASCADE
  kind         TEXT NOT NULL         -- proposal|vote|validation|broadcast|publication  (v1)
                                     -- cache|archive|deletion                          (phase 2)
  actor        TEXT DEFAULT ''       -- pseudo BBS ou "" (système/anonyme)
  payload      TEXT DEFAULT '{}'     -- JSON spécifique au kind
  at           INTEGER NOT NULL
```

Exemples de `payload` :
- `proposal`  → `{"source_url":"…","by":"pseudo"}`
- `vote`      → `{"by":"pseudo","weight":1}`
- `validation`→ `{"by":"sysop_pseudo","decision":"validated"}`
- `broadcast` → `{"module":"secubox-radio","session":42,"started_at":…}`
- `publication`→ `{"kind":"social","target":"mastodon","url":"…"}`

### Timeline — le chat temporel rejouable (v1, le cœur)

```
content_timeline
  id           INTEGER PRIMARY KEY AUTOINCREMENT
  content_id   TEXT NOT NULL REFERENCES content_object(id) ON DELETE CASCADE
  author       TEXT NOT NULL         -- pseudo BBS (les anonymes ne persistent PAS ici)
  author_id    INTEGER NOT NULL      -- id membre BBS (>0 obligatoire → gate d'identité)
  offset_ms    INTEGER NOT NULL      -- position DANS le média (0 pour un contenu non temporel)
  body         TEXT NOT NULL
  broadcast_at INTEGER DEFAULT 0     -- horodatage direct d'origine (contexte, optionnel)
  created_at   INTEGER NOT NULL
  INDEX(content_id, offset_ms)
```

**LIVE** : radio → chat → horodatage → `content_timeline(content_id, offset_ms)`.
**REPLAY** : média → `SELECT … ORDER BY offset_ms` → commentaires réaffichés au
bon instant. `author_id > 0` **imposé** : le gate d'identité vit dans le schéma,
pas seulement dans le code.

## Contrat d'API BBS (socket unix, JWT de flotte)

Les modules parlent au spine via l'API BBS (comme MetaNews poste déjà
`POST /api/v1/bbs/threads`). Tous JWT (sujet = module ou pseudo membre).

| Méthode | Route | Rôle |
|---------|-------|------|
| POST | `/api/v1/bbs/content` | Créer/mettre à jour un `ContentObject` (idempotent sur provenance originale). Corps : `{type,title,metadata,provenance:[{source_url,source_type,original}]}`. Retour : `{id}`. |
| POST | `/api/v1/bbs/content/{id}/representation` | Attacher une représentation `{kind,module,ref,is_cache,url}`. |
| POST | `/api/v1/bbs/content/{id}/event` | Émettre un event `{kind,actor,payload}` (propose/vote/validation/broadcast/publication). |
| POST | `/api/v1/bbs/content/{id}/topic` | Ouvrir (ou lier) le fil BBS de l'objet → renvoie `bbs_topic_id`. |
| POST | `/api/v1/bbs/content/{id}/timeline` | Ajouter un `TimelineComment` `{author_id,author,offset_ms,body}`. **Rejette `author_id<=0`** (anonyme = éphémère, hors timeline). |
| GET | `/api/v1/bbs/content/{id}` | Objet + provenance + représentations + derniers events. |
| GET | `/api/v1/bbs/content/{id}/timeline?from=&to=` | Commentaires ordonnés par `offset_ms` (pour le replay). |
| GET | `/api/v1/bbs/content/by-ref?module=&ref=` | Résoudre l'objet depuis une représentation (les adaptateurs s'en servent). |

Le **flux volatil du direct** (ambiance, incluant anonymes) reste servi par la
Radio elle-même (in-memory, TTL court) — il ne touche pas le spine.

## Adaptateurs (incrémentaux, par module)

Chaque module garde sa base ; il **ajoute** un lien + des events. Ordre de
déploiement conseillé : Radio (le cas moteur), puis MetaNews, puis Social.

- **Radio** — à la **validation** d'une piste : `POST /content` (provenance =
  source proposée, original=1) → `…/representation` (kind=radio, ref=piste_id) →
  `…/topic`. À chaque **passage antenne** : event `broadcast`. Le **chat** :
  message d'un **membre** → `…/timeline` avec `offset_ms = position du média` ;
  message anonyme → reste dans le flux volatil, **non** envoyé. Le replay lit
  `GET …/timeline`.
- **MetaNews** — un **événement** (grappe d'articles) = un `ContentObject`
  (type=article) ; chaque article = une `provenance` ; le topic BBS existant
  devient `bbs_topic_id`. (MetaNews a déjà topics + sources → mapping direct.)
- **Social Gateway** — un post relayé = un `ContentObject` (type=post) ;
  provenance = l'URL sociale d'origine ; représentation `social` + `cache`
  (média local déjà géré). Les publications sortantes = events `publication`.

**Backfill** : chaque adaptateur expose déjà le lien module↔objet (radio
`piste_id`, metanews `topic_id`, socialrelay `bbs_thread_id`) ; un one-shot par
module crée les `ContentObject` manquants et relie l'existant, sans doublon
(idempotence sur `content_representation` UNIQUE + provenance UNIQUE).

## Hors v1 (posé au-dessus du noyau, migrations additives)

Tout ce qui suit s'ajoute **sans remodeler** le noyau : l'objet reste stable, on
ajoute des colonnes (via `_migrations`) et des events. Chaque phase est
livrable/déployable seule.

---

## Phase 2 — Cycle de vie & rétention

### Deux axes orthogonaux

**Visibilité** (qui voit) et **durée de vie** (combien de temps) sont
**indépendants**. Un même objet peut être `public` + `temporary`, ou `family` +
`permanent`, ou `community` + `cache`. On ne les mélange jamais dans un seul
champ.

### La politique portée par l'objet

Migration additive sur `content_object` :

```
  lifecycle_state  TEXT DEFAULT 'permanent'  -- permanent|temporary|dormant|archived|ephemeral|cache
  expires_at       INTEGER DEFAULT 0         -- 0 = jamais
  delete_cache_at  INTEGER DEFAULT 0         -- purge des représentations is_cache=1
  archive_at       INTEGER DEFAULT 0         -- sortie du flux (gardé, non supprimé)
  redistribution_allowed INTEGER DEFAULT 0   -- autorise les events `publication` sortants
  keep_original    INTEGER DEFAULT 1         -- 1 = ne jamais supprimer objet+provenance, seulement les caches
```

`lifecycle_state` décrit ce que l'objet **est** ; les `*_at` sont les
**échéances**. `keep_original=1` est le défaut protecteur : on peut perdre un
cache, jamais la trace de la source.

### Machine à états

```
                       archive_at            delete_cache_at / expires_at
  permanent ──(rien)──▶ (reste)
  temporary ──expires_at──▶ archived ──(purge caches)──▶ dormant
  dormant   = caché du public, CONSERVÉ (représentations gardées, hors flux)
  archived  = rangé, hors flux, gardé (consultable sur demande)
  ephemeral ──expires_at──▶ DELETION (objet retiré ; provenance gardée en tombstone si keep_original)
  cache     ──delete_cache_at──▶ purge de la représentation cache (RECONSTRUCTIBLE depuis la source)
```

Règle d'or maintenue : supprimer un `cache` ne supprime jamais la source — la
provenance reste, la copie est reconstructible. Une suppression `ephemeral`
retire l'objet **mais** laisse un `DeletionEvent` (audit append-only) et, si
`keep_original`, une **tombstone** de provenance (on sait que ça a existé et d'où
ça venait, sans le contenu).

### Le balayeur (sweeper) — pattern double-caching

Tâche de fond dans le BBS (comme le refresh cache FastAPI/asyncio du projet) :
toutes les N minutes, elle scanne les échéances dépassées et **applique** la
transition **atomiquement**, en émettant l'event correspondant :

- `now ≥ delete_cache_at` → supprime les `content_representation` `is_cache=1`
  (+ demande au module propriétaire de purger son fichier) → `CacheEvent{purged}`.
- `now ≥ archive_at` → `lifecycle_state=archived` → `ArchiveEvent`.
- `now ≥ expires_at` sur `ephemeral` → retrait objet + `DeletionEvent`.
- `now ≥ expires_at` sur `temporary` → `archived` puis purge caches.

Le balayeur est **idempotent** et **borné** (K objets par tour), journalisé dans
`content_event`. Rollback 4R au sens CSPN : la transition passe par un shadow
(marque `pending_delete`) validé avant le swap réel, jamais une suppression sèche.

### Events phase 2 (mêmes tables, nouveaux `kind`)

`cache` (mise en cache / purge), `archive`, `deletion` — dans `content_event`,
`payload` décrit l'action et l'acteur (`balayeur` ou pseudo SysOp pour une action
manuelle).

### Surcouche PeerTube (application directe)

Une vidéo PeerTube devient une `content_representation` `kind=peertube`,
`is_cache=1` quand c'est une copie d'une source WAN. Son `lifecycle_state` porte
la surcouche demandée :

| État | Sens PeerTube |
|------|---------------|
| `permanent` | vidéo gardée indéfiniment |
| `temporary` | expire à `expires_at` |
| `dormant` | cachée du public, conservée |
| `archived` | sortie du flux, gardée |
| `cache` | copie **reconstructible** depuis la source WAN → suppressible sans perte |

La règle : une vidéo peut être permanente, temporaire, cachée, archivée ou juste
un cache reconstructible — **sans jamais** effacer/masquer la source d'origine.

---

## Phase 3 — Visibilité appliquée & cercles

### Cercles / clans

```
circle            id, slug, name, kind (community|tribal|family), owner_id, created_at
circle_member     circle_id, user_id, role (member|steward), added_at
```

`content_object.visibility ∈ {public, community, tribal, family, private}` +
`content_object.circle_id` (le cercle concerné pour tribal/family ; 0 sinon).
Une **représentation** peut porter un override de visibilité (ex. la diffusion
radio est `community`, mais son **cache photo** est `family`).

### Application (enforcement)

Une seule fonction d'autorisation, appelée partout où l'on sert un objet, un
topic, une timeline ou une représentation :

```
peutVoir(viewer, object) :
  public     → oui
  community  → viewer est membre BBS
  tribal/family → viewer ∈ circle_member(object.circle_id)
  private    → viewer == owner
```

- La **timeline** (déjà membres-only par le gate d'identité) applique **en plus**
  la visibilité de l'objet.
- Le **chat radio public éphémère** reste public (ambiance du direct), mais les
  `TimelineComment` persistants héritent de la visibilité de l'objet : un objet
  `family` n'expose sa conversation rejouable qu'au cercle.
- Les **médias servis** (`/media-vignette`, replays, caches) passent le même
  `peutVoir` avant diffusion.

---

## Phase 4 — Torrents & partages familiaux/tribaux

Même moteur, **politiques par défaut restrictives** :

- `visibility = family|tribal`, `circle_id` obligatoire.
- `lifecycle_state = temporary|ephemeral`, `expires_at` court par défaut.
- `redistribution_allowed = 0` (aucun event `publication` sortant sans opt-in
  explicite du steward du cercle).
- `keep_original` selon le cas : un partage familial reconstructible = `cache` ;
  un original de famille = `permanent` + `private/family`.

Un torrent/partage = `ContentObject` (type selon le média) + représentation
`cache` sous politique stricte + **expiration automatique** par le balayeur. La
redistribution hors cercle exige un franchissement explicite, tracé en event.

---

## Roadmap d'implémentation (la suite)

| Phase | Contenu | Dépend de |
|-------|---------|-----------|
| **1** | Noyau BBS : tables `content_*`, API `/content /representation /event /topic /timeline /by-ref`, **gate d'identité** timeline. **Adaptateur Radio** (cas moteur : validation → objet+topic, broadcast event, chat membre → timeline, replay). | — |
| **1b** | Adaptateurs **MetaNews** (topic→objet, articles→provenance) et **Social** (post→objet, cache→représentation, publications→events) + **backfill** idempotent des trois. | 1 |
| **2** | Colonnes lifecycle + **balayeur** (shadow/4R) + events cache/archive/deletion + **surcouche PeerTube**. | 1 |
| **3** | Cercles/clans + `peutVoir` unique + application visibilité (timeline, médias, replays). | 1, 2 |
| **4** | Torrents & partages familiaux/tribaux (politiques restrictives, expiration auto, redistribution contrôlée). | 2, 3 |

Chaque phase = un plan d'implémentation séparé (writing-plans) ; on ne code la
suivante qu'après revue et déploiement de la précédente. Le noyau v1 ne bouge
plus : tout le reste s'y accroche par colonnes additives et events.

---

## Ce qui reste hors périmètre (à décider plus tard)

- **Fédération / multi-nœud** du spine (partage d'objets entre box via MirrorNet)
  — le modèle s'y prête (id opaque + provenance), mais c'est un chantier distinct.
- **Modération/suppression** avancée des `TimelineComment` (droit du SysOp,
  droit à l'oubli d'un membre) — à cadrer avec la modération BBS existante.

## Auto-revue (spec)

- **Placeholders** : aucun TBD non intentionnel ; les zones « phase 2 » sont
  explicitement bornées, pas des trous.
- **Cohérence** : `content_timeline.author_id>0` applique la règle d'identité au
  niveau schéma ; `is_cache`/`is_original` appliquent la règle d'or au niveau
  données ; l'API `by-ref` sert les adaptateurs incrémentaux.
- **Portée** : un seul plan d'implémentation (noyau BBS + 3 adaptateurs) tient
  dans une itération ; le lifecycle est un second plan.
- **Ambiguïté** : « éphémère » est tranché — les messages anonymes ne sont
  **jamais** écrits dans `content_timeline` (gate schéma), seulement dans le flux
  volatil radio.
