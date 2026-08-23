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

## Ce que la v1 NE fait PAS (phase 2, à spécifier ensuite)

- **Lifecycle/rétention** : `expires_at`, `delete_cache_at`, `archive_at`,
  `redistribution_allowed`, `keep_original`, transitions
  permanent/temporary/dormant/archived/ephemeral/cache + le balayeur qui les
  applique.
- **Enforcement de la visibilité** au-delà du défaut community (tribal/family/
  private avec permissions par cercle).
- Events `cache` / `archive` / `deletion` et la **surcouche PeerTube**
  (vidéo permanente / temporaire / cachée / archivée / cache reconstructible).
- Torrents & échanges familiaux/tribaux (mêmes mécanismes, politiques plus
  restrictives + expiration auto).

Ces briques se posent **au-dessus** du noyau v1 sans le remodeler : l'objet reste
stable, on ajoute des colonnes (migrations additives) et des events.

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
