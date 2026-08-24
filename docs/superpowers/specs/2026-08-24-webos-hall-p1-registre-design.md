<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# WebOS SBX — Phase 1 : Registre normalisé partagé — spec de conception

**Issue** : #1175 · **Brief** : `docs/dossiers/webos-sbx-hall-cardlets.md` · **Discovery** : `docs/superpowers/specs/2026-08-24-webos-hall-phase0-discovery.md`
**Date** : 2026-08-24 · **Statut** : SPEC — à valider avant le plan d'implémentation

## Décisions de cadrage (validées avec l'utilisateur)
1. **Périmètre P1 = registre normalisé SEUL.** Aucune UI, aucune cardlet, aucun shell Hall.
2. **Jointure `id↔domaine` = Option 6-B** (champ `domain`/`same_origin` dans chaque
   `menu.d/*.json`, ~40 paquets) — validée en revue. Population par **sweep batché** avec
   **repli gracieux** (champ absent ⇒ convention `<id>.gk2.secubox.in` puis `null`), pour que le
   module `secubox-webos` ne bloque pas sur les 40 fichiers d'un coup.
   **Source santé = Option 5-C** (helper partagé `secubox_core.health`). **Domaine = `hall.gk2.net`.**
3. **Module dédié `secubox-webos`** avec sa propre socket — **indépendant de l'agrégateur**
   (aligne « composants vitaux indépendants de l'agrégateur », #1173). *Diverge du brief §8
   (« étendre le Hub »)* : justifié par la congestion agrégateur (R4) ; le registre reste
   **partagé** (source unique = `menu.d` du Hub), on ne duplique pas les définitions.
4. **Alias `all.gk2.net`/`hall.gk2.net` câblé D'ABORD** (avant le code registre).

---

## 1. Objectif (une phrase)
Livrer un **registre de services normalisé**, servi par un module dédié `secubox-webos`
(socket propre, cache-first), qui compose le catalogue autoritatif existant (`menu.d` du Hub)
avec santé/latence/reach, exposé sous forme d'un objet service unique — sans dupliquer aucune
définition ni aucune logique de santé, et sans jamais sonder en direct dans le chemin de requête.

## 2. Non-objectifs (P1)
Pas de `www/hall/index.html`, pas de `webos-runtime.js`/`webos.css`, pas d'adaptateur cardlet
(radio/bbs/metanews), pas de Session Bridge, pas de barre injectée, pas d'événements Cabine.
Ces éléments sont P2→P8 (brief §20) et **ne doivent pas apparaître** dans le code P1.

## 3. Architecture

```
                 /usr/share/secubox/menu.d/*.json   (source de vérité catalogue, Hub)
                          │  (lecture fichier, pas de duplication)
   santé/latence/reach ───┤
   (source choisie §5) ───┤
                          ▼
        secubox-webos.service  (uvicorn, /run/secubox/webos.sock)
          ├─ tâche de fond : refresh cache normalisé (intervalle §7)
          ├─ registry.py : compose + normalise → objet service §4
          ├─ idmap.py    : jointure id↔domaine (§6)
          └─ FastAPI :
               GET /api/v1/webos/public/services   (public, minimal, sans JWT)
               GET /api/v1/webos/services          (JWT, détail enrichi)
               GET /api/v1/webos/healthz
                          │
   nginx (hall.gk2.net)  ── location /api/v1/webos/ → unix:/run/secubox/webos.sock:/
```

**Indépendance agrégateur** : `secubox-webos.service` lance son propre uvicorn sur `webos.sock`
(comme `secubox-mail` #1173), jamais servi in-process par l'agrégateur. Si l'agrégateur wedge,
le registre WebOS reste debout.

**Dégradation gracieuse** (brief §10) : chaque source (santé, latence, reach) a un timeout et un
repli « last-known-good + timestamp stale ». Une source absente ⇒ champ `null` + `stale:true`,
jamais une 500. Une seule source morte ne casse jamais le registre entier.

## 4. Objet service normalisé (contrat de sortie)

Modèle Pydantic (schéma stable — c'est le contrat que P2+ consommera) :
```python
class ServiceUrls(BaseModel):
    lan: Optional[str] = None      # https://<domaine> vu du LAN, ou path relatif same-origin
    wan: Optional[str] = None      # https://<domaine> public si reach=wan, sinon None
    path: str                      # path relatif du menu.d (toujours présent, ex "/waf/")

class ServiceRouting(BaseModel):
    mode: Literal["localhost","lan","wan","unknown"] = "unknown"
    available: bool = True         # best-effort : le service répond-il ?

class ServiceHealth(BaseModel):
    state: Literal["online","degraded","offline","unknown"] = "unknown"
    latency_ms: Optional[float] = None      # best-effort ; null si non mesurée
    stale: bool = False                     # true si la donnée dépasse son TTL
    checked_at: Optional[str] = None        # ISO-8601

class ServiceAuth(BaseModel):
    mode: Literal["none","jwt","cookie","zkp","unknown"] = "unknown"

class Service(BaseModel):
    id: str
    name: str
    description: str = ""
    category: str
    icon: str = ""
    urls: ServiceUrls
    routing: ServiceRouting
    health: ServiceHealth
    auth: ServiceAuth
    capabilities: List[str] = []
    cardlet: Optional[dict] = None          # None en P1 (placeholder pour P3+)
    installed: bool = True
    active: bool = True
```

**Mapping santé** `ok/warn/error`(Hub) → `online/degraded/offline/unknown`(WebOS) :
`ok→online`, `warn→degraded`, `error→offline`, absent/inconnu→`unknown`. **Lossy et assumé**
(R3) : le vocabulaire 4-états du brief est plus riche que la source `ok/warn/error` ; `unknown`
couvre « pas de donnée ». La latence est `null` quand la source ne la fournit pas (la plupart
des modules aujourd'hui — R3), affichée telle quelle, jamais inventée.

**Public vs détail** (R6, brief §7 « count-before-content ») :
- `GET /public/services` → **minimal** : `id, name, category, icon, health.state` (état grossier
  seulement), `installed/active`. Pas de `urls`, pas de `latency_ms`, pas de `reach`, pas de
  `capabilities` — pas de fuite d'inventaire réseau à un visiteur WAN non authentifié.
- `GET /services` (JWT) → **objet complet** ci-dessus.

## 5. Source de santé/latence — sous-décision (à trancher en revue)

Le module étant dédié et indépendant de l'agrégateur, il faut choisir d'où vient la santé sans
(a) dépendre de l'agrégateur ni (b) dupliquer la *logique* de santé (R5, deux caches santé
coexistent déjà). Trois candidats, recommandation = **C** :

| Option | Comment | Pour | Contre |
|---|---|---|---|
| A. Consommer `/public/health-batch` du Hub | GET caché 5 s via aggregator.sock | zéro nouvelle logique | **couple à l'agrégateur** (contre décision #3) ; santé fige si agrégateur wedge |
| B. Re-sonder `systemctl` dans webos | rejouer le one-liner `systemctl list-units secubox-*` | indépendant ; cheap | risque de « 4ᵉ mécanisme » (R5) |
| **C. Helper partagé dans `secubox_core`** | **extraire** le batch systemctl de `hub/api/main.py:510-566` vers `secubox_core.health.systemd_batch()`, importé par Hub ET webos | **une seule logique**, deux consommateurs ; indépendant agrégateur ; refactor propre | touche `secubox-hub` (refacto sans changement de comportement) |

**Reco C** : factoriser le batch santé en code partagé résout R5 (pas de duplication de logique)
ET la décision #3 (indépendance). Latence/reach best-effort lus du cache `secubox-exposure`
(fichier, pas d'appel live) quand la jointure `id↔domaine` (§6) résout un vhost ; sinon `null`.

## 6. Jointure `id↔domaine` (R2, le vrai point dur) — DEUX OPTIONS À TRANCHER

Sans clé commune entre `menu.d.id` et le domaine (`vhost`/`exposure`), `urls{lan,wan}`,
`routing.mode` et `latency_ms` sont faux ou absents. Deux bases possibles :

### Option 6-A — Convention + fichier de surcharges *(recommandée : rapide, réversible)*
- Défaut : `domaine = f"{id}.gk2.secubox.in"`.
- Surcharges déclaratives `/etc/secubox/webos/idmap.json` (livré avec des exceptions connues) :
  ```json
  {"nc":"nextcloud.gk2.secubox.in","lyrion":"lyrion.gk2.secubox.in","radio":{"same_origin":true}}
  ```
- `idmap.py` : `resolve(id) -> domaine|None` (None = same-origin, pas de dual URL).
- **Coût** : 1 fichier + ~20 lignes + tests. **Risque** : la convention est fausse pour les LXC
  et sous-vhosts → surcharges à maintenir à la main (mais explicites et auditables).

### Option 6-B — Champ `domain` dans chaque `menu.d/*.json` *(plus propre à terme, plus lourd)*
- Ajouter `"domain": "...", "same_origin": bool` à chaque drop-in (~40 fichiers, répartis dans
  ~40 paquets).
- `idmap.py` lit le champ du manifeste (source de vérité par module).
- **Coût** : ~40 éditions + bumps de version + rebuilds/redeploys de ~40 paquets. **Risque** :
  gros diff transverse, plusieurs releases ; mais la donnée vit au bon endroit.

> **Reco : 6-A pour P1** (livrer le registre vite, valider la forme), migration vers 6-B
> possible plus tard sans changer le contrat de sortie §4 (`idmap.py` encapsule la source).
> **Décision demandée en revue.**

## 7. Cache / refresh (brief §10)
Tâche de fond unique dans `secubox-webos` : recompose le registre normalisé et le pose en
mémoire + fichier `/var/cache/secubox/webos/services.json`. TTL de départ : catalogue (menu.d)
relu 60 s ; santé 15 s ; latence/reach (exposure) 60 s. Endpoint = **lecture mémoire/fichier
seule**, jamais de composition ni de sonde dans le chemin de requête (R4). `ETag`/`If-None-Match`
sur les deux endpoints. `stale:true` + `checked_at` exposés quand une source dépasse son TTL.

## 8. Feature flags (brief §19)
`/etc/secubox/webos.toml` : `webos.enabled` (défaut **false**), `webos.registry_enabled`
(défaut true quand enabled). Service masqué/registre vide si désactivé — rollback par flag.

## 9. Auth (réutilisation verbatim, discovery §6)
Backend : `from secubox_core.auth import require_jwt` ; `public_router = APIRouter(prefix="/public")`
sans JWT (services minimal) ; `router` avec `Depends(require_jwt)` (services détail). Aucun secret
en clair, aucun bearer en query, secret JWT via la config partagée (jamais de défaut).

## 10. Alias `all.gk2.net` / `hall.gk2.net` (décision #4 — câblé d'abord)
Tâche d'ouverture de P1, **source-first, actions live consignées dans #1175** :
- `hall.gk2.net` → sert la surface WebOS (en P1 : uniquement `/api/v1/webos/*` ; la page racine
  viendra en P2). vhost nginx dans le paquet `secubox-webos` (`nginx/webos.conf`, `server_name
  hall.gk2.net`), route HAProxy déclarative (`haproxy.toml`), cert (certbot/Gandi DNS), DNS (API
  Gandi). Trafic via la chaîne d'inspection par défaut (pas de `waf_bypass`).
- `all.gk2.net` → `all.gk2.secubox.in` : finir l'item WIP ouvert (ajouter au `server_name` du Hub
  + ACL HAProxy + cert). *Cet alias sert le Hub existant, pas le nouveau module* — c'est le
  chantier R1, fait ici parce que décidé « d'abord », mais **découplé** du registre (le registre
  est testable via `admin.gk2` avant même l'alias).

## 11. Structure de fichiers P1
```
packages/secubox-webos/
├── debian/            control, rules, changelog, postinst (user secubox-webos, enable --now),
│                      prerm, compat=13, service unit, AppArmor profile
├── api/
│   ├── main.py        FastAPI app, root_path=/api/v1/webos, lifespan→refresh task,
│   │                  public_router + router, /healthz
│   ├── registry.py    normalize_services() : menu.d + santé + latence/reach → List[Service]
│   ├── idmap.py       resolve(id)->domaine|None (Option 6-A|B selon revue)
│   ├── models.py      Pydantic §4
│   └── flags.py       lecture webos.toml
├── nginx/webos.conf   server_name hall.gk2.net ; location /api/v1/webos/ → webos.sock
├── systemd/secubox-webos.service
├── etc/webos.toml.example        + idmap.json.example (si 6-A)
└── tests/             test_registry.py, test_idmap.py, test_models.py, test_endpoints.py
common/secubox_core/health.py     (NOUVEAU) systemd_batch() factorisé (Option 5-C)
packages/secubox-hub/api/main.py  (MODIF) _refresh_health_batch importe secubox_core.health
```

## 12. Definition of Done (P1)
Registre réel (services réels de `menu.d`) servi via `webos.sock`, indépendant de l'agrégateur ;
santé mappée 4-états ; latence/reach best-effort avec `stale` visible ; service offline rendu
seul (pas de 500 globale) ; endpoint public minimal (pas de fuite d'inventaire) vs détail JWT ;
`sbx_token`/`require_jwt` respectés ; cache-first strict (pas de sonde en requête) ; flag
`webos.enabled` (rollback) ; `hall.gk2.net` sert `/api/v1/webos/*` ; alias `all.gk2.net`→Hub
câblé ; helper santé factorisé sans changement de comportement du Hub ; tests verts.

## 13. Tests (brief §22, tranche registre)
Unit : normalisation registre (menu.d→Service) ; mapping santé 4-états (dont `unknown`) ;
`idmap.resolve` (convention + surcharge + same-origin) ; latence `null` quand absente ; cache
stale→`stale:true` ; **filtrage public vs authed** (public n'expose jamais urls/latency/reach) ;
flag off→registre vide. Sécurité : échappement, pas de secret en logs, public_router sans JWT
vs router avec, CSP nginx. (E2E board : parité services réels, service test offline isolé,
`hall.gk2.net/api/v1/webos/public/services` répond — documenté, exécuté à la livraison.)

## 14. Risques hérités (discovery §11) et traitement P1
- **R1 alias** → §10, découplé, testable avant alias.
- **R2 jointure** → §6, `idmap.py` encapsule, décision en revue.
- **R3 santé/latence** → §4 mapping lossy assumé + latence `null` best-effort ; prober HTTP #393
  hors périmètre (P1 se contente de `systemctl`+exposure-cache).
- **R4 agrégateur** → module dédié + cache-first strict (§3, §7).
- **R5 duplication santé** → Option 5-C (helper partagé), pas de 4ᵉ mécanisme.
- **R6 fuite inventaire** → split public-minimal / détail-JWT (§4).

---

## Décisions tranchées à la revue (2026-08-24)
1. **§6 jointure id↔domaine = Option 6-B** (champ `domain`/`same_origin` dans `menu.d`), sweep
   batché + repli gracieux.
2. **§5 source santé = Option 5-C** (helper `secubox_core.health` partagé, refacto neutre du Hub).
3. **Domaine = `hall.gk2.net`** (WebOS) ; `all.gk2.net`→Hub existant.

→ Prochaine étape : plan d'implémentation (skill writing-plans), puis exécution TDD
(subagent-driven-development).
