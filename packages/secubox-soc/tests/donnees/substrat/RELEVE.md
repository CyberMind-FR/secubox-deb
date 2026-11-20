<!--
SPDX-License-Identifier: LicenseRef-CMSD-1.0
Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
Source-Disclosed License — All rights reserved except as expressly granted.
See LICENCE-CMSD-1.0.md for terms.
-->
# Relevé du substrat SADE (tâche 1)

**Tiré du code, à vérifier au banc.** Aucune réponse n'a été relevée sur une box : les fixtures de ce dossier sont
dérivées des gestionnaires (noms de champs exacts, valeurs fictives, adresses de documentation 203.0.113.0/24 et
198.51.100.0/24 seulement). Ce qui ne se déduit pas du code est dit comme tel.

## 1. actord (`sbx-actord`, `packages/secubox-toolbox-ng/cmd/sbx-actord/`)

**Socket de lecture : `/run/secubox/actor.sock`** (drapeau `--api-socket`, unité `secubox-actord.service`).
`/run/secubox/actord.sock` est le socket d'**ingestion** des capteurs (écriture, groupe `actord-ingest`), pas l'API de
lecture. `substrat.SOURCES["actord"]` pointe donc sur `actor.sock` (écart assumé avec le texte du plan).

- **Préfixe** : deux arbres sur le même socket (`server.go`, ~l.277-308) : `/api/v1/actor/...` et la **racine** `/...`.
  L'arbre préfixé ne sert **que la vue réduite**. Pour la vue complète (cibles, `Targets`), appeler la **racine** avec
  l'en-tête exact `X-Sbx-Vue: complete` (`vue.go`). Le lecteur appelle donc `/actors`, `/proposals`, `/overview`,
  `/radar` à la racine, avec `entetes={"X-Sbx-Vue": "complete"}` pour `/actors`.
- **Garde** : aucune. Le code n'a ni `Authorization`, ni cookie, ni vérification de pair ; la protection est celle du
  socket (utilisateur `secubox-actord`, groupe `secubox`, `UMask=0007` : un processus du groupe `secubox` y accède).
  `/proposals` est « hors vue réduite » : 404 sur l'arbre préfixé ou sans l'en-tête.
- **Réponses** :
  - `/actors` (vue complète) : liste de `webActor` (`api.go`) : `id` (forme `ACT-NNNN`), `name` (toujours vide),
    `priority` (**0-100, c'est le score d'un acteur**), `level` (HIGH >= 80, MED >= 50, sinon LOW), `tags`,
    `vec` (sept axes 0-100 : severity, knowledge, continuity, intent, automation, persistence, confidence),
    `src` (compteurs ips/asns/countries, **jamais les adresses**), `first`/`last` (« HH:MM » UTC ou « — »),
    `targets`, `bans`, `hyp`, `tl` (toujours `[]`). Fixture : `actord_actors.json`.
  - `/proposals` : `{genere_le, shadow, propositions:[{actor, mode, raison, ttl_s, ips, bans, confiance, priorite,
    reversible}]}`. Seuls les acteurs en DENY ou QUARANTINE y figurent. **C'est la seule route de lecture qui porte les
    adresses IP d'un acteur** (`ips`). Fixture : `actord_proposals.json`.
  - `/overview` : `Apercu` (`overview.go`) : `genere_le, echantillon, top_pays[{code,n}], recents[{ts,heure,acteur,type,
    module,score}], activite_24h[24], techniques{acteur:[{nom,n}]}, activite_acteurs, robots`. Sans adresse. Pas de fixture
    (non demandée).
  - `/radar` : `{genere_le, politique, acteurs:[{id, risque{valeur,facteurs[{libelle,points}]}, confiance{...}, niveau,
    action_proposee, raisons, refus?, etapes, scenario, capteurs, evenements, mesure?}]}`. **`risque.valeur` (0-100) est
    le score d'analyse** (`analysis.Score.Valeur`) ; `niveau` vaut OBSERVE, MITIGATE ou BLOCK. Servi aussi en vue réduite.
    Pas de fixture : forme lue dans le code, non relevée.
- **Identité d'un acteur** : `id` (`ACT-NNNN`) seulement ; adresses via `/proposals` (`ips`) ; aucun nom.
- **Non déterminable du code** : valeurs réelles, volumétrie, formats exacts de `tl`/`hyp` en charge.

## 2. WAF (`packages/secubox-waf-ng/composants/waf/api/main.py`, socket `/run/secubox/waf.sock`)

Routes servies à la racine du socket (l'agrégateur retire `/api/v1/waf`).

| Route | Garde | Notes |
|---|---|---|
| `GET /bans` (~l.1707) | `require_lecture_ai` | `{bans:[...], total, application}` ; fixture `waf_bans.json` |
| `GET /bans/history` (~l.1799) | `require_lecture` | `{window_hours, total_ips, tracked:[...]}` ; `?hours=` (1-744), `?limit=` (1-1000) ; fixture `waf_bans_history.json` |
| `GET /menaces/flux` (~l.1948) | `require_lecture_ai` | flux à curseur `?depuis=<inode>:<octet>&max=` ; forme `{lignes:[{..., ligne}], ...}` produite par `_veille.lire_flux` : **non relevée**, pas de fixture |
| `POST /ban` (~l.1823) | `require_jwt` (administrateur réel) | voir ci-dessous |

Champs d'un ban (`/bans`) : `ip`, `value`, `scenario`, `reason`, `famille`, `duration` (« <n>s » ou vide),
`expires_in` (secondes, ou `null`), `type` (« ban »), `origin` (« sbxwaf »), `id` (`null`), `created_at` (vide),
`country`, `asn`, `asn_org`. `application` : `{etat, ok, detail}` plus, si présents, `reparations`,
`derniere_reparation`, `dernier_ban`, `dernier_echec`, `echec_a`, `verifie` ; `etat` vaut `appliquee`, `table_absente`,
`waf_arrete`, `desactive` ou `inconnu`.

### Route d'administration qui applique un ban (tâche 6)

- **`POST /ban`** (sur `waf.sock` ; publiquement `/api/v1/waf/ban`), garde **`require_jwt`**.
- Corps JSON `BanRequest` : `{"ip": str, "duration": "4h" (défaut), "reason": "Manual WAF ban" (défaut)}`.
- Effet : `sudo -n /usr/sbin/wafctl ban <ip> <duration>` (valide l'adresse, refuse le privé) ; échec propagé en
  HTTP 500 `{"detail": "bannissement refusé : <message>"}` ; succès `{"success": true, "ip", "duration", "message"}`.
  Le motif (`reason`) n'est **pas** transmis à nft (il vit dans le journal de menaces).
- Autres routes de ban vues : `POST /ai/ban` (`gestes_ia.py`, garde `require_ai_ban`, compte de service EdDSA lié à la
  requête : réservé à une box d'IA, **pas** utilisable par la façade) ; `_unban_ip` existe (`wafctl unban`), sa route
  n'a pas été relevée.
- Audit : `/ban` n'écrit pas lui-même dans `/var/log/secubox/audit.log` d'après le code lu ; la façade devra écrire
  sa propre ligne d'audit.

## 3. threatmesh (`packages/secubox-threatmesh/api/main.py`, socket `/run/secubox/threatmesh.sock`)

Routes à la racine du socket (`root_path` n'est que cosmétique). Service lancé en `User=root`.

- `GET /status` (`require_lecture`) : `{mode, node, capi, feeds, feed_total, mesh, mesh_total, peers, sources}`.
  Fixture `threatmesh_status.json`.
- `GET /peers` (`require_lecture`) : `{node, peers:[{id, name, address}]}`. Pas de fixture.
- `GET /decisions` (`require_lecture`) : liste `[{id, origin, type, scope, value, duration, consensus, sources}]`
  (`sources` est une chaîne séparée par des virgules, `?min_consensus=`, `?limit=`). Fixture `threatmesh_decisions.json`.
- `POST /feeds/refresh` : `require_jwt` (non utilisée).

## 4. Décision à vérifier : transmettre `Authorization` et `Cookie` de l'appelant

Réponse par lecture des gardes (non éprouvée au banc) :

| Route | Garde | Les identifiants transmis passent-ils ? |
|---|---|---|
| actord `/actors`, `/proposals`, `/overview`, `/radar` | aucune | Sans objet : les en-têtes sont ignorés ; le contrôle est celui des droits du socket |
| WAF `GET /bans`, `/menaces/flux` | `require_lecture_ai` = `require_lecture_ou_compte("ai-lecture")` | **Oui** pour un jeton de session HS256 (porteur) ou le cookie de session. Piège : un porteur EdDSA ou illisible est traité comme jeton de compte de service et refusé (401) ; un porteur non valide sans cookie ne retombe pas sur le mode tableau de bord (401) |
| WAF `GET /bans/history` | `require_lecture` | **Oui** : porteur ou cookie de session (`_validate_token`) ; sans jeton, repli « tableau de bord » seulement si `X-SecuBox-LAN: 1` (posé par nginx, absent sur un socket direct) |
| WAF `POST /ban` | `require_jwt` | **Oui** si la session est celle d'un **administrateur réel** ; sinon 403. Avec le **cookie**, la garde d'origine (#1607) exige en plus un en-tête `Origin`/`Referer` d'une page de la box sur une écriture : transmettre aussi ces en-têtes, ou préférer le porteur `Authorization`, non soumis à cette garde |
| threatmesh `GET /status`, `/peers`, `/decisions` | `require_lecture` | **Oui** : mêmes règles que `/bans/history` |

Conclusion : aucune route ne refuse le passage ; le plan peut continuer. Réserves : (a) les jetons sont vérifiés par
`secubox_core` avec le même secret sur la box : un jeton émis ailleurs (autre box du maillage) sera refusé ; (b) un
appelant en simple « tableau de bord LAN » (sans jeton) ne passera **pas** sur les sockets : `X-SecuBox-LAN` n'est
posé que par nginx ; la façade devra lui faire poser `require_lecture` d'abord, puis, selon le besoin, retransmettre
ce verdict ; (c) droits de socket de `waf.sock` et `threatmesh.sock` (threatmesh tourne en root) non relevés : à
vérifier au banc que le compte `secubox` de `secubox-soc` peut s'y connecter.
