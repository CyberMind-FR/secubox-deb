# Assist OFFER↔REQUEST Dual Rendezvous + Multi-Layer Join Link — Design

**Date :** 2026-07-25
**Statut :** validé (design), prêt pour le plan d'implémentation
**Module :** `secubox-assist` (+ `secubox-annuaire` control-plane, + `secubox-p2p` pour l'escalade WG)
**Extension** du socle assist (spec `2026-07-25-assist-request-design.md`, [[project_assist_request_module]]).

---

## Objectif

Transformer l'assistance d'un modèle **box→centre ciblé** (choisir qui aide) en un **marketplace de rendezvous** : un nœud **annonce sa disponibilité** (OFFER) ou **son besoin** (REQUEST), un **matcher décentralisé** rapproche les paires compatibles, et un **rendezvous mutuel** ouvre la session. La portée est **totale** : au-delà du mesh enrôlé, un **lien multi-couches auto-escaladant** (URL/IP → mesh éphémère → WireGuard → session) permet à n'importe qui d'aider ou d'être aidé, tout en gardant le **data-plane de session sur WireGuard** (invariant préservé).

## Décisions actées (issues du brainstorm)

1. **Dual symétrique + auto-match.** Les deux côtés publient : OFFER (disponible) et REQUEST (besoin), avec **tags libres + scope optionnel**. Un **matcher décentralisé** (chaque nœud, depuis sa copie du journal) rapproche offer↔request par **intersection de tags** (+ scope si présent, + non-expiré).
2. **Rendezvous mutuel double-accept.** Le match notifie **les deux** côtés ; chacun poste un `ASSIST_MATCH_ACCEPT` ; quand les deux ont accepté (« offer et request se sont répondu »), le poseur de REQUEST (= la box aidée) lance le **`SESSION_OPEN` existant** (l'offerer = centre/helper). Réutilise **tout** le socle assist (catalogue borné, console double-consent, audit, token, consentement).
3. **Portée totale via lien multi-couches auto-escaladant.** Un **join-link** single-use + time-boxé escalade automatiquement : **(0)** entrée URL ou IP publique (HAProxy TLS) → **(1)** enrôlement mesh **éphémère** (identité session-scoped, jamais membre gondwana permanent) → **(2)** tunnel **WireGuard** auto-monté (pair éphémère) → session WS **sur ce tunnel**. Un clic, escalade transparente, **teardown** en fin de session.
4. **Invariant data-plane WG-only préservé.** L'URL publique n'est que l'**entrée/bootstrap** ; la session assist tourne **toujours** sur WireGuard (mesh persistant OU tunnel éphémère). Consentement `SESSION_OPEN`, double-consent console, catalogue borné, token hashé, audit append-only, expiry fail-closed : **tous** s'appliquent par-dessus.

## Contexte (substrat, vérifié)

- `secubox-assist` (socle livré) : control-plane `ASSIST_REQUEST/ACCEPT/SESSION_OPEN/SESSION_CLOSE/CONSOLE_*` dans le journal annuaire ; data-plane daemon WS **bind wg-mesh only** + `authorize` (token-hash vs `active_session`) + `dispatch` (catalogue→ctl scopés) ; `console.py` (pty double-consent) ; `token.py` (single-use, hash seul journalisé) ; `audit.py` (append-only). Résolveurs `annuaire/assist.py` (session unique, souveraineté `issued_by==self_did`, expiry fail-closed).
- `secubox-annuaire` : journal signé append-only BLAKE2b + `mesh_sync` (réplication à tous les nœuds — base du matcher décentralisé) + `Grant` + verbs signés genesis-style.
- `secubox-p2p` : `wg-mesh` (WireGuard, gondwana 3 nœuds), `sbx-mesh-invite`/`join`, `adopt_state` (préserve les clés). Base de l'escalade WG éphémère.
- Enrôlement gondwana : genesis/invite/accept (identités DID `did:plc:[0-9a-f]{32}`).

## Composants

| Fichier | Rôle |
|---|---|
| `annuaire/model.py` (étendu) | ops `ASSIST_OFFER`/`ASSIST_OFFER_REVOKE`/`ASSIST_REQUEST_OPEN`/`ASSIST_MATCH_ACCEPT` ; modèles `AssistOffer{offer_id, tags[], scope?, ttl, issued_by, ts}`, `AssistOpenRequest{req_id, tags[], scope?, ttl, reason, issued_by, ts}`, `AssistMatchAccept{match_id, offer_id, req_id, side, issued_by, ts}` |
| `annuaire/assist_match.py` (neuf) | matcher **pur/décentralisé** : `active_offers(entries, now)`, `active_open_requests(entries, now)`, `matches(entries, now) -> [(offer, request, match_id)]` (intersection tags + scope + non-expiré) ; `match_ready(entries, match_id) -> bool` (les deux `ASSIST_MATCH_ACCEPT` présents, non-expirés) |
| `annuaire/verbs.py` (étendu) | `assist_offer`/`assist_offer_revoke`/`assist_open_request`/`assist_match_accept` (valide→signe→append) |
| `assist/rendezvous.py` (neuf, secubox-assist) | orchestration : détecte les matches, expose les propositions au panneau, sur `match_ready` déclenche le `SESSION_OPEN` existant côté requester (box aidée) avec `center_did=offerer` |
| `assist/joinlink.py` (neuf) | génère/valide un join-link single-use time-boxé ; encode l'invite WG éphémère + le contexte de match ; `mint_join(match_id\|offer_id, ttl) -> (url, token_hash)` ; `redeem(token) -> ephemeral_context` |
| `assist/escalate.py` (neuf) | escalade multi-couches auto : (0) sert l'entrée publique (redeem token) → (1) enrôle une **identité éphémère** (clé jetable, DID session-scoped, jamais persistée en membre) → (2) monte un **pair WG éphémère** (via secubox-p2p, IP dans un range dédié `10.11.0.0/24` réservé aux sessions ad-hoc) → signale « prêt » ; **teardown** : révoque identité + pair WG + token à `SESSION_CLOSE`/expiry |
| `api/main.py` (étendu) | endpoints `/offers` (publier/révoquer/lister), `/requests/open` (poster/lister), `/matches` (lister propositions), `/match/accept` (double-accept), `/joinlink` (générer/partager), `/join/<token>` (entrée publique, escalade) |
| `sbin/secubox-assistctl` (étendu) | `offer`/`offer-revoke`/`request-open`/`match-accept`/`joinlink`/`join` (écrit les ops signées + pilote escalate.py ; enrôlement éphémère = chemin privilégié scopé) |
| `www/assist/index.html` (étendu) | onglets : **Disponibilité** (publier/révoquer offer, tags), **Demander** (request ouvert), **Matches** (paires proposées + double-accept), **Inviter** (générer/copier join-link), **Rejoindre** (coller un lien) |
| nft / p2p | range WG éphémère `10.11.0.0/24` ; nft ouvre le WS assist aussi sur `wg-ephemeral` iface (même règle mesh-only, iface additionnelle) ; entrée publique `/assist/join/` via HAProxy→WAF (seule surface publique, bornée au redeem) |

## Modèle de données (ops journal)

```
ASSIST_OFFER         { offer_id, tags:[str], scope?:str, ttl_s:int, issued_by, ts, sig }
ASSIST_OFFER_REVOKE  { offer_id, issued_by, ts, sig }
ASSIST_REQUEST_OPEN  { req_id, tags:[str], scope?:str, ttl_s:int, reason, issued_by, ts, sig }
ASSIST_MATCH_ACCEPT  { match_id, offer_id, req_id, side:"offer"|"request", issued_by, ts, sig }
```

- `match_id` = hash déterministe `blake2b(offer_id + "|" + req_id)` — calculable identiquement par tous les nœuds (matcher décentralisé, pas de coordinateur).
- Un OFFER/REQUEST est **actif** ssi non-révoqué **ET** `now < ts + ttl_s` (liveness ; stale → fail-closed).
- Un match est **ready** ssi il existe un `ASSIST_MATCH_ACCEPT{side="offer"}` **ET** un `{side="request"}` pour le même `match_id`, tous deux non-expirés, avec offer+request encore actifs.
- **Souveraineté** : côté requester, seul un `SESSION_OPEN` émis par la box (`issued_by==self_did`) ouvre réellement la session ; le match ne fait qu'**appairer**, il n'accorde rien.

## Flux — Phase A (dual intra-mesh)

1. Nœud A publie `ASSIST_OFFER{tags:["lora","meshtastic"], ttl}` ; nœud B publie `ASSIST_REQUEST_OPEN{tags:["lora"], ttl, reason}`. Mesh-syncés.
2. Chaque nœud calcule localement `matches(entries, now)` → paire (A.offer, B.request, match_id) car `{lora} ∩ {lora,meshtastic} ≠ ∅`.
3. Panneau de A **et** de B affiche la proposition. A poste `ASSIST_MATCH_ACCEPT{side="offer"}`, B poste `{side="request"}`.
4. `match_ready` devient vrai. **B** (poseur du REQUEST = box aidée) lance le `SESSION_OPEN` existant avec `center_did=A` → consentement opérateur B → token → A se connecte au WS de B **sur le wg-mesh** → session assist (catalogue, console double-consent, audit). Identique au socle.

## Flux — Phase B (portée totale, lien multi-couches)

1. A (ou B) génère un **join-link** : `assistctl joinlink --for <match_id|offer_id> --ttl 900` → `https://assist.<domain>/assist/join/<token>` (single-use, time-boxé). Partagé hors-bande (email, chat…).
2. Un tiers **non-enrôlé** ouvre l'URL (**couche 0**, entrée publique HAProxy TLS, bornée au redeem).
3. `escalate.py` : **couche 1** — frappe une **identité éphémère** (clé jetable, DID session-scoped, marquée éphémère, jamais promue membre gondwana) ; **couche 2** — monte un **pair WireGuard éphémère** (`10.11.0.0/24`, via secubox-p2p) auto ; signale « prêt ».
4. La session assist s'ouvre **sur le tunnel WG éphémère** (WS bind `wg-ephemeral`), avec le **même** flux consentement/catalogue/console/audit. Le tiers joue le rôle offerer **ou** requester selon le sens du lien.
5. **Teardown** à `SESSION_CLOSE`/expiry : révoque l'identité éphémère + le pair WG + invalide le token. Rien ne persiste.

## Invariants souveraineté / CSPN

- **Data-plane WG-only** : la session tourne **toujours** sur WireGuard (mesh persistant ou éphémère `10.11.0.0/24`) ; l'URL publique `/assist/join/` est la **seule** surface publique, **bornée au redeem du token** (aucun endpoint de session exposé en clair). nft mesh-only étendu à `wg-ephemeral`.
- **Identité éphémère** : clé jetable session-scoped, **jamais** promue membre annuaire persistant ; auto-révoquée au teardown ; distincte des identités gondwana (flag `ephemeral=true`, TTL dur).
- **Join-link single-use + time-boxé** ; le secret ne transite que dans l'URL partagée hors-bande ; seul son hash est journalisé (comme le token de session).
- **Consentement inchangé** : `SESSION_OPEN` exige le consentement opérateur de la box aidée ; le match/rendezvous n'accorde **rien** (appairage seul). Double-consent console. Catalogue borné (auth/secrets inatteignables). Token hashé. Audit append-only complet (offer/request/match-accept/join/session/actions/console/close). Expiry fail-closed partout. Session unique par box.
- **Souveraineté matcher** : le matcher est **pur et local** (aucune autorité tierce) ; `match_ready` n'ouvre rien sans le `SESSION_OPEN` souverain de la box aidée.
- **Exposition des besoins** : un `ASSIST_REQUEST_OPEN` advertise un besoin dans le périmètre du mesh (tradeoff assumé du marketplace) ; mitigation : tags génériques possibles, `scope` optionnel, TTL court, révocable.

## Surface (webui + CLI + API)

- **Panneau `/assist`** (hybrid-dark, `sbx_token`, délégation d'événements) — nouveaux onglets : **Disponibilité** (offer tags+ttl, révoquer), **Demander** (request ouvert), **Matches** (paires + double-accept, état ready), **Inviter** (générer/copier join-link, sens offer|request), **Rejoindre** (coller un lien → escalade auto + statut couches 0→2).
- **CLI `secubox-assistctl`** : `offer`/`offer-revoke`/`request-open`/`match-accept`/`joinlink`/`join`.
- **API** délègue toute écriture au ctl (jamais d'action privilégiée in-process) ; lectures in-process depuis le journal + matcher.

## Tests

- **assist_match.py** (pur) : intersection tags ; scope respecté ; expiry fail-closed (offer/request/accept) ; `match_id` déterministe identique cross-nœud ; `match_ready` seulement si les deux side présents+actifs ; révocation (offer/request tombe → plus de match).
- **verbs** : signature + validation de chaque op ; `match_accept` d'un côté ne suffit pas.
- **rendezvous.py** : `match_ready` → déclenche `SESSION_OPEN` côté requester avec `center_did=offerer` ; souveraineté (le match d'un pair ne force pas la box).
- **joinlink.py** : single-use ; time-boxé ; hash-only journalisé ; redeem invalide après usage/expiry.
- **escalate.py** : couche 1 identité **éphémère** (jamais persistée membre) ; couche 2 pair WG éphémère `10.11.0.0/24` ; teardown révoque identité+pair+token ; échec d'une couche = fail-closed (pas de session).
- **invariants** : session data-plane jamais hors WG ; entrée publique bornée au redeem ; consentement `SESSION_OPEN` requis ; double-consent console ; catalogue borné ; audit complet.
- **e2e (mock mesh)** : A offer + B request → match → double-accept → session intra-mesh (Phase A). Join-link → tiers non-enrôlé → escalade 0→1→2 → session sur WG éphémère → teardown (Phase B).

## Risques connus

| Risque | Traitement |
|---|---|
| Un pair pousse un match pour forcer une box | le match n'accorde rien ; seul le `SESSION_OPEN` souverain (consentement + `issued_by==self_did`) ouvre |
| Identité éphémère promue/persistée par erreur | flag `ephemeral=true` + TTL dur + auto-révocation ; jamais dans le chemin genesis/invite gondwana |
| Surface publique du join-link | HAProxy→WAF, endpoint borné au **redeem** (aucun endpoint de session public) ; single-use + time-boxé ; hash-only |
| Session hors WG (fuite mesh-only) | WS bind wg-mesh **ou** wg-ephemeral uniquement ; nft mesh-only étendu ; l'URL n'est jamais le transport de session |
| Exposition des besoins (request ouvert) | tags génériques, scope optionnel, TTL court, révocable ; périmètre = mesh de confiance par défaut |
| Boucle/duplication de matches | `match_id` déterministe + idempotence ; `SESSION_OPEN` unique par box (invariant existant) |
| Teardown incomplet (pair WG orphelin) | teardown idempotent à `SESSION_CLOSE` **et** expiry ; garbage-collect périodique des pairs `10.11.0.0/24` expirés |

## Hors périmètre (YAGNI / futurs)

- Réputation/notation des offerers, files d'attente multi-matches simultanés par nœud, matching sémantique (synonymes de tags), fédération inter-mesh des offers au-delà du join-link.
- Réutilise le **console pty deferred** du socle (l'escalade console reste un follow-up du socle assist, orthogonal).
