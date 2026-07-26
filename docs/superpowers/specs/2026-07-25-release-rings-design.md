# Progressive Artifact Delivery — Center-Driven Release Rings — Design

**Date :** 2026-07-25
**Statut :** validé (design), prêt pour le plan d'implémentation
**Modules :** `secubox-annuaire` (control-plane) + `apt.secubox.in`/reprepro (actuateur repo) + actuateur box + surface webui/CLI
**Étend** Centres & Grants ([[project_gondwana_directory_live]], grant `capability`) et `apt.secubox.in` ([[project_apt_secubox_in_on_gk2]]).

---

## Objectif

Livrer les artifacts SecuBox (paquets `.deb`, images conteneur, bundles `www`) par **rings de promotion progressive** : `draft → internal → published`. Une **évolution/fix** est un set d'artifacts versionnés qui traverse les rings ; la **promotion** et l'**assignation de ring par-box** sont **pilotées par un centre** (via Centres & Grants), **honorées souverainement** par la box (seulement les centres qu'elle a accordés). Le ring `published` **est** le « profil de base auto » de toute box ; `internal`/`draft` sont des évolutions optionnelles empilées pour les canary. Traçable (journal signé), signé bout-en-bout (apt GPG), 4R fail-safe côté box.

## Décisions actées (issues du brainstorm)

1. **Rings de promotion** ordonnés `draft → internal → published` ; chaque évolution = artifact versionné ; promotion = **op signée** ; rollback = **de-promotion** signée.
2. **Une évolution = des artifacts** (paquets/images/contenus) ; la **config** est traitée séparément (Centres & Grants remote-config) — ce sous-projet ne gère **que** la livraison d'artifacts.
3. **Rings = canaux repo/registry** : distributions `apt.secubox.in` (`draft`/`internal`/`published`) + tags registry conteneurs ; promotion = `reprepro copy` entre distributions (+ retag) ; **pilotée par un centre** (grant `capability="release"`), qui **assigne aussi les rings par-box**. Souverain : la box honore seulement les centres accordés.

## Contexte (substrat, vérifié)

- `apt.secubox.in` : reprepro sur gk2 (`/data/apt`), signé GPG (219BA/44E50F = même clé), Freebox fwd → gk2 ([[project_apt_secubox_in_on_gk2]]). reprepro gère nativement **plusieurs distributions** — base directe des rings. (Ne jamais publier d'amd64-only.)
- Centres & Grants : `Grant{center_did, capability, scope, issued_by}` signé ; résolution `active_grants(entries, self_did)` filtrée **souveraineté** `issued_by==self_did` ; journal signé BLAKE2b + mesh_sync + audit append-only ([[project_assist_request_module]] réutilise le même socle).
- Profiles apply 4R : `profilectl apply/rollback` (dry-run défaut, snapshot 4R, audit) — patron de l'actuateur box ([[project_profiles_apply_phase3a]]).
- apt box : `sources.list` + clés ; l'actuateur box réécrit un **drop-in** de ring, jamais la source principale.

## Composants

| Fichier | Rôle |
|---|---|
| `annuaire/model.py` (étendu) | ops `RELEASE_PUBLISH`/`RELEASE_PROMOTE`/`RELEASE_DEMOTE`/`RING_ASSIGN` ; modèles `Evolution{evo_id, artifacts:[{kind, name, version, hash}], notes, issued_by, ts}`, `RingState{evo_id, ring, issued_by, ts}`, `RingAssign{box_did, ring, issued_by, ts}` ; `RINGS=["draft","internal","published"]` (ordre fixe) ; `capability="release"` reconnu |
| `annuaire/releases.py` (neuf) | résolveur pur : `current_ring(entries, evo_id)` (dernier `RELEASE_PROMOTE`/`DEMOTE`), `box_ring(entries, box_did, self_did)` (dernier `RING_ASSIGN` d'un centre **accordé** ; défaut `published`), `evolutions_in_ring(entries, ring)`, souveraineté `issued_by==self_did` partout |
| `annuaire/verbs.py` (étendu) | `release_publish`/`release_promote`/`release_demote`/`ring_assign` (valide grant `release` + ordre des rings → signe → append) |
| `sbin/secubox-releasectl` (neuf) | CLI : **côté centre** `publish`/`promote`/`demote`/`assign` (écrit les ops signées, grant `release` requis) ; **côté repo** `sync-repo` (applique l'état ring→reprepro) ; **côté box** `apply` (honnête au ring assigné) |
| `sbin/secubox-release-repo` (neuf, host apt) | actuateur repo idempotent : sur `RELEASE_PROMOTE(evo→ring)` → `reprepro -b /data/apt copy <ring> <src> <pkgs>` + retag registry ; op-gated (vérifie l'op signée) ; jamais de publication non-signée |
| `secubox-release/api/main.py` (neuf) | endpoints `/evolutions`, `/rings`, `/promote`, `/demote`, `/assign`, `/box-ring` ; lectures in-process (résolveur), écritures **déléguées à `secubox-releasectl`** (jamais d'action privilégiée in-process) |
| actuateur box `secubox-releasectl apply` | sur `RING_ASSIGN` honoré → **4R** : stage un drop-in `/etc/apt/sources.list.d/secubox-ring.list` vers le ring assigné → `apt-get update` (valider) → swap atomique → `apt-get -y upgrade` ciblé secubox-* ; **rollback** = restaurer le drop-in précédent + pin la version antérieure. Réutilise le 4R de `profilectl`. |
| `www/releases/index.html` (neuf) | panneau : matrice **évolution × ring** (promote/demote côté centre), matrice **box × ring** (assign), artifacts courants par box, historique/audit |
| `menu.d/…-releases.json`, `nginx/releases.conf` | navbar + vhost (socket dédié `release.sock`) |

## Modèle de données (ops journal)

```
RELEASE_PUBLISH { evo_id, artifacts:[{kind:"deb"|"image"|"www", name, version, hash}], notes, issued_by, ts, sig }
RELEASE_PROMOTE { evo_id, ring:"internal"|"published", issued_by, ts, sig }   # avance d'un cran
RELEASE_DEMOTE  { evo_id, ring, issued_by, ts, sig }                          # rollback d'un cran
RING_ASSIGN     { box_did, ring, issued_by, ts, sig }                         # un centre assigne le ring d'une box
```

- `RINGS=["draft","internal","published"]`, ordre fixe. Une évolution naît en `draft` (au `RELEASE_PUBLISH`) ; `PROMOTE` avance **d'un cran** (draft→internal→published) ; `DEMOTE` recule.
- **Validation** : `release_promote`/`ring_assign` exigent un `active_grants(entries, self_did)` avec `capability=="release"` pour le centre émetteur (sinon rejet) — **exactement** le pattern grant de Centres & Grants.
- **Souveraineté** : `box_ring` et `current_ring` ne comptent que les ops émises par un centre **accordé par la box** (`issued_by==self_did` sur le grant) ; l'op d'un pair fédéré non-accordé est **ignorée**.
- **Défaut** : sans aucun `RING_ASSIGN` accordé, une box est sur `published` (baseline auto).

## Flux — promotion + livraison

1. Un centre publie une évolution : `RELEASE_PUBLISH{evo_id, artifacts:[secubox-dpi 1.2.3 sha…]}` → naît en `draft`. L'artifact `.deb` est déjà uploadé dans la distribution `draft` d'apt.secubox.in (build CI).
2. Le centre teste, puis `RELEASE_PROMOTE(evo, internal)` (op signée, grant `release`). L'actuateur repo (`secubox-release-repo`, op-gated) fait `reprepro copy internal draft secubox-dpi` → l'artifact apparaît dans `internal`.
3. Le centre assigne les canary : `RING_ASSIGN{box=canary1, ring=internal}`. `canary1` a accordé le grant `release` à ce centre → honore : actuateur box 4R → drop-in sources `internal` → `apt update` → upgrade `secubox-dpi` depuis `internal`. Les autres box restent `published` (inchangées).
4. Sain après observation → `RELEASE_PROMOTE(evo, published)` → `reprepro copy published internal` → toutes les box `published` reçoivent `secubox-dpi 1.2.3` au prochain sync.
5. Dégradé → `RELEASE_DEMOTE(evo, internal)` + (option) pin la version antérieure sur les box → rollback 4R côté box.

## Invariants souveraineté / CSPN

- **Ops signées + grant `release`** : promouvoir ou assigner un ring exige un grant actif `capability="release"` accordé **par la box/flotte** ; révocable. La box honore **seulement** les centres qu'elle a accordés (souveraineté `issued_by==self_did`).
- **apt GPG bout-en-bout** : les artifacts restent signés (219BA) ; la promotion `reprepro copy` **ne contourne jamais** la signature ; la box vérifie GPG à l'`apt update` (chaîne existante). Jamais de publication amd64-only.
- **4R fail-safe côté box** : le switch de ring passe par shadow drop-in → `apt update` valide → swap atomique → rollback-on-failure ; un `apt` échoué **ne brique pas** la box (restaure le ring précédent). Ne jamais toucher la `sources.list` principale (drop-in seul).
- **Jamais d'auto-promote `published`** sans op centre explicite (ou une règle opt-in que la box a explicitement accordée) — pas de saut de ring (un cran à la fois).
- **Audit append-only** : publish/promote/demote/assign + apply/rollback box tracés dans `/var/log/secubox/audit.log` (qui a promu/assigné quoi, quand). Exigence CSPN.
- **Actuateurs non-privilégiés-in-process** : l'API délègue au `secubox-releasectl` scopé ; le `reprepro`/`apt` tournent via ctl root scopé + sudoers, jamais dans le daemon web ([[feedback_webui_delegates_to_confined_ctl]]). Ne jamais chown les parents partagés `/etc/secubox`/`/var/log/secubox`.
- **Zéro-centre = autonome** : sans grant `release`, la box reste sur `published` (baseline auto) et gère son apt normalement ; ajouter un centre release est purement additif.

## Surface (webui + CLI + API)

- **Panneau `/releases`** (hybrid-dark, `sbx_token`, délégation d'événements) : matrice **évolution × ring** avec boutons promote/demote (côté centre) ; matrice **box × ring** (assign) ; artifacts courants + version par box ; file/historique d'audit.
- **CLI `secubox-releasectl`** : `publish`/`promote`/`demote`/`assign` (centre) ; `sync-repo` (host apt) ; `apply` (box).
- **API** `secubox-release` (socket dédié `release.sock`, **pas** agrégateur-servi si actions apt lentes — patron socket dédié) : lectures in-process, écritures déléguées au ctl, JWT.

## Tests

- **releases.py** (pur) : `current_ring` (dernier promote/demote) ; `box_ring` (dernier assign d'un centre **accordé** ; défaut published ; op d'un pair non-accordé ignorée — souveraineté) ; ordre des rings (pas de saut) ; expiry/révocation de grant → l'op du centre tombe.
- **verbs** : `release_promote`/`ring_assign` sans grant `release` actif → rejet ; signature vérifiable ; un seul cran par promote.
- **actuateur repo** : `RELEASE_PROMOTE` → `reprepro copy` idempotent op-gated ; op non-signée/mauvais grant → refus ; jamais de publication non-signée.
- **actuateur box** : 4R (shadow drop-in → apt update valide → swap → rollback) ; `apt update` échoué → restaure ring précédent (box non-briquée) ; ne touche jamais la sources.list principale.
- **souveraineté e2e (mock mesh)** : box accorde centre A `release` → A promote+assign → box honore ; A révoqué → nouvelle op de A ignorée ; op d'un centre B non-accordé → ignorée (box reste published).
- **panneau** : matrices + délégation d'événements (garde XSS) ; menu.d valide.

## Risques connus

| Risque | Traitement |
|---|---|
| Un centre malveillant pousse un mauvais artifact partout | grant `release` box-émis + révocable ; promotion un cran à la fois ; canary internal avant published ; apt GPG signé |
| `apt upgrade` casse une box | 4R fail-safe (shadow→valider→swap→rollback) ; drop-in seul ; version pin au rollback |
| Publication amd64-only (brique arm64) | garde build/actuateur : refuser une évolution sans arm64 ([[project_apt_secubox_in_on_gk2]]) |
| Saut de ring (draft→published direct) | `PROMOTE` avance d'un seul cran ; `releases.py` valide l'ordre |
| Op de ring d'un pair non-accordé appliquée | souveraineté `issued_by==self_did` sur le grant ; op ignorée sinon |
| reprepro copy contourne la signature | actuateur op-gated + `reprepro` re-signe la distribution cible (chaîne GPG existante) |
| Centre pilote pendant zéro-centre | défaut `published`, autonome ; grant purement additif |

## Hors périmètre (YAGNI / futurs)

- **Canary auto-santé** (rollback automatique sur signaux de métriques) — nécessite le sous-projet métriques ([[project_assist_request_module]] → métriques centralisées) ; ici la promotion/rollback est **pilotée** (centre/opérateur), pas auto-santé.
- Cohortes % (10%→50%→100%) fines — ici l'assignation est par-box (canary = liste de box), pas par pourcentage.
- Registry conteneur complet (multi-tag, GC) — v1 : ref d'image + retag simple ; GC registry = futur.
- Fédération inter-mesh des rings au-delà d'un centre.
