<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Centres & Grants + Remote Config — Design

**Date :** 2026-07-25
**Statut :** validé (design), prêt pour le plan d'implémentation
**Module :** `secubox-annuaire` (+ surface webui/CLI)
**Sous-projet 1/3** d'un ensemble « auto-centre et multiple centres » (les suivants : *support/assistance request*, *métriques centralisées+meshed*, chacun son propre cycle spec→plan→impl, réutilisant ce socle).

---

## Objectif

Donner à une box la capacité de **fédérer avec un ou plusieurs « centres »** et de **recevoir de la config distante**, tout en restant **son propre centre autonome et souverain**. Ce sous-projet livre le **socle « Centres & Grants »** (enrôlement + octroi de capacités par-scope, révocable) porté par un cas concret : le **remote config**.

## Décisions actées

1. **Modèle de centre = hybride.** Chaque box est toujours son propre centre (autonome, fonctionne sans aucun centre). Elle peut fédérer avec 0..N centres. Un centre est une **identité annuaire (DID)** ; une « console dédiée » est simplement un centre opéré par un humain (une box en mode-centre, ou un service exposant le protocole annuaire). Une box peut aussi **être un centre** pour d'autres (peer-as-center, symétrique).
2. **Autorité par délégation (grant).** Un centre n'a d'autorité que ce que la box lui **accorde explicitement**, par capacité, **révocable à tout instant**. Souverain par défaut, géré à distance seulement par grant.
3. **Propriété de config = calques mono-propriétaire (layered).** Chaque scope de config (`firewall`, `dns`, …) est une **pile ordonnée de calques** ; chaque calque a **un seul propriétaire** (déterministe, zéro conflit intra-calque). Config effective = **deep-merge par précédence**, **box-local toujours au sommet**.
4. **Composition = deep-merge par clé.** Un calque override pose des clés individuelles ; le baseline fournit le reste ; effectif = fusion profonde. Le calque box-local gagne toujours (souveraineté).
5. **Approche = étendre le journal annuaire.** Grants et propriété-de-scope = **ops signées du journal append-only**, mesh-syncées, appliquées via le **4R double-buffer** existant. Réutilise tout le substrat (journal signé BLAKE2b, `mesh_sync`, `config_apply`, `resolver.can`).

## Contexte (substrat existant, vérifié)

- `secubox-annuaire` : journal signé append-only (`crypto.py`, `log.py`), `model.py` (Identity, NodeRecord, ConfigBlob, ServiceOffer, `Op.CONFIG_PUBLISH`/`CONFIG_REVOKE`), `mesh_sync.py`, `config_apply.py` (**4R déjà implémenté** : shadow → validate BLAKE2b + parse TOML → swap atomique `os.replace` → rollback gardé), `resolver.py` (`can` = gating de capacité), `verbs.py` (genesis/invite/accept/propose/vote/tally), `federation.py`, `threatmesh.py`.
- `secubox-p2p` : `federation.py`, `master-link/` webui, `annuaire_client.py`, `sbx-mesh-invite`/`join`.
- Le remote-config **mono-centre** est donc ~80% présent (ConfigBlob + `config_apply`). Ce sous-projet ajoute : le **modèle grant/centre**, le **multi-centres en calques**, la **composition deep-merge**, et la **surface** de gestion.

## Composants

| Fichier | Rôle |
|---|---|
| `annuaire/model.py` (étendu) | ops `GRANT_ISSUE`/`GRANT_REVOKE` ; modèle `Grant{center_did, capability, scope, layer, issued_by, ts}` ; `ConfigBlob` + champ `layer` |
| `annuaire/grants.py` (neuf) | résout les grants effectifs depuis le journal : `owner(scope, layer)`, `can_push(center_did, scope, layer)`, `revoked?` ; liste des calques ordonnés d'un scope |
| `annuaire/config_compose.py` (neuf) | deep-merge par clé des ConfigBlobs d'un scope, par précédence (baseline < override < … < box-local) → texte TOML composé (pur, testable) |
| `annuaire/config_apply.py` (étendu) | compose d'abord les calques (via `config_compose`) puis applique le texte composé via le 4R existant |
| `api/main.py` (étendu) | endpoints centres/grants : enrôler, grant/revoke scope-layer, matrice de propriété, diff config effective, propositions en attente |
| `sbin/sbx-centersctl` (neuf) | CLI root scopé : `enroll`/`grant`/`revoke`/`list`/`propose-accept` (écrit les ops de journal, jamais d'action root hors config_apply) |
| `www/centers/index.html` (neuf) | panneau : liste centres, matrice scope×calque→propriétaire, contrôles grant/révoque, diff effectif, file de propositions |
| `menu.d/…-centers.json` | entrée navbar |

## Modèle de données (ops de journal)

```
GRANT_ISSUE  { grant_id, center_did, capability="config", scope, layer, issued_by=<box_did>, ts, sig=<box> }
GRANT_REVOKE { grant_id, issued_by=<box_did>, ts, sig=<box> }
CONFIG_PUBLISH (existant, étendu) { scope, layer, content_hash, payload, publisher_did, ts, sig=<center> }
```

- `layer` ∈ ordre fixe `["baseline", "override", "local"]` (extensible ; `local` réservé box, non attribuable à un centre).
- Un `Grant` est valide s'il est `GRANT_ISSUE` non suivi d'un `GRANT_REVOKE` du même `grant_id`, émis par la box propriétaire du journal, et signé.
- **Invariant d'unicité** : au plus un grant actif par `(scope, layer)` non-local. Émettre un grant sur un `(scope, layer)` **déjà accordé est REJETÉ** — l'opérateur doit d'abord `GRANT_REVOKE` l'existant (transition de propriété explicite, jamais silencieuse ; aligné CSPN).

## Flux de données (push config distant)

1. La box émet `GRANT_ISSUE(center=A, config, scope=firewall, layer=baseline)` (op signée box, mesh-syncée).
2. Le centre A publie `CONFIG_PUBLISH{scope=firewall, layer=baseline, payload, sig=A}`.
3. `mesh_sync` livre l'op à la box.
4. La box **vérifie** : signature de A valide **ET** grant actif `(A, config, firewall, baseline)`. Sinon → **file de propositions** (non appliqué).
5. Si accordé : `config_compose` fusionne tous les calques du scope `firewall` (baseline de A + override éventuel + **box-local en dernier**) → texte TOML.
6. `config_apply` passe ce texte composé au **4R** : shadow → validate → swap → rollback gardé.
7. Résultat : `/etc/secubox/firewall.toml` reflète baseline(A) ⊕ override ⊕ local, atomiquement.

## Invariants souveraineté / CSPN

- Un centre ne peut **JAMAIS** écrire le calque `local` (box-local) — rejeté à la vérification.
- Tout grant est **émis par la box** et **révocable** ; le revoke est une op signée ; au revoke, le calque du centre tombe et la config est **recomposée + réappliquée** (4R).
- **Auto-apply** seulement pour les `(scope, layer)` accordés ; les pushs non-accordés → **file de propositions** (l'opérateur accepte/rejette explicitement).
- **4R fail-safe** : un blob composé invalide (hash mismatch, TOML non parseable) **garde le dernier-bon actif** (jamais de config à moitié écrite).
- **Journal signé = audit append-only** : qui a accordé / poussé / révoqué quoi et quand est traçable (exigence CSPN).
- **Scopes secrets non délégables par défaut** : `auth`, `secrets`, et tout scope listé dans une allow-list conservatrice restent **box-local uniquement** — un `GRANT_ISSUE` visant ces scopes est rejeté (protège OTP/secrets, cf. régressions historiques de chown des parents partagés).
- **Zéro-centre = autonomie totale** : sans aucun grant, seul le calque `local` existe ; la box est intégralement souveraine ; ajouter des centres est purement additif.

## Surface (webui + CLI + API)

- **Panneau `/centers/`** (hybrid-dark, jeton `sbx_token`, délégation d'événements — pas d'inline handler interpolé) :
  - Liste des centres enrôlés (DID, label, capacités accordées, dernier contact).
  - **Matrice de propriété** : lignes = scopes, colonnes = calques, cellule = propriétaire (box-local / centre / vide) + bouton grant/révoque.
  - **Diff config effective** : pour un scope, montre baseline ⊕ override ⊕ local composé vs box-local seul (ce qu'un centre a changé).
  - **File de propositions** : pushs de centres non-accordés → accepter (crée le grant + applique) / rejeter.
- **CLI `sbx-centersctl`** : `enroll <center-invite>`, `grant <center> <scope> <layer>`, `revoke <grant-id>`, `list`, `propose accept|reject <id>`.
- **API** délègue toute écriture à `sbx-centersctl` (sudo scopé ou ctl-direct selon les perms du daemon annuaire ; jamais d'action privilégiée in-process), pattern [[feedback_webui_delegates_to_confined_ctl]] / no-sudo si CAP suffit ([[project_rlevel_per_peer]]).

## Tests

- **grants.py** : résolution d'un grant actif ; révocation (grant tombe) ; unicité par `(scope, layer)` ; zéro-centre → seul `local` ; un `GRANT_ISSUE` sur `auth`/`secrets`/`local` est **rejeté**.
- **config_compose.py** (pur) : deep-merge par clé, précédence baseline<override<local, box-local gagne toujours ; baseline+override compose correctement ; scope sans aucun calque → vide/no-op.
- **config_apply.py** : 4R sur texte composé ; blob invalide (hash/TOML) garde le dernier-bon ; recomposition après revoke.
- **vérification de push** : signature centre invalide → rejet ; grant absent → file de propositions ; grant présent → apply.
- **API/CLI** : grant/revoke via ctl (pas d'action root in-process) ; scopes secrets non délégables ; propositions accept→grant+apply.
- **panneau** : matrice + diff + délégation d'événements (garde XSS) ; menu.d valide.
- **e2e (mock mesh)** : enrôler A, grant baseline firewall, A push → composé appliqué ; ajouter override local → local gagne ; revoke A → recompose sans baseline ; deux centres sur deux scopes distincts → aucun conflit.

## Risques connus

| Risque | Traitement |
|---|---|
| Un centre écrase une décision locale | calque `local` toujours au sommet, jamais délégable |
| Un centre malveillant pousse un secret | scopes `auth`/`secrets` non délégables (allow-list) |
| Config à moitié écrite | 4R shadow→validate→swap atomique, dernier-bon gardé |
| Grant fantôme après compromission d'un centre | grant box-émis + révocable instantanément (op signée) ; journal audite |
| Conflit multi-centres | unicité `(scope, layer)` : un seul propriétaire par calque |
| Deep-merge ambigu (listes/tables) | sémantique explicite : tables = merge récursif, valeurs scalaires/listes = remplacées par le calque supérieur (documenté + testé) |
| Boucle mesh_sync (op appliquée en boucle) | idempotence par `content_hash` (le 4R ne réécrit pas si hash inchangé) |

## Hors périmètre (YAGNI / sous-projets suivants)

- **Support/assistance request** (sous-projet 2) : demande d'assistance d'une box vers un centre + session d'aide — réutilisera le grant `capability="assist"`.
- **Métriques centralisées+meshed** (sous-projet 3) : flux de métriques vers les centres accordés + agrégation mesh (patron `threatmesh`) — grant `capability="metrics"`.
- Superposition à > 3 calques, quorum multi-centres pour un même scope, révocation par quorum, mode « flotte autoritaire » (approche 3 écartée). Extensions futures si besoin réel.
