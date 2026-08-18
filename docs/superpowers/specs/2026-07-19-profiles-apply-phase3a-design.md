<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Profils Phase 3a — Actionneur `apply` — Conception

**Date** : 2026-07-19
**Statut** : conception validée (scope 3a + boot-enforce décidés), prête pour le plan
**Auteur** : Gérald Kerma <devel@cybermind.fr>
**Module** : `secubox-profiles` (Phase 1 = manifests/scan/status/diff lecture-seule ; Phase 3a = le premier actionneur)

---

## Objectif & périmètre

Livrer **l'actionneur `apply`** : ce qui exécute réellement le plan de changement que
`diff.plan_changes()` calcule déjà. C'est le morceau « risque élevé » du spec Phase 1 — il
bascule des modules sur la board de prod. On le construit **isolé** et on le valide **module
par module, en commençant par `lyrion`** (LXC, sans dépendant — confirmé), jamais sur un lot.

**Dans 3a** : actuators (systemd/LXC/portail) · attente d'état · snapshot 4R · rollback
(sur-échec + commande) · CLI `apply`/`rollback` (dry-run défaut, `--yes`, `--only`) · audit
append-only · garde protégé · CLI **root-only**.

**Hors 3a (cycles suivants)** : Phase 2 (`Requires=`→`Wants=` des 80 units — prérequis avant
tout apply de masse sur des units natives, PAS nécessaire pour lyrion LXC) · réconciliation
au boot (décidée **enforce/auto-apply**) · surfaces API/panel/Companion + sudoers.

## Ce qui existe déjà (réutilisé, non réécrit)

- `diff.plan_changes(manifests, profile, pins, actuals) -> list[Change]` — plan **ordonné**
  (stops par priorité croissante, puis starts par priorité décroissante) ; lève
  `ProtectedViolation` sur un pin protégé→off. `Change(id, action, reason, priority)`.
- `observe.observe(m, *, run, routes) -> Actual` et `observe_all(...)` — **lecture seule**.
  `is_on(actual)`. `Manifest(runtime, units, lxc, portal_domain, protected, priority, …)`.
- `state.resolve` (protected → pin → profil → off). `cli._run` (rc=None = n'a pas pu tourner).

## ① Actuators — purs, `run` injecté

`apply_change(change, manifest, *, run) -> ActuationResult` mappe (type × action) → commandes :

| runtime | START | STOP |
|---|---|---|
| `native` | `systemctl enable --now <unit…>` | `systemctl disable --now <unit…>` |
| `lxc` | `lxc-start -n <lxc>` puis autostart=1 | `lxc-stop -n <lxc>` puis autostart=0 |
| `portal` (a `portal_domain`) | route ajoutée dans `haproxy-routes.json` (hot-reload) | route retirée |

- Un module peut cumuler (ex. `lyrion` = lxc **+** portal) : l'actionneur applique la couche
  runtime **puis** la couche portail, dans le bon sens (START : runtime puis portail ; STOP :
  portail puis runtime — on retire la route avant d'éteindre le backend).
- `run` injecté → testable sans board (on vérifie la séquence exacte de commandes émise).
- `lxc.start.auto` : écrit dans le fichier de conf LXC (persistance reboot). L'édition du
  fichier de config LXC est faite par une petite fonction dédiée (idempotente).
- La route portail : lecture + modification + réécriture **atomique** de `haproxy-routes.json`
  (temp+rename, mode préservé — même discipline que `emit.write_category`).

## ② Attente d'état — après chaque actionnement

`wait_state(manifest, want_on, *, observe, timeout=30, poll=1.0) -> bool` : sonde `observe(m)`
jusqu'à ce que `is_on` == `want_on` (START attend on, STOP attend off), avec un timeout. Pour
un module natif à socket (`/run/secubox/<id>.sock`), la présence du socket est un signal de
prêt additionnel. **Timeout → échec** du changement → déclenche le rollback.

`observe`/le clock sont injectés → testable (on simule une convergence, un timeout).

## ③ Snapshot 4R + rollback

**Avant** tout apply, capturer l'état réel courant (`{id: on|off}`) des modules **du plan**
(pas toute la box) dans un snapshot rotatif : `/var/lib/secubox/profiles/rollback/R1.json …
R4.json` (R1 = le plus récent ; on décale R1→R2→R3→R4, on jette l'ancien R4). Écriture
atomique. Chaque snapshot porte : horodatage RFC 3339, profil actif, la liste `{id: pre_state}`.

- **Rollback-sur-échec** (automatique) : si le module *K* échoue (actionnement ou timeout),
  on **inverse en mémoire** les *K-1* changements déjà appliqués (ré-actionne chaque module
  touché vers son `pre_state`), séquentiellement, best-effort, puis on s'arrête et on **rend
  compte** de ce qui a été appliqué/rollbacké. La box revient à son état d'avant-apply.
- **Rollback-commande** (`profilectl rollback [--target R1..R4] [--yes]`) : lit un snapshot,
  calcule le plan pour restaurer son état, l'applique avec la **même** sûreté (ordre, attente,
  audit). `R1` par défaut.

## ④ Orchestration — `apply_plan`

`apply_plan(plan, manifests, *, run, observe, audit, snapshot) -> ApplyReport` :

1. **Refus** si le plan contient un STOP sur un module `protected` (ceinture+bretelles ;
   `plan_changes` refuse déjà le pin protégé→off).
2. **Snapshot** l'état pré-apply des modules du plan (③).
3. Exécuter **dans l'ordre du plan** (stops avant starts, priorité — déjà ordonné) :
   **un module à la fois**, actionner (①) → attendre l'état (②) → **auditer** la décision.
   Jamais en parallèle.
4. Échec d'un module → **rollback-sur-échec** (③) → `ApplyReport(status="rolled_back", …)`.
5. Succès → `ApplyReport(status="applied", changed=[…])`.

**Sûreté OFF-avant-ON** garantie par l'ordre de `plan_changes` (stops d'abord). Avec ~2 Go
libres, allumer avant d'éteindre ferait un pic fatal — l'ordre est une décision de sûreté.

## ⑤ Audit append-only

`audit(record)` → append-only vers `/var/log/secubox/audit.log`, une ligne JSON par décision
(horodatage RFC 3339, module, action, résultat ok/fail, raison). Rotation sans truncate
(contrainte CSPN « journalisation immuable »). Best-effort : un audit qui échoue ne bloque pas
l'apply mais est signalé.

## ⑥ Surface CLI (Phase 3a)

`secubox-profilectl` gagne :

- `apply [--profile X] [--only ID …] [--yes]` — **dry-run par défaut** (affiche le plan, n'agit
  pas). `--yes` obligatoire pour agir. `--only ID` (répétable) **restreint le plan aux modules
  nommés** — c'est le primitif de la validation « module par module » (ex. `apply --only lyrion
  --yes`). `--profile` sinon le profil actif.
- `rollback [--target R1..R4] [--yes]` — dry-run par défaut ; `--yes` pour agir.

**Root-only** : `apply`/`rollback` refusent si `euid != 0` (comme `scan`) — ils pilotent
systemd/LXC/haproxy. (Le sudoers scopé + la route API/panel viennent au cycle des surfaces,
selon la guideline webui→ctl.)

`diff`/`status`/`scan` restent inchangés.

## Tests

- **Actuators (purs, run injecté)** : chaque (runtime × action) émet la séquence exacte ;
  lyrion (lxc+portal) applique runtime puis portail (START) / portail puis runtime (STOP) ;
  autostart écrit ; route portail ajoutée/retirée atomiquement.
- **wait_state** : converge → True ; timeout → False (clock/observe injectés).
- **Snapshot 4R** : capture le pré-état du plan ; rotation R1→R4 ; lecture ; atomique.
- **Orchestration** : ordre stops-avant-starts respecté ; un-à-un ; audit par décision ;
  refus sur STOP d'un protégé ; **échec au module K → rollback des K-1** (état restauré) ;
  dry-run n'agit pas.
- **Rollback-commande** : restaure un snapshot avec la même sûreté.
- **CLI** : dry-run par défaut n'écrit rien ; `--yes` requis ; `--only` restreint le plan ;
  euid≠0 refusé.
- Chaque test comportemental doit pouvoir échouer (mutation). Cible ≥ 80 % (CSPN).

## Validation réelle (protocole du spec — impératif)

Sur gk2, **root**, **`lyrion` seul** : `apply --only lyrion` (dry-run montre le plan) →
`apply --only lyrion --yes` (éteint lyrion : lxc-stop + autostart=0 + route portail retirée,
attente OK, audit) → vérifier lyrion arrêté + `rollback --yes` (ou pin on + apply) le rallume.
**Jamais** un lot. lyrion est LXC leaf → aucune cascade `Requires=core` (Phase 2 non requise
ici).

## Hors périmètre (YAGNI, cycles suivants)

- Phase 2 (`Requires=`→`Wants=` des 80 units) — prérequis avant apply de masse natif.
- Réconciliation au boot (`secubox-profile-apply.service`, **enforce/auto-apply** décidé).
- Surfaces API `/api/v1/profiles/apply|rollback` + panel + Companion + **sudoers scopé**
  (webui→ctl, cf. guideline).
- Planification horaire, sync mesh, profils par utilisateur.
