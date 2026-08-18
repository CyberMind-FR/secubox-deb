<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Profils — surfaces API/panel apply+rollback (webui→ctl) — Conception

**Date** : 2026-07-19
**Statut** : conception validée (NNP=false + dry-run/confirm approuvés)
**Auteur** : Gérald Kerma <devel@cybermind.fr>
**Module** : `secubox-profiles` (Phase 3a a livré le CLI `apply`/`rollback` ; ici on l'expose à l'UI)

---

## Objectif

Exposer `apply`/`rollback` dans l'API + le panneau `/profiles/`, via la guideline
**webui→ctl** : le panel (non privilégié) sous-traite au helper root `secubox-profilectl`
par un sudoers scopé commande-exacte. L'opérateur choisit un profil, voit le plan (dry-run),
confirme, applique ; peut rollback.

## Contrainte d'architecture (résolue)

Le service `secubox-profiles` tourne en `User=secubox`, **`NoNewPrivileges=true`**, sur sa
propre socket (jamais l'aggregator — le moteur ne doit pas dépendre de ce qu'il redémarre).
`NNP=true` **neutralise sudo** : impossible de déléguer à un helper root. Donc :

- **`NoNewPrivileges=false`** sur ce service (assouplissement ciblé, indispensable pour
  `sudo → profilectl`). Précédent projet : wireguard/wgctl, lxc-info status probes. Tradeoff
  documenté ; le reste du durcissement (User=secubox, ReadWritePaths restreints) est conservé.

## ① CLI — `--json` sur `apply`/`rollback`

`apply`/`rollback` impriment aujourd'hui du texte. On ajoute `--json` : un payload
`{"status", "changed", "failed", "rolled_back", "target"?}` que la route web parse. Sémantique
et codes retour **inchangés** (0 applied/planned, 2 sinon, 1 non-root, 3 refus protégé).

## ② Flux set-active-puis-apply (commande sudo FIXE)

L'apply utilise le **profil actif** (`/etc/secubox/profiles/active`). Le panel :

1. `POST /api/v1/profiles/active {name}` — la route (secubox) écrit le fichier active
   (atomique) après avoir vérifié que `<name>.toml` existe. `/etc/secubox/profiles` est
   writable par secubox (déjà le cas pour pins/members).
2. `POST /api/v1/profiles/apply` — la route lance **`sudo -n /usr/sbin/secubox-profilectl
   apply --yes --json`** (commande **fixe**, zéro arg variable → sudoers exact-command propre).
   L'apply agit sur le profil actif posé à l'étape 1.
3. `POST /api/v1/profiles/rollback` — `sudo -n secubox-profilectl rollback --yes --json`
   (défaut R1).

**`--only` reste CLI-only** : un `<id>` variable casserait le sudoers exact-command (wildcard
interdit). La prudence du panel vient du **dry-run affiché + confirm** (l'opérateur voit les N
modules avant d'agir), pas d'un filtre. Le rollout module-par-module reste l'outil root CLI.

## ③ Routes web (api/web.py)

Toutes `Depends(require_jwt)`. Les POST apply/rollback lancent un **subprocess bloquant** :
elles tournent via **`asyncio.to_thread`** (le service a sa propre boucle ; un apply de
plusieurs minutes ne doit pas figer le polling status du panel).

- `POST /profiles/active` `{name}` → 404 si profil inconnu ; écrit active ; renvoie `{active}`.
- `POST /profiles/apply` → `to_thread(sudo apply --yes --json)` ; mappe rc : 3→409 (refus
  protégé), !=0→500, sinon renvoie le rapport parsé.
- `POST /profiles/rollback` → idem avec rollback.
- `GET /profiles/diff` (EXISTE) sert déjà le plan pour l'aperçu.

## ④ Sudoers — `sudoers.d/secubox-profiles`

`0440`, exact-command, livré par le paquet (debian) :

```
secubox ALL=(root) NOPASSWD: /usr/sbin/secubox-profilectl apply --yes --json
secubox ALL=(root) NOPASSWD: /usr/sbin/secubox-profilectl rollback --yes --json
```

## ⑤ Panel `/profiles/`

Le panel a déjà la vue diff (start/stop). On ajoute une section **« Bascule »** :

- **Sélecteur de profil** (dropdown alimenté par `GET /profiles/profiles`) → bouton
  « Prévisualiser » : `POST /active {name}` puis affiche `GET /diff` (le plan).
- **Bouton Apply** — visible seulement après un aperçu ; `confirm()` explicite
  (« Ceci va démarrer/arrêter N modules sur la box. Continuer ? ») → `POST /apply` →
  affiche le rapport (changed/failed/rolled_back) ; `errorToast` persistant sur échec.
- **Bouton Rollback** → `confirm()` → `POST /rollback` → rapport.
- Réutilise le hybrid-skin, `esc()`, `sbx_token`, la vue diff existante. Un apply long montre
  un indicateur de progression persistant qui se résout en succès transitoire ou erreur
  persistante (jamais un succès qui disparaît avant la fin réelle).

## Tests

- **CLI `--json`** : `apply`/`rollback --json` émettent le rapport ; codes retour inchangés.
- **Route active** : profil inconnu → 404 ; connu → écrit active, renvoie `{active}`.
- **Route apply/rollback** : `run` (subprocess) injecté ; rc 3→409, rc!=0→500, rc 0→rapport
  parsé ; le subprocess est lancé via to_thread (n'écrit rien en direct — délègue au ctl).
- **Sudoers** : `visudo -c` ; commande fixe (pas de wildcard).
- Chaque test comportemental peut échouer (mutation). Cible ≥ 80 % (CSPN).

## Hors périmètre (cycles suivants)

- Réconciliation boot (a besoin d'un garde anti-nuke : refuser si pas de profil actif / plan
  > seuil — signalé dangereux).
- `--only` dans le panel (sudoers exact-command incompatible ; reste CLI).
- Companion `profiles` (l'API suffit ; l'app viendra).
- Progression temps-réel / streaming de l'apply (le rapport final suffit en v1).
