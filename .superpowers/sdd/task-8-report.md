# Task 8 — Rapport : Packaging + cross-build + rolling-deploy recipe (rlevel-per-peer)

**Statut :** Terminé.

(Note : ce fichier contenait précédemment un rapport Task-8 sans rapport avec
ce plan — TLS série Z / secubox-picobrew — écrasé ici car il ne concernait pas
le plan `feat/rlevel-per-peer`.)

## Commit

`build(toolbox): package rlevel (policyctl, sudoers, panel, seed default_mode) + changelog`

Fichiers modifiés/créés :
- `packages/secubox-toolbox/debian/rules` — installe `sbxmitm-policyctl` (0755),
  `www/rlevel/` → `usr/share/secubox/www/rlevel/`, `menu.d/27-rlevel.json`, et
  `debian/secubox-toolbox.sudoers` → `/etc/sudoers.d/secubox-toolbox` (0440).
- `packages/secubox-toolbox/debian/secubox-toolbox.sudoers` (créé) — 5 lignes,
  une par sous-commande fixée (`set-floor *`, `force *`, `set-chosen *`,
  `set-default *`, `list`), user `secubox-toolbox` (le `User=` du
  `systemd/secubox-toolbox.service`), pas de `sbxmitm-policyctl ALL`.
  Validé `visudo -cf` : OK.
- `packages/secubox-toolbox/debian/postinst` — seed idempotent de
  `/var/lib/secubox/toolbox/peer-rlevel.json`
  (`{"defaults":{"mode":"reel","floor":"passive"},"peers":{}}`), jamais
  écrasé sur upgrade, chown/chmod du fichier seul (aucun parent partagé
  touché). Choix `default_mode="reel"` documenté en commentaire +
  changelog : préserve le comportement actuel (tout peer MITM'd + block
  honoré) pour éviter un downgrade fleet-wide surprise au déploiement ;
  les opérateurs abaissent ensuite par-peer.
- `packages/secubox-toolbox/debian/control` — ajoute `sudo` aux `Depends`
  (transport de délégation `sudo -n` utilisé par `secubox_toolbox/api.py`
  pour appeler le ctl).
- `packages/secubox-toolbox/debian/changelog` — bump `2.8.6` → `2.8.7-1~bookworm1`.
- `packages/secubox-toolbox-ng/debian/changelog` — bump `0.1.37` → `0.1.38-1~bookworm1`
  (aucun changement `control`/`rules` : `rlevel.go` compile dans le binaire
  `sbxmitm` existant, même package Go, aucun fichier d'install nouveau).

Vérifié déjà en place (rien à ajouter) :
- `nftables.d/secubox-toolbox-wg.nft` + `-wg-fanout.nft` (named set
  `@rlevel_off` + `ip saddr @rlevel_off return`) sont déjà installés par
  `execute_after_dh_auto_install` dans `debian/rules` (confirmé par grep).
- API `/rlevel` déjà dans `secubox_toolbox/api.py`, packagée avec le reste
  du module Python (`cp -r secubox_toolbox`), rien à ajouter.

## Cross-build Go arm64

```
cd packages/secubox-toolbox-ng && GOARCH=arm64 GOOS=linux go build -mod=vendor -o /tmp/sbxmitm ./cmd/sbxmitm
file /tmp/sbxmitm
# ELF 64-bit LSB executable, ARM aarch64, ..., statically linked
```
→ **OK**. `rlevel.go`/`rlevel_test.go`/`rlevel_wire_test.go` déjà présents dans
`cmd/sbxmitm/`, même package `main` — inclus automatiquement, aucune
modification de `debian/rules` (toolbox-ng) nécessaire.

## Tests

- `go test -mod=vendor ./cmd/sbxmitm/` → **PASS**.
- `go test -mod=vendor ./...` (suite complète toolbox-ng : sbx-sentinel,
  sbxmitm, sbxwaf, internal/forge, httpcodec, relay, reload, sentinel) →
  **PASS** (8/8 packages ok).
- `pytest tests/test_rlevel_api.py tests/test_rlevel_panel.py` (secubox-toolbox)
  → **36 passed**.
- Suite complète `pytest tests/` (secubox-toolbox, 373 tests) → **335 passed,
  3 failed** — les 3 échecs sont **préexistants, hors scope** :
  `test_bypass_sources.py::test_load_bypass_tagged_missing_source_skipped`
  (drift schéma non lié à rlevel, commit `45f8397e` antérieur à cette
  branche) et 2 échecs `test_media_stats.py` (`ModuleNotFoundError:
  secubox_core` — artefact d'environnement local, module hors PYTHONPATH du
  venv de test, pas un régression rlevel). Vérifié : ces 3 tests échouent
  déjà indépendamment de nos modifications.

## Build des `.deb`

**secubox-toolbox (arch:all)** :
```
cd packages/secubox-toolbox && dpkg-buildpackage -us -uc -b
```
→ **OK**, `secubox-toolbox_2.8.7-1~bookworm1_all.deb` produit.
`dpkg-deb -c` confirme :
```
./etc/sudoers.d/secubox-toolbox          (0440 root:root)
./usr/sbin/sbxmitm-policyctl              (0755)
./usr/share/secubox/menu.d/27-rlevel.json
./usr/share/secubox/www/rlevel/index.html
```
`bash -n postinst` (extrait du .deb, post `#DEBHELPER#` substitution par
dh_installsystemd) → OK, `#DEBHELPER#` correctement remplacé (aucune
occurrence littérale restante), `exit 0` final présent.

Avertissements préexistants, hors scope de cette tâche (non liés à rlevel) :
`${python3:Depends}` non substituée et conffile `/etc/secubox/toolbox.toml`
« dupliqué » — déjà présents avant ce commit.

**secubox-toolbox-ng (arch:arm64)** :
```
cd packages/secubox-toolbox-ng && dpkg-buildpackage -a arm64 -us -uc -b
```
→ **Bloqué par le dependency-checker** : `dpkg-checkbuilddeps` exige
`golang-go` pour l'arch hôte **arm64** (`golang-go:arm64`), absent de cette
machine (seul `golang-go:amd64` est installé — pas de support multiarch Go
sur ce poste). C'est une limitation de l'outillage dpkg de vérification des
Build-Depends pour une cross-compilation Go pure (`CGO_ENABLED=0`), pas un
problème du build lui-même : Go cross-compile sans avoir besoin d'un
toolchain arm64 installé.
Contournement de **vérification uniquement** (`dpkg-buildpackage -a arm64 -d
...`, `-d` = ignore les dépendances de build) : le build réel a ensuite
**réussi** — `secubox-toolbox-ng_0.1.38-1~bookworm1_arm64.deb` produit,
`dpkg-deb -c` confirme `./usr/sbin/sbxmitm` (0755), et le binaire extrait est
bien `ELF ... ARM aarch64 ... stripped`. `bash -n` sur le postinst extrait →
OK, `#DEBHELPER#` correctement substitué.
Le `.deb` produit avec `-d` est donc valide et déployable, mais un build CI
« propre » sur cette machine échouerait à la porte `dpkg-checkbuilddeps` tant
que `golang-go:arm64` (ou l'équivalent multiarch) n'est pas installé — ceci
est indépendant de ce plan et déjà vrai avant ce commit (aucune régression
introduite ici). Le binaire cross-buildé de l'étape 4 (`/tmp/sbxmitm`) reste
la référence pour un déploiement manuel immédiat si le `.deb` CI n'est pas
disponible.

## Nettoyage post-build

Un fichier binaire préexistant et suivi par git,
`packages/secubox-toolbox-ng/sbx-sentinel` (déjà commité avant ce plan, non
gitignoré contrairement à `/sbxmitm`/`/sbxwaf`), a été régénéré à l'identique
(diff binaire, mêmes octets logiques mais horodatage/BuildID différents) par
`dh_auto_build`. Restauré via `git restore` pour ne pas polluer le commit
avec un artefact de build — signalé ici pour traçabilité, aucune action
requise côté plan (préexistant, hors scope).

Aucun `.deb`, `.buildinfo`, `.changes`, `debian/secubox-toolbox*/` de staging,
`.substvars` n'a été ajouté au commit — tous confirmés `git status
--ignored` sous les règles `.gitignore` existantes.

## Préoccupations

1. **arm64 cross-build CI** : si le runner CI n'a pas `golang-go:arm64`
   (multiarch) installé, `dpkg-checkbuilddeps` bloquera le build
   `secubox-toolbox-ng` même si le binaire compile parfaitement (Go pur,
   `CGO_ENABLED=0`). À vérifier sur l'environnement CI réel — probablement
   déjà résolu là-bas (image cross dédiée) puisque ce n'est pas nouveau à ce
   plan.
2. **3 tests pytest préexistants en échec** (`test_bypass_sources.py` +
   `test_media_stats.py` ×2) — sans rapport avec rlevel, mais à corriger
   séparément (drift de schéma bypass-sources ; `secubox_core` absent du
   PYTHONPATH de test local).
3. **Recette de rolling-deploy** (rolling restart des 4 workers,
   `sudo -n` avant chaque appel ctl, vérification bypass nft "off") reste à
   exécuter manuellement sur le board — hors périmètre de cette tâche de
   packaging (cf. section « Recette de déploiement » du brief).
