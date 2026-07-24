# Task 2 Report — transparent `.onion` (Unbound forward + tor TransPort + nft redirect + `torctl transparent`)

**Module:** `secubox-tor`
**Branche:** `feat/proxypac-wpad-autodetect`
**Commit Hash:** `b61b5aa1`

## Files Created

- `packages/secubox-tor/conf/torrc.d/60-secubox-transparent.conf`
- `packages/secubox-tor/conf/unbound/secubox-onion-forward.conf`
- `packages/secubox-tor/nft.d/secubox-tor-transparent.nft`
- `packages/secubox-tor/tests/test_torctl_transparent.py`
- `packages/secubox-tor/tests/test_onion_forward.py`
- `packages/secubox-tor/tests/test_nft_transparent.py`

## Files Modified

- `packages/secubox-tor/sbin/torctl` — ajout des variables d'env overridables
  (`TORCTL_TORRC_D` / `TORCTL_UNBOUND_D` / `TORCTL_NFT_D` / `TORCTL_DRYRUN`),
  des fonctions `transport_already_declared` / `transparent_on` /
  `transparent_off` / `transparent_status`, et de l'entrée `transparent)`
  dans le `case` existant. `detect-lan-ip` et `socks-lan` inchangés
  (non-régression vérifiée manuellement, cf. plus bas). `chmod +x` conservé
  (755).

## Test Output — BEFORE (échec attendu, Step 2)

```
FFFF                                                                     [100%]
=================================== FAILURES ===================================
____________ test_on_skips_transport_dropin_when_one_already_exists ____________
E       AssertionError: assert 2 == 0
E        +  where 2 = CompletedProcess(... 'transparent', 'on'], returncode=2,
             stderr='usage: torctl {detect-lan-ip|socks-lan ensure|transparent {on|off|status}}\n')
_______________________ test_off_removes_only_our_files ________________________
E       AssertionError: assert not True
________ test_onion_forward_targets_tor_dnsport_and_keeps_automap_range ________
E       FileNotFoundError: .../conf/unbound/secubox-onion-forward.conf
______________ test_nft_redirects_only_automap_range_to_transport ______________
E       FileNotFoundError: .../nft.d/secubox-tor-transparent.nft
=========================== short test summary info ============================
4 failed in 0.11s
```

## Test Output — AFTER (Step 7)

```
$ cd packages/secubox-tor && python3 -m pytest tests/test_torctl_transparent.py tests/test_onion_forward.py tests/test_nft_transparent.py -q
....                                                                     [100%]
4 passed in 0.07s
```

Suite complète du paquet (non-régression) :

```
$ cd packages/secubox-tor && python3 -m pytest tests/ -q
........................                                                 [100%]
24 passed, 1 warning in 0.70s
```

## Gestion du `cp`/`$SHARE` en dry-run (point crucial du brief)

Le pseudo-code du brief fait un `cp "$SHARE/…"` inconditionnel même quand le
dropin torrc est réutilisé (branche "déjà déclaré"), pour les templates
unbound et nft. Or `$SHARE` (`/usr/share/secubox/tor`) n'existe pas en
environnement de test (paquet non installé), et le script tourne avec
`set -euo pipefail` : un `cp` sur une source absente aurait fait échouer tout
le script (`returncode != 0`), cassant `test_on_skips_transport_dropin_when_one_already_exists`
qui exige `r.returncode == 0`.

**Décision retenue** : au lieu de contourner la sémantique de `_reload`
(réservée aux actions systemctl/nft/sysctl selon le brief), j'ai introduit un
troisième garde-fou dédié aux copies de templates, `_install_tpl(src, dst)` :

```bash
_install_tpl() {
  local src="$1" dst="$2"
  if [ -f "$src" ]; then
    cp "$src" "$dst"
  elif [ "$DRYRUN" = "1" ]; then
    :
  else
    echo "template manquant: $src" >&2
    return 1
  fi
}
```

- Hors dry-run (production réelle, paquet installé) : un template manquant
  sous `$SHARE` est une vraie erreur de packaging → le script échoue bruyamment
  (comportement inchangé par rapport au brief).
- En dry-run (`TORCTL_DRYRUN=1`, utilisé uniquement par les tests) : l'absence
  de la source est tolérée silencieusement — la seule chose sous test est le
  comportement observable demandé par le brief (présence/absence du dropin
  `60-secubox-transparent.conf` selon détection de `TransPort` existant, et
  non-suppression des fichiers d'un autre paquet par `off`), pas l'exécution
  réelle d'une copie de template qui n'a pas de sens hors paquet installé.

Je n'ai pas introduit de variable d'env `TORCTL_SHARE_D` : ni le brief ni les
tests fournis n'en définissent une, et cela aurait ajouté une surface non
testée. `SHARE` reste donc le chemin de production unique
`/usr/share/secubox/tor` (cohérent avec `socks_lan_ensure`, déjà en place
depuis Task 1).

## Invariants vérifiés

1. **Coordination de ports** — `transport_already_declared()` grep les
   `*.conf` de `$TORRC_D` pour `TransPort 127.0.0.1:9040` ; si un dropin
   externe (ex. `torrc-toolbox-egress.conf`) le déclare déjà, `60-secubox-transparent.conf`
   n'est jamais posé (`test_on_skips_transport_dropin_when_one_already_exists`).
2. **`off` ne retire que nos 3 fichiers** — `rm -f` cible nommément
   `60-secubox-transparent.conf` / `secubox-onion-forward.conf` /
   `secubox-tor-transparent.nft`, jamais un glob ; le dropin d'un autre
   paquet (`torrc-toolbox-egress.conf`) est préservé
   (`test_off_removes_only_our_files`).
3. **Dry-run** — `_reload()` court-circuite `sysctl`/`systemctl`/`nft` ;
   `_install_tpl()` tolère l'absence de `$SHARE` en dry-run (cf. ci-dessus).
4. **nft scope strict** — `nft.d/secubox-tor-transparent.nft` : table isolée
   `inet secubox-tor-transparent`, chaîne `prerouting` hook `dstnat`,
   `iifname { "wg-toolbox", "eth2" }`, `ip daddr 10.192.0.0/10` uniquement,
   DNAT explicite vers `127.0.0.1:9040` (pas de `redirect`, cf. note du
   brief sur `route_localnet=1`).
5. **Unbound** — `secubox-onion-forward.conf` contient bien
   `private-domain: "onion."` (anti-strip du range automap privé) et
   `forward-zone: name: "onion." forward-addr: 127.0.0.1@9053`.

## Non-régression manuelle

```
$ bash sbin/torctl
usage: torctl {detect-lan-ip|socks-lan ensure|transparent {on|off|status}}
rc=2

$ bash sbin/torctl detect-lan-ip
sbin/torctl: ligne 11: /usr/sbin/tor-lan-ip: Aucun fichier ou dossier de ce nom
rc=127   # inchangé — /usr/sbin/tor-lan-ip non installé sur cette machine dev,
         # pas une régression introduite par ce patch.
```

`socks-lan ensure` non exercé manuellement (dépend de `tor-lan-ip` non
installé ici) mais son code n'a pas été touché — seule la déclaration de
`TORRC_D`/`SHARE` en amont a changé de forme (valeur par défaut identique via
`${TORCTL_TORRC_D:-/etc/tor/torrc.d}`), sans impact fonctionnel.

## Concerns

- Un IDE-linter a signalé `UNBOUND_D`/`NFT_D` comme "unused" en ligne 7-8 ;
  faux positif — les deux variables sont utilisées dans
  `transparent_on`/`transparent_off`/`transparent_status` plus bas dans le
  fichier (vérifié par grep).
- `debian/rules` (override_dh_auto_install) ne copie actuellement AUCUN
  fichier de `conf/` ni `nft.d/` vers `/usr/share/secubox/tor` (pas plus pour
  les templates Task 1 que pour ceux de cette tâche) — le packaging Debian de
  ces trois nouveaux templates reste à faire dans une tâche ultérieure du
  plan (probablement la tâche de packaging/postinst, Task 8 mentionnée dans
  le brief pour `route_localnet`). Signalé mais hors périmètre de Task 2 qui
  ne demandait que le code + tests TDD.
- `packages/secubox-tor/api/main.py` référence déjà un
  `ONION_FORWARD_ZONE = /etc/unbound/unbound.conf.d/48-secubox-onion.conf`
  (Task 6, préexistant sur cette branche) — nom de fichier différent de
  `secubox-onion-forward.conf` posé par `torctl transparent on`. Les deux
  coexistent sans collision de test, mais une réconciliation de nommage
  sera probablement nécessaire dans une tâche future pour que
  `GET /onion_dns` observe le bon chemin. Non modifié ici (hors périmètre
  du brief Task 2, qui fixe explicitement le nom `secubox-onion-forward.conf`).

## Fix Important — SHARE surchargeable

**Constat de la revue (confirmé par mutation)** : `SHARE=/usr/share/secubox/tor`
était codée en dur dans `sbin/torctl`. En environnement de test,
`/usr/share/secubox/tor` n'existe jamais (paquet non installé) ; `_install_tpl`
tolère alors silencieusement l'absence de source en dry-run, donc **aucun**
`cp` de template n'était jamais réellement exercé par les tests — y compris
`60-secubox-transparent.conf`, qui n'était donc jamais créé, que le dropin
toolbox soit présent ou non. `test_on_skips_transport_dropin_when_one_already_exists`
passait pour la mauvaise raison (absence de source, pas logique de
déduplication `TransPort`) et ne discriminait pas les deux branches du `if`.
L'invariant de sécurité « pas de double déclaration `TransPort 9040` » n'avait
donc aucun filet automatisé réel.

### Correctifs appliqués

1. **`sbin/torctl`** — `SHARE` devient surchargeable :
   ```bash
   SHARE="${TORCTL_SHARE_D:-/usr/share/secubox/tor}"
   ```
   Comportement de production (`TORCTL_DRYRUN=0`, `TORCTL_SHARE_D` non défini)
   inchangé : chemin `/usr/share/secubox/tor` par défaut, `_install_tpl` échoue
   toujours bruyamment (`echo "template manquant: …" >&2; return 1`) si un
   template source manque — vérifié manuellement :
   ```
   $ TORCTL_SHARE_D=/nonexistent-share TORCTL_DRYRUN=0 bash sbin/torctl transparent on
   template manquant: /nonexistent-share/60-secubox-transparent.conf
   rc=1
   ```
   `detect-lan-ip` et `socks-lan ensure` non affectés (SHARE toujours résolu
   avant tout usage, seule la source de la valeur par défaut change de forme).
   `chmod +x` (755) conservé.

2. **`tests/test_torctl_transparent.py`** — réécrit pour être réellement
   discriminant :
   - `_make_share(tmp_path)` : crée un répertoire share temporaire et y copie
     (à plat, comme le fait le packaging) les 3 VRAIS templates du dépôt :
     `conf/torrc.d/60-secubox-transparent.conf`,
     `conf/unbound/secubox-onion-forward.conf`, `nft.d/secubox-tor-transparent.nft`.
   - `TORCTL_SHARE_D=<share>` ajouté à l'`env` du subprocess dans tous les
     tests, en plus de `TORCTL_TORRC_D/UNBOUND_D/NFT_D/DRYRUN=1` déjà présents.
     `TORCTL_DRYRUN=1` reste actif pour court-circuiter les reload
     `systemctl`/`nft`/`sysctl`, mais les `cp` de templates s'exécutent
     désormais réellement (source présente).
   - `test_on_skips_transport_dropin_when_one_already_exists` : renforcé —
     vérifie maintenant en plus que les templates unbound/nft sont bien posés
     (preuve que la copie a réellement eu lieu, pas juste tolérée en absence
     de source).
   - **Nouveau test** `test_on_installs_transport_dropin_when_none_exists` :
     sans dropin toolbox préexistant → `60-secubox-transparent.conf` DOIT être
     créé avec le contenu attendu. C'est le cas positif qui manquait pour
     prouver la discrimination réelle des deux branches.
   - **Nouveau test** `test_detects_transport_bound_without_ip` (durcissement
     point 3) : `TransPort 9040` sans IP explicite doit aussi être détecté
     comme déjà déclaré.

3. **Durcissement `transport_already_declared`** — regex élargie pour matcher
   `TransPort` sur le port 9040 quelle que soit l'adresse de bind, ancrée
   début de ligne :
   ```bash
   grep -rqiE '^[[:space:]]*TransPort[[:space:]]+([0-9.]+:)?9040\b' "$TORRC_D"/*.conf 2>/dev/null
   ```

### TDD — preuve du red → green

**AVANT le fix SHARE** (nouveaux tests ajoutés, `SHARE` encore codée en dur) :
```
FAILED tests/test_torctl_transparent.py::test_on_skips_transport_dropin_when_one_already_exists
  AssertionError: assert False
   +  where False = exists()
   +    where exists = ((.../u) / 'secubox-onion-forward.conf').exists
FAILED tests/test_torctl_transparent.py::test_on_installs_transport_dropin_when_none_exists
  AssertionError: sans TransPort préexistant, torctl DOIT poser son propre dropin
2 failed, 2 passed in 0.09s
```

**APRÈS le fix SHARE** (commande demandée) :
```
$ cd packages/secubox-tor && python3 -m pytest tests/test_torctl_transparent.py tests/test_onion_forward.py tests/test_nft_transparent.py -q
......                                                                   [100%]
6 passed in 0.08s
```

Suite complète du paquet (non-régression) :
```
$ cd packages/secubox-tor && python3 -m pytest tests/ -q
..........................                                               [100%]
26 passed, 1 warning in 0.65s
```

### Concerns

- Le point signalé dans « Concerns » ci-dessus (packaging `debian/rules` ne
  copie encore aucun fichier vers `/usr/share/secubox/tor`) reste
  d'actualité — hors périmètre de ce fix, qui ne portait que sur la
  surchargeabilité de `SHARE` et la discrimination réelle des tests.
- Le durcissement regex du point 3 n'a pas été demandé comme bloquant par la
  revue mais est appliqué « tant qu'on y est » comme précisé dans la
  consigne ; testé isolément par `test_detects_transport_bound_without_ip`.
