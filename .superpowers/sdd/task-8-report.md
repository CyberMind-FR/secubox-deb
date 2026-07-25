# Task 8 — Packaging (secubox-tor, secubox-proxypac) — Report

## Résumé

Les deux paquets `.deb` (arch:all) ont été construits avec succès, tous les
artefacts des tâches 1-7 sont installés, les invariants (DEBHELPER seul,
templates aplatis, conffile, sudoers scopé 0440, pas de chown de parent
partagé) sont respectés.

## Fichiers modifiés / créés

- `packages/secubox-tor/debian/rules` — installe `tor-lan-ip`, `torctl`,
  les 4 templates aplatis sous `/usr/share/secubox/tor/`, et le dropin
  sysctl reboot-persistant.
- `packages/secubox-tor/debian/postinst` — `sysctl --system || true` +
  `torctl socks-lan ensure || true` + `torctl transparent on || true`
  (dans le bloc `configure`, avant `#DEBHELPER#`).
- `packages/secubox-tor/debian/control` — Depends += `tor, unbound, nftables`.
- `packages/secubox-tor/debian/changelog` — nouvelle entrée `1.1.1-1~bookworm1`.
- `packages/secubox-tor/debian/secubox-tor-route-localnet.sysctl` (créé) —
  source du dropin `/etc/sysctl.d/60-secubox-route-localnet.conf`
  (`net.ipv4.conf.all.route_localnet=1`), pour que les ifaces recréées au
  boot (wg-toolbox) héritent du réglage que `torctl` pose déjà en live
  par-iface à `transparent on`.
- `packages/secubox-proxypac/debian/rules` — installe `conf/proxypac.toml`
  (conffile), `sbin/proxypac-wpad`, `debian/secubox-proxypac.sudoers`.
- `packages/secubox-proxypac/debian/postinst` — `proxypac-wpad apply || true`
  ajouté après la génération PAC existante (avant `#DEBHELPER#`).
- `packages/secubox-proxypac/debian/control` — Depends += `secubox-tor`.
- `packages/secubox-proxypac/debian/changelog` — nouvelle entrée `1.2.0-1~bookworm1`.
- `packages/secubox-proxypac/debian/secubox-proxypac.sudoers` (créé) —
  `secubox ALL=(root) NOPASSWD: /usr/sbin/proxypac-wpad apply, /usr/sbin/proxypac-wpad state, /usr/sbin/torctl transparent on, /usr/sbin/torctl transparent off`
  (mode 0440, validé `visudo -cf` → "analyse réussie").

## Diff (résumé)

```diff
diff --git a/packages/secubox-proxypac/debian/changelog b/packages/secubox-proxypac/debian/changelog
+secubox-proxypac (1.2.0-1~bookworm1) bookworm; urgency=medium
+  * Package proxypac.toml (conffile) + proxypac-wpad ctl + scoped sudoers
+    (proxypac-wpad apply|state, torctl transparent on|off); postinst applies
+    the WPAD tier at configure time.
+  * Depends: secubox-tor (provides tor-lan-ip/torctl consumed by proxypac-wpad).
+ -- Gerald KERMA <devel@cybermind.fr>  Fri, 24 Jul 2026 09:00:00 +0200

diff --git a/packages/secubox-proxypac/debian/control b/packages/secubox-proxypac/debian/control
-Depends: ${misc:Depends}, python3, python3-fastapi, python3-uvicorn, secubox-core, secubox-hub, nginx
+Depends: ${misc:Depends}, python3, python3-fastapi, python3-uvicorn, secubox-core, secubox-hub, secubox-tor, nginx

diff --git a/packages/secubox-proxypac/debian/postinst b/packages/secubox-proxypac/debian/postinst
     nginx -t && systemctl reload nginx || true
+    /usr/sbin/proxypac-wpad apply || true
 fi
 #DEBHELPER#

diff --git a/packages/secubox-proxypac/debian/rules b/packages/secubox-proxypac/debian/rules
+
+	install -D -m 644 conf/proxypac.toml debian/secubox-proxypac/etc/secubox/proxypac/proxypac.toml
+	install -D -m 755 sbin/proxypac-wpad debian/secubox-proxypac/usr/sbin/proxypac-wpad
+	install -D -m 440 debian/secubox-proxypac.sudoers debian/secubox-proxypac/etc/sudoers.d/secubox-proxypac

diff --git a/packages/secubox-tor/debian/changelog b/packages/secubox-tor/debian/changelog
+secubox-tor (1.1.1-1~bookworm1) bookworm; urgency=medium
+  * Package tor-lan-ip/torctl helpers + share templates (socks-lan, transparent,
+    onion-forward, nft) under /usr/share/secubox/tor/; postinst wires
+    `torctl socks-lan ensure` + `torctl transparent on` (idempotent, best-effort).
+  * Depends: tor, unbound, nftables.
+  * Ship /etc/sysctl.d/60-secubox-route-localnet.conf so ifaces recreated at
+    boot (wg-toolbox) inherit route_localnet=1 for the transparent DNAT.
+ -- Gerald KERMA <devel@cybermind.fr>  Fri, 24 Jul 2026 09:00:00 +0200

diff --git a/packages/secubox-tor/debian/control b/packages/secubox-tor/debian/control
-Depends: ${misc:Depends}, secubox-core (>= 1.0.0)
+Depends: ${misc:Depends}, secubox-core (>= 1.0.0), tor, unbound, nftables

diff --git a/packages/secubox-tor/debian/postinst b/packages/secubox-tor/debian/postinst
     systemctl start secubox-tor.service || true
+    sysctl --system || true
+    /usr/sbin/torctl socks-lan ensure || true
+    # transparent activé par défaut (aligné proxypac.toml transparent=true) ;
+    # idempotent, best-effort, réutilise le TransPort toolbox s'il existe.
+    /usr/sbin/torctl transparent on || true
 fi
 #DEBHELPER#
 exit 0

diff --git a/packages/secubox-tor/debian/rules b/packages/secubox-tor/debian/rules
+
+	# Helpers (torctl copies templates below from /usr/share/secubox/tor/)
+	install -D -m 755 sbin/tor-lan-ip debian/secubox-tor/usr/sbin/tor-lan-ip
+	install -D -m 755 sbin/torctl debian/secubox-tor/usr/sbin/torctl
+	install -d debian/secubox-tor/usr/share/secubox/tor
+	install -m 644 conf/torrc.d/50-secubox-socks-lan.conf conf/torrc.d/60-secubox-transparent.conf debian/secubox-tor/usr/share/secubox/tor/
+	install -m 644 conf/unbound/secubox-onion-forward.conf debian/secubox-tor/usr/share/secubox/tor/
+	install -m 644 nft.d/secubox-tor-transparent.nft debian/secubox-tor/usr/share/secubox/tor/
+
+	# route_localnet reboot-persistence: conf.all inherited by ifaces created
+	# after boot (wg-toolbox); torctl already sets it live per-iface at
+	# `transparent on` time, this dropin covers ifaces recreated later.
+	install -D -m 644 debian/secubox-tor-route-localnet.sysctl debian/secubox-tor/etc/sysctl.d/60-secubox-route-localnet.conf
```

## Vérifications

### bash -n + `#DEBHELPER#` seul sur sa ligne (source)

```
$ bash -n packages/secubox-tor/debian/postinst && echo "tor: OK"
tor: OK
$ bash -n packages/secubox-proxypac/debian/postinst && echo "proxypac: OK"
proxypac: OK
$ grep -n "^#DEBHELPER#$" packages/secubox-tor/debian/postinst
13:#DEBHELPER#
$ grep -n "^#DEBHELPER#$" packages/secubox-proxypac/debian/postinst
14:#DEBHELPER#
```

Vérifié aussi sur les postinst **construits** (après substitution dh) :
`bash -n` OK sur les deux, section `#DEBHELPER#` remplacée proprement par les
blocs `dh_installsystemd` — aucune ligne parasite, mon bloc `configure`
personnalisé reste intact et précède la section auto-générée.

### sudoers

```
$ visudo -cf packages/secubox-proxypac/debian/secubox-proxypac.sudoers
packages/secubox-proxypac/debian/secubox-proxypac.sudoers : analyse réussie
```

### Suites de tests (avant build)

```
$ cd packages/secubox-tor && python3 -m pytest -q tests/
26 passed, 1 warning in 0.71s

$ cd packages/secubox-proxypac && python3 -m pytest -q tests/
46 passed in 0.39s   # inclut tests/test_packaging.py
```

Aucune régression : les tests packaging existants (`test_rules_installs_all_artifacts`,
`test_postinst_enables_regen_and_seeds_rules`, `test_control_metadata`,
`test_no_conflicting_compat_file`) passent toujours après modification.

### Build

```
$ cd packages/secubox-tor && dpkg-buildpackage -us -uc -b 2>&1 | tail -3
dpkg-deb: construction du paquet « secubox-tor » dans « ../secubox-tor_1.1.1-1~bookworm1_all.deb ».
...
dpkg-buildpackage: info: envoi d'un binaire seulement (aucune inclusion de code source)

$ cd packages/secubox-proxypac && dpkg-buildpackage -us -uc -b 2>&1 | tail -3
dpkg-deb: construction du paquet « secubox-proxypac » dans « ../secubox-proxypac_1.2.0-1~bookworm1_all.deb ».
...
dpkg-buildpackage: info: envoi d'un binaire seulement (aucune inclusion de code source)
```

Les deux `.deb` construits sans erreur (build non-signé `-us -uc`, arch:all).

### `dpkg-deb -c` — présence des artefacts

`secubox-tor_1.1.1-1~bookworm1_all.deb` :
```
drwxr-xr-x root/root         0 ./etc/sysctl.d/
-rw-r--r-- root/root       475 ./etc/sysctl.d/60-secubox-route-localnet.conf
-rwxr-xr-x root/root      1037 ./usr/sbin/tor-lan-ip
-rwxr-xr-x root/root      3662 ./usr/sbin/torctl
drwxr-xr-x root/root         0 ./usr/share/secubox/tor/
-rw-r--r-- root/root       286 ./usr/share/secubox/tor/50-secubox-socks-lan.conf
-rw-r--r-- root/root       396 ./usr/share/secubox/tor/60-secubox-transparent.conf
-rw-r--r-- root/root       651 ./usr/share/secubox/tor/secubox-onion-forward.conf
-rw-r--r-- root/root       541 ./usr/share/secubox/tor/secubox-tor-transparent.nft
```

`secubox-proxypac_1.2.0-1~bookworm1_all.deb` :
```
-rw-r--r-- root/root       443 ./etc/secubox/proxypac/proxypac.toml
-r--r----- root/root       247 ./etc/sudoers.d/secubox-proxypac   (0440)
-rwxr-xr-x root/root      2001 ./usr/sbin/proxypac-wpad
-rw-r--r-- root/root       112 ./usr/share/secubox/menu.d/580-proxypac.json
```

### conffiles (auto-détectés par dh, tout ce qui est sous /etc)

- secubox-tor : `/etc/nginx/secubox.d/tor.conf`, `/etc/sysctl.d/60-secubox-route-localnet.conf`
- secubox-proxypac : `/etc/nginx/secubox.d/proxypac.conf`, `/etc/nginx/sites-available/wpad-vhost.conf`,
  `/etc/secubox/proxypac/proxypac.toml` (conffile, comme requis), `/etc/secubox/proxypac/rules.d/00-onion.rules`,
  `/etc/sudoers.d/secubox-proxypac`

### Depends (paquets construits)

- `secubox-tor` : `secubox-core (>= 1.0.0), tor, unbound, nftables`
- `secubox-proxypac` : `python3, python3-fastapi, python3-uvicorn, secubox-core, secubox-hub, secubox-tor, nginx`

## Invariants respectés

1. `#DEBHELPER#` seul sur sa ligne dans les deux postinst (source ET construit) — vérifié.
2. Templates aplatis dans `/usr/share/secubox/tor/` (pas d'installation directe
   de `50-secubox-socks-lan.conf` dans `/etc/tor/torrc.d`) — `torctl` s'en charge
   à l'exécution (`socks-lan ensure` / `transparent on`).
3. postinst secubox-tor : `torctl socks-lan ensure || true` puis
   `torctl transparent on || true`, idempotent (le script détecte un TransPort
   9040 déjà déclaré par le toolbox et ne duplique pas le dropin).
4. Dropin `/etc/sysctl.d/60-secubox-route-localnet.conf` (conf.all) livré +
   `sysctl --system || true` dans le postinst, en complément du réglage live
   par-iface que fait déjà `torctl transparent on`.
5. `proxypac.toml` sous `/etc/secubox/proxypac/proxypac.toml` — conffile
   automatique (dh traite tout `/etc/*` comme conffile), jamais écrasé de force.
6. Sudoers scopé aux 4 commandes exactes demandées, mode 0440, `visudo -cf` OK.
7. Aucun chown/chmod de parent partagé ajouté (`/run/secubox`, `/etc/secubox`,
   `/var/log/secubox` non touchés par ce changement).
8. Depends croisées ajoutées dans les deux `control`.
9. Changelogs : `secubox-tor` 1.1.1-1~bookworm1 (tête 1.1.0-1~bookworm2 + 1),
   `secubox-proxypac` 1.2.0-1~bookworm1 (tête 1.1.0-1~bookworm2), date
   `Fri, 24 Jul 2026`, signature `Gerald KERMA <devel@cybermind.fr>`.

## Commit

Voir hash dans le message de clôture de la tâche (rapporté séparément).
Message : "build(proxypac,tor): packaging — dropins, sudoers scopé, postinst
wiring (socks-lan+transparent+wpad), changelogs".

## Préoccupations / notes

- Le postinst de `secubox-tor` active `transparent on` par défaut à
  l'installation (intentionnel selon le brief — aligné `proxypac.toml
  transparent=true`) : sur un board où le toolbox n'a pas encore de TransPort
  9040 déclaré, ce postinst pose immédiatement le dropin nft
  `secubox-tor-transparent` sur `wg-toolbox`+`eth2`. `eth2` reste en dur
  (limitation connue, documentée dans le brief, hors périmètre de cette tâche).
- `sudo -n` utilisé côté API (`api/main.py`) correspond exactement aux 4
  entrées sudoers livrées — pas de dérive de commande observée.
- Build effectué en environnement de dev (amd64), `Architecture: all` donc
  portable ; pas de dépendance de build manquante rencontrée.

## Fix revue finale

Corrections apportées suite à la revue finale de branche
`feat/proxypac-wpad-autodetect` (findings #1 à #5).

### #1 (IMPORTANT) — override `role` de proxypac.toml inerte

`sbin/proxypac-wpad` : `role()` ignorait totalement le champ `role` de
`proxypac.toml` (auto|master|slave|off) — seul `WPAD_ROLE` (test) puis la
détection auto étaient consultés. Corrigé : après `WPAD_ROLE` (priorité
conservée pour les tests), le heredoc python charge désormais
`proxypac.config.load(WPAD_CONFIG)` (nouvelle variable d'env, défaut
`/etc/secubox/proxypac/proxypac.toml`) et mappe l'override :

- `master` → `master` (court-circuite la détection)
- `off` → `off` (no-op réseau, catch-all `*)` de `apply()` — vérifié, déjà
  correct, juste reformulé en commentaire)
- `slave` → force non-master : `slave-dns` si `role.detect()` voit un
  résolveur DNS, sinon `slave`
- `auto`/absent/inconnu → détection complète actuelle (tier→master/slave-dns/slave)

Résolution du chemin Python : `sys.path` reçoit d'abord
`/usr/lib/secubox/proxypac` (prod) puis, en priorité (insert index 0), la
racine du paquet dérivée de `dirname` du script (`sbin/..`) — un seul
heredoc résout donc `from proxypac.config import load` aussi bien en test
qu'en prod installé, sans dupliquer de logique de chemin.

Test ajouté (`tests/test_wpad.py::test_toml_role_master_override_forces_master`) :
role=master dans un toml temporaire, PAS de `WPAD_ROLE`, aucun signal DHCP
réel dans l'environnement de test → doit quand même produire le dropin
dnsmasq. Confirmé RED avant fix (`AssertionError: role=master du toml doit
forcer l'échelon master`), GREEN après (5 passed dans `test_wpad.py`).

### #3 (MINEUR) — coordination TransPort suppose DNSPort présent

`sbin/torctl` `transport_already_declared()` ne testait que `TransPort 9040`.
Durci : "déjà déclaré" exige maintenant `TransPort 9040` **ET** `DNSPort
9053` tous les deux présents dans `$TORRC_D/*.conf` (regex ancré début de
ligne, port-agnostique sur l'adresse, inchangé). Si un seul des deux existe,
notre dropin `60-secubox-transparent.conf` (qui déclare les deux) est posé —
évite qu'Unbound forwarde vers un DNSPort mort. Message adapté ("TransPort
9040 + DNSPort 9053 déjà déclarés"). Les fixtures existantes
(`test_on_skips_transport_dropin_when_one_already_exists`,
`test_detects_transport_bound_without_ip`) posaient déjà les deux ports —
inchangées, toujours vertes. Nouveau test
`test_on_installs_dropin_when_transport_exists_but_dnsport_missing` : TransPort
seul (sans DNSPort) → notre dropin EST posé.

### #4 (MINEUR) — NoNewPrivileges=true bloque la délégation sudo (unité fallback)

`systemd/secubox-proxypac.service` (unité standalone fallback, pas le chemin
live via aggregator) : `NoNewPrivileges=true` → `false`, avec commentaire
expliquant que l'API délègue root via `sudo -n` (torctl/proxypac-wpad) et que
NNP=true ferait échouer silencieusement `/transparent` et `/wpad/apply`
(`ok:false`). Aucun test n'assertait NNP=true sur cette unité (vérifié) —
pas de régression.

### #5 (MINEUR) — esc() manquant sur e.message

`www/proxypac/index.html`, chemin d'erreur `loadStatus` (~ligne 187) :
`e.message` injecté brut dans `innerHTML` — enveloppé dans `esc(...)` par
cohérence avec les autres handlers (`rules`, `candidates`). Cosmétique, non
exploitable (message vient de `fetch`/JSON local, pas d'entrée utilisateur
distante).

### #2 (MINEUR) — port de socks_endpoint ignoré par le SocksPort LAN

Option retenue : **commentaire documenté**, pas de modification du template
`50-secubox-socks-lan.conf` ni de `torctl`/`tor-lan-ip`. Raison : le chemin
d'exécution réel de `torctl socks-lan ensure` dépend de `lan_ip()` qui
invoque le binaire système absolu `/usr/sbin/tor-lan-ip` (pas de variable
d'env d'override, contrairement à `TORCTL_TORRC_D`/`TORCTL_SHARE_D`/etc.) —
ce chemin n'existe pas en environnement de dev/CI, donc toute modification
touchant `socks_lan_ensure` (dérivation du port + nouveau placeholder
`__SOCKS_PORT__` dans le template) n'aurait pu être vérifiée par un test
d'intégration réel sans ajouter un nouveau mécanisme de stub pour
`tor-lan-ip` — hors périmètre d'un correctif MINEUR et risque de sur-ingénierie
sur un template déjà testé (`test_socks_lan_dropin.py`). À la place :
`packages/secubox-proxypac/conf/proxypac.toml` documente désormais
explicitement que seul le port `:9050` est supporté pour le SocksPort LAN et
que `socks_endpoint` doit le conserver, tant que ce couplage dur persiste.
Si le besoin d'un port SOCKS LAN configurable devient réel, prévoir d'abord
une variable d'env de test pour `tor-lan-ip` dans `torctl` avant de toucher
au template.

### Suites de tests (après fix)

```console
$ cd packages/secubox-proxypac && python3 -m pytest tests/ -q
47 passed in 0.43s

$ cd packages/secubox-tor && python3 -m pytest tests/ -q
27 passed, 1 warning in 0.75s
```

### Fichiers modifiés

- `packages/secubox-proxypac/sbin/proxypac-wpad`
- `packages/secubox-proxypac/tests/test_wpad.py`
- `packages/secubox-proxypac/systemd/secubox-proxypac.service`
- `packages/secubox-proxypac/www/proxypac/index.html`
- `packages/secubox-proxypac/conf/proxypac.toml`
- `packages/secubox-tor/sbin/torctl`
- `packages/secubox-tor/tests/test_torctl_transparent.py`
