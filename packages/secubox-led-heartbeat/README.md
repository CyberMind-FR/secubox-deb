<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
# secubox-led-heartbeat

SecuBox LED heartbeat status indicator.

Visual system health indicator using MOCHAbin RGB LEDs.

Displays system health, security status, and resource usage via the IS31FL3199 I2C LED controller (3 RGB LEDs).

Depuis 2.3.0, l'affichage est un moteur en couches (`secubox-led-pulse`), voir plus bas.

Paquet Debian : version `2.3.3-1~trixie1`, architecture `all`.

## Contenu

- `boot/` : fichiers du module
- `etc/` : fichiers du module
- `kmod/` : fichiers du module
- `systemd/` : unités systemd
- `usr/` : fichiers du module

## Exécution

- `secubox-led-pulse.service` : **moteur d'affichage en couches**, seul écrivain des LED (activé par le postinst)
- `secubox-healthbump.service` (désactivé depuis 2.3.0) : SecuBox HealthBump LED Status Check (3-tier with I2C safety), lance `secubox-healthbump`
- `secubox-healthbump.timer` : SecuBox HealthBump LED Timer (every 30 seconds)
- `secubox-led-heartbeat.service` : SecuBox LED Heartbeat Status Indicator (utilisateur `root`), lance `secubox-led-heartbeat`
- `secubox-led-trigger.service` (désactivé depuis 2.3.0) : SecuBox LED Timer Triggers Setup, lance `secubox-led-trigger`
- `secubox-leds.service` : SecuBox LED Configuration, lance `modprobe`

## Dépendances SecuBox

`secubox-core`.

## Pilote des LED par DKMS (#3290)

Le noyau Debian stock (6.12.x) n'active pas `CONFIG_LEDS_IS31FL319X`. Le paquet livre les
sources du pilote (`kmod/`, référence Linux v6.12.107) dans `/usr/src/secubox-leds-<version>/`
avec un `dkms.conf` (`AUTOINSTALL=yes` : reconstruit à chaque nouveau noyau).

- `secubox-led-dkms install|remove <version>`, appelé par le postinst/prerm : `dkms add`,
  `build`, `install`, puis `modprobe leds-is31fl319x` sans redémarrage.
- **MOCHAbin seulement** (`secubox-led-board`) et jamais quand le bus I²C est neutralisé
  (`blacklist i2c_mv64xxx` ou `install i2c_mv64xxx /bin/false` dans `/etc`, `/run`, `/usr/lib`
  ou `/lib/modprobe.d/`, `modprobe.blacklist=` du noyau, ou `i2c-1` absent) : c'est le cas de **gk2**,
  où le paquet reste inerte (rien construit, rien chargé, aucune levée tentée).
- `dkms` et `linux-headers-arm64` sont en **Suggests** (ni Depends ni Recommends, qu'apt
  installerait par défaut, y compris sur gk2 et le rpi400) : sur un MOCHAbin avec LED, les
  installer explicitement (`apt-get install dkms linux-headers-arm64`, puis
  `dpkg-reconfigure secubox-led-heartbeat`). Leur absence donne ce message, pas un échec.
- Un échec de build ne fait jamais échouer `dpkg` (message, code 0 ; journal dans
  `/var/lib/dkms/secubox-leds/<version>/build/make.log`).
- Secure Boot : le module doit être signé par une clé MOK inscrite ; un message le rappelle,
  rien n'est contourné.
- Un noyau qui fournit déjà le pilote (in-tree) court-circuite DKMS ; un module déjà installé
  pour ce noyau et cette version n'est pas reconstruit ; il n'est retiré qu'à la désinstallation.
- Au démarrage, `secubox-leds.service` lance `secubox-led-dkms check` : avertissement dans le
  journal si la puce est présente sans module pour le noyau courant (noyau installé sans en-têtes).
- Les variables `SECUBOX_*` du script ne servent qu'aux tests (`SECUBOX_TEST=1`, hors root).

Chargement au démarrage : `modules-load.d/secubox-leds.conf`, puis `secubox-leds.service`
(`After=systemd-modules-load.service`) pour le cycle unbind/bind.

### Délai entre écritures I²C (`write_delay_us`)

En mai 2026, sur 6.12.85, le contrôleur `mv64xxx` se bloquait (`mv64xxx_i2c_fsm: Ctlr Error`)
après des écritures LED rapides ; seul un redémarrage le rendait. Contournement retenu : 1 ms
après chaque écriture du pilote. Paramètre de module `write_delay_us` (µs, 0..100000, défaut 1000,
0 = pilote amont) : `modprobe leds-is31fl319x write_delay_us=2000` ou
`/sys/module/leds_is31fl319x/parameters/write_delay_us`.

## Moteur d'affichage en couches (#3290, tranche 2)

`secubox-led-pulse` (unité `secubox-led-pulse.service`, code dans
`/usr/lib/secubox-led-heartbeat/ledcouches.py`) affiche une **liste ordonnée de couches**
lue dans `/etc/secubox/leds.toml`. Il remplace l'ancien démon shell du même nom ;
`secubox-healthbump.timer`, `secubox-led-trigger` et `secubox-led-heartbeat`, qui écrivaient
les mêmes canaux, sont désactivés par le postinst (fichiers conservés pour un retour arrière ;
l'unité porte `Conflicts=` avec eux).

### Grammaire visuelle (décisions du propriétaire, 2026-10-30)

| Forme | Lecture |
|---|---|
| `par_led` | une mesure par LED (3 sources : LED 1, 2, 3) |
| `jauge` | niveau = nombre de LEDs allumées (niveau 0 : LED 1 faible) |
| `mono` / `double` / `triple` | une mesure portée par 1, 2 ou 3 LEDs ensemble (`leds = [..]` pour choisir) |
| `etale` | la séquence du rythme répartie dans le temps sur les trois LEDs (déphasage d'un tiers) |
| `rotatif` | une LED qui défile 1→2→3→2, d'autant plus vite que le niveau est haut |
| couches `mono` consécutives | groupe rotatif : fenêtre de trois couches qui glisse d'une couche à chaque `duree` (plus de trois couches sans limite fixe) |

Rythmes : `fixe` ; `respiration` (rampe à 3 paliers, période 6 s) ; `pulsation`
(fréquence proportionnelle au niveau, période 3 s / niveau) ; `eclats` (N éclats = niveau).
La couleur porte le niveau 0..3 (`palette`, 4 couleurs) ; le rythme le redouble pour une
lecture sans les couleurs. **Inconnu** (source absente, illisible ou périmée) : gris-bleu faible
fixe, jamais vert. Avant chaque couche, un **repère** : N éclats blancs sur la LED 2 (N = rang
de la couche, 3 au plus), LEDs 1 et 3 éteintes.

Défaut livré : couche `systeme` (CPU, mémoire, E/S ; vert → jaune → orange → rouge ;
respiration ; 8 s) puis couche `trafic` (attaques, visites, alertes ; cyan → bleu → violet →
rose ; pulsations ; 8 s).

### Sources (locales, lecture seule, sans réseau ni secret)

| Source | Type | Origine | Seuils (niveaux 1, 2, 3) |
|---|---|---|---|
| `cpu` | `cpu` | `/proc/stat` (delta, hors idle et iowait) | 50 / 75 / 90 % |
| `memoire` | `memoire` | `/proc/meminfo` (100 − MemAvailable/MemTotal) | 60 / 80 / 92 % |
| `es` | `iowait` | `/proc/stat` (part iowait) | 5 / 15 / 30 % |
| `attaques` | `compteur_json` | `/var/cache/secubox/metrics-cache.json`, `waf.waf_blocked` (débit par minute) | 1 / 10 / 60 par min |
| `visites` | `jauge_json` | même cache, `connections.https` (connexions établies) | 1 / 20 / 100 |
| `alertes` | `alertes_json` | `/var/lib/secubox/soc/alerts.json` (non acquittées ; une critique = 3) | 1 / 3 / 10 |

Le cache `metrics-cache.json` est rafraîchi par `secubox-metrics` (30 s) ; au-delà de
`fraicheur_max` (300 s) la source passe à « inconnu » (horodatage interne `timestamp_epoch`
prioritaire sur la date du fichier). Les alertes : fraîcheur d'un jour (le SOC n'écrit qu'au
changement) et socket `/run/secubox/soc.sock` absente (SOC arrêté) = inconnu. Aucun journal relu.

Fichiers d'état lus par le démon root : sans suivre de lien ni bloquer (`O_NOFOLLOW|O_NONBLOCK`),
fichier régulier, propriétaire dans `proprietaires` (défaut : `root`, `secubox` — compte de
secubox-metrics et du SOC —, `secubox-metrics`, `secubox-soc`), non inscriptible par tous,
1 Mio au plus. JSON piégé (NaN, Inf, profondeur, types) = inconnu. Le profil AppArmor
`secubox-led-pulse` (enforce) n'autorise que les chemins par défaut : une source ajoutée
ailleurs reste « inconnue » tant que le profil n'est pas complété.

### Réglages (`[moteur]`)

`debit_max` (écritures I²C/s, tous canaux, défaut 20, 50 au plus ; 10 ms minimum entre deux), `luminosite` (0.05..1, défaut 0.6),
`pas` (image, 0.1 s), `repere_duree` (1.2 s), `periode_mesure` (5 s), `reprise_auto`.
`[couleurs]` surcharge ou ajoute des couleurs (palette validée : orange 255/80/0, jaune
255/200/0, violet 150/0/255, rose 255/20/120, cyan 0/220/255, turquoise 0/255/90, blanc chaud
255/150/60, blanc, rouge, vert, bleu). `[sources.<nom>]` : `type`, `chemin`, `cle`, `seuils`,
`fraicheur_max`. `[[couche]]` : `nom`, `sources`, `forme`, `palette`, `rythme`, `periode`,
`duree`, `leds`. Toute valeur invalide (bornes ou type) est remplacée par son défaut avec un avertissement
dans le journal ; un fichier illisible ou sans couche donne la configuration livrée.
`leds.toml` doit être root:root non inscriptible par d'autres (le postinst le fixe en 0644),
sinon le démon l'ignore.

### Bus I²C

Images calculées en mémoire ; un canal n'est écrit **que si sa valeur change** ; seau à
jetons de `debit_max` écritures/s, en tourniquet (aucun canal affamé). Le pilote
`leds-is31fl319x` n'expose pas les rampes matérielles de la puce : la respiration est
logicielle, à 3 paliers (mesuré en simulation : 3 à 9 écritures/s selon la forme).
Au démarrage, les déclencheurs noyau (`heartbeat`, `timer`) des 9 canaux sont retirés.
À l'arrêt (SIGTERM), les 9 canaux sont mis à 0, à 50 ms d'intervalle. Après 3 erreurs
d'écriture consécutives, le démon sort en 75 : `OnFailure=` lance `secubox-led-reprise.service`
(`secubox-led-reset`, au plus une fois par 10 min), qui recharge le module et relance le moteur.
Unité sans capacité, profil AppArmor enforce ; exception root écrite dans `RULES-CODE.md` § 10.

### Démonstration et vérification

```
secubox-led verifier                         # valide leds.toml, affiche les niveaux courants
secubox-led demo <forme> [--duree 20]        # niveaux 0, 1, 2, 3 puis inconnu, chacun duree/5
secubox-led demo triple --niveau 2 --rythme respiration
secubox-led demo systeme|trafic|toutes       # couches réelles de leds.toml
secubox-led-pulse demo rotatif --simule      # sans matériel : écritures sur la sortie
```

La démo arrête `secubox-led-pulse` le temps de l'affichage puis le relance, y compris si elle
est interrompue (fermeture SSH, Ctrl-C) ; si l'arrêt échoue, la démo est annulée (un seul écrivain).
