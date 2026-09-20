# Debian 13 (Trixie)

> Les images **Trixie** sont publiées depuis `v3.0.0-alpha.4`, pour la **VM
> x86_64** et le **Raspberry Pi 4 / 400**. Les autres cibles — Live USB,
> installeur, MOCHAbin — restent sur bookworm (12) pour l'instant.

## Ce qui change par rapport à bookworm

| | bookworm (12) | trixie (13) |
|---|---|---|
| Noyau | 6.6 LTS | 6.12 |
| Cibles publiées | Live USB, installeur, MOCHAbin | **VM x64, Raspberry Pi 4/400** |
| Profils | `isp` · `full` | `isp` · `full` |

## Les profils filtrent réellement

Jusqu'à l'alpha 4, `isp` et `full` produisaient la **même image** : le script de
construction installait tous les `.deb` trouvés, le profil ne servant qu'à
nommer le fichier. Deux artefacts d'un même run ne différaient que de 27 Ko sur
676 Mo — le bruit des horodatages.

Le profil suit désormais les dépendances de son méta-paquet et ne retient que
les modules atteignables :

| profil | modules |
|---|---|
| `lite` | 9 |
| `isp` | 39 |
| `full` | 58 |

Un profil peut aussi être **composé à la main** : au lieu d'un nom, on passe un
fichier listant les modules voulus, un par ligne. La fermeture transitive des
dépendances fait le reste, et un module inconnu échoue au lieu d'être ignoré.

## Mémoire : zram et plafond collectif

Les images Trixie embarquent **zram** (`zram-size = ram`, zstd) et placent tous
les modules SecuBox sous une slice systemd plafonnée :

```
secubox.slice   MemoryHigh = 60 %   MemoryMax = 75 %
```

Les bornes sont en **pourcentage**, résolues au démarrage : la même image se
borne correctement sur un Raspberry Pi 400 à 4 Go comme sur une VM à 16.

Ce plafond n'est pas cosmétique. Sans lui, l'épuisement mémoire frappait la
machine entière : le noyau répondait au ping, `sshd` acceptait le TCP — mais
plus aucun `fork()` n'aboutissait, et un shell console se figeait à la première
commande. Avec la slice, la pression reste **confinée** : on perd un module, pas
la machine.

## Cycle de vie des modules

Au **premier démarrage**, `secubox-profilectl scan` dérive un manifeste par
module dans `/etc/secubox/modules.d/`, puis le *sleeper* est activé. Les modules
déclarés `on-demand` s'endorment après inactivité et se réveillent sur requête
réelle, via les signaux de vhost émis par `sbxwaf`.

La dérivation exige `root`, un systemd vivant et `lxc-ls` — d'où son exécution
au premier démarrage plutôt qu'à la construction, où elle produirait un
inventaire faux.

Une politique par défaut est livrée dans
`/usr/share/secubox/lifecycle-defaults.toml` ; une copie dans `/etc/secubox/`
la remplace. Un module absent de la politique reste `always-on` : ne rien
savoir ne justifie jamais d'endormir.

## Moteur DPI

`secubox-ndpid-engine` embarque **nDPI 6.x en statique** et fournit
`/usr/sbin/nDPId` et `nDPIsrvd`. Il est désormais construit par la CI pour
**amd64 et arm64** — l'arm64 en compilation native émulée, parce que le
`debian/rules` du paquet appelle `cmake` directement, sans chaîne croisée : une
construction croisée aurait produit des binaires amd64 sous une étiquette
arm64.

`secubox-dpi` en dépend désormais durement. En `Recommends`, il n'arrivait dans
aucune image, la construction installant avec `--no-install-recommends`.

## Vérifier une image

```bash
sha256sum -c SHA256SUMS --ignore-missing
```

Une fois démarrée, les points à contrôler :

```bash
swapon --show                      # /dev/zram0 doit apparaître
systemctl show secubox.slice -p MemoryCurrent -p MemoryMax
systemctl --failed                 # attendu : vide
ls /etc/secubox/modules.d/*.toml | wc -l
systemctl is-active secubox-sleeper
```

## Limites connues

- Le provisionnement de certains conteneurs LXC demande que `/data` soit
  monté — c'est le cas sur les images, pas nécessairement sur une installation
  manuelle.
- Les images ESPRESSObin ne sont pas publiées : à construire depuis les
  sources (**[[Building]]**).

Voir aussi **[[Installation]]** · **[[ARM-Installation]]** · **[[Building]]**
