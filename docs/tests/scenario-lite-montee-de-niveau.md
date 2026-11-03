<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
<!-- Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr> -->

# Scénario : image lite puis montée de niveau isp (#3428)

Validation manuelle et reproductible du principe « une image par matériel, profil d'amorçage `lite`,
profil final installé depuis premier pas par apt ». À dérouler d'abord sur une VM `live-amd64`, puis sur
un Raspberry Pi (`rpi-arm64`, kiosque HDMI). Aucune box du parc n'est touchée.

## Matrice des images

| Image | Profil d'amorçage | Options |
|---|---|---|
| `live-amd64` (`build-live-usb.sh`) | lite | kiosque |
| `vm-x64` (`build-image.sh`) | lite | — |
| `rpi-arm64` (`build-rpi-usb.sh`) | lite | kiosque HDMI |
| `rpi4-dsi` (`build-rpi-usb.sh --rpi-dsi`) | lite | kiosque + écran DSI 7" |
| `mochabin` | lite | — |
| `espressobin-v7` | minimal | — |

## Préparation

1. Récupérer l'artefact CI `secubox-live-amd64-trixie` (ou construire :
   `sudo bash image/build-live-usb.sh --suite trixie --slipstream --kiosk --profile lite`).
2. Noter la taille : `ls -l secubox-live-amd64-trixie.img.gz` et taille décompressée.
3. VM : 2 vCPU, 4 Go de RAM, une carte réseau en NAT (accès à `apt.secubox.in`), démarrage UEFI sur l'image.

## 1. Démarrage lite

- [ ] Le menu de démarrage s'affiche, l'entrée par défaut démarre sans message noyau à l'écran.
- [ ] Console (tty1 ou kiosque) : l'écran premier pas indique l'adresse où continuer dans un navigateur.
- [ ] En SSH ou console de secours :

```bash
dpkg-query -W -f='${db:Status-Abbrev} ${Package}\n' 'secubox-*' | grep -c '^ii'   # nombre de paquets lite
dpkg -l secubox-lite secubox-isp secubox-full 2>&1 | grep -E '^(ii|un)|no packages'   # lite ii, isp/full absents
cat /etc/apt/sources.list.d/secubox.list                                            # source signée apt.secubox.in
systemctl --failed --no-legend | grep secubox                                       # rien
free -m                                                                              # RAM au repos lite (après 5 min)
```

## 2. Premier pas (console puis kiosque)

- [ ] Ouvrir l'adresse affichée (ou le kiosque) : l'assistant propose les profils de services
  « Garder les modules actuels », `lite`, `minimal`, `isp`, `full`… (lus dans `/usr/share/secubox/profiles/`).
- [ ] Renseigner nom, fuseau, mot de passe, réseau `lan`, puis choisir **isp**.
- [ ] Lancer l'application : l'étape « services » exécute
  `secubox-profilectl apply --profile isp --yes`, qui installe d'abord `secubox-isp` par apt
  (plusieurs minutes : ne pas interrompre, apt n'a pas de délai).
- [ ] L'assistant se termine sans avertissement.

## 3. Vérifications après montée

```bash
dpkg -l secubox-isp | grep '^ii'                                    # isp installé
grep -E 'profile_upgrade_(start|done|failed)' /var/log/secubox/audit.log   # start puis done
cat /etc/secubox/profiles/active                                    # isp
secubox-profilectl status | head -40                                # modules isp allumés (DPI, nDPId, toolbox…)
systemctl --failed --no-legend | grep secubox                       # rien
free -m                                                             # RAM au repos isp (après 5 min)
```

- [ ] Le Hall et la WebUI d'administration répondent ; le menu montre les entrées d'isp (DPI…).
- [ ] **Flotte** : si la box a rejoint un maillage, elle apparaît dans la page Flotte du maître
  (`/fleet/`) avec son nouveau profil (agent de pilotage, sortant seulement).
- [ ] **live.secubox.in** : la box exposée (si un vhost est déclaré) reste servie à travers HAProxy puis sbxwaf ;
  aucune route ajoutée à la main.

## 4. Sans réseau (comportement attendu)

Refaire l'étape 2 sur une image neuve avec la carte réseau débranchée (ou `nft` qui coupe la sortie) :

- [ ] `secubox-profilectl apply --profile isp --yes` rend le code **4** et écrit sur stderr :
  « secubox-isp n'a pas pu être installé (apt rc=…) … Rien n'a été changé : la box garde son profil actuel.
  Relancer une fois connecté : secubox-profilectl apply --profile isp --yes ».
- [ ] Premier pas affiche un **avertissement** à l'étape services et va jusqu'au bout (marqueur
  `/var/lib/secubox/.premier-pas-fait` posé) : la box reste en lite, utilisable.
- [ ] Le journal d'audit porte `profile_upgrade_start` puis `profile_upgrade_failed`.
- [ ] Réseau rebranché, relancer la commande : `profile_upgrade_done`, profil isp actif.

## 5. Retour arrière

- [ ] `secubox-profilectl apply --profile lite --yes` : les modules propres à isp sont arrêtés et désactivés,
  les paquets restent installés (pas de désinstallation automatique).
- [ ] En cas d'échec de l'apply, `secubox-profilectl rollback --target R1 --yes` restaure l'état précédent.
- [ ] Désinstallation éventuelle (manuelle, assumée) : `apt-get remove secubox-isp` ne retire que le méta-paquet.

## 6. Raspberry Pi (rpi-arm64, kiosque HDMI)

Même déroulé sur un Pi 4 ou Pi 400 avec l'image `secubox-lite-rpi-arm64-trixie.img` :

- [ ] Le kiosque (Chromium plein écran) s'ouvre sur premier pas au premier démarrage.
- [ ] Montée isp par le kiosque : vérifier la RAM (4 Go) et la température pendant l'installation apt.
- [ ] Variante `rpi4-dsi` : l'écran 7" s'allume après le premier redémarrage (secubox-rpi-dsi-boot.service).

## Mesures à reporter

| Mesure | live-amd64 lite | live-amd64 après isp | rpi-arm64 lite | rpi-arm64 après isp |
|---|---|---|---|---|
| Taille image `.img.gz` | | — | | — |
| Paquets `secubox-*` installés | | | | |
| RAM utilisée au repos (`free -m`, 5 min) | | | | |
| Durée de la montée (apt) | — | | — | |
| Unités secubox en échec | | | | |

Reporter les valeurs dans l'issue #3428 avec la date et le commit des images.
