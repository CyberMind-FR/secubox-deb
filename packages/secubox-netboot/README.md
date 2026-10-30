<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# secubox-netboot

Network boot and provisioning for GlobalScale MOCHAbin (Armada 7040) and
ESPRESSObin v7/Ultra (Armada 3720) appliances running SecuBox-Deb.

The **server** (gk2) stays at B0 — it only serves artifacts. Boot overlays
and flashing happen on the device under test (DUT) only, with explicit
operator confirmation.

---

## Boot Levels

| Level | Source | Integrity | When |
|-------|--------|-----------|------|
| **B0 — Local** | eMMC/SD (factory) | — | Server (gk2) default; untouched |
| **B1 — TFTP raw** | TFTP | none (trusted LAN) | Chain-proof / bench test |
| **B2 — HTTP signed** | HTTP `boot.fit` | **FIT signature** (verified by `bootm`) | Production: integrity from signature, not transport |
| **B3 — Installer** | B2 + release image | FIT + detached image sig | Provisioning: download → verify → write eMMC → reboot |

B0 is the default. A board opts into a network level through its profile.
B2 is the production target: plain HTTP is acceptable because integrity is
guaranteed by the FIT signature, not the transport.

---

## Enhanced Tow-Boot (#748)

Factory U-Boot (2020.10 on MOCHAbin) lacks `wget`, making HTTP netboot
impossible without a bootloader upgrade.

The solution is a **chainloaded overlay**: a second U-Boot built from
[Tow-Boot](https://tow-boot.org) (SecuBox fork) with `CONFIG_CMD_WGET`,
`CONFIG_FIT_SIGNATURE`, DHCP, and `booti` enabled, packaged as a signed FIT
and loaded **into RAM only** — the SPI firmware is never touched in this phase.

### Chainload flow

```
BootROM → TF-A (SPI mtd0) → U-Boot FACTORY (SPI mtd0)
                                  │  bootcmd redirected (overlay active)
                                  ▼
                     load /boot/sbx-uboot.fit  [signed, RAM only]
                                  │  bootm → go
                                  ▼
                         U-Boot OVERLAY (RAM)  — wget / FIT-sig / menu
                                  │  executes /boot/sbx-boot.scr
                                  ▼
                DHCP → HTTP boot.fit (B2) | TFTP Image (B1 fallback)
                     → bootm verifies FIT signature → booti
```

### Anti-brick safeguard

`bootcmd` is wrapped with `bootcount`/`altbootcmd`:

- If the overlay fails to load or the FIT signature check fails, execution
  falls through to `factory_bootcmd` immediately.
- If the OS fails to confirm health (`bootcount=0`) within 3 attempts,
  `altbootcmd` restores the factory boot automatically — no serial
  intervention required.
- Manual rollback: `secubox-netboot-overlay revert --commit`.

### Building the Tow-Boot overlay (#748)

Requires a host with [Nix](https://nixos.org/nix/):

```bash
cd tools/Tow-Boot
sg nix-users -c "nix-build -A globalscale-mochabin-8gb"
# outputs: result/Tow-Boot.spi.bin  result/u-boot.bin
```

Wrap the output into a signed chainload FIT:

```bash
packages/secubox-netboot/scripts/build-uboot-overlay.sh \
  --board mochabin \
  --tow-boot result/ \
  --key-dir /etc/secubox/netboot/keys \
  --out /var/lib/secubox/netboot/staging/overlay
```

Overlay load address: `OVERLAY_LOAD=0x06000000` (mochabin, validated).
Outputs: `sbx-uboot.fit` (signed), `sbx-boot.scr` (chainload script).

`Tow-Boot.spi.bin` is also produced for optional SPI flashing (opt-in,
operator-confirmed — see serial flasher below).

---

## Serial Flasher (#748, planned)

For boards where the factory bootloader cannot chainload at all, SecuBox
netboot will include a **UART push** path using the Marvell BootROM:

- Armada 7040/8040 (MOCHAbin): `mvebu64boot`
- Armada 3720 (ESPRESSObin v7/Ultra): `kwboot`

This bootstraps the enhanced Tow-Boot over serial before any network boot is
possible. Implementation is gated on HW validation (Phase 2 serial flasher
CLI in `sbin/`).

---

## Artifact Paths

```
/srv/secubox/netboot/
├── tftp/<id>/          TFTP root per board (by MAC): Image, board.dtb, initrd.img
├── http/<id>/          HTTP root per board: boot.fit (signed)
└── http/overlay-<board>/  overlay sbx-uboot.fit + sbx-boot.scr
```

`<id>` is the board MAC address (e.g. `00504384fb2f` for c3q).

HTTP boot vhost listens on **`:8099` only** — never `:80`. Its `listen` address is the template `@ADRESSE_LAN@`, filled by `secubox-netboot-serve up` with this box's private address (`SBX_NETBOOT_ADRESSE=<ip>` to force it). There is no `/sbxboot/` location on the main vhost.

Config: `/etc/secubox/netboot.toml`

---

## Commands

```bash
# Activate server role (TFTP + nginx boot vhost)
secubox-netboot-serve up
secubox-netboot-serve status

# Probe local board: U-Boot version, capabilities, env layout, boot media
secubox-netboot-probe

# Publish signed artifacts for a DUT
secubox-netboot-publish --id <MAC> --sign \
    --kernel /boot/Image --dtb /boot/armada-7040-mochabin.dtb \
    --initrd <installer.initrd> --addrs board/mochabin/addrs.env

# Publish an overlay (Tow-Boot chainload)
secubox-netboot-publish --id overlay-mochabin \
    --overlay-fit staging/sbx-uboot.fit --scr staging/sbx-boot.scr

# Apply overlay (dry-run by default; --confirm=true to commit)
secubox-netboot-overlay apply [--commit]
secubox-netboot-overlay status
secubox-netboot-overlay confirm-healthy   # reset bootcount after healthy boot
secubox-netboot-overlay revert --commit   # restore factory bootcmd

# Lifecycle hooks
secubox-netboot-triggers <event>
```

---

## REST API

Socket: `/run/secubox/netboot.sock` (standalone, never in-process aggregator).
All endpoints require JWT (`Authorization: Bearer <token>`).

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/netboot/health` | Public health check |
| GET | `/api/v1/netboot/probe` | Board capabilities (read-only) |
| GET | `/api/v1/netboot/status` | Overlay state, bootcount, backup |
| GET | `/api/v1/netboot/inventory` | Board + overlay combined view |
| GET | `/api/v1/netboot/images` | Signed release image catalog |
| GET | `/api/v1/netboot/audit` | Append-only audit log |
| POST | `/api/v1/netboot/overlay/apply` | Apply overlay (`confirm=true` to commit) |
| POST | `/api/v1/netboot/overlay/revert` | Revert to factory bootcmd |
| POST | `/api/v1/netboot/overlay/persist` | Lock overlay as permanent boot |
| POST | `/api/v1/netboot/overlay/confirm-healthy` | Mark boot healthy (bootcount=0) |
| GET | `/api/v1/netboot/live` | Lives servis (#3100) : commandes U-Boot lues dans le `boot.cmd` servi, base HTTP, images eMMC (taille, SHA-256, signature, `taille_brute` décompressée si connue, #3233) |
| POST | `/api/v1/netboot/flash/prepare` | Préparer le (re)flash d'une box (#3100) : `{"nom", "mot_de_passe"?}`, 24 h |

Hors JWT, servi par le **seul vhost de boot `:8099`** (404 sur le vhost principal) :

| Method | Path | Description |
|--------|------|-------------|
| GET | `http://<maître>:8099/lot-flash?nom=NOM` | Lot de flash signé remis au live (#3100) |

---

## Flash par le réseau et association au maillage (#3100)

Sur le live de la box à flasher : `sbx-netflash --image IMAGE --nom NOM`.

1. Le live demande `GET /lot-flash?nom=NOM` au vhost `:8099` (LAN seulement, ponts conteneurs
   et maillage refusés, 6 lots par heure et par adresse). nginx y pose le marqueur
   `X-SecuBox-Netboot-Lot` et `X-SecuBox-Adresse-Serveur: $server_addr` (adresse du maître
   jointe par le live, portée par le code ; à défaut, source de `ip route get`).
2. `secubox-netboot-lot NOM [--adresse A]` (root) émet un code de jonction lié au nom (48 h) et
   signe le lot `{nom, domaine, code, ancre du maître, admin_empreinte?}` avec la clé netboot.
3. Le live vérifie la signature AVANT toute écriture, flashe l'eMMC, puis y dépose le code,
   l'ancre et `profil.toml` (maillage automesh). Sans empreinte dans le lot, le mot de passe
   administrateur est saisi à la console.

**Reflash d'une box déjà associée.** Le code ne remplace la clé d'un pair existant (`--flash`)
que si l'administrateur a **préparé** ce nom : `POST /api/v1/netboot/flash/prepare`
(`{"nom": "gk1"}`, mot de passe facultatif, gardé en empreinte argon2 seulement). La préparation
vaut 24 h, est prise atomiquement et consommée par un seul lot. Sans préparation, le code est
ordinaire : un nom neuf rejoint le maillage, un nom déjà approuvé reçoit un 409
(« nom déjà pris : préparer un flash… »).

Noms admis partout (lot, `sbx-netflash`, `sbx-netflash-profil`) : `^[a-z]([a-z0-9-]{0,29}[a-z0-9])?$`.

## Live léger multi-carte et flash en flux (#3233)

**Réglages par carte.** `board/<carte>/live.env` fixe ce qui est propre à chaque carte : DTB, pilote Ethernet, console, `ethact`, adresses de chargement (hors zone PSCI 0x04000000-0x04200000) et options du noyau. Deux cartes existent : `mochabin` et `espressobin-v7` (eMMC, 1 Go).

**Live léger** (ESPRESSObin). Le script `scripts/build-live-leger.sh --carte espressobin-v7 --sortie LIVE.img.gz --pub CLE.pub [--cle-ssh ID.pub] [--srv HOTE:PORT]` construit une Debian minimale. Elle contient le réseau, SSH par clé et les outils de flash, en démarrage normal. Le live :
- n'a pas de pile SecuBox ;
- ouvre une session root sur la console série (accès de banc) ;
- n'a aucun mot de passe.

L'image produite sert de deux façons :
- **clé USB** :
  - partition 1 : FAT `SBXBOOT`, avec `boot.scr` pour `fatload usb 0:1` ;
  - partition 2 : ext4 `SBXLIVE` ;
- **netboot** : `scripts/build-live-netboot.sh --live LIVE.img.gz --carte espressobin-v7 --srv 192.168.1.200:8099 --tftp 192.168.42.1 --flash IMAGE.img.xz`.

Depuis le U-Boot usine (console série `ttyMV0`) :

- par le réseau (bloc exact, généré : voir « Préparation de l'environnement U-Boot » ci-dessous) :

<!-- uboot-env: netboot espressobin-v7 192.168.42.1 -->
```
setenv ethact neta@30000; setenv autoload no
setenv kernel_addr_r 0x07000000; setenv fdt_addr_r 0x06f00000; setenv ramdisk_addr_r 0x0b000000
dhcp; setenv serverip 192.168.42.1
tftpboot ${loadaddr} espressobin-live/boot.scr; source ${loadaddr}
```

- par la clé USB :

  ```
  usb start; fatload usb 0:1 ${loadaddr} boot.scr; source ${loadaddr}
  ```

**Flash en flux** (#3233, toujours depuis #3271). `sbx-netflash` passe l'image à `secubox-flash-emmc --stdin gz|xz --sig --pub --sha256 --auto --no-reboot`, quelle que soit la mémoire de la carte (une MOCHAbin de 8 Go copiait l'image dans un tmpfs et le live manquait de mémoire) :
- elle est écrite au fil du téléchargement, jamais copiée en mémoire ;
- la signature et le SHA-256 du flux compressé sont vérifiés pendant l'écriture ;
- en cas d'échec (signature, empreinte, flux coupé), le début et la fin de l'eMMC sont remis à zéro.

**Clé USB finale** (`scripts/build-cle-finale.sh --image IMG.img.xz --sortie CLE.img.gz [--publier espressobin-live]`). La clé porte l'image système elle-même, avec des étiquettes et des GUID propres à la clé (`rootfs-usb`, `data-usb`, `BOOTUSB`) : sa racine n'est jamais confondue avec celle d'une eMMC déjà écrite. Elle contient en plus une partition `SBXFLASH` qui range l'image signée. Deux commandes U-Boot :

- **tester** : `usb start; load usb 0:1 ${loadaddr} boot-usb.scr; source ${loadaddr}`. Le système tourne sur la clé ; l'eMMC n'est pas touchée.
- **autoflash** : `usb start; load usb 0:1 ${loadaddr} autoflash.scr; source ${loadaddr}`. Avec `sbx_autoflash=1`, `sbx-autoflash` vérifie la signature, puis écrit l'image sur l'eMMC par le flux vérifié, et la carte s'éteint. On retire alors la clé : la carte démarre sur l'eMMC.

Publiée avec `--publier`, la clé apparaît sur la page `/netboot/` (`cle-usb.img.gz`, signée, et `cle-usb.txt`). L'API `/live` renvoie `titre`, `console`, `usb` et `commandes_usb`.

`images.txt` porte une 4ᵉ colonne, la taille décompressée. Une image plus grande que l'eMMC est refusée avant toute écriture. Formats acceptés : `.img.gz` et `.img.xz`.

---

## Préparation de l'environnement U-Boot (#3271)

Le U-Boot d'usine Marvell (MOCHAbin : 2018.03, relevé le 2026-10-29) n'a pas de `scriptaddr`, garde `ethact=mvpp2-0`
(cage SFP+ sur la MOCHAbin), un `bootcmd` TFTP/NFS et des adresses qui posent un noyau Debian (~37 Mo) sur la zone
réservée du firmware. Un même script par carte, **`secubox-uboot-env.scr`** (source `secubox-uboot-env.cmd`), pose et
enregistre (`saveenv`) :

- les adresses sûres (`kernel_addr_r`, `fdt_addr_r`, `ramdisk_addr_r` : celles de `board/<carte>/live.env`) ;
- `ethact` (port WAN : `mvpp2-2` sur la MOCHAbin, `neta@30000` sur l'ESPRESSObin v7) et `autoload no` ;
- `bootcmd` : démarrage depuis le support installé (MOCHAbin : WAN + `dhcp`, puis `boot.scr` de l'eMMC `mmc 0` ;
  ESPRESSObin v7 : `boot.scr` de l'eMMC `mmc 1`, puis `boot-usb.scr` de la clé) ;
- `bootcmd_netboot` : secours netboot, **jamais lancé seul** (un DHCP du WAN ne doit pas pouvoir démarrer la box) ;
  à la console : `setenv serverip <IP du maître>; run bootcmd_netboot` ;
- l'ancien `bootcmd` dans `bootcmd_avant`, seulement s'il n'existe pas déjà (forme `if test -n … else … fi`, celle
  du `boot.cmd` ESPRESSObin validé sur carte). Retour : `setenv bootcmd "${bootcmd_avant}"; saveenv`.

Le `bootcmd` MOCHAbin enchaîne par `;` (`setenv ethact mvpp2-2; dhcp; mmc dev 0; fatload …; source …`) : un `dhcp`
raté n'empêche pas le démarrage. C'est la séquence validée au banc le 2026-10-29 ; ne pas en changer la forme (`&&`,
`if … then`) sans nouvel essai sur la carte.

**Pourquoi pas depuis Linux (R-3271-1).** L'écriture de l'environnement par `fw_setenv` depuis le live est
abandonnée : sous le noyau Debian 6.12 de ces cartes, sans pilote `spi-orion`, `/proc/mtd` est vide (la SPI n'est pas
exposée), et une MOCHAbin du banc a une SPI instable. Le script, lancé depuis U-Boot (partition `/boot` de l'image ou
dossier netboot de la carte), est la seule voie. `sbx-uboot-env` (dans le live) n'est plus qu'un diagnostic :
`--commandes` (affiché à la fin du flash par `sbx-netflash`), `--afficher` (commandes, script de référence, et la ligne
« la SPI n'est pas exposée sous ce noyau : utilisez secubox-uboot-env.scr depuis U-Boot », code 5, quand `/proc/mtd` ne
liste pas le mtd attendu).

R-3271-2 : cette décision vise le live et `sbx-uboot-env`. L'overlay #737 (`secubox-netboot-overlay`,
`secubox-netboot-confirm-healthy`, `installer/init`) garde des chemins `fw_setenv` antérieurs à cette branche,
inopérants sans MTD (ils ne font rien sous ces noyaux) ; leur sort est suivi par #3281.

**ESPRESSObin v7 : à valider au banc avant tout usage.** Son `secubox-uboot-env.scr` est livré, mais ses adresses
(`0x07000000`/`0x06f00000`/`0x0b000000`) sont celles du live, pas encore éprouvées pour le système installé ; son
en-tête le dit. La MOCHAbin (adresses #3091, `bootcmd` du 2026-10-29) est validée au banc.

**Où est le script.** À la racine de la partition de démarrage (FAT) de l'image (`image/build-image.sh`), avec l'alias
`fix-bootcmd.scr` le temps d'une version (procédures #2826) : sur l'ESPRESSObin, l'ancien `fix-bootcmd` inchangé
(`bootcmd_avant` et `bootcmd` seulement) ; sur la MOCHAbin, une copie complète. Il est aussi dans le dossier netboot de la carte, à côté de
`boot.scr` (TFTP et HTTP, `build-live-netboot.sh`), ainsi que sur la clé du live léger.

**Sources.** `board/<carte>/live.env` et `board/<carte>/uboot-env.env` (données, jamais exécutées). Le générateur
`scripts/uboot-env.py` en tire `secubox-uboot-env.cmd`/`.scr` (versionnés dans `board/<carte>/` à la racine du dépôt ;
le `.cmd` est la référence, le `.scr` sa compilation, vérifiée par les tests), l'en-tête du `boot.cmd` du live (bloc
netboot affiché par la page), `preparation.txt` et la configuration du diagnostic. Les blocs de cette page sont
vérifiés contre lui (`tests/test_uboot_env_3271.py`). Régénérer après toute modification :

```
python3 scripts/uboot-env.py generer --mkimage ~/CyberMindStudio/secubox-openwrt/secubox-tools/openwrt/staging_dir/host/bin/mkimage
```

(`mkimage` de la chaîne OpenWrt locale, 2024.07 ; `SOURCE_DATE_EPOCH` fixé, le `.scr` ne change que si le `.cmd` change.)

**Procédure, MOCHAbin** (console série `ttyS0`) :

<!-- procedure: mochabin -->
1. Après le flash, au redémarrage, interrompre le compte à rebours de U-Boot.
2. `mmc dev 0; fatload mmc 0:1 ${loadaddr} secubox-uboot-env.scr; source ${loadaddr}` (ou depuis le netboot : `setenv ethact mvpp2-2; setenv autoload no; dhcp; setenv serverip 192.168.1.200; tftpboot ${loadaddr} mochabin-live/secubox-uboot-env.scr; source ${loadaddr}`).
3. `reset` : la carte démarre seule sur l'eMMC, WAN initialisé ; l'ancien `bootcmd` reste dans `bootcmd_avant`.
<!-- /procedure -->

**Procédure, ESPRESSObin v7** (console série `ttyMV0`) :

<!-- procedure: espressobin-v7 -->
1. Après le flash, au redémarrage, interrompre le compte à rebours de U-Boot.
2. `mmc dev 1; load mmc 1:1 ${loadaddr} secubox-uboot-env.scr; source ${loadaddr}` (ou depuis le netboot : `setenv ethact neta@30000; setenv autoload no; dhcp; setenv serverip 192.168.42.1; tftpboot ${loadaddr} espressobin-live/secubox-uboot-env.scr; source ${loadaddr}`).
3. `reset` : la carte démarre seule sur l'eMMC (puis la clé USB en repli) ; l'ancien `bootcmd` reste dans `bootcmd_avant`.
<!-- /procedure -->

**Netboot MOCHAbin** (câble sur le port WAN cuivre) :

<!-- uboot-env: netboot mochabin 192.168.1.200 -->
```
setenv ethact mvpp2-2; setenv autoload no
setenv kernel_addr_r 0x08000000; setenv fdt_addr_r 0x0c000000; setenv ramdisk_addr_r 0x0c100000
dhcp; setenv serverip 192.168.1.200
tftpboot ${loadaddr} mochabin-live/boot.scr; source ${loadaddr}
```

**Commandes exactes**, à copier (MOCHAbin, puis ESPRESSObin v7) :

<!-- uboot-env: preparation mochabin 192.168.1.200 reseau -->
```
setenv ethact mvpp2-2; setenv autoload no; dhcp; setenv serverip 192.168.1.200; tftpboot ${loadaddr} mochabin-live/secubox-uboot-env.scr; source ${loadaddr}
reset
```

<!-- uboot-env: preparation mochabin 192.168.1.200 installe -->
```
mmc dev 0; fatload mmc 0:1 ${loadaddr} secubox-uboot-env.scr; source ${loadaddr}
reset
```

<!-- uboot-env: preparation espressobin-v7 192.168.42.1 reseau -->
```
setenv ethact neta@30000; setenv autoload no; dhcp; setenv serverip 192.168.42.1; tftpboot ${loadaddr} espressobin-live/secubox-uboot-env.scr; source ${loadaddr}
reset
```

<!-- uboot-env: preparation espressobin-v7 192.168.42.1 installe -->
```
mmc dev 1; load mmc 1:1 ${loadaddr} secubox-uboot-env.scr; source ${loadaddr}
reset
```

| Carte | Environnement (source, diagnostic seulement) |
|---|---|
| MOCHAbin | SPI `0x3f0000`, 64 Kio (U-Boot Globalscale 2018.03, `mvebu_armada-common.h`) ; 2020.10 : `0x180000` |
| ESPRESSObin v7 | SPI `0x3f0000`, 64 Kio (2017.03, 2018.03, 2020.10) |

---

## Key Configuration (`/etc/secubox/netboot.toml`)

```toml
[server]
http_base = "http://boot.gk2.secubox.in:8099"
tftp_root = "/srv/secubox/netboot/tftp"

[overlay]
max_tries = 3           # bootcount before auto-rollback to factory
key_hint  = "secubox-netboot"

[security]
require_signed_fit = true   # refuse unsigned overlay
confirm_required   = true   # all overlay/flash actions need confirm=true
```

---

## Security Constraints

- Boot vhost on `:8099` only — not routed through WAF (FIT signature is the
  integrity mechanism, not transport).
- FIT signature mandatory for B2/B3 profiles; `secubox-netboot-publish`
  refuses unsigned artifacts for those levels.
- SPI flashing AUTOMATION (the serial-flash CLI) is Phase 2; the
  `Tow-Boot.spi.bin` artifact itself is produced in Phase 1 for
  operator-initiated manual flash (opt-in, requires operator confirmation).
- Audit log: `/var/log/secubox/netboot/audit.log` (append-only, CSPN).
- Daemon runs as `secubox-netboot` (dedicated user/group, created in
  `debian/postinst`). The overlay #737 `fw_setenv` paths are inoperative on
  kernels without MTD (see « Préparation de l'environnement U-Boot », #3281).

---

## References

- Boot levels: `docs/BOOT-LEVELS.md`
- Overlay spec (Phase 2): `docs/PHASE2-uboot-overlay.md`
- Test topology (2× MOCHAbin): `docs/TEST-TOPOLOGY.md`
- Board addresses: `board/mochabin/addrs.env`, `board/espressobin-v7/`
- Issue tracker: #737 (netboot core), #748 (enhanced Tow-Boot + serial flasher)
