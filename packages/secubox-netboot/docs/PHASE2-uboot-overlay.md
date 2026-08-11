# Phase 2 — Overlay U-Boot chainloadé (HTTP + FIT-signature)

> #737 · cible MOCHAbin (Armada 7040) en premier, puis ESPRESSObin v7/Ultra.
> But : **ajouter les fonctions manquantes** (HTTP/HTTPS, FIT-signature, menu de
> boot réseau) **sans reflasher le U-Boot usine**, via un 2ᵉ U-Boot chargé en
> chaîne, avec **rollback automatique** vers l'usine si l'overlay échoue.

---

## 1. Pourquoi un overlay et pas un reflash

Le U-Boot usine (SPI-NOR `mtd0`) sait au minimum charger un payload depuis eMMC/SD
(`load mmc …`) et l'exécuter (`bootm`/`go`). On **n'écrit donc rien dans le SPI** :
on dépose un 2ᵉ U-Boot signé sur `/boot` (eMMC p1) et on détourne `bootcmd` pour le
chaîner. Zéro risque de brick du bootloader primaire ; rollback = restaurer
`bootcmd`. Le reflash (P3) reste réservé aux usines incapables de chainloader.

```
BootROM → TF-A (SPI mtd0) → U-Boot USINE (SPI mtd0)
                                   │  bootcmd détourné (overlay actif)
                                   ▼
                      charge /boot/sbx-uboot.fit  (2ᵉ U-Boot, SIGNÉ)
                                   │  bootm → go
                                   ▼
                          U-Boot OVERLAY (RAM)  ── wget/HTTPS/FIT-sig/menu
                                   │  exécute /boot/sbx-boot.scr
                                   ▼
            DHCP → (TFTP|HTTP) kernel+dtb+initrd  → vérif FIT → booti
```

---

## 2. Pré-requis runtime à fiabiliser (bloquant)

### 2.1 Lire l'environnement U-Boot (`fw_env.config`)
`fw_printenv` a échoué (CRC) car l'offset/redondance de `mtd2` n'est pas calé. Le
probe (`sbin/secubox-netboot-probe`) doit **détecter** le layout :

```
# /etc/fw_env.config — candidats à tester par le probe, dans l'ordre :
# 1) env simple plein-secteur
/dev/mtd2 0x0000 0x10000 0x1000
# 2) env redondant (2 copies de 32K)
/dev/mtd2 0x0000 0x8000 0x1000
/dev/mtd2 0x8000 0x8000 0x1000
```
Le probe écrit chaque candidat, teste `fw_printenv -c … ver` ; le premier qui rend
un CRC valide est retenu et persisté. **Lecture seule tant que le layout n'est pas
confirmé** ; aucun `fw_setenv` avant validation.

### 2.2 Capacités du U-Boot usine (probe)
À récupérer (via `ver`, et si besoin un boot interactif série une seule fois) :
- version U-Boot (≥ 2023.04 ⇒ `wget`/`bootm FIT` probables) ;
- présence des commandes : `bootm`, `load mmc`, `dhcp`, `tftpboot`, `wget`, `bootcount`/`altbootcmd` ;
- média de boot effectif (SPI vs eMMC) et adresses de chargement utiles
  (`loadaddr`, `fdt_addr_r`, `kernel_addr_r`).

> Si l'usine a **déjà** `wget` + `bootm FIT signé`, l'overlay 2ᵉ U-Boot devient
> optionnel → on retombe sur un simple `boot.scr` (P1). Le probe tranche.

---

## 3. Artefact overlay : `sbx-uboot.fit`

Un **U-Boot mainline** compilé pour la board, empaqueté en **FIT signé**.

### 3.1 Build (CI, par board)
- Source : U-Boot mainline pinné + `board/<name>/uboot.fragment` (config delta) activant :
  `CONFIG_CMD_WGET`, `CONFIG_WGET`, (option `CONFIG_WGET_HTTPS`+mbedTLS),
  `CONFIG_FIT_SIGNATURE`, `CONFIG_CMD_BOOTMENU`, réseau de la board.
- Sortie : `u-boot.bin` (+ DTB) → `sbx-uboot.fit` via `mkimage`.

### 3.2 FIT signé (`.its`)
```
/dts-v1/;
/ {
  description = "SecuBox overlay U-Boot (chainload)";
  images {
    uboot@1 {
      description = "U-Boot mainline mochabin";
      data = /incbin/("u-boot.bin");
      type = "standalone";        /* chargé puis 'go'/'bootm' */
      arch = "arm64";
      compression = "none";
      load = <0x06000000>;        /* hors zone TF-A/usine — à valider par board */
      entry = <0x06000000>;
      hash@1 { algo = "sha256"; };
      signature@1 {
        algo = "sha256,rsa2048";
        key-name-hint = "secubox-netboot";
      };
    };
  };
  configurations {
    default = "conf@1";
    conf@1 { description = "overlay"; firmware = "uboot@1"; signature@1 {
      algo = "sha256,rsa2048"; key-name-hint = "secubox-netboot";
      sign-images = "firmware"; }; };
  };
};
```
Signature : `mkimage -F -k keys/ -K <dtb_avec_cle_pub> -r sbx-uboot.fit`. La **clé
publique** est embarquée dans le **DTB du U-Boot usine** (si on contrôle son build)
ou, à défaut, vérifiée par l'overlay lui-même au 2ᵉ étage (chaîne de confiance
décalée d'un cran — documenté comme limite P2, durci en P4 via TF-A verified boot).

### 3.3 Placement
`sbx-uboot.fit` + `sbx-boot.scr` déposés dans **`/boot`** (eMMC p1), gérés en
**double-buffer** (`active/` ↔ `shadow/`) à la manière de l'Eye-Remote boot-media :
pose = écrire en shadow + valider signature + swap atomique ; rollback = swap inverse.

---

## 4. Détournement de `bootcmd` (pose de l'overlay) + rollback automatique

On **ne remplace pas** `bootcmd` : on l'encadre avec `bootcount`/`altbootcmd` pour
qu'un overlay défaillant **revienne tout seul** au boot usine.

```bash
# Sauvegarde de l'amorce usine (une seule fois, par le probe)
fw_setenv -c /etc/fw_env.config factory_bootcmd "$(fw_printenv -n bootcmd)"

# Amorce overlay : tente le 2ᵉ U-Boot signé ; sinon enchaîne l'usine
fw_setenv -c /etc/fw_env.config sbx_overlay \
  'load mmc 0:1 ${loadaddr} sbx-uboot.fit && bootm ${loadaddr}'
fw_setenv -c /etc/fw_env.config bootcmd \
  'if test ${bootcount} -gt 2; then echo SBX overlay KO -> factory; run factory_bootcmd; else run sbx_overlay; run factory_bootcmd; fi'

# Garde-fou anti-brick : compteur de boots + bascule auto
fw_setenv -c /etc/fw_env.config bootcount 0
fw_setenv -c /etc/fw_env.config altbootcmd 'run factory_bootcmd'
```
- `bootm` du FIT **vérifie la signature** ; échec ⇒ on tombe sur `factory_bootcmd`.
- Si le 2ᵉ U-Boot boote mais l'OS ne valide pas, l'**OS remet `bootcount=0`** au
  premier boot sain (`bootcount` géré côté Linux via `fw_setenv bootcount 0` en
  `secubox-netboot-overlay --confirm-healthy`). Sinon, après 3 essais, retour usine.
- **Rollback manuel** : `fw_setenv bootcmd "$(fw_printenv -n factory_bootcmd)"`.

---

## 5. `sbx-boot.scr` (exécuté par l'overlay 2ᵉ U-Boot)

```bash
# compilé en boot.scr : mkimage -A arm64 -T script -C none -d sbx-boot.cmd sbx-boot.scr
setenv autoload no
dhcp
setenv sbx_srv ${serverip}        # fourni par DHCP (option next-server)
# 1) menu réseau si présent, sinon image assignée à cette board (par MAC/serial)
if wget ${loadaddr} http://${sbx_srv}/netboot/${ethaddr}/boot.fit; then
  bootm ${loadaddr}               # FIT signé : kernel+dtb+initrd vérifiés
else
  # repli TFTP (fonctions usine garanties)
  tftpboot ${kernel_addr_r} ${sbx_srv}:netboot/Image
  tftpboot ${fdt_addr_r}    ${sbx_srv}:netboot/board.dtb
  booti ${kernel_addr_r} - ${fdt_addr_r}
fi
```
Le `boot.fit` côté serveur contient kernel + dtb + initrd **installeur** (mini-rootfs
qui télécharge l'image release complète, vérifie sa signature détachée, écrit sur
eMMC/SD, puis reboot). HTTP simple OK car FIT signé.

---

## 6. Cycle de vie & triggers (P2)

| Étape | Action | Hook |
|-------|--------|------|
| `probe` | détecte ver/capacités/layout env/média | `on-version-mismatch` |
| `overlay/apply` | shadow FIT+scr → vérif sig → swap → set `sbx_overlay`/`bootcmd` | `pre-overlay`,`post-overlay` |
| boot | usine chaîne l'overlay (signature vérifiée par `bootm`) | — |
| `confirm-healthy` | OS sain → `bootcount=0` | `on-boot-success` |
| échec ×3 | `altbootcmd` → boot usine | `on-boot-fail` |
| `overlay/revert` | restaure `factory_bootcmd` | — |

Hooks = scripts drop-in dans `/etc/secubox/netboot/hooks/<event>.d/*`, exécutés par
`secubox-netboot-triggers` (env : `BOARD`, `MODEL`, `UBOOT_VER`, `IMAGE_VER`, `SLOT`).

---

## 7. UI de suivi/contrôle (P2 minimal)

`www/netboot/` :
- **Carte board** : modèle, U-Boot ver (probe), overlay actif/inactif, `bootcount`,
  dernier résultat de boot, slot.
- **Actions** (confirmation) : *Probe*, *Poser l'overlay*, *Confirmer sain*,
  *Revert overlay*. (Le flash A/B = P3, grisé en P2.)
- **Live** : journal du dernier `apply`/boot via la console série Eye-Remote.

---

## 8. Definition of Done (P2)

1. `secubox-netboot-probe` détecte de façon fiable : layout `fw_env`, version
   U-Boot, capacités (`wget`/`bootm FIT`), média de boot — sur MOCHAbin gk2.
2. `sbx-uboot.fit` (overlay) **buildé + signé** pour mochabin ; `bootm` le vérifie.
3. `overlay/apply` pose l'overlay en double-buffer + détourne `bootcmd` avec
   `bootcount`/`altbootcmd` ; `overlay/revert` restaure l'usine.
4. **Test anti-brick prouvé** : un FIT volontairement mal signé ⇒ la board
   **retombe sur l'usine** sans intervention (banc série).
5. UI : carte board + actions + live console.
6. Aucun flash SPI/eMMC-boot en P2 (reflash = P3).

---

## 9. Risques & limites P2

- **Chaîne de confiance décalée** : si on ne contrôle pas le DTB du U-Boot usine,
  la 1ʳᵉ vérif signature se fait au 2ᵉ étage (overlay) → l'usine reste « trust on
  first chainload ». Acceptable en P2, **fermé en P4** (TF-A verified boot + clé en
  SPI). À documenter dans l'audit.
- **Adresses de chargement** (`load`/`entry` 0x06000000) à **valider par board**
  (ne pas chevaucher TF-A/usine/réservé) — sinon hang. Banc série obligatoire.
- **Média de boot** : si la board boote réellement eMMC (pas SPI), le détournement
  `bootcmd` suffit ; si SPI, idem tant qu'on ne touche pas `mtd0`.
- **ESPRESSObin 3720** : driver réseau + adresses différents → fragment board distinct.
