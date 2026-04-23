# Gestion des médias de démarrage Eye Remote Bootstrap

**Version:** 2.1.0
**Dernière mise à jour:** 2026-04-23
**Statut:** Production
**Auteur:** CyberMind — Gerald Kerma

---

## Présentation générale

Le système Eye Remote Bootstrap étend le gadget USB OTG du Pi Zero W pour fournir un canal de gestion de médias de démarrage pour les cartes ESPRESSObin. Via un seul câble USB OTG, l'Eye Remote fournit simultanément :

1. **Transport de métriques** (ECM) — Réseau Ethernet-sur-USB sur `10.55.0.0/30`
2. **Console série** (ACM) — Console de débogage sur `/dev/ttyACM0` (hôte) / `/dev/ttyGS0` (gadget)
3. **Média de démarrage** (Mass Storage) — LUN USB servant les images kernel, DTB, initrd et rootfs

Cela permet un workflow de récupération sans nécessiter d'intervention physique : flasher un nouveau noyau depuis le tableau de bord web de l'Eye Remote, le tester sur la carte cible, puis le promouvoir vers le slot actif avec une sémantique de swap atomique.

### Diagramme d'architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Eye Remote Pi Zero W                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─────────────────┐    ┌──────────────────┐    ┌───────────────┐  │
│  │ FastAPI Router  │───▶│ core/boot_media  │───▶│ gadget-setup  │  │
│  │ /boot-media/*   │    │ (Python)         │    │ (Bash)        │  │
│  └────────┬────────┘    └────────┬─────────┘    └───────┬───────┘  │
│           │                      │                      │          │
│           ▼                      ▼                      ▼          │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │              /var/lib/secubox/eye-remote/boot-media/        │   │
│  │  ┌─────────┐  ┌─────────┐  ┌──────────────────────────────┐  │   │
│  │  │ active  │  │ shadow  │  │ images/<sha256>.img          │  │   │
│  │  │ (link)  │  │ (link)  │  │ images/<sha256>.img.tmp (UP) │  │   │
│  │  └────┬────┘  └────┬────┘  └──────────────────────────────┘  │   │
│  │       │            │                                         │   │
│  │       ▼            ▼                                         │   │
│  │  ┌─────────────────────────────┐    ┌────────────────────┐  │   │
│  │  │ LUN 0 (mass_storage.usb0)   │    │ tftp/ (symlinks)   │  │   │
│  │  │ points to active slot       │    │ serves shadow slot │  │   │
│  │  └─────────────────────────────┘    └────────────────────┘  │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  ┌───────────────────────────────────────────────────────────────┐ │
│  │                    libcomposite configfs                       │ │
│  │  ┌──────────┐  ┌──────────┐  ┌────────────────────┐           │ │
│  │  │ ecm.usb0 │  │ acm.usb0 │  │ mass_storage.usb0  │           │ │
│  │  │ 10.55.0.2│  │ ttyGS0   │  │ LUN 0 (removable)  │           │ │
│  │  └──────────┘  └──────────┘  └────────────────────┘           │ │
│  └───────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              │ USB OTG cable
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     ESPRESSObin U-Boot                              │
│  Option 1: usb start → fatload usb 0 Image                          │
│  Option 2: dhcp → tftpboot $kernel_addr_r Image (shadow channel)    │
└─────────────────────────────────────────────────────────────────────┘
```

### Structure du répertoire des médias de démarrage

L'Eye Remote maintient une structure de stockage à double buffer 4R :

```
/var/lib/secubox/eye-remote/boot-media/
├── state.json                    ← Métadonnées et état du média de démarrage
├── active                        ← Symlink → images/<sha256>.img
├── shadow                        ← Symlink → images/<sha256>.img (ou NULL)
├── images/
│   ├── a1b2c3d4e5f6.img         ← Image FAT32 ou ext4 (lecture seule, dédupliquée)
│   ├── f0e1d2c3b4a5.img.tmp     ← Upload en cours (temporaire)
│   ├── rollback-r1/             ← Active précédent (4R #1)
│   │   └── a1b2c3d4e5f6.img
│   ├── rollback-r2/             ← Active précédent (4R #2)
│   ├── rollback-r3/             ← Active précédent (4R #3)
│   └── rollback-r4/             ← Active précédent (4R #4)
└── tftp/                        ← Racine du service TFTP (symlinks vers shadow)
    ├── Image → ../images/f0e1d2c3b4a5.img
    ├── device-tree.dtb
    └── initrd.img
```

### Machine à états

```
État initial : Vide (pas d'active, pas de shadow)
                    │
                    ▼
    ┌─────────────────────────────────┐
    │   UPLOAD SHADOW                 │
    │ (via /api/v1/eye-remote/        │
    │  boot-media/upload)             │
    └────────────┬────────────────────┘
                 │
                 ▼
    ┌─────────────────────────────────┐
    │   SHADOW READY                  │
    │ (image valide, extractible)     │
    │                                 │
    │ [Branche A] Test via TFTP ──┐  │
    │            (Optionnel)       │  │
    │                             ▼   │
    │                      Test...    │
    │                             │   │
    │ [Branche B] ◄───────────────┘   │
    │ Promouvoir Shadow vers Active   │
    │ (via /api/v1/eye-remote/        │
    │  boot-media/swap)               │
    └────────────┬────────────────────┘
                 │
                 ▼
    ┌─────────────────────────────────┐
    │   ACTIVE ONLY                   │
    │ (shadow effacé, active défini)  │
    │ (LUN éjecté et rattaché)        │
    └────────────┬────────────────────┘
                 │
    [Optionnel]  │ Upload nouveau shadow
                 ▼
    ┌─────────────────────────────────┐
    │   READY TO SWAP                 │
    │ (active + shadow définis)       │
    │ Peut tester shadow ou rollback  │
    └────────────┬────────────────────┘
                 │
    ┌────────────┴───────────┐
    │                        │
    │ Swap (promouvoir)      │  Rollback (restaurer R1)
    │                        │
    └────────────┬───────────┘
                 │
                 ▼
    ┌─────────────────────────────────┐
    │   SWAPPED                       │
    │ (shadow → active, active → R1)  │
    └─────────────────────────────────┘
```

---

## Fonctionnalités

### 1. LUN USB Mass Storage

- **Fonction:** `mass_storage.usb0` via libcomposite configfs
- **LUN 0:** Pointe vers le slot **active**
- **Média amovible:** Oui (permet l'éjection sans démontage)
- **Taille:** 16 MiB–4 GiB (indépendant du système de fichiers)
- **Formats supportés:** FAT16, FAT32, ext2, ext3, ext4
- **Accès:** Lecture+Écriture (flashage environnement U-Boot, logs, etc.)

### 2. Double buffer avec rollback 4R

L'Eye Remote maintient **4 snapshots de rollback (4R)** :

- **Active:** Actuellement servi via LUN USB à l'ESPRESSObin
- **Shadow:** En attente de validation (uploadé mais non promu)
- **R1–R4:** États actifs précédents, disponibles pour rollback

Chaque changement d'état (swap, rollback) est lié atomiquement et journalisé.

### 3. Canal shadow TFTP

En parallèle du LUN USB, l'Eye Remote exécute **dnsmasq TFTP** sur `10.55.0.2` port 69 :

- **Racine:** `/var/lib/secubox/eye-remote/boot-media/tftp/`
- **Contenu:** Symlinks vers le slot shadow (`Image`, `device-tree.dtb`, `initrd.img`)
- **Cas d'usage:** Tester un nouveau noyau sans swapper le slot actif
- **Commande de démarrage (ESPRESSObin U-Boot):**
  ```
  => setenv serverip 10.55.0.2
  => setenv ipaddr 10.55.0.1
  => tftpboot $kernel_addr_r Image
  => booti $kernel_addr_r - $fdt_addr_r
  ```

### 4. Swap atomique résistant aux pannes

Lors de la promotion du shadow vers active :

1. **Éjecter LUN** du gadget (forcer la déconnexion)
2. **Swapper les symlinks atomiquement** (rename, pas unlink-puis-link)
3. **Mettre à jour les métadonnées** (state.json)
4. **Rattacher LUN** au gadget
5. **Vérifier** que le fichier LUN correspond au chemin attendu

Toutes les opérations protégées par **file lock + process lock** (style module PARAMETERS).

### 5. Gestion API

**Chemin de base:** `/api/v1/eye-remote/boot-media/`

Tous les endpoints nécessitent **l'authentification JWT** avec scope `boot:write` (pour POST) ou `boot:read` (pour GET).

---

## Endpoints API

| Méthode | Chemin | Authentification | Description |
|--------|------|------|---|
| **GET** | `/state` | `boot:read` | Récupérer l'état actuel du média de démarrage (slots, métadonnées) |
| **POST** | `/upload` | `boot:write` | Streamer une image vers le slot shadow (multipart chunked) |
| **POST** | `/swap` | `boot:write` | Promouvoir shadow vers active, rotation active → R1 |
| **POST** | `/rollback` | `boot:write` | Restaurer l'active précédent depuis R1–R4 |
| **GET** | `/tftp/status` | `boot:read` | État du service TFTP et contenu shadow |
| **GET** | `/images` | `boot:read` | Lister les images disponibles avec métadonnées |

### Spécifications détaillées des endpoints

#### GET `/api/v1/eye-remote/boot-media/state`

**Requête:**
```bash
curl -H "Authorization: Bearer $JWT" \
     http://10.55.0.1:8000/api/v1/eye-remote/boot-media/state
```

**Réponse (200 OK):**
```json
{
  "active": {
    "path": "images/a1b2c3d4e5f6.img",
    "sha256": "a1b2c3d4e5f6...",
    "size_bytes": 268435456,
    "created_at": "2026-04-23T10:30:00Z",
    "label": "debian-bookworm-arm64-espressobin"
  },
  "shadow": {
    "path": "images/f0e1d2c3b4a5.img",
    "sha256": "f0e1d2c3b4a5...",
    "size_bytes": 268435456,
    "created_at": "2026-04-23T11:45:00Z",
    "label": "debian-bookworm-arm64-espressobin-rc1"
  },
  "lun_attached": true,
  "last_swap_at": "2026-04-23T10:00:00Z",
  "tftp_armed": true,
  "rollback_available": ["r1", "r2", "r3"]
}
```

#### POST `/api/v1/eye-remote/boot-media/upload`

**Requête (multipart/form-data):**
```bash
curl -X POST \
  -H "Authorization: Bearer $JWT" \
  -F "image=@debian-bookworm-arm64.img" \
  -F "label=debian-bookworm-arm64-espressobin-rc1" \
  http://10.55.0.1:8000/api/v1/eye-remote/boot-media/upload
```

**Paramètres:**
- `image` (fichier, requis): Image de démarrage (FAT32/ext4)
- `label` (chaîne, optionnel): Libellé lisible par l'humain

**Traitement:**
1. Streamer vers fichier temporaire avec suffixe `.tmp`
2. Calculer SHA256 pendant le streaming
3. Valider la magic du système de fichiers et la taille (16 MiB–4 GiB)
4. Extraire les fichiers de démarrage vers `tftp/` (si extractible: Image, dtb, initrd)
5. Renommage atomique vers `images/<sha256>.img`
6. Mettre à jour le symlink shadow

**Réponse (201 Created):**
```json
{
  "path": "images/f0e1d2c3b4a5.img",
  "sha256": "f0e1d2c3b4a5...",
  "size_bytes": 268435456,
  "created_at": "2026-04-23T11:45:00Z",
  "label": "debian-bookworm-arm64-espressobin-rc1",
  "tftp_ready": true
}
```

**Réponse (400 Bad Request) — Image invalide:**
```json
{
  "error": "Invalid filesystem",
  "detail": "Image size must be 16 MiB–4 GiB"
}
```

#### POST `/api/v1/eye-remote/boot-media/swap`

**Requête:**
```bash
curl -X POST \
  -H "Authorization: Bearer $JWT" \
  http://10.55.0.1:8000/api/v1/eye-remote/boot-media/swap
```

**Paramètres optionnels:**
- `verify=true` (défaut): Vérifier que le LUN est rattaché avec succès

**Traitement:**
1. Vérifier que shadow existe et est valide
2. Éjecter LUN du gadget
3. Swapper les symlinks: `active` ← `shadow`, `r1` ← ancien `active`
4. Décaler la chaîne de rollback: `r2` ← `r1`, `r3` ← `r2`, `r4` ← `r3`
5. Effacer le slot shadow
6. Rattacher LUN
7. Mettre à jour state.json

**Réponse (200 OK):**
```json
{
  "success": true,
  "message": "Boot slot swapped successfully",
  "active": {
    "path": "images/f0e1d2c3b4a5.img",
    "sha256": "f0e1d2c3b4a5...",
    "size_bytes": 268435456,
    "created_at": "2026-04-23T11:45:00Z"
  },
  "rollback_available": ["r1", "r2", "r3", "r4"]
}
```

**Réponse (409 Conflict) — Shadow non prêt:**
```json
{
  "error": "No shadow to swap",
  "detail": "Upload an image to shadow before promoting"
}
```

#### POST `/api/v1/eye-remote/boot-media/rollback`

**Requête:**
```bash
curl -X POST \
  -H "Authorization: Bearer $JWT" \
  http://10.55.0.1:8000/api/v1/eye-remote/boot-media/rollback?target=r1
```

**Paramètres:**
- `target` (chaîne): Slot de rollback à restaurer (`r1`, `r2`, `r3`, ou `r4`)

**Traitement:**
1. Vérifier que la cible existe
2. Éjecter LUN
3. Promouvoir la cible vers active, rotation de la chaîne
4. Rattacher LUN

**Réponse (200 OK):**
```json
{
  "success": true,
  "message": "Restored from r1",
  "active": {
    "path": "images/a1b2c3d4e5f6.img",
    "sha256": "a1b2c3d4e5f6...",
    "size_bytes": 268435456,
    "created_at": "2026-04-23T10:30:00Z"
  }
}
```

#### GET `/api/v1/eye-remote/boot-media/tftp/status`

**Requête:**
```bash
curl -H "Authorization: Bearer $JWT" \
     http://10.55.0.1:8000/api/v1/eye-remote/boot-media/tftp/status
```

**Réponse (200 OK):**
```json
{
  "enabled": true,
  "dnsmasq_running": true,
  "port": 69,
  "root": "/var/lib/secubox/eye-remote/boot-media/tftp",
  "shadow": {
    "path": "images/f0e1d2c3b4a5.img",
    "label": "debian-bookworm-arm64-espressobin-rc1"
  },
  "files": [
    {
      "name": "Image",
      "size": 12582912,
      "type": "kernel"
    },
    {
      "name": "device-tree.dtb",
      "size": 65536,
      "type": "devicetree"
    },
    {
      "name": "initrd.img",
      "size": 8388608,
      "type": "initramfs"
    }
  ]
}
```

---

## Exemples de workflow

### Workflow 1: Upload d'une nouvelle image

```bash
#!/bin/bash

# 1. Générer un token JWT (login en tant qu'utilisateur boot:write)
JWT=$(curl -s -X POST http://10.55.0.1:8000/api/v1/auth/token \
  -H "Content-Type: application/json" \
  -d '{"username":"boot-admin","password":"secubox-bootstrap"}' | jq -r .access_token)

# 2. Uploader nouvelle image vers shadow
curl -X POST \
  -H "Authorization: Bearer $JWT" \
  -F "image=@debian-bookworm-arm64-espressobin-rc1.img" \
  -F "label=RC1 Build $(date +%Y%m%d)" \
  http://10.55.0.1:8000/api/v1/eye-remote/boot-media/upload

# 3. Vérifier l'état actuel
curl -H "Authorization: Bearer $JWT" \
  http://10.55.0.1:8000/api/v1/eye-remote/boot-media/state | jq .

# Sortie:
# {
#   "active": { ... ancienne image ... },
#   "shadow": { ... nouvelle image uploadée ... },
#   "tftp_armed": true,
#   ...
# }
```

### Workflow 2: Test via TFTP (Optionnel)

Aucun appel API nécessaire ! Le shadow est immédiatement disponible via TFTP.

```bash
# Sur la console U-Boot ESPRESSObin:
=> setenv serverip 10.55.0.2
=> setenv ipaddr 10.55.0.1
=> tftpboot $kernel_addr_r Image
=> booti $kernel_addr_r - $fdt_addr_r

# Les logs de démarrage apparaissent sur la console série via Eye Remote
```

Si le noyau de test panique ou échoue, redémarrer simplement : U-Boot chargera le slot **active** depuis le LUN USB (inchangé).

### Workflow 3: Promouvoir Shadow vers Active

Une fois que le shadow est testé et stable :

```bash
# 1. Obtenir JWT (déjà disponible depuis upload)
JWT=$(...)

# 2. Promouvoir shadow vers active
curl -X POST \
  -H "Authorization: Bearer $JWT" \
  http://10.55.0.1:8000/api/v1/eye-remote/boot-media/swap

# La réponse montre que active contient maintenant l'image RC1,
# l'ancien active est sauvegardé en r1, et shadow est effacé.

# 3. Redémarrer ESPRESSObin (ou cycle d'alimentation)
# U-Boot chargera maintenant le nouveau noyau depuis le LUN
```

### Workflow 4: Démarrage depuis LUN

Sur la console U-Boot ESPRESSObin :

```bash
=> usb start
=> usb tree

# Sortie:
# USB device tree:
#   1  Hub (480 Mb/s, 0mA)
#   |  ├─ 1.1 Mass Storage (active boot media)
#   └─ ...

=> fatload usb 0 $kernel_addr_r Image
=> fatload usb 0 $fdt_addr_r device-tree.dtb
=> fatload usb 0 $initrd_addr_r initrd.img
=> booti $kernel_addr_r $initrd_addr_r:$initrd_size $fdt_addr_r
```

### Workflow 5: Rollback vers version précédente

Si l'image active devient corrompue ou instable :

```bash
# 1. Vérifier les points de rollback disponibles
curl -H "Authorization: Bearer $JWT" \
  http://10.55.0.1:8000/api/v1/eye-remote/boot-media/state | \
  jq .rollback_available

# Sortie: ["r1", "r2", "r3", "r4"]

# 2. Rollback vers r1 (précédent le plus récent)
curl -X POST \
  -H "Authorization: Bearer $JWT" \
  http://10.55.0.1:8000/api/v1/eye-remote/boot-media/rollback?target=r1

# La réponse confirme que active est maintenant restauré depuis r1
# contenu r1 déplacé vers r2, r2→r3, r3→r4, r4 effacé

# 3. Redémarrer ESPRESSObin — démarre à nouveau l'ancien noyau
```

---

## Exigences des images

### Format

- **Supportés:** FAT16, FAT32, ext2, ext3, ext4
- **Recommandé:** FAT32 (compatibilité maximale U-Boot)

### Taille

- **Minimum:** 16 MiB (permet espace pour kernel + DTB + initrd)
- **Maximum:** 4 GiB (limite pratique du stockage de masse USB)
- **Typique:** 256 MiB–1 GiB

### Contenu

**Requis (pour démarrage LUN USB):**
- Image du noyau (`Image` pour arm64, `zImage` pour arm32)
- Binaire device tree (`device-tree.dtb` ou `<board>.dtb`)

**Optionnel:**
- Disque RAM initial (`initrd.img`)
- Variables d'environnement U-Boot
- Script de démarrage

**Exemple de structure FAT32:**
```
/Image                   ← Noyau (requis)
/device-tree.dtb        ← Device tree (requis)
/initrd.img             ← Initramfs (optionnel)
/uEnv.txt               ← Environnement U-Boot (optionnel)
/boot.scr               ← Script de démarrage (optionnel)
```

### Validation

L'Eye Remote valide les images lors de l'upload :

1. **Magic système de fichiers:** Vérifier les octets magic pour FAT ou ext
2. **Vérification de taille:** Imposer limites 16 MiB–4 GiB
3. **Extractibilité:** Pour TFTP, tenter d'extraire Image, dtb, initrd
4. **Digest SHA256:** Calculer et stocker pour suivi d'intégrité

Si la validation échoue, l'upload rejette avec 400 Bad Request.

---

## Configuration

### secubox.conf

L'Eye Remote bootstrap respecte les paramètres suivants dans `/etc/secubox/secubox.conf` :

```toml
[eye_remote]
enabled = true
bootstrap_enabled = true
bootstrap_root = "/var/lib/secubox/eye-remote/boot-media"
max_image_size_gb = 4
min_image_size_mb = 16

[eye_remote.tftp]
enabled = true
dnsmasq_config = "/etc/dnsmasq.d/secubox-eye-remote-tftp.conf"
port = 69

[eye_remote.gadget]
ecm_enabled = true
acm_enabled = true
mass_storage_enabled = true
```

### Configuration TFTP DHCP (dnsmasq)

**Fichier:** `/etc/dnsmasq.d/secubox-eye-remote-tftp.conf`

```ini
# Service TFTP pour bootstrap Eye Remote
enable-tftp
tftp-root=/var/lib/secubox/eye-remote/boot-media/tftp
tftp-port=69
listen-address=10.55.0.2
# Autoriser lecture depuis racine tftp uniquement (sécurité)
tftp-secure
# Augmenter timeout pour initrd volumineux
tftp-max-block-size=1024
```

### Ordre de mise sous tension

**Note:** Le gadget Eye Remote attache le LUN immédiatement au démarrage. L'U-Boot ESPRESSObin est responsable de détecter le LUN et d'initier `usb start`.

**Séquence recommandée:**
1. Mettre sous tension l'ESPRESSObin (U-Boot démarre, attend l'entrée utilisateur)
2. Brancher le câble USB OTG à l'Eye Remote
3. Attendre 2 secondes pour l'énumération USB
4. Appuyer sur Entrée sur U-Boot pour interrompre l'autoboot
5. Exécuter la commande `usb start`
6. Exécuter `fatload usb 0 ...` pour charger le noyau

---

## Dépannage

### Problème: "LUN non visible sur ESPRESSObin"

**Symptômes:**
- `usb start` n'affiche aucun périphérique de stockage de masse
- `usb tree` liste uniquement le hub, pas de LUN

**Diagnostic:**
```bash
# Sur Eye Remote (hôte):
ssh pi@eye-remote.local
systemctl status secubox-eye-remote-gadget

# Vérifier si l'arbre gadget existe:
ls -la /sys/kernel/config/usb_gadget/secubox/functions/mass_storage.usb0/
```

**Solutions:**
1. **Redémarrer le gadget:**
   ```bash
   systemctl restart secubox-eye-remote-gadget
   ```

2. **Vérifier que le symlink active existe:**
   ```bash
   ls -la /var/lib/secubox/eye-remote/boot-media/active
   # Doit pointer vers un fichier image réel
   ```

3. **Vérifier que le fichier est lisible:**
   ```bash
   ls -lah /var/lib/secubox/eye-remote/boot-media/images/
   # Les fichiers doivent avoir les permissions de lecture
   ```

4. **Vérifier physiquement la connexion USB:**
   - Utiliser le port DATA (milieu), pas le port PWR
   - Essayer un câble USB ou port différent
   - Vérifier qu'il n'y a pas de hub USB entre Eye Remote et ESPRESSObin

### Problème: "Timeout TFTP / Image non trouvée"

**Symptômes:**
- `tftpboot` se bloque ou signale "not found"
- Chemin racine TFTP incorrect

**Diagnostic:**
```bash
# Vérifier le service TFTP:
curl http://10.55.0.1:8000/api/v1/eye-remote/boot-media/tftp/status | jq .

# Vérifier le symlink shadow:
ls -la /var/lib/secubox/eye-remote/boot-media/tftp/

# Vérifier que dnsmasq TFTP est en cours d'exécution:
ps aux | grep dnsmasq
netstat -tlnup | grep :69
```

**Solutions:**
1. **Uploader d'abord une image vers shadow:**
   ```bash
   curl -X POST \
     -H "Authorization: Bearer $JWT" \
     -F "image=@debian-bookworm.img" \
     http://10.55.0.1:8000/api/v1/eye-remote/boot-media/upload
   ```

2. **Vérifier la connectivité réseau:**
   ```bash
   # Sur ESPRESSObin U-Boot:
   => ping 10.55.0.2
   # Devrait répondre avec l'IP de l'hôte
   ```

3. **Vérifier que l'extraction de fichier a réussi:**
   - L'état TFTP devrait montrer un tableau `files` non vide
   - Si l'image est brute (pas de système de fichiers), l'extraction doit échouer gracieusement
   - Utiliser le démarrage LUN à la place

### Problème: "Échec du swap / Timeout d'éjection LUN"

**Symptômes:**
- `POST /swap` retourne une erreur 500
- LUN reste bloqué dans le gadget

**Diagnostic:**
```bash
# Vérifier le verrou gadget:
lsof | grep /var/lib/secubox/eye-remote/boot-media/

# Vérifier le log gadget-setup.sh:
journalctl -u secubox-eye-remote-gadget -n 50

# Vérifier que le verrou fichier n'est pas tenu:
ps aux | grep eye-remote
```

**Solutions:**
1. **Forcer l'éjection via shell (attention !):**
   ```bash
   sudo /usr/sbin/gadget-setup.sh swap-lun ""
   sleep 0.5
   sudo /usr/sbin/gadget-setup.sh swap-lun \
     "/var/lib/secubox/eye-remote/boot-media/active"
   ```

2. **Redémarrer le service gadget:**
   ```bash
   systemctl stop secubox-eye-remote-gadget
   sleep 2
   systemctl start secubox-eye-remote-gadget
   ```

3. **Vérifier les processus obsolètes:**
   ```bash
   systemctl status secubox-eye-remote-api
   # Si le processus API détient le verrou, le redémarrer
   systemctl restart secubox-eye-remote-api
   ```

### Problème: "Système de fichiers invalide lors de l'upload"

**Symptômes:**
- `POST /upload` retourne 400 Bad Request
- Erreur: "Invalid filesystem" ou "Size out of range"

**Solutions:**
1. **Vérifier le format de l'image:**
   ```bash
   file debian-bookworm.img
   # Devrait afficher: FAT boot sector, x86 or x64 boot loader binary
   # ou: Linux rev 1.0 ext4 filesystem
   ```

2. **Vérifier la taille de l'image:**
   ```bash
   ls -lh debian-bookworm.img
   # Devrait être entre 16 MiB et 4 GiB
   ```

3. **Créer une image FAT32 valide si nécessaire:**
   ```bash
   # Créer une image FAT32 de 256 MiB
   fallocate -l 256M debian-bookworm.img
   mkfs.vfat -F32 debian-bookworm.img

   # Monter et copier les fichiers du noyau
   sudo mount debian-bookworm.img /mnt/boot
   sudo cp Image /mnt/boot/
   sudo cp device-tree.dtb /mnt/boot/
   sudo umount /mnt/boot
   ```

---

## Voir aussi

- **[Eye Remote Hardware](Eye-Remote-Hardware.md)** — Connexions physiques, affectation des broches
- **[Eye Remote Gateway](Eye-Remote-Gateway.md)** — Configuration réseau, DHCP/DNS
- **[Eye Remote Implementation](Eye-Remote-Implementation.md)** — Internals Python/Bash, structure du codebase
- **[Architecture Boot](Architecture-Boot.md)** — Architecture de démarrage globale pour SecuBox-Deb
- **[U-Boot Documentation](../eye-remote/uboot-bootcmd.md)** — Commandes U-Boot ESPRESSObin

---

**CyberMind · SecuBox-Deb · Eye Remote Bootstrap v2.1.0**

*Dernière révision: 2026-04-23 · Mainteneur: Gerald Kerma <gandalf@cybermind.fr>*
