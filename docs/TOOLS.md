# SecuBox-DEB — Build & Generation Tools

Référence complète des outils de build, génération et déploiement.

---

## Quick Reference

| Catégorie | Script | Description |
|-----------|--------|-------------|
| **Image Build** | `image/build-image.sh` | Image disque ARM64/x64 |
| **Image Build** | `image/build-live-usb.sh` | Live USB amd64 |
| **Image Build** | `image/build-ebin-live-usb.sh` | Live USB ESPRESSObin |
| **Image Build** | `image/build-rpi-usb.sh` | Image Raspberry Pi |
| **Image Build** | `image/build-installer-iso.sh` | ISO hybride installer |
| **Eye Remote** | `remote-ui/round/build-eye-remote-image.sh` | Image Pi Zero W |
| **Eye Remote** | `remote-ui/round/build-storage-img.sh` | Storage ESPRESSObin |
| **Eye Remote** | `build-eye-remote-full.sh` | Pipeline complet |
| **Packages** | `scripts/build-packages.sh` | Build tous les .deb |
| **Packages** | `scripts/build-all.sh` | Build + deploy |
| **Deploy** | `scripts/deploy.sh` | Déploiement SSH |
| **VM** | `scripts/run-qemu.sh` | Test QEMU |
| **VM** | `scripts/run-vbox.sh` | Test VirtualBox |

---

## 1. Image Build Scripts

### `image/build-image.sh`

Build d'images disque pour ARM64/x64 via debootstrap.

```bash
sudo bash image/build-image.sh --board mochabin --slipstream
sudo bash image/build-image.sh --board vm-x64 --vdi
```

**Boards supportés:** `mochabin`, `espressobin-v7`, `espressobin-ultra`, `vm-x64`, `vm-arm64`

**README:** [image/README.md](../image/README.md)

---

### `image/build-live-usb.sh`

Build d'image Live USB bootable pour x64 avec UEFI + Legacy BIOS.

```bash
sudo bash image/build-live-usb.sh --local-cache
```

**Features:** Plymouth boot, kiosk mode, persistence

---

### `image/build-ebin-live-usb.sh`

Build d'image Live USB pour ESPRESSObin V7 avec flasher eMMC intégré.

```bash
sudo bash image/build-ebin-live-usb.sh --embed-image output/secubox-ebin.img.gz
```

**Features:** Slipstream SecuBox packages, SquashFS, U-Boot boot

---

### `image/build-installer-iso.sh`

Build d'ISO hybride (live + installer headless).

```bash
sudo bash image/build-installer-iso.sh --slipstream --preseed config.tar.gz
```

---

### `image/build-rpi-usb.sh`

Build d'image pour Raspberry Pi 400 (ARM64).

```bash
sudo bash image/build-rpi-usb.sh --local-cache --kiosk
```

---

## 2. Eye Remote Build Scripts

### `build-eye-remote-full.sh`

**Pipeline complet** : build debs + storage + Pi Zero image.

```bash
sudo bash build-eye-remote-full.sh
```

**Étapes:**
1. Build tous les packages SecuBox (.deb)
2. Build storage.img ESPRESSObin (avec modules)
3. Build image Pi Zero W (avec storage embarqué)

---

### `remote-ui/round/build-eye-remote-image.sh`

Build d'image SD pour Pi Zero W + HyperPixel 2.1 Round.

```bash
sudo bash remote-ui/round/build-eye-remote-image.sh \
    --embed-storage output/eye-remote-storage.img
```

**Features:**
- Base Raspberry Pi OS Lite (armhf)
- HyperPixel 2.1 Round display config
- USB OTG gadget (ECM + ACM + mass_storage)
- Storage ESPRESSObin embarqué

---

### `remote-ui/round/build-storage-img.sh`

Build d'image storage ESPRESSObin avec SecuBox slipstreamé.

```bash
sudo bash remote-ui/round/build-storage-img.sh
```

**Sources packages:**
- `output/debs/` (prioritaire)
- `~/.cache/secubox/debs/` (fallback)

**README:** [remote-ui/round/README.md](../remote-ui/round/README.md)

---

## 3. Package Build Scripts

### `scripts/build-packages.sh`

Build tous les packages SecuBox en .deb.

```bash
bash scripts/build-packages.sh
bash scripts/build-packages.sh --package secubox-hub
```

---

### `scripts/build-all.sh`

Build complet + déploiement sur cible.

```bash
bash scripts/build-all.sh
```

---

### `scripts/build-all-local.sh`

Build local avec cache APT.

```bash
bash scripts/build-all-local.sh
```

---

### `scripts/build-add-local.sh`

Ajouter un package au repo local.

```bash
bash scripts/build-add-local.sh secubox-hub
```

---

## 4. Deploy Scripts

### `scripts/deploy.sh`

Déployer packages sur cible via SSH.

```bash
bash scripts/deploy.sh secubox-hub root@192.168.1.1
```

---

### `remote-ui/round/deploy.sh`

Déployer dashboard sur Pi Zero W.

```bash
./remote-ui/round/deploy.sh -h 10.55.0.2 --api-url http://10.55.0.1:8000
```

---

### `remote-ui/round/install_zerow.sh`

Flasher et configurer SD pour Pi Zero W.

```bash
sudo ./remote-ui/round/install_zerow.sh \
    -d /dev/mmcblk0 \
    -i raspios-lite.img.xz \
    -s "WiFi_SSID" -p "password" \
    -r  # USB OTG
```

---

## 5. VM & Test Scripts

### `scripts/run-qemu.sh`

Lancer une image dans QEMU.

```bash
bash scripts/run-qemu.sh output/secubox-vm-x64.img
```

---

### `scripts/run-vbox.sh`

Lancer VM VirtualBox.

```bash
bash scripts/run-vbox.sh
```

---

### `image/create-vbox-vm.sh`

Créer une VM VirtualBox configurée.

```bash
bash image/create-vbox-vm.sh output/secubox.vdi --ram 4096
```

---

### `image/create-qemu-arm64-vm.sh`

Créer VM QEMU ARM64 pour tests.

```bash
bash image/create-qemu-arm64-vm.sh output/secubox-arm64.qcow2
```

---

## 6. Utility Scripts

### `scripts/new-package.sh`

Scaffold nouveau package SecuBox.

```bash
bash scripts/new-package.sh secubox-mymodule
```

---

### `scripts/new-module.sh`

Scaffold nouveau module avec API FastAPI.

```bash
bash scripts/new-module.sh mymodule
```

---

### `scripts/port-frontend.sh`

Porter frontend LuCI depuis secubox-openwrt.

```bash
bash scripts/port-frontend.sh crowdsec-dashboard
```

---

### `scripts/setup-local-cache.sh`

Configurer apt-cacher-ng + repo local.

```bash
sudo bash scripts/setup-local-cache.sh
```

---

### `scripts/local-repo-add.sh`

Ajouter package au repo local.

```bash
bash scripts/local-repo-add.sh output/debs/secubox-core_1.0.0.deb
```

---

## 7. Generation Scripts

### `repo/scripts/generate-gpg-key.sh`

Générer clé GPG pour signature APT.

```bash
bash repo/scripts/generate-gpg-key.sh
```

---

### `image/scripts/generate-plymouth-assets.sh`

Générer assets Plymouth boot splash.

```bash
bash image/scripts/generate-plymouth-assets.sh
```

---

## 8. Fix & Maintenance Scripts

| Script | Description |
|--------|-------------|
| `scripts/fix-navbar.sh` | Fix navbar modules |
| `scripts/fix-emoji-fonts.sh` | Install emoji fonts |
| `scripts/fix-namespace-errors.sh` | Fix Python namespace |
| `scripts/ui-fix-checker.sh` | Vérifier UI modules |
| `scripts/retrofit-nginx-modular.sh` | Update nginx config |
| `scripts/update-nginx-modular.sh` | Update nginx modular |

---

## 9. Clone & Export Scripts

### `image/build-c3box-clone.sh`

Cloner configuration d'un C3Box existant.

```bash
sudo bash image/build-c3box-clone.sh --host 192.168.1.100
```

---

### `image/export-c3box-clone.sh`

Exporter configuration pour clonage.

```bash
bash image/export-c3box-clone.sh --host localhost --port 2222
```

---

### `scripts/export-preseed.sh`

Exporter preseed configuration.

```bash
bash scripts/export-preseed.sh
```

---

## README Status

| Directory | README | Status |
|-----------|--------|--------|
| `image/` | [README.md](../image/README.md) | OK |
| `scripts/` | [README.md](../scripts/README.md) | OK |
| `remote-ui/` | [README.md](../remote-ui/README.md) | OK |
| `remote-ui/round/` | [README.md](../remote-ui/round/README.md) | OK |
| `repo/` | [README.md](../repo/README.md) | OK |

---

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SECUBOX_BOARD` | Target board | `vm-x64` |
| `SECUBOX_SUITE` | Debian suite | `bookworm` |
| `SECUBOX_OUT` | Output directory | `./output` |
| `C3BOX_HOST` | Clone target host | `localhost` |
| `C3BOX_PORT` | Clone SSH port | `2222` |

---

## Author

Gerald KERMA <devel@cybermind.fr>
https://cybermind.fr | https://secubox.in
