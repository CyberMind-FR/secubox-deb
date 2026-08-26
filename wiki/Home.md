<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# SecuBox-Deb

**Appliance cybersécurité libre, basée Debian**

CyberMind · Notre-Dame-du-Cruet, Savoie | [FR](Home-FR) | [DE](Home-DE) | [中文](Home-ZH)

---

SecuBox-Deb est une plateforme de sécurité réseau complète portée d'OpenWrt vers Debian bookworm. Le projet vise la certification ANSSI CSPN à horizon 2027. Toute la stack est libre, auditable, et conçue pour fonctionner sur du matériel que vous possédez déjà — c'est le principe BYOH (Bring Your Own Hardware).

L'architecture repose sur six modules canoniques organisés en chemin hamiltonien : `AUTH → WALL → BOOT → MIND → ROOT → MESH`. Chaque module expose une API REST FastAPI, le tout orchestré par un profile-generator hiérarchique YAML. La cryptographie s'appuie sur le framework GK·HAM-HASH ZKP à trois niveaux.

---

## 🔴 Démarrage rapide — Alpha3

> Tester, installer ou booter la pré-release **`v3.0.0-alpha`** (série *Alpha3*) — en machine virtuelle ou sur matériel réel arm64. Toutes les commandes se lancent depuis un clone du dépôt (`git clone` puis `cd secubox-deb`).

### 🖥️ A. En VM — le plus rapide (une commande)

VirtualBox amd64, image **téléchargée** depuis les releases GitHub, VM créée automatiquement :

```bash
bash image/create-vbox-vm.sh --download
# ou une release précise :  bash image/create-vbox-vm.sh --download v3.0.0-alpha.1
```

La VM redirige les ports invité 22/80/443 vers l'hôte. Accès :

```bash
ssh -p 2222 root@localhost           # console
# portail :  https://localhost:9443/
```

→ Détails, options (`--headless`, RAM/CPU, ports) : **[[Live-USB-VirtualBox]]**

### 🧪 B. En VM ARM64 émulée (QEMU — dev arm64)

```bash
# récupérer/construire une image arm64, puis :
bash image/create-qemu-arm64-vm.sh output/secubox-*-mochabin-bookworm.img --convert
```

Nécessite `qemu-system-aarch64` + `qemu-efi-aarch64` (`apt install qemu-system-arm qemu-efi-aarch64 ovmf`). → **[[QEMU-ARM64]]**

### 🔌 C. Sur matériel réel arm64 (MOCHAbin / ESPRESSObin)

```bash
# 1) Construire l'image (defaut : mochabin) :
sudo bash image/build-image.sh --board mochabin --out ./output
#    cibles : mochabin | espressobin-v7 | espressobin-ultra | vm-x64

# 2) Flasher sur SD/eMMC — VÉRIFIEZ le device (lsblk) avant dd :
sudo dd if=output/secubox-*-mochabin-bookworm.img of=/dev/sdX bs=4M status=progress conv=fsync
```

Ou **netboot U-Boot** (images `secubox-mochabin-bookworm.img.gz`) — voir **[[ARM-Installation]]** / **[[ESPRESSObin]]**.

**Premier boot** : `firstboot.sh` génère le secret JWT, importe la clé SSH depuis `/boot/authorized_keys` et applique le hostname depuis `/boot/hostname`.

### 📦 D. Par APT (sur une Debian bookworm arm64 existante)

```bash
curl -fsSL https://apt.secubox.in/install.sh | sudo bash
sudo apt update && sudo apt install secubox-hub   # + les modules voulus
```

### ✅ Vérifier que ça tourne

```bash
ssh root@<ip-secubox>
systemctl status 'secubox-*' --no-pager | head
```

Portail de services : `https://<ip>/` (ou `all.gk2.net` sur le LAN). Comptes maîtres : **gk2** (hôte) / **admin** (gestion). → **[[Installation]]** · **[[Hardware-Matrix]]**

---

## Démarrer

La documentation technique couvre l'installation sur différentes cibles matérielles et virtuelles.

- **[[Architecture]]** — Vue d'ensemble des six modules et de la stack technique
- **[[Hardware-Matrix]]** — Matrice de compatibilité BYOH par carte et SoC
- **[[Installation]]** — Guide d'installation complet (APT, Live USB, ARM)
- **[[Live-USB-VirtualBox]]** — Test rapide en machine virtuelle
- **[[QEMU-ARM64]]** — Émulation ARM sur x86 pour développement
- **[[Modules|MODULES-EN]]** — Documentation des 128 modules

---

## Soutenir le projet

SecuBox-Deb est un projet libre sans campagne de financement participatif, sans deadline, sans tier de récompense. Le modèle repose sur trois piliers indépendants.

- **[[Financing-Model]]** — Vue d'ensemble du modèle de financement
- **[[Support]]** — Dons shareware et canaux de contribution
- **[[Sponsor-a-Port]]** — Mécénat de portage pour nouvelles cibles matérielles
- **[[Acknowledgments]]** — Crédits donateurs et sponsors

---

## Statut

| Élément | Valeur |
|---------|--------|
| Version courante | v2.41.0 |
| Base Debian | bookworm (12) |
| Kernel | 6.6 LTS mainline |
| Paquets | 125 |
| Endpoints API | 2000+ |
| Dernière mise à jour matrice | 2026-05 |
| Dernier port livré | MOCHAbin (Armada 7040) |

---

## Cibles matérielles principales

| Carte | SoC | Profil | Usage |
|-------|-----|--------|-------|
| MOCHAbin | Armada 7040 | Full | Gateway entreprise |
| ESPRESSObin v7 | Armada 3720 | Lite | Routeur PME/domicile |
| ESPRESSObin Ultra | Armada 3720 | Lite+ | Routeur avec Wi-Fi |
| VM x86_64 | — | Full | Test/développement |
| QEMU ARM64 | Émulé | Full | Test ARM sur x86 |

Voir **[[Hardware-Matrix]]** pour la matrice complète avec statuts de support.

---

## Modules par stack

| Stack | Fonction | Modules principaux |
|-------|----------|-------------------|
| 🟠 AUTH | Authentification, ZeroTrust, MFA | auth, portal, users, nac |
| 🟡 WALL | Firewall, CrowdSec, WAF, IDS/IPS | crowdsec, waf, threats, ipblock |
| 🔴 BOOT | Déploiement, provisioning | cloner, vault, vm, rezapp |
| 🟣 MIND | IA, analyse comportementale, DPI | dpi, netifyd, ai-insights, soc |
| 🟢 ROOT | Système, CLI, hardening | core, hub, system, console |
| 🔵 MESH | Réseau, WireGuard, QoS | wireguard, haproxy, netmodes, turn |

---

## Liens

- [Dépôt GitHub](https://github.com/CyberMind-FR/secubox-deb)
- [Releases](https://github.com/CyberMind-FR/secubox-deb/releases)
- [Issues](https://github.com/CyberMind-FR/secubox-deb/issues)
- [CyberMind](https://cybermind.fr)

---

---

## Licence

**CMSD-1.0** (CyberMind Source-Disclosed License) — Code source lisible, droits réservés.

| ✅ Autorisé | ❌ Interdit |
|------------|------------|
| Lire et étudier le code | Utiliser en production |
| Compiler pour test/audit | Redistribuer ou créer des dérivés |
| Publier résultats de recherche sécurité | Intégrer dans d'autres produits |
| Citer en contexte académique/journalistique | Proposer en SaaS |

**ANSSI CSPN Ready** : Audits par laboratoires accrédités (CESTI, CC) autorisés sans autorisation préalable.

Voir [LICENCE-CMSD-1.0.md](https://github.com/CyberMind-FR/secubox-deb/blob/master/LICENCE-CMSD-1.0.md) (FR, référence) ou [LICENSE-CMSD-1.0.en.md](https://github.com/CyberMind-FR/secubox-deb/blob/master/LICENSE-CMSD-1.0.en.md) (EN).

---

*© 2024-2026 [CyberMind](https://cybermind.fr) · Gérald Kerma · Notre-Dame-du-Cruet, Savoie*
*Voir [[Acknowledgments]] pour les crédits contributeurs*
