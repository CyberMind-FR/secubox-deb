<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# SecuBox

## Votre réseau. Vos règles.
### Your network. Your rules.

<p align="center">
  <img src="https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/assets/poster/secubox-affiche-bilingue.jpg" alt="SecuBox — Reprenez le contrôle de votre réseau. Your network. Your rules. Affiche illustrative en pâte à modeler 2D½" width="900">
</p>

> *Affiche illustrative : elle représente des fonctions et une interface imaginées. L'état réel de chaque composant est détaillé dans « Où en est-on ? » ci-dessous.*

**[FR](#fr) · [EN](#en) · [中文](Home-ZH)** | **CyberMind · Gondwana · Notre-Dame-du-Cruet · Savoie**

| Code source | Documentation | Discuter avec CyberMind |
|---|---|---|
| Dépôt public et suivi du développement<br>[github.com/CyberMind-FR/secubox-deb](https://github.com/CyberMind-FR/secubox-deb) | Architecture, composants, installation et limites connues.<br>[Cette wiki](Home) · [Architecture-Modules](Architecture-Modules) | Retours techniques, essais, partenariats et contributions.<br>[Signaler ou proposer (issues)](https://github.com/CyberMind-FR/secubox-deb/issues) · [cybermind.fr](https://cybermind.fr) |

---

<a id="fr"></a>
## FR 🇫🇷

SecuBox est un projet de sécurité réseau et d'hébergement souverain, construit sur Debian 13 Trixie. Son ambition : rendre les outils de sécurité et d'autonomie numérique accessibles aux particuliers, aux associations et aux petites organisations.

Le projet dispose déjà de briques fonctionnelles et d'un prototype opérationnel. Les composants n'ont pas tous le même niveau de maturité : certains sont utilisables, d'autres continuent d'évoluer.

**Nos objectifs**
- Protéger les réseaux et les services.
- Réduire le pistage et les sollicitations publicitaires indésirables.
- Héberger ses propres outils et maîtriser ses données.
- Relier des sites et des équipements de manière sécurisée.
- Construire une plateforme modulaire, auditable et évolutive.

**Le projet est ouvert à la discussion.** Testeurs, développeurs, experts en sécurité, associations et curieux : vos retours sont les bienvenus. Explorez le code, posez des questions, signalez les limites et proposez vos idées.

**Tester · Contribuer · Échanger · Partager**

<a id="en"></a>
## EN 🇬🇧

SecuBox is a network security and sovereign hosting project built on Debian 13 Trixie. Its ambition is to make digital security and autonomy more accessible to individuals, associations and small organizations.

A working prototype and functional components already exist. Components have different maturity levels: some are usable, while others remain under active development.

**Our goals**
- Protect networks and hosted services.
- Reduce tracking and unwanted advertising.
- Host your own tools and retain control of your data.
- Securely connect sites and devices.
- Build a modular, auditable and evolving platform.

**SecuBox welcomes open discussion.** Testers, developers, security experts, associations and curious minds are invited to explore the code, ask questions, report limitations and share ideas.

**Test · Contribute · Discuss · Share**

---

## Où en est-on ? / Where are we?

*État au 19 octobre 2026, à relire avant publication. SecuBox n'est ni certifié ni prêt pour tous les usages ; la certification CSPN (ANSSI) est un objectif, pas un acquis.*

| Niveau | Composants | Remarque |
|---|---|---|
| **Utilisable** (en service sur une box d'infrastructure) | Administration web, pare-feu nftables en refus par défaut, WAF `sbxwaf` derrière HAProxy TLS 1.3, filtrage DNS et publicités, WireGuard et maillage pair à pair, services en conteneurs LXC (courrier, fichiers, messagerie, dépôt de code, média) | Testé sur MOCHAbin et x86. Les mises à jour sont encore fréquentes. |
| **En test** | Détection et classification DPI (nDPId), préparation automatique des cartes (Auto-Load), profil « minimal » pour cartes de 1 Go (ESPRESSObin) | Le DPI est gourmand en mémoire et ses résultats ne sont pas à considérer comme une preuve d'attaque. Sur 1 Go, le WAF et HAProxy saturent la carte : ils sont exclus du profil minimal. |
| **Conception** | Pare-feu par zones (physiques et par appareil), publication et rattachement automatiques des cartes | Pas encore codé ou pas encore déployé. |

<p align="center">
  <img src="https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/assets/poster/secubox-affiche-ateliers.jpg" alt="SecuBox — Votre réseau. Vos règles. Les sept ateliers : réseau, sécurité, services, média, communication, IA et outils, système" width="900">
</p>

> *Seconde affiche : les « ateliers » sont une présentation illustrée. Dans l'administration, les modules sont regroupés en six espaces (vue d'ensemble, protection, surveillance, services, identité et accès, système).*

**Matériel.** MOCHAbin (Marvell 7040) et x86 : utilisés au quotidien. ESPRESSObin v7 (1 Go) : installable avec un profil allégé, voir le [guide d'installation](https://github.com/CyberMind-FR/secubox-deb/blob/master/docs/INSTALL-ESPRESSOBIN.md). Autres supports de l'affiche (Raspberry Pi 5, mini-PC Intel N100) : images prévues, à confirmer carte par carte.

---

## Qu'est-ce que SecuBox OS ?

SecuBox OS est un système d'exploitation durci orienté sécurité réseau :

| Fonction | Description |
|----------|-------------|
| **Firewall** | nftables DEFAULT DROP, règles automatiques |
| **WAF** | HAProxy + sbxwaf, 300+ règles ModSecurity |
| **VPN** | WireGuard natif, mesh P2P |
| **DNS** | Unbound Vortex, blocklists automatiques |

---

## 🔴 BOOT — Démarrage rapide

### VirtualBox (Recommandé)

```bash
# One-liner avec téléchargement auto
curl -sL https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/image/create-vbox-vm.sh | bash -s -- --download
```

Voir [[Live-USB-VirtualBox]] pour les détails.

### Live USB

```bash
wget https://github.com/CyberMind-FR/secubox-deb/releases/latest/download/secubox-live-amd64-bookworm.img.gz
zcat secubox-live-amd64-bookworm.img.gz | sudo dd of=/dev/sdX bs=4M status=progress
```

Voir [[Live-USB]] pour le guide complet.

### Installation APT

```bash
curl -fsSL https://apt.secubox.in/install.sh | sudo bash
sudo apt install secubox-full
```

---

## 🟠 AUTH — Accès

| Service | Utilisateur | Mot de passe | Port |
|---------|-------------|--------------|------|
| Web UI | admin | secubox | 9443 |
| SSH | root | secubox | 2222 |

---

## 🟢 ROOT — Matériel supporté

### ARM64 (Production)

| Board | SoC | Profil | Usage |
|-------|-----|--------|-------|
| MOCHAbin | Armada 7040 | Full | Entreprise, datacenter |
| ESPRESSObin v7 | Armada 3720 | Lite | PME, agences |
| ESPRESSObin Ultra | Armada 3720 | Lite+ | PME étendu |

### x86_64 (Dev/Test)

| Plateforme | Profil | Usage |
|------------|--------|-------|
| VirtualBox | Full | Développement |
| QEMU/KVM | Full | Test/CI |
| Bare metal | Full | Production x86 |

---

## 🟣 MIND — Stack modulaire

SecuBox OS est organisé en 6 stacks fonctionnelles :

| Stack | Code couleur | Modules clés |
|-------|--------------|--------------|
| 🟠 **AUTH** | Orange | auth, portal, nac, users |
| 🔴 **BOOT** | Rouge | cloner, vault, vm, backup |
| 🟣 **MIND** | Violet | dpi, ai-insights |
| 🟢 **ROOT** | Vert | core, hub, system, admin |
| 🔵 **MESH** | Bleu | wireguard, haproxy, qos, mesh |

Voir [[Modules]] pour les 125 modules.

---

## 🔵 MESH — Documentation

### Démarrage
- [[Live-USB-VirtualBox|VirtualBox]]
- [[Live-USB|USB Boot]]
- [[ARM-Installation|Boards ARM]]
- [[QEMU-ARM64|Émulation QEMU]]

### Configuration
- [[Configuration]]
- [[Configuration-Advanced]]
- [[Troubleshooting]]

### Architecture
- [[Architecture-Boot|Couches de boot]]
- [[Architecture-Modules|Design modulaire]]
- [[Architecture-Security|Modèle de sécurité]]

### Développement
- [[Developer-Guide]]
- [[Build-System|Build Images]]
- [[Design-System|UI/UX]]
- [[API-Reference]]

---

## 🟡 WALL — Sécurité

### Firewall & IDS
- **nftables** — DEFAULT DROP, règles dynamiques
- **Suricata** — Signatures ET Open

### WAF & Inspection
- **HAProxy** — TLS 1.3, load balancing
- **sbxwaf** — Inspection HTTPS transparente
- **300+ règles** — OWASP ModSecurity CRS

### AI & Threat Intel
- **AI-Insights** — Détection ML anomalies
- **Threat feeds** — AbuseIPDB, Emerging Threats
- **Geo-blocking** — Blocage par pays

---

## Addons

### 👁️ Eye Remote (Addon)

Dashboard USB gadget compact pour monitoring SecuBox.

| Composant | Description |
|-----------|-------------|
| Hardware | Pi Zero W + HyperPixel 2.1 Round (480×480) |
| Connexion | USB OTG (10.55.0.0/30) ou WiFi |
| Modes | Normal, Flash, Debug, TTY, Auth |

**Documentation :** [[Eye-Remote|Eye Remote Addon]]

```bash
# Build image Pi Zero W
cd remote-ui/round
sudo ./build-eye-remote-image.sh -i raspios-lite.img.xz
```

---

## Liens

- [GitHub](https://github.com/CyberMind-FR/secubox-deb)
- [Releases](https://github.com/CyberMind-FR/secubox-deb/releases)
- [APT Repository](https://apt.secubox.in)
- [CyberMind](https://cybermind.fr)

---

*© 2026 CyberMind · Notre-Dame-du-Cruet, Savoie*
