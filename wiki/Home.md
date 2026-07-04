# SecuBox-Deb

**Appliance cybersécurité libre, basée Debian**

CyberMind · Notre-Dame-du-Cruet, Savoie | [FR](Home-FR) | [DE](Home-DE) | [中文](Home-ZH)

---

SecuBox-Deb est une plateforme de sécurité réseau complète portée d'OpenWrt vers Debian bookworm. Le projet vise la certification ANSSI CSPN à horizon 2027. Toute la stack est libre, auditable, et conçue pour fonctionner sur du matériel que vous possédez déjà — c'est le principe BYOH (Bring Your Own Hardware).

L'architecture repose sur six modules canoniques organisés en chemin hamiltonien : `AUTH → WALL → BOOT → MIND → ROOT → MESH`. Chaque module expose une API REST FastAPI, le tout orchestré par un profile-generator hiérarchique YAML. La cryptographie s'appuie sur le framework GK·HAM-HASH ZKP à trois niveaux.

---

## Démarrer

La documentation technique couvre l'installation sur différentes cibles matérielles et virtuelles.

- **[[Architecture]]** — Vue d'ensemble des six modules et de la stack technique
- **[[Hardware-Matrix]]** — Matrice de compatibilité BYOH par carte et SoC
- **[[Installation]]** — Guide d'installation complet (APT, Live USB, ARM)
- **[[Live-USB-VirtualBox]]** — Test rapide en machine virtuelle
- **[[QEMU-ARM64]]** — Émulation ARM sur x86 pour développement
- **[[Modules|MODULES-EN]]** — Documentation des 125 paquets

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
| Version courante | v2.2.4-pre1 |
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
