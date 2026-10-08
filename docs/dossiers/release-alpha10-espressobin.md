<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
<!-- Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr> -->
# Release v3.0.0-alpha.10 — profils corrigés, essai sur ESPRESSObin (2026-10-09)

Objectif : tester sur une ESPRESSObin (Armada 3720, 1 à 2 Go) l'image **lite** issue de la refonte des profils (#2146).
Ce document prépare la release ; il ne la publie pas (le tag déclenche CI, images et publication : décision du propriétaire).

## Ce qui change depuis alpha.9
- **Profils** : lite = tous les modules de protection (+ routage, QoS, Freebox, certificats, Tor) ; isp = lite + opérateur + tout l'hébergement ; full = isp + le Hall
  et son contenu. Un module n'est que dans un profil. `secubox-lite` 1.5.0, `secubox-isp` 1.3.1, `secubox-full` 1.5.0 ; `secubox-full` s'installe sur amd64.
  Détail : `docs/PROFILS-COMPARATIF.md`.
- **Matrice des images** (`.github/scripts/matrice-images.py`) : l'ESPRESSObin ne bâtit plus que **lite**. `isp` porte l'hébergement (≈ 8 Go) et n'est plus le « socle de comparaison » des petites cartes.
- **Corrections livrées depuis alpha.9** : Hall (registre non vidé si `menu.json` manque, carte Actor sans double slicer, carte du monde sans bande à -15°), `sbx-actord`
  (`/stats` et `/overview` en double tampon), watchdog Lyrion sans relance en boucle, réveil ClamAV sans boucle, services onion dans `torrc.d`, historique mémoire (`secubox-metrics` 1.17),
  rapport WAF avec carte et vue d'ensemble.

## Conditions préalables (à lever avant le tag)
1. **Dépôt apt signé à jour.** `secubox-metrics` 1.17.0 et les correctifs `soc` 1.1.9, `webos` 1.5.12, `waf-ng` 1.19.2 sont dans le pool mais pas dans l'index :
   `reprepro -b /data/apt export` sur gk2 demande la passphrase de la clé (agent GPG à déverrouiller par le propriétaire).
2. **CI verte sur master** hors le contrôle d'en-têtes (corrigé, #2149) ; les 5 tests de `scripts/tests` rouges avant la refonte le restent (sockets chmod, relais du Hall).
3. **Mémoire de gk2 confirmée stable** : relevés de `/api/v1/metrics/memory/history` (le noyau non récupérable doit rester sous 200 Mo après le reboot du 2026-10-08).

## Déclenchement
- Tag : `git tag v3.0.0-alpha.10 && git push origin v3.0.0-alpha.10` → `release.yml` (suite trixie : paquets, images, publication). Ou `workflow_dispatch` avec `version=v3.0.0-alpha.10`,
  `build_images`, `publish`, `suite=trixie`.
- Images attendues pour la carte : `secubox-lite-espressobin-v7-trixie.img.gz` (+ `SHA256SUMS`). Pour l'Ultra : `workflow_dispatch` de `build-image.yml` avec `board=espressobin-ultra`.
- Le contrôle `verify-profile.sh` refuse l'image si un paquet de `secubox-lite` manque : les 43 dépendances de lite existent en arm64/all dans l'index apt (vérifié le 2026-10-09).

## Protocole d'essai sur l'ESPRESSObin
1. Écrire l'image sur SD/eMMC (voir `docs/FIRST-BOOT.md`), démarrer, noter l'heure du premier démarrage.
2. À T+5 min puis T+30 min : `free -m`, `swapon --show`, `uptime`, `systemctl --failed`, `systemd-analyze blame | head`, et la mémoire noyau (`grep SUnreclaim /proc/meminfo`).
3. Lire `/api/v1/metrics/memory/history?heures=1` : alertes et croissance du noyau.
4. Vérifier que le WAF (`sbxwaf`), Unbound, HAProxy, nftables (`DEFAULT DROP`) et WireGuard sont actifs, et que le Hall répond.
5. Mesurer ce qui ne tient pas : les services mesurés pour lite sur gk3 pèsent ≈ 2,1 Go (agrégateur 127 Mo, security-posture 117 Mo, annuaire + openpgp 178 Mo, toolbox 91 Mo, DPI 79 Mo, mediaflow 107 Mo).
   **La cible 1-2 Go de la carte est probablement trop juste pour lite en l'état** : c'est précisément ce que l'essai doit chiffrer. Leviers déjà en place : swap 512 Mo, `secubox-profiles`
   (palier lite, mise en sommeil des modules inactifs), DPI passif seulement. Si l'essai cale, la décision à prendre est de retirer `toolbox`, `annuaire`/`mediaflow` de lite, ou de viser 4 Go.

## Risques connus
- Lite a grossi (routage, QoS, Freebox, certificats, Tor, coffre, sauvegarde, SOC) : plus lourd que l'ancien lite annoncé pour 2 Go.
- `secubox-sentinelle-gsm` (arm64) n'est qu'en Recommends de lite : absent d'une image construite sans Recommends.
