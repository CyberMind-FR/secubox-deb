<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
# secubox-system-tuning

SecuBox System Tuning — swap + zram + memory/CPU caps for LXC.

Per-board memory tuning for SecuBox: configures a swap file in /data (boards typically ship with 0 swap and exhaust real memory under LXC load), and applies per-LXC-container cgroup MemoryHigh soft caps to throttle (not OOM-kill) runaway containers.

Captures the by-hand fix applied on gk2 on 2026-05-27 (#391) so other boards inherit it automatically. Idempotent: re-running the tuning script after editing the TOML config only diffs the deltas.

Configuration lives at /etc/secubox/tuning/{config.toml, lxc-memory-high.toml}. Apply with secubox-tuning-apply or wait for the next package upgrade.

Distinct from secubox-hardening (kernel sysctl + AppArmor + module blacklist for *security*) — this package is *performance* tuning: swap and cgroup soft limits.

## Budget mémoire des conteneurs (#3941)

**Règle.** Jamais `memory.high` (frein) sous `memory.max` (plafond) quand `memory.swap.max = 0`. Dès que la mémoire anonyme
approche le frein, le noyau n'a que les pages de fichiers à évincer : le conteneur relit son propre code sans fin, n'est
jamais tué, et toute la box paie. Mesuré sur gk2 (gitea, frein 384M sous 512M, échange à 0, 393 Mo anonymes) : 13 700
relectures de pages/s, conteneur bloqué 48 % du temps, pression mémoire de la box à 41 % ; frein retiré et échange borné à
256M, la box est à 0,5 % et gitea passe de 504 à 200 en 1 s.

- Un générateur de configuration LXC qui pose `memory.max` pose aussi `memory.swap.max`, **borné** (moitié du plafond par
  défaut, zram d'abord), jamais 0 ; `memory.high` n'est permis qu'avec cet échange borné.
- Un conteneur qui a son propre `memory.max` ne reçoit **jamais** de frein de `lxc-memory-high.toml` ; un frein hérité est
  retiré (configuration et cgroup). Les autres conteneurs sont traités comme avant. La valeur du TOML n'est pas modifiée.
- Une unité systemd ne combine pas `MemoryHigh` et `MemorySwapMax=0` (le plafond seul, sans frein, reste permis).
- `secubox-mail` tient seul le bloc du conteneur `mail` (1G, échange 256M : le plafond que compte la fenêtre #3925).
- Garde du dépôt : `tests/test_regle_memoire_paquets_3941.py` parcourt tous les paquets.

`/usr/sbin/secubox-lxc-memoire migrer [--dry-run] [conteneur...]` (lancé au `configure`) corrige les configurations
existantes : frein sous le plafond avec échange interdit (toute origine), ou lignes de l'ancien budget #496 (`# Phase 6.P`,
script `secubox-apply-lxc-memory-budget` retiré, qui ajoutait un commentaire à chaque passage). Une copie
`config.avant-3941` est gardée, les limites sont écrites à chaud, **aucun conteneur n'est redémarré**. Un échange interdit
sans cette signature est signalé comme choix local et laissé en place. Retour arrière : remettre la copie et les valeurs du
cgroup.

Paquet Debian : version `1.2.5-1~bookworm1`, architecture `all`.

## Contenu

- `etc/` : fichiers du module
- `sbin/` : exécutables
- `tests/` : tests

## Tests

2 fichier(s) de test. Lancer : `python3 -m pytest packages/secubox-system-tuning`.
