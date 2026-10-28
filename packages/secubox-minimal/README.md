<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# secubox-minimal

Méta-paquet du profil **minimal**, pour une petite carte (ESPRESSObin, 1 Go) tenue en **boîtier de garde sans tête**.

## Contenu

Garde DNS, filtre de publicités, NAC, Freebox, garde IPv6, filtrage web, WireGuard (`secubox-wireguard` >= 1.3.0, sortie Internet
pour clients distants), agent Auto-Load (il tire `secubox-profiles` et `secubox-premier-pas`, donc la CLI `secubox-profilectl`, le
sleeper et le waker), et le seul socle d'administration (core, aggregator, system, hardening, hub, portal, auth). annuaire et p2p
(maillage) arrivent par les `Recommends` de premier-pas.

## Exclusions (`Conflicts`)

- `secubox-webos` (Hall), `secubox-waf-ng` et `secubox-waf` (le WAF reste sur l'infrastructure), `secubox-metrics`, `secubox-toolbox`.
  Un `Recommends` de `secubox-auth` ou de `secubox-freebox` ramenait le Hall : le `Conflicts` est le seul moyen de dire à apt de ne
  pas le reprendre.
- `secubox-dpi`, `secubox-ndpid-engine`, `secubox-courbes`, `secubox-routes` (#3218, banc de l'ESPRESSObin gk5 le 2026-10-28) :
  nDPId prenait tout le CPU, le DPI sans lui n'affiche rien ; Courbes et netdiag (livré par `secubox-routes`) sont des surplus.
  En `Conflicts` et non simplement retirés : la mise à jour du méta-paquet les **retire** des box (majauto installe par
  `apt-get install --only-upgrade`, qui retire un paquet en conflit).

Pas de `Conflicts` sur `haproxy` (paquet Debian) : il n'est tiré par aucun paquet du profil ; c'est le constructeur d'image qui le
préinstallait (#3218, corrigé dans `image/build-image.sh`).

## Ce que le méta-paquet ne peut pas exclure

Certains surplus sont des **composants** d'un paquet du socle, livrés dans le même `.deb` : `admin` et `ksm` (`secubox-system`),
`network-anomaly` et sa collecte (`secubox-dns-guard`), l'API `profiles`, `profiles-releve` et `cache-warm@*` (`secubox-profiles`,
exigé par l'agent Auto-Load), `netstats` (`secubox-hub`), `metrics-publish` (`secubox-annuaire`), le service `secubox-portal`
(son paquet livre `login.html`). Ils sont arrêtés et désactivés par le **profil d'activation**, pas par apt.

## Profil d'activation

`packages/secubox-profiles/profiles/minimal.toml` : ce que `secubox-profilectl apply --profile minimal` laisse allumé (`on`), les
minuteries qu'il arrête (`minuteurs_off`), l'API protégée qu'il coupe (`proteges_off = ["profiles"]`, la CLI reste) et les entrées
de menu qu'il masque (`menu_off`). Il doit rester le miroir de ce méta-paquet.

## Historique d'essai

0.4.0 avait ajouté HAProxy et le WAF : sur 951 Mo, la carte a saturé (swap plein, charge > 10, deux coupures franches). Retirés en 0.5.0 (#2849).
0.10.0 (#3218) : banc gk5 — swap de 819 à 489 Mo, PSS Python de 1012 à 646 Mo une fois DPI, surplus, haproxy et portal arrêtés.
Voir `docs/FAQ-ESPRESSOBIN-1GO.md`.

## Tests

`pytest packages/secubox-minimal/tests` : fermeture des dépendances (aucun module exclu, même indirect), `Conflicts`, retrait de
DPI, nDPId, Courbes et Routes (#3218).
