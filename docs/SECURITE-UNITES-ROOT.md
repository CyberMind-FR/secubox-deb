<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Registre des unités systemd exécutées en root

Vague 0 du plan de simplification (`docs/dossiers/simplification-modules-beta.md`, issue #2050). La règle du projet est
« un utilisateur dédié et un profil AppArmor par service ». Le 2026-10-06, **21 paquets** livrent une unité en
`User=root` (au moins 24 unités) ; aucune n'est confinée par `NoNewPrivileges` sauf deux. **Cette liste ne doit jamais s'allonger** :
`scripts/tests/test_unites_root_2050.py` échoue si un nouveau paquet y entre. Pour en retirer un, on le supprime à la fois
de ce registre et de la liste du test.

## Serveurs d'API en root (15) — le vrai risque, à corriger en priorité

Ces unités exposent une API (socket Unix, protégée par JWT) avec tous les privilèges de la machine : une faille de l'API
vaut une prise de contrôle. Cible : utilisateur `secubox-<module>`, `AmbientCapabilities` minimales, et un assistant root
étroit (`sudo -n /usr/sbin/<module>ctl …`, sudoers exact) pour les seules opérations privilégiées.

| Paquet | Pourquoi root aujourd'hui (à vérifier) | Cible | Priorité |
|---|---|---|---|
| `qos` (+ `traffic`, composant depuis #2050) | `tc` (qdisc root), nft | `CAP_NET_ADMIN` seule ; **un seul propriétaire du qdisc root** (conflit connu entre les deux) | haute |
| `nettweak` | sysctl | `CAP_SYS_ADMIN` ciblée ou assistant `nettweakctl` | haute |
| `routes` (composant `netdiag` depuis #2050 ; l'unité `netdiag` seule est en root) | ping, traceroute, nmap (sockets bruts) | `CAP_NET_RAW`, utilisateur dédié | haute |
| `haproxy` (composant `exposure` depuis #2050 ; l'unité `exposure` seule est en root) | édite `/etc/tor/torrc` et `/etc/nftables.conf` par regex, snippets nginx | assistant root étroit ; **fin des éditions par regex** (drop-ins uniquement) | haute |
| `cookies` | capture MITM, clé de capture | utilisateur dédié, clé en lecture seule | haute |
| `threatmesh` | nft + WireGuard ; **écoute sur `0.0.0.0:8780`** (les pairs du maillage y postent par `wg*` ; la table nft ne laisse passer que `lo` et `wg*`) | utilisateur dédié, liaison à l'adresse du maillage et à `127.0.0.1` | haute |
| `admin`, `ksm` | mises à jour, redémarrage, sysfs KSM | assistants dédiés ; `ksm` : capacité sur `/sys/kernel/mm/ksm` | moyenne |
| `certs` | ACME, écriture des certificats | utilisateur dédié + accès en écriture ciblé | moyenne |
| `mail` | pilote le LXC du courrier | assistant LXC (modèle `voicestudioctl`) | moyenne |
| `vm`, `netboot`, `backup` (+ `cloner`, composant depuis #2050) | virtualisation, TFTP/dnsmasq, imagerie disque | privilégiés par nature : confiner (AppArmor, `ReadWritePaths`, `NoNewPrivileges` hors LXC) | moyenne |
| `interceptor` | rôle flou (voir le dossier : candidat à l'archivage) | auditer puis archiver ou durcir | basse |

## Tâches ponctuelles ou démons d'infrastructure en root (9) — justifiés, à confiner

| Paquet | Unité | Justification |
|---|---|---|
| `aggregator` | `secubox-group-root@` | groupe volontairement root (isolation par groupe) ; livrée par `groupd` jusqu'à #2050 N1 |
| `health` | `secubox-module-prober` | sondes de services (`systemctl`) |
| `led-heartbeat` | `secubox-led-heartbeat` | accès matériel (LED) |
| `metrics` | `secubox-geoipupdate` | `oneshot` ; déjà `NoNewPrivileges=true` |
| `profiles` | `secubox-sleeper` | arrête et démarre des unités ; déjà `NoNewPrivileges=true` |
| `threatmesh` | `secubox-threatfeed` | `oneshot`, écrit la liste de blocage nft |
| `toolbox` | `secubox-blacklist-attrib`, `-sync`, `secubox-escalate` | `oneshot`, nft |
| `mqtt` | `secubox-zigbee-backup` (composant zigbee, #2050) | `oneshot`, sauvegarde du LXC |

## Autres écarts à la règle relevés en passant

- Aucun profil AppArmor dédié pour la grande majorité des modules (seuls `macro`, `waf-ng`, `webfilter`, `eye-square`) ;
  `common/apparmor/` ne contient que cinq profils génériques ; les conteneurs LXC utilisent `lxc.apparmor.profile = generated`.
- 118 unités tournent sous le compte partagé `secubox` plutôt que sous un compte propre.
- `surf` (TCP 9082) et `mesh` (TCP 8743) écoutent en TCP local au lieu d'un socket Unix.
