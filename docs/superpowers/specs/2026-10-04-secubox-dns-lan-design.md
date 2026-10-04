<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
# secubox-dns-lan : le DNS du LAN dans un paquet (#1938)

## Problème

Sur gk2, cinq fichiers qui font le DNS du réseau local n'appartiennent à aucun paquet : quatre drop-ins
Unbound (`96-secubox-lan.conf`, `96-secubox-lan-ipv6.conf`, `96-secubox-gk2-local.conf`,
`98-secubox-voicestudio-lan.conf`) et le fichier systemd-networkd de l'adresse IPv6 stable
(`50-secubox-ipv6-stable.conf`). Une réinstallation de la box perd le DNS du LAN et l'IPv6 stable.

Hors périmètre, parce qu'ils ont déjà un propriétaire dans les sources : `97-mail-srv.conf`
(secubox-mail), `98-secubox-lxc.conf` et `99-secubox-wg.conf` (secubox-toolbox). Le split-horizon
`97-secubox-split-horizon.conf` (redirection de `mail.secubox.in`) relève du paquet mail : noté, pas traité ici.

## Décision (validée par le propriétaire le 2026-10-04)

Un paquet `secubox-dns-lan`, sans aucune adresse appliquée d'office. Les valeurs du site vivent dans
`/etc/secubox/dns-lan.toml`, que l'exploitant pose lui-même à partir d'un modèle livré
(`/usr/share/secubox/dns-lan/dns-lan.toml.exemple`, qui reproduit gk2) : le paquet ne crée pas ce fichier, pour
qu'une autre box ne reçoive jamais les adresses de gk2. La commande `secubox-dns-lan` génère les cinq fichiers à
partir de ce TOML.

## Comportement

- `secubox-dns-lan generate` : calcule les fichiers, sauvegarde l'état précédent, écrit chaque fichier de façon
  atomique, fait valider l'ensemble par `unbound-checkconf` (qui lit les chemins réels, donc pas de dossier d'essai),
  puis recharge. En cas d'échec du contrôle, les fichiers précédents sont restaurés octet pour octet (ou supprimés
  s'ils n'existaient pas) et rien n'est rechargé.
- Unbound n'est rechargé **que si la configuration effective change** (lignes hors commentaires). Un fichier dont
  seuls les commentaires diffèrent est réécrit sans recharger : une mise à jour sur gk2 ne coupe pas le DNS.
- `networkctl reload` seulement si le fichier de l'adresse IPv6 change effectivement.
- `secubox-dns-lan check` : compare l'état du disque à ce que le TOML produirait, code de sortie non nul en cas de
  dérive. `secubox-dns-lan status` : résumé lisible.
- Chaque application effective est consignée dans `/var/log/secubox/audit.log` (une ligne, ajout seul).
- Le postinst lance `generate` seulement si `/etc/secubox/dns-lan.toml` existe ; sinon il affiche la marche à suivre. Il ne bloque jamais l'installation : un échec est affiché et la
  configuration précédente est conservée.

## Ajouts issus de la relecture de sécurité

Adresses sans identifiant de zone ni valeur non spécifiée, réseaux trop larges refusés, chemins confinés, verrou unique,
retour arrière robuste (restauration fichier par fichier, échec audité), échec de rechargement = restauration, redémarrage
(et non rechargement) quand une écoute nouvelle apparaît, suppression des fichiers générés devenus orphelins, binaires en
chemin absolu, avertissement sur stderr si l'audit est inaccessible.

## Valeurs de départ (gk2)

Le TOML livré reproduit exactement l'état de gk2 : écoute `192.168.1.200`, accès `192.168.0.0/16`, IPv6 stable
`2a01:e0a:dec:c4e0::200/64` et l'adresse EUI-64 actuelle, accès `2a01:e0a:dec:c4e0::/64` et `fd0f:ee:b0::/64`,
vue locale `gk2.secubox.in.` → `192.168.1.200`, hôte `voicestudio.gk3.secubox.in.` → `192.168.1.9` (TTL 300).

## Limites assumées (v1)

- L'adresse EUI-64 reste listée comme `interface:` : à l'identique de gk2 aujourd'hui. Remplacer par `::0` et un
  `access-control` strict est un changement de comportement : second temps, dans une autre version.
- Pas de service ni d'API : outil root appelé à la main et par le postinst, donc ni AppArmor ni utilisateur dédié.
- Pas de rechargement automatique de systemd-networkd hors changement du fichier.

## Tests

Unitaires : le rendu du TOML de gk2 a les mêmes lignes effectives que les fichiers capturés sur la box
(`tests/fixtures/gk2/`) ; validation des entrées (adresse, CIDR, nom de domaine) ; décision de rechargement ;
rollback quand `unbound-checkconf` échoue ; idempotence ; audit. Un test de bout en bout lance le vrai
`unbound-checkconf` quand il est installé.
