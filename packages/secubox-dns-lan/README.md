<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
# secubox-dns-lan

Le DNS du réseau local d'une SecuBox (#1938) : drop-ins Unbound (écoute et accès sur le LAN, résolveur IPv6, vue locale du
sous-domaine de la box, noms redirigés vers des machines du LAN) et fichier systemd-networkd de l'adresse IPv6 stable.

## Utilisation

1. Copier `/usr/share/secubox/dns-lan/dns-lan.toml.exemple` vers `/etc/secubox/dns-lan.toml` et y mettre les adresses du site.
2. `secubox-dns-lan check` : compare le disque à ce que le TOML produirait (code 3 en cas d'écart).
3. `secubox-dns-lan generate` : écrit, valide par `unbound-checkconf`, recharge Unbound **seulement si la configuration effective
   change**. Si le contrôle échoue, les fichiers précédents sont restaurés et rien n'est rechargé.
4. `secubox-dns-lan status` : état lisible.

Le paquet n'applique jamais de valeurs par défaut : sans `/etc/secubox/dns-lan.toml`, le postinst ne génère rien.

## Fichiers générés

| Section du TOML | Fichier |
|---|---|
| `[lan]` | `<dossier unbound>/96-secubox-lan.conf` |
| `[ipv6]` | `<dossier unbound>/96-secubox-lan-ipv6.conf` et `dropin_reseau` (adresse stable) |
| `[vue_locale]` | `<dossier unbound>/96-secubox-gk2-local.conf` |
| `[[hote]]` | `<dossier unbound>/98-secubox-voicestudio-lan.conf` |

Les autres drop-ins Unbound (`97-mail-srv`, `98-secubox-lxc`, `99-secubox-wg`) restent à leurs paquets.
Chaque application effective est consignée dans `/var/log/secubox/audit.log` (module `dns-lan`).

## Garanties

- **Validation stricte** : adresses sans identifiant de zone (`%eth0`), sans adresse non spécifiée ; aucun réseau plus large que /8 (IPv4)
  ou /32 (IPv6) ; fichiers écrits confinés à `/etc/unbound/unbound.conf.d` et `/etc/systemd/network/<x>.network.d/`.
- **Un seul `generate` à la fois** (verrou `/run/lock/secubox-dns-lan.lock`), écriture atomique avec `fsync`, lien symbolique refusé.
- **Retour arrière** si le contrôle, l'écriture ou le rechargement échoue ; si une restauration échoue, la liste des fichiers non
  restaurés est donnée et auditée (`generate-echec-restauration`).
- **Rechargement ou redémarrage** : `unbound-control reload` ne rouvre pas les sockets, donc une écoute nouvelle (`interface:`)
  provoque un redémarrage d'Unbound ; un simple changement de contrôle d'accès ou de données se contente d'un rechargement.
- **Section retirée du TOML** : le fichier correspondant, s'il porte la marque « GÉNÉRÉ par secubox-dns-lan », est supprimé ; un
  fichier posé à la main n'est jamais touché.

## Limites

L'adresse EUI-64 de la box reste listée comme `interface:` ; elle change si le préfixe de l'opérateur change.

## Tests

`python -m pytest tests` ; le test de bout en bout avec le vrai `unbound-checkconf` est ignoré s'il n'est pas installé.
