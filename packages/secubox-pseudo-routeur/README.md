<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
<!-- Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr> -->
# secubox-pseudo-routeur

gk2 devient la passerelle DHCP du LAN plat de la Freebox (#2940), filet de secours
(`sonde-secours`) armé avant toute bascule.

## Configuration

`/etc/secubox/pseudo-routeur.toml` (exemple :
`/usr/share/secubox/pseudo-routeur/pseudo-routeur.toml.example`) :

```toml
lan_if = "eth2"               # interface du LAN plat
lan_subnet = "192.168.1.0/24" # détection si lan_if absent
```

## Relais IPv6 par next hop Freebox (#3807)

La Freebox ignore la passerelle DHCP pour l'IPv6 et ne sait pas couper son IPv6 LAN ; elle
sait en revanche router son /64 principal vers un next hop lien-local
(`connection/ipv6/config/`, `delegations[0].next_hop`) et cesse alors de l'annoncer. Section
`[relais_ipv6]` de `pseudo-routeur.toml` ; `role` vide (défaut) : **rien n'est actif**, tous
les verbes sont sans effet. Chaque valeur est validée (`ipaddress` : lien-local fe80::/10 sans
zone, /64 global, adresse fixe dans le préfixe, RDNSS routable) avant tout usage.

| Clé | Exemple | Usage |
|---|---|---|
| `role` | `"routeur"` / `"repli"` / `"tout"` / `""` | rôle de cette box |
| `lan_if` | `"eth2"` | interface du LAN (sinon `lan_if` racine) |
| `fichier_network` | `"10-eth2.network"` | facultatif, sinon `networkctl status <lan_if>` |
| `prefixe` | `"2a01:e0a:dec:c4e0::/64"` | /64 principal de la Freebox |
| `adresse_fixe` | `"2a01:e0a:dec:c4e0::94/64"` | adresse du routeur (obligatoire pour `routeur`) |
| `passerelle_ll` | `"fe80::3a07:16ff:fe77:17d3"` | Freebox, route par défaut du routeur |
| `routeur_ll` | `"fe80::250:43ff:fe84:252f"` | lien-local du routeur = next hop (rôle `tout` : facultatif, lu sur `lan_if`) |
| `dns` | `"2a01:e0a:dec:c4e0::200"` | RDNSS annoncé |
| `sonde_cible` | `"2001:4860:4860::8888"` | cible externe de la sonde (obligatoire pour `repli`) |

**Rôle routeur (gk1)** — `pseudo-routeurctl relais6-preparer` : valide d'abord (`nft -c`,
`dnsmasq --test`) puis pose un drop-in networkd `<fichier>.network.d/zz-secubox-relais6.conf`
(`Address=` + `[Route] Gateway=` Freebox, appliqué par `networkctl reload` : jamais de lien
coupé ni de MTU changée), la table `inet secubox_relais6` (`/etc/nftables.d/zz-secubox-relais6.nft` :
redirections ICMPv6 sortantes sur `lan_if` jetées, transit `lan_if`→`lan_if` du préfixe
accepté) et l'instance dnsmasq `secubox-relais6-ra.service` (`/etc/secubox/relais6-ra.conf` :
`port=0`, pas de DHCPv4, `enable-ra`, `dhcp-range=::,constructor:<lan_if>,ra-stateless,64`,
`ra-param=<lan_if>,high,0`, RDNSS `option6:dns-server`). `relais6-retirer` retire les trois,
idempotent, sans lire le TOML. `relais6-etat` : pièces posées, adresse et route présentes.

**Rôle repli (gk2, connecteur Freebox)** — `relais6-basculer` (`POST /relais6/basculer`) ne
règle le next hop sur `routeur_ll` (`freeboxctl nexthop-regler`) que si la sonde passe
(`ping -6` de `routeur_ll%lan_if`, de l'adresse fixe et de `sonde_cible`), puis arme
`pseudo-routeur-relais6-sonde.timer` (60 s). Au 3e échec consécutif la sonde sort en erreur et
`OnFailure=` lance `pseudo-routeur-relais6-retour.service` → `relais6-revenir` (next hop
`vide`, minuterie désarmée ; toujours exécuté, même TOML cassé). Chaque écriture est
auditée (`relais6_*` dans `/var/log/secubox/audit.log`, `ipv6_next_hop` côté secubox-freebox).

**Rôle tout (gk2 seule, décision du propriétaire)** — la même box est routeur ET repli :
`relais6-preparer` (partie routeur) puis `relais6-basculer` / `relais6-revenir` et la sonde.
`routeur_ll` vide = lien-local de la box sur `lan_if`, lu à l'exécution et validé. Si
`adresse_fixe` est déjà configurée sur `lan_if` par un autre fichier (gk2 : `::200` par
`50-secubox-ipv6-stable.conf`), le drop-in ne la redéclare pas et ce fichier n'est jamais
touché ; seule la route par défaut via la Freebox est ajoutée. La sonde vérifie alors le
routage **local** : `net.ipv6.conf.all.forwarding=1`, `secubox-relais6-ra.service` actif, route
par défaut via `passerelle_ll` sur `lan_if`, ping d'une cible IPv6 externe ; 3 échecs →
`relais6-revenir` (fonctionne même annonces RA mortes).

> **Limite du rôle tout** : si gk2 tombe entièrement (panne, coupure secteur), plus rien ne
> peut rendre le next hop à la Freebox. La maison n'a plus que l'IPv4 jusqu'à ce que le next
> hop soit vidé à la main (interface Freebox : Paramètres → Configuration IPv6, ou
> `freeboxctl nexthop-regler vide` une fois gk2 revenue).

Écritures `relais6-*` et sonde sérialisées par `flock` sur `/run/lock/secubox-relais6.lock`.
`relais6-basculer` arme la sonde AVANT de régler le next hop (désarme si le réglage échoue) ;
`relais6-revenir` ne désarme la sonde qu'après un retour réussi (sinon elle le relance).
`relais6-preparer` défait tout (`relais6-retirer`) si une étape échoue après le drop-in.

## Chaîne forward (#3803)

Seul le trafic entré par `lan_if` est filtré ; br-lxc, wg et maillage sont acceptés
d'emblée. Policy `accept` : un appareil du LAN non classé garde Internet ; seuls
`blocked` et `quarantine_zone` du NAC sont jetés (copies locales = instantané pris à la
génération ; la chaîne forward de secubox-nac, priorité -5, reste celle qui fait foi).
Le fichier généré supprime puis
redéclare la table dans une seule transaction (activation idempotente) ;
`activer-transfert` écrit d'abord un temporaire `.zz-…tmp`, le valide par `nft -c`, puis
le renomme atomiquement (échec : fichier précédent intact). `retour-freebox` supprime la
table (échec signalé et audité, jamais bloquant) et le fichier persistant, puis rend le
DHCP à la Freebox ; `ip_forward=1` est laissé volontairement (les LXC en ont besoin).

## API

| Route | Garde | Rôle |
|---|---|---|
| `GET /etat` | lecture | comptes seuls `appareils_compte` {total, passes}, actif, depuis, passerelle distribuée (lue au connecteur Freebox), sonde + historique, compteurs `sbx_pr_forward_lan`/`sbx_pr_forward_rejete` ; `null` si non relevé |
| `GET /appareils` | admin | un appareil par MAC (`ip neigh` sur `lan_if`) : nom NAC, zone NAC, `passe_par_gk2` (MAC dans l'ensemble dynamique `vus_lan`, 15 min ; `null` si chaîne absente), `ipv6_actif` (booléen : la part IPv6 n'est pas mesurable par gk2) |
| `GET /apercu` | admin | voisins du LAN absents de tout ensemble NAC, à montrer avant activation (informatif : ils garderont Internet) |
| `POST /activer` | admin | bascule (refusée si la sonde n'est pas active) |
| `POST /retour` (alias `/retour-freebox`) | admin | retour à la Freebox, inconditionnel |
| `POST /tester-retour` | admin | essai à blanc du retour : étapes et faisabilité, ne modifie rien |
| `GET /suggestions` | admin | appareils vus par la Freebox, zone suggérée |
| `GET /journal` | admin | bascules de passerelle et de next hop IPv6 (audit.log) |
| `GET /relais6` | admin | relais IPv6 : rôle, next hop lu, sonde (repli) ou pièces posées (routeur) |
| `POST /relais6/basculer` | admin | next hop du /64 vers le routeur, si la sonde passe (409 sinon) |
| `POST /relais6/revenir` | admin | next hop rendu à la Freebox, inconditionnel |

`GET /apercu` → `{"lan_if": "eth2", "non_classes": [{"ip": "...", "mac": "..."}], "note": "..."}`
