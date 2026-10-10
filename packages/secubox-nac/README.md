<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# 🛡️ Network Access Control

Client guardian and NAC with quarantine

**Category:** Security

## Screenshot

![Network Access Control](../../docs/screenshots/vm/nac.png)

## Features

- Device control
- MAC filtering
- Quarantine
- VLAN assignment

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-nac
```

## Configuration

Configuration file: `/etc/secubox/nac.toml`

## API Endpoints

- `GET /api/v1/nac/status` - Module status
- `GET /api/v1/nac/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).


## Application réseau du blocage et des zones (#1766)

L'API tourne sans privilège (`NoNewPrivileges`, aucune capacité) : elle n'appelle jamais `nft`.

1. Bloquer / mettre en quarantaine / changer de zone écrit l'**état voulu** dans
   `/var/lib/secubox/nac/nft-desired.json` (écriture atomique, verrouillée).
2. `secubox-nac-apply.path` voit le changement et lance `secubox-nac-apply` (root, étroit :
   `CAP_NET_ADMIN` seul). Il **valide chaque MAC et chaque nom d'ensemble**, puis charge en une
   transaction les règles `/etc/nftables.d/secubox-nac.nft` et les éléments.
3. Au démarrage de nftables (et à chaque redémarrage), le service reconstruit la table.

| Ensemble | Effet |
|---|---|
| `blocked` | rien n'entre ni ne sort, ni vers la box ni à travers elle |
| `quarantine_zone` | rien à travers la box ; vers la box seulement DHCP et DNS |
| `iot_zone`, `guest_zone` | internet oui ; LAN et conteneurs (RFC 1918) non |
| `lan_allowed`, `lxc_zone` | aucune restriction |

Statut réel : `/var/lib/secubox/nac/nft-applied.json` (repris par `/status`). Les chaînes tournent à
`priority filter - 5` : un drop est final, un oubli ne rend rien accessible. `GET /sync_zones`
redemande l'application. Preuve de bout en bout : topologie client/routeur/serveur en espaces de noms.

## Détection passive de l'OS et du type fin (#2236)

`devices.db` porte quatre colonnes de plus, remplies par le collecteur (`api/osdetect.py`, fonctions pures) et exposées par `GET /api/v1/nac/clients` et
`GET /api/v1/nac/client/{mac}` :

| Colonne | Sens |
|---|---|
| `os` | système d'exploitation déduit (`iOS 17`, `Android 13`, `Windows`, `OpenWrt (Linux)`…), ou `null` |
| `os_source` | **la preuve**, obligatoire dès qu'`os` est renseigné : `dhcp-vendor-class:…`, `user-agent:…`, `dns:<domaine>`, `hostname:<nom>`, `empreinte-nac:openwrt` |
| `device_subtype` | type fin (`smartphone`, `tablette`, `télévision`, `imprimante`, `streaming`, `objet connecté`…), ou `null` |
| `mac_random` | `1` si le bit « localement administré » de la MAC est posé (confidentialité iOS/Android/Windows) |

Règles : **aucune inférence sans preuve** (`store.set_detection` refuse un OS sans `os_source`) ; le fabricant (OUI) seul ne donne jamais d'OS ; une MAC aléatoire
n'est pas typée par son fabricant ; une preuve plus forte l'emporte (classe vendeur DHCP > User-Agent > domaines DNS > nom de l'appareil > empreinte du NAC) ;
une conclusion dont la preuve a disparu est retirée au cycle suivant.

Preuves effectivement branchées : le **nom** de l'appareil, les **domaines DNS de connectivité** (lus en lecture seule dans la base d'ad-guard,
`api/dnsevidence.py`, jamais d'autre domaine), l'empreinte OpenWrt/SecuBox du NAC. La classe vendeur DHCP, le User-Agent et les services mDNS sont compris par le
détecteur mais **pas encore alimentés** : sur gk2 le DHCP est servi par la Freebox (la box ne voit pas l'option 60) et sbxmitm ne remonte pas encore de
User-Agent par appareil.

Conteneurs LXC : chaque entrée de `/clients` porte `conteneur` (br-lxc, 10.100.0.0/16, OUI `00:16:3e`) ; `?exclure_conteneurs=true` les retire (`conteneurs_exclus`
donne leur nombre). Le défaut est inchangé : la zone `lxc` du NAC, la toolbox et Tor comptent sur eux.

## Quarantaine automatique d'un appareil du LAN (#2274)

Quand actord publie pour un appareil du réseau local la mesure `QUARANTINE` (niveau BLOCK : risque ≥ 75, confiance ≥ 80, deux capteurs distincts au moins), le NAC
l'**isole lui-même** dans sa zone de quarantaine existante — la même que pour un appareil inconnu (DNS et le reste comme aujourd'hui). Il lit `GET /mesures`
sur la socket locale d'actord, à la racine (vue complète : c'est la seule qui porte les adresses). Libération : un administrateur reconnaît et valide l'appareil ; il n'y a pas de libération automatique, et une même mesure
n'isole qu'une fois.

| Réglage (`[nac]` de `/etc/secubox/secubox.conf`) | Défaut | Rôle |
|---|---|---|
| `quarantaine_auto` | `auto` | `auto` isole, `propose` consigne seulement le candidat, `off` coupe ; toute autre valeur vaut `off` |
| `quarantaine_protegees` | `[]` | adresses MAC jamais isolées |

Jamais la box, un routeur, un équipement OpenWrt/SecuBox, ni un appareil absent depuis plus de 3 h. `GET /api/v1/nac/quarantaine/auto` rend le mode et les candidats ; chaque
isolement laisse une ligne `quarantine_auto` dans l'historique de l'appareil et un événement `client_quarantined_auto`.
