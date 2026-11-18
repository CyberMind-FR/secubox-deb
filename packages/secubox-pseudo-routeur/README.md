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
| `GET /journal` | admin | bascules de passerelle (audit.log) |

`GET /apercu` → `{"lan_if": "eth2", "non_classes": [{"ip": "...", "mac": "..."}], "note": "..."}`
