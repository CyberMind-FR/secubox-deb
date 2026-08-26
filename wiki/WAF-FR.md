<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# sbxwaf — le WAF autonome 🛡️

[EN](WAF) | **[FR](WAF-FR)** | **🟡 WALL** | pare-feu applicatif souverain

> Motif détecté, bannissement dans le noyau. Aucun service tiers dans le chemin
> de décision.

## Ce qui a changé

Jusqu'en août 2026, la chaîne de blocage passait par CrowdSec : détection
locale, réputation communautaire, puis un *bouncer* qui traduisait la décision
en règle. Depuis, `sbxwaf` décide et applique lui-même.

Ce n'est pas un rejet technique. CrowdSec a couvert des mois de production et
la détection communautaire a rendu service. Trois raisons ont fait pencher la
balance :

- **la dépendance d'un tiers dans le chemin de décision** — si le service tombe,
  plus rien ne bannit, et c'est arrivé en silence ;
- **le coût en charge** sur une carte ARM contrainte — la charge de la box de
  référence est passée de 15–22 à 5–7 après l'arrêt ;
- **la réciprocité** de la mutualisation, qui n'était plus tenue dans la durée.

## Comment ça bannit

```
requête → sbxwaf → motif → set nft (waf_ban / waf_ban6)
                            ↑
                     chaîne waf_drop, hook input, priorité -100
                     ip saddr @waf_ban counter drop
```

Le point important est la **chaîne**. Un ensemble nft rempli mais référencé par
aucune règle ne bloque rien : c'est une liste sans portier. `sbxwaf` crée donc
la chaîne et les deux règles au démarrage, avec un `flush chain` préalable —
`add rule` n'est pas idempotent, sans quoi chaque redémarrage empilerait un
doublon.

Relevé sur la box de référence :

| Mesure | Valeur |
|---|---|
| Adresses bannies | 115 IPv4 + 2 IPv6 |
| Paquets jetés par le noyau | 12 545 |
| Volume écarté | 878 Ko |
| Catégories de règles | 25 |
| Détections comportementales | 4 |

## Anti-robots par vhost

48 robots nommés (moteurs de recherche, moissonneurs d'IA, outils SEO) plus des
motifs génériques. Trois chemins restent **toujours** servis, même à un robot
banni : `/robots.txt`, `/favicon.ico` et `/.well-known/`. Bloquer `robots.txt`
empêcherait le robot d'apprendre qu'il n'est pas le bienvenu.

La case du panneau Vhost est libellée **Anti-robots** : cochée, elle bloque.

## Hors-HTTP : sbx-authwatch

Un WAF ne voit que le web. `sbx-authwatch` lit SSH, SMTP et IMAP — journal
systemd et fichiers — et écrit dans **le même ensemble de bannissement et le
même journal de menaces**. C'est la corrélation qui existait avec CrowdSec,
reconstruite localement.

- Motifs écrits depuis de vraies lignes de production, pas depuis la
  documentation amont.
- Détection de **campagne** (clé : le compte visé) et de **compte inexistant** —
  une tentative sur un domaine dont personne ne se sert est une agression, pas
  une faute de frappe.
- **10 ports leurres**. Un leurre note et se tait : il n'imite jamais le
  protocole, car imiter, c'est offrir une surface.
- Filtres par service déclaratifs dans `/etc/secubox/authwatch/services.json` —
  un service sans motif vérifié y reste `"actif": false`, avec la raison écrite,
  plutôt qu'avec un motif deviné.

## Voir ce qui se passe

`https://waf.<box>/` — LAN uniquement. Attaquants, pays, noms non résolus par
les vhosts existants, détections comportementales, comptes visés, leurres
touchés, efficacité par catégorie. Histogrammes en SVG inline, sans bibliothèque
externe.

## Notes

- Le paquet `crowdsec` peut rester installé : il est simplement arrêté et
  désactivé au démarrage.
- `secubox-blacklist-sync` et `secubox-threatmesh-bridge` en dépendent par
  `Requisite=` : sans CrowdSec ils ne démarrent pas, au lieu d'échouer en boucle.
