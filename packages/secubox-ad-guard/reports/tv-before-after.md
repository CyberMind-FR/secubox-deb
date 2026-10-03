# Comparaison TV — avant / après filtrage DNS

> Mesures réelles tirées des compteurs de la box (différence de deux relevés par phase). Formulation : **réduction des domaines publicitaires/tracking résolus par DNS** — ce n'est pas une suppression de publicités.

Appareil : `192.168.1.95,2a01:e0a:dec:c4e0:c147:c3cf:6dd7:3429`

| Phase | Mode | Requêtes DNS | Domaines uniques | Advertising (résolus) | Tracking (résolus) | Bloqués (requêtes) | Domaines bloqués | Erreurs amont |
|---|---|---|---|---|---|---|---|---|
| C | BLOCK | 144 | 26 | 0 | 0 | 79 | 4 | 0 |
| E | OBSERVE | 50 | 24 | 12 | 0 | 0 | 0 | 0 |
| P | OBSERVE | 56 | 21 | 17 | 0 | 0 | 0 | 0 |

## Phase C
Durée : 287 s. Note de l'opérateur : BLOCK: pre-roll nouvelle serie = ecran noir ~6 s sans pub puis lecture normale de la video; aucune erreur affichee

| Domaine classé | Catégorie | Décision | Requêtes |
|---|---|---|---|
| `videos-pub.ftv-publicite.fr` | custom | BLOCKED | 28 |
| `aes.eu-central.3px.axp.amazon-adsystem.com` | advertising | BLOCKED | 26 |
| `aax-events-cell02-cf.eu-central.3px.axp.amazon-adsystem.com` | advertising | BLOCKED | 24 |
| `ad.doubleclick.net` | advertising | BLOCKED | 1 |

## Phase E
Durée : 596 s. Note de l'opérateur : replay lance, pub vue puis interrompue

| Domaine classé | Catégorie | Décision | Requêtes |
|---|---|---|---|
| `aax-events-cell02-cf.eu-central.3px.axp.amazon-adsystem.com` | advertising | ALLOWED | 2 |
| `ad.doubleclick.net` | advertising | ALLOWED | 2 |
| `ade.googlesyndication.com` | advertising | ALLOWED | 2 |
| `aes.eu-central.3px.axp.amazon-adsystem.com` | advertising | ALLOWED | 2 |
| `pagead2.googlesyndication.com` | advertising | ALLOWED | 2 |
| `v.adsrvr.org` | advertising | ALLOWED | 2 |

## Phase P
Durée : 1097 s. Note de l'opérateur : replay France TV, coupures pub vues, lecture reprise

| Domaine classé | Catégorie | Décision | Requêtes |
|---|---|---|---|
| `aes.eu-central.3px.axp.amazon-adsystem.com` | advertising | ALLOWED | 5 |
| `aax-events-cell02-cf.eu-central.3px.axp.amazon-adsystem.com` | advertising | ALLOWED | 4 |
| `pagead2.googlesyndication.com` | advertising | ALLOWED | 4 |
| `ad.doubleclick.net` | advertising | ALLOWED | 2 |
| `ade.googlesyndication.com` | advertising | ALLOWED | 2 |
| `app-measurement.com` | telemetry | ALLOWED | 2 |
| `region1.app-measurement.com` | telemetry | ALLOWED | 2 |

## À renseigner par l'opérateur
- Domaines **nécessaires** au fonctionnement du service (ceux dont le blocage casse quelque chose) : …
- Faux positifs constatés : …
- Fonctions cassées en phase C : …
