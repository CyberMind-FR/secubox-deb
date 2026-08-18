<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# sbxwaf — mode `detect` (essayer une règle avant de l'armer)

**Date** : 2026-07-17
**Statut** : conception validée, prête pour le plan d'implémentation
**Auteur** : Gérald Kerma <devel@cybermind.fr>

---

## Objectif

Pouvoir **essayer une règle WAF sans bloquer** : elle matche, elle est comptée et journalisée, mais
la requête passe. Aujourd'hui sbxwaf n'a que deux états — évaluée (et bloquante) ou pas évaluée du
tout.

## Pourquoi maintenant

Ce spec naît d'une question plus large — *dériver des règles WAF depuis les CVE* — dont l'exploration
a montré que le mode `detect` en était le **prérequis bloquant**. Mais il a de la valeur seul, et il
est livré seul.

Trois constats mesurés sur gk2 (2026-07-17) :

1. **Il n'existe aucun moyen d'essayer une règle.** `cmd/sbxwaf/rules.go:178` — `if cat.Enabled !=
   nil && !*cat.Enabled` : la catégorie est sautée ou elle bloque. Rien entre les deux. Toute
   nouvelle règle est donc un pari : on l'arme en production et on découvre les faux positifs sur du
   trafic réel — devant Nextcloud, PeerTube, Gitea et billets.
2. **Le risque est démontré.** Le cache média de sbxwaf a déjà servi du JS vide en avalant le
   `Content-Encoding` (YaCy blanc). Les régressions WAF cassent en silence des services réels.
3. **Le poids mort est déjà là.** 149 patterns sur 17 catégories, dont ~39 (voip/xmpp) inutiles en
   HTTP, et une catégorie `cve_2024` de 6 patterns visant **PAN-OS, Ivanti et F5** — trois produits
   absents de cette box Debian. Sans mode `detect`, on ne peut ni prouver qu'un pattern sert, ni le
   retirer en confiance.

Le mode `detect` transforme « je crois que cette règle est bonne » en « j'ai mesuré ».

## Le réel mesuré

- `/etc/secubox/waf/waf-rules.json` : `{_meta:{version,updated,sources}, categories:{...}}`
- 17 catégories, **149 patterns**. Forme d'une catégorie :
  ```json
  "sqli": { "name": "SQL Injection", "severity": "critical", "enabled": true,
            "owasp": "A03:2021",
            "patterns": [ {"id": "sqli-001", "pattern": "union\\s+(all\\s+)?select", "desc": "..."} ] }
  ```
- `cve_2024` porte déjà un champ `cve` par pattern → le schéma sait déjà tracer une provenance.
- sbxwaf **recharge à chaud** (`watcher`, `reload.Target` dans le binaire) : un changement de règles
  ne demande pas de redémarrage.
- Sévérités utilisées : `critical` (8 catégories), `high` (5), `medium` (3), `low` (1).
- Le service tourne sur une box à **118 services, load 5.4 sur 4 cœurs** : le coût par requête compte.

---

## Conception

### Le champ

Un champ **`mode`** par catégorie, à côté de `enabled` :

```json
"cve_2024": { "name": "...", "severity": "critical", "enabled": true,
              "mode": "detect",           // "detect" | "block"
              "patterns": [ ... ] }
```

Sémantique, sans ambiguïté :

| `enabled` | `mode` | Comportement |
|---|---|---|
| `false` | *(ignoré)* | catégorie non évaluée — coût nul |
| `true` | `"block"` | match → requête bloquée (**comportement actuel**) |
| `true` | `"detect"` | match → compté + journalisé, **requête laissée passer** |

**`mode` absent ⇒ `"block"`.** C'est la décision structurante : les 17 catégories existantes ne
portent pas le champ et ne doivent rien changer. Un défaut `detect` transformerait silencieusement
tout le WAF en observateur — une panne de sécurité muette, le pire des deux mondes. Le même
raisonnement que `Enabled *bool` (pointeur, `nil` = absent = `true`) déjà en place ligne 144.

### Ce que produit un match en `detect`

Le même enregistrement de menace qu'un blocage, **plus un discriminant explicite** :

```json
{"ts": "...", "ip": "...", "rule": "cve-2024-3400", "category": "cve_2024",
 "severity": "critical", "action": "detect", "url": "..."}
```

`action` distingue `detect` de `block`. Sans ce champ, les statistiques mélangeraient « bloqué » et
« aurait bloqué » — et le compteur de menaces (198k aujourd'hui) deviendrait un mensonge.

**Un match en `detect` ne déclenche AUCUN effet de bord** : pas de ban CrowdSec, pas de décision nft,
pas de compteur de bannissement. `detect` veut dire *observer*, pas *punir plus tard*. C'est
l'invariant central : une catégorie en `detect` doit être exactement aussi inoffensive qu'un
`enabled: false`, à la journalisation près.

### Ce qu'on peut alors faire (et qu'on ne peut pas aujourd'hui)

- Armer une nouvelle règle en `detect`, regarder une semaine de trafic réel, **puis** décider.
- Basculer `cve_voip`/`cve_xmpp` en `detect` et **prouver** par les compteurs qu'ils ne matchent
  jamais — avant de les retirer. Aujourd'hui on ne peut que supposer.
- Faire atterrir toute règle générée automatiquement (chantier CVE→WAF à venir) en `detect` par
  construction.

---

## Hors périmètre (YAGNI)

- **Pas de `mode` par pattern.** La catégorie suffit : c'est l'unité que l'opérateur manipule, et un
  `mode` par pattern multiplierait les états à comprendre sans besoin démontré.
- **Pas de promotion automatique `detect` → `block`.** Un WAF qui s'arme tout seul est un WAF qui se
  coupe tout seul. L'humain décide, toujours.
- **Pas de nettoyage des 149 patterns** dans ce chantier. Le mode `detect` donne l'instrument de
  mesure ; le nettoyage est une décision d'exploitation qui viendra avec les chiffres.
- **Pas de génération de règles depuis les CVE.** C'est le chantier suivant, qui s'appuiera sur ce
  mode. Rappel de son cadrage : source = templates **Nuclei** (MIT, vérifié — les CVE eux-mêmes ne
  contiennent aucun exploit, vérifié sur le KEV : champs `cveID/cwes/product/requiredAction`, aucune
  URL) ; filtre = `KEV ∧ paquet installé ∧ module exposé` (l'inventaire `secubox-profiles` donne
  `exposure`, 16 modules publics sur 187) ; expiration à la correction du paquet.

---

## Tests

- **Défaut** : une catégorie sans `mode` bloque (non-régression des 17 existantes — le test le plus
  important du lot).
- `mode: "block"` explicite bloque.
- `mode: "detect"` : le match est compté et journalisé avec `action: "detect"`, **et la requête
  passe** (assertion sur le code de retour, pas seulement sur le log).
- `mode: "detect"` **ne produit aucun ban** : pas d'appel CrowdSec, pas de décision nft.
- `enabled: false` + `mode: "detect"` → catégorie non évaluée (le `enabled` prime).
- `mode` avec une valeur inconnue (`"monitor"`, `""`, `null`) → **rejet bruyant au chargement**, pas
  un repli silencieux sur `detect` : un mode mal orthographié qui désarmerait le WAF en silence est
  précisément le défaut à éviter.
- Le rechargement à chaud prend en compte un changement de `mode` sans redémarrage.

Chaque test doit pouvoir échouer : vérifier par mutation (retirer le comportement, constater
l'échec, restaurer).

---

## Découpage

| Phase | Contenu | Risque |
|---|---|---|
| 1 | Champ `mode` + parsing + défaut `block` + rejet des valeurs inconnues | faible |
| 2 | Le chemin `detect` : compter, journaliser `action`, laisser passer, aucun ban | moyen — c'est le cœur |
| 3 | Déploiement gk2 : rebuild arm64, `mv` sur `/usr/sbin/sbxwaf`, `systemctl restart secubox-waf-ng` | moyen |

⚠️ Contraintes de déploiement établies : `cp` échoue (« text file busy ») → `mv` ; **jamais**
`kill -HUP` → `systemctl restart secubox-waf-ng`. sbxwaf est en frontal de tous les vhosts publics :
une régression coupe tout.
