<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Générateur de règles WAF « produit absent » — Conception

**Date** : 2026-07-18
**Statut** : conception validée, prête pour le plan d'implémentation
**Auteur** : Gérald Kerma <devel@cybermind.fr>

---

## Objectif

Générer automatiquement des règles WAF qui **fichent les scanners** sondant des exploits de produits
que la box ne fait **pas** tourner (F5, PAN-OS, Ivanti…). Une requête `/mgmt/tm/util/bash` sur une box
sans F5 est un signal pur, à **zéro faux positif possible parce que le produit est absent**.

## Principe directeur

> Le honeypot est au WAF ce que le DPI est au mitmproxy : un complément de pertinence qui rend le
> bruit pertinent.

Le WAF voit tout le trafic — un torrent de bruit. Ces règles ne filtrent pas *plus*, elles
*qualifient* : « cette requête ne peut viser qu'un attaquant ». Le bruit devient donnée d'attaquant
exploitable. C'est la moitié « pertinence » du couple détection/qualification.

## Où ça vit

Dans **`secubox-cve-triage`**, pas un nouveau module. Il possède déjà : l'inventaire dpkg
(`scan_packages`, `main.py:169`), le flux KEV CISA, les données CVE. Le générateur est « cve-triage
émet des règles WAF » — zéro doublon, un seul endroit qui connaît l'inventaire.

## Ce qui est déjà livré et sur quoi ça s'appuie

- **Mode `detect`** (PR #872) : une catégorie WAF qui matche, journalise (`action=detect`), laisse
  passer, ne bannit jamais. Les règles générées y naissent.
- **Mode `escalate`** (PR #873) : observe puis bannit un scanner récidiviste. **Promotion à la main
  seulement** — le générateur n'arme jamais un ban.
- **`secubox-profiles`** : `exposure` par module + `haproxy-routes.json` — une source de présence.
- Le WAF **recharge à chaud** un changement de `waf-rules.json` (livré).
- La catégorie `cve_2024` existante (6 patterns F5/PAN-OS/Ivanti) est exactement la forme cible,
  écrite à la main — le générateur l'industrialise.

---

## ① La source — sous-ensemble Nuclei vendored

Les templates Nuclei (`projectdiscovery/nuclei-templates`, **licence MIT** — vérifié : redistribution
et dérivés autorisés, attribution requise) portent le produit en clair :

```yaml
classification:
  cpe: cpe:2.3:a:f5:big-ip:*
  vendor: f5
  product: big-ip
tags: cve,cve2024,f5,kev,rce
http:
  - method: GET
    path: ["{{BaseURL}}/mgmt/tm/util/bash"]
```

**Vendored, pas de git-pull runtime.** Un sous-ensemble figé est embarqué dans le paquet sous
`packages/secubox-cve-triage/nuclei-subset/`, filtré aux CVE **KEV** dont la sonde est une **URL
extractible**. Rationale : une box de sécurité (cible CSPN) ne doit pas exécuter au runtime du contenu
tiers qui change sans revue, ni dépendre du réseau. Le sous-ensemble est reproductible, auditable,
versionné avec le paquet, rafraîchi à la main lors d'une release. L'attribution MIT est conservée dans
`nuclei-subset/LICENSE`.

Le peuplement initial du sous-ensemble est un **script de curation hors-ligne** (`scripts/`), lancé par
le mainteneur, pas au runtime : il clone Nuclei, garde les templates KEV + appliance + URL-extractible,
copie le fichier tel quel (attribution) dans `nuclei-subset/`. Non embarqué dans le service.

## ② L'extraction — de la sonde au pattern

sbxwaf matche une regex sur `path + query + body + UA`. On ne peut donc utiliser qu'un template dont la
sonde est **une requête à chemin extractible** :

- **Retenu** : un `http:` à `method: GET`/`POST` avec un `path` littéral (ou une query fixe). On extrait
  le chemin, on l'échappe en regex (`regexp.QuoteMeta` côté humain ; ici en Python `re.escape`), on
  ancre au path.
- **Rejeté** (loggé, pas généré) : templates multi-étapes, matchers sur le corps de réponse,
  extractors, `{{...}}` autres que `{{BaseURL}}`, raw requests. Un template non réductible à un motif
  d'URL déterministe ne produit pas de règle — silence serait une couverture surestimée, donc on
  **journalise chaque rejet** avec sa raison.

Le pattern émis est **volontairement spécifique** (le chemin exact), pas une généralisation : le but
n'est pas de bloquer la vuln (c'est du virtual patching, hors sujet) mais de **reconnaître la sonde**.
Zéro faux positif exige la spécificité.

## ③ L'oracle de présence — DEUX barrières

Le mode d'échec à tuer : croire un produit absent alors qu'il est présent → règle qui matche du trafic
légitime → en escalate, **ban d'un vrai utilisateur**. D'où deux garde-fous indépendants ; un candidat
ne passe que s'il franchit **les deux**.

### Barrière 1 — famille d'appliance connue-absente (allowlist)

On ne génère que pour des produits d'une **liste curée de familles d'équipements réseau** qu'une box
Debian n'est catégoriquement pas :

```
f5 (big-ip), paloalto (pan-os), ivanti (connect secure, epmm),
citrix (netscaler/adc), fortinet (fortios/fortigate), cisco (ios/asa/ise),
vmware (vcenter/esxi), sonicwall, zyxel, dlink, netgear, juniper (junos)
```

Liste versionnée dans le code (`APPLIANCE_VENDORS`), pas dérivée automatiquement — c'est une assertion
humaine sur ce que la box **n'est jamais**. Le `vendor`/`product`/`cpe` du template doit y matcher.

### Barrière 2 — absent de l'union de présence

En plus, le produit ne doit apparaître dans **aucune** source de présence :

```
présent  ⟺  produit ∈ ( dpkg hôte  ∪  vhosts routés WAF  ∪  modules secubox installés )
```

- **dpkg hôte** : l'inventaire `cve-triage` existant (`scan_packages`).
- **vhosts routés WAF** : `haproxy-routes.json` — CRUCIAL, car nextcloud/gitea tournent en LXC et sont
  **absents du dpkg hôte** mais routés (vérifié sur gk2). Sans cette source, on générerait une règle
  nextcloud qui bannirait un vrai utilisateur.
- **modules secubox** : `menu.d/` / l'inventaire `secubox-profiles`.

**Règle de sûreté absolue : dans le doute, PRÉSENT.** Toute erreur de lecture d'une source, tout
mapping ambigu, toute source indéterminable ⟹ le produit est traité comme présent ⟹ la règle n'est
**pas** générée. Rater une sonde de fichage est sans conséquence ; bannir un vrai utilisateur ne l'est
pas. (Même leçon « inconnu ≠ définitif » que le mode detect a établie côté sondes.)

Un candidat de la famille F5 passe : famille appliance ✓, absent de l'union ✓. Un candidat PHP est
rejeté par la Barrière 1 (pas une appliance) **et** par la Barrière 2 (nextcloud LXC l'utilise) — double
protection.

## ④ La sortie — catégorie `detect`, additive, jamais armée

Le générateur écrit une catégorie **`product_absent_probes`** dans `waf-rules.json`, en **mode
`detect`** :

```json
"product_absent_probes": {
  "name": "Product-absent scanner probes (generated)",
  "severity": "high",
  "mode": "detect",
  "generated": true,
  "generated_at": "2026-07-18T...",
  "patterns": [
    {"id": "f5-cve-2023-46747", "pattern": "/mgmt/tm/util/bash",
     "desc": "F5 BIG-IP RCE probe (product absent)", "cve": "CVE-2023-46747",
     "vendor": "f5", "source": "nuclei"}
  ]
}
```

Invariants :

- **Ne touche JAMAIS les 17 catégories existantes.** Régénérer réécrit **uniquement** sa propre
  catégorie `product_absent_probes` (idempotent, marquée `generated: true`) ; le reste du fichier est
  préservé octet pour octet (lecture, remplacement de la seule clé, réécriture atomique temp+rename).
- **Naît en `detect`, jamais en `escalate`.** Le générateur n'arme aucun ban. L'opérateur observe zéro
  faux positif sur du trafic réel, **puis** bascule la catégorie en `escalate` à la main. C'est la
  contrainte de sûreté du spec escalate, honorée ici.
- Le WAF recharge la nouvelle catégorie à chaud (livré) — pas de redémarrage.

## ⑤ Surfaces

- **CLI** : `secubox-cvectl waf-rules generate [--dry-run]` — dry-run par défaut affiche ce qui serait
  généré (candidats retenus + rejets avec raison) sans écrire. `--apply` écrit la catégorie.
- **Panel** `/cve-triage/` (existe) : un onglet montrant la catégorie générée, les rejets, et un bouton
  « régénérer » (dry-run d'abord). Style cyan hybrid-skin.
- Pas de timer au départ : la génération est déclenchée à la main (le sous-ensemble Nuclei ne change
  qu'à une release). Un timer pourra venir plus tard si le vendored est rafraîchi automatiquement.

Toutes les surfaces exigent JWT.

---

## Découpage d'implémentation

| Phase | Contenu | Risque |
|---|---|---|
| 1 | Script de curation hors-ligne + sous-ensemble vendored initial + LICENSE | faible |
| 2 | Extraction Nuclei → candidat (parse YAML, sonde URL, rejets journalisés) — **fonctions pures** | nul |
| 3 | Oracle de présence : les 2 barrières (allowlist + union, fail-safe présent) — **pur, testable** | faible |
| 4 | Émission de la catégorie `product_absent_probes` (additive, idempotente, atomique) | moyen |
| 5 | CLI `waf-rules generate` (dry-run par défaut) | faible |
| 6 | Panel : onglet règles générées + rejets | faible |

Les phases 2-3 sont pures et testables sans board ni réseau. La phase 4 est la seule qui écrit
`waf-rules.json` (le fichier du WAF frontal) — d'où le remplacement de la seule clé + écriture atomique.

## Hors périmètre (YAGNI)

- **git-pull runtime** de Nuclei (décidé : vendored).
- **Promotion automatique `detect`→`escalate`** (décidé : humain — c'est du ban).
- **Génération hors familles-appliances**, même « prouvée absente » (le mapping serait trop faillible ;
  la Barrière 1 le refuse).
- **Généralisation des patterns** pour bloquer la vuln (c'est du virtual patching, un autre but).
- **Corrélation ASN/JA4** des scanners fichés (le C2 auto-learn existant s'en charge, hors périmètre).

---

## Tests

- **Extraction (pure)** : un template GET à path littéral → pattern échappé ancré ; un template
  multi-étapes / body-matcher / raw → **rejeté** avec raison ; un `path` avec `{{BaseURL}}` seul est
  accepté, avec d'autres `{{...}}` rejeté.
- **Barrière 1 (pure)** : un produit F5/PAN/Ivanti passe ; un produit hors liste (php, wordpress,
  nginx) est rejeté.
- **Barrière 2 (pure)** : un produit présent dans dpkg, ou dans les vhosts routés, ou dans les modules,
  est traité présent ; une source illisible ⟹ présent (fail-safe) ; absent des trois ⟹ absent.
- **Combinaison** : un candidat ne passe que si Barrière 1 ET Barrière 2 ; le cas nextcloud (absent
  dpkg, présent vhost) est correctement retenu comme présent → non généré.
- **Émission** : régénérer préserve les 17 catégories octet pour octet ; ne modifie que
  `product_absent_probes` ; la catégorie sort en `mode: "detect"` ; idempotence (deux runs = même
  fichier) ; écriture atomique (un crash mi-écriture ne corrompt pas `waf-rules.json`).
- **Sûreté** : aucun chemin de code n'émet une catégorie en `escalate` ou `block` ; le dry-run n'écrit
  rien.
- Chaque test comportemental doit pouvoir échouer (mutation).

Couverture ≥ 80 % (contrainte CSPN).
