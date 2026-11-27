<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Bibliothèque figée de motifs du WAF (#4020) — attributions

`categories.json` contient des motifs RE2 **dérivés** de deux projets tiers, utilisés comme
**sources de motifs** uniquement : aucun de leurs moteurs n'est livré ni exécuté. Seul `sbxwaf`
évalue ces motifs. Les fichiers de ce dossier qui viennent de ces projets gardent **leur licence
d'origine**, reproduite dans `LICENCES/` ; l'outil de construction et la présente notice relèvent
de la licence CMSD-1.0 du dépôt.

| Source | Version | Licence | Copyright | Ce qui en est tiré |
|---|---|---|---|---|
| OWASP Core Rule Set — https://github.com/coreruleset/coreruleset | v4.31.0 | Apache-2.0 (`LICENCES/OWASP-CRS-LICENSE-Apache-2.0.txt`) | OWASP CRS project | expressions `@rx` et listes `@pm`/`@pmFromFile` des règles de niveau de paranoïa 1 (familles 913, 930, 932, 933, 941, 942), converties pour un champ de requête ; référence `CRS <id>` |
| ProjectDiscovery nuclei-templates — https://github.com/projectdiscovery/nuclei-templates | v10.5.3 | MIT (`LICENCES/NUCLEI-TEMPLATES-LICENSE-MIT.txt`) | ProjectDiscovery, Inc. | chemins littéraux des requêtes GET des modèles `http/technologies`, `http/exposed-panels`, `http/exposures`, `http/misconfiguration` ; référence `nuclei <id de modèle>` |

Modifications apportées (Apache-2.0 § 4 b) : les règles CRS sont réduites à leur seul motif,
rattachées à un champ (`chemin`, `requete`, `ua`, `corps`), sans transformation, sans score
d'anomalie ; les listes `@pm` sont réécrites en alternatives RE2 échappées. Les modèles Nuclei
sont réduits à leurs chemins de requête (aucun « matcher » de réponse n'est repris). Chaque motif
porte sa référence d'origine (`ref`).

Mise à jour : uniquement par publication d'une nouvelle version du paquet
(`composants/waf/bibliotheque/construire.py`, voir le README du paquet). Aucun téléchargement à
l'exécution sur la box.
