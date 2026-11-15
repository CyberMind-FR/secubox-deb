<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
-->

# Jeu de référence de la veille V2 (#3718)

Extrait (399 événements) des journaux **réels** de gk2 relevés le 2026-11-15 (fenêtre ≈ 14/11 00 h → 15/11 09 h), copiés en lecture
seule puis anonymisés par `anonymiser.py` (méthode dans son en-tête). Rien de brut n'est versionné.

| Fichier | Source sur gk2 | Contenu |
|---|---|---|
| `menaces.jsonl` | `waf-threats.log` (+ `.1`) | 180 lignes : chaque famille vue, 8 requêtes du LAN (`local`), 2 groupes de doublons exacts réels |
| `bans.jsonl` | `bans.jsonl` | 183 lignes : `leurre`, `mesure`, `campagne`, `host_anomaly`, `scanners`, `honeypot`, `waf_fingerprint`, `\|prolonge` ; deux /24 gardés entiers |
| `reevaluations.jsonl` | `reevaluations.jsonl` | 10 RELEASE, 10 EXTEND |
| `campagnes.json` | `campagne-ban-etat.json` | état du détecteur de campagnes, 12 candidats |
| `ai-ban.jsonl` | `ai-ban.jsonl` | gestes de l'IA : ban puis annulation (essai du 14/11) |

Repères pour les tests :

- `203.0.113.0/24` : bloc réel de **≥ 20 adresses bannies** (cas sûr de #3716) ; `198.51.100.0/24` : second bloc le
  plus peuplé, sous le seuil.
- `lfi`, `xss`, `sqli` dans `bans.jsonl` viennent de l'**autotest du WAF** (`SecuBox-WAF-SelfTest/1`), pas d'une attaque.
- Les horodatages de `menaces.jsonl` portent le décalage local (`+01:00`) ; ceux des bans sont en époque UTC.
- Les bans de sbx-authwatch n'existent que par `action = banned` dans `menaces.jsonl` (absents de `bans.jsonl`, § 6.3
  de l'annexe de phase 0).

Régénérer : copier les six fichiers bruts (voir `anonymiser.py`) dans un dossier hors dépôt, puis
`python3 -I anonymiser.py <brut> packages/secubox-ai/tests/donnees`, et relancer `tests/test_donnees_reference_3718.py`.
Les valeurs hexadécimales et l'ordre des adresses changent à chaque tirage (sel aléatoire).
