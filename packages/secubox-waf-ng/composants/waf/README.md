<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# 🔥 Web Application Firewall

WAF with 300+ OWASP security rules

**Category:** Security

## Screenshot

![Web Application Firewall](../../docs/screenshots/vm/waf.png)

## Features

- OWASP rules
- Custom rules
- Request logging

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-waf
```

## Configuration

Configuration file: `/etc/secubox/waf.toml`

## API Endpoints

- `GET /api/v1/waf/status` - Module status
- `GET /api/v1/waf/health` - Health check
- `GET /api/v1/waf/enforcement[?statut=active|expired|released]` - actions défensives (bans de sbxwaf) : type, cible, raison, durée, échéance, rollback (#2240)
- `GET /api/v1/waf/enforcement/mode` - `PASSIVE_ONLY` / `SIMULATION` / `ACTIVE`, par source (acteurs, campagnes) et global
- `GET /api/v1/waf/decisions` - décisions des bans automatiques : `BLOCKED`, `WOULD_BLOCK` (simulation), `OBSERVE` (écarté, avec le motif)
- `POST /api/v1/waf/enforcement/{id}/rollback` - annule une action active (retire l'adresse du set nft), audité dans `/var/log/secubox/audit.log` ; `require_jwt`
- `GET /api/v1/waf/populations` - populations d'attaquants sur 7 jours (`require_lecture_ai`, #3919) : cache de la tâche de fond et son âge, `{"disponible": false}` s'il manque ; détail dans le [`README.md` du paquet](../../README.md)
- `GET /api/v1/waf/rapports` - sujets ayant un rapport multi-historique (campagnes, acteurs), âge du relevé (`require_lecture_ai`, #4006)
- `GET /api/v1/waf/rapports/{genre}/{id}` - rapport d'un sujet (`genre` = `campagne` | `acteur`) : `dossier` (faits JSON, aucune adresse), `historique` (séries 90 j), `regles` (lecture par règles, toujours exacte), `ia` (lecture IA relue par le code : `gardees`, `retirees` avec motifs, `taux_retenues_pct`, `perimee`), `markdown` (export)
- `POST /api/v1/waf/rapports/{genre}/{id}/rediger` - rédaction IA à la demande (`require_jwt`), une à la fois ; moteur : `[rapports] llm_urls` du WAF, sinon `llm_urls`/`llm_url` de `/etc/secubox/zia.toml` (http en boucle locale seulement)

### Rapports multi-historiques (#4006)

Tâche de fond horaire (`python3 -m api.rapports --ecrire /var/lib/secubox/waf/rapports.json`, nice 10, tuée à 540 s) :
bans neufs des 90 derniers jours (`bans.jsonl` + `bans-AAAAMM.jsonl.gz`), populations de #4005, campagnes du profileur,
20 acteurs d'actord (chronologie en vue complète). Vague = jours actifs séparés par au moins 3 jours sans ban (5 bans au
moins) ; récurrence = adresses, /24 ou opérateurs d'une vague déjà vus dans une vague précédente ; phases par préfixe de
catégorie (`rapports.PHASES`). Jalons datés facultatifs : `/etc/secubox/waf/rapports-jalons.json`
(`[{"date": "AAAA-MM-JJ", "libelle": "...", ...chiffres}]`).

Vérificateur (`api/verif_rapport.py`, sans modèle) : une phrase est retirée si elle porte une adresse IP, un motif de
causalité ou de capacité (listes `CAUSALITE`, `CAPACITE`), une tendance non mesurée, un nombre / une date / un nom
(CVE, hôte, catégorie, opérateur) absent du dossier, un nombre lié à une autre unité que la sienne (« 18 651 adresses »
quand 18 651 compte des bans), une date de fin donnée pour un début, ou aucun ancrage. Une supposition adossée est
gardée et marquée « hypothèse ». Limite : deux faits justes mal reliés (le sujet d'une phrase) ne sont pas détectés.
- `GET /api/v1/waf/php/signaux` - signaux de l'analyse PHP de sbxwaf sur 24 h (`require_lecture`, #3273) : `familles` (`php2shell`, `roundcube`, `nextcloud`, `php_requete`, `outil`), `regles`, `vhosts`, `adresses` publiques (jamais « local » ni une adresse privée), `etat` (`ok` / `inconnu`) ; les lignes d'état de gravité `audit` ne sont pas comptées. Lu dans le relevé `/var/lib/secubox/waf/php-signaux.json`, recalculé toutes les 60 s en tâche de fond : le journal n'est jamais relu à la requête. Relevé absent : `etat: inconnu`, compteurs `null`.
- `GET /api/v1/waf/detections` - gagne l'entrée `analyse_php` (mode `detect`, vhosts armés lus dans `/etc/secubox/waf/vhost_profiles.json`, `<n> signaux en 24 h`) ; la page Menaces affiche la carte « Analyse des requêtes PHP » et la page Attaquants la signature PHP de chaque adresse.

Les trois lectures (`require_lecture`) relisent les fichiers de sbxwaf (`bans.jsonl`, `actor-ban-etat.json`, `campagne-ban-etat.json`) ; rien n'est recopié.

### Compte de service `ai-ban` (#3716)

Garde `require_ai_ban` (jeton EdDSA par requête, usage unique, lié au corps), **pas** `require_jwt` : exception écrite à `RULES-CODE` § 3. Servies par `secubox-waf.service` seul (waf.sock, `SECUBOX_WAF_GESTES_IA=1`) ; ailleurs 503 `processus`. Détail des corps, motifs, clés et rotation : [`README.md` du paquet](../../README.md).

- `POST /api/v1/waf/ai/ban` - `{geste: "ban", cible, duree_s, mode: clic|auto, conseil, motif}` → `{id, cible, fin, audit}` ; IPv4 publique ou /24 exact, 1 h à 7 j, `auto` : bloc, 24 h au plus, cas sûr recontrôlé ; plafonds d'office 5/h et 20/j, du compte 30/h et 100/j ; refus 409 `{"detail": {"motif"}}`.
- `POST /api/v1/waf/ai/unban` - `{geste: "unban", id}` → `{id, etat}` (`annule`, `echu`, `deja_annule`, `couvert`) ; seulement un ban posé par `ai-ban`, jamais un ban qu'une autre source couvre.
- `GET /api/v1/waf/ai/etat` - sans corps → `{actifs, compteurs, plafonds}`.

## Cartes vivantes (#3945)

Voir « Graphiques vivants » du README de secubox-waf-ng : recul sur les relevés successifs de l'onglet, jamais inventé.

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).

## Page Modes (#3741)

| Route | Garde | Rôle |
|---|---|---|
| `GET /api/v1/waf/categories` | `require_lecture` | mode, `ban_seuil`, `ban_duree`, `motifs`, `structurels`, `rules_count` (= motifs + structurels), `verrouille` ; `source` = `box` (cvectl) ou `paquet` (repli) |
| `POST /api/v1/waf/categories/modes` | `require_jwt` | lot `{changements: [{categorie, mode, ban_seuil?, ban_duree?}]}` (1–40) → `secubox-cvectl waf-modes appliquer` ; 409 sur une catégorie générée (mode fixé) |
| `POST /api/v1/waf/category/{cat}/mode` | `require_jwt` | un seul changement |
| `GET /api/v1/waf/categories/stats7j` | `require_lecture` | touches 7 j par catégorie, faux positifs estimés (« local » = LAN + maillage, adresses privées, liste blanche) ; `robots_verifies: null` (absent du journal) ; journal absent → `categories: null` ; tâche de fond toutes les 15 min, cache écrit atomiquement, la requête lit seulement (`etat: calcul en cours` avant le premier passage) |
| `GET/POST /api/v1/waf/leurres-service/modes` | lecture / `require_jwt` | `observer` ou `bannir` par leurre, messagerie comprise (#3924 : `submission`, `imap`, `pop3`, `observer` par défaut ; `smtp`, `smtps`, `imaps`, `pop3s` fixés à `observer`) → `wafctl leurres-modes`, relu à chaud par sbx-authwatch |
| `GET /api/v1/waf/php-hotes` | lecture | ancienne vue brute (#3741), gardée en lecture ; plus d'écriture (#3974) |
| `GET /api/v1/waf/php-sites` | lecture | sites PHP **détectés** parmi les sites servis (preuve, première et dernière date), exceptions `forcer`/`exclure`, compte `autres` des sites servis non PHP, `tout_couvrir_herite` ; jamais d'adresse ni de nom non servi |
| `POST /api/v1/waf/php-sites` | `require_jwt` | listes complètes `forcer`, `exclure` et/ou `retirer_tout_couvrir: true` → `wafctl php-sites ecrire` ; exclure un site couvert par un service PHP ou un motif livré : 422 |
| `POST /api/v1/waf/php-sites/detecter` | `require_jwt` | relance la détection (sinon toutes les heures par la tâche de fond) |

Sites PHP (#3974) : `wafctl php-sites detecter` (root, `/usr/lib/secubox/waf/waf-php-sites`) relève trois preuves sur les
sites servis (`haproxy-routes.json`) : appli d'un service déclaré PHP ; au moins 2 réponses 2xx à un chemin `.php` dans
`/var/log/nginx/secubox-hosts.log` (+ `.1`), taille différente de celle de « / » (attrape-tout écarté) ; `X-Powered-By: PHP`
ou cookie de session PHP rendu par le serveur d'origine à `GET /`. Les signaux d'attaque ne sont pas une preuve. État dans
`/etc/secubox/waf/php-sites.json` ; `php_hotes` = motifs livrés gardés + `^site$` des (détectés servis ∪ forcés) − exclus.
Première exécution (postinst) : les anciens motifs explicites deviennent des exceptions `forcer`, `^.*$` reste jusqu'au
retrait explicite. Retour arrière : `wafctl php-sites retablir` (root) remet les `php_hotes` d'avant et met l'état de côté.

Écritures : l'API audite l'intention avant et l'issue après ; `wafctl leurres-modes|php-hotes ecrire` audite lui-même chaque issue (ok, refus, échec), appel sudo direct compris. Une bascule ne touche jamais `enabled`. Le mode choisi est marqué `mode_choisi: true` : `waf-rules-sync` le garde aux mises à jour du paquet. Un contrôle
structurel en `block` bannit l'adresse au premier constat (analyse après relais : ban immédiat, requêtes suivantes
bloquées) ; en `escalate` il nourrit le compteur de la catégorie. Pas de fenêtre par catégorie (fenêtre escalate
globale). sbxwaf relit à chaud tout `vhost_profiles.json` (pas seulement `php_hotes`) ; un fichier illisible au
démarrage laisse la phase G coupée jusqu'au redémarrage.
