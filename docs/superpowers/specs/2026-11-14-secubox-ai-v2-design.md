<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# SecuBox AI V2 — veille, corrélation, analyste et réponses bornées (#3583)

Document de conception. Il adapte une spécification proposée hors du projet (« SecuBox AI V2.0, spécification
technique détaillée ») à l'état réel de SecuBox-DEB et à ses règles (`AGENTS.md`, `.claude/RULES-CODE.md`,
`.claude/MODULE-COMPLIANCE.md`). La proposition est reprise comme **contenu** : ce qui contredit le dépôt est corrigé,
et chaque correction donne sa raison (§ 3). Aucun code n'est écrit par ce document.

## 1. Intention

`secubox-ai` 0.1.x (étape 1 du portage du POC gk0, déployée sur gk3) sait **lire** les menaces de gk2, les résumer
sans inventer et **proposer** des gestes dans un catalogue fermé. #3716 a livré sur gk2 le seul chemin par lequel une
IA peut **agir** sur le pare-feu : le compte de service `ai-ban`.

La V2 fait de ce module un poste de veille : il garde un historique propre des événements de gk2, les regroupe en
**incidents multi-sources** (ce que gk2 ne fait pas encore), les fait expliquer par un analyste IA dont chaque
affirmation renvoie à une preuve en base, et propose ou applique des réponses **bornées par des politiques**, toujours
par `ai-ban`. La règle d'or de la proposition est gardée telle quelle : **le moteur de sécurité reste maître de
l'infrastructure, même quand l'IA est indisponible**. Ici, ce moteur est gk2 (sbxwaf, sbx-authwatch, waf-blocs) ;
gk3 n'en est que le conseiller.

## 2. Décisions du propriétaire (2026-11-14)

1. **V2 = évolution du paquet existant** `secubox-ai`, version finale `2.0.0-1~trixie1`. Pas de nouveau paquet.
2. **Tourne sur gk3, lit gk2 à distance** par ses routes de lecture (`require_lecture`), comme `api/menaces.py`.
3. **Agit sur gk2 uniquement** par le compte de service `ai-ban` existant (`/api/v1/waf/ai/*`), `waf-blocs` (root,
   sur gk2) et le recontrôle de gk2 (cas sûr, plafonds, audit). Aucun autre chemin d'écriture.
4. **Déploiement Debian intégré** : unités systemd, pas de LXC, **aucun nouveau montage dans l'agrégateur**.
5. **Stockage SQLite en WAL**.
6. **Premier périmètre : les données de gk2.** gk1, les pairs du maillage et MirrorNet viendront plus tard.
7. **Automatisation hybride par politique, avec approbation humaine** pour tout ce qui sort des cas d'office.
8. **Maquettes** : la planche « Radar » est approuvée (compteurs, anneau de gravité, fil des alertes en direct,
   classement des pays — **pas de carte du monde** —, cartes Messagerie / Sites web / Balayages, campagnes, panneau
   Analyste IA, familles d'alertes, blocs /24 cas sûrs, panneau Réponses avec plafonds et suspension). La planche
   « Chaîne » (7 couches : sources, collecte, corrélation, analyste IA, console, réponses, retour ; existant et à
   construire) sert de carte d'architecture au § 5.

## 3. Corrections apportées à la spécification proposée

| # | La proposition disait | Ce document retient | Raison |
|---|---|---|---|
| C1 | YAML dans `/etc/secubox-ai/` (`config.yaml`, `models.yaml`, `policies.yaml`, `sources.yaml`), PyYAML | **TOML** : `/etc/secubox/ai.toml` (existant, sections nouvelles) et `/etc/secubox/ai/politiques.toml` ; `tomllib` de la bibliothèque standard | AGENTS : config TOML sous `/etc/secubox/` ; le paquet lit déjà `ai.toml` ; une dépendance de moins |
| C2 | Socket `/run/secubox-ai/api.sock` | **`/run/secubox/ai.sock`** (existant, 0660, groupe `secubox`) | AGENTS et RULES-CODE § 2 : `/run/secubox/<module>.sock` ; nginx y envoie déjà `/api/v1/ai/` |
| C3 | Llama.cpp en TCP `http://127.0.0.1:8080`, modèle secondaire sur 8081 | **Moteurs existants** : `secubox-ai-moteur` sur `/run/secubox-ai/moteur.sock` (local, géré par `secubox-aictl`) et le moteur distant de gk0 (`[distant]`, clé) ; choix par `api/moteurs.py` | Jamais de port TCP direct ; le moteur, sa mémoire (contexte automatique, refus de démarrer) et son arrêt d'inactivité existent et sont calibrés sur gk3 |
| C4 | RBAC `ai.read`, `ai.analyze`, `ai.approve`, `ai.execute`, `ai.admin` | **`require_jwt`** sur toute route (administrateur réel), `GET /health` seul sans garde, comme 0.1.x. Le RBAC fin n'est **pas** introduit | AGENTS § API ; aucun rôle de ce genre n'existe dans `secubox_core.auth`. Question ouverte Q1 |
| C5 | Table `audit_log` chaînée dans SQLite comme journal d'audit | **`/var/log/secubox/audit.log` (ajout seul) reste obligatoire** pour toute décision de sécurité ; la table chaînée s'y **ajoute** (lecture rapide, détection d'une réécriture de la base) | AGENTS § CSPN ; la proposition le reconnaît : un chaînage dans la base ne la rend pas inviolable |
| C6 | « Isolation et permissions » sans AppArmor, secrets non situés | Compte **`secubox-ai`** (existant), **AppArmor enforce** pour chaque service nouveau, secrets sous **`/etc/secubox/secrets/ai/`**, socle systemd RULES-CODE § 10 | AGENTS § Réseau/sécurité ; le profil du moteur local est encore en complain (README) : à passer en enforce (phase 7) |
| C7 | Sources Fail2ban, nftables, sbxwaf, nginx, WireGuard, nDPI | Sources réelles de gk2 : **sbxwaf** (journal des menaces `waf-threats.log`), **sbx-authwatch** (SSH, SASL, IMAP, balayages, leurres de service — écrit au **même** journal et dans le **même** ensemble `waf_ban`), **`bans.jsonl`** (historique des bans et famille), **nft** (`waf_ban`, `secubox_waf_blocs`), **leurres / honeypot**, **security-posture**, **campagnes du WAF**. Pas de Fail2ban. DNS et nDPI plus tard | Fail2ban n'existe pas dans SecuBox-DEB (sbx-authwatch l'a remplacé, #1220) ; on ne collecte que ce que gk2 produit vraiment |
| C8 | « Helper privilégié » `secubox-ai-actions` sur la box de l'IA, adaptateurs nftables / WAF / WireGuard, nouvelles règles nftables | **Aucun helper privilégié sur gk3, aucune règle nftables posée depuis gk3.** Le § 18 de la proposition existe déjà : c'est la chaîne de #3716 (jeton `ai-ban` signé par requête → `require_ai_ban` → bornes et cas sûr recontrôlés sur gk2 → `wafctl` / `waf-blocs` root → `audit.log`). La V2 n'ajoute des gestes que **par ce compte** (ex. `prolonger`), implantés côté gk2 dans `gestes_ia.py` | Un seul chemin d'écriture, déjà relu et déployé ; gk2 ne fait foi de rien de ce que dit le relais |
| C9 | `require_confidence: 0.95` comme condition d'un ban automatique | **Supprimé comme garde.** Le cas sûr est décidé **par le code**, relais ∧ gk2 (familles ⊆ `CATEGORIES_SURES`, ≥ `SEUIL_BLOC` adresses, plafonds), jamais par la confiance d'un modèle | La confiance d'un LLM n'est ni calibrée ni vérifiable ; mémoire « IA : éviter les inventions, contrôle par le relais et pas par une consigne » (#3509) |
| C10 | Corrélateur qui détecte lui-même campagnes SSH, SMTP, scanners, WAF | Le corrélateur **reprend** les campagnes du WAF (`/waf/campaigns`), les familles de `bans.jsonl` et les blocs de `waf-blocs` comme faits ; sa valeur propre est l'**incident multi-sources** (même acteur ou même bloc vu par plusieurs sources ou plusieurs services) | Ne pas dupliquer sbxwaf ni sbx-authwatch, qui comptent et bannissent déjà ; deux vérités divergeraient |
| C11 | Nouveaux panneaux SBXOS décrits en liste | **Maquette Aurora avant chaque écran nouveau** : Radar approuvé ; Incidents et Réponses (détail) auront chacun leur maquette approuvée avant code | `.claude/AURORA-REFERENCE.md`, `.claude/WEBUI-PANEL-GUIDELINES.md` |
| C12 | `Version 2.0.0`, `Section: net`, `debian/install`, `conffiles` génériques, unités sous `debian/` | `X.Y.Z-N~trixie1`, `debhelper-compat (= 13)` (le paquet le porte déjà), `Standards-Version: 4.6.2`, SPDX CMSD-1.0 sur tout fichier, `postinst` `systemctl enable --now`, `prerm` `systemctl stop`, unités dans `packages/secubox-ai/systemd/` | AGENTS § Paquets |
| C13 | 4 services (api, worker, collector, correlator), `MemoryMax=768M` du worker | **2 processus Python** : `secubox-ai.service` (API, existant) et `secubox-ai-veille.service` (collecte, corrélation, file de travaux, réponses) | gk3 a ~3,2 Go disponibles avec `mail` et le kiosque ; un seul écrivain SQLite ; une seule unité détient la clé `ai-ban` (§ 5.3) |
| C14 | Plateformes MOCHAbin, RPi 5, N100 | Cible **gk3** d'abord (paquet `Architecture: all` ; llama-server de `secubox-zia-llm`) ; autres plateformes plus tard | Premier périmètre décidé (D6) |
| C15 | Analyste IA conversationnel `/chat` neuf | Le dialogue existe (`/essai/flux`) ; l'analyste V2 est une **tâche** (`api/taches.py`) sur un incident, et le dialogue reçoit l'incident en contexte | Ne pas dupliquer `dialogue.py` |

Ce qui est **gardé** de la proposition : séparation analyse IA / décision, preuves obligatoirement présentes en base,
prompts versionnés, mode dégradé sans LLM, propositions qui expirent, approbation liée à une version de proposition,
protection contre la double exécution, file de travaux SQLite, rétentions, tests de sécurité (injection dans les
journaux, JSON invalide, preuve inconnue, adresse protégée, double approbation), profils de charge.

## 4. Ce qui existe déjà

| Brique | Où | Ce qu'elle fait aujourd'hui |
|---|---|---|
| Module `secubox-ai` 0.1.2 | `packages/secubox-ai/` (README) | API `/run/secubox/ai.sock`, compte `secubox-ai`, AppArmor (API enforce, moteur complain), `ai.toml`, `memoire.db` (FTS5), journal sans contenu |
| Menaces (lecture de gk2) | `packages/secubox-ai/api/menaces.py` | GET `/waf/stats`, `/waf/bans`, `/waf/campaigns`, `/waf/alerts`, `/security-posture/overview` de gk2 ; relevé agrégé sans IA (cache 15 s), instantanés toutes les 2 min (≈ 3 h), lecture IA en double tampon, contrôles anti-invention, propositions sur catalogue fermé |
| Moteurs | `api/moteurs.py`, `api/contexte_auto.py`, `secubox-aictl`, `secubox-ai-moteur.service` | Moteur local (llama-server, socket Unix, contexte automatique, refus mémoire) ; moteur distant gk0 (clé) ; choix auto / local / distant |
| Tâches | `api/taches.py` | Tâches de fond avec étapes, avancement, arrêt, résultat partiel |
| Compte de service `ai-ban` | `common/secubox_core/compte_service.py` (branche #3716) | Jeton EdDSA par requête, `aud` = la box, portée `waf-ban`, `jti` unique, empreinte du corps, ≤ 60 s ; clé publique seule sur gk2 (`/etc/secubox-comptes-service/ai-ban/`), deux clés au plus (rotation) |
| Gestes IA sur gk2 | `packages/secubox-waf-ng/composants/waf/api/gestes_ia.py`, README de `secubox-waf-ng` § « Bans de bloc /24 et compte de service `ai-ban` » (1.35.x) | `POST /ai/ban` (adresse IPv4 publique ou /24 exact, 1 h–7 j ; `auto` = bloc seul, 24 h, cas sûr recontrôlé), `POST /ai/unban` (par `id`, jamais lève ce qu'une autre source couvre), `GET /ai/etat` ; plafonds 5/h·20/j d'office, 30/h·100/j du compte ; audit `ai-ban-demande` avant, `ai-ban` après |
| Blocs /24 | `waf-blocs` (root), table `inet secubox_waf_blocs` | Gardes privé / protégées / box / pairs WireGuard ; état root rejoué ; refus tant que `protegees.env` est vide |
| sbx-authwatch | `packages/secubox-toolbox-ng/cmd/sbx-authwatch/` | SSH, SASL postfix, IMAP dovecot, balayages, leurres de service ; écrit au journal des menaces du WAF et dans `waf_ban` |
| Routes de lecture de gk2 | `packages/secubox-waf-ng/composants/waf/api/main.py` | `require_lecture` : `/history`, `/campaigns`, `/detections`, `/alerts`, `/bans`, `/bans/history`, `/decisions`, `/reevaluations`, `/stats`, `/geoip/{ip}`… ; lecteur anonyme du LAN = « tableau de bord » (peut taire des champs) |
| Relevé réel du 2026-11-14 | maquette Radar | 1 411 menaces/jour, 2 499 bans actifs, 20 campagnes ; familles dominantes `auth_smtp:sasl_failed` (641), `host_anomaly:unrouted` (285), `scanners` (228) ; tous les bans d'origine `sbxwaf` |

État de #3716 : déployé sur gk2 (secubox-waf-ng 1.35.2), **automatique suspendu en attente du go du propriétaire** ;
le relais qui signe aujourd'hui est le POC de gk0 (`gestes.py`). La V2 hérite de cette suspension : elle ne la lève pas.

## 5. Architecture V2

### 5.1 Les sept couches (planche « Chaîne »)

| Couche | Existant | À construire en V2 |
|---|---|---|
| 1. Sources (gk2) | sbxwaf, sbx-authwatch, `bans.jsonl`, nft, leurres, security-posture, campagnes WAF | rien côté gk2 sauf une route de lecture manquante relevée en phase 0 |
| 2. Collecte (gk3) | relevé agrégé et instantanés de `menaces.py` | collecteur à curseurs, normalisation, déduplication, table `evenements` |
| 3. Corrélation (gk3) | — (gk2 fait campagnes et blocs) | incidents multi-sources, reprise des campagnes et blocs de gk2 |
| 4. Analyste IA (gk3) | lecture en double tampon, contrôles anti-invention | analyse d'incident en JSON validé, preuves vérifiées en base, prompts versionnés |
| 5. Console (gk3) | page `/ai/` (onglets du POC) | Radar, puis Incidents et Réponses (maquettes à approuver) |
| 6. Réponses | `ai-ban` + `waf-blocs` sur gk2 ; propositions sur catalogue fermé | politiques TOML, propositions, approbations, exécution par `ai-ban`, geste `prolonger` côté gk2 |
| 7. Retour | `GET /ai/etat`, `ai-ban.jsonl`, `audit.log` de gk2 | rapprochement de chaque action avec l'état de gk2, effet mesuré (l'acteur revient-il ?) |

### 5.2 Processus

```
gk2 (moteur de sécurité, fait foi)                      gk3 (secubox-ai, conseiller)
──────────────────────────────────                      ─────────────────────────────────────────────
sbxwaf, sbx-authwatch, waf-blocs                        secubox-ai.service  (API, existant)
routes require_lecture  ◀── GET (LAN, lecture) ──────── │  /run/secubox/ai.sock ◀─ nginx ◀─ console
                                                        │  lit veille.db (lecture seule)
                                                        │  écrit approbations (table approbations)
                                                        │
                                                        secubox-ai-veille.service  (NOUVEAU)
                                                        │  collecte → corrélation → file de travaux
                                                        │  analyses (tâches) → moteurs.py
/api/v1/waf/ai/* ◀── POST signé ai-ban (seul écrivain) ─│  réponses : clé ai-ban par LoadCredential
  require_ai_ban → bornes, cas sûr, plafonds            │  /var/lib/secubox/ai/veille.db (seul écrivain)
  → wafctl / waf-blocs (root) → audit.log de gk2        │  → /var/log/secubox/audit.log de gk3
```

- **`secubox-ai.service`** (existant) : sert la console et les routes nouvelles (§ 11). Il **lit** `veille.db` et
  n'y écrit que les décisions humaines (`approbations`, `propositions.etat`), dans des transactions courtes. Il ne
  détient pas la clé `ai-ban`.
- **`secubox-ai-veille.service`** (nouveau) : un seul processus Python (`User=secubox-ai`, socle RULES-CODE § 10,
  profil AppArmor `secubox-ai-veille` en enforce), boucles asynchrones : collecte (30 s), corrélation (60 s), file de
  travaux (analyses), exécuteur des réponses, rétention (horaire). Aucun socket d'écoute. Il continue sans moteur IA.
- **Moteurs** : inchangés (`secubox-ai-moteur`, distant gk0). Une analyse ne réveille le moteur local que si la
  politique le permet (§ 9.4) ; elle ne compte pas comme une activité de l'administrateur (même règle que le résumé
  automatique des menaces).
- Rien dans l'agrégateur, aucune route nginx nouvelle (le préfixe `/api/v1/ai/` existe), aucune exposition publique.

### 5.3 La clé `ai-ban` sur gk3

- Paire Ed25519 **générée sur gk3** par `secubox-aictl cle-ai-ban generer` (root) : privée
  `/etc/secubox/secrets/ai/ai-ban.key` (root 0600), publique imprimée pour être posée sur gk2 par
  `wafctl cle-ai-ban ajouter` (root, hors sudoers). La privée ne quitte jamais gk3.
- Remise à la seule unité `secubox-ai-veille` par `LoadCredential=` : l'API et le moteur ne la lisent pas.
- Coexistence avec le POC de gk0 : gk2 admet deux clés (rotation). Les **plafonds sont ceux du compte**, partagés entre
  les deux relais. Le retrait de la clé du POC est la question Q3.

### 5.4 Flux

1. **Collecte** : par source, GET sur la route de lecture de gk2 depuis le curseur gardé (`curseurs`), normalisation,
   empreinte, insertion idempotente. Une source injoignable marque son curseur `en_panne` ; rien n'est inventé.
2. **Corrélation** : sur la fenêtre glissante (30 min, réglable), rattache les événements aux faits de gk2
   (campagne, bloc, famille) et ouvre ou étend un incident quand une règle multi-sources est vraie (§ 8).
3. **Analyse** : un incident nouveau ou aggravé dépose une tâche `analyser` ; le travailleur construit le contexte
   (preuves marquées non fiables), appelle le moteur, valide le JSON, vérifie les preuves, enregistre.
4. **Proposition** : le moteur de politiques (code, pas le modèle) transforme une recommandation admise par le
   catalogue en proposition, ou la refuse avec un motif.
5. **Décision** : `auto` si la politique et le cas sûr le permettent (et que l'automatique n'est pas suspendu),
   sinon attente d'une approbation dans la console.
6. **Exécution** : `secubox-ai-veille` signe un jeton `ai-ban` et appelle gk2 ; la réponse de gk2 (200, 409 motif,
   503) est enregistrée telle quelle. gk2 a le dernier mot.
7. **Retour** : `GET /ai/etat` et la collecte suivante confirment l'état ; l'incident garde l'effet observé.

## 6. Données : `veille.db`

- Fichier `/var/lib/secubox/ai/veille.db` (à part de `memoire.db` : la mémoire du dialogue a d'autres règles de vie
  privée et d'export). WAL, `foreign_keys = ON`, `busy_timeout = 5000`, transactions courtes, `temp_store` dans
  `/var/lib/secubox/ai/tmp/` (existant).
- **Un seul écrivain régulier** (`secubox-ai-veille`) ; l'API n'écrit que les décisions humaines.
- Migrations versionnées dans le paquet (`/usr/lib/secubox/ai/migrations/NNNN-*.sql`), appliquées par
  `secubox-ai-veille` au démarrage après une sauvegarde par l'API de sauvegarde SQLite (`veille.db.avant-NNNN`,
  une seule gardée) ; jamais de suppression de la base à la désinstallation ni à la purge.
- Horodatages UTC RFC 3339 (RULES-CODE § 8). Champs venant de gk2 = **données non fiables**.
- Garde d'espace : la collecte se suspend (et le dit) sous un seuil libre de `/var/lib` (réglable, 1 Gio par défaut,
  à mesurer en phase 0).

Tables (noms de la proposition traduits, colonnes adaptées) :

```sql
CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, appliquee_le TEXT NOT NULL);

-- Curseur par source (reprise après redémarrage, état de la source)
CREATE TABLE curseurs (
  source TEXT PRIMARY KEY,            -- 'waf_alertes', 'waf_bans', 'bans_historique', 'campagnes', 'posture', …
  position TEXT,                      -- dernier horodatage / id vu, propre à la source
  etat TEXT NOT NULL,                 -- 'ok' | 'en_panne' | 'suspendu'
  derniere_lecture TEXT, derniere_erreur TEXT, lus_total INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE evenements (
  id TEXT PRIMARY KEY,                -- uuid
  source TEXT NOT NULL,               -- 'sbxwaf' | 'sbx-authwatch' | 'bans' | 'nft' | 'leurre' | 'posture' | 'campagnes'
  id_source TEXT,                     -- identifiant stable s'il existe
  noeud TEXT NOT NULL,                -- 'gk2'
  horodatage TEXT NOT NULL,
  famille TEXT NOT NULL,              -- famille SecuBox telle que gk2 la nomme (scanners, auth_smtp, honeypot…)
  sous_famille TEXT,                  -- 'sasl_failed', 'unrouted'…
  gravite TEXT NOT NULL,              -- 'info' | 'low' | 'medium' | 'high' | 'critical' (échelle de gk2)
  ip_src TEXT, bloc24 TEXT,           -- bloc calculé à l'ingestion
  pays TEXT, service TEXT, vhost TEXT,
  message TEXT,                       -- tronqué (512), non fiable
  attributs_json TEXT NOT NULL DEFAULT '{}',
  empreinte TEXT NOT NULL,            -- SHA-256 (source, horodatage, ip, famille, vhost, id_source)
  cree_le TEXT NOT NULL,
  UNIQUE(empreinte)
);
CREATE INDEX idx_evt_temps ON evenements(horodatage);
CREATE INDEX idx_evt_ip ON evenements(ip_src, horodatage);
CREATE INDEX idx_evt_bloc ON evenements(bloc24, horodatage);
CREATE INDEX idx_evt_famille ON evenements(famille, horodatage);

-- Faits repris de gk2 (jamais recalculés ici)
CREATE TABLE campagnes (
  id TEXT PRIMARY KEY,                -- signature de la campagne du WAF
  outil TEXT, attaquants INTEGER, sondes INTEGER, haute_valeur INTEGER,
  premiere_vue TEXT NOT NULL, derniere_vue TEXT NOT NULL, attributs_json TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE blocs (
  bloc24 TEXT PRIMARY KEY, adresses INTEGER, familles_json TEXT, banni_jusqua TEXT, origine TEXT, vu_le TEXT NOT NULL
);

CREATE TABLE incidents (
  id TEXT PRIMARY KEY,
  regle TEXT NOT NULL,                -- règle de corrélation qui l'a ouvert (§ 8)
  cle TEXT NOT NULL,                  -- acteur : ip, bloc24 ou signature de campagne
  titre TEXT NOT NULL,                -- produit par le code, pas par le modèle
  etat TEXT NOT NULL,                 -- 'ouvert' | 'calme' | 'clos'
  gravite TEXT NOT NULL,              -- max des gravités des preuves (code)
  sources_json TEXT NOT NULL,         -- sources distinctes vues
  campagne_id TEXT REFERENCES campagnes(id),
  premiere_vue TEXT NOT NULL, derniere_vue TEXT NOT NULL, cree_le TEXT NOT NULL, maj_le TEXT NOT NULL,
  UNIQUE(regle, cle, premiere_vue)
);
CREATE TABLE incident_preuves (
  incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  evenement_id TEXT NOT NULL REFERENCES evenements(id),
  PRIMARY KEY(incident_id, evenement_id)
);

CREATE TABLE analyses (
  id TEXT PRIMARY KEY,
  incident_id TEXT NOT NULL REFERENCES incidents(id),
  moteur TEXT, modele TEXT, version_prompt TEXT NOT NULL,
  etat TEXT NOT NULL,                 -- 'en_attente' | 'valide' | 'rejete' | 'quarantaine' | 'echec' | 'sans_ia'
  resultat_json TEXT,                 -- objet validé seulement
  motif_rejet TEXT, commence_le TEXT, fini_le TEXT
);

CREATE TABLE travaux (
  id TEXT PRIMARY KEY, type TEXT NOT NULL, etat TEXT NOT NULL, priorite INTEGER NOT NULL DEFAULT 5,
  charge_json TEXT NOT NULL, essais INTEGER NOT NULL DEFAULT 0, essais_max INTEGER NOT NULL DEFAULT 3,
  disponible_le TEXT NOT NULL, verrouille_le TEXT, derniere_erreur TEXT, cree_le TEXT NOT NULL, maj_le TEXT NOT NULL
);
CREATE INDEX idx_travaux_prets ON travaux(etat, priorite, disponible_le);

CREATE TABLE propositions (
  id TEXT PRIMARY KEY,
  version INTEGER NOT NULL DEFAULT 1, -- l'approbation porte sur (id, version)
  incident_id TEXT REFERENCES incidents(id), analyse_id TEXT REFERENCES analyses(id),
  geste TEXT NOT NULL,                -- catalogue fermé : 'ban', 'ban_bloc', 'prolonger', 'unban'
  cible TEXT NOT NULL, duree_s INTEGER,
  mode TEXT NOT NULL,                 -- 'clic' | 'auto'
  politique TEXT NOT NULL,            -- clé de politiques.toml qui l'a admise
  motif TEXT NOT NULL,                -- produit par le code
  etat TEXT NOT NULL,                 -- 'proposee' | 'approuvee' | 'refusee' | 'expiree' | 'envoyee' | 'faite' | 'refusee_gk2' | 'echec'
  expire_le TEXT NOT NULL, cree_le TEXT NOT NULL
);
-- Une seule proposition vivante par geste et cible
CREATE UNIQUE INDEX idx_prop_vivante ON propositions(geste, cible)
  WHERE etat IN ('proposee', 'approuvee', 'envoyee');
CREATE TABLE approbations (
  id TEXT PRIMARY KEY, proposition_id TEXT NOT NULL REFERENCES propositions(id), version INTEGER NOT NULL,
  acteur TEXT NOT NULL,               -- 'sub' du jeton require_jwt
  decision TEXT NOT NULL,             -- 'approuver' | 'refuser'
  motif TEXT, cree_le TEXT NOT NULL,
  UNIQUE(proposition_id, version)     -- pas de double décision
);
CREATE TABLE actions (
  id TEXT PRIMARY KEY, proposition_id TEXT NOT NULL UNIQUE REFERENCES propositions(id),  -- pas de double exécution
  jti TEXT NOT NULL,                  -- du jeton envoyé (jamais le jeton)
  code_http INTEGER, reponse_json TEXT, id_gk2 TEXT, fin_gk2 TEXT,
  envoyee_le TEXT NOT NULL, constatee_le TEXT, effet TEXT  -- 'retour_acteur' | 'silence' | NULL
);

-- Chaînage EN PLUS de /var/log/secubox/audit.log (C5)
CREATE TABLE audit_chaine (
  id INTEGER PRIMARY KEY AUTOINCREMENT, horodatage TEXT NOT NULL, acteur TEXT NOT NULL,
  operation TEXT NOT NULL, objet TEXT, objet_id TEXT, resultat TEXT NOT NULL, details_json TEXT,
  empreinte_prec TEXT, empreinte TEXT NOT NULL
);

CREATE TABLE mesures (
  horodatage TEXT PRIMARY KEY, retard_collecte_s INTEGER, retard_correlation_s INTEGER,
  file_travaux INTEGER, memoire_dispo_mo INTEGER, moteur TEXT, latence_moteur_ms INTEGER, erreurs INTEGER
);
```

Écarts à la proposition : `UNIQUE(source, source_event_id)` remplacé par `UNIQUE(empreinte)` (plusieurs sources de
gk2 n'ont pas d'identifiant stable) ; `campaigns` devient un miroir des campagnes du WAF (C10) et `blocs` s'ajoute ;
`confidence` disparaît des incidents et des propositions (C9) ; `actions.rollback_*` est remplacé par le geste
`unban` (une annulation est une proposition comme une autre, et gk2 refuse de lever ce qu'une autre source couvre).

Rétention (lots de 1 000, tâche horaire) : événements 30 j, incidents et analyses 365 j, mesures 30 j, propositions
et actions 730 j, `audit_chaine` 730 j ; `audit.log` suit sa propre rotation, jamais purgé par la V2.

## 7. Collecteur

- **Lecture de gk2 seulement par ses routes `require_lecture`** (GET, `trust_env=False`, délai court, `menaces_url`
  de `ai.toml`). gk3 ne lit aucun fichier de gk2 par SSH ni partage. Si une source n'a pas de route (relevé en
  phase 0), la route s'ajoute **dans le paquet propriétaire sur gk2**, en lecture, pas dans `secubox-ai`.
- Correspondance source → route (à confirmer en phase 0) :

  | Source | Route de gk2 | Ce qu'on en tire |
  |---|---|---|
  | sbxwaf + sbx-authwatch (journal des menaces) | `/waf/alerts`, `/waf/history`, `/waf/detections` | événements par adresse, famille, vhost, gravité, pays |
  | `bans.jsonl` | `/waf/bans/history`, `/waf/bans` (avec `famille`) | bans, prolongations, échéances, famille effective |
  | nft (`waf_ban`, blocs) | `/waf/bans`, `/waf/ai/etat` en lecture (jeton) ou `wafctl blocs` exposé en lecture | qui est banni maintenant |
  | Leurres / honeypot | familles `honeypot`, `leurre` du journal | contacts certains |
  | Campagnes du WAF | `/waf/campaigns` | signature, outil, attaquants (faits) |
  | security-posture | `/security-posture/overview` | contexte de la box (pas des événements d'attaque) |

- **Lecteur anonyme** : `require_lecture` sans jeton sert le « tableau de bord », qui peut taire des champs. La phase 0
  mesure ce qui manque ; si c'est bloquant, voir Q2 (compte de lecture).
- Normalisation vers `evenements` ; familles et gravités **telles que gk2 les nomme** (pas de taxonomie neuve) ;
  `bloc24` calculé ; message tronqué ; toute valeur inattendue rangée dans `attributs_json`, jamais interprétée.
- Déduplication par empreinte ; volume du jour (≈ 1 400 menaces, ≈ 8 500 observations) loin des profils de charge.
- Le relevé actuel de `menaces.py` (cache 15 s, instantanés 2 min) **reste** : le Radar en vit ; la collecte V2
  alimente l'historique, la corrélation et les preuves. À terme les instantanés peuvent se lire depuis `veille.db`
  (Q8).

## 8. Corrélateur

- **Déterministe, sans IA.** Fenêtre glissante de 30 min, passe toutes les 60 s, lots de 500.
- **Faits de gk2 repris** : campagnes (`/waf/campaigns`), familles de `bans.jsonl`, blocs de `waf-blocs` et cas sûrs
  candidats. Le corrélateur ne recompte pas ce que sbxwaf ou sbx-authwatch décident déjà (un ban SSH reste un fait
  d'sbx-authwatch, pas un incident recréé).
- **Règles V2** (valeur propre) — chaque règle a un nom stable écrit dans `incidents.regle` :
  1. `multi_source` : même adresse vue par ≥ 2 sources (ex. balayage authwatch puis sondes WAF) dans la fenêtre.
  2. `multi_service` : même adresse sur ≥ 2 services (smtp, imap, ssh, vhosts web).
  3. `bloc_mixte` : un /24 dont les adresses mêlent familles sûres et familles d'attaque (n'est **pas** un cas sûr :
     il va en un clic, jamais d'office).
  4. `retour_apres_ban` : une adresse ou un bloc revenu après la fin d'un ban (alimente « effet » et le geste
     `prolonger`).
  5. `campagne_etendue` : campagne du WAF dont des membres apparaissent aussi chez sbx-authwatch.
  6. `leurre_puis_attaque` : contact d'un leurre suivi d'une tentative réelle de la même adresse ou du même bloc.
- **Gravité** = maximum des gravités des preuves (échelle de gk2), éventuellement relevée d'un cran par une règle
  écrite (ex. `leurre_puis_attaque`). Pas de score de confiance : un incident a des preuves, pas une probabilité.
- Un incident sans nouvelle preuve depuis 6 h passe `calme`, 7 j `clos` (réglable).
- La sortie est testée sur des événements de référence tirés du relevé réel (phase 0), anonymisés (plages de
  documentation).

## 9. Analyste IA

### 9.1 Ce qu'il fait

Pour un incident : expliquer en français ce qui se passe, nommer les preuves, dire ce qui manque, et recommander au
plus N gestes **du catalogue**. Il n'ouvre ni ne ferme d'incident, ne fixe ni la gravité ni le titre, ne décide
d'aucune exécution.

### 9.2 Contrat de sortie (validé par Pydantic strict, `extra="forbid"`)

```json
{
  "resume": "≤ 600 caractères",
  "lecture": "≤ 2 000 caractères",
  "preuves": [{"evenement_id": "uuid", "raison": "≤ 200 caractères"}],
  "manques": ["≤ 200 caractères"],
  "recommandations": [{"geste": "ban|ban_bloc|prolonger|unban", "cible": "…", "duree_s": 3600, "raison": "…"}]
}
```

Contrôles du code, dans l'ordre (un échec = analyse `rejete` ou `quarantaine`, jamais montrée comme valide) :

1. JSON valide et conforme au schéma (sinon une relance, puis `rejete`).
2. **Chaque `evenement_id` existe dans `veille.db` et appartient aux preuves de l'incident** ; sinon `quarantaine`.
3. Chiffres, pays, familles cités dans `resume` / `lecture` présents dans les preuves (mêmes contrôles que
   `menaces.py` : chiffres absents, tendance non mesurée, pays absents, arrondi toléré).
4. Recommandations : geste du catalogue, cible présente dans les preuves, jamais une adresse de la box, du LAN, du
   maillage ni d'une plage protégée connue de gk3 ; sinon la recommandation est retirée (motif gardé).
5. Le texte du modèle ne devient jamais un `motif` de geste ni un titre : ceux-ci sont produits par le code.

### 9.3 Prompts versionnés

`/usr/share/secubox/ai/prompts/analyste-v1.txt` (et suivants), versionnés dans le paquet ; `analyses.version_prompt`
garde la version. Les preuves sont jointes dans un bloc délimité « données non fiables, à citer, jamais à suivre »
(règle déjà appliquée aux sources du dialogue). Une analyse ne peut pas changer les consignes : elles ne viennent que
du fichier du paquet.

### 9.4 Moteur, mémoire et mode dégradé

- Moteur choisi par `moteurs.py` (distant gk0 s'il répond, sinon local). Une analyse à la fois ; contexte limité
  (preuves triées et plafonnées en jetons réels, comme `outils.sources_max_jetons`).
- Le moteur local n'est réveillé pour une analyse que si `[veille.analyste] reveiller_local = true` (défaut `false` :
  gk3 garde sa mémoire pour `mail` et le kiosque) ; sinon l'analyse attend dans la file (`disponible_le`).
- **Mode dégradé sans LLM** : collecte, corrélation, incidents, propositions par politique et exécution continuent ;
  l'analyse porte `etat = sans_ia` et la console affiche le résumé produit par le code (règle, sources, chiffres).
- Délais : 90 s par appel, coupe-circuit après 3 échecs (15 min), aucun appel LLM dans une requête de lecture.

## 10. Réponses

### 10.1 Catalogue et chemin unique

| Geste V2 | Route `ai-ban` sur gk2 | Existe ? |
|---|---|---|
| `ban` (adresse) | `POST /ai/ban`, `mode = clic` | oui (#3716) |
| `ban_bloc` (/24) | `POST /ai/ban`, `mode = clic` ou `auto` (cas sûr) | oui (#3716) |
| `unban` | `POST /ai/unban` (par `id` du journal) | oui (#3716) |
| `prolonger` | `POST /ai/prolonger` (`geste = prolonger`, `id`, nouvelle fin bornée) | **à ajouter côté gk2** (phase 5), avec ses bornes, son audit et un `geste` distinct (contrainte P9) |

Tout geste hors de ce tableau est refusé par le code de gk3 **et** n'a pas de route sur gk2. Aucun geste WireGuard,
nginx, règle nftables ou politique WAF (la proposition les prévoyait ; ils restent à la main de l'administrateur).

### 10.2 Politiques (`/etc/secubox/ai/politiques.toml`)

Double tampon (ombre → validation → bascule, retour arrière 4R), validées au chargement ; une politique invalide
garde la précédente et le dit. Exemple :

```toml
version = 1

[defauts]
mode = "hybride"          # "observation" (rien n'est proposé à l'exécution) | "hybride"
refuser_inconnu = true    # geste absent du catalogue = refus
expiration_min = 120      # une proposition non décidée expire

[gestes.ban_bloc]
actif = true
auto = true               # d'office SEULEMENT si le cas sûr est vrai côté gk3 ET recontrôlé par gk2
duree_auto_s = 86400      # ≤ borne de gk2 (24 h)
duree_clic_s = 604800

[gestes.ban]
actif = true
auto = false              # une adresse seule : toujours en un clic

[gestes.prolonger]
actif = true
auto = false              # d'office plus tard, sur décision (Q5)
duree_max_s = 604800

[gestes.unban]
actif = true
auto = false

[suspension]
automatique_suspendu = true   # hérite de l'état de #3716 ; levé par l'administrateur seulement
```

Pas de `confidence` (C9). Le cas sûr côté gk3 reprend **le même ensemble** `CATEGORIES_SURES` et le même
`SEUIL_BLOC` que gk2 (constantes partagées par un fichier de données du paquet, testées contre celles de
`gestes_ia.py`) ; gk2 recontrôle de toute façon.

### 10.3 Propositions, approbations, exécution

- Une proposition naît du code (règle + politique), avec cible, durée, `motif` et `expire_le`. Une seule proposition
  vivante par (geste, cible).
- **Approbation** : `POST /api/v1/ai/propositions/{id}/approuver` (`require_jwt`), corps `{version}` ; refusée si la
  version a changé, si elle a expiré, ou si une décision existe déjà. `refuser` de même.
- **Exécution** : seul `secubox-ai-veille` exécute (approuvée ou d'office) ; la ligne `actions` est créée **avant**
  l'envoi (`UNIQUE(proposition_id)` empêche une double exécution, même après redémarrage) ; un envoi interrompu est
  rapproché par `GET /ai/etat` avant toute nouvelle tentative, jamais rejoué à l'aveugle.
- Plafonds : ceux de gk2 font foi ; gk3 garde des plafonds **plus bas ou égaux**, lus dans `politiques.toml`, pour ne
  pas épuiser ceux du compte (partagés avec le POC tant qu'il signe).
- **Suspension** : un interrupteur de la console (et `secubox-aictl veille suspendre`) arrête tout geste d'office ; les
  propositions en un clic restent possibles. Un 409 `plafond_*` répété ou un 503 de gk2 suspend l'automatique de
  lui-même et le dit (retour d'expérience de #3716).
- Audit : chaque proposition admise, approbation, refus, envoi et réponse de gk2 → une ligne de
  `/var/log/secubox/audit.log` de gk3 (jamais le jeton, l'empreinte de la clé) **et** une ligne de `audit_chaine`.

## 11. Console

### 11.1 Radar (maquette approuvée)

Premier écran nouveau, dans la page `/ai/` (onglet « Radar », avant « Menaces »), style Aurora. Contenu de la
maquette : compteurs (menaces du jour, observées, bans actifs, alertes de l'heure, campagnes), anneau de gravité,
**fil des alertes en direct**, **classement des pays** (pas de carte), cartes Messagerie (smtp, SASL), Sites web
(vhosts), Balayages, campagnes les plus actives, panneau Analyste IA (dernier incident analysé, état du moteur),
familles d'alertes, blocs /24 cas sûrs, panneau Réponses (en attente, faites, plafonds restants, interrupteur de
suspension). Chaque chiffre vient du relevé ou de `veille.db`, jamais du modèle.

Routes de lecture (toutes `require_jwt`, GET) : `/radar` (agrégat en cache, ≤ 15 s), `/radar/fil` (curseur), `/incidents`,
`/incidents/{id}`, `/propositions`, `/propositions/{id}`, `/actions`, `/veille/etat` (sources, curseurs, retards,
file, moteur). Actions (`require_jwt`, POST) : `/incidents/{id}/analyser`, `/propositions/{id}/approuver`,
`/propositions/{id}/refuser`, `/veille/suspendre`, `/veille/reprendre`. Pagination par curseur, 100 par défaut,
500 au plus.

### 11.2 Écrans suivants (maquette à approuver avant code)

- **Incidents** : liste et détail (chronologie des preuves, sources, campagne et bloc de gk2, analyse, manques).
- **Réponses** : propositions, historique des actions avec la réponse de gk2, effet observé, politiques en lecture.
- **Moteur** (état, file, latence) : peut rester dans l'onglet Modèles existant.

Les onglets du POC (Essai, Menaces, Code, Documents, Mémoire, Historique, Modèles, Préférences, Médias, Journal)
restent tels quels.

## 12. Garde-fous

- **gk2 fait foi** : gk3 propose, signe et enregistre ; gk2 décide, borne, recontrôle et audite.
- Un seul chemin d'écriture : `ai-ban`. Pas de sudo, pas de `systemd-run`, pas de helper root nouveau sur gk3
  (hors verbes `secubox-aictl` : clé, suspension, migrations — root, arguments en liste blanche, audités).
- Le modèle n'a ni shell, ni fichier, ni réseau : il reçoit un texte et rend un JSON que le code valide.
- Cas sûr = code (relais ∧ gk2) ; automatique suspendu par défaut ; plafonds ; expiration des propositions.
- Unités : socle RULES-CODE § 10, `UMask=0027`, `ProtectSystem=strict`, `ReadWritePaths=/var/lib/secubox/ai`,
  AppArmor enforce, `IPAddressAllow` limité à gk2 et gk0 pour `secubox-ai-veille` (comme le drop-in de l'API).
- Vie privée : le journal du module ne reçoit ni adresse lue, ni question, ni résumé (règle de 0.1.x) ; les adresses
  vivent dans `veille.db` (0640, `secubox-ai`), rétention bornée.
- Secrets : `/etc/secubox/secrets/ai/` seulement ; jamais dans `ai.toml` ni `politiques.toml`.
- TLS : appels à gk2 vérifiés (CA de la box), jamais `verify=False` (RULES-CODE § 4).
- Async : aucun appel bloquant dans la boucle (RULES-CODE § 6) ; SQLite par `asyncio.to_thread`.

## 13. Tests

- **Unitaires** (`packages/secubox-ai/tests/`, suffixe de l'issue de phase) : normalisation et empreinte par source,
  curseurs et reprise, déduplication ; règles de corrélation sur événements de référence ; schéma de l'analyste
  (JSON invalide, champ en trop, preuve inconnue, preuve d'un autre incident, chiffre absent) ; politiques (TOML
  invalide, geste inconnu, `auto` hors cas sûr, plafonds, expiration, version d'approbation) ; signature du jeton
  `ai-ban` (portée, `aud`, `corps`, `jti`) contre la garde réelle de `secubox_core.compte_service` ;
  `test_toute_route_est_gardee` étendu.
- **Intégration** (banc, gk2 simulé par une application FastAPI de test servant les routes de lecture et `/ai/*`) :
  1 000 événements de référence → incidents attendus → analyse (moteur factice puis moteur réel) → proposition →
  approbation → envoi → 200 / 409 / 503 → état et audit ; redémarrage de `secubox-ai-veille` en plein envoi.
- **Sécurité** : injection de consignes dans un message, un vhost, un user-agent ; double approbation et double
  exécution concurrentes ; adresse protégée ; proposition expirée ; moteur arrêté ; file saturée ; base verrouillée ;
  base corrompue (restauration depuis la sauvegarde de migration) ; jeton rejoué (doit échouer côté gk2) ; revue
  `relecteur-securite` sans constat bloquant.
- **Charge** : 100 / 500 / 1 000 événements par minute (profils, pas des garanties) ; retard de collecte et de
  corrélation, temps de réponse de `/radar`, taille de la base à 30 j, mémoire des deux processus.
- **Matériel gk3** : mémoire et CPU avec `mail` et le kiosque actifs ; le moteur local n'est pas démarré par la veille
  par défaut ; `mail` et le kiosque répondent pendant une analyse longue.

## 14. Phases

Chaque phase est une issue GitHub, un worktree, une PR ; déployée sur gk3 par paquet avant la suivante. Versions de
travail `2.0.0~pN-1~trixie1` (le tilde les place avant `2.0.0-1~trixie1`), version finale en phase 7.

| Phase | Titre | Livrable | Dépend de |
|---|---|---|---|
| 0 | Audit des sources réelles de gk2 | inventaire route → champs → volume → lecteur anonyme ; événements de référence anonymisés ; mesures mémoire et disque de gk3 ; liste des routes de lecture manquantes | #3716 déployé |
| 1 | Socle de la veille | `veille.db` (WAL, migrations, sauvegarde), `secubox-ai-veille.service` (AppArmor enforce), `[veille]` dans `ai.toml`, `audit_chaine`, `/veille/etat` | 0 |
| 2 | Collecteur | curseurs par source, normalisation, déduplication, garde d'espace, rétention | 1 |
| 3 | Corrélateur | faits de gk2 repris, 6 règles multi-sources, incidents, `/incidents` | 2 |
| 4 | Analyste IA | tâche `analyser`, contrat JSON validé, preuves vérifiées, prompts versionnés, mode dégradé | 3 |
| 5 | Réponses par `ai-ban` | `politiques.toml`, propositions, approbations, exécuteur, clé sur gk3, geste `prolonger` sur gk2, suspension | 3 (4 pour les recommandations), #3716 clos |
| 6 | Console Radar, Incidents, Réponses | onglet Radar (maquette approuvée) ; maquettes Incidents et Réponses approuvées puis écrans | 3, 5 |
| 7 | Paquet 2.0.0 et validation | `2.0.0-1~trixie1`, tests de charge et matériels, montée depuis 0.1.x, AppArmor du moteur en enforce, README, wiki, suivi | 1–6 |

Critères d'acceptation : voir le fichier des phases (corps des issues) ; résumé ici.

- **0** : chaque source du § 7 a sa route, ses champs et son volume réels relevés ; ce que le lecteur anonyme tait est
  écrit ; ≥ 200 événements de référence anonymisés versionnés ; aucune commande d'écriture sur gk2.
- **1** : installation sur gk3 sans régression des onglets 0.1.x ; base en WAL, migrations rejouables ; l'unité tourne
  en enforce sans refus AppArmor ; arrêt du moteur IA sans effet sur la veille.
- **2** : collecte réelle de gk2 sur 24 h sans doublon ni trou (rapprochement avec les compteurs de gk2 à ±1 %) ;
  reprise après redémarrage ; gk2 injoignable = source `en_panne`, rien d'inventé.
- **3** : chaque règle a un test sur les événements de référence ; aucune campagne du WAF recalculée ; un incident
  multi-sources réel au moins observé sur gk2 ou expliqué pourquoi aucun.
- **4** : 100 % des analyses montrées comme valides ont toutes leurs preuves en base ; injection dans les journaux
  sans effet ; mode sans IA complet.
- **5** : aucun geste hors catalogue possible ; double approbation et double exécution impossibles (test concurrent) ;
  un geste d'office n'a lieu qu'avec suspension levée et cas sûr vrai des deux côtés ; `prolonger` relu par
  `relecteur-securite` ; audit des deux côtés.
- **6** : Radar conforme à la maquette approuvée, chiffres identiques au relevé ; maquettes Incidents et Réponses
  approuvées avant leur code.
- **7** : `apt install` propre et montée depuis 0.1.2 sans perte (mémoire, historique, modèles, préférences) ;
  profils de charge mesurés ; `mail` et kiosque de gk3 intacts ; `relecteur-securite` sans constat bloquant.

## 15. Questions ouvertes

### Tranchées par le propriétaire (2026-11-14)

- **Q1** : pas de RBAC fin en V2 ; `require_jwt` sur toute route, comme le reste du dépôt.
- **Q2** : gk3 lit gk2 par un **compte de service en lecture seule** (même mécanisme que `ai-ban`, portée lecture), pas
  par le lecteur anonyme du LAN — à créer en phase 2.
- **Q3** : la clé ai-ban du POC gk0 est **retirée** (`wafctl cle-ai-ban retirer`) le jour où la V2 signe depuis gk3.


- **Q1 — RBAC fin** (`lecture`, `analyser`, `approuver`, `administrer`) : utile si un second opérateur apparaît ;
  aujourd'hui `require_jwt` seul. À reprendre avec `secubox-auth`, plus tard.
- **Q2 — Lecteur de gk2** : le lecteur anonyme du LAN suffit-il (champs tus) ? Sinon, un compte de service de
  **lecture** (même mécanique Ed25519 que `ai-ban`, portée `waf-lecture`) plutôt qu'une session.
- **Q3 — POC gk0** : quand la V2 signe depuis gk3, la clé du POC est-elle retirée (`wafctl cle-ai-ban retirer`) ou les
  deux relais coexistent-ils, plafonds partagés ?
- **Q4 — Levée de la suspension** : la V2 hérite de l'automatique suspendu de #3716. Qui le lève, et après quelle
  période d'observation sur gk3 ?
- **Q5 — `prolonger` d'office** : sur `retour_apres_ban` d'un bloc cas sûr, autorisé d'office dans les plafonds, ou
  toujours en un clic ?
- **Q6 — Moteur de l'analyste** : le modèle local de gk3 (1B–3B) donne-t-il des lectures utiles, ou l'analyste
  n'écrit-il que quand gk0 répond (analyses différées) ?
- **Q7 — Notifications** : une proposition en attente doit-elle prévenir (mail du relais local, BBS, Companion) ou
  rester dans la console ?
- **Q8 — Instantanés de `menaces.py`** : garder leur fichier ou les lire depuis `veille.db` (une seule vérité) ?
- **Q9 — Rétention et disque de gk3** : 30 j d'événements tiennent-ils (mesure en phase 0) ?
- **Q10 — Sources suivantes** : DNS (Unbound, listes), nDPI, autres nœuds (gk1, maillage) : ordre et calendrier.
- **Q11 — Archivage des maquettes** : où ranger les planches Radar et Chaîne approuvées dans le dépôt ?
