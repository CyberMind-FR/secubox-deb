<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# RFC-0013 — Prompt Claude Code : audit, implémentation et validation live

> Source : `SecuBox_Actor_Intelligence_Design_FINAL.pdf` (RFC pack « TPI inverse,
> profils d'acteurs, score de connaissance et défense adaptative », v0.1 —
> 6 septembre 2026). Ce fichier reproduit **verbatim** le prompt de la RFC-0013,
> mission de référence pour construire le moteur **Actor Intelligence** (`sbx-actord`).
> Voir le pack de design : [`actor-intelligence-rfc-pack.md`](actor-intelligence-rfc-pack.md)
> et l'audit préalable : [`actor-intelligence-audit.md`](actor-intelligence-audit.md).
> Issue de suivi : #1240 (umbrella Cyber Senses / Intelligence).

**But :** donner à Claude Code une mission complète, fondée sur le dépôt réel,
pour auditer l'existant, implémenter Actor Intelligence sans casser SBX WAF / DPI /
Sentinel, puis vérifier les résultats en shadow mode et en live.

```text
Tu travailles dans le dépôt GitHub CyberMind-FR/secubox-deb.

MISSION
Implémenter une évolution défensive de SecuBox Toolbox NG appelée « Actor Intelligence / TPI inverse ». Le but n'est PAS d'attribuer une personne physique ni de contre-attaquer. Le but est de corréler localement des événements WAF, DPI, Sentinel et authentification afin de reconnaître des campagnes probables malgré les changements d'IP, mesurer ce que l'émetteur semble connaître de la cible, distinguer automatisation et ciblage, expliquer chaque score, puis proposer une réponse défensive graduée.

CONTRAINTE ABSOLUE
CrowdSec est retiré de l'architecture actuelle. Ne l'ajoute pas, ne le réactive pas, ne crée aucune nouvelle dépendance vers CrowdSec. Si des références historiques subsistent dans le dépôt, inventorie-les comme dette documentaire et propose leur suppression/migration séparément. L'architecture cible est SBX WAF + Toolbox NG + DPI + Sentinel + moteurs SecuBox/CyberMind maison.

0. COMMENCE PAR UN AUDIT, NE CODE PAS À L'AVEUGLE
- Inspecte packages/secubox-toolbox-ng, packages/secubox-waf-ng, packages/secubox-waf, packages/secubox-dpi, Sentinel, les APIs WebUI, systemd units, sockets Unix, stockage, logs, règles, scénarios et tests.
- Retrouve l'implémentation réelle de sbxwaf, sbxmitm, sbx-sentinel, sidecars, event/verdict stores et mécanismes de bannissement/ratelimit actuels.
- Cherche les fonctions déjà présentes qui font scénario, corrélation, scoring, fingerprinting, JA4/TLS, HTTP fingerprint, ASN/Geo, honeypot/leurres ou agrégation.
- Dresse un tableau : EXISTANT / PARTIEL / MANQUANT / À NE PAS DUPLIQUER.
- Identifie les références CrowdSec résiduelles sans les utiliser.
- Avant toute modification, produis docs/design/actor-intelligence-audit.md avec les chemins de fichiers et symboles exacts.

1. ARCHITECTURE CIBLE
Préserve le hot path. SBX WAF et DPI doivent seulement produire des événements compacts et asynchrones. Aucun appel réseau externe bloquant dans le chemin requête.

Créer, si l'audit confirme que cela n'existe pas déjà :
packages/secubox-toolbox-ng/cmd/sbx-actord/
packages/secubox-toolbox-ng/internal/actor/

Sous-modules :
- envelope : schéma Event Envelope v1
- features : extraction de caractéristiques
- similarity : similarité multi-signal
- graph : ActorGraph / campagnes
- knowledge : KnowledgeScore
- intent : IntentScore + AutomationScore + PersistenceScore
- evidence : Evidence Ledger append-only/logique immuable
- response : recommandations défensives avec TTL/rollback
- api : stats/actors/campaigns/evidence
Réutilise les bibliothèques et conventions existantes du dépôt plutôt que créer une deuxième infrastructure.

2. EVENT ENVELOPE V1
Normalise au minimum :
event_id, timestamp, sensor, src_ip, src_port, dst_service, vhost,
transport, protocol, action, rule_id, severity,
credential_token_hash, path_shape, user_agent_family,
tls_fingerprint, http_fingerprint, behavior_tags,
asn, geo_country, reverse_dns_class,
request_rate_bucket, session_duration_bucket, evidence_refs.

Minimise les PII. Ne conserve jamais un mot de passe. Pour les identifiants utiles à la corrélation, utilise HMAC-SHA256 avec secret local rotatable plutôt qu'un SHA256 nu lorsque cela protège mieux contre les dictionnaires.

3. ACTORGRAPH
Une IP n'est pas une identité.
Implémente une corrélation multi-signal explicable, versionnée et testable.
Poids de départ à calibrer :
- credential/token rare réutilisé : 30
- même séquence de chemins : 18
- famille d'outillage HTTP : 12
- empreinte TLS : 12
- cadence temporelle : 8
- IP identique : 10 avec décroissance
- ASN : 5
- pays : 1 maximum
Le pays seul ne doit jamais provoquer une décision.

Expose continuity_score 0..100 et confidence 0..100.
Ne présente jamais « même attaquant certain ». Utilise « continuité de campagne probable ».

4. KNOWLEDGESCORE
K0 générique
K1 public
K2 contextuel
K3 historique/spécifique
K4 sentinelle/canari

Construis un score 0..100 avec explication par evidence_id.
Prévois une allowlist de données connues comme publiquement exposées afin d'éviter de surévaluer un login présent dans une fuite ou une ancienne page indexée.

5. HONEY-IDENTITIES
Ajoute un framework optionnel, DARK par défaut, permettant des identifiants canaris qui ne donnent aucun accès :
- alias SSH inexistant
- adresse mail canari
- endpoint leurre
- identifiant synthétique
Chaque leurre possède id, created_at, scope, exposure_state, secret provenance et TTL.
Une touche de canari crée une preuve forte mais ne suffit pas seule à une attribution.
Aucune fonctionnalité ne doit créer un compte authentifiable vulnérable.

6. INTENT / AUTOMATION / PERSISTENCE
Sépare impérativement les axes.
Détecte notamment :
- cadence régulière
- rotation d'IP avec payload stable
- séquences répétées
- reprise après changement de source
- adaptation aux réponses
- passage entre services
- faible volume mais forte pertinence
Un acteur peut être simultanément très automatisé et très ciblé.

7. THREAT VECTOR
Expose :
severity
knowledge
continuity
intent
automation
persistence
confidence

PriorityScore initial :
0.25*severity +
0.20*knowledge +
0.20*intent +
0.15*continuity +
0.10*persistence +
0.10*confidence

Ne mets pas automation directement dans la gravité.

8. DEFENSE ADAPTATIVE
Modes :
OBSERVE -> DELAY -> CHALLENGE -> TARPIT -> DENY -> QUARANTINE

Dans les premières phases, le moteur PROPOSE mais n'applique pas.
Toute action future doit avoir :
decision_id, reason, evidence_refs, created_at, TTL, rollback, scope, operator_override.
Pas de hack-back, scan offensif ou action sur l'hôte distant.
Préserve un kill switch global.

9. STOCKAGE ET API
Privilégie le mécanisme local déjà utilisé par Toolbox NG/Sentinel si adapté. Sinon bbolt ou SQLite.
API read-only locale :
GET /stats
GET /actors
GET /actors/{id}
GET /campaigns
GET /evidence/{id}

Feedback opérateur authentifié local :
POST /feedback/{actor_id}
labels : false_positive, confirmed_campaign, known_scanner, unknown

Le feedback peut influencer la calibration future mais ne modifie jamais les preuves historiques.

10. WEBUI
Intègre une vue conforme au mockup du document :
- posture actuelle
- attaques/tentatives
- acteurs identifiés
- campagnes actives
- carte des sources, présentée comme origine réseau et NON attribution
- top ASN/pays
- vecteurs
- statut SBX WAF
- Actor Cards
- profil acteur
- timeline
- flux OBSERVE/DELAY/CHALLENGE/TARPIT/DENY/QUARANTINE
- honey-identities
- score global
Chaque score doit être cliquable vers « Pourquoi ce score ? » avec evidence_refs et contre-hypothèses.

11. SHADOW MODE ET LIVE VALIDATION
La première activation doit être 100 % observation.
Aucun blocage automatique.
Ajoute métriques :
- events/sec
- queue depth
- dropped events
- processing p50/p95/p99
- RSS/CPU
- actors active
- merge/split count
- confidence distribution
- score distribution
- false-positive feedback
- WAF latency delta

Critère : l'émission vers Actor Intelligence ne doit pas ajouter plus de 1 ms p99 au hot path, hors traitement async.

12. TESTS
Unitaires :
- similarity
- score boundaries
- decay
- graph merge/split
- knowledge classification
- evidence immutability
- TTL/rollback
- privacy/HMAC

Fixtures :
A bot générique
B credential stuffing public
C campagne ciblée avec ancien login
D rotation VPN même pattern
E botnet multi-IP même payload
F deux acteurs distincts derrière même NAT
G canari touché
H faux positif
I changement ASN/pays sans changement comportemental
J même IP mais comportement totalement différent

Tests d'intégration :
SBX WAF -> event socket -> actord -> Actor Card
DPI -> actord
Sentinel -> actord
auth SSH/mail -> actord si collecteur existant
WebUI -> API

13. VALIDATION SUR DONNÉES LIVE
Ne modifie pas la production sans garde-fou.
Prévois :
--shadow
--read-only
--no-enforcement
--replay <journal>
--since <duration>

Créer un outil de replay permettant d'injecter une copie anonymisée des événements existants.
Comparer sur 24 h puis 7 jours :
- nombre d'événements
- clusters
- sources par cluster
- changements IP/ASN
- KnowledgeScore
- erreurs de fusion
- erreurs de séparation
- coût CPU/RAM
- impact p99 WAF

Produire automatiquement :
/var/lib/secubox/actor/reports/actor-intelligence-live-report.json
et un rapport lisible Markdown/HTML dans le portail.

14. OBSERVABILITÉ ET PREUVES
Chaque Actor Card doit pouvoir expliquer :
« score 78 parce que ... »
avec contributions positives/négatives.
Stocke algorithm_version et weights_version.
Une mise à jour des poids ne doit pas falsifier les anciens verdicts.

15. SÉCURITÉ
- user systemd dédié ou réutilisation justifiée d'un compte non privilégié
- NoNewPrivileges
- ProtectSystem strict si compatible
- ProtectHome
- capabilities minimales
- socket permissions minimales
- pas de secret dans les logs
- rotation des journaux
- limites de taille/retention
- validation stricte des événements
- résistance aux événements forgés destinés à polluer le clustering
- backpressure : si actord tombe, SBX WAF continue de protéger
- aucune dépendance cloud obligatoire

16. LIVRABLES
A. audit d'existant
B. design final mis à jour
C. plan d'implémentation par commits atomiques
D. code
E. tests
F. unités systemd/config Debian
G. API
H. WebUI
I. replay harness
J. rapport live
K. documentation opérateur
L. migration/rollback
M. liste explicite des références CrowdSec historiques à retirer, sans les réintroduire

17. MODE DE TRAVAIL
Avant chaque phase :
- montre les fichiers touchés
- explique ce qui est réutilisé
- donne les risques
- exécute les tests pertinents
- ne masque aucun test rouge
- n'affirme jamais « live validé » sans montrer les mesures
- ne remplace pas une fonction existante avant d'avoir démontré la parité
- garde les changements petits et réversibles

18. GO/NO-GO
GO pour activer les recommandations opérateur si :
- aucun impact fonctionnel WAF/DPI/Sentinel
- p99 hot path dans le budget
- zéro perte silencieuse d'événements
- scores explicables
- fixtures passent
- replay 24 h cohérent
- faux regroupements documentés et acceptables

GO pour automatiser DENY/QUARANTINE uniquement dans une phase ultérieure et séparée, après validation humaine sur plusieurs jours. Ne l'active pas dans cette implémentation initiale.

À LA FIN
Fournis :
1. résumé de l'architecture réellement trouvée ;
2. diff conceptuel par rapport à cette RFC ;
3. liste des commits ;
4. résultats de tests ;
5. résultats shadow/live avec chiffres ;
6. captures ou description WebUI ;
7. risques restants ;
8. commandes exactes pour activer, désactiver et rollback ;
9. recommandations de calibration des poids.
```

## Checklist de revue avant merge (RFC-0013)

- Actor Intelligence peut être désactivé sans réduire la protection SBX WAF.
- Aucune nouvelle dépendance CrowdSec n'est introduite.
- Le hot path ne fait aucun enrichissement externe synchrone.
- Chaque score possède une explication et une version d'algorithme.
- Les canaris ne donnent aucun accès réel.
- Les pays/ASN restent des indices contextuels et non une attribution.
- Le shadow mode est le mode initial.
- Les données live sont minimisées et leur rétention est configurable.
- Les décisions sont réversibles et l'enforcement initial reste désactivé.
- Le rapport live contient des mesures p50/p95/p99, CPU/RAM et faux positifs.
