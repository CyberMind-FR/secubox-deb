<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# SecuBox Toolbox NG — Threat Actor Intelligence (RFC pack)

> **RFC pack : TPI inverse, profils d'acteurs, score de connaissance et défense adaptative.**
> Version 0.1 — 6 septembre 2026 — Draft pour issue / revue d'architecture.
> Source : `SecuBox_Actor_Intelligence_Design_FINAL.pdf` (17 pages), transcrit ici
> car le PDF est un binaire hors-dépôt. Prompt d'implémentation :
> [`actor-intelligence-rfc13-prompt.md`](actor-intelligence-rfc13-prompt.md).
> Audit préalable : [`actor-intelligence-audit.md`](actor-intelligence-audit.md).
> Issue de suivi : **#1240** (umbrella Cyber Senses / Intelligence).

**Objectif :** transformer les événements déjà vus par SBX WAF, DPI et Sentinel en
une intelligence locale et explicable : « est-ce le même acteur malgré le changement
d'IP ? », « que semble-t-il connaître de la cible ? », « s'agit-il d'un bruit automatisé
ou d'une campagne ciblée ? » et « quelle réponse défensive proportionnée appliquer ? ».

**État du dépôt (point de départ).** SecuBox-Deb contient déjà un sbxwaf Go host-native
dans secubox-toolbox-ng, un moteur Sentinel asynchrone et un mécanisme de sidecars.
Cette RFC n'ajoute pas un nouveau SIEM lourd : elle ajoute une **couche d'identité
comportementale** au-dessus des événements existants.

**Important : CrowdSec est explicitement HORS architecture cible.** Les anciennes
références sont de la dette documentaire, pas une dépendance de conception.

---

## RFC-0000 — Philosophie : de l'IP à l'acteur probable

Une adresse IP est un **transport, pas une identité**. Un « acteur » SecuBox est un
**cluster probabiliste** d'événements partageant assez de caractéristiques stables pour
être étudiés ensemble. Le moteur ne doit jamais afficher « cet attaquant est X » sur la
seule base d'une IP, d'un ASN ou d'un pays. Il affiche : ce qui est **observé**, ce qui
est **inféré**, le **niveau de confiance**, les **hypothèses concurrentes**, et les
**preuves** permettant de reproduire le verdict.

**Trois questions centrales :** (1) *Continuité* — plusieurs sources réseau appartiennent-elles
à la même campagne / au même outillage ? (2) *Connaissance* — l'émetteur utilise-t-il des infos
génériques, publiques, historiques, spécifiques ou sentinelles ? (3) *Intention* — scan
opportuniste, énumération, credential stuffing, reconnaissance ciblée ou progression coordonnée ?

**Non-objectifs :** attribuer une personne physique ; « riposter » ; collecter des données
externes intrusives ; bloquer automatiquement sur géolocalisation ; confondre corrélation et
preuve d'identité.

## RFC-0001 — SBX ActorGraph

ActorGraph reçoit les événements normalisés (SBX WAF, DPI, SSH/mail auth logs, Sentinel) et
construit des « actor candidates ».

**Event Envelope v1** — format commun :
`event_id, ts, sensor, src_ip, src_port, dst_service, vhost, transport, protocol, action,
rule_id, severity, credential_token_hash, path_shape, user_agent_family, tls_fingerprint,
http_fingerprint, behavior_tags, asn, geo_country, reverse_dns_class, request_rate_bucket,
session_duration_bucket, evidence_refs[]`. Valeurs sensibles hashées ou bucketisées.

**Fingerprint multi-signal** — le score de continuité entre deux événements ne repose jamais
sur un seul attribut. Pondération initiale : credential/token rare réutilisé **+30** ; même
séquence chemins/endpoints **+18** ; même famille d'outillage HTTP **+12** ; même empreinte TLS
**+12** ; même cadence temporelle **+8** ; même ASN **+5** ; même pays **+1** ; IP identique **+10**
(avec décroissance temporelle).

**Seuils :** 0–29 non relié ; 30–49 ressemblance faible ; 50–69 campagne probable ; 70–84 forte
continuité ; 85–100 très forte continuité (toujours « probable », jamais identité certaine).

**Actor Card** (objet local) : `actor_id, confidence, first_seen/last_seen, source_count,
asn_count/country_count, targeted_services, knowledge_score, automation_score, persistence_score,
campaign_score, top_behaviors[], top_evidence[], counter_hypotheses[], recommended_response`.

## RFC-0002 — KnowledgeScore : ce que l'attaquant semble savoir

Taxonomie : **K0** générique (admin, root, test, wordpress, chemins standards) ; **K1** public
(domaine, techno fingerprintable, comptes publics) ; **K2** contextuel (structure/identifiant
cohérent avec l'organisation) ; **K3** historique (login/alias/hostname utilisé auparavant mais
non nécessaire au service actuel) ; **K4** sentinelle (donnée canari créée uniquement pour détecter
une fuite ou une connaissance préalable).

**Score** = somme pondérée des observations, plafonnée à 100, avec décroissance temporelle et
pénalité si l'info est largement présente dans des fuites publiques. Ex. K0 : 0–5 ; K1 : 5–20 ;
K2 : 20–45 ; K3 : 45–75 ; K4 : 75–100. Le score ne dit pas « qui » : il dit « combien
d'information spécifique le comportement semble posséder ».

**Honey-identities défensives** — identifiants sentinelles qui ne donnent aucun accès (alias SSH
inexistant, adresse mail canari, endpoint leurre, identifiant synthétique dans une page non
indexée). Une tentative sur un canari augmente fortement KnowledgeScore, mais uniquement si la
chaîne de création et l'absence d'exposition accidentelle sont auditables.

## RFC-0003 — IntentScore et AutomationScore

**Signaux d'automatisation :** cadence extrêmement régulière ; rotation d'IP sans changement de
payload ; ordre de tests identique ; user-agent incohérent ou très stable ; parallélisme élevé ;
reprises exactement au même offset après changement de source.
**Signaux de ciblage :** adaptation aux réponses de la box ; passage d'un service à un autre après
découverte ; utilisation d'un identifiant spécifique ; retour après changement de DNS/IP ; séquence
reconnaissance → auth → endpoint précis ; faible volume mais forte pertinence.
Deux axes **indépendants** : une campagne peut être « très automatisée ET très ciblée ». L'interface
doit rendre ça visible.

## RFC-0004 — TPI inverse / Campaign Correlator

Le « TPI inverse » part de la cible et remonte vers les **invariants de l'attaquant** : « quelles
sources successives reproduisent la même connaissance, la même grammaire d'attaque et le même
tempo ? ». Pipeline : `SBX WAF / DPI / SSH-Mail / Sentinel → Event Normalizer → Feature Extractor →
ActorGraph → {KnowledgeScore, Intent/Automation, Campaign clustering, Evidence ledger}`.

**Fenêtres de corrélation simultanées :** courte 15 min (séquences/burst) ; tactique 24 h (rotation
de sources) ; campagne 30 jours (habitudes/retours) ; historique (empreintes résumées, pas les
payloads bruts indéfiniment). Clustering initial volontairement explicable : *weighted similarity
+ union-find / graph components*. Pas de modèle opaque requis en v1.

## RFC-0005 — Adaptive Defense

Réponse = fonction de **Confidence × Knowledge × Intent × Severity**.
Modes : `OBSERVE → DELAY → CHALLENGE → TARPIT → DENY → QUARANTINE`.
Exemples : scan générique → journaliser + rate-limit ; bot persistant → délai/jitter + limitation ;
forte connaissance mais faible confiance → observation renforcée + capture de métadonnées ; canari
touché + continuité forte → blocage temporaire, alerte haute priorité, gel des preuves ; attaque
applicative confirmée → blocage SBX WAF + règle locale temporaire. Toutes les actions automatiques
ont **TTL, raison, preuve, rollback et plafond**. Aucun « hack back ».

## RFC-0006 — Intégration Toolbox NG / SBX WAF / DPI / Sentinel

**Hot path :** sbxwaf et DPI produisent des événements compacts ; aucune requête réseau externe ;
aucune géolocalisation bloquante ; aucune analyse lourde. **Warm path :** sbx-actord reçoit les
événements via socket Unix → enrichissement local/cache → clustering → scores → décisions proposées.
**Cold path :** Sentinel et rapports périodiques analysent campagnes, tendances et faux positifs.

**Nouveaux composants :**
```
packages/secubox-toolbox-ng/
  cmd/sbx-actord/
  internal/actor/
    envelope.go  features.go  similarity.go  graph.go
    knowledge.go  intent.go  response.go  evidence.go
  cmd/sbxctl/ actor ...
```
Stockage suggéré : bbolt ou SQLite local, **append-only** pour l'evidence ledger, rotation
configurable.

**Interfaces.** Socket Unix `/run/secubox/actor.sock`. Endpoints read-only : `GET /stats`,
`GET /actors`, `GET /actors/{id}`, `GET /campaigns`, `GET /evidence/{id}`. Décision, authentifié
localement : `POST /feedback/{actor_id}` avec `label: false_positive|confirmed_campaign|known_scanner|unknown`.
Le feedback humain ajuste les poids mais **ne réécrit jamais** les preuves historiques.

## RFC-0007 — Evidence Ledger et attribution prudente

Chaque inférence possède : `evidence_id, observation brute minimisée, hash, timestamp, capteur,
poids, explication, version de l'algorithme`. Affichage recommandé : **« 78 % de continuité de
campagne »** et **non** « 78 % de chances que ce soit la même personne ». ASN et pays sont des
contextes de routage, pas des identités (un VPN, un botnet, un proxy résidentiel ou un cloud
rendent l'attribution géographique trompeuse).

## RFC-0008 — API et schéma de score

```
ThreatVector T = { severity, knowledge, continuity, intent, automation, persistence, confidence }  // chacun 0..100
PriorityScore = 0.25*severity + 0.20*knowledge + 0.20*intent
              + 0.15*continuity + 0.10*persistence + 0.10*confidence
```
`automation` n'augmente **pas** directement la gravité : il décrit le mode opératoire.

## RFC-0009 — Mockup WebUI

Console « Toolbox NG / Actor Intelligence » (voir la Figure 1 du PDF) : posture, attaques/tentatives,
acteurs identifiés (TPI inverse), campagnes actives, carte temps réel présentée comme **origine
réseau et non attribution**, top pays/ASN, vecteurs d'attaque, statut WAF, Actor Cards, profil
acteur, timeline, flux de défense `OBSERVE/DELAY/CHALLENGE/TARPIT/DENY/QUARANTINE`, honey-identities,
score global. **Chaque score cliquable → « Pourquoi ce score ? »** avec `evidence_refs` et
contre-hypothèses. Vue « Constellation » : Actor Cards au centre, sources réseau autour, services
ciblés à droite ; traits épais selon la confiance ; pas de drapeau de pays géant.

**Réalisation (aperçu).** La console est maquettée dans
[`actor-intelligence-webui.html`](actor-intelligence-webui.html) — style maison
hybrid-dark (Courier Prime, cyan `#00d4ff`), Actor Cards + ThreatVector cliquable
« Pourquoi ce score ? » (preuves +/- et contre-hypothèses), timeline, flux de
défense `OBSERVE→QUARANTINE`, honey-identities, score global. Elle interroge
`/api/v1/actor/*` et remplace l'illustration par du réel dès que `sbx-actord`
répond (sinon bannière « aperçu design » explicite — jamais de faux passé pour
du réel).

## RFC-0010 — Plan d'implémentation

- **Phase 0** — Instrumentation, aucune décision automatique : Event Envelope ; adaptateurs
  WAF/DPI/auth/Sentinel ; evidence ledger ; métriques de coût CPU/RAM.
- **Phase 1** — ActorGraph *shadow* : clustering en lecture seule ; KnowledgeScore ; UI Actor Cards ;
  export JSON de campagnes.
- **Phase 2** — Calibration : rejouer 30 jours de logs anonymisés ; mesurer faux regroupements /
  séparations ; calibrer poids ; corpus synthétique (bot générique, bot ciblé, humain, rotation VPN,
  botnet).
- **Phase 3** — Défense assistée : suggestions de réponses ; validation opérateur ; TTL et rollback.
- **Phase 4** — Défense adaptative limitée : automatiser uniquement les décisions à confiance élevée ;
  fail-open/fail-safe selon service ; kill switch global.

**Critères d'acceptation :** aucun événement ne ralentit le hot path de plus de **1 ms p99** hors
I/O asynchrone ; un changement d'IP ne casse pas une campagne si 3+ signaux indépendants restent
stables ; le pays seul ne dépasse jamais un seuil ; chaque score explicable par une liste de
preuves ; suppression/rotation des données vérifiable ; désactiver Actor Intelligence n'affecte pas
SBX WAF ; faux positif labellisé visible dans les tests de non-régression.

## RFC-0011 — Proposition d'issue GitHub

**Titre :** *Toolbox NG: Actor Intelligence / inverse TPI — campaign correlation, KnowledgeScore &
adaptive defense.* **Deliverables :** sbx-actord ; Event Envelope v1 ; ActorGraph ;
KnowledgeScore/IntentScore/AutomationScore ; Evidence Ledger ; API read-only ; Actor Cards WebUI ;
shadow mode ; tests et corpus de calibration ; documentation RFC. **Hors périmètre :** attribution
nominative, contre-attaque, collecte intrusive, blocage par pays.

## RFC-0012 — Message public / communication

« **L'adresse IP n'est plus l'attaquant.** » SecuBox Toolbox NG expérimente une couche d'intelligence
défensive : au lieu de compter des IP et des signatures, la box observe la **continuité d'un
comportement**. L'objectif n'est pas d'identifier une personne, mais de reconnaître une campagne,
mesurer son degré de ciblage et adapter la défense **sans envoyer la télémétrie de la box dans un
cloud tiers**. — *Observe. Correlate. Explain. Defend.*

## RFC-0013 — Prompt d'implémentation

Voir [`actor-intelligence-rfc13-prompt.md`](actor-intelligence-rfc13-prompt.md).
