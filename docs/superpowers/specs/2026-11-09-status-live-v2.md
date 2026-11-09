<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# SecuBox Status Live v2 — spécification STV2-001 (#3595)

Supervision distribuée des appliances, en lecture seule. Paquet indépendant `secubox-status`.

| Propriété | Décision |
|---|---|
| OS / arch | Debian 13 trixie, arm64 + amd64 (`Architecture: all`) |
| Nœuds | gk2 (agrégateur), gk3 et c3box (agents) |
| Backend | FastAPI sur socket Unix `/run/secubox/status.sock` |
| Historique | SQLite WAL, `/var/lib/secubox/status/status.db` |
| Fédération | Annuaire / MirrorNet existants, aucun nouveau transport |
| Signature | Identité Ed25519 du nœud (`node.key` de l'Annuaire) |
| Interfaces | page Status publique + vue privée dans le Hall |

## 1. Architecture

Trois agents, un agrégateur public sur gk2 (`status.gk2.secubox.in`).

Règle d'indépendance :
- chaque nœud collecte et garde son historique même si les autres sont hors ligne ;
- gk2 affiche le dernier relevé valide des autres nœuds, avec son âge réel ;
- une panne de l'agrégateur n'efface jamais les données d'un agent.

Réutilisation : `secubox-annuaire` publie et vérifie déjà des relevés de flotte signés
(`/api/v1/annuaire/fleet/modules/self`, `/fleet/modules`, `sbx-fleetctl publish-modules`,
`fleet.sign_modules()` / `fleet.verify_modules()` dans `annuaire/fleet.py`). Status v2 ajoute un
contrat **distinct et versionné** (`StatusSnapshot`) à ce mécanisme, sans détourner `ModulesSnapshot`.
Le relevé de validation de `secubox-profiles` (`/var/lib/secubox/profiles/validation/releve.json`)
est déjà signé par l'Annuaire : on le lit, on ne le re-signe pas.

## 2. Contrat fonctionnel

| Fonction | gk2 | gk3 | c3box |
|---|---|---|---|
| Collecte locale, santé modules / HTTP, ressources, historique | oui | oui | oui |
| Signature et publication Annuaire | oui | oui | oui |
| Agrégation de flotte, page publique | oui | non | non |

Les sources optionnelles sont déclarées par profil matériel : une sonde absente (température) n'est pas un incident.

États normalisés : `operational`, `degraded`, `outage`, `maintenance`, `unknown`.
États de relevé : `untrusted` (signature ou identité invalide, relevé exclu) et `partial` (incomplet mais utilisable). Aucun des deux ne vaut panne.

Agrégation :
1. un service critique en panne peut dégrader ou rendre indisponible une appliance ;
2. un service optionnel en panne ne rend jamais l'appliance indisponible ;
3. une mesure absente ne vaut jamais panne ;
4. une signature invalide exclut le relevé ;
5. un nœud hors ligne garde son dernier état, affiché comme périmé.

La santé de la flotte se calcule indépendamment de celle de chaque appliance.

**Modules absents** : un module non installé sur un nœud n'apparaît pas. Seuls les modules installés et
attendus par le profil comptent (même règle que celle à corriger sur la Vue d'ensemble de l'admin).

## 3. Paquet

```
packages/secubox-status/
├── api/            main.py, public.py, admin.py, schemas.py
├── secubox_status/ config, collector, sources/{health,modules,fleet,system,network,external},
│                   normalizer, aggregator, freshness, signing, incidents, history, publisher, privacy
├── schemas/        snapshot-v2.json, public-v2.json
├── www/            index.html, appliance.html, incidents.html
├── conf/status.toml
├── tests/
└── debian/
```

Dépendances : `python3-fastapi`, `python3-uvicorn`, `python3-pydantic`, `secubox-core` en `Depends` ;
`secubox-health`, `secubox-profiles`, `secubox-annuaire` en `Recommends` (le moteur reste installable
en profil minimal, les sources absentes passent à `unknown`). Client HTTP : celui déjà utilisé par
l'Annuaire, pas de nouvelle dépendance si on peut l'éviter.

Configuration `/etc/secubox/status.toml` : `node_role = "aggregator" | "agent"`, intervalle de collecte
60 s, rétention 90 j détaillée puis agrégats journaliers 12 mois, chemins des caches, `stale_after_seconds = 180`,
`require_signature = true`, section `[public]` (`expose_resources = false`, `expose_module_inventory = false`).
L'identité d'un nœud est toujours vérifiée par son DID, jamais par son nom.

## 4. Données

- **Relevé local** `secubox.status.snapshot` v2 : `node` (id, did, hostname, architecture), `sequence`,
  `collected_at`, `release`, `health` (overall, system, network, security, services), `resources`
  (nombres finis ou `null`, jamais NaN), `counts`, `sources` (fresh / partial / stale / absent).
- **Relevé signé** : Ed25519 sur le contenu normalisé complet (DID, séquence, horodatage, version,
  résultats, états des sources) ; `signer_did`, `signer_pub`, `signature` détachée. La clé privée ne
  quitte jamais l'outil de signature ; le processus FastAPI n'y a pas accès.
- **Projection publique** `secubox.status.public` v2 : état de flotte et de chaque nœud, `last_seen`.
  Jamais le relevé brut.

SQLite : tables `nodes`, `snapshots`, `services`, `incidents`, `events`, `availability` ; index
`(node_id, collected_at)`, `(service_id, collected_at)`, `(incident_id, started_at)`, `(node_id, sequence)` ;
écritures transactionnelles.

## 5. Sources

Le Status **lit les caches, il ne les recalcule pas**. Pas de rafale de commandes système chaque minute.

| Source | Fichier | Fréquence |
|---|---|---|
| Vhosts | `/var/cache/secubox/health/status.json` | 60 s |
| Modules | `/var/cache/secubox/health/modules.json` | 60 s |
| Validation de flotte | `/var/lib/secubox/profiles/validation/releve.json` | 300 s |
| Annuaire | API fleet | 60 s |
| Système | `/proc/stat`, `/proc/meminfo`, `statvfs`, `/proc/uptime`, `/proc/loadavg`, `/sys/class/thermal` | 60 s |

Réseau : interfaces, routage, nombre de pairs WireGuard, dernière synchro MirrorNet, latence des liens.
Jamais de clés, d'endpoints privés ni d'adresses internes dans la projection publique.

Sondes externes : services déclarés (page Status, API, Hall, DNS, mail, Nextcloud, WAF par un endpoint
neutre). Une sonde depuis gk2 ne prouve pas la disponibilité vue d'Internet : on distingue sonde locale
et sonde externe, et l'interface le dit.

## 6. API `/api/v1/status`

| Méthode | Route | Garde |
|---|---|---|
| GET | `/summary`, `/nodes`, `/nodes/{id}`, `/services`, `/incidents`, `/history`, `/metrics` | publique filtrée (voir §11, question 1) |
| GET | `/health` | sonde technique |
| GET | `/admin/sources`, `/admin/snapshots`, `/admin/diagnostics` | `require_jwt` |

Interface : rafraîchissement 30 s (vue générale, appliance, incidents), historique à la demande, SSE plus tard.

## 7. Fédération et confiance

Chaîne : collecte → normalisation → écriture atomique locale → signature → publication Annuaire →
vérification (signature, DID, séquence, horodatage, forme) → agrégation gk2 → projection publique.

Ajouts côté Annuaire : modèle `StatusSnapshot`, `sign_status()`, `verify_status()`, `GET /fleet/status/self`,
`GET /fleet/status` (authentifiée). Contrôles de transport existants conservés : pas de proxy implicite,
pas de redirection, pairs du réseau de confiance seulement, taille et délai bornés.

Anti-rejeu : séquence strictement croissante par DID, avec gestion explicite du redémarrage et de la
restauration ; horodatage futur rejeté.

Distinguer : `signature_verified`, `measurement_complete`, `measurement_fresh`, `externally_confirmed`.
Une signature prouve la provenance, pas l'exactitude de la mesure.

Tout relevé rejeté (signature, DID, rejeu) est une décision de sécurité : une ligne dans
`/var/log/secubox/audit.log`.

## 8. Incidents et disponibilité

Disponibilité = temps opérationnel observé / temps éligible observé. `unknown` ne compte jamais comme
opérationnel. La maintenance déclarée est exclue de la métrique mais reste visible dans l'historique.

Incident : 2 échecs consécutifs = suspect, 3 = candidat, confirmation par une seconde observation si
disponible, retour à la normale après 2 succès. Cause et heure de résolution conservées. Une maintenance
coupe les alertes, jamais l'historique.

## 9. Sécurité et unités

- Utilisateur dédié `secubox-status`, AppArmor `enforce`, jamais root.
- Signature par un outil séparé à privilèges minimaux (patron ctl + sudoers), seul à lire `node.key`.
- Durcissement systemd : `NoNewPrivileges`, `PrivateTmp`, `ProtectSystem=strict`, `ProtectHome`,
  `ProtectKernel*`, `ProtectControlGroups`, `ReadWritePaths=/var/lib/secubox/status` ; lectures des caches
  explicitement autorisées ; vérifié sur arm64 et amd64.
- WebUI : pas d'`innerHTML` avec des données distantes, CSP, réponses bornées, limitation de débit publique.
- Exposition : HAProxy TLS 1.3 → `sbxwaf` → nginx ; route WAF déclarée par le paquet (`secubox-waf-route`).

| Unité | Type | Rôle |
|---|---|---|
| `secubox-status-api.service` | permanent | API et WebUI |
| `secubox-status-collect.service` + `.timer` | oneshot, 60 s | collecte et agrégation locales |
| `secubox-status-publish.service` + `.timer` | oneshot, 60 s | signature et publication, idempotente |

L'API ne collecte jamais et ne contacte jamais les pairs pendant une requête.

## 10. Tests d'acceptation

| Cas | Attendu |
|---|---|
| Cache health absent | source `unknown` |
| Module arrêté | dégradation identifiée |
| Module on-demand endormi | état veille, pas panne |
| Module non installé | absent de la vue |
| gk3 hors ligne / de retour | indisponible avec historique gardé / resynchro sans doublon |
| Signature invalide, DID incorrect, séquence ancienne, horodatage futur | relevé rejeté et audité |
| gk2 redémarré | historique restauré |
| Nœud sans sonde thermique | température `null`, pas de panne |
| API arrêtée | collecte locale continue |

Sortie de bêta : trois appliances authentifiées ; aucun faux `operational` sur une donnée inconnue ;
aucun secret dans l'API publique ; historique gardé au redémarrage ; signature vérifiée avant ingestion ;
mémoire maîtrisée sur arm64 ; installation et purge Debian reproductibles.

## 11. Arbitrages (2026-11-09)

1. **Page publique statique.** Le collecteur écrit la projection publique (`public-v2.json`) et la page ;
   nginx les sert. Aucune route anonyme sur l'API : toutes les routes `/api/v1/status/*` portent
   `require_lecture` ou `require_jwt`. Le tableau §6 se lit donc : routes « publiques » = fichiers statiques.
2. **Paquet `secubox-status` séparé**, utilisateur dédié, installable en profil minimal.
3. **gk2 seul d'abord.** Jalon 1 sur gk2 uniquement ; c3box et gk3 se décident au jalon 2
   (gk3 = voicestudio, toujours sur accord explicite).
