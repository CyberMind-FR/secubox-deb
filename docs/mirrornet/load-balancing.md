<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Load Balancing — sbxwaf multi-cibles, santé, DNS (#3429, phase B)

CONCEPTION, non implémentée. Composants N5 (A21), N12 (après bêta). Marquage : EXISTANT / À ÉTENDRE / NOUVEAU.

Arbitrage : **pas de second nœud exposé avant la bêta** ; la répartition se fait **derrière gk2**, le WAF reste unique
et en tête ; aucune répartition HAProxy en `waf_bypass` (`.claude/reference/SECURITE-WAF.md`).

Vision du 2026-11-03 (`architecture.md` § 0) : les routes sont posées **automatiquement** à la publication — nom de
nœud tout de suite, nom court quand le registre des noms désigne un titulaire (`distributed-hosting.md` § 6) — et les
visites du nom court sont **réparties** entre les copies placées d'office. gk2 sert sa copie locale s'il en a une,
sinon relaie par wg-mesh. Décision 4 inchangée.

## 1. Existant

| Élément | Statut | Référence |
|---|---|---|
| HAProxy → un serveur `waf` avec `check` | EXISTANT | `secubox-haproxy/sbin/haproxyctl:1477` |
| HAProxy multi-serveurs `[backends.X] servers` | EXISTANT, inutilisable ici (bypass) | `haproxyctl:1500-1520` |
| Table sbxwaf : un hôte → `[ip, port]` | EXISTANT (verrou) | `secubox-toolbox-ng/cmd/sbxwaf/routes.go:106` (`loadRoutesJSON`), `:285` (`Lookup`) |
| Rechargement à chaud, écriture atomique | EXISTANT | `routes.go:31,279` ; `secubox-core/usr/sbin/secubox-waf-route:60,108` |
| Relais d'un nom vers un pair | EXISTANT (un seul pair) | `secubox-p2p/sbin/secubox-relais-maillage:159` (`routes_ecrire`), `:472` |

## 2. Format de route étendu (À ÉTENDRE, rétrocompatible)

`/etc/secubox/waf/haproxy-routes.json` garde sa forme actuelle ; une entrée peut **aussi** être un objet :

```json
{
  "nc.gk2.secubox.in": ["127.0.0.1", 8090],
  "blog.secubox.in": {
    "site": "blog",
    "source": "gk6",
    "politique": "priorite",
    "cibles": [
      {"noeud": "gk2", "ip": "127.0.0.1",  "port": 8472},
      {"noeud": "gk6", "ip": "10.10.0.6",  "port": 8472},
      {"noeud": "gk4", "ip": "10.10.0.4",  "port": 8472}
    ]
  },
  "blog.gk6.secubox.in": {"site": "blog", "cibles": [{"noeud": "gk6", "ip": "10.10.0.6", "port": 8472}]}
}
```

- Format **validé 2026-11-03** (décision 4). Les cibles sont les points de service **déclarés par le module**
  (`[service].port` de `mirrornet.d`, ici metablogizer 8472), jamais un port mirrornet ; la clé `site` désigne le
  service.
- Une entrée tableau = une cible, comportement **inchangé** (aucune régression sur les 275+ routes existantes).
- Plafond : 16 cibles par hôte ; `ip` limité à boucle locale et 10.10.0.0/24 (wg-mesh) — une cible publique est refusée
  au chargement (pas de proxy ouvert).
- Écrivain : `secubox-waf-route` (À ÉTENDRE : verbe `poser-multi <hote> <fichier-json>` validé par schéma) appelé par
  `mirrornetctl route-poser` ; jamais d'édition à la main.
- Les équivalences `<service>.<nœud>.secubox.in` sont des routes à une cible portant `site` (corrélation conservée).
- Cycle automatique (`mirrornetctl`, lot L8) : publication → route du nom de nœud ; titularité → route multi-cibles du
  nom court ; `refuse`/`bloque` → aucune route de nom court ; `conteste` → route conservée ; `suspendu` (source
  révoquée) ou retrait → route retirée. Jamais deux routes de nom court pour un même nom.

## 3. Santé (NOUVEAU), hors du chemin de requête

```
secubox-mirrornet (sonde toutes les 10 s, GET http://<cible><[sante].chemin du module>, délai déclaré)
        │ écrit atomiquement
        ▼
/run/secubox/mirrornet/sante.json   {"blog": {"gk6": {"etat":"sain","empreinte":"b2:41…","vu":…}, …},
                                     "attendue": {"blog": "b2:41…"}}
        │ rechargé à chaud (même watcher que routes.go)
        ▼
sbxwaf : table de santé en mémoire, lue sans verrou par Lookup
```

- Anti-rebond : 3 échecs pour « hors service », 2 succès pour revenir (modèle `HealthStore`,
  `secubox-p2p/api/federation.py:17-40`).
- Repli **passif** dans sbxwaf : échec de connexion à une cible → elle est écartée 30 s localement et la requête est
  rejouée sur la suivante **seulement** pour GET/HEAD (le statique n'a pas d'autre méthode ; une requête non idempotente
  n'est jamais rejouée).
- Éligibilité : cible saine **et** servant l'empreinte attendue. Si aucune n'est à jour (propagation en cours), on sert
  une cible saine à la version précédente de la chaîne et l'événement est journalisé (mode dégradé).
  Si aucune cible n'est saine : 503 du WAF avec page d'erreur existante.
- Fichier de santé périmé (> 60 s) : sbxwaf considère toutes les cibles saines (pas de panne totale parce que la sonde
  est morte), journalise une fois par minute.

## 4. Politique de choix

| Politique | Effet | Usage A21 |
|---|---|---|
| `priorite` | première cible éligible (copie locale de gk2 d'abord : pas de trafic wg-mesh inutile) | oui |
| `tourniquet` (défaut du nom court, répartition des visites) | rotation entre cibles éligibles | oui |
| pondérée (charge, bande passante, latence, état de sécurité ActorD) | poids recalculés par mirrornet dans `sante.json` | **A22** (arbitrage #3420) ; c'est aussi le partage de ressources entre **services équivalents** d'une même classe (`distributed-hosting.md` § 8, ex. Voice Studio) |

Coût visé : un choix O(n ≤ 16) sans allocation par requête ; aucune E/S dans `Lookup`.

## 5. Identifiant de site transmis au WAF (À ÉTENDRE)

La route porte `site` ; sbxwaf l'ajoute à chaque événement ActorD (`Envelope`, `secubox-toolbox-ng/internal/actor/
envelope/envelope.go:100-108`, nouveau champ `site_id`, chaîne bornée comme `Vhost`) et à `waf-threats.log`. Exploité
par ActorD pour la corrélation **par site** (A21 : champ transmis ; A22 : corrélation multi-nœuds, `collective-defense.md`).

## 6. Exposition et DNS

| Étape | Contenu | Calendrier |
|---|---|---|
| vhosts HAProxy | `haproxyctl vhost add` du nom de nœud à la publication et du nom court à la titularité, backend `sbxwaf_inspector` (EXISTANT `haproxyctl:619`), sans geste | A21 |
| certificats | `*.secubox.in` + `*.<nœud>.secubox.in` sur gk2 par DNS-01 (`joker.py` EXISTANT, À ÉTENDRE pour l'apex `secubox.in`) | A21 |
| DNS | tous les noms vers gk2 | A21 |
| DNS multi-cibles avec retrait sur santé, plusieurs nœuds exposés (chacun HAProxy + sbxwaf + certificats) | NOUVEAU (N12) | après bêta |
| relais à plusieurs pairs (`secubox-relais-maillage` groupe de pairs, E2) | rendu inutile en A21 par les routes multi-cibles ; à réévaluer | après bêta |

## 7. Risques

- Régression du WAF de la **seule** box exposée : le format tableau doit rester lu à l'identique (tests de non-régression
  sur la table réelle de gk2 anonymisée), déploiement d'abord sur gk6.
- Une cible wg-mesh lente bloque des connexions : délai de connexion 2 s, puis repli.
- Boucle : une cible ne doit jamais être l'adresse du WAF lui-même (refus au chargement de `127.0.0.1:8085`).
