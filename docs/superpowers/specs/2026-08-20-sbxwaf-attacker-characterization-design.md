<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# sbxwaf — caractérisation d'attaquants, ban natif & empreinte d'outils

**Statut :** design (à valider avant plan d'implémentation)
**Composant :** `packages/secubox-toolbox-ng` — binaire `cmd/sbxwaf` (WAF Go, backend HAProxy `mitmproxy_inspector`, 127.0.0.1:8085)
**Config runtime :** `packages/secubox-waf/config/waf-rules.json`

---

## 1. Contexte — état actuel (audit code)

| Domaine | Ce qui existe | Ce qui manque |
|---|---|---|
| **Host / vhost** | `r.Host` lu et comparé à l'allow-list `haproxy-routes.json` ; hôte inconnu → **421** (`main.go:300-321`). `trustedHosts` bypass. | Le 421 n'est **ni banni, ni loggé menace, ni signalé**. Aucune détection IP-brut / Host vide / nom généré (DGA). |
| **Footprint URL** | Regex par catégorie (`scanners`, `honeypot`, `credential_harvest`…) sur `path+query+body+UA` (`rules.go`) ; `block`→ban gradué (3 hits/300s), `detect`→log, `escalate`→fenêtre longue. | `recon_crawler` **désactivé** ; machinerie `escalate`/#875 « produit absent » présente mais **aucune règle ne l'utilise** ; nuclei/gobuster/masscan/ffuf/wpscan absents ; `/config.json`, `/phpmyadmin` génériques absents. |
| **Empreinte** | UA en texte de scan (nikto/sqlmap… — spoofable) + buckets UA (`visitstats.go`) pour tableau de bord. | **Aucun JA3/JA4/JA4H** (ils vivent dans `sbxmitm`/`sentinel`, pas sur ce chemin HTTP) ; aucune identification d'**outil** réelle. |
| **Autoban** | `Ban.hits: IP→[]timestamp` en mémoire (perdu au restart), seuil 3/300s, puis `cscli decisions add` → bouncer nft (`crowdsec.go`). | Pas de ban **premier coup** ; pas de nft natif sbxwaf ; état par-IP sans historique de sondes. |
| **Corrélation** | `IP→hits` + compteurs cumulés. Log NDJSON `waf-threats.log`. | **Aucun** regroupement comportemental, session, campagne, ni chaîne d'outils. |

---

## 2. Objectifs (demande)

1. **Traiter les hôtes anormaux comme attaque** : hôte non routé, IP brute, Host vide, nom généré (DGA) → signal scanner, suivi + ban.
2. **Ban natif sbxwaf** (nft direct), **en parallèle** de CrowdSec au minimum, avec **retrait différé** géré **dans** le WAF → outil autonome (ne dépend plus de cscli/bouncer pour fonctionner).
3. **Empreinte d'outils** : utiliser le **maximum d'outils connus** et, **quand c'est certain, les nommer** (nuclei, gobuster, masscan, ffuf, wpscan, nikto, sqlmap…).
4. **Caractériser les attaquants** : regrouper les tentatives d'un même **workflow** (même séquence de sondes) à travers le temps et les IP.

---

## 3. Design

### A. Détection d'anomalie d'hôte (`hostanomaly.go`)
Sur chaque requête, avant la 421 actuelle, classer le `Host` :
- **unrouted** : absent de `haproxy-routes.json` et non « endormi » (waker).
- **ip_literal** : Host est une IP (`net.ParseIP` sur l'hôte sans port).
- **empty** : Host vide/absent.
- **dga** : score lexical (longueur, ratio consonnes, entropie, absence de voyelles, TLD improbable) au-dessus d'un seuil — réutiliser l'heuristique de `internal/sentinel/c2signal.go` (portée sur le Host HTTP).

Chaque classe est une **catégorie WAF** (`host_anomaly`, sévérités graduées) alimentant le pipeline d'action (§B). Un vrai navigateur n'envoie jamais un Host qu'on ne sert pas → **signal fort, ban premier coup** pour `ip_literal`/`empty`/`dga` ; `unrouted` reste gradué (un lien périmé légitime existe). La réponse au client demeure **421** (ne rien divulguer), mais l'événement est **loggé + banni**.

### B. Ban natif sbxwaf + retrait différé (`nftban.go`, `banstore.go`)
Rendre le WAF **autonome** :
- **Écriture nft directe** : sbxwaf gère son propre set nft `inet secubox waf_ban` (timeout par élément = durée du ban). Ajout via `nft add element` (ou netlink) au franchissement du seuil / premier coup selon la catégorie.
- **Store persistant** : `banstore.go` remplace le `map` volatile par un fichier append-only `/var/lib/secubox/waf/bans.jsonl` (IP, catégorie, outil, première/dernière sonde, échéance) rechargé au démarrage — les bans **survivent au restart**.
- **Retrait différé géré dans le WAF** : une goroutine de balayage relit le store, retire de nft les éléments échus, et écrit une ligne `unban`. Durées **graduées** (récidive → plus long) et **halvening** possible. Le timeout nft est la ceinture ; le balayage est les bretelles + l'audit.
- **En parallèle de CrowdSec** : on **garde** `cscli`/bouncer (mesh, partage), mais le ban est désormais **effectif même si CrowdSec est absent**. Flag de config `ban.backend = ["nft","crowdsec"]`.

### C. Empreinte d'outils — nommer quand certain (`toolprint.go`, `tools.json`)
Base de signatures `tools.json` (hot-reload comme `waf-rules.json`), chaque outil décrit par des **traits corroborants** :
- **séquence de chemins** caractéristique (nuclei templates, wordlists gobuster/dirbuster, wpscan `/wp-json/…`),
- **UA** connus (souvent spoofés → poids faible),
- **ordre/casse des en-têtes**, absence de `Accept-Language`, `Connection` atypique,
- **JA4/JA4H** (§E) quand disponible — poids fort (peu spoofable),
- **cadence** (inter-arrivées quasi-constantes = machine).

Règle de nommage : on **n'affiche le nom de l'outil que si le score de corroboration dépasse un seuil** (≥2 traits forts) ; sinon `outil: inconnu (famille: scanner|fuzzer|cve-mass)`. Jamais de faux nom : l'incertitude reste explicite.

### D. Corrélateur d'attaquants / campagnes (`profiler.go` + surface metrics)
Au-dessus de `waf-threats.log` (déjà NDJSON — matière première) :
- **Profil par attaquant** clé = **JA4 si dispo, sinon IP** : séquence **ordonnée** des (host, path, catégorie) sondés, fenêtre temporelle, outil déduit (§C), verdict.
- **Clustering de workflow** : deux attaquants partageant la même sous-séquence de sondes (n-grammes de chemins) = **même campagne/outil** — c'est exactement « même workflow depuis plusieurs tentatives ». Regroupement par empreinte de séquence (hash des n-grammes normalisés).
- **Surface** : endpoint `secubox-metrics` (`/api/v1/metrics/waf/attackers`) + vignette dashboard : top campagnes, outils nommés, IP/JA4 regroupés, séquence-type. Réutilise le pattern double-cache (60 s).

### E. JA4 depuis HAProxy → sbxwaf
sbxwaf ne voit que du HTTP déchiffré (pas de ClientHello). **HAProxy calcule JA3/JA4** (`fc_*` / lua) et l'injecte en en-tête `X-Sbx-JA4` sur le backend `mitmproxy_inspector`. sbxwaf lit l'en-tête (de confiance car ajouté par HAProxy, jamais du client — le stripper des requêtes entrantes), et **clé de ban/empreinte = JA4** (non spoofable, contrairement à l'UA). Fallback IP si l'en-tête manque.

### F. Enrichissement des règles
- **Activer** la voie `escalate`/#875 (produit absent) avec des catégories réelles.
- **Ajouter** signatures : `nuclei|gobuster|masscan|ffuf|feroxbuster|wpscan|dirbuster|httpx`, chemins `/config.json`, `/phpmyadmin` génériques, `/.git/HEAD`, `/actuator/env`, etc.
- Réactiver `recon_crawler` en mode `detect` (observation, pas ban) pour nourrir le profiler.

---

## 4. Découpage (phases)
1. **F + A** : signatures + détection host-anomaly (petit, gros ROI immédiat).
2. **B** : ban natif nft + store persistant + retrait différé (autonomie).
3. **C** : `toolprint.go` + `tools.json` (nommage prudent).
4. **E** : JA4 HAProxy→header (clé non spoofable).
5. **D** : profiler + surface metrics (caractérisation/campagnes).

Chaque phase est indépendamment livrable et testable (TDD Go : les faux d'`internal` existent déjà pour `resolveur_test.go`).

## 5. Points ouverts
- Durées de ban graduées : barème exact (première infraction, récidive, halvening).
- Seuil DGA (faux positifs sur sous-domaines légitimes générés).
- JA4 dans HAProxy : lua vs patch natif selon la version déployée.
- Confidentialité : le profiler stocke des séquences par IP/JA4 — rétention + purge (RGPD/CSPN).
