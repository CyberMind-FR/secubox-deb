<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
<!-- Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr> -->
# Rapport complet — rassemblement des paquets et des modules (#2050)

Période : 2026-10-04 → 2026-10-08. Destinataire : le propriétaire du projet. Tous les chiffres ci-dessous sont **mesurés** (dépôt, box gk2) ; ce qui n'a pas pu
être vérifié est dit comme tel.

## 1. En un coup d'œil

| Indicateur | Avant | Maintenant | Après retrait des transitoires |
|---|---:|---:|---:|
| Paquets sources dans `packages/` | 166 | 168 | 107 |
| dont paquets **actifs** (non transitoires) | 162 | **107** | 107 |
| dont paquets transitoires vides | 4 | 61 | 0 |
| `.deb` déclarés (méta-paquets compris) | 222 | 224 | ≈ 163 |
| Méta-paquets (générés depuis `arbre.yaml`) | 48 | 48 | 48 |
| Paquets tolérés avec une unité `User=root` (registre) | 22 | 19 | 19 |
| Suites de tests de la CI (matrice backend) | — | 32 | — |

**Lecture honnête.** Le nombre de paquets *actifs* baisse de 55 (162 → 107) alors que deux modules neufs ont été ajoutés (`freebox`, `ipv6guard`) : 57 paquets ont donc été
absorbés ou retirés. Mais le nombre de sources et de `.deb` **n'a pas encore baissé** : chaque paquet absorbé reste un paquet *transitoire vide* pendant un cycle de
publication (c'est ce qui permet la montée de version sans casser une box). La baisse visible des `.deb` (≈ 224 → ≈ 163) n'arrivera qu'à leur retrait.

Le travail représente 244 commits, 1 747 fichiers touchés (+23 893 / −15 026 lignes) et **437 fonctions de test ajoutées**.

## 2. Ce qui a été fait

### 2.1 Les regroupements (51 absorptions par l'outil, plus un retrait)

Un module absorbé devient un **composant** de l'absorbant : ses sources vont sous `composants/<ancien>/`, il garde **les mêmes chemins** (unités, sockets, URL, dossiers), ses
scripts de maintenance sont rejoués par l'absorbant, et l'ancien paquet devient vide (`Section: oldlibs`). Les processus, les comptes et les privilèges ne sont **pas** fusionnés.

| Absorbant | Absorbé(s) |
|---|---|
| `ai-gateway` | `localrecall`, `mcp-server` |
| `annuaire` | `openpgp` |
| `appstore` | `metacatalog` |
| `auth` | `users`, `sbxid`, `oidc` |
| `backup` | `cloner` |
| `cdn` | `mirror` |
| `dns` | `dns-provider`, `dns-lan` |
| `dns-guard` | `network-anomaly` |
| `dpi` | `ndpid`, `mediaflow` |
| `haproxy` | `vhost`, `exposure` |
| `health` | `health-doctor`, `watchdog` |
| `ipblock` | `vortex-firewall`, `cyberfeed` |
| `jitsi` | `turn` |
| `mail` | `smtp-relay` |
| `matrix` | `jabber` |
| `media` | `smb`, `freeboxtv` |
| `metablogizer` | `droplet`, `publish` |
| `metanews` | `devwatch`, `yacy` |
| `metrics` | `grafana`, `glances`, `reporter` |
| `mqtt` | `zigbee` |
| `p2p` | `meshname` |
| `qos` | `traffic`, `nettweak` |
| `repo` | `release` |
| `routes` | `netdiag` |
| `security-posture` | `cve-triage`, `antirootkit` |
| `streamlit` | `streamforge` |
| `system` | `system-hub`, `admin`, `ksm`, `system-tuning` |
| `threats` | `ai-insights` |
| `tor` | `proxypac`, `macro` |
| `waf-ng` | `waf` |
| `webos` | `sbxui` |
| `ytsas` | `torrent` |

À cela s'ajoutent, hors outil : les chantiers S1 (shims NAC), S2 (`soc-web`) et N1 (`defaults`, `groupd`) et le **retrait de `vortex-dns`** (décision du propriétaire, §2.3).

### 2.2 Les deux dernières vagues de cette session

- **N2** : `system` absorbe `system-hub`, `admin`, `ksm`, `system-tuning` (unités root conservées, une par composant).
- **3r** : `cdn` absorbe `mirror` ; `qos` absorbe `nettweak`.
- **S7** : `waf-ng` absorbe `waf` — **les paquets seulement** : `sbxwaf` (Go) et l'API Python restent deux processus, deux comptes, deux unités. Déployé avec relevé avant/après
  (unités, ligne de commande de `sbxwaf`, 145 bans nft, sudoers, endpoints).
- **`surf` et `mesh`** : socket Unix `/run/secubox/<module>.sock` à la place des ports TCP 9082 et 8743 — **fin de la dernière exception** à la règle « jamais de port TCP direct ».

### 2.3 Décisions du propriétaire sur les chantiers à enjeux

| Chantier | Décision | Pourquoi / ce qui a été trouvé |
|---|---|---|
| D3 — moteur DNS | **Unbound seul** | `dnsmasq` est arrêté sur gk2 ; le blocage de `dns-guard` y échouait déjà en silence (service sous `secubox`). |
| D4 — gestes sur Unbound | **Une bibliothèque commune** | Voir §3. |
| `vortex-dns` | **Retiré** | Actif mais jamais branché : aucun RPZ côté Unbound, dossiers de listes et de zones vides. Paquet vide, unité arrêtée et désactivée. |
| S7 — `waf` + `waf-ng` | **Paquets seulement** | La « voie de ban dupliquée » de l'API Python (`POST /check`) n'a aucun appelant : code mort, à retirer à part. |
| M9 — démons Go | **Abandonné** | Voir §2.4. |
| M3, I2 | Écartés dès la vague 2 | Gain trop faible pour le risque. |
| WireGuard / Reality | Reportés | Privilèges et tunnels. |

### 2.4 M9 : une affirmation de ma part était fausse (corrigée)

J'avais annoncé « environ 580 Mo dupliqués dans le dépôt » pour les `vendor/` Go de `radio`, `metanews` et `socialrelay`. Vérification faite : `radio` et `metanews` sont
identiques ; **`socialrelay` ne l'est pas** (Go 1.25 contre 1.22, `x/sys` v0.47.0 contre v0.19.0, `x/net` et `go-qrcode` en plus). Surtout, **git stocke déjà une seule fois** les
fichiers identiques (1,9 Go compressé) : la duplication est dans la copie de travail et les checkouts de CI, pas dans le dépôt. Unifier aurait exigé de monter `radio` et `metanews`
à Go 1.25, donc de changer le build de deux services en production. D'où l'abandon, décidé par le propriétaire.

## 3. Ce qui a été construit (outils et bibliothèques)

- **`scripts/absorber-paquet.py`** : fait un regroupement complet (sources, règles de construction, scripts de maintenance rejoués, dépendances réécrites, paquet transitoire) et
  compare les `.deb` avant/après (`--comparer`). Corrigé au fil des vagues (une dizaine de défauts trouvés à l'usage : unités mal nommées, sources non préfixées, alternatives de
  dépendances perdues, `compat` dans les transitoires…).
- **`arbre.yaml` + `gen-meta.py`** : les 48 méta-paquets sont **générés** et vérifiés en CI ; un module oublié casse la construction, pas l'installation.
- **`secubox_unbound`** (livrée par `secubox-core`) : l'unique code qui pose une vue Unbound, la vérifie (`unbound-checkconf`), recharge et revient en arrière octet pour octet ;
  écriture atomique qui refuse les liens symboliques ; stdlib seulement et sans effet de bord à l'import (les assistants root sous AppArmor ne doivent pas charger FastAPI).
  Consommateurs : `webfilter-ctl`, `dns-lan`, `ad-guard` TV et `adblock-sync`. **Le redémarrage d'Unbound n'existe que dans une sous-classe** réservée à `dns-lan` ; `webfilter` n'en a
  pas la capacité (le test le vérifie sur le comportement).
  - Défaut supprimé au passage : `adblock-sync` n'écrivait pas de façon atomique et, sur un échec de rechargement, enchaînait sur `systemctl restart unbound` — une coupure possible de la
    résolution de tout le réseau.
  - Vérifié sur gk2 : `webfilter-apply` (427 312 zones, 74 s) et `adblock-sync` (657 780 domaines) passent par la bibliothèque ; l'uptime d'Unbound continue (rechargement, pas
    redémarrage), la résolution fonctionne, l'audit est écrit.
- **`secubox-lxc-sans-sandbox`** : remet en marche les services de conteneurs LXC tombés en `226/NAMESPACE` (AppArmor, depuis le 2026-10-05).
- **Tests de garde** : registre des unités root (« ne peut que se réduire »), non-régression des absorptions, test `node --check` de tous les scripts du Hall, test de non-dérive
  entre l'unité de `sbxwaf` et son modèle de leurre.

## 4. Déploiements et vérifications

- Les vagues 0 à 3p ont été déployées **gk3 puis gk2**. N2, 3r, S7, D3/D4, `surf`, `mesh` et le retrait de `vortex-dns` l'ont d'abord été sur gk2.
- **gk3 rattrapé le 2026-10-08** (adresse 192.168.1.9 ; l'alias `gk3` ne se résout pas depuis ce poste), par groupes avec relevé avant/après : `core`, N2, 3r, DNS (dns, dns-guard,
  vortex-dns, webfilter, ad-guard), Hall (hub, appstore, webos, soc, ipv6guard), `surf`/`mesh`/`mail`, WAF (`waf-ng` + `waf`, construits pour amd64), `radio`, puis les 48 méta-paquets.
  Aucun `secubox-vault` (2.1.6 inchangé). Restent volontairement non installés sur gk3 : `secubox-haproxy` 1.10.1 et `secubox-interceptor` 1.1.2 (ne changent que des dépendances ;
  l'installation de haproxy recharge le frontal TLS). Tous les `.deb` sont publiés dans `apt.secubox.in` (arm64 et amd64).
- Chaque déploiement sur gk2 a eu un relevé avant/après (unités, `/health`, ou comportement du service concerné). Les vérifications couvrent le **chemin nominal** ; les chemins
  d'échec (configuration Unbound refusée, rechargement raté) ne sont couverts que par les tests unitaires, pas essayés sur la box.

## 5. Incidents et erreurs survenus pendant le chantier

| Quand | Quoi | Cause | État |
|---|---|---|---|
| vague 3n | `secubox-vault` réinstallé → **coffre re-scellé** | le service redémarre, la clé maîtresse n'est qu'en mémoire | l'administrateur doit se reconnecter ; le vault est désormais **exclu** des lots |
| vague 3 | boucle de redémarrage de l'API `dpi` sur gk3 | base SQLite dans un dossier appartenant à root | corrigé (`dpi` 1.7.2) |
| 2026-10-05 | services de conteneurs en `226/NAMESPACE` | AppArmor + sandbox systemd dans les LXC | outil `secubox-lxc-sans-sandbox` |
| 2026-10-05 → 07 | **ingestion d'Actor muette près de deux jours** | script de droits de la socket : fenêtre de 12 s, `actord` met ~4 min à démarrer | corrigé (waf-ng 1.18.14) |
| 2026-10-07 | un changement de l'unité de `sbxwaf` **sans effet** | un *drop-in* (leurre) recopie `ExecStart` et masque l'unité | modèle remis en miroir + test (waf-ng 1.18.17) |
| 2026-10-08 | script de la carte Actor **invalide** | apostrophe non échappée dans une chaîne JavaScript (de ma part) | attrapé avant déploiement ; test `node --check` ajouté |
| plusieurs vagues | catalogue de l'appstore citant un module absorbé | oubli de ma part (cinq fois, puis `waf`) | attrapé par la CI à chaque fois ; test de génération ajouté |
| installations | **effets de bord d'activation** : `secubox-ksm` (arrêté avant, actif après), `dns-guard` (remis à l'arrêt), `secubox-metacatalog` (actif ; je ne sais pas s'il l'était avant) | la règle des transitoires / les postinst remettent l'unité en route | `dns-guard` corrigé ; `ksm` et `metacatalog` laissés actifs |

## 6. Dette et risques restants

1. ~~gk3 en retard~~ : rattrapé le 2026-10-08 (§4), sauf `haproxy` et `interceptor` (volontairement) ; `ksm`, `dns-guard` et `mesh` y ont été remis à l'état d'avant (arrêtés et désactivés).
2. **61 paquets transitoires** à retirer un cycle après publication (aucun gain visible de `.deb` avant).
3. **Tests rouges préexistants** (non causés par ce chantier, constatés identiques avant/après) : 7 dans `scripts/tests` (`profils_composition` ×2, `sockets_chmod` ×3,
   `verifie_relais_hall` ×2), `secubox-meta::test_sbxos_pose_tout_le_hall`, 15 dans `annuaire`, tests de génération de `haproxy`, `test_stats_cache` du composant `waf` (importe une classe
   qui n'existe plus), et le **contrôle des en-têtes de licence de la CI**, rouge sur de nombreux fichiers (dont deux des miens, non corrigés).
4. **Privilèges** : les unités root ne sont pas supprimées, elles sont *regroupées* ; le registre passe de 22 à 19 paquets, mais les composants absorbés gardent leur unité root dans l'absorbant.
   `surf` tourne toujours en root (pas de `User=`) ; un utilisateur dédié exige de valider le rendu Chromium.
5. **Code mort du WAF** : `POST /check` de l'API Python (auto-ban sans appelant) à retirer dans une issue séparée. Les tests du composant `waf` ne sont pas dans la matrice de la CI.
6. **Pression mémoire sur gk2** (≈ 7,3 Go utilisés sur 7,9, 5 Go de swap) : non causée par ce chantier mais elle ralentit tout (cartes du Hall, embeds).
7. **Congestion de la CI** : un changement de `secubox-core` déclenche plus de cent builds ; un build a attendu plusieurs dizaines de minutes dans la file.

## 7. Ce qui reste séparé, et pourquoi

`toolbox-ng` (chemin de tout le trafic), `toolbox` (cabine captive), `interceptor`, `sbxwaf`/`actord` (processus Go distincts de l'API), `wireguard` et `reality` (reportés),
`bbs`/`radio`/`metanews`/`socialrelay` (démons Go, M9 abandonné). Les méta-paquets de service restent générés depuis `arbre.yaml` (vague 5 : après le retrait des transitoires).

## 8. Prochaines étapes proposées (dans l'ordre)

1. Installer `haproxy` 1.10.1 et `interceptor` 1.1.2 sur gk3 quand un rechargement du frontal TLS est acceptable.
2. Décider du sort de `secubox-ksm` et `secubox-metacatalog` (actifs depuis les installations) : garder ou remettre à l'arrêt.
3. Ouvrir l'issue « retirer `POST /check` du WAF Python » et celle des tests rouges préexistants (priorité : en-têtes de licence, `profils_composition`, `sockets_chmod`).
4. Un cycle de publication, puis retirer les 61 transitoires et passer à la vague 5.
5. Utilisateur dédié pour `surf` après validation du rendu Chromium.
