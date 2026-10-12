<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.

  SPÉCIFICATION (2026-10-12) — NON IMPLÉMENTÉE. À valider avant tout code : pare-feu et Tor sont une zone sensible.
-->

# Spécification — politique de sortie par zone ou par appareil

Issue #2424. Statut : **proposition**, aucune ligne de pare-feu n'est modifiée par ce document.

## 1. Objet

Aujourd'hui, ce que fait un appareil du LAN vers Internet dépend de sa zone NAC (LAN, IoT, Invités, Quarantaine, Bloqué) et, séparément,
du niveau R du Toolbox (R0 à R3) pour les pairs WireGuard. Tor existe (module `secubox-tor`, sortie Tor du Toolbox) mais n'est pas un
réglage du NAC. Cette spécification ajoute **une politique de sortie** que l'on choisit par zone ou par appareil.

**Valeurs** : `direct` · `tor` · `vpn` · `bloque`.

**Non-objectifs** : Tor ou VPN par défaut pour tout le LAN ; anonymat garanti de l'utilisateur (voir § 7) ; relais ou nœud de sortie Tor
(la box reste un **client** Tor, jamais un relais).

## 2. Modèle

| Notion | Règle |
|---|---|
| Défaut global | `direct`. Un changement de défaut global est refusé par l'API (garde-fou : jamais Tor par défaut pour tout le LAN). |
| Par zone | Chaque zone porte une politique. Valeur initiale : `direct`, sauf Quarantaine et Bloqué qui restent coupés. |
| Par appareil | Une politique d'appareil l'emporte sur celle de sa zone. |
| Priorité | `bloque` (appareil) > appareil > zone > défaut. L'état Bloqué du NAC l'emporte toujours. |
| Quarantaine | Aucune sortie, quelle que soit la politique : seuls DNS et DHCP vers la box restent permis (comportement actuel). |
| Conteneurs LXC | Hors champ : leur sortie reste gérée par leur propre configuration. |

Premier cas d'usage recommandé : **zone Invités en `tor`** (opt-in), puis un appareil précis. Pas d'autre zone par défaut.

## 3. Architecture (même motif que le NAC actuel)

L'API du NAC tourne sans privilège et ne parle pas à nftables. Elle écrit un **état voulu** ; un service root valide et applique.

1. `POST /api/v1/nac/egress` (garde `require_jwt`) écrit `egress-desired.json` (zone → politique, MAC → politique), validé : valeurs connues,
   MAC canoniques, refus du défaut global ≠ `direct`.
2. `secubox-nac-apply` (root, déclenché par une unité `.path`) compare l'état voulu à l'état appliqué, construit un **tampon d'ombre**
   (nouveau jeu de règles), le **valide** (`nft -c`), puis le **bascule de façon atomique** ; en cas d'échec, retour à l'état précédent
   (double tampon et rollback 4R, comme toute configuration sensible).
3. Chaque décision est écrite dans `/var/log/secubox/audit.log` (append-only) : qui, quelle zone ou MAC, ancienne et nouvelle valeur.
4. Nouveaux ensembles nft de MAC : `egress_tor`, `egress_vpn`. `direct` = absence des deux. `bloque` réutilise l'ensemble `blocked`.

## 4. Règles nft (esquisse, à valider en banc d'essai)

- **Tor** : pour une MAC de `egress_tor`, en `prerouting` (table `nat`), rediriger le TCP sortant vers le TransPort local (déjà configuré :
  `127.0.0.1:9040`) et le DNS vers le DNSPort (`127.0.0.1:9053`). **Exceptions avant la redirection** : réseaux privés (10/8, 172.16/12,
  192.168/16), adresses de la box (DNS, DHCP, NTP).
- **UDP** : tout UDP sortant d'un appareil en `tor` est **refusé** (Tor ne transporte que le TCP) ; en particulier UDP/443 pour forcer le
  repli de QUIC vers TCP. ICMP refusé.
- **IPv6** : refusé pour un appareil en `tor` tant que la sortie IPv6 de Tor n'est pas validée (sinon fuite).
- **Coupe-circuit (fail-closed)** : si Tor n'est pas prêt (amorçage incomplet, aucun circuit), le trafic de ces appareils est **refusé**,
  jamais renvoyé en clair. Le NAC lit l'état de Tor (module `secubox-tor`, port de contrôle) et retire la redirection seulement
  en même temps que l'accès.
- **VPN** : voir § 8, question ouverte 1.

## 5. DNS

- Appareil en `tor` : son DNS passe par le DNSPort de Tor (résolution `.onion` incluse via l'automap existant). Il ne doit **jamais** être
  résolu en clair par Unbound.
- Appareil en `direct` : inchangé (ad-guard, Unbound).
- Conséquence assumée : ad-guard ne voit plus les requêtes des appareils en `tor` ; le tableau de bord le dit au lieu d'afficher « 0 ».

## 6. Isolation et état de Tor

- Un circuit par appareil (`IsolateClientAddr` ou port d'isolation dédié) : deux appareils d'une même zone ne partagent pas leur
  identité de sortie.
- Ponts (obfs4, snowflake, webtunnel) selon l'échelle existante quand le FAI filtre Tor ; l'horloge de la box doit être juste (Tor la
  vérifie).
- Pays de sortie : réglage global existant du Toolbox, non dupliqué ici.

## 7. Ce que cette politique ne promet pas

Tor transparent n'est pas Tor Browser : l'empreinte du navigateur, les comptes connectés et les cookies identifient l'utilisateur quel que
soit le circuit. Les débits sont de quelques Mbit/s ; les sorties Tor sont souvent bloquées (banques, authentification forte, CAPTCHA).
L'interface le dit en toutes lettres à côté du réglage.

## 8. Questions ouvertes

1. **Que signifie `vpn` ?** Je n'ai identifié aucun tunnel *sortant* dans les paquets (le Toolbox héberge des pairs WireGuard *entrants*) : à confirmer. À trancher : tunnel WireGuard vers
   un fournisseur ou un autre nœud SecuBox, ou retrait de la valeur de la v1.
2. **Visibilité** : le DPI reste côté LAN avant la redirection ; faut-il en revanche masquer les destinations d'un appareil en `tor` dans
   les tableaux (vie privée) ?
3. **Priorité avec le niveau R du Toolbox** pour un pair WireGuard : le niveau R (inspection) doit-il être forcé à R0 quand la sortie est
   `tor` (une interception locale sous Tor est contradictoire) ?
4. **Ressources** : la box est déjà à ~78 % de mémoire ; plafonner le nombre d'appareils en `tor` simultanés ?
5. **Périmètre CSPN** : le démon Tor et son port de contrôle élargissent la surface évaluée ; confirmer le traitement avec le dossier ANSSI.

## 9. Phases

| Phase | Contenu | Effet réseau |
|---|---|---|
| 0 | Cette spécification validée. | aucun |
| 1 | Modèle, API `egress` (lecture/écriture), page NAC, audit ; l'état voulu est écrit mais **non appliqué** (« à blanc »). | aucun |
| 2 | Application nft pour `tor` avec coupe-circuit, UDP refusé, DNS Tor, sur la **zone Invités** seulement, derrière un indicateur explicite. | zone Invités |
| 3 | Politique par appareil ; isolation des circuits ; tableau de bord de l'état de Tor. | appareils choisis |
| 4 | `vpn`, selon la réponse à la question 1. | à définir |

## 10. Tests attendus

- Jeu de règles généré : une MAC en `tor` a sa redirection, ses exceptions privées, son refus UDP/IPv6 ; une MAC en `direct` n'a rien.
- Bascule : jeu invalide → l'ancien jeu reste appliqué ; coupure de Tor → trafic refusé (jamais en clair).
- Priorité : appareil > zone > défaut ; Bloqué l'emporte ; le défaut global ≠ `direct` est refusé.
- Fuites : aucun paquet DNS en clair d'un appareil en `tor` (capture), aucune requête hors TransPort.
- Interface : confirmation intégrée, avertissement du § 7 visible, actions inertes en démonstration.
