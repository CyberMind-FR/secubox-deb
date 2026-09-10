# Architecture GK2 Clone

GK2 Clone représente la chaîne de publication et de services de la SecuBox de développement sous forme AMD64 reproductible. Le diagramme suivant présente le chemin logique des requêtes publiques vers SBXOS Hall et les services proposés.

## Table des matières

- [1. Schéma](#1-schéma)
- [2. Chemin des requêtes](#2-chemin-des-requêtes)
- [3. Rôles des composants](#3-rôles-des-composants)
- [4. Limites de sécurité](#4-limites-de-sécurité)

## 1. Schéma

![Architecture GK2 Clone : Internet, HAProxy, SBXWAF, SBXOS Hall et services](assets/svg/gk2-clone-architecture.svg)

## 2. Chemin des requêtes

1. **Internet** transmet une requête au point d’entrée publié.
2. **HAProxy** termine et route le trafic exposé selon la configuration active.
3. **SBXWAF** inspecte le trafic HTTP applicatif avant la remise au hall.
4. **SBXOS Hall** sert de point de distribution vers les services publiés.
5. Chaque service — Nextcloud, Mail, Radio, BBS, PeerTube ou API — demeure un backend distinct avec sa propre configuration et ses propres journaux.

Le diagramme est volontairement logique : il ne déclare pas une exposition automatique de tous les services. Seuls les vhosts, routes et règles explicitement activés doivent être accessibles.

## 3. Rôles des composants

| Composant | Rôle | Principe d’exploitation |
|---|---|---|
| Internet | Réseau externe ou réseau de test | Aucun accès d’administration implicite |
| HAProxy | Façade TLS et routage | Configurations contrôlées, rechargement validé |
| SBXWAF | Inspection applicative | Blocage et journalisation des requêtes non conformes |
| SBXOS Hall | Point d’entrée des modules | Découplage entre présentation et backend |
| Services | Fonctions souveraines et API | Activation explicite, moindre privilège |

## 4. Limites de sécurité

La VM GK2 Clone doit rester dans un périmètre de développement tant que les certificats, secrets et politiques de pare-feu n’ont pas été adaptés. HAProxy et SBXWAF ne remplacent ni la segmentation réseau, ni une politique d’accès administrateur, ni des sauvegardes vérifiées.

Pour la topologie des interfaces, consultez [VM GK2 Clone](VM-GK2-CLONE.md). Pour un incident d’accès, consultez [Dépannage AMD64](TROUBLESHOOTING-AMD64.md).
