<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Automesh — jonction automatique au maillage (lite)

Besoin : support à distance et première installation d'une box lite. La box APPELLE son parent (connexion sortante : elle traverse une Freebox sans port entrant).

## Flux

1. Sur le parent (administrateur) : `POST /api/v1/p2p/master-link/invite` rend, entre autres, `code` : `sbxmesh1.<base64url>.<somme>` — adresse du parent + jeton à usage unique, durée limitée (3600 s par défaut), `auto_approve` au choix.
2. La préparation de la box (Auto-Load, premier pas) dépose ce code dans `/var/lib/secubox/p2p/automesh.code` (0600, propriétaire `secubox`).
3. `secubox-automesh.timer` (45 s après le démarrage, puis toutes les 2 min) lance `secubox-automesh`, uniquement si le fichier existe. Il exécute `sbx-mesh-join <parent> -` (jeton par l'environnement) : clés WireGuard, demande, offre du parent, tunnel.
4. Résultat dans `/var/lib/secubox/p2p/automesh.json` (statut : `approuve`, `en_attente`, `echec`, `invalide`, `expire` ; jamais le code). Approuvé -> code supprimé. En attente -> gardé 24 h au plus. Refusé 5 fois -> supprimé.

## Garde-fous

- Aucun droit n'est donné par le code seul : le parent valide le jeton et décide (`auto_approve` du jeton ou approbation manuelle `/master-link/approve`).
- Les routes d'invitation exigent le JWT d'un administrateur (voir #2476 : une route « locale » sans authentification a été supprimée).
- Adresse et jeton sont revalidés à l'encodage ET au décodage ; la somme de contrôle refuse un code tronqué ou fauté.
- Une adresse non locale passe par HTTPS à certificat vérifié (route `join-with-code`) ; `sbx-mesh-join` reste en HTTP sur le port du module (réseau local, VPN, maillage).

## À valider sur deux box

Le tunnel s'établit de bout en bout (parent applique le pair de façon asynchrone) ; le dépôt du code par Auto-Load (agent) n'est pas encore branché : phase suivante, avec la découverte du parent par mDNS (`_secubox._tcp` annonce déjà `node_id` et `mesh_ip`).
