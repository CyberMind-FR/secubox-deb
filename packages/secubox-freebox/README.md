<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# secubox-freebox

Connecteur de l'API Freebox OS (v0.1, lecture). Conception : `docs/dossiers/connecteur-freebox.md`.

- **Autorisation** : `POST /api/v1/freebox/autoriser` (admin), puis appui sur ✓ sur la Freebox ; droits réglés dans
  Freebox OS → Paramètres → Gestion des accès → Applications. Le jeton d'application reste dans
  `/var/lib/secubox/freebox/app.json` (0600) et n'est jamais renvoyé ni journalisé.
- **Lecture** (`require_lecture`) : `/status`, `/appareils`, `/connexion`, `/pare-feu`, `/redirections`, `/autoriser/etat`.
- **Admin** (`require_jwt`) : `/autoriser`, `/revoquer`, `/explorer` (liste blanche de chemins).
- Panneau : `/freebox/` (menu Réseau). Socket `/run/secubox/freebox.sock`, utilisateur `secubox-freebox`, sans capacité.
- Contrôle des DNS annoncés (#3769) : `GET /dns` (réglage, attendus, dernier contrôle, sans requête Freebox),
  `POST /dns/reglage` {reglage:{actif, mode: alerter|corriger, ipv4, ipv6 ("auto" ou adresse)}}, `POST /dns/appliquer`
  {confirme, corriger}, `POST /dns/reinitialiser` {confirme} (admin). Réglage `/var/lib/secubox/freebox/dns-reglage.json`,
  état `dns-controle.json`. Passage toutes les 15 min (`freeboxctl dns-controle`, unité `secubox-freebox-maillage`).
  Jamais de DNS secondaire ; jamais de correction vers un serveur qui ne répond pas. Défaut : actif, corriger.
- Autoconfiguration : `GET /autoconfig` (écarts), `POST /autoconfig` {ids, confirme, confirme_dmz} (admin, droit « settings », audit ; la DMZ exige `confirme_dmz`).
- Écriture : `POST /pare-feu/ipv6` {actif, confirme:true} (réglage `ipv6_prefix_firewall` de la Freebox, `ipv6_firewall` sur les anciens firmwares ; un interrupteur global : le désactiver laisse entrer l'IPv6 vers tout le réseau) (admin, droit « settings », relecture, audit). Redirections de ports : celle du maillage distant (ci-dessous).
- **Maillage distant (#3742)** : sur un rendez-vous qui déclare `[wireguard] public_endpoint` dans `/etc/secubox/p2p.toml`,
  `GET /maillage-distant` (lecture) rend la redirection IPv4 UDP du port annoncé vers la box, l'exception IPv6 et le dernier
  contrôle ; `POST /maillage-distant` {confirme:true} (admin, droit « settings ») la pose par `fw/redir/` : lecture d'abord,
  création seulement si absente, jamais de doublon, relecture et audit. Seule la règle portant le commentaire
  « SecuBox maillage distant (wg-mesh) » est corrigée (PUT) ; une autre règle qui prend le port (plage, `tcp_udp` compris)
  vers un autre appareil est refusée (`port_pris`, IP occupante, journalisé) et jamais réécrite ; une règle tierce déjà
  identique compte comme conforme ; des doublons SecuBox sont signalés, jamais supprimés. DMZ active vers la box (et aucune règle tierce
  active sur le port, qui l'emporterait) : l'IPv4 est déjà ouverte, état `couvert_par_dmz`, aucune redirection créée (cas
  de gk2). Une exception IPv6 tierce active vers une autre IPv6 sur ce port est signalée (`occupants`), jamais modifiée. Exception IPv6 ciblée (UDP vers l'IPv6
  fixe) seulement si la Freebox expose une voie d'exceptions (`fw/ipv6/`, `fw/ipv6/redir/`, `fw/pinhole/`) ; sur la
  Freebox de gk2 les trois sont **refusés** : état `indisponible`, aucune écriture IPv6 tentée, et le pare-feu IPv6 global
  n'est jamais désactivé d'office (les nœuds distants passent par l'IPv4). Aussi item `maillage_distant` de
  l'autoconfiguration et verbes `freeboxctl maillage-lire|maillage-appliquer <ip_box>`.
- **Contrôle de l'IPv6 fixe** : `secubox-freebox-maillage.timer` (15 min) lance `freeboxctl maillage-controle` (lecture
  seule : `ip -j -6 addr`, résolution AAAA du nom annoncé) ; état dans `/var/lib/secubox/freebox/maillage-controle.json`,
  alerte au journal (priorité avertissement) si l'IPv6 fixe disparaît du WAN ou diffère de l'AAAA publiée. IPv6 attendue :
  `[maillage] ipv6_fixe` de `/etc/secubox/freebox.toml`, sinon la première adresse globale à durée illimitée de
  l'interface de la route IPv6 par défaut ; sans route par défaut ni déclaration : aucune IPv6, donc aucune ouverture IPv6.
  Unité durcie (`ProtectProc=invisible`, `ProcSubset=pid`, `MemoryDenyWriteExecute=yes`) ; `freeboxctl` sous profil
  AppArmor enforce `secubox-freeboxctl` (`/etc/apparmor.d/usr.sbin.freeboxctl` : écriture sous `/var/lib/secubox/freebox/`
  seulement, ajout à l'audit, exécution de `ip`, réseau inet + netlink), déchargé par le postrm. Aucune modification
  DNS automatique : aucun module ne publie l'AAAA aujourd'hui ; pour l'ajouter, poser l'AAAA de `gk2.secubox.in` à la main
  chez le registrar (valeur = `ipv6_attendue` du contrôle), le contrôle vérifie ensuite qu'elle reste juste.
- UPnP : `GET /upnp` (état + ports ouverts par les appareils), `POST /upnp` {actif, confirme:true} (admin, droit « settings », audit).
