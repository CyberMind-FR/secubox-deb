<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# FAQ — ESPRESSObin (951 Mo) : ce qui tient, ce qui sature

Retour d'essai du 2026-10-16 sur une ESPRESSObin v7 (profil `minimal`, #2816, #2838, #2849).

## La carte ne répond plus (ping oui, SSH et HTTPS non)

Elle manque de mémoire vive : swap plein (950/950 Mo), `systemd-journald : Under memory pressure` dans `dmesg`, charge > 10. Pas de panne matérielle (aucune erreur d'E/S, aucun OOM-kill).
**Cause constatée** : installer de gros paquets (WAF `sbxwaf`, HAProxy) sur la carte vivante. Ils ont été retirés ; le WAF reste sur l'infrastructure (gk2).
**À faire** : installer en tâche détachée (`nohup … &`), jamais dans la session SSH (elle meurt avec le swap), puis attendre la charge < 5. Dernier recours : couper l'alimentation, puis `dpkg --configure -a`.

## `ndpid-engine` redémarre toutes les 5 s (« pcap_open_live: eth2 : No such device »)

`secubox-ndpid-engine` 1.7.1 lance nDPId sur `eth2` (valeur de gk2). Le choix de l'interface est dans **1.7.2** (#2740) ; `secubox-minimal` >= 0.5.1 l'exige (#2851).
Vérifier : `systemctl show secubox-ndpid-engine -p NRestarts`.

## L'agent Auto-Load a rejoué le nom et le mot de passe au redémarrage

Il reprend son étape « application » avec les réponses d'origine : le nom revient et le mot de passe d'usine peut être reposé (#2853). Contournement : `systemctl disable --now secubox-autoload-agent`.
Le mode réseau `routeur` échoue (« secubox-net-detect » n'est livré par aucune image) : utiliser `lan` (une seule carte, le réseau en place est conservé).

## Je ne peux plus me connecter en SSH

Le SSH de la carte est réservé au LAN (`192.168.1.0/24`) et au support depuis gk2 par le tunnel `wg-autoload` (`10.64.0.1`) : `/etc/secubox/hardening/nft-input-trust.d/00-ssh-lan.nft`.
Depuis gk2 : `ssh -i /etc/secubox/secrets/support-ssh/id_ed25519 -o IdentitiesOnly=yes root@10.64.0.9` (#2854 : à poser par l'enrôlement).

## Pourquoi pas le WAF sur la carte ?

HAProxy + sbxwaf + les unités absorbées (exposure, vhost) coûtent environ 100 Mo de plus sur une carte qui en a déjà 800 d'occupés. Les leurres de service et la détection de force brute
tournent sur gk2 (`sbx-authwatch`, dans `secubox-toolbox-ng`) ; l'administration de la carte y est publiée derrière le WAF (`admin.<nom>.secubox.in`, #2844).

## `secubox-portal` : pourquoi le garder ?

Il livre `login.html`, la page de connexion de la WebUI (le hub ne la livre plus depuis 1.9.6). Sans lui, plus de connexion par navigateur.
