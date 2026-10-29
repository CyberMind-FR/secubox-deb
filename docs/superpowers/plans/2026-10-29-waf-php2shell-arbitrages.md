<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# WAF PHP2Shell (#3257) — arbitrages et mineurs reportés

Relevé du registre d'exécution du plan `2026-10-29-waf-php2shell.md` (2026-10-29).

## Arbitrages

- Ruling R1: dans le JSON structurel, `source` est une LISTE de chaînes ; le chargeur de T2 l'accepte ([]string) ou l'ignore, sans jamais faire échouer le fichier ; le test de T2 l'inclut — pourquoi : un type incompatible ferait échouer tout waf-rules.json (moteur vide) — coût si faux : aucun
- Ruling R2: TestCorpusLivreSansRejet utilise le corps imbriqué de TestAnalyserMultipartImbrique (progress + 900 fichiers), qui déclenche 001 et 002 — pourquoi : l'exploit à 4 parties ne déclenche pas 002 — coût si faux : aucun
- Ruling R3: T5 repère le commentaire CrowdSec de main.go par son contenu, pas par le numéro 193 — coût si faux : aucun
- Ruling R4: la ligne multipart-limite porte `concurrence` = cap(s.capturesMultipart) (16 en production) — pourquoi : vraie dans les tests à capacité 1 — coût si faux : aucun
- Ruling R5: « io.EOF → analyse » du brief remplacé par « io.EOF ET frontière finale --boundary-- vue dans le préfixe » (frontiereFinaleVue) — pourquoi : Go rend un io.EOF nu sur un préfixe coupé en plein en-tête, la règle du brief aurait déclaré « analyse » un corps tronqué — coût si faux : un en-tête tronqué contenant littéralement la frontière finale passe pour complet (mode detect, sans effet de sécurité)
- Ruling R6: Content-Disposition découpé sur ; HORS guillemets (et non sur tout ;) — pourquoi : filename="a;<?php" échapperait sinon, et PHP respecte les guillemets — coût si faux : aucun
- Ruling R7: les signatures rejetées sont nommées `<catégorie>/<id>` (format des motifs regex de #1317) au lieu de l id seul du brief ; `<catégorie>#<index>` sans id ; `<catégorie>#structural` si la valeur n est pas une liste — pourquoi : un seul format dans rejetes — coût si faux : aucun
- Ruling R8: le jeton du sémaphore est rendu APRÈS l analyse (et non juste après figer()) — pourquoi : la borne mémoire couvre aussi les allocations de l analyse — coût si faux : une capture tient son jeton ~1,6 ms de plus
- Ruling R9: l analyse dans le defer retarde les derniers octets bufferisés de la réponse au client (≤ 4 Kio, ~µs à 1,6 ms x86) ; le relais vers le backend n est pas retardé — accepté au regard de « aucun tampon ajouté avant le relais » — coût si faux : quelques ms de queue de réponse sur les envois multipart des vhosts PHP
- Ruling R10: la ligne du sémaphore plein devient `multipart-concurrence` ; `multipart-limite` reste le statut de l analyseur (plafond de parties) — pourquoi : une saturation et une forme d attaque ne doivent pas porter la même étiquette chez actord — coût si faux : aucun
- Ruling R11: la contrainte « aucune mention de CrowdSec » vise les FICHIERS touchés ; README.md et CUTOVER.md de secubox-waf-ng sont réécrits pour décrire le fonctionnement actuel (bans nft natifs, actord, campagnes, leurres), « pont de blocage externe retiré (#1218) » sans nommer l outil ; changelog Debian historique et Conflicts/Replaces intouchés — pourquoi : consigne du propriétaire (jamais CrowdSec, même historique) — coût si faux : un peu d histoire de doc en moins
- Ruling R12: la capture analyse TOUS les clients, réseau local et 127.0.0.1 compris (l arbitrage 3 « LAN exempté » est retiré) — pourquoi : en mode detect l exemption ne protège rien, les adresses privées ne partent jamais vers actord (journal « local »), et elle aveuglait les vhosts .onion (Tor arrive en 127.0.0.1) — coût si faux : des lignes « local » de plus dans le journal
- Ruling R13: I1 corrigé par un balayeur calqué sur main/rfc1867.c de PHP 8.2 (source de référence citée), en remplacement de mime/multipart ; même interface ResultatMultipart — pourquoi : la spec § 6.1 (« la bibliothèque standard suffit ») est contredite par les sondes — coût si faux : un balayeur maison à maintenir
- Ruling R14: I2b — waf-rules-sync garde la valeur `enabled` de la box pour une catégorie livrée (choix de l opérateur, audité s il diffère) ; waf-profils-fusion consigne les noms déjà proposés (`php_services_proposes`, idem pour les motifs) et n ajoute que les noms jamais proposés : un retrait par l opérateur reste acquis — coût si faux : une clé de suivi de plus dans le fichier
- Ruling R15: I3 — motifs d hôte génériques `php_hotes` (regex sur le nom d hôte, livrés : ^(nc|nextcloud|cloud)\. et ^(webmail|roundcube)\.) en plus des vhosts explicites ; une ligne au démarrage donne le nombre de vhosts et de motifs PHP armés — coût si faux : un hôte nommé ainsi mais sans PHP serait analysé (detect seulement)
- Ruling R16: dérogation à « une seule passe » : le résidu I1 (contournement de détection, correctif de 3 lignes validé contre l oracle C) et N1, N2 sont corrigés avant la fusion — coût si faux : une reprise de plus

## Mineurs reportés

- Task 1: minor (deferred): filename* non décodé (%3C%3Fphp) ; champ PROGRESS qui porte un filename non compté ; en-têtes tolérés par PHP mais refusés par Go → Malforme avec comptes partiels (la tâche 4 évalue les signatures quel que soit le statut — à vérifier en relecture T4)
- Task 2: minor (deferred): tests des noms de rejet trop lâches (Contains "x-1" au lieu de la liste exacte php2shell/x-1, php2shell#structural, php2shell#4)
- Task 2: minor (deferred): un severity/cve mal typé fait perdre l id lisible (rejet nommé #index)
- Task 2: minor (deferred): ids structurels dupliqués non détectés
- Task 2: minor (deferred): doc d Integrite() et en-tête de rules.go muets sur les structurelles
- Task 3: minor (deferred): test_fusion_php_service_inconnu_ignore n affirme pas le message stderr (capsys) ; docstring trop longue ; doublon php_services non testé en Go
- Task 4: minor (deferred): jeton tenu pendant tout un envoi lent (16 envois au goutte-à-goutte coupent la capture ; visible par les lignes multipart-concurrence) — plafond par adresse ou durée de détention, issue à ouvrir
- Task 4: minor (deferred): lignes multipart sans JA4 ni Tool (parité avec les lignes detect regex)
- Task 4: minor (deferred → doc T5): --max-body-inspect règle aussi la fenêtre de capture (16 × fenêtre au pire)
- Task 4: minor (deferred): préallocation sur Content-Length non vérifié (≤ 16 × 1 Mio, borné par le sémaphore) ; multipart-concurrence journalisé même pour une requête ensuite bloquée
- Task 5: minor (deferred): « 4 h » trop général dans README/CUTOVER (ban gradué ; campagnes et leurres 4 h à 7 j)
- Final: minor (deferred → issues): saturation du sémaphore (M4, compte en requêtes et non en octets) ; bourrage au-delà de la fenêtre (M5) — un automate en flux sans fenêtre réglerait les deux
