<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# TODO — SecuBox-DEB : backlog actif
*Mis à jour : 2026-10-11 (release alpha.11).* Seul le backlog actif est ici (≥ 2026-09-01).
Le reste est archivé, jamais perdu : `.claude/archive/INDEX.md` (≈ 240 cases ouvertes
y dorment, par mois) — ne le lire que sur demande.

---

## 2026-10-11 — suites de la release alpha.11
- [ ] **Auto-Load phase A** : mettre `secubox-autoload-agent` dans les images (aujourd'hui hors profils) et livrer l'unité de premier démarrage (zero-touch ; unité root : demander d'abord). Puis netboot (#2186), udp/51830 de la Freebox, SMTP.
- [ ] **Vérifier la CI du tag** : assets de la release (images, installateur sans écran `.iso.gz`/`.img.gz`), `SHA256SUMS`, boot de l'installateur en VM, essai ESPRESSObin lite (#2177).
- [ ] **Échelle de réponse** (#2274, fermée) : surveiller les adresses partagées (CGNAT) ; trancher les bans sur plages Cloudflare (exemption ?) ; écrire les décisions de sbxwaf dans le journal central
      `audit.log` (aujourd'hui `/var/log/secubox/waf/audit.log`) ; quarantaine du LAN : aucun appareil concerné à ce jour.
- [ ] **#2236** détection d'OS : DHCP (la Freebox sert le DHCP : l'option 60 n'est pas vue), User-Agent par appareil (sbxmitm), noms mDNS/SSDP ne sont pas alimentés ; 8 appareils sur 657 typés.
- [ ] **#2212 étape 9** : décider du retrait de la navigation par catégories (`?nav=categories`, champ `categories` de `/public/menu`) ; le menu en service est sans doublon ni orphelin.
- [ ] **MetaNews → billets** : publier 1 à 2 sujets par tour au lieu d'une rafale de 6 au premier tour.
- [ ] **Dépôt apt gk2** : automatiser le contrôle de la date de `InRelease` après `includedeb` (l'export signé échoue en silence quand l'agent est verrouillé).

## 2026-10-08 — idées du propriétaire, à concevoir (design d'abord)
- [ ] **Connecteur Freebox** (`secubox-freebox` + panneau d'administration) : autorisation unique de l'API Freebox (validation sur la Freebox),
      puis, dans l'ordre : appareils du réseau (noms, adresses), pare-feu IPv6 et redirections (lecture), état de la connexion, redirections
      de ports (écriture, confirmée et journalisée). Consommateurs : IPv6 Guardian (étapes « bloquées » et « exceptions », noms), NAC, exposition.
      Étend le mode « SecuBox esclave, non routeur » aux possibilités de l'API Freebox. Dossier : `docs/dossiers/ipv6-guardian.md` (phase 2).
- [ ] **#2050 reste** : voir `docs/dossiers/rassemblement-reste-2050.md` (D3/D4 DNS : un moteur Unbound + bibliothèque commune ; S7 waf←waf-ng en paquets seulement, voie de ban dupliquée à part ; M9 ABANDONNÉ (vendors radio/metanews identiques, socialrelay différent ; git déduplique déjà)). **Décisions du propriétaire requises** avant tout code.
- [ ] **Freebox : autoconfiguration depuis le panneau** (demande du 2026-10-08) : « autoconfig freebox, dns, fwipv6, dmz… depuis freebox webui ». Panneau `/freebox/`
      onglet « Configuration automatique » : lire l'état, montrer ce que SecuBox recommande (pare-feu IPv6 actif, DNS DHCP de la Freebox → la box, redirections
      utiles, DMZ **seulement sur demande explicite** car elle expose toute la machine), prévisualiser le changement (dry-run), appliquer avec confirmation,
      audit et retour arrière. Prérequis : droit « settings ». À concevoir : chemins API DNS/DMZ de la Freebox v9 (à explorer en lecture d'abord).
- [ ] **Rapport complet après le rassemblement** (demande du 2026-10-08) : une fois #2050 terminé (paquets et modules), produire un rapport complet pour le propriétaire :
      avant/après (nombre de paquets, méta-paquets, unités, comptes root), carte des modules, ce qui reste séparé et pourquoi, risques, déploiements, dette
      (transitoires à retirer, tests rouges préexistants), prochaines étapes. À publier en page (artefact) + `docs/dossiers/`.
- [ ] **Cast / diffusion** : diffuser un média du Hall (bibliothèque YouTube SAS, radio, diffusion du Hall) vers les appareils Google Cast détectés par
      IPv6 Guardian (Freebox Player POP, Chromecast, TV Android…) ; « viewpoint » (précisé le 2026-10-07 : « node view surf ») = la vue d'un nœud du maillage, affichée par secubox-surf (relais par-origine) ; à diffuser vers un écran Cast. Conception à écrire d'abord : source = page surf d'un nœud, cible = appareil Cast détecté.
      Contraintes : URL de média joignable par l'appareil (HTTP LAN), pas de contournement de DRM.

## 2026-10-02 — backlog noté (analyse 25/09 → 02/10), à corriger dans l'ordre

### 🔴 Sécurité
- [ ] **#1766** nac : blocage, quarantaine et zones sans effet réseau.
- [ ] **#1754** nginx `set_real_ip_from` à restreindre aux relais réels.
- [ ] **#1366** Coffre P0 : clé apt 219BA872 en clair en deux copies.
- [ ] **#1516** `/data/shared/photos` et dossiers `<user>/` en 0777.
- [⏸️] **#1851** Coffre P3 niveau 0 : SUSPENDU 2026-10-03 (voir WIP) ; liaison TPM : #1902 ; à la place #1903 (sauvegardes chiffrées) et #1904 (un groupe par secret).
- [ ] **#1852** Coffre P6 : Autocrypt, `mail_crypt` à mesurer.
- [x] **#1581** `require_jwt` = administrateur réel — livré et déployé.
- [x] **#1855** Coffre : la connexion ouvre le Coffre (admin) et le compartiment de toute personne, invités compris — fusionné (PR #1856), déployé gk2 (vault 2.0.15, auth 1.1.18, aggregator 0.3.10).

### 🟠 Boxes installées par image
- [x] **#1808 / #1684** gk3 vérifié en direct le 2026-10-02 (frontal HAProxy → sbxwaf → nginx, 0 unité en échec).
- [ ] gk3 : `secubox-hardening` inactif à expliquer ; `hall.gk3` répond 421 sur 443 à vérifier.
- [ ] **#1540** drop-ins `RuntimeDirectory=secubox` ré-approprient `/run/secubox`.
- [ ] **#1826 / #1623** noms gk2 en dur ; écritures `/etc/haproxy` hors bac à sable.
- [ ] **#1735 / #1734** installation LXC non reprenable ; conteneur gitea privilégié.

### 🟡 À finir
- [ ] **#1748** déployer gk3 ; garde-fou CI contre les fusions qui écrasent master (`scripts/check-merge-overwrite.sh` est sur la branche `backup/suivi-2026-10-02`).
- [x] **#1743** podman/docker retirés des paquets et des boxes (2026-10-03) ; reste à fermer après validation de #1917.
- [x] Synthèse vocale lente : voix rapide Piper (0.5.0). Reste : l'interface native du studio utilise toujours le grand modèle (110-140 s) pour ses propres synthèses — piste : le moteur n'accepte qu'un backend TTS global (`OMNIVOICE_TTS_BACKEND`), à ne changer que si l'exploitant renonce au clonage et aux 600 langues ; progression visible (« jusqu'à 2 min ») à ajouter pour les voix nommées.
- [ ] **#1917** voicestudio : validation au navigateur par une personne connectée (administration, usager, carte du Hall), puis fermer ; retirer `migrer-podman` / `basculer` du ctl quand aucune box ne peut plus en avoir besoin ; sur gk2 l'agrandissement de la carte « VoiceStudio » vise `voicestudio.gk2…` (hôte inexistant : le module n'est pas sur gk2, la carte le dit mais l'agrandissement ouvre une page vide) ; le minuteur horaire du relais doit prendre `voicestudio.gk3` tout seul (vérifier demain) ; dettes nommées dans son README — profil AppArmor (complain → enforce), utilisateur dédié `secubox-voicestudio`, `--require-hashes` sur les dépendances Python, `--apply`/dry-run du ctl, interface native (`frontend/dist`) non embarquée.
- [ ] gk3 : `authorized_keys` de root a été vidé dans la nuit du 02 au 03/10 sans trace (cause inconnue) — à surveiller ; vérifier que rien ne l'écrase (tmpfiles `f^` ? antirootkit ?).
- [ ] `secubox-haproxy` : 2 tests ACME échouent sur master (`test_acme_wiring.py::test_generator_reads_ssl_redirect`, `test_redirection_https_exige_un_certificat`) — préexistants, sans rapport avec VoiceStudio ; la fixture de génération exige un /run/haproxy inscriptible (root ; sinon `unshare -Urm`).
- [ ] `tests/test_conformite_jwt.py::test_aucune_route_non_gardee_nouvelle` échoue sur master (72 routes hors inventaire : billets, webos…, aucune de voicestudio) : inventaire à mettre à jour ou routes à garder.
- [ ] secubox-hub 1.9.30 (sidebar sans RustDesk) publié, non déployé (risque login.html) ; secubox-meta et secubox-profils republiés.
- [ ] Coffre : gk2 scellé depuis le dernier redémarrage — rouvrir par la connexion admin ; tester la connexion d'un non-admin et d'un invité de bout en bout.
- [ ] À valider au navigateur : SSO Nextcloud (cadre `/sbx/entrer`), « Mes sites » en lien direct.
- [x] #1855, #1857, #1858, #1859, #1862, #1863 — fusionnés, déployés gk2, issues fermées (2026-10-02).

### 🟢 Chantiers (hors correctifs)
- SBXOS/Aurora P1–P18 + SDK phases 1–5 (#1594–#1622) ; Hall v4 (#1590).
- Identité #1405/#1417/#1562/#1589/#1829 ; fédération #1388 ; propagation #1824.
- Antivirus mail : ClamAV installé mais arrêté dans le LXC `mail` ; `secubox-mail-security` (#1834) à concevoir.

---

## 2026-09-25 — suites identité SBX OS (#1405)

- [ ] **Demandes de compte depuis le Hall** : « il me manque Nextcloud » ou
      « relier mon compte existant », validées par l'administration, suivies,
      révocables.
- [ ] **Certificat client pour les abonnements** — maquette, puis demande
      embarquée dans les webui ; lien de maillage par certificat.
- [ ] **Jarre de cookies vaultée** par personne dans son conteneur de rejeu ;
      la révocation de l'appareil ou de la personne la purge.
- [ ] **Sessions listées** : retirer celles qui sont expirées ou d'appareils
      refusés (elles sont déjà refusées à l'usage, mais encombrent la liste).
- [ ] **MacIntel de gandalf** sans session récente : garder ou révoquer.
- [ ] **`scripts/generate-docs.py`** : erreur de syntaxe ligne ~1802 sur master
      (antérieure au retrait d'OSSEC).
- [ ] **identity / avatar** : l'ancien module d'identité n'est plus au menu ;
      le rendre transitionnel vers secubox-sbxid.

---

## 2026-09-16 — suites Zigbee & accès (#1365, #1366 livrés)

- [ ] **Zigbee : luminosité et température de couleur.** `/devices/{nom}/set`
      n'accepte que `state`. Les ampoules exposent `brightness` et `color_temp`
      en accès 7 — la carte pourrait porter un réglage long-press. À faire
      seulement si l'usage le demande : la carte existe pour le geste d'une
      seconde, pas pour remplacer la console.
- [ ] **Zigbee : lecture sans jeton sur le LAN ?** La carte porte `auth:true`
      parce que `require_lecture` est fermé par défaut. Armer
      `[tableau_de_bord] actif = true` ouvrirait la lecture au LAN — décision
      d'exploitant, pas de code.
- [ ] **Sonder le groupe C restant.** `webmail` a été exclu du décommissionnement
      et garde un vhost qui répond 200 : vérifier ce qu'il sert réellement.
- [ ] **Unités orphelines de `metablog-sync`.** `.service` et `.timer` ne sont
      possédés par aucun paquet (comme l'était `secubox-wazuh`). Les empaqueter
      ou les retirer.
- [ ] **File de notifications BBS.** Toujours sans persistance : une notification
      perdue est perdue. Poser la file si les pertes se voient.

---

## 2026-09-14 — suites leurre & renseignement (#1290 livré)

- [ ] **Vue « marques revenues »** dans la page Renseignement. Le moteur
      enregistre `marque_revenue` dans l'enveloppe et crie au journal ; l'interface
      ne l'expose pas. C'est le moment où le filigrane paie, il doit se voir.
- [ ] **Filigrane à l'authentification** — chercher la marque là où le corps est
      DÉJÀ lu (login), au lieu de bufferiser le trafic de toute la box.
- [ ] **Honeypot : ratio d'échantillonnage** si l'on veut un jour n'en armer
      qu'une fraction. Aujourd'hui : tout ou rien, apprentissage seul.
- [ ] **Ports leurres** — armer `--leurre-bannieres` sur gk2 après observation
      du coût réel (plafond de 64 connexions simultanées).
- [ ] **Page de blocage** : étendre le remplacement au-delà des appâts
      intrinsèques ? À ne PAS faire pour les injections — répondre 200 ferait
      croire la charge passée sur une page qui existe.

## 2026-09-14 — suites crypto (#1288 livré)

- [ ] **JWT HS256 → EdDSA** (RFC 8037) : distribuer une clé publique de
      vérification sans partager le pouvoir de signer.
- [ ] **Courbes** — si l'évaluation CSPN exige la liste historique ANSSI
      (FRP256v1, Brainpool) plutôt que Curve25519, rouvrir. Les primitives sont
      isolées dans un seul module : le changement serait local.
- [ ] **`secubox-nac`** (#1289) — conflit de fichier avec `secubox-hub`, paquet
      gelé. Décider qui possède la vue NAC.

## 2026-09-14 — suites Lexie (#1287 livré)

- [ ] **Moteur** : Piper + whisper.cpp arm64 sur la box, ou `moteur = "distant"`
      vers VoiceStudio sur poste x86. Arbitrage sur la taille du modèle.
- [ ] **Traits comportementaux dans le profil acteur** — ils partent dans
      l'enveloppe, l'interface ne les affiche pas encore.

---

## 2026-09-11 — suites crypto souveraine (#1263, #1272 fusionnés)

### 🟡 Boucle backend souverain
- [ ] **`secubox-identity` — générer la clé via hermes** : `ensure_x25519_pubkey`
      détecte `hermes-souverain` mais appelle encore `cryptography` stdlib pour la
      keygen. Câbler sur `hermes.Identity.generate()` (même primitive X25519, aucun
      impact sécu — ferme juste la boucle). Worktree + vérif déploiement.
- [ ] **Consommateurs `Session`** : brancher mesh/MirrorNet et l'invitation (#1262)
      sur `secubox_core.crypto.Session` (ECDH X25519 + HKDF) plutôt que du stdlib ad hoc.

### 🟢 Perf / stégano (optionnel, côté upstream)
- [ ] **Carter classique** : étendre l'optimisation `random_grid` (PR livreedhermes#6)
      à `carter.py` → nécessite de revoir les 2 tests d'avalanche à bruit figé
      (dépendance à la granularité de consommation `os.urandom` cellule-par-cellule).
- [ ] **Pré-chauffage référent 18×18** : build à froid ~262 ms (puis caché) — envisager
      un warm-up au démarrage si la latence du premier message compte.

### 📌 Suivi contributions upstream
- [ ] Suivre review/merge des PR `CyberMind-FR/livreedhermes` **#5** (N1/W1/W2) et
      **#6** (perf) — ressort de l'upstream, pas d'auto-merge.

---

## 2026-09-07 — suites Freebox TV / réveils / capacité gk2

### 🔴 Capacité gk2 / réveils on-demand
- 📄 **Plan complet : `.claude/AUDIT-ALLEGEMENT-2026-09.md`** (audit RAM data-driven,
  23 modules en double, fuites metrics/devwatch, phases P1-P5).
- [ ] **Charge chronique** : load ~5, RAM ~250 Mo libres → les « réveils »
      (POST /api/v1/profiles/wake) démarrent mal les services on-demand (pas un
      bug du wake — profiles répond, /wake authed). Réduire l'empreinte (Streamlit
      & services lourds), cf. #946. `secubox-droplet` inactif → droplet/status 504.

### Freebox TV (#1238 fermé — suites optionnelles)
- [ ] Annonce `{sbx:'media'}` + `lecteur`/`zoomable` → dock + mini-viewer (comme radio/podcaster).
- [ ] Playlist « de base » curatée (actuellement 177 chaînes standard).
- Note : LAN-gating **NON** — laissé sans authent + WAN (choix utilisateur).

### ZIA Action Layer — Phase E (généralisation)
- [ ] Manifestes `capabilities.d/*.json` : **lyrion** (media.toggle, media.stop=pause,
      `cast`), **peertube** (ui.zoom, media.stop). Capacités déjà prouvées à l'audit.

### CSP / aide partagée
- [ ] SBXAide impose `style-src 'unsafe-inline'` aux services stricts (radio/bbs faits) —
      à terme, externaliser sa CSS + positionner sans style inline pour garder strict.


- [ ] VoiceStudio LAN : l'override DNS Unbound et `relais-maillage.toml` de gk2 sont posés à la main (aucun paquet ne les porte). Les packager (candidat : secubox-annuaire-noms ou un drop-in `secubox-split-horizon`) ; sans eux, le nom résout vers l'IP publique et le studio redevient inatteignable.

- [ ] #1852 : valider avec une session réelle la page `pgp.<domaine>` + greffon `secubox_pgp` (bouton Chiffrer/Signer dans Elastic, affichage d'un message chiffré, pastille, Autocrypt entrant) ; PGP/MIME (multipart/encrypted) non géré ; brouillons en clair (autosave) ; journal du Coffre : une lecture de clé par chargement de page (à espacer si le bruit gêne).

- [ ] #1943 POC DNS AdBlock TV : **activer sur gk2** = redémarrer l'agrégateur (ad-guard est servi dans l'agrégateur : ~110 modules, plusieurs minutes de 502 au redémarrage à froid) puis jouer la procédure A/B/C sur les 2 Freebox TV (`docs/poc-dns-adblock-tv.md` §7) et remplir `packages/secubox-ad-guard/reports/tv-before-after.md` (domaines nécessaires, faux positifs, fonctions cassées). Fichiers déployés (1.2.0), POC INACTIF.
- [ ] #1946 `secubox-adblock-sync` : l'exemption d'IP par vue Unbound vide ne marche pas (à vérifier sur Unbound 1.17 de gk2, ajouter `local-zone: "." transparent`).
- [ ] `secubox-toolbox` : des tests importent encore `mitmproxy` / `mitmproxy_addons` (reste de l'ancienne architecture ; le moteur est `sbxmitm` en Go) — à supprimer.
- [ ] Mise à niveau de gk3 vers Debian 13 par SAUVEGARDE des données puis RÉINSTALLATION + restauration (suite de #1294) : inventaire gk3 relevé (UEFI, nvme 465 Go : / 461 Go ext4 « secubox », /data 4 Go ext4 quasi plein, ESP 512 Mo ; LXC mail + voicestudio ; /srv/secubox 37 Go, /var/lib/secubox 6 Go) ; à faire : plan de sauvegarde hors box, image Trixie amd64, restauration, essai à blanc.
