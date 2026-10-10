<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# HISTORY — SecuBox-DEB : mois courant
Entrées datées, les plus récentes en haut. Seul le **mois courant** vit ici ; les mois
précédents sont dans `archive/HISTORY/AAAA-MM.md` (lus sur demande, voir `archive/INDEX.md`).

## 2026-10-10 — MetaNews crée des billets éphémères de 5 minutes (ref #2268)
Route `POST /service/ephemere` dans billets (jeton de flotte `metanews`, éphémères seulement, plafond 60/h, interne), client + `internal/diffusion` dans MetaNews (≥ 2 sources, 6/h, grâce 1 h, TTL 5 min). secubox-billets 0.11.0, secubox-metanews 0.4.0.

## 2026-10-10 — Billets éphémères (ref #2268)
`ttl_s` à la création, `expires_at` (migration 0007), exclusion à la lecture dès l'échéance, 410 sur le permalien, balayage archive→suppression (24 h), compte à rebours et extinction dans le fil ouvert. secubox-billets 0.10.0. Reste : MetaNews qui les crée.

## 2026-10-10 — Billets : le fil est vivant (ref #2266)
Un billet publié ou commenté remonte en tête (`bumped_at`, migration 0006), `/feed/maj` + sondage 15 s dans `immersif.js`, animation d'arrivée (nouveau) et de remontée (FLIP, pastille « commenté »). secubox-billets 0.9.0. 52 échecs de tests préexistants dans le module (CSRF/fixtures), aucun de plus.

## 2026-10-10 — NAC : détection passive de l'OS et du type fin (ref #2236)
Colonnes `os`/`os_source`/`device_subtype`/`mac_random` (preuve obligatoire), détecteur pur `osdetect.py`, preuve DNS d'ad-guard en lecture seule, drapeau `conteneur` et `?exclure_conteneurs=`. Page `/appareil/` : OS + preuve + type détaillé + MAC aléatoire. secubox-nac 3.3.0, secubox-hub 1.9.53. DHCP/User-Agent/mDNS compris mais non alimentés.

## 2026-10-10 — waf-ng 1.26.2 : le postinst recharge le profil AppArmor (ref #2240)
`aa-enforce` ne recharge pas un profil déjà en enforce : les règles DNS de 1.26.1 n’étaient pas dans le noyau. `apparmor_parser -r` ajouté. Constat gk2 : après rechargement manuel, les 4 bans Googlebot sont levés (unban `robot-verifie:googlebot.com`).

## 2026-10-10 — sbxwaf : le DNS des robots refusé par AppArmor, audit du kill switch illisible (ref #2240)
L'exemption Googlebot (FCrDNS) échouait en silence : profil AppArmor sans UDP ni fichiers du résolveur. Audit des réévaluations déplacé vers `/var/log/secubox/waf/audit.log` (le journal central n'est pas écrivable par `secubox-waf`). toolbox-ng 0.11.1, waf-ng 1.26.1.

## 2026-10-10 — Phase 5 : Radar des acteurs dans le Hall, et on ne bannit plus Googlebot (ref #2240)
Carte Hall `radar` (risque et confiance sur deux axes, fiche avec facteurs/scénario/refus) alimentée par `GET /radar` de sbx-actord (vue réduite, liste blanche sans adresse ni cible). `GET /api/v1/waf/reevaluations`. **Correctif** : 8 adresses Googlebot bannies par les leurres (4 prolongées par le kill switch) — exemption des robots d'indexation vérifiés par DNS inverse confirmé (FCrDNS) au point unique `BanFor`, bans existants levés au démarrage. toolbox-ng 0.11.0, waf-ng 1.26.0, webos 1.6.0.

## 2026-10-10 — Actor Intelligence 2.0, phase 4 : kill switch logique (ref #2240)
Réévaluation de chaque ban à l'échéance (RELEASE ou EXTEND gradué, plafond 30 j, jamais permanent), compteurs par élément sur `waf_ban{,6}` avec migration, preuves `reevaluations.jsonl` + audit, modes off/propose/auto (`--reevaluation`, `--reeval-seuil`). toolbox-ng 0.10.0, waf-ng 1.25.0. Tests Go `reevaluation_test.go`.

## 2026-10-12 — Les leurres bannissent partout (ref #2240)

Décision du propriétaire : un service simulé n'a d'autre but que détecter. Ban sur le chemin-appât d'un vrai vhost (jusque-là leurré mais pas banni), marque rejouée = 24 h minimum sur tout vhost, plages protégées respectées par le ban de leurre. toolbox-ng 0.9.1, waf-ng 1.24.0.

## 2026-10-12 — Carte du monde de la page Actor : ligne 7 corrigée (ref #2240)

La grille TERRE (60 × 120 points de 3°) avait une ligne 7 fautive : bande de 64 points d'une rive à l'autre de l'Atlantique Nord, Sibérie absente. Reconstruite ; waf-ng 1.23.1.

## 2026-10-12 — Le binaire sbx-actord est livré par secubox-waf-ng (ref #2240)

La phase 3 était dans toolbox-ng 0.9.0 (sources) mais le binaire `sbx-actord` (et `sbxwaf`) est livré par **secubox-waf-ng** : 1.23.0 le rebâtit. Piège : monter toolbox-ng seul ne change pas actord.

## 2026-10-12 — Actor Intelligence 2.0, phase 3 : scénarios, risque et confiance (ref #2240)

toolbox-ng 0.9.0 : `internal/actor/analysis` (scénario ordonné, risque ≠ confiance avec facteurs, décision OBSERVE/MITIGATE/BLOCK, BLOCK ≥ 2 capteurs), routes `/actors/{id}/{timeline,graph,risk}` et `/events` (vue complète). Reste : phases 4 (kill switch), 5 (vue Hall), 6 (doc).

## 2026-10-12 — PhotoPrism dans « Mes comptes » et le SSO du Hall (ref #2255)

PhotoPrism n'avait aucun réglage OIDC (`photoprismctl sso` jamais abouti) ; `sso` rejoué sur gk2, `/api/v1/oidc/login` → IdP du Hall. Carte « Mes comptes » (OIDC, sans lien) + `ENTREE_SSO` + `install` appelle `sso`. webos 1.5.16, photoprism 1.4.2.

## 2026-10-11 — sites-enabled : des liens, plus des copies (ref #2253)

Causes : `sed -i` (secubox-vhost-logs) et `os.replace` (nginxgen) remplacent un lien par une copie. Corrigés (metrics 1.17.1, profiles 0.20.0) + `secubox-wakectl nginx-relink` pour adopter les 19 copies de gk2. Disque local à 100 % constaté et nettoyé (worktrees fusionnés).

## 2026-10-11 — Vhosts on-demand : le réveil était masqué par les pages d'erreur (ref #2251)

PhotoPrism ne se réveillait pas (504 puis 502). Cause : `secubox-errorpages` avant `secubox-waking` dans le vhost (nginx retient la première `error_page`). Corrigé dans photoprism, peertube, radio, podcaster ; `nginxgen.wire()` insère avant et déplace un include mal placé (profiles 0.19.18) ; garde de dépôt.

## 2026-10-11 — /ndpid/ : l'API lit le moteur nDPId via sbxdpi (ref #2240)

secubox-dpi 1.8.0 : `SbxdpiBridge` (statut, flux, protocoles, applications, risques, JA4) avant le repli ndpiReader. Moteur nDPId démarré sur gk2 (engine 1.7.1, eth2).

## 2026-10-11 — Cause racine de /ndpid/ vide : deux paquets, une même unité (ref #2240)

`secubox-ndpid-engine` (capture nDPId) et `secubox-dpi` (API) livraient tous deux `secubox-ndpid.service` ; l'API l'emportait, nDPId ne tournait jamais. Unité du moteur renommée `secubox-ndpid-engine.service` (engine 1.7.1), API qui l'attend (dpi 1.7.4), test anti-collision. Consigne du propriétaire : nDPId n'a PAS été écarté, c'est netifyd.

## 2026-10-11 — Page /ndpid/ vide : mauvaise route d'API et aucun jeton (ref #2240)

secubox-dpi 1.7.3 : base `/api/v1/ndpid` (l'ancienne `/api/ndpid` donnait 404), jeton `sbx_token`, erreurs visibles, bandeau « source = ndpiReader ». JA3/JA4 et événements de risque restent vides tant que nDPId ne tourne pas.

## 2026-10-11 — Actor Intelligence 2.0, phase 2d : capteur DPI (ref #2240)

toolbox-ng 0.8.0 : sbxdpi émet une enveloppe `dpi` pour une adresse publique cumulant des risques nDPI hostiles (`DPI_ACTOR_SOCK`). Phase 2 terminée (WAF, pare-feu, DNS, DNS-détournement, DPI). Reste : phases 3 à 6.

## 2026-10-11 — Actor Intelligence 2.0, phase 2c : détournement DNS (ref #2240)

ad-guard 1.10.0 : `dns.hijack.new_net` / `dns.hijack.special` à partir d'un instantané du cache d'Unbound (`sudo -n secubox-adguard-tv cache-dump`). Reste : DPI.

## 2026-10-11 — Actor Intelligence 2.0, phase 2b : capteur DNS (ref #2240)

ad-guard 1.9.0 : `secubox-adguard-dnssensor` (domaines malveillants ou anormaux uniquement ; dérive des domaines connus). Consigne du propriétaire : « seulement les domaines malveillants ou anormaux » + « possiblement les domaines normaux qui auraient pu être corrompus ». Reste : DPI, réponses DNS (détournement).

## 2026-10-11 — Actor Intelligence 2.0, phase 2a : capteur pare-feu (ref #2240)

hub 1.9.52 (sonde nft additive), toolbox-ng 0.7.0 (`--scan-sensor`, enveloppe `firewall`/`dns`), waf-ng 1.22.0 (unite). Reste : capteurs DNS et DPI.

## 2026-10-11 — Actor Intelligence 2.0, phase 1 : actions defensives et decisions (ref #2240)

waf-ng 1.21.0 : `/enforcement`, `/enforcement/mode`, `/decisions`, rollback audite. CrowdSec retire du plan (consigne : sbxwaf le remplace). Reste : phases 2 a 6 ; vue « Radar des acteurs ».

## 2026-10-11 — WAF : leurres, campagnes et acteurs suivis deviennent des bans (ref #2238)

toolbox-ng 0.6.0 + waf-ng 1.20.0 : `--leurre-ban` (1 h / 24 h / 7 j), `--campagne-ban auto` (haute valeur, preuve par adresse), `--actor-ban auto`. NON deploye : redemarrage de secubox-waf-ng a annoncer. Surveiller `actor-ban-etat.json` et `campagne-ban-etat.json` apres activation.

## 2026-10-11 — Admin SBXOS : les six espaces deviennent la navigation par defaut (ref #2212)

secubox-hub 1.9.51, apres validation du proprietaire (« 2 ok »). Retour: `?nav=categories`. Reste: nettoyage des anciennes entrees apres un delai d'usage ; #2212 reste ouverte jusque-la.

## 2026-10-11 — Admin SBXOS : type, materiel et OS detailles par appareil (ref #2212)

secubox-hub 1.9.50 : le regroupement par type (1.9.49) etait un contresens, retire. L'OS est deduit (nom + DNS) avec preuve ; detection native cote NAC non faite.

## 2026-10-11 — Admin SBXOS : appareils regroupes par MAC, type et materiel (ref #2212)

secubox-hub 1.9.49. OS : non detecte par le NAC (aucun champ) ; piste : empreinte DHCP/TTL/User-Agent cote NAC, a decider.

## 2026-10-11 — Admin SBXOS : les conteneurs LXC ne sont plus des appareils (ref #2212)

secubox-hub 1.9.48 : `/appareil/` masque les entrees NAC de br-lxc (10.100.0.0/16) et d'OUI 00:16:3e. Le NAC lui-meme les stocke encore (a revoir cote collecteur si on veut les exclure a la source).

## 2026-10-11 — Admin SBXOS : flux deduits du DNS sur la fiche appareil (ref #2212)

secubox-hub 1.9.47 : fiche `/appareil/#mac` + flux DNS (ad-guard `/flux`), sans DPI ni volumes. La jointure DPI par octets n'est pas faite : sbxdpi ne donne que des paires IP, pas de total par appareil.

## 2026-10-11 — Admin SBXOS : deploiement gk2 et entree « acces » (ref #2212)

secubox-hub 1.9.45 installe sur gk2 (1.9.39 -> 1.9.45), agregateur redemarre une fois ; menu : 6 espaces + 1 orphelin « acces » (menu genere par secubox-auth) classe en 1.9.46. Essai : `?nav=espaces`, pages /apercu/, /espace/#id, /appareil/.

## 2026-10-10 — Admin SBXOS : pages d'espace et d'appareil (ref #2212)

secubox-hub 1.9.45 : `/espace/#id` (services + etat) et `/appareil/` (liste + fiche NAC). Reste : jointure DNS (ad-guard) et DPI sur la fiche appareil, validation par le proprietaire, bascule du defaut, nettoyage.

## 2026-10-10 — Admin SBXOS : recherche globale (ref #2212)

secubox-hub 1.9.44 : champ de recherche dans la vue par espaces (sans casse ni accents). Le panneau de notifications reste porte par la section Alertes de la Vue d'ensemble (pas de requete supplementaire sur chaque page). Suite : pages d'espace, fiches appareil/service.

## 2026-10-10 — Admin SBXOS : page Vue d'ensemble (ref #2212)

secubox-hub 1.9.43 : page `/apercu/` branchee sur `/api/v1/hub/apercu`, entree de menu dans l'espace Vue d'ensemble. Suite : recherche globale, notifications, pages d'espace, fiches appareil/service.

## 2026-10-10 — Admin SBXOS : API de la Vue d'ensemble (ref #2212)

secubox-hub 1.9.42 : `GET /api/v1/hub/apercu`, agregat des caches (pas d'apt/systemctl), `api/apercu.py` pur. Suite : la page web qui l'affiche, puis recherche et notifications.

## 2026-10-10 — Admin SBXOS : navigation a six espaces derriere un drapeau (ref #2212)

secubox-hub 1.9.41 : sidebar.js v2.42.0, `?nav=espaces` / `?nav=categories`, choix memorise, defaut inchange. Suite : page Vue d'ensemble, recherche, fiches appareil/service, bascule du defaut apres validation.

## 2026-10-10 — Admin SBXOS : audit, matrice et table des six espaces (ref #2212)

Audit (docs/SBXOS_ADMIN_UI_AUDIT.md) et matrice de migration générée (docs/SBXOS_ADMIN_UI_MAP.md, scripts/generate-admin-ui-map.py) : 125 entrées de menu rattachées à 6 espaces et 9 objets centraux, aucune route supprimée. hub 1.9.40 : `espaces.json` et champ `espaces` dans /api/v1/hub/public/menu, compatibilité conservée. Prochaine étape : navigation à 6 espaces dans sidebar.js derrière un drapeau.

## 2026-10-10 — Auto-Load : rapport final, écran et courrier (ref #2192)

secubox-autoload 0.5.0 / autoload-agent 0.5.0 : rapport sans secret construit par la box (écran + diffusion par le tunnel), validé strictement et conservé par l'infrastructure, envoyé par courrier au client si son contact est renseigné (adresse validée contre l'injection d'en-tête, relais configurable dans /etc/secubox/autoload.toml, panne SMTP sans effet sur la box). WebUI : courriel du client et onglet Rapports. Reste à faire côté exploitant : poser /etc/secubox/autoload.toml sur gk2 pour activer le courrier.

## 2026-10-10 — Auto-Load : WebUI d'administration (ref #2191)

secubox-autoload 0.4.0 : page `/autoload/` (hybrid-dark) avec box en provisioning (statut, progression), génération du jeton (valeur montrée une seule fois) avec durée d'abonnement et profil, révocation/suspension/réactivation confirmées, pré-rapports (détail, refus). 11 tests navigateur. Les « modules inclus » du schéma de principe restent à porter.
## 2026-10-10 — Auto-Load : banc de bout en bout sans matériel (ref #2193)

Huit scénarios réunissent moteur, client, service d'enrôlement (public et tunnel), jetons, fichier signé (vrai gpg) et vraies clés WireGuard (`packages/secubox-autoload/tests/test_banc_2193.py`). Restent hors banc : l'essai sur matériel (#2186, netboot), le démarrage automatique au boot (une unité root : à décider), la redirection udp/51830 de la Freebox, la WebUI (#2191) et le rapport final (#2192).

## 2026-10-10 — Auto-Load : service d'enrôlement et panel côté infrastructure (ref #2190, ref #2182)

secubox-autoload 0.3.0 : deux applications (publique sur socket Unix : POST /enrol à preuve de jeton + administration ; tunnel sur 10.64.0.1:8470 : progression, pré-rapport, refus ; identité = adresse source dans WireGuard), registre étendu (jeton `gk2_`, échéance et formule d'abonnement, statut et progression des box, pré-rapports), unités durcies application du tunnel par sudoers à argv exact (aucune nouvelle unité root), AppArmor enforce, nginx, nftables. À déployer sur gk2 ; la redirection udp/51830 de la Freebox est à faire à la main. Suite : #2191 (WebUI), #2192 (rapport final), #2193 (banc de bout en bout) ; #2186 (netboot) attend le matériel.

## 2026-10-10 — actord : les robots connus sont classés à part (ref #2201)

meta-externalagent (2 743 adresses, 65 pays) était l'acteur critique n°1 alors qu'il ne fait que parcourir git.gk2. toolbox-ng 0.5.9 / waf-ng 1.19.3 : un accès de robot annoncé refusé par la politique du vhost (étiquette unique `robots`, sévérité basse, non bloqué, famille nommée) ne crée plus d'acteur ; il est compté par famille (`GET /robots`, champ `robots` de l'aperçu) et la page Actor affiche une tuile dédiée. Dès qu'un robot sort de ce rôle, ses événements redeviennent ordinaires. À déployer : redémarrage de `secubox-actord` (puis page waf-ng).

## 2026-10-10 — WAF : l'auto-test sort des statistiques et des scores (ref #2200, ref #2201, ref #2202)

Constat sur gk2 : actord est en shadow (aucun ban par la détection d'acteurs) ; les bans viennent de sbxwaf (nftables, 4 h) et tiennent (28 adresses réelles bannies en 24 h, aucune revue pendant son ban). L'auto-test de health-doctor (198.51.100.77) gonflait les chiffres : 572 des 5 073 « banned ». toolbox-ng 0.5.8 : il va dans `waf-selftest.log`, ni dans `waf-threats.log` ni vers actord. À déployer : sbxwaf redémarre (reload = restart). Suite : #2201 (robots connus classés à part), #2202 (étude de l'application des propositions d'actord).

## 2026-10-09 — Fermeture de #2146 (profils) et de #2050 (suite en #2180) : closes #2146, closes #2050

#2146 : profils lite/isp/full livrés, release alpha.10 publiée, paquets de profils 1.0.42 dans l'index trixie ; l'essai ESPRESSObin est suivi en #2177. #2050 : vagues 0, 2, 3, 4 faites, 60 transitoires retirés des sources (PR #2179) et de l'index apt trixie, profils 1.0.42 publiés avant le retrait. Le reste (outillage vague 1, écrivains concurrents, méta-paquets en vues, code mort /check, WireGuard/Reality, surf encore en root) est repris dans #2180.

## 2026-10-09 — Vague 5 (#2050) : retrait des 60 paquets transitoires (ref #2050, ref #2146)

Les 60 répertoires `packages/secubox-*` dont la section est `oldlibs` (publiés un cycle dans alpha.10) sont retirés des sources ; `gabriel-mood` (source mixte `sbxos-audio-mood`) est conservé. Références réparées : liste « hors-arbre » de `arbre.yaml`, profil `secubox-profils` 1.0.42, liste `AvailablePackages` du CLI Go, `profiles/tier-standard.yaml`, source de `scripts/sync-sbxui.sh`, chemins des unités devwatch/freeboxtv dans `test_sockets_chmod_2026.py`. Tests de transition (transitoire vide, postinst du transitoire) remplacés par « le répertoire n'existe plus ». Les absorbants gardent `Replaces`/`Breaks`. Une box encore sur l'ancien module doit d'abord passer par alpha.10.

## 2026-10-09 — Dépôt apt : clé de signature déjà déverrouillée par l'unité du niveau 0 : closes #2007 (ref #1366)

La demande de #2007 (charger la phrase de la clé au démarrage) est couverte depuis 2026-10-03 par `secubox-depot-deverrouille.service` (#1366, phrase aléatoire systemd-creds, aucune phrase humaine). Constaté et utilisé le 2026-10-09 : `systemctl restart secubox-depot-deverrouille.service` rétablit la signature, `reprepro export` re-signe les huit suites, ad-guard 1.8.0, acces 1.7.1, oidc 0.1.3, sbxid 0.4.20 et users 1.8.18 publiés dans trixie. Ne JAMAIS préparer la clé à la main (`gpg-preset-passphrase`) : une valeur fausse écrase la bonne en cache.

## 2026-10-09 — ad-guard 1.8.0 : panneau TV simplifié, mode auto par défaut : closes #2174

Une page : état en une phrase, une carte et un interrupteur par appareil (auto en interne), liste « une pub passe encore ? » (Bloquer / C'est légitime), anciens onglets et modes observe/block/off sous « Avancé ». Après chaque bascule le drop-in Unbound est relu : le panneau dit si le changement est appliqué ou ce qui diverge. Déployé gk2 (dpkg + redémarrage de l'agrégateur, routes 401 puis état réel cohérent). Reste : validation visuelle par le propriétaire, index apt à republier (clé verrouillée). Validé par le propriétaire le 2026-10-09.

## 2026-10-09 — Profils, fuite mémoire de gk2, fermetures vérifiées : closes #1986, closes #2024, closes #2028, closes #2032, closes #2034, closes #2037, closes #2039, closes #2042, closes #2045, closes #2047 (ref #2146, ref #2050)
- **Fermetures** : dix issues, après audit en lecture seule (correctif fusionné ET version déployée sur la box concernée, vérifiée par `dpkg -l`, unités et configuration). Laissées ouvertes malgré un correctif déployé : #2021 (le 502 au démarrage de gk3 n'est confirmé que par un redémarrage), #1978 (le panneau n'a pas été vu, seulement ses sources de données), #2030 (test réel du micro dans un navigateur), #2026 (`secubox-zia` 0.1.25 non déployé).
- **Profils (#2146)** : lite = tous les modules de protection (+ routes, qos, freebox, certs, tor) ; isp = lite + modem, exposition, maillage et tout l'hébergement (courrier, Matrix, visio, Nextcloud, photos, Gitea, sites, BBS, billets, actualités) ; full = isp + le Hall et tout son contenu (médias, domotique, IA, assistant). Un module n'est que dans un profil (test), `secubox-full` s'installe sur amd64. `secubox-lite` 1.5.0, `secubox-isp` 1.3.1, `secubox-full` 1.5.0.
- **gk2 saturée (#2146)** : deux boucles nées vers 6 h 40 — le watchdog Lyrion relançait LMS toutes les 2 min (141 fois en 3 h, scan permanent ; `secubox-lyrion` 1.6.20) et le réveil ClamAV échouait 37 fois en 3 min (deux blocs `lxc.net.0` ; `secubox-clamav` 0.1.3). 4,2 Go de mémoire noyau non récupérable s'étaient accumulés ; un redémarrage les a ramenés à 123 Mo (hypothèse : fuite par `lxc-start` en échec). ClamAV mis de côté sur gk2 (module Rspamd retiré, mandataire masqué, LXC conservé). `sbx-actord` : `/stats` et `/overview` en double tampon (`secubox-waf-ng` 1.19.1). Registre du Hall : un `menu.json` absent ne le vide plus (`secubox-webos` 1.5.10).
- **Suivi mémoire permanent** : `secubox-metrics` 1.17.0, un relevé toutes les 5 minutes (`/var/lib/secubox/metrics/memoire.jsonl`), route `/api/v1/metrics/memory/history`, alerte sur seuil et sur croissance du noyau.
- **Rapport WAF quotidien** : carte du monde et vue d'ensemble de la box dans le PDF (`secubox-metrics` 1.16).
- **#2050** : services onion dans `torrc.d`, un fichier par service (`secubox-haproxy` 1.10.2, PR #2158) ; liste de l'issue remise à jour. `nftables.conf` : décision de ne pas toucher (propriétaire : `secubox-hardening`).
- **Blocage connu** : la publication apt de `secubox-metrics` 1.17.0 et des correctifs de carte (`soc` 1.1.9, `webos` 1.5.12, `waf-ng` 1.19.2) attend le déverrouillage de la clé de signature (`reprepro export`).

## 2026-10-08 — gk3 rattrapé (192.168.1.9) (ref #2050)
74 paquets mis à jour sur gk3 (amd64) par groupes avec relevé avant/après des unités actives et en échec : core → N2 → 3r → DNS → Hall/appstore/webos/soc/ipv6guard → surf/mesh/mail → WAF (waf-ng 1.19.0 et radio 0.1.78 d'abord construits pour amd64 : le dépôt n'avait que 1.18.13/0.1.77, et mettre à jour `waf` seul aurait retiré l'API du WAF sans remplaçant) → radio → 48 méta-paquets. Résultat : hall/admin/dashboard WAF à 200, Unbound sans redémarrage (uptime continu), bans nft et sudoers WAF intacts, `surf` en socket (port 9082 fermé), seule unité disparue `vortex-dns` (retrait voulu), apparues `dns` et `dns-provider` (la veille automatique les rendormira). Effets de bord corrigés : `ksm`, `dns-guard`, `mesh` remis arrêtés et désactivés comme avant. Non installés volontairement : haproxy 1.10.1 et interceptor 1.1.2. `secubox-vault` non touché.

## 2026-10-08 — S7 : waf-ng absorbe waf, déployé sur gk2 (ref #2050)
Paquets seulement : `waf-ng` 1.19.0 absorbe `waf` (API Python, tableau de bord, wafctl, sudoers, logrotate) ; **deux processus, deux comptes, deux unités conservés** (sbxwaf/`secubox-waf-ng`, API/`secubox-waf`) ; `waf` 1.10.44 devient vide. Aucune collision de fichiers (vérifié sur les listes de gk2). Déploiement contrôlé en une seule transaction apt (waf-ng + waf + appstore) avec relevé avant/après : unités actives, ligne de commande de `sbxwaf` identique (upstream-timeout 1h, actor-ban propose, honeypot), 145 bans nft intacts, deux sudoers WAF présents, tableau de bord admin/WAF/Hall à 200, wafctl possédé par waf-ng. appstore 0.5.6 : `waf` retiré du groupe « bouclier » (un contrôle manqué de ma part, attrapé par la CI avant la fusion). **Voie de ban dupliquée** : le ban automatique de l'API Python n'existe que dans `POST /check` (JWT), sans aucun appelant (dépôt, journaux d'accès) ; c'est du code mort à retirer dans une issue séparée.

## 2026-10-08 — D3/D4 : un seul moteur DNS (Unbound), bibliothèque commune, vortex-dns retiré (ref #2050)
**D4** : `secubox_unbound` (common/, livrée par secubox-core 1.7.0, stdlib seulement, sans effet de bord à l'import car le `__init__` de `secubox_core` tire FastAPI et la config) pose une vue Unbound, la vérifie (`unbound-checkconf`), recharge et revient en arrière octet pour octet ; écriture atomique qui refuse les liens symboliques ; redémarrage dans une sous-classe réservée à dns-lan. `webfilter-ctl` (0.2.4) et `dns-lan` (dns 1.3.1) l'utilisent à la place de leurs deux copies ; webfilter n'a toujours pas la capacité de redémarrer Unbound (test passé de « lire le source » à « vérifier le comportement »). Vérifié sur gk2 : un passage complet de `secubox-webfilter-apply` (427 312 zones, 74 s) via la bibliothèque, uptime d'Unbound continu, résolution OK, audit écrit. **D4 terminé** (core 1.7.1, ad-guard 1.7.2) : `ad-guard` TV et adblock aussi. `secubox-adblock-sync` n'écrivait pas de façon atomique et, sur un échec de rechargement, enchaînait sur `systemctl restart unbound` (coupure possible de la résolution du réseau) : remplacé par écriture atomique + retour arrière + rechargement de l'ancienne vue, jamais de redémarrage. Vérifié sur gk2 : sync complet (657 780 domaines, rechargement, uptime d'Unbound continu, résolution OK), `adguard-tv status` valide. **M9 abandonné** (décision du propriétaire : les vendors de radio et metanews sont identiques mais socialrelay diffère, git déduplique déjà ; gain faible, risque réel).
**D3** : dns-guard 1.3.0 n'écrit plus /etc/dnsmasq.d (échouait déjà en silence : service sous `secubox`) ; POST /sync dit « aucun_moteur ». **vortex-dns retiré** (décision du propriétaire) : actif mais jamais branché (aucun RPZ, dossiers vides) ; paquet vide 1.1.4, unité arrêtée et désactivée, retiré du catalogue, de l'arbre des méta-paquets et des routes du hub. Effet de bord corrigé : l'installation a activé dns-guard (arrêté avant) ; remis à inactive/disabled. 55 .deb publiés.

## 2026-10-08 — Freebox, IPv6 Guardian, Actor Intelligence, radio, N2 (ref #2050, #1070)
**surf 1.0.32 et mesh 2.0.8** : socket Unix `/run/secubox/<m>.sock` à la place des ports TCP 9082 et 8743 (fin de la dernière exception à la règle). surf déployé sur gk2 : un même appel du vhost `surf-*` rend 200 avant et après, le port 9082 est fermé, la socket est en 660 root:secubox ; son postinst redémarre le service AVANT de recharger nginx (sinon 502). mesh publié dans apt mais non installé sur gk2 (arrêté ; son postinst le démarrerait). `surf` tourne toujours en root (pas de `User=`) : dette notée.
**secubox-freebox 0.3.0** (nouveau) : connecteur Freebox OS (autorisation validée sur la Freebox, jeton 0600 jamais renvoyé), lecture appareils/connexion/pare-feu IPv6/redirections/UPnP, réglage du pare-feu IPv6 et de l'UPnP (admin, confirmation, droit « settings », relecture, audit), panneau `/freebox/`. Constat : pare-feu IPv6 désactivé au départ (le propriétaire l'a activé), accès distant Freebox actif, UPnP actif sans port ouvert. **ipv6guard 0.2.1** lit ce pare-feu (verdict « exposé » / « pare-feu actif, à confirmer » : l'API v9 ne publie pas les exceptions IPv6).
**Actor Intelligence** : ingestion muette depuis le 5/10 (le script de droits de la socket n'attendait que 12 s, actord met ~4 min à ouvrir sa socket) corrigée (waf-ng 1.18.14) ; ban automatique piloté par actord livré en **mode propose** (waf-ng 1.18.15+, aucun acteur ne atteint DENY) ; `/overview` (pays, événements, activité 24 h, techniques) en cache 30 s (1.18.18) ; carte Hall refaite façon maquette (webos 1.5.3→1.5.6), carte du monde en points Natural Earth. **Piège** : le drop-in du leurre recopiait ExecStart de sbxwaf et masquait tout changement de l'unité (timeout 1 h, skip-body, actor-ban) → modèle remis en miroir + test (1.18.17).
**Radio 0.1.78** : « moins souvent » (geste sysop, poids ×0,08, jamais zéro), probabilité de tirage affichée, appel à `rendProbas` inexistant supprimé. **waf 1.10.43** : badge d'état réel (plus de « en écoute » figé), carte du monde, efficacité repliée. **soc 1.1.8** : fond de continents sur la carte. **webos** : bulle des diffusions au clic (plus de survol).
**N2 (vague 3q) et 3r** : system absorbe system-hub, admin, ksm, system-tuning ; cdn absorbe mirror ; qos absorbe nettweak. Déployés sur gk2 (9 paquets, 7 /health à 200, rien en échec de nouveau) et 64 .deb publiés dans apt. `secubox-ksm` était inactif avant et est actif après (règle des transitoires : l'unité existante est remise en route). gk3 non fait.

## 2026-10-07 — Rassemblement, vague 3n : annuaire←openpgp, p2p←meshname (R5) ; déployée gk3 + gk2, publiée (ref #2050)
annuaire 0.11.0 absorbe openpgp : son `dh_installsystemd` est restreint à ses propres unités (l'unité openpgp reste gérée par son postinst : clé et liaison AVANT le démarrage) et l'utilisateur dédié `secubox-openpgp` est conservé. p2p 1.12.0 absorbe meshname. Contrôles avant/après sur les deux nœuds : empreinte de `node.key` identique (gk3 d59bee65…, gk2 2b05e2e5…), mêmes droits, dossier openpgp intact, annuaire/openpgp/p2p actifs, wg-mesh inchangé. Tests : openpgp 23 verts (conftest repointé), p2p 184 verts, annuaire 443 verts / 15 en échec identiques avant la fusion. isp 1.2.10, profils 1.0.36, meta 0.1.36, vault 2.1.5. meshname, inactif avant, est démarré par son postinst rejoué.

## 2026-10-08 — Rassemblement, vague 3p : security-posture←cve-triage,antirootkit (S6) ; déployée gk3 + gk2, publiée (ref #2050)
Packaging seul. security-posture 2.2.0 absorbe cve-triage et antirootkit : 5 unités gérées une fois, utilisateur dédié `secubox-antirootkit`, sudoers, règles d'audit et table nft anti-évasion conservés (comparés sur build local, aucune perte). Après déploiement : cve-triage, inactif avant, est démarré par son postinst rejoué ; la table nft `secubox_antiescape` (confinement du tranche `sbx-untrusted`) est chargée par le postinst d'antirootkit, comme à chaque mise à jour. Outil : sources `$(CURDIR)/<dir>` suivies, `debian/compat` retiré des transitoires (dh refusait compat + debhelper-compat), test de garde. Carte « Cloud » vivante (webos 1.3.0) et cartes en double corrigées (1.2.4) déployées. Compte actuel : 112 paquets actifs, 52 transitoires, 57 méta-paquets.

## 2026-10-07 — Incidents du jour et flux YouTube : coffre, Lyrion, PeerTube, nginx, I1 déployé (ref #2050)
**Coffre scellé puis impossible à rouvrir** : ma vague 3n a réinstallé `secubox-vault` (changement de dépendance) → redémarrage → coffre re-scellé (clé en mémoire). À la reconnexion, ouverture refusée : `Permission denied` sur `/var/log/secubox/coffre.journal`, resté au propriétaire `secubox` d'avant le compte `secubox-coffre`. vault 2.1.6 : le postinst remet le journal à `secubox-coffre:secubox` 0640 (contenu chaîné jamais touché). Leçon : exclure vault des lots de déploiement (mémoire `feedback_vault_redeploy_reseals`).
**Services en 226/NAMESPACE dans les LXC** (AppArmor, depuis le redémarrage du 2026-10-05) : redis de PeerTube (500), apache2 du webmail (502), redis du courrier. Nouvelle commande partagée `secubox-lxc-sans-sandbox <conteneur> <service>…` (core 1.6.1, tests) ; `mailctl webmail` (mail 2.14.0) ; redis de PeerTube relancé avec elle. **Lyrion** arrêté depuis le même redémarrage (`lxc.start.auto = 0`) : relancé à la main, 502 levé.
**I1 déployé** (auth←users,sbxid,oidc, sbxos aurora15) sur gk3 et gk2, hors vault. gk2 : `users.json` identique (3 comptes, 2FA intacte, propriétaire root:secubox par design) ; gk3 : le postinst d'`users` a créé un compte administrateur `gk3` sans mot de passe (graine « admin + nom d'hôte »), à supprimer ou à doter d'un mot de passe par le propriétaire.
**Flux YouTube** : ytsas 0.4.0 (+0.4.1) et carte du Hall (webos 1.2.x) : listes du compte avec les cookies du coffre, lecture seule, route Hall authentifiée. Erreur de ma part : `location` regex à accolades sans guillemets → `nginx -t` en échec sur gk2 (corrigé, webos 1.2.1, test de garde). Cartes dynamiques (`si_present`) : VoiceStudio absent de gk2 ne s'affiche plus. Carte Activité : diffusions de la bibliothèque ytsas cliquables (1.2.2). Catalogue appstore 0.5.3.

## 2026-10-07 — Action live gk2 : publication du site metablogizer « all » (demande du propriétaire)
`all.gk2.secubox.in` et son alias `all.gk2.net` répondaient 404 : `published: false` dans `site.json` depuis le 21 août, donc aucun bloc nginx (#1322). La voie officielle (API du publieur) demande un jeton admin ; la même opération a été faite en root par les fonctions du paquet : `published` mis à vrai (écriture atomique, copie avant : `/root/site-all.json.avant-publication` sur gk2), puis `regenerate_nginx_config()` (aide root `metablog-nginx` : installe, teste, recharge). Résultat : 200 sur les deux noms, `nginx -t` valide, 163 sites émis. Le vault n'a pas été touché. Alias de « 3d » et « all » non émis comme blocs séparés : « déjà pris » par le bloc principal, attendu.

## 2026-10-07 — Rassemblement, vague 3m : haproxy←vhost,exposure (R1) ; déployée gk3 + gk2, publiée (ref #2050)
haproxy 1.10.0 absorbe vhost et exposure : contenus comparés sur build local (aucune perte), chaque unité gérée une fois, deux unités conservées (exposure reste en root, le registre des unités root pointe sur haproxy). Frontal vérifié avant/après sur les deux boxes : hall, admin et webmail inchangés, `haproxy -c` identique. Tests des composants repointés (exposure 74 verts) ; la suite vhost ne se collecte pas sans /etc/secubox/secubox.conf lisible (déjà le cas avant). isp 1.2.9, profils 1.0.35, meta 0.1.35.

## 2026-10-07 — Rassemblement, vague 3l : ipblock←vortex-firewall,cyberfeed (S3) ; déployée gk3 + gk2, publiée (ref #2050)
Packaging seul : les tables nft restent distinctes (une table unique = L, déconseillé avant la bêta). ipblock 1.3.0 ; threatmesh 1.0.4 (dépendance `ipblock | toolbox`, alternative conservée). Outil : une alternative de dépendance (`a | b`) n'est plus remplacée en bloc, seule la branche concernée change. isp 1.2.8, lite 1.3.6, profils 1.0.34, meta 0.1.34. ipblock et cyberfeed, inactifs avant, sont démarrés par leurs postinst rejoués (API de tableau de bord, aucune règle nft chargée).

## 2026-10-07 — Courrier : rapport WAF (421 / timed out) et webmail en 502 ; metrics 1.15.1, mail 2.14.0 déployés gk2, publiés
Rapport WAF : le scan antivirus attend le réveil à froid du LXC `clamav` (jusqu'à ~120 s, `rspamd_task_timeout`), le job coupait à 20 s (« Connection unexpectedly closed: timed out ») alors que le courrier arrivait : délai de 200 s (metrics 1.15.1). Politique du scan inchangée (décision du propriétaire : rien ne passe sans scan). Webmail 502 : apache2 en 226/NAMESPACE dans le LXC roundcube depuis le 5 octobre (AppArmor refuse le montage du bac à sable systemd) → `mailctl webmail` (mail 2.14.0) pose la surcharge et démarre Apache ; webmail.gk2 répond 200. `mail.gk2.secubox.in` répond 421 par conception : le vhost du courrier est `email.gk2.secubox.in`.

## 2026-10-07 — Rassemblement, vague 3k : tor←proxypac,macro ; déployée gk3 + gk2, publiée (ref #2050)
tor 1.4.0 absorbe proxypac (PAC, minuterie et chemin de régénération, sudoers) et macro (assistant `macroctl`, sudoers, profil AppArmor) ; listes de fichiers comparées sur build local, aucune perte. Outil : une source `debian/secubox-<ancien>.sudoers` n'est plus réécrite comme dossier de destination. Tests proxypac repointés vers le control/rules de tor. profils 1.0.33, meta 0.1.33. proxypac, inactif sur gk2 avant, y est démarré par le postinst d'origine rejoué.

## 2026-10-07 — Rassemblement, vague 3j : routes←netdiag ; déployée gk3 + gk2, publiée (ref #2050)
Deux unités conservées dans un seul paquet : `routes` (secubox) et `netdiag` (root, sockets bruts), le registre des unités root pointe maintenant sur routes. isp : reste de `traffic` (vague 3a) retiré. Versions : routes 1.3.0, isp 1.2.7, profils 1.0.32, meta 0.1.32.

## 2026-10-07 — Rassemblement, vague 3i : metanews←devwatch,yacy ; déployée gk3 + gk2, publiée (ref #2050)
metanews 0.3.0 (arch any, amd64 + arm64) absorbe devwatch et yacy ; son `dh_installsystemd --name=` est complété pour yacy, devwatch active toujours la sienne dans son postinst (masquage respecté). surf reste séparé : écoute en TCP 127.0.0.1:9082, le passage en socket Unix demande de changer ses consommateurs. Versions : meta 0.1.31, full 1.4.8, profils 1.0.31.

## 2026-10-07 — Rassemblement, vague 3h : dpi←ndpid,mediaflow ; défauts de CI et de dpi corrigés ; déployés gk3 + gk2, publiés (ref #2050)
dpi 1.7.x absorbe ndpid et mediaflow (dpi reste arch any : amd64 + arm64). Outil : nom des unités nommées (`<paquet>.<nom>.service` → `<nom>.service`), motif `\b` qui retirait aussi `ndpid-engine` de l'arbre, conftest et bats des composants repointés. CI : la détection « arch all » prenait un commentaire de `debian/control` pour une architecture (arm64 sauté) → expression ancrée ; suite publish et catalogue appstore (0.5.2, groupe publication) réparés, test de génération du catalogue ajouté. Défaut ancien trouvé sur gk3 : l'API dpi bouclait sur « unable to open database file » (16 620 fois depuis au moins le 5 octobre), le répertoire d'état appartenant à root ; base d'ingestion déplacée dans `/var/lib/secubox/dpi-ingest` (secubox), ancienne base migrée par le postinst (dpi 1.7.2). Pannes sans lien : peertube-backlog (délai dépassé) sur gk2.

## 2026-10-07 — Rassemblement, vague 3g : metrics←grafana ; transitoires qui remettent l'unité en route ; déployés gk3 + gk2, publiés (ref #2050)
grafana arrêté à la mise à jour par l'ancien `prerm` et jamais relancé (gk2) : les transitoires grafana, reporter, smtp-relay, traffic et zigbee (dont l'ancien prerm arrêtait l'unité sur `upgrade`) portent maintenant un `postinst` qui la rétablit sauf si masquée ; l'outil l'écrit pour les prochaines fusions, test de garde ajouté. iot-guard était déjà un transitoire vers nac : rien à absorber (I5 sans objet). Versions : metrics 1.15.0, meta 0.1.29, profils 1.0.29.

## 2026-10-07 — Rassemblement, vagues 3e et 3f : mail←smtp-relay, metablogizer←droplet,publish ; déployées gk3 + gk2, publiées (ref #2050)
Unités vérifiées sur build local : dh détecte déjà les unités installées dans l'arbre, un `dh_installsystemd --name=` en plus les déclare deux fois (retiré de media 1.8.1). L'unité smtp-relay bouclait en 226/NAMESPACE (`ReadWritePaths` sur `/var/log/mail.log`, absent de l'hôte car le courrier est dans le LXC) : préfixe `-`, mail 2.13.1. Dépendants full 1.4.6, isp 1.2.5, profils 1.0.28, meta 0.1.28. CI : suite publish déplacée.

## 2026-10-06 (nuit) — Rassemblement, vagues 3c et 3d : media←freeboxtv, repo←release, jitsi←turn ; déployées gk3 + gk2, publiées (ref #2050)
Overrides `dh_installsystemd` fusionnés à la main et vérifiés sur un build local (une seule gestion par unité). `absorber-paquet` sait désormais absorber un paquet installé par `debian/<paquet>.install`. Constats corrigés au passage : la CI échouait sur trois suites déplacées (metacatalog, zigbee, defaults) → chemins mis à jour ; appstore 0.5.1 (groupes du catalogue citaient smb et zigbee, la construction cassait) ; test périmé de l'unité release (RuntimeDirectory retiré, #1022) ; mediactl ancrait sur un commentaire. README : « environ 135 paquets + 57 méta-paquets » (chiffres comptés). Méta : meta 0.1.27, full 1.4.5, profils 1.0.27. Reste le contrôle d'en-têtes de licence (dizaines de fichiers `.claude/`, ancien).

## 2026-10-06 (nuit) — Rassemblement, vague 3b : ytsas absorbe torrent, déployé gk3 + gk2, publié (ref #2050)
Première fusion à `override_dh_installsystemd` : les minuteries `conserve` des deux paquets sont déclarées ensemble dans ytsas 0.3.0 ; torrent 2.4.10 devient transitoire. Tests de torrent repointés vers le composant (14 pytest + 17 bats verts), dépendants `full`, `profils`, `meta` mis à jour avec montée de version (meta 0.1.25, profils 1.0.26). Constat sans lien avec la fusion : l'actuateur de profils (`profilectl apply`) a ramené ai-gateway, glances et mcp-server à l'état du profil de gk2 (désactivés) après leur activation par les postinst ; mcp-server plante en boucle sur gk2 quand on l'active (`/tmp/secubox` appartient à root), il l'était déjà avant la vague.

## 2026-10-06 (nuit) — Rassemblement, vague 3a : 9 fusions déployées gk3 + gk2 et publiées (ref #2050)
qos←traffic, streamlit←streamforge, media←smb, mqtt←zigbee, backup←cloner, metrics←glances,reporter, ai-gateway←localrecall,mcp-server (outil `absorber-paquet`, transitoires vides). 20 paquets construits ; correctif du champ Depends de secubox-profils (commentaire deb822, PR #2079) et garde de forme des controls. Installation par apt sur gk3 puis gk2 (65 paquets, rc=0) : unités absorbées actives sous le nouveau propriétaire, zigbee reste masqué comme avant, Hall 200, DNS OK. Publié dans `trixie` (amd64+arm64) ; secubox-dns 1.3.0 déjà présent, contenu identique, gardé tel quel. Pannes restantes, sans lien : metrics-rapport-waf (envoi SMTP) et wg-quick@wg-mesh sur gk2.

## 2026-10-06 (soir) — Rassemblement, vague 2 terminée : outil `absorber-paquet`, 9 fusions, correctifs de panne (ref #2050)
`scripts/absorber-paquet.py` (patron du dossier §10 + `--comparer` du contenu des .deb) : **D1** dns←dns-provider,dns-lan, **D2** dns-guard←network-anomaly, **S4** threats←ai-insights, **N3** health←health-doctor,watchdog, **N5** webos←sbxui, **M2** matrix←jabber, **M8** appstore←metacatalog ; anciens paquets transitoires vides ; chaque fusion vérifiée par comparaison de contenu (a attrapé 4 unités `debian/<paquet>.service` oubliées). Écartées : M3 bbs←messagerie (dépendances de bbs volontairement minimales), I2 zkp (paquet C par architecture). Déployé gk3 puis gk2 par apt (27 paquets), publié `trixie`. Même jour, pannes réparées : webfilter-apply (chmod refusé par AppArmor + profil sans nameservice, 0.2.3), metrics (python3-fpdf sur Debian 13), mail 2.12.5 (redis du conteneur : bac à sable systemd refusé par AppArmor, rootfs décalé à moitié sur gk3 — 12 975 entrées —, resolv.conf du conteneur), core 1.5.58 (vhost nginx 80/443 derrière HAProxy). **Reste** : rapport WAF (l'envoi du courriel expire encore), wg-quick@wg-mesh, relais-maillage sur gk3 ; soc-agent et soc-gateway livrent leur unité deux fois (/lib et /usr/lib) : non installables en usrmerge.

## 2026-10-06 — Cardlet « Éphéméride » du Hall : module secubox-ephemeride 0.1.0 + webos 1.0.405 (ref #2050)
Date, heure dans le fuseau de la box (horloge côté client, sans appel API), soleil (lever, coucher, durée, jour et nuit polaires), Lune (phase, illumination, lever/coucher, prochaine phase), saint du jour (366 jours, fichier d'administrateur prioritaire), météo et qualité de l'air (Open-Meteo, facultatives, cache, repli hors-ligne), observations (SQLite, écriture réservée à l'admin). Astronomie et calendrier calculés localement (`api/astro.py`, validé sur les 25 lunes de 2026 et le lever de Londres). Un composant, trois niveaux (compact, standard, étendu). Utilisateur dédié, durcissement complet. Déployé gk3 puis gk2, publié `trixie`. **À faire** : relire `data/saints.json` ; renseigner `[ephemeride.location]` (sinon repli sur la ville du fuseau, « approximatif ») ; wiki FR/EN et capture ajoutés.

## 2026-10-06 — Simplification des modules, vague 0 et début des vagues 1-2 (ref #2050)
Plan : `docs/dossiers/simplification-modules-beta.md`. **Vague 0** : routes dns en double, MSS par nftables (plus d'iptables) dans netmodes, Recommends de streamforge et zkp, unités root (garde-fou `test_unites_root_2050.py` + registre `docs/SECURITE-UNITES-ROOT.md`, 22 paquets), threatmesh durci, un seul propriétaire du qdisc racine (`secubox_core.qdisc`, qos et traffic), `secubox-hub` remis dans l'arbre, README profiles. **Vague 1** : clé `theme` dans les 127 `menu.d` (`scripts/generate-menu-theme.py`, test de dérive) et regroupement `themes` dans le menu du hub (1.9.38). **Vague 2** : S1 `mac-guard`/`device-intel`/`iot-guard` → `nac` 3.2.0 (transitoires ; pages 301, API 410), S2 `soc-web` supprimé, N1 `defaults` → `core` 1.6.0 et `groupd` → `aggregator` 0.4.0 (transitoires). Déployé sur gk3 puis gk2, publié dans la suite `trixie`. Pièges : `dpkg` ne retire pas un conffile obsolète (`rm_conffile`) ; `dpkg -i` refuse un `Breaks` si l'absorbant passe avant l'absorbé (apt ordonne) ; le postinst de core recréait la vhost nginx 80/443 derrière HAProxy (core 1.5.58). Les `menu.d` thémés ne sont livrés qu'avec le prochain build de chaque paquet.

## 2026-10-05 — Noyau stock Debian pour la MOCHAbin, WAN rétabli, défaut sur gk2 : closes #2004, closes #2011
Noyau `6.12.111-2secubox` (config Debian + fragment `config-6.12-stock-wan.fragment`) validé par le propriétaire sur gk2 (WAN, Hall, radio) et placé par défaut ; `secubox-5` (Image, initrd, entrée extlinux, DTB mpcie-fix) retiré de `/boot`. Cause du WAN absent : le commutateur DSA 88E6141, en module, arrivait après l'ouverture de eth2 par networkd ; mvpp2 rebasculait ses tampons, rouvrait les ports, et le PHY 88E1510 était rattaché deux fois sans jamais remonter. Correctif : BRIDGE, HSR, NET_DSA, tags DSA/EDSA et MV88E6XXX intégrés (HSR=m plafonnait NET_DSA à m ; PR #2014, #2015) ; liaison eth2 en 4 s, comme avec l'ancien noyau. Pièges : `/boot` en vfat, dpkg ne peut pas y faire de lien de sauvegarde pour un noyau de MÊME version (retirer `System.map-` et `config-` avant `dpkg -i`) ; l'étape `bindeb-pkg` finit en erreur mais le .deb image est complet (md5sums vérifiés). Replay (#2011) : coupures de pub bloquées sur Netflix et Free Ciné, validé par le propriétaire. Alpha 9 : `secubox-sentinelle-gsm` 0.4.6 en `Architecture: all` (introuvable pour `secubox-full` sur x64) et délai des Live USB arm64 porté à 240 min (PR #2016).

## 2026-10-04 — Validation par le propriétaire : closes #1959, closes #1960, closes #1963, closes #1965
Validés et déployés (ad-guard 1.6.2, dpi 1.5.0 arm64, dépôt apt à jour). Restes sortis en issues de suite pour ne rien perdre : #1973 (DPI : destinations vues par IP seule, table IP→nom d'après le cache d'Unbound, catalogue élargi) et #1974 (export des compteurs du toolbox vers ad-guard, dossier 0750 illisible). Essais du jour consignés : réponse `0.0.0.0` à la place de NXDOMAIN sans gain mesuré, NXDOMAIN conservé (#1969, fermée) ; autorisations de la seconde TV (imasdk.googleapis.com, licensing.bitmovin.com) ; règles RTL9 (ads-canalplus.akamaized.net, vizchoice.viznet.tv) à l'essai de 24 h sur les deux TV.

## 2026-10-05 — Migration en place vers Debian 13 (Trixie) validée sur gk3 et gk2 (ref #1996, ref #1997)
gk3 (amd64) puis gk2 (MOCHAbin) mis à jour de bookworm vers trixie en place (`full-upgrade`, 10 puis 45 min, aucun paquet SecuBox retiré), radio et Hall validés par le propriétaire. Pièges relevés et corrigés : `python3-python-multipart` (et non `python3-multipart`), venv billets recréé, interfaces renommées end0/end1 sans `net.ifnames=0` (gk2 démarre par extlinux, pas boot.scr), HAProxy 3.0 négocie h2 → réécriture d'URI en `%[pathq]` (`secubox-haproxy` 1.8.26, 421 sur tous les domaines publics sinon), surfer : `.onion` en http (`secubox-surf` 1.0.30), `secubox-geoipupdate` après Unbound. gk2 reste sur son noyau maison `secubox-5` (CFS_BANDWIDTH) : le noyau Debian stock ne donne pas de porteuse sur eth2 (cages SFP en attente du pca9554, pilotes I2C/SFP/PHYLINK en modules). Noyaux sans CFS_BANDWIDTH supprimés de /boot. `secubox-threat-analyst` supprimé (redondant). Debian 13 devient la base : suite par défaut `trixie`, tag v3.0.0-alpha.9, alpha 8 abandonnée.

## 2026-10-04 — secubox-webfilter 0.2.1, essai réel de blocage sur 192.168.1.3 et deux corrections (ref #1962)
Essai réel sur un appareil du LAN (blocage effectif, retour arrière vérifié, Unbound coupé ~10 s à l'application et ~7 s au retour). Deux défauts trouvés et corrigés : une catégorie en `block` sans liste synchronisée est maintenant refusée (« lancer une synchronisation des listes ») au lieu de ne rien bloquer ; la carte est relue dès que son fichier change (plus de retard jusqu'à 60 s) ; le postinst demande une synchronisation si aucune liste `.lst` n'existe après mise à jour. Déployé sur gk2 (PID d'Unbound inchangé), dépôt apt à jour. #1962 reste ouverte (P3 apprentissage/parking, P4 DPI).

## 2026-10-04 — secubox-webfilter 0.2.0, phase 2 : profils, appareils, blocage par vues d'Unbound (ref #1962)
Livré et déployé sur gk2 (0.2.0, dépôt apt à jour). Profils (observe ou block par catégorie, autorisations), appareils rattachés par adresse MAC avec exceptions, blocage par des vues
d'Unbound **partagées** (une vue par configuration effective distincte : mesure du jour, 227 000 zones = 90 Mo et 3 copies = 184 Mo, d'où l'abandon de l'option B ; un rechargement passe de
6,9 s à 9,4 s avec 312 000 zones de catégories en plus). Le réseau entier pointe vers `wf-defaut`, des `/32` et `/128` plus précis vers les vues des appareils assignés (vérifié sur Unbound
1.17.1) ; **les TV d'ad-guard gardent leur vue et sont exclues**. Contrôleur root `secubox-webfilter-ctl` déclenché par fichier (`appliquer.demande` + `.path`) et à 04:00, jamais par sudo :
dossier d'état ouvert sans suivre de lien et propriétaire vérifié, `config.json` plafonné et validé comme entrée hostile, budget de zones et d'octets, contrôle `unbound-checkconf`, rechargement,
retour arrière, audit dans `audit.log`. Aucun blocage configuré : aucun drop-in, aucun rechargement. Panneau : onglets Profils, Appareils, Appliquer, confirmations avant tout nouveau blocage.
Essai complet sur un Unbound jetable de gk2 (vrai contrôleur, vrai `unbound-checkconf`, vraies requêtes) : tablette bloquée, poste libre non, adresse d'ad-guard sans entrée, application identique sans
rechargement, contrôle refusé = ancien fichier conservé, plus aucun blocage = drop-in retiré. Relecture de sécurité finale (0 bloquant, 6 importants, 13 mineurs) : importants et promus corrigés avec test.
Déploiement : première application sans configuration = « inchange », Unbound intact (même PID), base migrée, routes publiques en 401 sans jeton. **Essai réel de blocage sur un appareil de gk2 : non fait**
(en attente de l'accord du propriétaire pour 3 à 4 coupures du DNS de 10 s). Restent : P3 (apprentissage, parking), P4 (association au DPI), mineurs différés du registre de relecture.

## 2026-10-04 — secubox-webfilter 0.1.0, phase 1 « observe » livrée et déployée sur gk2 (ref #1962)
Nouveau paquet `secubox-webfilter` (arch:all, dépôt apt à jour) : classement des requêtes DNS par catégorie (adulte, jeux d'argent, phishing/malware) à partir du
journal d'Unbound et de 4 listes publiques téléchargées à l'exécution (HaGeZi NSFW et gambling medium, Block List Project phishing, URLhaus), index compact (8 octets par
domaine), compteurs par jour/appareil/catégorie/entrée de liste sur 30 jours, API (`/etat` agrégé, `/stats` et domaines réservés à l'administrateur, `/sync`), panneau
`/webfilter/`. **Observe seulement : rien n'est bloqué, aucune zone écrite dans Unbound** (vérifié : même PID et même horodatage d'Unbound avant et après).
Essai technique d'Unbound fait avant d'écrire du code : les étiquettes ne se combinent pas avec les vues d'ad-guard et ne sont pas démontrées fiables ; option B retenue (profils par vue
d'ad-guard, phases suivantes). Relecture de sécurité finale (2 bloquants, 9 importants) : tout corrigé avec test (profil AppArmor sans registre des sessions, cardinalité non bornée des
compteurs, socket en 0666, base lisible par le groupe secubox, motif du journal incompatible avec `journalctl -o cat`, groupe systemd-journal donné à tout le compte, route nginx dans un dossier non lu, postrm absent…).
Vérifié sur gk2 : services actifs, socket en 0660, dossier d'état 0700, comptage réel (6 requêtes de test vers bet365.com = une ligne « jeux / bet365.com »), détail par appareil refusé sans jeton y compris par l'adresse publique.
**À savoir** : AppArmor n'existe pas dans le noyau de gk2 (seul `capability` est actif) : les profils sont livrés mais inertes sur cette box ; l'audit de synchronisation va au journal systemd
(`audit.log` est `secubox:secubox 0640`, un compte dédié n'y écrit pas ; arrivera en P2 avec un contrôleur root) ; `systemd-tmpfiles` signale un « unsafe path transition » bénin sous `/var/lib/secubox/webfilter` (le sous-dossier `listes` est créé par la synchronisation).
Restent (phases 2 à 4) : profils et appareils par MAC, exceptions, blocage par vue d'ad-guard, apprentissage, association au DPI. Mineurs différés : voir le registre de la relecture.

## 2026-10-04 — secubox-dns-lan : le DNS du LAN et l'IPv6 stable dans un paquet (ref #1938)
Livré et déployé sur gk2 : `secubox-dns-lan` 0.1.0 (arch:all, dépôt apt à jour). Quatre drop-ins Unbound (`96-secubox-lan`, `96-secubox-lan-ipv6`,
`96-secubox-gk2-local`, `98-secubox-voicestudio-lan`) et le fichier networkd de l'IPv6 `…::200`, jusque-là posés à la main, sont générés depuis
`/etc/secubox/dns-lan.toml` (modèle fourni, jamais appliqué d'office). `generate` pose, valide par `unbound-checkconf`, restaure si le contrôle
ou le rechargement échoue, et ne recharge Unbound que si la configuration effective change (redémarrage si une écoute nouvelle apparaît).
Relecture de sécurité faite (1 bloquant : identifiant de zone IPv6 permettant l'injection de directives ; 8 importants), tout corrigé avec test.
Essai sur gk2 : zéro écart, 5 fichiers réécrits, Unbound ni rechargé ni redémarré, DNS IPv4 et IPv6 inchangés, audit écrit. Reste de #1938
(réglage Freebox, certificat de gk3, plage DHCP) : non traité ici, l'issue reste ouverte. Hors périmètre, à ranger plus tard : `97-secubox-split-horizon.conf`
(redirection de `mail.secubox.in`) relève du paquet mail.

## 2026-10-03 — Page OpenPGP : chaîne d'ancêtres du cadre (ref #1852)
- `secubox-vault` 2.1.2. Premier essai avec une vraie session (capture et console de l'exploitant) : les boutons « Chiffrer » / « Signer » apparaissent dans la rédaction d'Elastic (greffon chargé) ; la page `pgp.<domaine>` était bloquée par sa CSP `frame-ancestors https://webmail…` car le webmail est lui-même dans le Hall et le navigateur vérifie TOUTE la chaîne. `coffre-pgp-vhost` reprend la liste que le webmail annonce (HAProxy, services cadrables) + le Hall ; origines validées (https, pas de joker). Sur gk2 : `frame-ancestors https://webmail.gk2.secubox.in https://hall.gk2.secubox.in https://hall.gk2.net https://billets.gk2.secubox.in https://hall.gk3.secubox.in`.
- Leçon : un test dans un cadre unique ne voit pas une CSP de chaîne ; seul un test avec le Hall autour du webmail (ou une vraie session) la révèle.
- Le redéploiement du paquet a de nouveau SCELLÉ le Coffre (redémarrage du démon).

## 2026-10-04 — ad-guard : autorisations par appareil, exceptions au puits complet (ref #1965)
- `secubox-ad-guard` 1.6.2 (gk2, apt à jour). Le puits complet a bloqué le **replay RMC** (roue sans vidéo ni pub) : bissection avec le propriétaire sur la TV, tour par tour (rechargement de 1,5 s à chaque essai). Exceptions nécessaires : **`licensing.bitmovin.com`** (vérification de licence du lecteur Bitmovin) et **`imasdk.googleapis.com`** (chargeur du module de pub de Google : sans lui le lecteur attend sans jamais demander la vidéo ; les serveurs de pub `doubleclick`, `pagead2`, `springserve` restent refusés, donc toujours aucune pub). `api.mediarithmics.com`, `imagino`, `pa-cd.com`, Firebase, Tealium et l'analytique Bitmovin restent bloqués.
- **Mécanisme (mesuré sur l'Unbound 1.17.1 de gk2)** : une zone `transparent` dans la vue `view-first` N'exempte PAS (Unbound retombe sur les zones globales quand la vue ne répond pas) ; `local-zone-override <zone> <adresse> transparent` exempte un client précis, même dans une vue `view-first`, sans toucher aux autres. État `autorisations` {identifiant de l'appareil → domaines}, routes `POST auto/appareils/{nom}/autoriser` et `GET auto/appareils/{nom}/refus`, bouton « Autorisations » dans le panneau (refus de la dernière heure → « Autoriser »). Un changement recharge Unbound (non applicable à chaud) et s'audite.
- **Leçon** : le puits complet (~656 000 domaines publics) peut refuser un nom nécessaire à un service précis ; M6 et France TV passaient, RMC non. Le retour arrière (case « puits complet ») et les autorisations par appareil sont les garde-fous ; le propriétaire avait raison de s'en méfier.
- Fichier d'essai temporaire `/etc/unbound/unbound.conf.d/97-zz-test-exceptions-tv-1964.conf` (issue #1965 en réalité) supprimé après migration vers l'état.

## 2026-10-04 — ad-guard : métriques de la partie standard (ref #1963)
- `secubox-ad-guard` 1.6.1 (gk2, apt à jour). Le panneau standard affichait des zéros (Tracked Devices 0, Blocked 0, trackers appris 0, statuts verts). Causes : `/var/lib/secubox/toolbox` en `secubox-toolbox:secubox-toolbox` 0750 et `toolbox.db` en 0660 → `secubox` ne peut plus les lire, l'erreur était avalée et rendait 0 (88 appareils, 76 425 blocages, 140 Ko de pisteurs appris existent) ; la carte « Blocked (24h) » lisait `detections_24h`, que `/stats` ne remplissait pas ; `learn_status` rendait des pastilles vertes par défaut ; `get_stats` écrivait dans un dictionnaire mis en cache.
- Maintenant : chiffres tirés des compteurs DNS d'ad-guard (jour courant UTC, MAC regroupées, box et passerelle exclues) — **12 appareils vus, 2 921 requêtes bloquées sur 28 155 (10 %)** le 2026-10-04 — ; « — » avec la raison quand une source est illisible ; `autolearn`/`ad_learn` lus dans `filters.json` (lisible).
- **Décision ouverte** : les compteurs d'apprentissage (trackers appris, pure-trackers, allowlist) et les blocages du MITM sont des données du toolbox, aujourd'hui illisibles pour ad-guard ; ne pas élargir les droits sur sa base (métadonnées de navigation). Piste : le toolbox publie un export de compteurs lisible par `secubox`.

## 2026-10-04 — DPI enrichi par les données d'ad-guard (ref #1960)
- `secubox-ad-guard` 1.6.0 + `secubox-dpi` 1.5.0 (gk2, dépôt apt à jour, **dpi en arm64 seulement** : le collecteur Go est compilé par architecture, la construction amd64 du poste produit un binaire x86-64 qui casserait gk2 → toujours `dpkg-buildpackage -aarm64` pour gk2). Fichier d'échange `dpi-feed.json` (`0600`) : un résumé par appareil du LAN regroupé par MAC (requêtes, blocages, top 10 services organisation+type, types), JAMAIS les noms demandés ; route `GET /dpi/lan_dns` (JWT, fail-empty, périmé > 15 min refusé) ; étiquettes d'ad-guard pour les destinations non classées de `/usage` (une règle du DPI gagne) ; deux cartes dans la page du DPI (« vu au DNS », sans volumes).
- **Relecture de sécurité** (0 critique, 4 importants corrigés avec un test rouge chacun) : horodatage futur présenté comme frais, tube nommé qui bloque un fil du pool (et le moteur de #1954 en tête de `main`), JSON très imbriqué ou surrogate isolé → 500, travail synchrone dans la boucle de l'agrégateur (maintenant `asyncio.to_thread`, règles chargées une fois par appel).
- **Vérifié sur gk2** : routes montées (401 sans jeton), fichier écrit en `0600` par `secubox`, `lan_dns` rend 7+ appareils regroupés par MAC avec leurs blocages (TV banc : 508 blocages sur 923 requêtes).
- **Constat honnête** : l'enrichissement de `/usage` étiquette **0 sur 60** destinations non classées aujourd'hui : ce sont des adresses IP seules et les vhosts de gk2, sans nom à classer ; `services.txt` (37 lignes) laisse aussi « (inconnu) » comme premier service de la plupart des appareils. Pistes : table IP→nom d'après le cache d'Unbound (`dump_cache`), et un catalogue de services plus large.

## 2026-10-04 — ad-guard TV : ajout automatique, puits complet, agrégation (ref #1959)
- `secubox-ad-guard` 1.5.0 (gk2, dépôt apt à jour). **Puits complet** : en mode `auto`, la vue Unbound de l'appareil porte `view-first: yes` et pas de zone transparente : il garde le puits de production (656 516 zones) ET ses règles (essai sur l'Unbound 1.17.1 de gk2). **Ajout automatique** des TV/streamers détectés par comportement DNS (insertion publicitaire + ≥ 2 services de contenu), regroupés par MAC, avec le profil de base ; désactivé par défaut. **Agrégation** des règles confirmées sur ≥ 2 appareils. Journal sans les requêtes de la box. 279 tests, essai sur Unbound réel, relecture de sécurité (1 critique préexistant — identifiant de portée IPv6 recopié dans le drop-in — et 5 importants corrigés avec un test chacun).
- **Essai réel du puits complet, validé par le propriétaire (2026-10-04)** sur « TV banc » avec un replay M6 : la vidéo démarre directement, plus de pub d'introduction, aucun écran noir, aucune roue de chargement, aucune erreur. Avant, en mode `block` avec les 35 règles seules, la pub d'introduction passait : M6 utilise un autre segment FreeWheel (`7cbf2.v.fwmrm.net`) que France TV (`7cd77`), que seul le puits bloque en entier (`fwmrm.net`). Autorisés et nécessaires : licences DRM (`lic.drmtoday.com`, `license.oqee.net`), contenu `6cloud.fr`/`6play.fr`, consentement. Bloqués par le puits : FreeWheel, Beeswax, LinkedIn, Tealium, New Relic, Youbora.
- **Mesures** : rechargement complet d'Unbound ≈ 10 s pour la commande, coupure du DNS ≈ 6,6 s (6 sondes en échec), mémoire d'Unbound inchangée (≈ 305 Mo avant et après `view-first`).
- **Constat** : « TV banc » avait été repassée en `block` entre-temps (par le panneau, vraisemblablement) ; l'essai n'a donc réellement eu lieu qu'après remise en `auto`. Non vérifié : l'ajout automatique en réel (la seconde TV, MAC `38:07:16:94:fb:5b`, vue en IPv6) ; les seuils (deux TV, deux services) ; les mineurs reportés (HISTORY de la relecture : audit sans auteur, `ignores` sans levée, appareils administrateur sans MAC dupliqués par l'ajout automatique, etc.).

## 2026-10-03 — ad-guard TV : mode auto, essai 24 h, confirmation, retour arrière (ref #1954)
- **1.4.3 (ref #1938)** : fiche « DNS de la box » dans le panneau (adresses du LAN, IPv6 stable `…::200`, écoute d'Unbound, alertes), route de lecture `GET /adblock-tv/dns-box`. Déployée sur gk2, agrégateur redémarré (43 s), vérifiée par l'adresse publique : eth2, IPv4 192.168.1.200, SLAAC, stable `…::200`, toutes écoutées, aucune alerte.
- **VALIDÉ par le propriétaire (2026-10-03, soir) : closes #1954, closes #1943.** Panneau fonctionnel, plus aucune publicité depuis la mise en place, essai sur 2 Freebox TV dont une pendant plusieurs heures. Déployé : `secubox-ad-guard` 1.4.2 (gk2, dépôt apt à jour).
- `secubox-ad-guard` 1.4.0 (gk2, dépôt apt à jour) : mode `auto` par appareil. Candidats appris par comparaison coupure/lecture → essai 24 h → confirmation ; un essai non confirmé est RETIRÉ ; « Ça ne marche plus » retire d'un geste ; signaux indirects (rafale, contenu disparu). Application **à chaud** par `unbound-control view_local_zone` (essai réel sur Unbound 1.17.1 de gk2 : ajout immédiat, retrait rend la main), repli sur rechargement. Moteur : minuterie chaque minute. Panneau admin dans l'onglet existant.
- Spécification et plan : `docs/superpowers/specs|plans/2026-10-03-adguard-tv-auto*`. Écarts assumés : règles en `regles.json` (pas SQLite), appareil = son nom (pas la MAC), minuterie systemd (pas le démon), seuil de rafale 60/min (la lecture NORMALE mesurée redemande ~10/min).
- **Relecture de sécurité** (sous-agent, contexte neuf) : 2 critiques et 10 importants corrigés avec un test chacun — dossier de root hors de l'arbre de `secubox` (un lien posé sur `applique.tmp` écrasait un fichier arbitraire en root), unité de la minuterie autorisée à écrire là où le contrôleur écrit (sudo hérite de `ProtectSystem=strict`), drop-in vérifié AVANT l'application à chaud, verrou et retour arrière de `regles.json`, collision de noms, activité comptée hors refus, purge, `disable` durable, routes synchrones, audit des transitions. Exception § 10 écrite dans RULES-CODE.
- **Vérifié** : 177 tests ; test sur Unbound réel jetable de gk2 ; paquet installé, minuterie active, routes gardées (401). **Non vérifié** : le mode auto sur la TV réelle (aucun appareil n'est en `auto` : la TV reste en `block`) ; le `sudo` de la minuterie sous `ProtectSystem=strict` (déduit, à confirmer au premier essai) ; les seuils (une TV, une application).
- **Mineurs reportés** : revalidation complète de `applique.json`, `regles.json` en 0640, FIFO, essais expirés ignorés par le contrôleur, TOML invalide sans trace, test des gardes incomplet, sortie du puits de production non signalée dans l'interface, erreurs 409/422/502 non affichées, `sudo` dans `Depends`, `sqlite3.OperationalError` du moteur.
- **Mis en service le 2026-10-03 soir** : les 35 domaines que bloquait la TV sont importés comme règles CONFIRMÉES (origine admin), puis la TV (192.168.1.95 et son IPv6) est passée en `auto` : même protection qu'avant, désormais gérée par règles. Versions 1.4.0 → 1.4.2 déployées, dépôt apt à jour.
- **Trois défauts trouvés seulement à l'essai réel, corrigés** : (1) l'unité de la minuterie échouait — `LockPersonality` (1.4.1) puis `ProtectKernelTunables` (1.4.2) reposent sur seccomp et systemd active alors `NoNewPrivileges` d'office malgré « no » : sudo refusé. Mesuré avec `systemd-run` ; un test interdit les options seccomp dans l'unité ; le moteur relance une application échouée (marque `.a-appliquer`). (2) **`secubox-aggregator` sert ad-guard dans son propre processus** (importé au démarrage, lancé le 2 octobre) : les routes `/adblock-tv/*` étaient en 404 par l'adresse publique alors que le socket du module (que je testais) répondait. Redémarré une fois (retour en 49 s, watchdog à période de grâce actif) ; à refaire après toute mise à jour du module. (3) l'interface levait une exception sur une réponse HTML ou 404 (`return res.json()` sans await) : corrigée.
- IPv6 stable pour le DNS de la Freebox : adresse statique `2a01:e0a:dec:c4e0::200/64` posée À CHAUD sur gk2 (drop-in networkd persistant ; Unbound redémarré pour écouter dessus, DNS coupé ~13 s ; un `reload` ne rouvre pas les ports). Répond depuis le poste. Le propriétaire la renseigne dans la Freebox. Reste à packager (#1938).

## 2026-10-03 — POC « DNS AdBlock TV » dans secubox-ad-guard (ref #1943)
- `secubox-ad-guard` 1.2.0 : mesure du filtrage DNS par appareil (Freebox TV), OBSERVE / BLOCK, **une vue Unbound par mode** (les autres clients et le puits de production de 658 316 domaines ne sont pas touchés ; retirer le drop-in remet tout en l'état). Inactif par défaut. Bibliothèque `api/dnstv.py` + routes `/adblock-tv/*` + onglet « DNS AdBlock TV » ; contrôleur root `secubox-adguard-tv` (sudo à arguments exacts, état relu et revalidé, liens symboliques refusés, `unbound-checkconf` avant de garder) ; démon `secubox-adguard-dnsfeed` (compteurs jour/appareil/domaine/décision ALLOWED·BLOCKED·UPSTREAM_ERROR depuis le journal d'Unbound, rétention 30 j, ni contenu ni cookie ni URL) ; `lists/` versionnées (MANIFEST.json) ; `tools/` (client DNS, banc des limites, procédure A/B/C).
- **Mesuré** (banc local, Unbound 1.22 réel, sans Internet) : A et B bloquables (NXDOMAIN en BLOCK, résolus en OBSERVE) ; C (pub et vidéo sur un même nom) : bloquer le nom supprime aussi la vidéo ; D (pub dans le flux) : aucun nom à bloquer ; E (IP en dur) : 0 requête DNS ; F (résolveur externe) : la box ne voit rien ; G (domaine partagé) : faux positif ; **isolement** : l'appareil observé échappe au blocage global, les autres clients restent bloqués. Journal réel d'Unbound lu par l'analyseur.
- **Trouvaille** : l'exemption d'un client par une vue Unbound **vide** (allowlist d'IP de `secubox-adblock-sync`) ne marche pas (client toujours bloqué, `view-first` yes ou no) ; seule une vue contenant `local-zone: "." transparent` exempte. Non corrigée (comportement de production) : issue séparée. Aussi : un amont MUET fait attendre Unbound sans rien journaliser ; `UPSTREAM_ERROR` correspond à un amont qui répond une erreur.
- Tests : 82 réussis sous Debian 13 (Python 3.13, Unbound réel), 74 + 11 sautés sur le poste sans Unbound. Un test a trouvé un vrai défaut de validation (`clients` non-liste accepté en silence), corrigé.
- **Validé en partie sur la Freebox TV 192.168.1.95** (2026-10-03, replay France TV, une application, une session) : phases E/P/C mesurées. Blocage de `videos-pub.ftv-publicite.fr` + Amazon Ads : pré-roll remplacé par un écran noir de ~6 s, lecture normale. Blocage en plus de `7cd77.v.fwmrm.net` (FreeWheel, serveur d'insertion) : **plus de pub, lecture en direct normale** (constat opérateur, y compris sur les coupures en cours de programme, sans attente ; peu d'observations). Seconde TV non testée. Détail : `docs/poc-dns-adblock-tv-results.md`. TV laissée en BLOCK sur ce périmètre, réversible.

## 2026-10-03 — Webmail OpenPGP : page du Coffre à origine séparée, greffon Roundcube, Autocrypt entrant, pastille (ref #1852, P5)
- `secubox-vault` 2.1.1 + `secubox-mail` 2.12.1 (gk2, dépôt apt à jour). Page `pgp.<domaine>/pgp/` : clé secrète de la personne lue depuis son compartiment par la session de connexion (aucune phrase), tenue EN MÉMOIRE ; OpenPGP.js 6.3.2 livré (sha256 e19bf4f0…, LGPL). Le webmail (autre origine) lui parle par postMessage ; la page n'obéit qu'au cadre parent dont l'origine est dans `origines.json`. Chiffrer / signer / déchiffrer / vérifier ; destinataire sans clé = REFUS (jamais en clair). Autocrypt ENTRANT : clé publique valide portant l'adresse annoncée, jamais supplantant l'annuaire, rangée dans le compartiment (secret `openpgp-contacts`). Pastille de signature : valide / invalide / clé inconnue / non signée.
- Greffon Roundcube `secubox_pgp` (aucune cryptographie ; texte affiché par `textContent`) ; `mailctl webmail-pgp` le pose et l'active (php -l, retour arrière). `coffre-pgp-vhost` écrit le vhost (CSP sans script en ligne, `frame-ancestors` = le webmail, 2 routes d'API relayées seulement) + exposition HAProxy/WAF.
- **Tests** : 23 en vrai navigateur (Chromium, deux origines HTTPS) + GnuPG pour l'interopérabilité (chiffré par la page → déchiffré par GnuPG ; signé → vérifié par GnuPG ; message GnuPG → déchiffré et vérifié par la page), dont : parent non autorisé = silence, clé secrète jamais dans une réponse ni dans le stockage, XSS (`<img onerror>`) affiché en texte, envoi annulé si clé manquante / Coffre scellé / HTML. `nginx -t` réel sur le vhost.
- Trouvés au déploiement sur gk2 : accolade `{1,64}` d'une expression nginx non guillemetée (`nginx -t` refusait, vhost retiré, rien cassé → 2.1.1) ; Roundcube Debian charge ses greffons depuis `/var/lib/roundcube/plugins` (liens) (→ 2.12.1).
- **Le déploiement du Coffre l'a SCELLÉ** (le démon redémarre ; la clé maîtresse n'est qu'en mémoire) : rouvrir par la connexion d'un administrateur.
- **Non validé** : le parcours complet avec une session réelle (je n'en ai pas) — ouvrir un message chiffré, envoyer un message chiffré depuis le webmail, bouton dans la barre de rédaction d'Elastic. PGP/MIME (multipart/encrypted) non géré (inline seulement). Brouillons : l'enregistrement automatique envoie le CLAIR dans Brouillons (boîte de la personne, sur la box) — à désactiver pour qui chiffre.

## 2026-10-03 — Webmail OpenPGP : Autocrypt sortant (ref #1852, P2)
- `secubox-openpgp` 0.3.0 + `secubox-mail` 2.11.0 (gk2, dépôt apt à jour). `sbx-openpgp autocrypt` : table {adresse: keydata} des clés PUBLIQUES minimales de l'annuaire, adresses VÉRIFIÉES seulement, clé expirée ou > 6 Ko omise. Règle rspamd `autocrypt.lua` (postfilter) : ajoute `Autocrypt: addr=…; keydata=…` aux envois authentifiés dont le From est l'adresse de la session (`*maître` du SSO du webmail toléré) ; jamais au nom d'un autre, jamais sans session, jamais par-dessus un en-tête du client. `mailctl autocrypt-sync` (+ minuteur horaire) pousse table et règle, `rspamadm configtest` avant rechargement.
- Mesuré sur le rspamd de gk2 (`rspamc -u`) : session = From → en-tête ajouté (replié) ; autre session, sans session, en-tête déjà posé → rien ; login `…*master` → ajouté. **La table de production est vide** (aucune personne n'a publié de clé) : la règle n'agit sur rien tant qu'une clé n'est pas publiée dans « Mon coffre ».
- Correction de l'étude #1852 : Mailvelope est dans le CŒUR de Roundcube 1.6.5, aucun greffon à livrer. Le bouton « chiffrer » n'apparaît que si l'extension Mailvelope est installée et le domaine autorisé.

## 2026-10-03 — Sonde DHCP en lecture seule (ref #1935)
- `secubox-netdiag` 1.3.0 : `secubox-dhcp-probe` (un DISCOVER, aucun bail, socket brute). Mesuré sur gk2 : UN seul serveur DHCP (la Freebox, 192.168.1.254), passerelle 192.168.1.254, **DNS annoncé 192.168.1.200 (gk2) déjà configuré** dans Freebox OS 4.12 (« Serveur DNS 1 »). Le DHCP IPv4 n'a donc PAS besoin d'être remplacé.
- Cause réelle du 421 de voicestudio.gk3 sur un poste : le DNS **IPv6** annoncé par la Freebox (`fd0f:ee:b0::1`, via annonce de routeur) passait avant celui de gk2 et répondait l'IP publique. Poste corrigé (NetworkManager : gk2 seul DNS, IPv6 DNS ignoré). Autres postes : à traiter côté IPv6 (désactiver l'IPv6 du LAN dans Freebox OS ou annoncer gk2 par RA).

## 2026-10-03 — Studio natif de VoiceStudio réservé au réseau local (ref #1917)
- **Cause des « 504 »** du studio natif (`/generate`, `/transcribe`, `/archetypes/…/preview`) : `sbxwaf` de gk2 coupe à 120 s (`--upstream-timeout 120s`, journal `timeout awaiting response headers`) ; le grand modèle met 110 à 140 s et davantage sous contrainte mémoire. Décision de l'exploitant : « voicestudio limité au LAN ».
- `secubox-voicestudio` 0.5.1 : le vhost du studio répond 403 à tout client que `$lan_client` ne tient pas pour local (avant la garde administrateur). `secubox-haproxy` 1.8.25 : le backend `nginx_vhosts` (accès direct, sans WAF) porte le délai de 1 h du domaine `voicestudio.*`.
- **gk2 (hors paquet, à reproduire)** : `secubox-relais-maillage retirer voicestudio.gk3.secubox.in` + `haproxyctl generate --allow-shrink` (5 lignes retirées, sauvegarde `/root/haproxy.cfg.avant-retrait-voicestudio`) ; `/etc/secubox/relais-maillage.toml` `exclure = ["wpad","boot","voicestudio"]` pour que le minuteur ne le ré-expose pas ; Unbound `/etc/unbound/unbound.conf.d/98-secubox-voicestudio-lan.conf` : `voicestudio.gk3.secubox.in → 192.168.1.9` (les postes locaux, qui utilisent gk2 comme DNS, atteignent gk3 directement). Mesuré : LAN direct → 401 (garde), mesh → 403, nom résolu 192.168.1.9.

## 2026-10-03 — VoiceStudio : voix rapide et WebSocket de l'interface native (ref #1917)
- `secubox-voicestudio` 0.5.0 (gk3 ; dépôt apt à jour). **Cause du « je n'ai pas de résultat »** : le grand modèle de synthèse met 110 à 140 s par phrase sur le CPU de gk3 (mesuré, y compris pendant des installations de modèles lancées depuis le catalogue du studio) ; l'écran restait muet. Le chargement du modèle ne compte que pour 4 s : garder le modèle chargé n'aurait rien changé, c'est le calcul qui est lent.
- **Solution** : voix rapide = Piper français (`vits-piper-fr_FR-siwis-medium`, 67 Mo, sha256 épinglé) par sherpa-onnx, déjà dans le moteur ; serveur `voix-rapide.py` dans le LXC (:3901, même clé), 0,9 s pour 4,6 s d'audio. « Dire » sans voix nommée l'utilise, sans demander de mémoire ; voix nommée ou voix rapide absente → grand modèle. `voicestudioctl voix-rapide` + unité d'installation (marqueur posé seulement si le serveur répond).
- **Interface native** : WebSocket `/ws/transcribe` refusé en 403 — le moteur compare l'Origin (https) à son schéma (http derrière HAProxy). nginx ramène à http l'Origin exacte du vhost ; toute autre reste refusée (mesuré : `https://evil.example` → 403).
- Le 504 « Stories chained preview » de l'interface native venait du même calcul trop long.

## 2026-10-02 — VoiceStudio en LXC natif, interface administrateur et usager (ref #1917, #1743)
- `secubox-voicestudio` 0.2.0 : plus aucun podman. LXC Debian non privilégié `voicestudio` (10.100.0.230), sources amont épinglées par commit **et** sha256 (vérifié avant extraction), versions Python tirées de l'image validée (`pip list`, 268 contraintes, sans CUDA), torch CPU depuis l'index PyTorch seul, `pip check` en fin d'installation. Même disposition que l'image (`/app`, `/app/omnivoice_data`) : la base SQLite garde ses chemins absolus.
- Mandataire d'hôte à activation par socket (`systemd-socket-proxyd`, utilisateur `nobody`) : port 3900 sur les adresses `[reseau] publier` (LAN, maillage — adresses publiques refusées) et le loopback ; mode `permanent` (défaut) ou `demande`.
- Interface : API `/api/v1/voicestudio` (socket Unix ; `require_jwt` pour l'administration, `require_personne` pour l'usager, `/status` minimal en lecture, `/detail` réservé), panneau d'administration (état, démarrer/arrêter, mode, mémoire, CPU, modèle ASR, adresses, clé, essai, journal, sauvegarde) et page d'usager (dire, dicter). Une seule porte privilégiée : `voicestudioctl api` (JSON sur stdin, actions en liste blanche, sudoers à argv exact, audit).
- Mesuré hors box (poste amd64, python 3.11, torch CPU) : installation complète OK, moteur prêt en 9 s, `/health` 200, clé exigée pour tout client non-loopback (401 sans clé ou mauvaise), `/v1/audio/voices` (`voice_id`), dictée 200. Les deux pages essayées dans Chromium (Playwright), 231 tests.
- Relecture de sécurité : 0 bloquant, 10 importants dont deux défauts réels corrigés (moteur jamais démarré à la première installation ; clé renouvelée non relue après un sommeil), migration podman atomique, `flock` sur les commandes mutantes, verrous usager/admin séparés, cache des échecs du ctl. Dettes nommées dans le README (pas d'AppArmor, LAN en clair, pas de `--require-hashes`).
- Constaté sur gk3 avant déploiement : le moteur podman ne répondait plus (aucune réponse en 90 s, swap saturé) ; le vrai consommateur est gk2 (`voice.toml` en `mixte`, `http://10.10.0.5:3900`).
- **0.2.1 (pare-feu)** : le mandataire écoute sur l'hôte, donc sous la chaîne d'entrée en DROP ; l'ancien moteur passait par la redirection de podman, qui la contourne. Après la bascule, gk2 n'atteignait plus le moteur de gk3 (`10.10.0.5:3900` sans réponse). Règle posée par le ctl (adresses publiées × sources privées, par poignée, jamais de `flush`) + `/etc/nftables.d/zz-secubox-voicestudio.nft` (table déclarée de façon additive ; vérifié dans un espace de noms jetable : crochet et politique préservés, rechargement = une seule règle).
- **0.2.2 (sudo sous bac à sable)** : `ProtectKernelTunables`, `RestrictSUIDSGID` et `LockPersonality` imposent implicitement `NoNewPrivileges=yes` (seccomp) ; sudo répondait « no new privileges flag is set » malgré `NoNewPrivileges=no` et tous les boutons du panneau échouaient. Trouvé en rejouant le code de l'API dans une unité transitoire aux réglages identiques (les tests unitaires ne pouvaient pas le voir) ; réglages retirés un à un, test et commentaire dans l'unité. Vérifié ensuite sur gk3 : statut, aperçu de clé, journal, liste blanche, clé du moteur, voix par le mandataire.
- **0.2.3 (journal)** : `systemd-journald` échoue dans le LXC non privilégié (seccomp) : l'onglet Journal était toujours vide. Le ctl lit désormais `omnivoice.log` (dossier de données, côté hôte, LXC arrêté compris).
- **0.2.4** : sans session, le panneau annonce « Connexion requise » / « Réservé aux administrateurs » (et non « API injoignable ») ; point de montage vide laissé par la migration retiré.
- **Déployé et vérifié sur gk3** (PR #1918 à #1922, versions 0.2.0 à 0.2.4, toutes publiées dans le dépôt apt) : provisionnement 3 min 30 s (20:17 → 20:20), bascule automatique à 20:21 (605,5 Mo reprises, volume podman conservé), moteur 620 Mo, `/health` 200, clé exigée, dictée 200 en 1,9 s par le mandataire, gk2 → `10.10.0.5:3900` avec sa clé inchangée (200 avec, 401 sans), LXC sortant vers Hugging Face et PyPI. **Ne pas fermer #1917 avant la validation par une personne connectée** (pages d'administration et d'usager au navigateur).
- Incident pendant la validation : l'accès SSH de gk3 a refusé ma clé dans la nuit (`authorized_keys` vide ou absent, gk3 non redémarré, aucune trace dans le journal ; cause inconnue). Clé réinstallée avec l'accord de l'exploitant.
- Reste #1743 : validation de la bascule sur gk3, purge de podman/buildah/crun des boxes, ligne photoprism.

## 2026-10-02 — SESSIONS SOBRES, WAF SANS FAUX POSITIFS, COFFRE POUR TOUS (ref #1863, #1858, #1859, #1857, #1855, #1862)

- **Contexte (#1863)** : WIP.md 485 Ko, HISTORY.md 516 Ko et TODO.md 89 Ko lus « en premier » ;
  CLAUDE.md et AGENTS.md dupliqués. Découpe par mois dans `archive/`, **zéro perte prouvée**
  (SHA-256 identique à l'octet, `archive/reassembler.py`) ; instructions à source unique.
- **WAF** : `cred-004` prenait `requesttoken=` de Nextcloud pour un jeton (l'iPhone était
  compté, 2/3 avant bannissement) ; `api-001` bannissait l'administrateur légitime ;
  bruit `localhost` retiré de sbxwaf ; `waf-rules-sync` met à jour les règles livrées sans
  écraser celles de wafgen (secubox-waf 1.10.42, secubox-waf-ng 1.18.12). PR #1860, #1861.
- **Coffre** : la connexion ouvre le Coffre de l'admin ET le compartiment de toute personne,
  invités compris (vault 2.0.15, auth 1.1.18, aggregator 0.3.10 ; PR #1856 fusionnée) ;
  un pin `vault = off` périmé le tenait arrêté (le Coffre rejoint les modules protégés de
  `secubox-profiles`) ; 421 `undefined`/`vault.gk2` corrigés dans le Hall (webos 1.0.395).
- **Accès délégués retirés (#1857)** : l'identité SBX OS porte les liens ; sonde de session
  `GET /api/v1/webos/session` ; « Mes sites » en lien direct ; cadre embarqué par
  `/sbx/entrer`. Le coffre `webos-acces` est conservé (il sert l'Identity Manager).
- **RustDesk décommissionné (#1862)** : paquet, conteneur LXC (archive 190 Mo), flux
  HAProxy, références dépôt (54 métapaquets republiés).
- **gk3** vérifié en direct : frontal HAProxy → sbxwaf → nginx, 0 unité en échec (#1808, #1684).

## 2026-10-02 — Polices Google via le cache de la box (#1875)
- secubox-hub 1.9.31 : zone `sbx_fonts` + snippet `/cdn/fonts/css|s/` (proxy_cache, CSS réécrit). billets 0.8.70, podcaster 1.2.6 : liens `/cdn/fonts/css/…`, CSP sans hôte Google. Vérifié Chromium : 0 requête Google (podcaster, billets, Hall). Déployé gk2. Reste (phase 2) : ~30 autres pages www/ (ref #1875).
- Dette notée : `billets.conf` livré diverge du live (waking, X-SecuBox-LAN) ; sites-enabled/billets.conf était une copie, remplacée par un lien.

## 2026-10-02 — Backends fermés côté eth2 (ref #1306)
- secubox-hardening 1.3.0 : `/etc/nftables.d/secubox-wan-guard.nft` (table `inet secubox_wan_guard`, priorité filter-10) coupe 7331, 8088, 8404, 8880, 8900, 8910, 9080 en entrée eth2, sans toucher la règle de base `iif "eth2" accept` (fichier non géré par un paquet). Déployé gk2 : ces ports sont fermés depuis le LAN, 22/80/443/9443 ouverts, sites 200. Reste : 8780, 8099, 8000, 9000, 8888, 9050 (usage LAN non établi) et le propriétaire du pare-feu de base.

## 2026-10-02 — Garde des ports de backend intégrée à secubox-hardening (ref #1306)
- hardening 1.4.1 : `GET /wan-guard` (règle livrée, ports gardés, ports encore en écoute joignables par le LAN), carte dans le tableau de bord, `hardeningctl wan-guard` (table chargée, root), 4 tests. Déployé gk2 (aggregator redémarré, hall 200). Reste non gardé et à trancher : 2222, 8000, 8780, 8888, 9000, 9050 + les leurres (23, 445, 1433, 3306, 3389, 5432, 5900, 6379, 9200, 27017).

## 2026-10-02 — Leurres fermés côté eth2 (ref #1306)
- hardening 1.4.2 : la garde coupe aussi les écoutes de leurre de sbx-authwatch (23, 1433, 3306, 3389, 5432, 5900, 6379, 9200, 27017) ; 445 (SMB réel) reste ouvert. Déployé gk2, vérifié depuis le LAN. Effet : sbx-authwatch ne voit plus de sondes sur eth2. Reste non gardé : 2222, 8000, 8780, 8888, 9000, 9050.

## 2026-10-02 — Une seule base de pare-feu pour toutes les SecuBox (ref #1306)
- secubox-hardening 1.5.1 livre /etc/nftables.conf (table `inet filter`, superset gk2 + firstboot/gk3 : ICMPv6, DHCP, WireGuard 51820-51825, maillage, mDNS, masquerade LXC). Propre à la box : `/etc/secubox/hardening/nft-input-trust.d/` (interfaces de confiance) et `nft-site.d/` (tables NAT reprises de l'ancienne base). `image/firstboot.sh` n'écrit plus sa propre base : il installe celle du paquet (secubox-meta dépend de secubox-hardening). Essai sur gk2 en espace de noms isolé : ruleset = ancien + ajouts seulement, rien perdu ; non appliqué en direct (effet au prochain démarrage de nftables).
- À vérifier avant de propager à gk3 : ses règles de `secubox_filter` (bonjour, noms, relais) sont reprises par la base ; contrôler en espace de noms puis au prochain démarrage.

## 2026-10-02 — Test dynamique du WAF dans la page Santé (ref #1883)
- health-doctor 1.1.1 : contrôle `waf-selftest` (sbxwaf à l'écoute, témoin non bloqué, canaris XSS/SQLi/LFI/RCE en 403 depuis 198.51.100.77, vhost public hall.*), au plus toutes les 5 min, `POST /waf-selftest/run` pour le rejouer. hub 1.9.32 : section « WAF — test dynamique » dans /health/. Vérifié gk2 + Chromium. Constat : sbxwaf n'inspecte pas admin.* ni git.* (liste en dur du binaire).

## 2026-10-02 — Menu admin : entrées p2p/zkp ignorées sur une box neuve (ref #1888)
- Cause : secubox-p2p et secubox-zkp livraient leur entrée en /etc/secubox/menu.d, que le hub ne lisait pas ; gk2 les avait par copie manuelle (21/05), gk3 non. hub 1.9.33 lit aussi /etc/secubox/menu.d (locale prioritaire, dédoublonnée) ; p2p 1.11.18 et zkp 1.2.3 livrent en /usr/share/secubox/menu.d. 3 tests. gk2 : p2p inchangé (déjà présent), zkp non affiché faute de www/zkp. Écarts de gk3 restants : pas de dpi, mediaflow, sentinelle-gsm (jeu de paquets), hub/health-doctor/hardening en retard sur gk2.

## 2026-10-02 — Assistance : boutons de session non muets (ref #1894)
- secubox-assist 0.2.10 : sans session active, Kill session / Autoriser / Retirer sont désactivés avec l'explication ; le POST passe par postAction (succès et échec visibles). Avant : `if (!sid) return;` et réponse jamais lue. 3 tests.
## 2026-10-02 — Santé : veille pondérée (ref #1887)
- core 1.5.53 + hub 1.9.35 : unités au repos (oneshot ou TriggeredBy timer/path, dernier passage réussi) et modules endormis = ok + `veille`; unités not-found/masked écartées; échec = alerte. Page Santé : carte 💤 en veille, score pondéré (sain 1, veille 1, dégradé 0,5, panne 0). gk2 : dégradés 59 → 2 (premier-pas-console, zia-llm), 68 en veille, 121 sains, 0 panne. 14 tests core.

## 2026-10-02 — Assistance : demandes reçues visibles (ref #1895)
- secubox-assist 0.2.11 : la carte « Demandes en attente » liste aussi les demandes ouvertes reçues des autres box (bouton Répondre). La demande de gk3 (motif sbx, req 4e68e4cb…) était active dans le journal de gk2 mais ne s'affichait que dans l'onglet « Demandes ouvertes ». Déployé gk2 (page seule, sans redémarrage). 4 tests.

## 2026-10-02 — Accès : erreur « Votre nom est nécessaire » rattrapée (ref #1893)
- sbxid 0.4.18 : bouton() des pages d'accès exécute l'action dans la chaîne de promesses ; le throw synchrone n'est plus une erreur non rattrapée avec bouton figé. Non traité : iframes blob:https://admin.gk2… bloquées par la CSP du Hall (origine non identifiée, aucun createObjectURL d'iframe dans les sources) ; bruit Firefox Feature Policy autoplay/encrypted-media et Layout forced sans effet.

## 2026-10-03 — Reporter : téléchargement du PDF dans Firefox (ref #1895)
- Cause : le PDF était servi (200, 21014 o) mais Reporter, embarqué dans le Hall, téléchargeait par blob: ; Firefox traite la navigation vers le blob comme un chargement de cadre refusé par frame-src du Hall (les trois iframes blob bloquées de la console = les trois clics). Chromium télécharge dans tous les cas (reproduit). reporter 1.2.3 : lien direct (cookie de session) sinon blob en repli avec ancre dans le DOM et révocation différée ; guillemet final du nom de fichier retiré. Non vérifié dans Firefox (absent ici). Clôt aussi l'iframe blob: laissée « origine inconnue » dans #1893.

## 2026-10-03 — nginx real_ip : relais propres à la box seulement (closes #1754)
- hub 1.9.36 : `secubox-lan-geo.conf` ne trustait plus que 127.0.0.1 ; `secubox-realip` (service + minuteur 60 s) engendre `/etc/nginx/conf.d/secubox-real-ip-local.conf` avec les adresses locales (gk2 : 11 adresses). Avant : 192.168.1.0/24, 10.100.0.0/24, 192.168.255.0/24 crues. Mesuré gk2 avant/après : `X-Forwarded-For: 8.8.8.8` depuis un poste du LAN → journalisé 8.8.8.8 (avant), 192.168.1.3 réel (après) ; clients réels (192.168.1.254, IP externes) toujours résolus via HAProxy ; sites 200 ; verdict $lan_client inchangé. 6 tests, dont un bug du script trouvé par les tests (set -e).
- closes #1306 : pare-feu — backends fermés côté eth2 (hardening 1.4.x), base unique livrée par le paquet (1.5.1, gk2 et gk3 à jour, images via firstboot) ; les services LAN-only (Lyrion 3483/9000/8888, 2222, 8000, 8099, 9050) restent ouverts par décision de l'exploitant.

## 2026-10-03 — NAC : blocage, quarantaine et zones ont un effet réseau (ref #1766)
- nac 3.1.7 : l'API écrit l'état voulu (nft-desired.json), `secubox-nac-apply` (root, CAP_NET_ADMIN seul, unité .path) valide et charge en une transaction règles + éléments ; `/etc/nftables.d/secubox-nac.nft` enfin référencé par des règles (blocked, quarantine, iot/guest isolés du LAN). Preuve de bout en bout gk2 (netns jetables) : bloqué → ping KO, retiré → OK, quarantaine KO, IoT internet OK / LAN KO. Chaîne réelle API→.path→nft vérifiée (ajout/retrait d'une MAC factice, 3 s). 8 tests. Non déployé gk3 (apt). 2 tests test_discovery échouent déjà sur master.

## 2026-10-03 — Dossiers photo partagés : fin des 0777 (closes #1516)
- UID mesurés sur gk2 : Nextcloud www-data=100033 (seul écrivain 30 j), PhotoPrism = utilisateur `photoprism` uid 995 → 100995 (pas root ; arrêté sur gk2). nextcloud 1.8.10 + photoprism 1.3.10 : racine 0755 100000:100000, dossiers d'usagers 2750 100033:100995 ; `nextcloudctl fix-photos-perms` (racine + sous-dossiers directs, jamais récursif) appelé par la postinst. Trois points de création corrigés (nextcloudctl, photoprismctl, postinst + install-lxc.sh de photoprism qui remettaient 0777). Vérifié gk2 : www-data écrit gk2/ et admin/, uid 100995 lit, un autre uid refusé, contenu intact (1001:1001 conservé), nc.gk2 200. Le premier jet avait le groupe 100000 : PhotoPrism n'aurait pas lu — trouvé en mesurant avant de déployer le reste. Hors périmètre vu en passant : /data/droplet/*_html en 0777 (107:114), un tar de sauvegarde mail en 0666.

## 2026-10-03 — Clé de signature apt protégée au niveau 0, déverrouillée au boot (ref #1366)
- vault 2.0.16 : `coffrectl depot proteger --demarrage` (phrase aléatoire systemd-creds, relue avant application, retour arrière si échec), `depot deverrouiller`, `secubox-depot-deverrouille.service` (condition : crédence présente). Appliqué sur gk2 à la clé 219BA872 : fichier de clé `protected-private-key` sur disque, 0 phrase humaine, Coffre non requis. Vérifié : signature + vérification OK ; agent tué (reboot simulé) → fermée ; unité lancée → signe ; `reprepro export` re-signe le dépôt (Release.gpg et InRelease valides) ; gk3 `apt update` OK. 5 tests avec vrai gpg (dont copie du disque qui ne signe pas, crédence illisible → clé intacte).
- Reste #1366 (gestes humains) : clé USB de l'export hors ligne puis effacement du poste ; décision sur .github/workflows/publish-packages.yml ; clé de mise en scène 31848880 sur le poste. Les phrases `gpg --passwd` humaines ne sont plus nécessaires.

## 2026-10-03 — Garde-fou CI contre les fusions qui écrasent master (ref #1748)
- `scripts/check-merge-overwrite.sh` (modes `--commit`, `--range`, historique) et `.github/workflows/merge-overwrite-guard.yml` : sur chaque PR, la fusion simulée et les fusions de la branche sont contrôlées ; un .py modifié des deux côtés dont la fusion reprend un côté octet pour octet fait échouer ; étiquette `ecrasement-voulu` pour l'exception. 6 tests sur dépôts jetables (écrasement détecté, vraie fusion à trois voies passe, plage, historique). Le script retrouve bien aff481735 (12 paquets).
- Recherche d'autres fusions du même type (depuis 2026-06-01) : 7ebe27403 (core config.py, metrics), 0c07799fd (nac discovery.py), c43ffe9b0 (nextcloud), 2c15f1448/1356a04e0/6a68f3b25 (toolbox bundle.py, api.py), f8e38edda (ytsas). Lignes de master retirées par la fusion ET toujours absentes aujourd'hui : nextcloud 54, metrics 32, toolbox bundle 27, config.py 5, nac discovery 3, toolbox api 6/3, ytsas 0 — à auditer (une partie peut avoir été réécrite depuis ; pas de preuve de perte).
- gk3 : mise à jour apt complète le 2026-10-03 (68 paquets, hub 1.9.35…).

## 2026-10-03 — Niveau 0 réévalué, #1851 suspendue (ref #1851, #1902)
- Évaluation sur gk2/gk3 : gk2 sans TPM, clé d'hôte `/var/lib/systemd/credential.secret` sur le même disque ; sauvegardes = /etc/secubox + /var/lib/secubox sans cette clé. Le niveau 0 ne protège que les copies partielles ; disque volé, root ou service compromis : aucun gain. gk3 : liaison TPM2 **implicite** (défaut `auto` de systemd, aucun `--with-key` dans niveau0.py) — différence de menace entre boxes jamais décidée.
- Décision de l'exploitant : #1851 suspendue ; liaison TPM explicite et optionnelle (défaut identique partout) ouverte en #1902 et mise de côté. Pistes à plus fort rendement ouvertes : #1903 (sauvegardes chiffrées par défaut), #1904 (un groupe par secret ; 70 processus sous `secubox`, 11 secrets en 0640 root:secubox). La clé apt de gk2 (#1366) garde sa phrase de niveau 0 : gain limité aux copies sans la clé d'hôte, root signe toujours.

## 2026-10-03 — Audit des fusions écrasantes terminé (closes #1748)
- Méthode : pour chaque fusion signalée par `check-merge-overwrite.sh` depuis juin, lignes de master retirées puis comparaison des fonctions et routes (avant fusion / aujourd'hui).
- **nac `discovery.py` (0c07799fd) : PERTE RÉELLE**, restaurée dans nac 3.1.8 — `_parse_arp` ne consignait plus l'interface, `discover()` ne la gardait plus face à un bail de rang supérieur, `br-lxc` n'était plus une interface LAN (conteneurs non découverts, zone lxc jamais auto-attribuée). Les 2 tests `test_discovery` qui échouaient sur master repassent (206 verts). Déployé gk2 et gk3 (paquet ; effet au prochain redémarrage de l'agrégateur).
- core `config.py` (7ebe27403) : le bloc cookie-audit réécrit depuis par #1311 (`get_cookie_audit_config`) — rien de perdu.
- metrics `main.py` (7ebe27403) : 27 routes présentes ; le préchauffage #740 réécrit (`_prechauffer_cache`) — rien de perdu.
- nextcloud `main.py` (c43ffe9b0) : 22 routes avant → 27 aujourd'hui, aucune fonction manquante, correctif d'URL publique (2e061afd7) présent — rien de perdu.
- toolbox `api.py`/`bundle.py` (2c15f1448, 1356a04e0, 6a68f3b25) : déjà restauré par bb527ddb7 (#1778) ; aucune fonction ni route manquante.
- ytsas `main.py` (f8e38edda) : rien.
- Garde-fou en place (PR #1901). Les 12 paquets d'aff481735 avaient été restaurés auparavant.

## 2026-10-03 — SSO Nextcloud : session de compte ambiguë départagée (ref #1907)
- Cause mesurée : le compte `gk2` porte 8 appareils acceptés (6 de gandalf, 2 de gek) ; `personne_du_porteur` exige UNE personne pour une session de compte → None → pas de `Remote-Sbx-Nextcloud` → formulaire de connexion (200, 11,6 Ko dans le journal nginx). Mail, BBS et PeerTube retombent sur `Remote-User` (comptes homonymes) ; user_saml ne lit que HTTP_X_SBX_NEXTCLOUD_USER. Côté Nextcloud, l'en-tête posé à la main ouvre la session (303 /apps/files/).
- core 1.5.54 : le lien `sbx_app_links` (app=systeme) départage ; jamais pour une session d'appareil ; inchangé quand les appareils désignent déjà une seule personne. 271 tests core verts (2 nouveaux). gk2 vérifié : personne = gandalf, nextcloud=gk2, bbs=gk2, email=gk2@secubox.in, peertube=gk2 ; `admin` reste « non personne ». À confirmer en navigateur par l'exploitant.
- Autres issues vérifiées résolues : #1289 et #1418 (seul secubox-nac livre www/nac/index.html, nac 3.1.8 s'installe sur gk2 et gk3), #1419 (cache meshtastic écrit, 0 erreur).

## 2026-10-03 — Hall : le bouton Partager du lecteur radio copie un lien (ref #1836)
- Cause confirmée en lisant le code : `viewer-share` faisait `if(!courant) return;` ; avec un lecteur de service (radio, #1662) `courant` est vide, le bouton sortait sans rien copier ni dire. De plus `writeText` n'était pas lu : un refus était avalé et le bouton s'allumait quand même.
- webos 1.0.397 : lien = morceau annoncé du lecteur, sinon média courant, sinon adresse du lecteur (URL absolue et publique, #1579) ; résultat de la copie lu, repli par champ temporaire puis boîte affichant le lien ; le bouton ne s'allume que sur une copie réussie. 7 tests (Node, navigateur simulé : radio avec/sans piste, média courant, rien à partager, refus avec repli, refus total). Déployé gk2 (page statique) ; Hall se charge sans erreur. Non testé avec un vrai clic dans le popup radio : à confirmer par l'exploitant.

## 2026-10-03 — Sauvegardes chiffrées par défaut (ref #1903)
- backup 2.1.1 : chiffrement par défaut (clé publique de la box), échec fermé (pas d'archive en clair par omission), dossiers 0750 / fichiers 0640, outil root `backupctl` (etat, init-key, chiffrer-existantes, restaurer), `Depends: age`. gk2 : paire générée, 13 archives en clair listées puis chiffrées (clair CONSERVÉ : à purger par l'exploitant avec `--supprimer-clair` après avoir copié la clé privée hors de la box). Archives de config contenant /etc/secubox/secrets en clair, certaines en 0666 dans des dossiers 0777 : constat à l'origine.
- Bug de mon premier jet (2.1.0), trouvé en testant sur gk2 : `dechiffrer` écrivait au nom de l'archive d'origine, donc `backupctl restaurer` a supprimé le clair `config-20260925-191334.tar.gz` ; la vérification de `--supprimer-clair` comparait un fichier à lui-même. Corrigé en 2.1.1 (déchiffré dans un dossier temporaire 0700, comparaison de deux fichiers distincts) ; le clair a été rétabli depuis le chiffré (sha256 identique avant/après restauration). 11 tests dont régression avec un vrai gpg.

## 2026-10-03 — Sauvegardes : chemins de l'interface + case Chiffrer (ref #1903), analyses ClamAV et GPG (ref #1834, #1852)
- backup 2.1.2 : l'interface appelait `/create` et `/container/backup`, qui écrivaient des archives EN CLAIR sans passer par le chiffrement de 2.1.0/2.1.1 (seules les sauvegardes planifiées étaient protégées). Tous les chemins passent par `finaliser_archive` ; échec de chiffrement = code 1 et aucune archive en clair ; l'API `/encryption` ; case « Chiffrer » cochée par défaut (confirmation si décochée) ; état du chiffrement ; 🔒/⚠️ ; bouton Restaurer qui donne la commande root ; `backupctl restaurer --liste` ; restauration d'une archive chiffrée par l'API : 409 avec la commande. 16 tests.
- ClamAV (#1834) : arrêté pour 2 raisons — base de signatures jamais téléchargée (`clamav-freshclam` disabled) ET clamd (1,2–1,5 Go) ne tient pas dans le budget mémoire de `mail` (384 Mo, déjà au plafond) ; ni gk2 (2,2 Go disponibles, zram à 2 Go) ni gk3 (1,4 Go, swap plein) n'ont de marge. Le courrier n'est PAS scanné aujourd'hui (fail-open implicite). Options A–D consignées sur l'issue, recommandation : LXC clamav dédié éveillé à la demande.
- GPG/SSO/webmail (#1852) : le SSO (`secubox_sso`) établit déjà l'identité de la boîte ; la contrainte est #1738 (jamais de clé privée côté serveur). Étude par couches, ordre WKD → Autocrypt → pastille de signature → Mailvelope → page Coffre à origine séparée ; décision attendue.

## 2026-10-03 — ClamAV : LXC dédié éveillé à la demande, courrier enfin scanné (ref #1912, #1834)
- Décision de l'exploitant : option A. Paquet `secubox-clamav` 0.1.2 : LXC `clamav` (10.100.0.220, `lxc.start.auto = 0`, mémoire 1,4/1,8 Go **seulement éveillé**), mandataire d'hôte à activation par socket `10.100.0.1:3310` (`systemd-socket-proxyd --exit-idle-time=600s` ; `ExecStartPre` réveille, `ExecStopPost` rendort), mise à jour hebdomadaire de la base, `clamavctl`. `secubox-mail` 2.10.18 : `mailctl antivirus on` ne pose que le module Rspamd (plus d'installation dans le conteneur mail), `task_timeout` 150 s. `health-doctor` 1.2.0 : contrôle « clamav » (le sommeil est normal, la base périmée non).
- Mesuré sur gk2 : démarrage à froid 45–55 s, EICAR **détecté** par le mandataire ; message propre 0,05 s éveillé ; conteneur ≈ 980 Mo (hôte 2,2 Go → 1,3 Go disponibles pendant l'éveil). Rspamd : message avec pièce jointe EICAR → `reject`, symbole `CLAM_VIRUS: Eicar-Test-Signature` ; message propre inchangé. Le courrier était JUSQU'ICI non scanné (fail-open implicite).
- Quatre défauts trouvés en conditions réelles, tous corrigés : (1) clamd démarré par activation de socket IGNORE `TCPSocket` → écoute TCP déclarée sur `clamav-daemon.socket.d` ; (2) le gabarit Rspamd enveloppait sa conf dans `antivirus { … }` → section imbriquée, « unknown antivirus type », module désactivé en silence — l'antivirus Rspamd n'avait donc JAMAIS fonctionné ; (3) `options.inc` du conteneur mail appartient à l'uid 0 de l'hôte → `task_timeout` écrit côté hôte (l'ajout par lxc-attach échouait en silence, 8 s auraient coupé le scan à froid) ; (4) le contrôle de santé sous `secubox` ne voit pas le conteneur (« ABSENT » à tort) → cache d'état écrit par la partie root.
- 16 tests clamavctl, 9 bats mailctl, 11 tests health-doctor. Arrêt automatique CONFIRMÉ (dernière connexion 18:40, mandataire arrêté 18:50:21, LXC STOPPED, hôte 2,5 Go disponibles) ; état lu sans privilège OK (santé « clamav » ok, veille_normale). Reste : gk3 non déployé (moins de mémoire : 1,4 Go disponibles, swap plein — à mesurer d'abord) ; fail-closed configurable non fait.

## 2026-10-03 — LXC uniquement : retrait des modules docker/podman (ref #1743)
- Décisions de l'exploitant : retirer sept modules du catalogue (hexo, ollama, gotosocial, redroid, simplex, newsbin, voip) **et** Frigate ; aucun n'avait de conteneur en marche (gk2 et gk3). `git rm` des 8 paquets ; références vivantes retirées (arbre des métapaquets + control régénéré par gen-meta, profils, App Store, profils toml, descriptions ai-gateway / mcp-server / peertube). gen-meta a en outre révélé un oubli de mon lot ClamAV : `secubox-clamav` n'était dans aucun métapaquet → ajouté en Suggests du service courrier.
- Agrégateur 0.3.11 : `RETIRED_MODULES` — les modules retirés encore cités dans `/etc/secubox/aggregator.toml` d'une box sont ignorés sans erreur de chargement. 3 tests.
- Test de dépôt `tests/test_pas_de_docker_1743.py` : aucun nouveau fichier ne peut tirer ni piloter docker/podman ; liste `tests/docker-podman-assumes.txt` qui ne peut que rétrécir (dettes nommées : voicestudio ; commentaires historiques jitsi/matrix ; nettoyage photoprism ; outils de migration). 4 tests.
- Déployé : gk2 (dpkg, 54 paquets du lot) et gk3 (apt dist-upgrade) ; 8 paquets purgés sur les deux ; résidus `__pycache__` nettoyés ; LXC `frigate` détruit (gk2 3,6 Go, gk3 750 Mo) après archive des données (/root/archives-1743/*-frigate-donnees.tar.gz) ; paquets retirés du dépôt apt (bookworm, trixie) et dépôt re-signé. Les 60 paquets du lot publiés.
- Pas de paquet « retraits » (proposé puis abandonné sur décision de l'exploitant : liste sans fin, `Conflicts` éternel ; les modules n'étaient que des essais). Derniers restes des 8 modules ôtés de l'image live (liste de masquage), de `audit-packages.py` et de `generate-secubox-yaml.py`.
- Reste #1743 : voicestudio (podman sur l'hôte, conteneur ACTIF sur gk3 : reconnaissance vocale de Lexie) à convertir en LXC natif ; purge de podman/buildah/crun des boxes une fois voicestudio converti ; ligne photoprism (`podman rm` de nettoyage) à retirer quand plus aucune box n'a l'ancien conteneur.

## 2026-10-03 — Test des méta-paquets : cartes Coffre (ref #1743)
- `test_sbxos_pose_tout_le_hall` échouait (avant mes changements aussi) sur « coffre → secubox-coffre, mon-coffre → secubox-mon-coffre ». Cause : la table `PAQUET_DE` du test ne connaissait pas ces deux cartes et devinait des paquets qui n'existent pas. Réalité vérifiée : les deux cartes sont des pages de `secubox-vault` (`/vault/`, `/coffre/`), la carte est livrée par `secubox-webos` (`www/hall/cardlets/coffre.html`) ; gk2 ET gk3 ont vault 2.0.16 et webos 1.0.397 par apt, la page `/coffre/` répond 200 sur les deux ; `sbxos` installe `secubox-vault` (Recommends du service Identité). Rien n'était propre à gk2. Correction : mapping ajouté au test ; 6 tests verts. J'avais d'abord écarté cet échec comme « préexistant » sans l'examiner — à ne plus faire : un test rouge qui touche un module est une question, pas un bruit.
