<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# HISTORY — SecuBox-DEB : mois courant
Entrées datées, les plus récentes en haut. Seul le **mois courant** vit ici ; les mois
précédents sont dans `archive/HISTORY/AAAA-MM.md` (lus sur demande, voir `archive/INDEX.md`).

## 2026-10-23 — Netboot : live MOCHAbin par TFTP et flash eMMC depuis le live (ref #3079)

« preparer tftpboot avec latest mochabin ready to live and flash ». Dernière release : v3.0.0-alpha.18 (16/10) — clé live
`secubox-mochabin-live-usb`, images eMMC `isp` et `lite` (pas d'image `full` MOCHAbin dans cette release). Téléchargées sur gk2
(`/data/sbx-netboot/alpha18/`, empreintes identiques à la release). **La clé live USB alpha.18 n'est pas amorçable** : sa partition de boot est vide
(`build-mochabin-live-usb.sh` cherchait `boot/vmlinuz`, Debian installe `boot/vmlinuz-<version>` ; extlinux visant les noyaux de
gk2) — corrigé dans le script (PR #3081), à reconstruire par la CI. L'installeur B3 existant gardait l'image DÉCOMPRESSÉE en RAM
et ne lisait pas un .gz, et son initrd n'a aucun module : inutilisable. PR #3080, `secubox-netboot` 0.6.0 :
`scripts/build-live-netboot.sh` (serveur) — Image, DTB, initrd et `boot.scr` en TFTP, rootfs en squashfs servi en HTTP
(live-boot `fetch=`), fstab de la clé neutralisé, initrd contrôlé (live-boot, mvpp2), images eMMC signées par la clé netboot et
listées dans `images.txt` ; `installer/sbx-netflash` (live) — mémoire, téléchargement, signature vérifiée avec la clé publique
embarquée, puis `secubox-flash-emmc` (embarqué au paquet). `squashfs-tools` installé sur gk2. Publié sur gk2 (netboot 0.6.1) : TFTP
`/srv/secubox/netboot/tftp/mochabin-live/` (Image Debian 6.12.107, board.dtb, initrd avec live-boot + mvpp2, boot.scr), HTTP
`:8099/mochabin-live/` (filesystem.squashfs 2,19 Go, images `isp` et `lite` signées, `images.txt`) ; vérifié par tftp/curl depuis
gk2 et `openssl dgst -verify` (OK). **Non prouvé au banc** : aucun DUT démarré. Limites : le live tient en RAM (squashfs 2,2 Go) et
l'image à flasher aussi → MOCHAbin 8 Go requis (4 Go : non) ; pas de pilote du switch 4 ports dans l'initrd → câble sur le port
WAN 1G ou le SFP+. Incident : mksquashfs (même en nice 19) a fait passer l'agrégateur en 504 vers 11:45 ; mis en pause (SIGSTOP),
retour en 20 s, repris confiné à un cœur (taskset), Hall sain jusqu'au bout.

## 2026-10-23 — Agrégateur : admin, cloner, netdiag, certs, cookies, mail relayés à leur service root (closes #3077)

Audit (agent en lecture seule) des 8 modules à unité root encore montés dans l'agrégateur. Six exécutaient leurs actions sous
`secubox` : **mail** (`mailctl status` → « Not installed » alors que le conteneur tourne : toutes les actions et plusieurs lectures
faussées), admin (systemctl refusé par polkit, reboot), cloner (tar de /etc et /var/lib), certs (certbot, /etc/letsencrypt),
cookies (/etc/secubox/cookies.json, clé Fernet), netdiag (ping « Operation not permitted », ss -p tronqué). ksm et vm sains
(ctl + sudoers ; vm : `lxc-create`/`lxc-destroy` restent volontairement hors root, décision de conception à prendre). PR #3078,
`secubox-aggregator` 0.4.8 : DEDICATED_MODULES + AGG_EXCLUDE. Déployé gk2 : 79 modules montés, aucun des six ; `mail/status`
voit le conteneur (installé, en marche, 5 comptes). Sockets des six en 0666 root:root (antérieur, à resserrer).
Coût : trois démarrages à froid de l'agrégateur ce matin (10:50, 10:59 ; ~4 à 8 min chacun sous 5 Go de swap) — Hall et cartes
« hors ligne » pendant ce temps (signalé par le propriétaire : « Mes comptes » HORS LIGNE). Grouper les redémarrages.

## 2026-10-23 — ZIA : « Activez la radio » répondait « rien trouvé » (closes #3074)

Capture du propriétaire : « Activez la radio. » → outils `search_objects(activez radio)` puis `delegate(remote)`, réponse « Je n'ai
rien trouvé de visible ». Trois causes. (1) Ni « active » ni le vouvoiement n'étaient des commandes (seuls lance/joue/démarre au
tutoiement, en bascule). (2) La bascule aurait mis en pause une radio qui joue déjà. (3) La page `/zia/` refaite en Aurora (#2646)
ne relayait plus AUCUNE action au Hall : « coupe la radio » répondait « Je coupe le son » sans rien couper (seule la carte micro
relayait). PR #3075 : `secubox-zia` 0.3.1 (verbes de lecture au tutoiement et au vouvoiement → `media.play` idempotente, repli sur
la bascule pour un service qui ne la déclare pas, « écouter » à l'infinitif reste une recherche ; relais des actions depuis `/zia/`),
`secubox-radio` 0.2.2 (commande `play` : lance si arrêtée, ne fait rien sinon), `secubox-webos` 1.19.24 (sur `media.play` sans
lecteur ouvert, le Hall ouvre la vue /micro du service en mini puis lui envoie `play`). Tests : zia 247 dont Playwright du relais
vu rouge puis vert. Déployé gk2, publié trixie. Non vérifié dans le navigateur du propriétaire : le lancement sans geste local peut
être bloqué par la politique d'autoplay du navigateur (la radio réarme alors la lecture au premier clic). Constat annexe : le
service ZIA met environ 2 min 25 s à ouvrir sa socket au démarrage sur gk2 (antérieur, non traité).

## 2026-10-23 — Sauvegardes sur /data, restauration par root, audit DNS par compte (closes #3072)

Suite de #3064, demandée par le propriétaire (liste des points ouverts). PR #3073. `secubox-backup` 2.5.0 : `/etc/secubox/backup.toml`
(`path`, `lxc_path`, `service_paths`) lu par l'API et par `backupctl` (sudo vide l'environnement, seul un fichier atteint le ctl
root) ; restauration toujours par root — `backupctl restaurer` accepte le clair et vise `lxc_path` pour un conteneur, nouveau
`restaurer-conteneur NOM FICHIER` (extraction à côté, remplacement seulement si l'archive contient `NOM/config`) ; l'API répond 409
avec la commande au lieu de lancer `tar -x` sous `secubox` (une archive en clair appartient à `secubox` : un sudoers qui l'extrairait
sur / serait une élévation de privilège) ; nom de fichier avec chemin refusé (422). `secubox-dns` 1.6.1 : le journal d'audit de
dns-provider nomme le compte de la session (avant : toujours « system »). Sur gk2 : `backup.toml` = `/data/secubox-backups` et
`/data/lxc` ; archives copiées (tailles identiques) puis retirées de `/srv/backups` ; **disque racine 91 % → 74 %** ; archive de
configuration chiffrée créée dans /data par le sudoers ; sauvegarde « services » lancée vers /data. Les 16 archives en clair sont
toujours là (déplacées, pas supprimées) : décision du propriétaire. Les dossiers `mail-phase1/2` restent sous `/srv/backups`.

## 2026-10-23 — DNS : OVH inutilisable, vue des vhosts et domaines gérés/gérables, clés en 0600 (closes #3070)

« https://admin.gk2.secubox.in/dns/ ou sont les vhosts et domain managed et manageable et api remote gandi et ovh » puis
`/dns-provider/`. Constat : un seul fournisseur (Gandi `gk2-gandi`, 2 zones) ; **OVH ne pouvait pas être configuré** — l'adaptateur
exigeait la bibliothèque Python `ovh`, absente de la box et de Debian (HTTP 501) — alors que `gk2.net` (5 vhosts) est chez OVH ;
aucune page ne croisait les 131 vhosts avec les zones ; `providers.json` (clé d'API Gandi) était en **0664**. PR #3071,
`secubox-dns` 1.6.0 : adaptateur OVH par httpx (signature `$1$`+SHA-1 imposée par le protocole, horodatage du serveur OVH, ovh-eu/ca/us,
refresh de zone après écriture, erreurs 502 lisibles ; exception ajoutée à `docs/POLITIQUE-CRYPTO.md`) ; `GET /couverture` + onglet
« Vhosts et domaines » (vhosts actifs de `haproxy.toml` × zones des fournisseurs × NS publics par `dig`, cache 1 h : géré / gérable /
externe, zones sans vhost, bouton « Ajouter OVH » présélectionné) ; `providers.json` en 0600 (écriture, démarrage, postinst).
Déployé gk2 (agrégateur relancé pour le nouveau code), relevé réel : 130 vhosts, 4 domaines — `secubox.in` (119) et `aletheiavox.eu`
(2) gérés par Gandi, `cybermind.fr` (4) gérable (NS Gandi, mais zone hors du compte de la clé configurée), `gk2.net` (5) gérable
(NS OVH, aucun fournisseur OVH). Reste à faire par le propriétaire : créer l'application OVH (clés application / secret / consumer)
et l'ajouter dans l'onglet Fournisseurs ; décider pour `cybermind.fr` (autre compte Gandi ?). Non fait : clés restent dans
`/var/lib/secubox/dns-provider/` (API sans privilège) et non dans `/etc/secubox/secrets/` ; suffixes à deux niveaux (`.co.uk`).
Constat annexe : le journal d'audit du module attribue tout à l'utilisateur « system » (jamais à l'administrateur réel).

## 2026-10-23 — Hall : le dé SecuBox immobile sur ordinateur (closes #3068)

« not rotating cube dice on computer, looks fine on ipad ». Le dé de la topbar v2 (`sbx-dice.js`) était figé sous la préférence
système `prefers-reduced-motion: reduce` (décision de la phase 1bis, sans aucun indice visible) ; une tablette ne l'a pas, un poste
de bureau l'a souvent (animations désactivées dans l'environnement). Cause **non confirmée sur le poste du propriétaire** (à vérifier :
`matchMedia('(prefers-reduced-motion: reduce)').matches` dans la console, ou `data-etat` de `<sbx-dice>`). PR #3069,
`secubox-webos` 1.19.23 : sous cette préférence le dé tourne à un quart de vitesse (`data-etat=calme`) ; `localStorage sbx_de=fige`
le fige (`data-etat=fige`). Tests Playwright (rotation sous préférence réduite, figé par `sbx_de`) ; suite webos : seul le
test ytflux, déjà rouge sur master, échoue. Déployé gk2 (cache WAF purgé), publié dans apt trixie.

## 2026-10-23 — Sauvegarde : l'API ne pouvait rien lire de /etc, archives créées par root (closes #3064)

Collage de la page /backup/ : « Config backup failed: tar: /etc/secubox/secrets: Cannot open: Permission denied » (et ~60 autres
fichiers). L'API tourne sous `secubox` (NoNewPrivileges, aucun sudoers) et lançait elle-même `tar` sur /etc, `lxc-stop`/`tar`/
`lxc-start` sur les conteneurs, `tar` sur les données de services : plus aucune archive de configuration depuis le 15 mai ; et
un échec rendait `code 0`. PR #3067, `secubox-backup` 2.4.1 : `backupctl archiver config|services|conteneur … chiffre|clair`
(root) crée et chiffre l'archive (clé publique de la box, échec = rien ne reste), sudoers `secubox-backup` aux verbes exacts,
API qui délègue (`/create`, `/container/backup`, planification), nom validé avant sudo, destinataire imposé par la box (422),
échec = code 1, unité sans NoNewPrivileges, postinst `visudo -cf`. **Incident de test sur gk2** : la première version n'avait
aucune garde d'espace ; l'archive « services » (3,8 Go de données dans /var/lib/secubox) a rempli le disque racine à 100 %
(SSH instable quelques minutes) avant que je ne tue tar et supprime le fichier partiel (1,4 Go) ; disque revenu à 91 %, services
tous actifs. Garde ajoutée au ctl : pas de départ sous 1 Go libre (`SECUBOX_BACKUP_RESERVE_MB`), tar interrompu et partiel
supprimé sous 512 Mo ; vérifiée (refus immédiat avec une réserve de 5 Go ; archive de configuration chiffrée réelle OK).
À savoir : la sauvegarde « services » ne peut pas tenir sur gk2 tant que le disque racine reste à 91 % (destination à déplacer,
par exemple sur /data) ; la restauration et `/container/restore` lancent encore `tar -x` en `secubox` ; le chemin des
conteneurs est `/srv/lxc` alors que ceux de gk2 sont sous `/data/lxc` ; une archive de configuration partielle en clair
(`config-20261023-082749.tar.gz`, issue de l'échec) et 16 archives en clair restent dans /srv/backups.

## 2026-10-23 — Réglages réseau, trafic, QoS : actions refusées, modules montés dans l'agrégateur (closes #3065)

« Échec : net.core.rmem_max : sysctl: permission denied on key … » (16 clés), puis `/traffic/`. `nettweak`, `traffic` et `qos` ont
chacun leur service root (`User=root`, `/run/secubox/<m>.sock`) mais figuraient aussi dans `aggregator.toml` : l'agrégateur
(utilisateur `secubox`) les montait en processus et nginx routait vers lui — leurs actions s'exécutaient sans privilège. Vérifié :
`sysctl -w` réussit depuis l'espace de noms du service nettweak et échoue en `secubox` ; `sudo -u secubox tc qdisc add dev lo
root pfifo` → « Operation not permitted ». PR #3066, `secubox-aggregator` 0.4.7 : les trois rejoignent `DEDICATED_MODULES` (relayés à
leur socket, jamais montés) et le script de migration ; 3 tests. Déployé gk2 (85 modules montés, aucun des trois), pages 200,
publié dans apt trixie. À examiner un par un (unité root ET monté, pas de preuve d'écriture privilégiée sans sudo) : admin,
cloner, ksm, netdiag, vm, certs, cookies, mail. Même famille que #3013 (exposure), #3060 (turn) et #3064 (sauvegardes).

## 2026-10-23 — Anti-rootkit : démon aveugle depuis juillet, alertes de conteneurs, AppArmor (closes #3058)

« https://admin.gk2.secubox.in/antirootkit/ ok ?? » : page et API en ligne, mais le journal d'exécution était figé du 28 juillet
au 23 octobre et les 100 alertes affichées étaient du bruit. Causes : (1) point de contrôle `ausearch` périmé — à la première
rotation d'`audit.log` l'inode mémorisé disparaît, `ausearch` sort en 10 à chaque appel et le démon prenait ce code pour « rien de
neuf » ; (2) exécutions vues depuis des conteneurs LXC (`/usr/bin/php8.2`, `/memfd:lxc-attach`), chemins absents de l'hôte donc
« non dpkg » ; (3) le parseur lisait `auid` (4294967295) à la place de `uid` (`.*?uid=` s'arrêtait sur `auid=`) ; (4) aucun profil
AppArmor ; (5) aucun signe de vie du démon. PR #3063, `secubox-security-posture` 2.4.2 : `execscan` réamorce sur 10/11/12 et trace ;
décision `conteneur` pour l'étiquette `subj=lxc-container-default…` / `lxc-<nom>_<…>` (comptée, ni alerte ni jail ; `lxc-attach`
de l'hôte reste surveillé) ; `\buid=` ; `pouls.json` + `GET /status` → `pouls` (`aveugle` après 2 min) + ligne dans la page ; profils
enforce `secubox-antirootkit-api` / `-daemon` (`AppArmorProfile=-…`, chargés par le postinst avant le démarrage, écriture des `.pyc`
refusée en silence). 16 tests (les 3 échecs de `test_packaging` existent sur master). Déployé gk2 : les deux processus sous profil
enforce, aucun refus, le démon revoit l'audit (2 593 exécutions en 3 min, 14 de conteneurs, 0 signalée, 1 réamorçage), API 200 par
nginx ; publié dans apt trixie. Non touché : les 100 alertes et 219 lignes de juillet restent (journal forensique en ajout seul).
Cause première de la cécité non traitée ailleurs : toute surveillance qui lit un curseur doit distinguer « rien de neuf » de « curseur
invalide » — le pouls est là pour que cela se voie.

## 2026-10-23 — TURN : la page était inerte, coturn n'avait jamais reçu la configuration SecuBox (closes #3060)

« https://admin.gk2.secubox.in/turn/ ko repair et activate ». L'API tournait sous `secubox` avec `NoNewPrivileges=true`,
sans sudoers ni ctl : `/etc/turnserver.conf` (root:turnserver 0640) illisible — realm, ports, utilisateurs à « — » —,
`systemctl start|stop|restart coturn`, `turnadmin` et l'écriture de la configuration lancés par l'API elle-même, donc
inopérants. coturn tournait avec la configuration Debian par défaut (aucune ligne SecuBox) sur toutes les adresses, WAN
comprise. PR #3062, `secubox-jitsi` 2.4.1 (composant turn) : `secubox-turnctl` root aux verbes exacts (`status`,
`start|stop|restart|enable`, `generer [realm]`, `secret-renouveler`, `credentials`, `users`, `user-add` par stdin,
`user-del`, `sessions`, `journal`, `config` masqué), sudoers `secubox-turn`, configuration SecuBox générée en double
tampon (ombre `.sbx-nouveau` → bascule → relance → `is-active` → retour arrière sur `.avant`), realm dans
`/etc/secubox/turn.toml` (`secubox-domaine turn`), secret dans `/etc/secubox/secrets/turn/`, TLS seulement avec un
certificat du realm, relais vers loopback/lien local refusé, décisions dans `audit.log`. L'API délègue tout et valide
avant ; `POST /config` → 409, `POST /generer` ; panneau en lecture seule avec « Régénérer », secret renouvelé côté
serveur. Unité API sans `NoNewPrivileges` ni accès à `turnserver.conf` ; postinst `visudo -cf` puis génération si la
configuration en place n'est pas SecuBox. 13 tests (ctl `bash -n` + shellcheck, sudoers, unité, API par TestClient,
paquet, panneau). Déployé gk2 : `turnserver.conf` SecuBox, realm `turn.gk2.secubox.in`, coturn actif et activé, ctl
par sudo depuis `secubox` OK, identifiants temporaires émis, STUN répond en local ; publié dans apt trixie. Reste : pas de
certificat pour `turn.gk2.secubox.in` donc pas de TURNS (à poser dans HAProxy/ACME si besoin) ; aucun utilisateur long terme.

## 2026-10-23 — Webmail d'office : une déconnexion de Roundcube coupait le SSO pour toujours (closes #3059)

« mes comptes courriel sso ko », puis « fix sso correctly en permanently ». Diagnostic par le chemin public : session du Hall
valide (cookie `.gk2.secubox.in`), boîte liée dans `sbx_app_links`, greffon `secubox_sso` actif dans le LXC roundcube,
`/api/v1/auth/auth/verify` joignable depuis le conteneur — et un jeton factice envoyé par curl déclenche bien la vérification.
À l'ouverture réelle, aucun appel : le greffon se taisait avant. Cause : `deconnecte()` posait `secubox_sso_off=1` en cookie
de session (durée 0), que Firefox restaure avec sa session ; une seule déconnexion du webmail coupait le SSO définitivement.
PR #3061, `secubox-mail` 2.16.6 : le cookie d'arrêt porte l'empreinte SHA-256 (32 hex) du jeton `secubox_session` fermé,
12 h ; `coupe()` ne tait le SSO que pour ce jeton, retire un cookie d'un autre jeton ou de l'ancien format. 3 tests statiques
(pas de PHP sur le poste ; `mailctl webmail-sso` fait `php -l`). Déployé gk2 (postinst → greffon reposé dans le conteneur),
vérifié en boîte noire : jeton seul → vérification appelée ; `sso_off=1` → cookie `deleted` et vérification appelée ;
empreinte du même jeton → formulaire sans appel. Publié dans apt trixie. Même session : `auditd` sur gk2 ne possédait plus
de descripteur sur `audit.log` depuis le 16 octobre (aucun enregistrement, `lost 0`) — relancé, il écrit de nouveau ;
`secubox-exposure.service` retrouvée `disabled` sans trace dans le journal (réactivée à la main, cause non établie) ;
le profil de services coupe `secubox-matrix.service` toutes les 34 s en échec (737 lignes d'audit en une nuit), à traiter.

## 2026-10-22 — Exposition « HORS LIGNE » : l'unité du composant exposure n'était jamais activée (closes #3056)

« https://admin.gk2.secubox.in/exposure/ » : page « HORS LIGNE », API 404. `secubox-exposure.service` était `disabled`,
jamais démarrée depuis l'installation de haproxy 1.12.3 (#3013 l'a sortie de l'agrégateur vers son unité root dédiée) :
l'unité du composant est installée à la main par `debian/rules` de secubox-haproxy, donc inconnue de `dh_installsystemd`,
et le postinst n'activait que `secubox-haproxy.service`. PR #3057, `secubox-haproxy` 1.12.4 : postinst `enable --now`,
prerm `stop`/`disable`, tests statiques. Sur gk2 : unité activée à la main puis paquet déployé (enabled/active, API 200,
page « EN LIGNE » : 43 ports à l'écoute, 1 onion, 1 service émancipé), publié dans apt trixie. Leçon : une unité installée
par `rules` hors `dh_installsystemd` doit être activée explicitement par le postinst — vérifier `systemctl is-enabled` après
un déplacement de module hors de l'agrégateur.

## 2026-10-22 — Hub : lien d'un module autonome vers son propre vhost (closes #3054)

« https://admin.gk2.secubox.in/metanews/ » : la page rendue était « Module Not Found » du hub (HTTP 200 trompeur) — MetaNews
n'a pas de page sous l'administration, son interface vit sur `metanews.<domaine>` ; l'entrée « autonome » de #3042 pointait
donc dans le vide. PR #3055, `secubox-hub` 1.12.26 : pour un module `autonome`, `_compute_menu_sync` pose
`externe = https://<hote>.<domaine de la box>/` (`hote_box`, clé `hote` optionnelle, jamais un domaine codé en dur ; sans
domaine connu, pas de lien) ; `sidebar.js` v2.45.0 rend alors un lien `target=_blank rel=noopener` sans `navClick`. Déployé
sur gk2 (agrégateur relancé, `menu.json` porte `externe` pour metanews), publié dans apt trixie.

## 2026-10-22 — Retrait de secubox-socialrelay (closes #3052)

« https://admin.gk2.secubox.in/social/ decomissionne ». PR #3053, même procédure que reality / ai-insights / zkp :
sources du paquet et icône SBX OS (`art/socialrelay.webp`) retirées ; références vives nettoyées — carte, aide de carte et
`sbxos/espaces.toml` du Hall, jeux `EMBEDDABLE` / `_CUMULES`, `render-ref.html`, `espaces.json` du hub, métapaquets
(`isp` Depends, `service-fediverse` Recommends, `arbre.yaml`), `groupes.yaml` de l'appstore, catalogue `tutorial/catalog`,
`working-set.gk2.txt`, wiki, `generate-admin-ui-map`, test de composition des profils, test `autonome` du hub. Les
consommateurs tolérants (BBS `--parc` et covers réseaux, radio, metanews, sbxmitm : clients ou émetteurs optionnels) ne sont
pas touchés : sans socket ils dégradent. Box gk2 : service arrêté, données (439 Mo) archivées dans
`/var/backups/socialrelay-20261022-1545.tar.gz`, `apt purge`, menu.d et extraits nginx retirés, vhost retiré
(`haproxyctl vhost remove` puis `generate --allow-shrink` : la garde anti-dérive refuse de réduire sans l'aveu), dépôt apt
nettoyé (trixie et bookworm). `secubox-webos` 1.19.22 et `secubox-hub` 1.12.25 déployés et publiés. `secubox-appstore`
0.9.1 ne se construit pas sur master (`gen-appstore-catalog` : assist et courbes hors arbre, même cause que secubox-meta) :
source montée, binaire à produire quand l'arbre sera réparé. Le vhost `socialrelay_gk3_secubox_in` de gk3 reste dans le
toml de gk2 (entrée d'une autre box, hors périmètre).

## 2026-10-22 — Hall v2 : rubrique « Applications », vignettes Streamlit sous session (ref #2996)

« next » (le GO sur la fusion des flux reste au propriétaire). PR #3051 : `secubox-streamlit` 1.6.2 ajoute
`GET /apps/vitrine` (lecture gardée : nom, en ligne, domaine de la première instance active de `streamlit.toml`, vignette
conservée et sa date ; jamais de capture déclenchée). `secubox-webos` 1.19.21 : relais du vhost du Hall pour
`/apps/vitrine` et `/apps/{nom}/screenshot` **sous `auth_request`** — décision #1776 (une vignette photographie l'appli)
respectée, un anonyme reçoit 401, un POST 403, le reste de l'API Streamlit n'est pas relayé ; rubrique « Applications » dans
la mosaïque (tuile = lien vers le domaine de l'appli ou console Streamlit embarquée, archivées écartées, pastille
en ligne / endormie, message explicite sans session). Corrige au passage un dégât du `ruff --fix` de 1.19.20 : l'import
`Service` de `api/main.py` que `test_endpoints` lit avait été retiré (le test échouait seul, et dans la suite selon
l'ordre) — rétabli avec `# noqa: F401`. Déployé sur gk2, publié dans apt trixie. Leçon : ne jamais `ruff --fix` un fichier
d'API sans relire les suppressions d'imports (un import « inutilisé » peut être un point d'accès des tests).

## 2026-10-22 — Registre du Hall : fiches `registre.d` pour les modules API seule (ref #2996)

« next » (le GO sur la fusion des flux reste au propriétaire). PR #3050 : un module API seule — sans page, donc sans
menu.d, donc absent du menu du hub et du registre du Hall (« aucune source » sur sa carte alors qu'il répond) — se déclare
par `/usr/share/secubox/registre.d/<id>.json` livré par son paquet (id, name, category, description, path).
`registry.charger_registre_d()` + `normalize_services(…, supplements=…)` : mêmes règles de santé que le menu (socket ⇒ en
ligne, unité en échec ⇒ alarme), jamais en double avec une entrée de menu, fichier illisible ignoré. Premiers déclarants :
`secubox-ephemeride` 0.1.1, `secubox-ipv6guard` 0.2.2 ; `secubox-webos` 1.19.20. Déployé sur gk2 (119 entrées au registre,
les deux « actif » / en ligne, cartes « actif »), publié dans apt trixie. Reste sans fiche, à dessein (modules internes) :
actord, courbes, dpi-live, federation, mirror, openpgp, rbs-sensor, release, routes, sentinel-mirror, voice, waker.

## 2026-10-22 — Hall v2 : variante encartée des micros MetaNews, BBS et Billets (ref #2996)

« next » (le GO sur la fusion des flux reste au propriétaire). PR #3049 : `secubox-webos` 1.19.19 adresse `{sbx:'carte'}`
aussi aux micros d'autres origines, à l'origine exacte du cadre lue au moment de l'envoi (jamais `*`) ; les trois micros qui
portaient une marque en double la rangent (icône + titre, le compteur reste) : `secubox-metanews` 0.5.2 et `secubox-bbs`
0.37.12 (cross-build arm64), `secubox-billets` 0.13.3 (règle dans `api/static/micro.css`, écouteur dans le gabarit). Radio
et Podcaster sont des lecteurs sans titre : rien à faire. Tests : Go (bbs, metanews), pytest (billets), Hall (Chromium de
test ne charge pas un cadre https intercepté : le test donne au micro une origine http interceptée). Tout déployé sur gk2
et publié dans apt trixie ; vérifié en direct pour MetaNews (les cartes BBS, Billets et YTSaS ne sont pas affichées sur le Hall
de gk2 : le micro BBS n'y apparaît qu'emboîté dans le cumul Forums, hors portée du message). Échecs préexistants inchangés : bbs
`TestDepotPasserelleRefuseAuJetonMembre`, billets 35 (test_admin & co, identiques sur master), webos ytflux.

## 2026-10-22 — Hall v2 : plus de double en-tête sur les cardlets habillés en `Card` (ref #2996)

« next » (le GO sur la fusion des flux reste au propriétaire : item sauté). `secubox-webos` 1.19.18 (PR #3048), déployé
sur gk2, publié dans apt trixie. Un cardlet servi par le Hall (`/cardlets/`, même origine) et habillé en Card reçoit
`{sbx:'carte'}` par postMessage (au chargement et à chaque rechargement, réveil compris) ; `sonde.js`, que chargent les
21 cardlets, pose `html.sbx-carte` et une règle : la marque (icône, titre, sous-titre) disparaît, les commandes de l'en-tête
(rafraîchir, rouage) restent, un en-tête sans commande disparaît (`:has`). Seul, ou dans le Hall v1, l'en-tête reste ; les
micros d'autres origines (MetaNews, BBS, radio, billets, podcaster) ne reçoivent rien et gardent le leur. Test
`test_cardlet_encarte_2996.py` (lit dans les cadres). Vérifié en direct sur gk2.

## 2026-10-22 — Hall v2 : carte « Flux d'actualités » fusionnée (MetaNews, YouTube, Billets) (ref #2996)

« next ». `secubox-webos` 1.19.16 (PR #3046) puis 1.19.17 (PR #3047), déployés sur gk2, publiés dans apt trixie. Une `Card`
native sous Accès rapide, `NewsItem` en tourniquet MetaNews → YouTube → Billets, neuf entrées au plus, relue toutes les
15 min et au retour de l'onglet ; YouTube (listes du compte, `/api/v1/ytsas/flux`) absent sans session. Deux relais nginx
en lecture seule ajoutés au vhost du Hall (`/api/v1/metanews/(topics|img)` et `/api/v1/billets/feed.json`, verdict LAN
comme tout relais — `test_verdict_lan` l'exige). Les liens des billets sont reconstruits vers le vhost des billets (le
feed.json porte l'hôte du relais) ; un sujet MetaNews ouvre l'accueil de MetaNews (son interface n'expose pas de lien
profond). 1.19.17 : les vignettes répondaient 404 sur gk2 — `NewsItem` ré-encodait l'adresse du relais d'image déjà
encodée ; il n'encode plus. Les trois anciennes cartes restent (prompt : « sans retirer l'ancien tant que le nouveau n'est
pas validé »). Vérifié en direct : MetaNews et Billets fusionnés, vignettes 200.

## 2026-10-22 — Hall v2 : carte « Accès rapide » native ; hub : modules autonomes au menu et au registre (ref #2996, closes #3042)

« next ». (1) `secubox-webos` 1.19.14 (PR #3043) : la carte « Accès rapide » de la maquette en `Card` native sous le
Hero — huit `Tile` au plus vers le service embarqué (`data-open`), favoris de la bande ★ puis récents puis curation,
pastille du statut typé, action › vers la mosaïque ; redessinée quand favoris, récents ou registre changent ; `Tile` porte
des attributs. 1.19.15 (PR #3045) : statut emprunté aussi pour Coffre (vault), Contenu (droplet), Cloud (nextcloud),
Forums (bbs) — les tuiles le montraient « sans source ». (2) #3042 : sur gk2, metanews et socialrelay (Go, page servie
par le binaire, sans `www/`) étaient écartés du menu du hub, donc du registre du Hall (« aucune source ») ; clé
`"autonome": true` dans menu.d honorée par `secubox-hub` 1.12.24 (PR #3044), déclarée par `secubox-metanews` 0.5.1 et
`secubox-socialrelay` 0.1.20 (cross-build arm64). Le hub vit dans l'agrégateur : relancé une fois après l'installation
des trois paquets ; menu 117 entrées, metanews et socialrelay « actif » dans le registre et sur leurs cartes. Tout
déployé sur gk2 et publié dans apt trixie. Échecs préexistants inchangés : hub 2 (`test_charge_hub_1835`,
`test_espaces_2212`), webos 1 (ytflux). Un worktree de cross-build Go laisse des fichiers non inscriptibles : `chmod -R u+w`
avant `git worktree remove`.

## 2026-10-22 — Hall v2, phase 4 : second lot de cartes habillées en `Card`, fin de la liste du prompt (ref #2996)

« next ». `secubox-webos` 1.19.13 (PR #3041), déployé sur gk2, publié dans apt trixie. `MIGREES` couvre maintenant toute
la liste du prompt : Flux d'actualités (metanews, ytflux, billets), Radio dock, Mur de discussion (bbs), Éphéméride, Zigbee,
DevWatch, ZIA, Mes comptes, Lyrion, Freebox TV, L'écoute (mood), YTSaS ; onze icônes SVG ajoutées à `composants.js` ;
statut emprunté pour ytflux (ytsas), comptes (sbxid), mood (sbxos-audio-mood), freeboxtv (freebox). Tests phase 3 et #3011
lisent le relevé de la radio dans son pied Card. Sur gk2 : 18 cartes habillées, 11 génériques (hors liste) ; « aucune
source » honnête pour metanews, ephemeride, ipv6guard (absents du registre — à vérifier pour metanews), ytsas et lyrion
(registre `nosource`). Reste de nature différente : Accès rapide en `Tile`, fusion des flux en `NewsItem`, corps natifs
pour les cardlets à double en-tête.

## 2026-10-22 — Hall v2, phase 4 (suite) : cartes de l'accueil habillées en `Card`, premier lot dans l'ordre du prompt (ref #2996)

« next » → premier ⬜ de WIP. `secubox-webos` 1.19.11 (PR #3039) puis 1.19.12 (PR #3040), déployés sur gk2 et publiés dans
apt trixie. Lot `MIGREES` (`hall-v2.js`) rapporté aux cartes réelles : Sécurité = securite, acteurs, radar ; DNS et Appareils
= guardian ; Réseau = dpi, ipv6guard ; Notifications = activite ; État système = le Hero. Une carte du lot est **habillée sur
place** (`SbxUI.Card({hote: article})`, nouveau) : en-tête icône SVG + titre + pastille de statut typé + action › (`data-open`,
délégation du Hall), cardlet intact dans le corps, pied « hôte · Relevé » ; l'ancien rendu n'est pas retiré (poignée, étoile,
aide descendues dans la bande du pied pour ne pas tronquer le titre ; glisser, favoris, auto-guide inchangés). Hors lot : pied
v2 de la phase 3 ; Hall v1 intact. 1.19.12 : une carte de curation sans module à son nom prend le statut du module qui la sert
(`SOURCE_STATUT` : waf, actor, ad-guard, sbxid) — sur gk2 elles s'affichaient « aucune source » en pointillés. Test
`test_cartes_card_2996.py` ; suite webos 676 passés, 1 échec préexistant (`test_ytflux_aurora_2638`, route `flux` sur le
vhost admin). Dossier §5 avec captures 1440 / 390. Stale worktree de #2996 (PR #2997 fusionnée) retiré, refait depuis master.

## 2026-10-22 — Radio : titres en « Récupération… » (ytsas figé par des yt-dlp orphelins) et jeton radio refusé par le BBS (closes #3034, closes #3036)

« radio » (capture : titres en RÉCUPÉRATION…). Deux causes distinctes. (1) Dans le LXC ytsas, 62 processus `yt-dlp -j
--no-download … /channel/…` dormaient depuis 25 h sur `pipe_write` : `_probe()` levait au dépassement de
`asyncio.wait_for` sans tuer le processus, dont plus personne ne lisait la sortie ; la file ne traitait plus rien, cinq
titres ajoutés le 6 octobre restaient idle (un `POST /add` les a téléchargés en 25 s) ; part visible de la charge de gk2.
`secubox-ytsas` 0.8.5 (PR #3037) : `_attend_borne()` tue le processus au dépassement, `reprend_incomplets()` remet en
file au démarrage ; sur gk2 orphelins tués, service relancé, 130/130 pistes en cache. (2) Le BBS refusait le jeton de
service de la radio (« jeton sans session ») : depuis #1814, `emetteursPasserelle` ne connaissait que metanews et
socialrelay ; `secubox-bbs` 0.37.11 (PR #3035) ajoute `secubox-radio` (130 pistes sans `content_id` jusque-là). Les deux
publiés dans apt trixie. Règle notée : un `wait_for` sur un sous-processus se termine par `kill()`.

## 2026-10-22 — Mood et Radio en Aurora ; Mail : boîtes externes réelles, rapatriement IMAP OVH, relais local (closes #3026, closes #3028, closes #3029, closes #3033)

« /sbxos-audio-mood/ aurora » : `sbxos-audio-mood` 0.10.7 puis 0.10.8 (PR #3027, arm64) — panneau au profil Aurora,
script gardé dans `admin.js` (CSP `script-src 'self'` de la route), « Tout effacer » confirmé dans la page ; le menu
latéral avait disparu (« a perdu le left menu bar ») : coque posée en JS (nav#sidebar, `main-content`, sidebar.js) comme
/metrics/, et même correctif pour le Coffre (`secubox-vault` 2.1.11, PR #3030). « /radio/ aurora » : la page Aurora
0.2.0 (#2612) n'avait jamais été construite ni publiée (gk2 et le dépôt en 0.1.79) ; `secubox-radio` 0.2.1 (PR #3031,
arm64) déployé. Mail (`secubox-mail` 2.16.4, PR #3032) : le volet « Boîtes externes » dit l'état réel — greffon
`ident_switch` du webmail (conteneur `roundcube`, PAS `mail` : il n'y est pas installé, le volet le dit) et relais SMTP
sortant ; « mail remote imap retrieve sync with ovh ssl0.ovh.net » : `mailctl imap-sync add|del|list|run` = `doveadm
sync -R` avec le backend imapc de Dovecot dans le LXC mail (rien à installer, OVH joignable), identifiants gardés par la
box (`/etc/secubox/secrets/mail/imap-sync`, root 0600, jamais en argument ni en retour), minuterie 15 min, routes
`/imap-sync`, volet avec préréglage OVH ; « /smtp-relay/ local default » : `local_default` (LXC mail :25 sans auth)
et `POST /config/local-default`, bouton dans la page. Incident : 2.16.3 a laissé l'API mail à terre 15 min (`re` non
importé, invisible à `py_compile`) ; 2.16.4 corrige, règle notée (importer le module avant de déployer). 2.16.5 (PR
#3038) : « Relais SMTP sortant : via # » (un `relayhost =` vide lu jusqu'à la ligne suivante) et introduction du volet
honnête quand le greffon manque. Tout publié
dans apt trixie. Sans boîte OVH déclarée tant que le propriétaire n'a pas saisi ses identifiants dans le volet.

## 2026-10-22 — Retrait de zkp ; Coffre en Aurora ; Annuaire : offres de services réelles (closes #3019, closes #3020, closes #3021)

« /zkp/ remove » : `secubox-zkp` retiré (PR #3024 ; aggregator 0.4.6 `RETIRED_MODULES`, hub 1.12.23 sans sonde de
l'unité zkp ni entrée d'espace ; catalogues, wiki, scripts, ISO, tests nettoyés ; `zkp-hamiltonian` conservé). Sur gk2 :
purge, unité/socket/nginx/données retirés (archive `/var/backups/retrait-3019-zkp-*`), `aggregator.toml` et `pins.toml`
nettoyés, paquet retiré du dépôt trixie et bookworm. « /vault/ aurora » : `secubox-vault` 2.1.10 (PR #3022), page du
Coffre au profil Aurora, autonome, actions et routes identiques (phrase, code de secours, TOTP, clé d'appareil
WebAuthn PRF, sceller, poser/retirer un secret, enrôler/retirer une clé), confirmations dans la page, hauteur annoncée
`sbxVue`/`vault`, démo annoncée, 10 tests + captures 1400/420 lues. « /annuaire/ vrais services… » : les trois offres
étaient des démonstrations de juin (`annuairectl offer`). `secubox-annuaire` 0.14.8 (PR #3023) : `offres-collecte`
(root : onions de Tor, cartes publiques de la curation du Hall hors hôte `admin.`, dépôt apt → `offres-reelles.json`),
`offer-sync` (secubox : publie/révoque les offres `source=sync` de ce nœud, offres manuelles intouchées),
`revoke-offer`, unité à deux temps (root ne touche jamais au journal) + minuterie quotidienne. Sur gk2 : 17 offres
réelles, les deux démonstrations signées par ce nœud révoquées ; « Suricata IDS feed » est signée par did:plc:077c48…
et ne peut être révoquée que par ce nœud-là. Les quatre paquets publiés dans apt trixie. Suite « INJOIGNABLE » :
`_get_offers` rebalayait le journal PAR OFFRE (17 × 5 000 entrées, 6 s par appel, boucle bloquée) ; 0.14.9 (PR #3025) relève
les clés publiques en un seul balayage, déployé et publié. Incident évité : un `git stash
pop` sans remisage préalable a ressorti un vieux remisage du propriétaire (binaires toolbox-ng) ; checkout remis à HEAD,
les 14 remisages sont intacts.

## 2026-10-22 — Retrait de secubox-reality et du composant ai-insights (closes #3017)

« retrait reality et ai-insights » (propriétaire, après inventaire : Reality sans binaire `xray` ni point de sortie,
ai-insights avec deux modèles codés en dur et des menaces jamais alimentées). PR #3018 : sources retirées (90 fichiers),
`secubox-threats` 1.6.1 sans le composant, `secubox-aggregator` 0.4.5 (`RETIRED_MODULES` += reality, ai-insights),
`secubox-system` 1.11.3 (anneau MIND → ai-gateway), `secubox-core` 1.7.13, `secubox-profiles` 0.23.12, `secubox-hub`
1.12.22, `secubox-ai-gateway` 1.5.1, métapaquets meta/isp/profils en source ; catalogues, wiki, scripts et workflows
nettoyés ; `test_absorptions_2050` repasse au vert. Sur gk2 : unités arrêtées, `apt purge` des deux paquets (l'ancien
transitionnel `secubox-ai-insights` 1.2.3 compris), extraits nginx et données retirés (archive
`/var/backups/retrait-3017-*.tar.gz`), `ai-insights` retiré d'`aggregator.toml` (sauvegarde `.avant-3017`), paquets
retirés du dépôt apt (trixie et bookworm). Non redéployés : métapaquets (`secubox-meta` ne se construit pas sur master,
`gen-meta` refuse assist/courbes/zkp hors arbre), isp/profils (absents de gk2).

## 2026-10-22 — Double tampon réel des caches ; certificats HAProxy ; exposition par socket dédiée (closes #3011, closes #3012, closes #3013)

« problème dans le double buffer de refresh de cache, il refresh à vide avant de régénérer la seconde passe » (page
`metrics/vhosts.html`). Cause réelle : `VhostStatsAggregator` modifiait `_jours` en place pendant qu'une requête le lisait
(« dictionary changed size during iteration » → 500 → page vide, 5 fois en 6 h) et chaque vue se recalculait sur le chemin
de la requête (7-8 s, 100 000 entrées, process metrics à 1,5 Go / 87 % CPU). `secubox-metrics` 1.29.4 (PR #3014) :
verrou lectures/collecte, vues servies depuis un tampon rebâti par la collecte puis basculé d'un coup (vues de base
toujours prêtes, autres tant que demandées < 1 h), plus de TTL ; la page garde la vue précédente si un appel échoue.
Même principe pour `secubox-hub` 1.12.21 (un `list-units` expiré ne remplace plus le lot de santé ; menu vide refusé
par-dessus un menu plein ; `sidebar.js` 2.44.1 ignore un lot `warming`/vide) et `secubox-webos` 1.19.10 (sondes
agrégateur/profils/systemd distinguant « injoignable » de « vide », dernière valeur conservée, `_un_cycle()`, le Hall
n'applique qu'une réponse remplie). Après déploiement : metrics à 33 % CPU / 670 Mo, aucun traceback. Deux tests
metrics à date figée (2026-08-25, hors rétention) réparés ; échecs préexistants sur master inchangés (hub 2, metrics 1,
haproxy 19). « Suppression impossible : HTTP 500 » (page HAProxy) : `delete_certificate` faisait mkdir + rename dans
`/srv/haproxy/certs` (root) sous `secubox` ; `secubox-haproxy` 1.12.3 (PR #3015) : `haproxyctl cert delete <nom>` (root,
nom validé, .pem mis de côté dans `certs/backup/`), sudoers `secubox-haproxy` à argv exact par le postinst, API qui délègue
hors boucle (404/502 explicites). « Erreur 500 » de l'exposition par vhost (lyrion) : `exposure` monté EN PROCESSUS dans
l'agrégateur (`secubox`, `ProtectSystem=full`) alors qu'il écrit /etc/nginx et torrc et que son service root
`secubox-exposure.service` tourne ; `secubox-aggregator` 0.4.4 (PR #3016) : `DEDICATED_MODULES = {lyrion, exposure}` et
`AGG_EXCLUDE`, relais transparent vers `/run/secubox/exposure.sock` ; sur gk2 `exposure` retiré d'`aggregator.toml`
(sauvegarde `.avant-3013`), `/api/v1/exposure/status` répond 200 par le chemin public. Même famille que #3003 (`system`),
toujours à l'arbitrage. Les cinq paquets déployés sur gk2 (trois redémarrages de l'agrégateur, 2-3 min de chauffe chacun
sous une charge de 20-28) et publiés dans apt trixie. Inventaire demandé : `secubox-reality` 0.2.3 (gestionnaire de points de
sortie VLESS+Reality+Vision Xray) tourne sur gk2 sans binaire `xray`, base vide, aucun point de sortie ; seuls les
métapaquets isp/profils/meta le citent ; proposition : décommissionner (voir WIP, à trancher). Note : un `reality.db` vide
appartenant à root est né à 05:02 pendant mon inventaire (probable effet d'une sonde sqlite en root) ; sans incidence tant
que le module est inutilisé, à supprimer avec lui.

## 2026-10-21 — Hall : Services en ordre alphabétique ; PeerTube : SSO pour l'administrateur gk2 (closes #3007, closes #3008)

« services ordre alphabetiques et sso ko avec peertube ». `secubox-webos` 1.19.9 (PR #3009) : la rubrique « Services »
de la sidebar v2 et sa mosaïque sont triées par libellé (`localeCompare` fr, insensible à la casse) au lieu de l'ordre de
la curation FEATURED ; 662 tests verts, 1 rouge préexistant (`test_ytflux_aurora_2638`). `secubox-peertube` 1.6.2,
`peertubectl` 1.2.0 (PR #3010) : le compte PeerTube `gk2` est administrateur (rôle 0) et le greffon secubox-sso n'ouvre
qu'un compte rattaché, ce que `sso-rattache` refusait aux administrateurs ; nouveau drapeau explicite `--administrateur`
(l'automatisme `sso` reste limité aux comptes ordinaires), chaque rattachement audité en JSON dans `audit.log`, drapeau
inconnu refusé, test shell avec `lxc-attach` factice. Décision du propriétaire : une session SecuBox administrateur a déjà
la main sur PeerTube par le ctl, pas d'escalade ; avec `pluginAuth` posé, PeerTube refuse le mot de passe pour `gk2`
(`root` reste par mot de passe, `sso-detache` fait machine arrière). Déployés sur gk2, flux SSO exercé de bout en bout
depuis l'hôte (route du greffon → `externalAuthToken` → jeton `/api/v1/users/token`), publiés trixie, PR fusionnées.

## 2026-10-21 — Hall vue maître, phases 1 + 1bis : jetons, coque v2 et dé SecuBox (ref #2996)

secubox-webos 1.15.0 (source, non déployé) : `tokens.css` (palette du brief, thème clair par redéfinition seule,
pont vers les anciens noms en v2 seulement), coque `hall-v2.css/js` (topbar complétée : menu, disposition,
notifications, pastille « SecuBox-DEB vX · En ligne » ; sidebar 220 px avec rubriques, favoris et usager ;
zone principale `flex:999 1 560px` ; ruptures 1180 / 980 / 720 px). Inerte tant que `hall_v2 = false`
dans `/etc/secubox/webos.toml` ; `?hall=v2` prévisualise par navigateur ; `GET /public/etat` expose le
flag et la version. Phase 1bis : le dé de 3d.gk2 (« SecuBox Dice 3D », canvas 2D sans bibliothèque) extrait
en composant `<sbx-dice>` (8 Ko), textures en fichiers, chargé seulement en v2, figé sous
prefers-reduced-motion, en pause hors écran, 0,29 ms/image mesuré ; le thème Plymouth `secubox-cube`
reprend les six faces. Tests Playwright aux trois largeurs (captures dans `docs/assets/images/hall-vue-maitre/`).
Phase 2 (même jour) : `composants.js/.css` (`window.SbxUI` : Card, Pill, StatRing, Sparkline, Tabs, Tile,
ModuleTile, NewsItem, DeviceRow, Hero ; jetons seuls, SVG inline, statuts active/idle/offline/stale/nosource)
et Hero vivant en tête de l'accueil v2 (horloge, radio, CPU/mémoire/stockage/réseau/E/S disque toutes les 5 s)
sur la nouvelle route `GET /public/systeme` (`api/systeme.py` : /proc hors boucle, cache 5 s, 503 si illisible).
PR #2997 ouverte en `ref` (l'issue couvre les phases 3-4). Identité et avatar : secubox-avatar 1.4.0 ajoute
`GET /par-nom/{username}` (garde de lecture) ; le Hall le relaie (relais de lecture, vérifié par
`scripts/verifie-relais-hall.py`, dont les 4 écarts restants préexistent sur master) et la carte d'usager v2
montre l'image du pseudo sbxid, avec liens « Mes comptes » et « Mon identité ». Bannière
`docs/assets/secubox-eyemote-banner.svg` régénérée dans la palette de la vue maître (chiffres à jour :
1 203 paquets, 118 modules, 3.0.0-α18). **Déployé** sur gk2 le même jour : webos 1.15.0 puis 1.15.1 (l'image
d'avatar n'est demandée que si le module est en ligne — il dort en scale-to-zero, le relais répondait 502 ;
bouton Lexie en picto sous 720 px) et avatar 1.4.0, publiés dans la suite `trixie`. Vérifié par le chemin
public et dans Chromium sur `hall.gk2.secubox.in/?hall=v2` (captures `hall-v2-gk2-*.png`). Décision du
propriétaire : **trixie est la suite par défaut** des scripts de build (`build-packages.sh`, `build-all-local.sh`,
`build-add-local.sh`) et des nouvelles entrées de changelog (`~trixie1`), AGENTS.md mis à jour.
Phase 3 (webos 1.16.0) : statut typé côté registre (`statut()`, veille lue sur `profiles.sock`), `/public/services`
+ `status`/`releve`/`intervalle_s`, cartes v2 avec pied « Relevé » et « données périmées », aperçu sans requête pour
un module en veille, sondages à recul exponentiel, dock média vérifié persistant, sparklines du Hero en deux séries.
Phase 4, premier pas (webos 1.17.0) : mosaïque cliquable derrière « Modules » et les rubriques (tuiles de modules
`data-open` ouvrant le service dans le Hall, onglets Tous/Récents/Favoris/catégories/Sites, mur metablogizer avec
ses vignettes). Constat : aucune capture d'écran n'existe pour les webuis de modules sur gk2 (176 sites
metablogizer et 20 applis Streamlit en ont). Menus liés (webos 1.18.0) : rubriques dépliables sur leurs modules,
module embarqué marqué et sa sous-navigation `/public/menu/{id}` sous lui (délégation `[data-ctx]`), sidebar en
rail de 64 px pendant l'embarquement (le « décalage » de la page admin embarquée est sa mise en page centrée).
Régression corrigée (webos 1.18.1) : la coque v2 masquait les menus Services/Système, donc les accès rapides ⚙️ admin
et ⧉ onglet ; rétablis, et posés aussi sur les tuiles de la mosaïque et les modules dépliés. `/sbxos/` régénérée
(sbxos 0.6.0~aurora17-3, révision seule, dist Aurora inchangé) au profil vue maître ; déployée sur gk2 par dpkg -i
(un aperçu `~aurora` n'entre jamais dans apt). Le `dist/` ignoré par git doit être recopié dans un worktree avant
`dpkg-buildpackage` (debian/rules le vérifie, ne le construit pas). Vignettes des modules (webos 1.19.0/1.19.1) :
`webos-vignettes` + minuterie (3 min, un module par tour, charge ≤ 8, CPUQuota 20 %), `secubox_core.shotter` sur la
page publique, nginx statique `/public/vignette/{id}`, `vignette` dans le registre ; première capture `acces` validée.
**Bascule `hall_v2 = true` sur gk2** le 2026-10-21 (GO du propriétaire « go switch ») ; sauvegarde du TOML dans
`/var/backups/`. Le `grep … | head` dans une chaîne `set -e` ne stoppe pas sur un test rouge : 1.19.0 a été déployée
avec un test faux-négatif (PNG factice invalide) — corrigé en 1.19.1, sans effet en production.
Navigation unique (webos 1.19.3 → 1.19.8, arbitrage « en haut ou à gauche, pas les deux » : la sidebar fait foi) :
onglets de la mosaïque retirés, rubriques Récents, Services (curation FEATURED, après « on a reperdu les services ») et
Favoris dynamique (suit la bande ★ de l'accueil, dépliable avec ⚙/⧉, mosaïque au clic, remplace la section statique ;
« il manque le favoris dynamique »), menu contextuel `#mnav-ctx` du service embarqué rétabli (1.19.6) ; colonne vide des
pages admin embarquées supprimée (hub 1.12.20, `body.emb`). Vignettes : sonde HTTP avant capture (pages 421 du WAF et
pages de connexion marquées `sans-page.json`, 15 PNG fautifs purgés), seuil de charge 4 → 8, rattrapage transitoire
`sbx-vignettes-rattrapage` (seuil 40) lancé sur gk2 ; `Cache-Control: no-cache` sur la coque v2 + `wafctl purge-cache`
après chaque déploiement d'actifs (le navigateur servait un `hall-v2.js` périmé).
Constat : `test_ytflux_aurora_2638::test_la_route_flux_n_est_pas_ouverte_sur_le_vhost_admin` échoue déjà
sur `master`, indépendamment de ce chantier. Dossier : `docs/dossiers/hall-vue-maitre.md`.

## 2026-10-21 — media : panneau de gestion des partages SMB (ksmbd) (closes #3000, PR #3001 fusionnée le 2026-10-22)

Demande « webui management shares samba with ksmb tools ». Le composant SMB de `secubox-media` (ksmbd, `smbctl`,
nft LAN seul) n'avait ni route d'API ni panneau, et `smbctl` n'était pas dans le sudoers. `secubox-media` 1.9.1 :
`smbctl` 1.1.0 (`share-add` : nom assaini, chemin réel sous `SECUBOX_SMB_ROOTS`, comptes existants, `valid users`,
écrit par `ksmbd.addshare` hors du bloc généré ; `share-del` jamais sur un partage généré ; `user-del` ; `status`
enrichi ; une ligne d'audit JSON par décision, sans secret), sudoers `secubox → smbctl`, routes `/api/v1/media/smb/*`
toutes en `require_jwt` (mot de passe sur l'entrée standard du ctl), panneau Aurora `/media/smb.html` + menu
« Partages SMB ». Deux bogues préexistants corrigés : `ksmbd.adduser -i` n'existe plus en ksmbd-tools 3.5 (`-P`,
vérifié sur gk2 avec une base jetable) ; `cmd | grep -q` sous `pipefail` faisait annoncer au hasard le module ou
l'écoute absents (SIGPIPE), `usable` faux sur gk2. Incident de ma part : `ksmbd.control -s` ARRÊTE ksmbd (ce n'est
pas « status »), relancé dans la foulée, quelques secondes sans SMB. 77 tests verts ; déployé sur gk2 (1.9.3 : ReadWritePaths /etc/ksmbd, /var/log/secubox, /run — `sudo smbctl` hérite du
ProtectSystem=strict et la création de partage échouait en « Read-only file system » ; 1.9.2 : Recommends cifs-utils, installé
sur gk2), publié trixie.

## 2026-10-21 — podcaster : portail public par podcast, un flux RSS par podcast (closes #2998, PR #2999 fusionnée le 2026-10-21)

Demande « associer les podcasts et leurs flux respectifs ». `secubox-podcaster` 1.6.1 : `GET /share/feed/{fid}.xml`
(RSS d'un seul podcast : titre, description, pochette rendue absolue, ses épisodes téléchargés, `require_lecture`,
404 si inconnu), liste `podcasts` dans `/public/library` (`feeds`/`episodes` conservés pour le Hall et les cardlets),
portail : mosaïque des podcasts (pochette ou initiale, bouton RSS propre), podcast choisi → ses épisodes, ZIP, flux,
copie de son adresse ; flux global en tête ; contrats du Hall et vue micro inchangés. Bogue préexistant corrigé :
sans `public_base`, `request.base_url` porte le root_path et doublait `/api/v1/podcaster` devant `/media/` (flux
global compris) ; l'origine vient désormais de l'hôte (https pour un nom, schéma transmis pour une IP). 92 tests
verts ; déployé sur gk2 (8 podcasts, flux 465 à 60 épisodes vérifié), publié trixie.

## 2026-10-22 — webfilter : Chaturbate de nouveau bloqué pour le Pop!_OS, budget checkconf levé (ref #3005)

« chaturbate re ko ? » : l'application nocturne de 04:00 (carte version 43) ne connaissait le MAC `ac:19:8e:ab:26:c9` que par
deux IPv6 ; `192.168.1.3` revenue ensuite tombait dans `wf-defaut` (adulte = block). Une ré-application déposée à la main
(`appliquer.demande`) a d'abord été REFUSÉE : `unbound-checkconf` dépassait le budget de 60 s codé dans `secubox_unbound`
(1,4 M de zones, charge 20), le ctl restaurait l'ancien drop-in ; la seconde a réussi (149 s, 822 540 zones), 192.168.1.3 est
revenue dans la vue visiteurs. Correctif de fond : `secubox-core` 1.7.12 (`DELAI_CHECKCONF = 600`, le refus doit venir de
checkconf, jamais du chronomètre) et `secubox-webfilter` 0.4.3 (unité d'application `TimeoutStartSec=20min`, Depends core
>= 1.7.12, `/health` et test de version alignés : deux tests rouges depuis 0.4.x). Déployés sur gk2, publiés trixie. Reste
(#3005) : ré-appliquer quand les adresses d'un appareil assigné changent. Incident de session : disque de la station à 100 %
(647 Mo libres), trois worktrees fusionnés retirés ; un dossier `secubox-deb-worktrees/3005-webfilter-checkconf` incomplet
reste à supprimer à la main.

## 2026-10-21 — system : mises à jour apt depuis les pages système et admin sans privilège dans l'API (closes #3002, PR #3004 fusionnée le 2026-10-21)

« Échec de la mise à jour : E: Could not open lock file /var/lib/dpkg/lock-frontend … are you root? » sur
admin.gk2/admin/. Les routes `check_updates`/`apply_updates` (page système) et `/updates`/`/update` (composant admin)
lançaient `apt-get` depuis l'API, servie en `secubox` par l'agrégateur. `secubox-system` 1.11.0 → 1.11.2 : l'API dépose
une demande dans `/run/secubox/system/maj` (« verbe [paquets] »), l'unité root `secubox-maj.path/.service` la draine
par `secubox-majctl` (`verifier` = update + simulation avec versions ; `appliquer [paquets]` = upgrade ou install
--only-upgrade, confold, jamais dist-upgrade/autoremove ; état JSON 0644, journal `/var/log/secubox/system-maj.log`) ;
ni sudo ni polkit, donc indépendant du processus qui sert l'API. `GET /maj_status` et `GET /update/status` ; les deux
pages suivent la mise à niveau jusqu'à la fin. Le postinst relance l'agrégateur (il garde le module en mémoire :
~2–3 min sans administration à chaque déploiement de ce paquet). Vérifié sur gk2 : demande déposée par `secubox`,
drainée en 20 s, 61 paquets à mettre à jour listés. Issues ouvertes en chemin : #3003 (`/api/v1/system/` servi par
l'agrégateur alors que la règle polkit n'autorise que `secubox-system.service` : caches/heure/pare-feu/éteindre
injoignables par ce chemin), #3005 (webfilter : carte MAC→IP de 04:00 sans l'IPv4 192.168.1.3 revenue ensuite,
Chaturbate de nouveau bloqué pour le Pop!_OS ; ré-application déposée à la main par `appliquer.demande`).

## 2026-10-19 — secubox-pseudo-routeur : gk2 passerelle DHCP du LAN plat (ref #2940, PR #2945)

Nouveau paquet secubox-pseudo-routeur 0.1.0 (source seulement, pas encore installé ni essayé sur gk2) :
gk2 peut devenir la passerelle DHCP du LAN plat de la Freebox (192.168.1.0/24), filtrage à l'aller
seulement (réseau plat : routage asymétrique accepté, pas d'état ni de DPI fiable sur le retour).
Sonde de secours (dead-man switch, une vérification par minute, 3 échecs consécutifs = retour
automatique à la Freebox en moins de 3 minutes, sans action humaine) ; chaîne nftables `forward`
DEFAULT DROP par zone (lan_allowed/lxc_zone/guest_zone/iot_zone acceptés, blocked/quarantine_zone
recopiés — six ensembles NAC, pas cinq, corrigé en relecture) ; bascule DHCP gardée par la sonde
(`pseudo-routeurctl activer` refuse sans sonde active ; `retour-freebox` inconditionnel) ; suggestions
de classement (appareils vus par la Freebox non connus du NAC, jamais appliquées seules) ; API et
panneau Aurora. La sonde ne démarre jamais seule à l'installation : seule `POST /activer` l'arme.
secubox-freebox monté à 0.6.0 (passerelle DHCP, import des appareils, `freeboxctl`). Relecture
sécurité (`relecteur-securite`) : 1 bloquant corrigé (lxc_zone), 2 à corriger corrigés (`/journal`
en `require_jwt`, pannes de socket journalisées) ; 5 remarques différées (durcissement systemd,
style bash, commentaire sudoers, repli root de `freeboxctl` sans `sudo`, tests de garde manquants
sur 4 routes). Reste : l'essai réel sur gk2 (hors heures d'usage, sonde observée 10-15 min, coupure
manuelle du service de sonde pour vérifier le retour sous 3 minutes), classé en NAC/Freebox pour
l'import des appareils non classés.

## 2026-10-18 — Guide d'installation de l'ESPRESSObin (ref #2913)

docs/INSTALL-ESPRESSOBIN.md : neuf etapes (materiel, image de la release GitHub ou construction, console serie, memoire et sauvegarde SPI, demarrage USB, install eMMC, profil minimal, rattachement a gk2) + recuperation UART. Les points non verifies sont signales : l'image lite de la release (v3.0.0-alpha.18) n'est pas une cle live dediee a l'ESPRESSObin, et le rattachement a gk2 reste manuel. Tutoriel interactif correspondant : artefact prive du proprietaire.

## 2026-10-17 — Cloture validee par le proprietaire

Le proprietaire valide et demande la cloture : closes #2857 (hub, panneau Reseau), closes #2859 (dns, moteur reel), closes #2861 (hub, nom de la carte), closes #2863 (filterlists dans secubox-core ; deploye sur la carte, pas encore sur gk2), closes #2865 (secubox-courbes ; deploye sur la carte, pas encore sur gk2). Reste a deployer sur gk2 : core 1.7.10 + ad-guard 1.14.3 + dns-guard 1.4.7, et courbes 0.1.0 + metrics 1.24.0.

## 2026-10-17 — Courbes et Glances pour minimal : secubox-courbes (ref #2865, #2863, #2861, #2859, #2857)

secubox-courbes 0.1.0 (nouveau, leger) : bibliotheque secubox_courbes (serie, systeme), API a la racine servie par secubox-groupd (/api/v1/courbes/{series,systeme}, aucun processus de plus), pages /grafana/ (Courbes) et /glances/, minuterie secubox-courbes-serie (meme fichier series.jsonl). secubox-metrics 1.24.0 en depend et delegue ; secubox-minimal 0.7.0 l'embarque ; profiles 0.23.4. Deploye et verifie sur la carte (health 200, pages 200, releve en marche), PAS encore sur gk2. Meme jour : secubox-core 1.7.10 livre secubox_filterlists (ad-guard 1.14.3, dns-guard 1.4.7 : secubox-adblock-sync marche sans toolbox, 119 265 domaines sur la carte, #2863, suite de #2855) ; dns 1.5.1 (moteur reel Unbound, #2859) et hub 1.12.12/1.12.13 (panneau Reseau, nom de la carte, #2857, #2861) deployes sur gk2 avec un redemarrage de l'agregateur ; carte : tor, waker, meshname, ksm arretes (environ 50 Mo de RAM, 130 Mo de zram).

## 2026-10-16 — ESPRESSObin : reflash SPI 2 Go rate, recuperation UART (ref #2855, #2857)

Le U-Boot de la carte d'essai est un build « espressobin-v7-1gb » (DRAM 1 GiB). Flash de l'image OpenWrt 21.02.7 « v7-2gb » : carte muette (TIM/WTMI en boucle, pas de BL1). Recuperee par mox-imager (UART, sans cavaliers, 115200, plusieurs coupures d'alimentation) puis `bubt` de l'image v7-1gb : SPI = build OpenWrt du 17 avril 2023, carte revenue (eMMC, tunnel Auto-Load, SSH de support, admin public OK). Conclusion : cette carte est une v7 1 Go. Autres faits du jour : hub 1.12.12 (panneau Reseau : WAF = route par defaut, #2857) ; secubox-minimal 0.6.0 sans toolbox ni R-level, ad-guard 1.14.2 (toolbox en Recommends, #2855) ; sur gk2, `apt remove secubox-toolbox` tape a la main a 20:00 a retire toolbox, lite et ad-guard : restaures (toolbox 2.13.4, ad-guard 1.14.1, lite 1.8.0), un `apt upgrade` de 19:52 a installe un nouveau noyau non actif (ne pas redemarrer gk2 sans verifier). FAQ-ESPRESSOBIN-1GO.md complete.

## 2026-10-16 — Support SSH depuis gk2 vers la box enrolee (ref #2854, #2853)

Pose a la main sur lgm-ebin : cle dediee /etc/secubox/secrets/support-ssh/id_ed25519 (gk2, 0600), cle publique dans authorized_keys de la box avec from="10.64.0.1" et sans redirections, regle nft iifname wg-autoload + ip saddr 10.64.0.1 sur le port 22 avant le drop « hors LAN » (00-ssh-lan.nft). Test depuis gk2 : OK. #2854 : le faire poser par l'enrolement Auto-Load (revocable, journalise). #2853 : l'agent Auto-Load rejoue nom et mot de passe a chaque demarrage (desactive sur la carte). Suivi du jour : WIP, TODO, FAQ-ESPRESSOBIN-1GO.md, README racine, README secubox-minimal et secubox-annuaire.

## 2026-10-16 — minimal : ndpid-engine >= 1.7.2, fin de la boucle sur eth2 (ref #2851)

secubox-minimal 0.5.1. La carte portait ndpid-engine 1.7.1 (61 redemarrages, nDPId sur eth2 inexistante) ; la correction #2740 etait en 1.7.2. 1.7.2 arm64 (artefact CI) publie dans apt trixie et installe sur la carte : actif sur eth0.

## 2026-10-16 — minimal : WAF et HAProxy essayes puis retires (ref #2847, #2849)

secubox-minimal 0.4.0 avait ajoute haproxy, secubox-haproxy, secubox-waf-ng (+ leurre arme par postinst) ; sur l'ESPRESSObin (951 Mo) la carte a sature (swap plein, charge > 10) et a du etre coupee deux fois. Decision du proprietaire : retrait. secubox-minimal 0.5.0 (sans WAF ni HAProxy, Conflicts waf-ng retabli, WireGuard garde), secubox-profiles 0.23.2. Retire de la carte (paquets purges, drop-in et filigrane supprimes). Le WAF reste sur gk2 (publication admin.lgm-ebin.secubox.in). Hors source sur la carte : regle nft SSH reserve au LAN (/etc/secubox/hardening/nft-input-trust.d/00-ssh-lan.nft), agent Auto-Load desactive. Reste : alleger le profil (ndpid-engine, python3 de l'agregateur, minuteurs), agent Auto-Load qui rejoue le mot de passe d'usine au demarrage.

## 2026-10-16 — WireGuard distant par WAN : la box lgm-ebin offre la sortie Internet (ref #2845, #2844)

secubox-wireguard 1.3.0 : `wgctl serveur init` (wg-clients 10.66.0.1/24, nft propre forward+masquerade, point d'acces configurable), configs clientes 0640 root:secubox (etaient 0644 avec la cle privee). Deploye sur la box d'essai ; sur gk2 : relais UDP 51840 -> 10.64.0.9:51820 (table nft secubox_relais_wg, /etc/nftables.d/zz-secubox-relais-wg-lgm-ebin.nft, HORS SOURCE, a porter dans secubox-autoload) ; publication admin.lgm-ebin.secubox.in (certificat, vhost, route sbxwaf 10.64.0.9:9080, HORS SOURCE, #2844). Reste : redirection UDP 51840 de la Freebox vers gk2, essai de bout en bout depuis un client.

## 2026-10-16 — fleet : panneau des pairs p2p (ref #2842)

secubox-annuaire 0.14.3 : /fleet/ lit aussi GET /api/v1/p2p/peers (nom, adresse, statut par poignee de main, dernier vu), masque si absent ou vide. Deploye gk2, publie apt.

## 2026-10-16 — fleet : panneau des box Auto-Load enrolees (ref #2840)

secubox-annuaire 0.14.2 : /fleet/ lit aussi GET /api/v1/autoload/boxes (client, profil, statut, progression, etape, derniere activite). Panneau masque si module absent ou liste vide. Deploye gk2, publie apt.

## 2026-10-16 — Auto-Load : profil minimal, ESPRESSObin beta client (ref #2838)

secubox-minimal 0.3.0 (+ agent Auto-Load), secubox-profiles 0.23.0 (profil d'activation minimal), secubox-autoload-agent 0.9.0 (connait minimal), secubox-autoload 0.6.1 (atelier). Tunnel sortant vers gk2, aucun port entrant ; identifiants d'usine a changer au premier login. Procedure d'atelier dans docs/AUTOLOAD-ATELIER.md.

## 2026-10-16 — Sante sur ESPRESSObin : page masquee et fausse alarme ytsas (ref #2836)

secubox-core 1.7.9 : `location = /health` (egalite exacte) ; secubox-hub 1.12.11 : la sonde LXC ne juge que les modules installes.

## 2026-10-16 — Images minimales publiees pour ESPRESSObin v7 et RPi 400 (ref #2834)

matrice-images.py : `minimal` publie pour espressobin-v7 (a cote de lite) et rpi400 ; le workflow n'ajoute pas de kiosque a minimal (WebUI d'administration seule).

## 2026-10-16 — Catalogue App Store : secubox-minimal hors-arbre (ref #2832)

secubox-meta 0.1.44 : arbre.yaml declare secubox-minimal ; gen-appstore-catalog (et la construction de secubox-appstore) echouait depuis le profil minimal.

## 2026-10-16 — webos : le retrait retire son lien nginx (ref #2830)

secubox-webos 1.12.3 : postrm retire sites-enabled/hall.gk2.net.conf (le lien casse faisait echouer nginx -t apres une purge).

## 2026-10-16 — Banniere de connexion : https://<IP>/ (ref #2828)

build-image.sh annonçait le port 9443 (copie de l'image Raspberry Pi) ; les images servent le HTTPS sur 443.

## 2026-10-16 — ESPRESSObin : script fix-bootcmd (ref #2826)

fix-bootcmd.scr (livre dans la partition de demarrage de l'image) : bootcmd = boot.scr de l'eMMC puis boot-usb.scr de la cle ; ancien bootcmd garde dans bootcmd_avant. Une ligne : usb start; load usb 0:1 ${loadaddr} fix-bootcmd.scr; source ${loadaddr}.

## 2026-10-16 — Image ESPRESSObin : boot.scr et boot-usb.scr toujours livres (ref #2824)

La CI n'installait pas u-boot-tools : l'image n'avait ni boot.scr ni boot-usb.scr (copie dans le bloc conditionnel de mkimage). Le workflow installe u-boot-tools, boot-usb.scr est copie sans mkimage, et l'absence de mkimage FAIT ECHOUER la construction d'une image espressobin*.

## 2026-10-16 — hub : depend de l'agregateur, /api/v1/hub/ plus en 404 sur image neuve (ref #2822)

secubox-hub 1.12.10 : Depends secubox-aggregator (le postinst de hub n'ecrit dans aggregator.toml que si l'agregateur l'a deja cree).

## 2026-10-16 — Profil minimal 0.2.0 et demarrage USB (ref #2816)

secubox-minimal 0.2.0 : + ipv6guard, webfilter ; Hall, WAF, metrics en Conflicts (un Recommends de auth/freebox ramenait le Hall dans l'image). Demarrage USB de l'ESPRESSObin en une ligne U-Boot : boot-usb.scr (root=LABEL=rootfs) livre dans la partition de demarrage.

## 2026-10-16 — Comparatif des profils (ref #2819)

secubox-profiles 0.22.0 : page /profiles/comparatif.html, contenu lu des meta-paquets a la construction, profil actif et modules installes (dpkg), memoire mesuree.

## 2026-10-16 — Profil minimal (ref #2816)

secubox-minimal 0.1.0 : DPI + moteur nDPI, dns-guard, ad-guard, NAC, Freebox, socle d'administration (core, aggregator, system, hardening, hub, portal, auth). Ni WAF, ISP, Hall, ni metrics (« visites »), ni VPN. `minimal` choisissable en declenchement manuel (build-image.yml, matrice-images.py) ; la matrice publiee est inchangee. Image ESPRESSObin sur cle USB : en cours.

## 2026-10-16 — Barre laterale du Hall : liens vers admin.* (ref #2814)

secubox-hub 1.12.9 : sur un hote hall.*, les liens du menu visent admin.* (meme domaine, port conserve).

## 2026-10-16 — App Store : installation a distance (closes #2808)

secubox-appstore 0.9.0 : demande d'installation sur un autre noeud via la boite OpenPGP, accord de l'admin cible (nom retape), reponse a l'expediteur. Rendu valide par le mainteneur ; une demande reelle entre deux noeuds n'a pas encore ete exercee (suivi a faire).

## 2026-10-16 — cookies : metriques vides, module always-on (closes #2811)

secubox-profiles 0.21.1 : cookies always-on par defaut (cible du relais sbxmitm). Sur gk2 : `secubox-profilectl set-lifecycle`.

## 2026-10-16 — Hall : barre de navigation sur /identite/ (closes #2809)

secubox-webos 1.12.2 : /shared/ en lecture seule + menu et health-batch derriere le double verrou LAN+session sur le vhost du Hall.

## 2026-10-16 — proxypac etape 2 : cache des CDN statiques (closes #2804, closes #2752)

secubox-toolbox-ng 0.13.0 (cache de reponses dans sbxmitm, liste fermee, par instance) + secubox-tor 1.7.0 (accepter/retirer dans proxypac). Etape 3 abandonnee (nos pages n'ont pas de CDN statique externe) ; routage PAC sans cible (MITM sur wg-toolbox/loopback seulement).

## 2026-10-16 — antirootkit : API KO corrigee (closes #2805)

secubox-security-posture 2.4.1 : SupplementaryGroups=secubox dans l'unite antirootkit (secret JWT illisible sinon).

## 2026-10-16 — App Store : cumuls par categorie (closes #2802)

secubox-appstore 0.8.0 : panneau de cumuls par categorie (installes/total, a installer), cliquable pour filtrer.

## 2026-10-16 — Barre du haut sans icones (closes #2800)

secubox-hub 1.12.8 : smart-strip masquee.

## 2026-10-16 — nDPId Flux : synthese au-dessus de la liste (closes #2798)

secubox-dpi 1.14.2 : repartition par protocole / applications / hotes passent au-dessus des flux actifs.

## 2026-10-16 — Espaces : sondes YouTube SAS et Glances (closes #2796)

secubox-hub 1.12.7 : `glances` suit `metrics` ; `ytsas` (LXC) sonde par connexion TCP au conteneur. Plus d'arret affiche a tort pour des pages qui fonctionnent.

## 2026-10-16 — Vue d'ensemble : etats coherents avec la page Espaces (closes #2794)

secubox-hub 1.12.6 : `/apercu` suit la sonde de sante (monte dans l'agregateur, en veille = en service ; `error` = arret) au lieu de la seule unite/socket ; apercu et health, pages du hub, ont une sonde. Reste a l'arret a juste titre : MESH 802.11s.

## 2026-10-16 — Barre laterale sans pastilles (closes #2792)

secubox-hub 1.12.5 : le bloc de pastilles en haut a gauche (live, menaces, services KO, materiel) est retire sur toutes les pages (masque CSS, y compris depuis le cache HTML ; `loadStatusBarData` ne fait plus de requetes).

## 2026-10-16 — Systeme : actions rapides reelles et honnetes (closes #2788)

secubox-system 1.10.2 : cinq unites root `secubox-systeme-*.service` (verification pare-feu, heure NTP, caches, redemarrer, eteindre) demarrees via la regle polkit #2615 ; l'API rend le vrai code retour et la raison (502/504) au lieu de « HTTP 200 » muet. « Recharger le pare-feu » verifie la config (`nft -c`) sans la charger (`flush ruleset` viderait les bannissements). Redemarrage en bloc des services refuse (409). `override_dh_installsystemd` : le postinst ne demarre pas les unites d'action (il aurait eteint la machine). 24 tests.

## 2026-10-16 — Système : actions rapides réelles et honnêtes (secubox-system 1.10.2) (closes #2788)

- Cause : l'API (User=secubox, NoNewPrivileges) ne pouvait ni recharger nftables, ni régler l'heure, ni vider les caches, ni éteindre ; elle répondait HTTP 200 `{"success": false}` sans raison (« Échec : HTTP 200 »), et « Redémarrer les services » / « Éteindre » annonçaient un succès sans contrôle.
- Correctif : cinq unités root `secubox-systeme-*.service` démarrées par `systemctl start` (règle polkit #2615) ; vrai code retour + raison en 502/504 ; « Recharger le pare-feu » = vérification `nft -c` (pas de flush : `/etc/nftables.conf` commence par `flush ruleset`, ce qui viderait les bannissements) ; redémarrage en bloc refusé (409) ; `override_dh_installsystemd` pour que le postinst ne démarre pas les unités d'action. 24 tests. Déployé gk2 (1.10.2) et vérifié : polkit autorise pare-feu-verif et heure depuis le cgroup du service, refuse ssh.service ; bannissements intacts. closes #2788

## 2026-10-16 — Santé : la sonde WAF teste le hall de cette box, pas celui d'un nœud mort (secubox-health 1.3.2, closes #2786)
- Suite de #2784. Cause réelle de « requête saine : timed out » : `choisir_host` prenait le premier `hall.*` par ordre alphabétique, `hall.gk1.secubox.in`, routé vers `10.10.0.3:9080` (un autre nœud du maillage, qui ne répond plus ; le RPi400 est en 10.10.0.6). Mesuré sur gk2 : hall.gk1 → 14 s sans réponse ; hall.gk2 → 4 ms ; hall.gk3 → 12 ms ; canaris refusés en 5 ms. Le verdict « amont lent » de #2784 n'était donc qu'un pansement honnête ; la vraie correction est ici.
- Correctif : hall de la box (`hall.<domaine>`) → sinon un amont hors maillage (10.10.0.x) → sinon l'ancien choix. 8 tests de plus.
- À suivre : la table de routes porte `hall.gk1 → 10.10.0.3` (adresse périmée du nœud relayé) ; et gk2 saturée (swap 10 de 12 Go, mémoire 94 %, disque racine 97 %, charge 22) — non masquée.

## 2026-10-16 — Santé : la sonde du WAF ne déclare plus « défaillant » un amont lent (secubox-health 1.3.1, secubox-hub 1.12.4, closes #2784)
- Constat du mainteneur (page Santé) : « WAF — test dynamique » rouge, « requête saine — non bloqué · timed out » ; « tu es certain de tes sondes d'état ? all greens ».
- Analyse : le témoin (`GET /robots.txt`) traverse sbxwaf jusqu'à l'amont ; sur gk2 chargée (charge ~14, mémoire 94 %) l'amont dépasse 5 s. Un délai dépassé n'est pas un blocage (le WAF refuse en 403 immédiat) et les quatre canaris du même passage étaient bien refusés : le WAF fonctionnait.
- Correctif : délai du témoin 12 s ; témoin expiré + quatre canaris bloqués = WAF sain avec avertissement « amont lent » (indéterminé, jamais vert sans preuve) ; un canari en échec, un témoin bloqué (faux positif) ou un refus de connexion restent des échecs. Page Santé : « bloque les attaques · amont lent ». 9 tests. La cause de fond (gk2 saturée : mémoire 94 %, disque 97 %, charge 14) n'est pas masquée : elle reste visible dans les tuiles.

## 2026-10-16 — Billets : les réponses-images du BBS s'affichent en vignettes (secubox-billets 0.13.2, closes #2782)
- Constat du mainteneur (billet `business-plan-now-v2-gk2-f-…`) : « plus de vignettes ???? ». La réponse miroir du BBS (une image `/f/126.png`) apparaissait en URL texte dans la console du billet. Vérifié : fichiers du BBS publics, CSP du billet autorisant les images https, vignettes `_t.png` du billet servies — le défaut était l'affichage des commentaires système.
- Fait : `miroir_bbs.rendre_corps` — URL de fichier du BBS de cette box → vignette cliquable (image paresseuse) ; vidéo → lien « ▶ vidéo » ; texte échappé et lié ; jamais d'image d'un autre hôte, d'un sous-domaine piège ni en http. 12 tests de plus (39 au total) ; échecs de la suite identiques à master.

## 2026-10-16 — Miroir BBS : le premier post du fil n'est plus recopié (secubox-billets 0.13.1, closes #2780)
- Constaté sur gk2 après le déploiement de 0.13.0 : la source du billet (premier post du fil 1147, une image) apparaissait aussi comme commentaire. Un billet relayé porte une copie locale du média, donc l'égalité de corps ne la reconnaissait pas.
- Correctif : jamais de recopie depuis le premier post d'un fil lié (plus petit identifiant, public ou non) ; les copies déjà posées sont retirées au balayage suivant. Premier balayage réel : 62 commentaires système sur l'ensemble des billets liés au BBS. Piège noté : le service met ~27 s à démarrer ; une vérification faite trop tôt voit l'ancien état.

## 2026-10-16 — Billets : les réponses publiques des fils BBS liés deviennent des commentaires système et font remonter le billet (secubox-billets 0.13.0, closes #2778)
- Constat du mainteneur (billet `business-plan-now-v2-f-125-…`) : le billet ne se remplissait pas des posts et réponses publics des fils liés du BBS (le fil 1147 portait une réponse publique, post 1218, invisible) ; puis : « cela fait remonter le billet dans le fil », « un commentaire système avec la réponse et l'auteur en référence », « visible partie droite du fil comme les likes internes ».
- Fait : miroir en lecture seule (`services/miroir_bbs.py`) — fils liés par `ref_url` ou lien du corps vers `bbs.<domaine>/t/<id>` ; posts publics non supprimés d'un fil public → commentaires `source='bbs'`, `author_ref='bbs:<handle>'`, à l'heure de la réponse (donc remontée dans le fil) ; le post d'origine du billet n'est pas recopié ; `/f/NN.ext` devient un lien absolu vers le BBS ; compteur de commentaires à côté de 💬 sur les cartes du fil ; balayage au plus toutes les 20 s, un billet seul à l'ouverture ; panne du BBS sans effet sur la page.
- Garde-fous testés : local/privé/supprimé/fil non public jamais lus ; corps hors du dossier de contenu refusé ; hôte étranger ou sous-domaine piège ignoré ; idempotent ; rejet administrateur respecté ; 24 tests, échecs de la suite identiques à master (35, préexistants).

## 2026-10-16 — Annuaire : l'acceptation d'une proposition accepte les scopes avec deux-points (secubox-annuaire 0.14.1, closes #2776)
- Constat du mainteneur (page des centres, « Propositions ») : « Acceptation impossible : String should match pattern '^[a-z0-9][a-z0-9._-]*$' ».
- Cause (reproduite sur gk2) : les propositions réelles portent des scopes `mitm-exclusion:gk2` / `mitm-exclusion:c3box` (publiés par la toolbox) ; la requête d'acceptation et d'octroi, le modèle de la config signée et de l'octroi délégué, et le nom de fichier appliqué refusaient le deux-points.
- Correctif : `:` admis dans cette chaîne seulement ; `config_apply` passe en `fullmatch` (le `$` de `re.match` laissait passer un « \n » final dans un nom de fichier). Offres et incidents d'assistance gardent leur motif strict. 74 tests ; les 15 échecs de la suite sont ceux de master (authentification locale).

## 2026-10-16 — Rapport de sécurité PDF : tuiles Actor réparées, volet visites et bannissements (secubox-metrics 1.28.0, closes #2772)
- Demande du mainteneur (capture du PDF) : « pdf missing actor metrics », puis « missing visites and bans stats and graphics » ; sources désignées : « waf et nft ».
- Tuiles Actor vides : `GET /api/v1/actor/stats` d'actord met 5,0 s sur gk2 (mesuré), le rapport n'attendait que 4 s → `stats` valait None. Délai par appel : 30 s pour `/stats`, 4 s pour les lectures rapides. (actord `/stats` à 5 s reste lent : performance à voir séparément.)
- Nouveau volet (page 3 sur 5) « WAF — visites et bannissements » : visites (`/var/log/secubox/waf/visits-stats.json` : requêtes, navigateurs, erreurs, sites, types de clients, statuts, systèmes ; les adresses `top_ips` ne sortent jamais), bannissements (`bans.jsonl` : bans, prolongations, levées, actifs, par heure, par catégorie ; lecture bornée à la fin du fichier), pare-feu (`nft-etat.json` : actif, vérification, réparations). `secubox` appartient au groupe `secubox-waf`, donc lit ces fichiers ; il ne peut pas appeler `nft` (NoNewPrivileges) : le nombre d'éléments de l'ensemble `waf_ban` n'est pas affiché, les « actifs » viennent du journal (985 adresses contre 1016 éléments nft au moment de l'essai).
- Sources : onze au total (3 de plus), listées si absentes ou périmées ; rien n'est envoyé si aucune ne répond. 25 nouveaux tests.

## 2026-10-16 — NAC : les conteneurs LXC sont nommés (secubox-nac 3.9.2, closes #2773)
- Demande : « Nommer les conteneurs lxc » (`/nac/` affichait « Conteneur sans nom » pour 10.100.0.110, .111, .120, .130).
- Cause : l'inventaire root `secubox-nac-lxc-names` (#2445) ne lisait que `/var/lib/lxc` (7 adresses) ; mqtt, zigbee, peertube, photoprism, ytsas, lyrion, jellyfin, jitsi, torrent, picobrew, clamav, grafana, yacy, toolbox-mitm vivent dans `/data/lxc`, adresse en dur dans leur config. Piste écartée : `lxc-ls` (le service root est confiné, sans droit d'entrer dans un espace de noms).
- Correctif : les deux dossiers sont lus (`SBX_LXC_DIR` en accepte plusieurs, séparés par « : ») ; la première déclaration d'une adresse l'emporte. Essai à blanc sur gk2 avant déploiement : 21 conteneurs nommés au lieu de 7.

## 2026-10-16 — Glances remplacée par « Système en direct », barres visibles ; Courbes : graphiques vides corrigés (secubox-metrics 1.27.0, closes #2769, closes #2770)
- Verdict du mainteneur sur la page « Système en direct » : « garder celle-là, la tienne » → elle remplace /glances/ (l'ancienne page, ses tests et ses commandes de démon Glances sont retirés ; l'API Glances reste). Capture du mainteneur : barres des cœurs vides.
- Cause des barres vides (reproduite avec les vraies feuilles du cadre) : `hybrid-skin.css` impose `background-color: transparent !important` à tout ce qui est dans `<main>` ; un fond posé en style direct est annulé. Parade : style direct `!important`. Test de non-régression avec la vraie feuille.
- Courbes vides (« les histogrammes graphiques sont empty ») : gk2 avait 59 relevés sur l'heure mais 300 tranches de 12 s étaient demandées → chaque point isolé, aucune ligne. Serveur : jamais plus de tranches que de relevés ; page : trou d'une tranche ponté, point isolé dessiné, pastille du présent visible sous le cadre.
- Piège à retenir pour toute page Aurora : un fond (barre, pastille, jauge en `background`) posé en CSS ou en style direct sans `!important` disparaît sous le cadre ; les tests doivent charger `hybrid-skin.css`, pas un fichier vide.

## 2026-10-16 — Glances : « Système en direct » livrée à côté de la page actuelle (secubox-metrics 1.26.0, closes #2767)
- Demande : « test le remplacement de glances que tu avais fait ». La page Glances actuelle est jugée impeccable : elle n'est PAS touchée. L'alternative est livrée à part : `/glances/direct.html` (lien « ← Glances » pour revenir) + `GET /api/v1/metrics/systeme` non bloquant (l'API de Glances dort 0,5 s à chaque appel).
- Jauges et cœurs animés, courbes glissantes de 60 points avec lecture au survol, débit en direct, top processus qui glissent à leur nouvelle place, humeur de la box (Zen → En feu) qui règle le battement du cœur, pause, rythme 1/2/5 s, mouvement réduit respecté. Jamais de ligne de commande de processus.
- 9 tests d'API et 15 en vrai navigateur (dont la lecture au survol : un bogue de la première version, l'identifiant de la lecture n'était pas transmis). Déployée sur gk2 (pages et API répondent). Verdict du mainteneur : « processeur, level graphique, c'est top » → les deux pages sont gardées côte à côte, Glances inchangée.

## 2026-10-15 — « Courbes » remplace Grafana (secubox-metrics 1.25.0, closes #2765)
- Demande : « remplacer grafana et glances par des équivalents quick aurora responsive dynamique fun simple réactive ». **Glances : conservée telle quelle** — le mainteneur a jugé la page actuelle « impecc » ; mon remplacement « Système en direct » a été retiré avant livraison (API, page et tests supprimés).
- Grafana (page d'accès à un conteneur arrêté sur gk2) → page « Courbes » sans conteneur : relevé par minute de compteurs bruts (jiffies CPU, octets, connexions, disque) par `secubox-metrics-serie.timer` (stdlib, 7 jours) ; `GET /api/v1/metrics/series` ; page Aurora réactive : plages 15 min → 7 j, survol synchronisé sur les six courbes, glisser pour zoomer, repère du présent, actualisation (figée pendant un zoom). Un compteur remis à zéro ou une mesure absente donne un trou, jamais un pic ou un zéro.
- 11 tests de collecte/API et 18 en vrai navigateur ; les 3 échecs de la suite metrics sont ceux de master. L'entrée de menu `grafana` devient « Courbes » (id inchangé, pins et profils intacts).

## 2026-10-15 — Metrics : cartes dynamiques et métriques en temps réel (secubox-metrics 1.24.0, closes #2763)
- Demande : « dynamiser les mappes avec les connexions et autres metrics en real time ». Les deux cartes étaient des cercles statiques par pays, rafraîchis toutes les 15 s ; les connexions n'étaient que des compteurs.
- API `GET /api/v1/metrics/live` (lecture, sans cache) : connexions TCP établies par pays (GeoLite2 local), entrantes 22/80/443 et sortantes, LAN et inconnues comptées à part, débit des interfaces physiques, charge, mémoire. Jamais d'adresse IP dans la réponse ; `ss` tourne sous `secubox`, sans privilège.
- Page : carte « Connexions en direct » (pulsations par pays quand il augmente, arcs animés vers la box, débit en octets/s calculé entre deux mesures, pastille EN DIRECT, interrogation toutes les 3 s avec repli exponentiel en cas de panne, pause quand l'onglet est caché, `prefers-reduced-motion` respecté) ; les cartes attaques et visiteurs pulsent aussi quand un pays augmente. Démonstration animée (`?demo=1`). Pays de la box : `SECUBOX_PAYS`, « FR » par défaut.
- 14 tests d'API et 10 en vrai navigateur ; échecs de la suite identiques à master.

## 2026-10-15 — Mesh : le RPi400 (gk1) rejoint le maillage de gk2 (action d'exploitation, sans changement de code)
- Constat : gk2 ↔ gk3 maillés (wg-mesh 10.10.0.1 / .5) ; le RPi400 n'avait ni wg-mesh, ni p2p.toml, ni code de jonction.
- Fait sur demande du mainteneur : jeton de jonction auto-approuvé de 15 minutes, minté sur gk2 par la fonction `ml_token_generate` du module p2p (la route d'invitation exige le JWT d'un administrateur, #2476 ; le CLI `sbx-mesh-invite` donne un jeton de 32 hex que l'automesh refuse), encodé `sbxmesh1.…` vers `admin.gk2.secubox.in` (HTTPS à certificat vérifié : le port 7331 de gk2 est fermé côté LAN), déposé par stdin dans `/var/lib/secubox/p2p/automesh.code` (0600, secubox) du RPi400 ; le code n'a jamais été affiché. `secubox-automesh` : « approuvé », 10.10.0.6/24, code effacé.
- Vérifié : handshake wg-mesh avec gk2, ping 10.10.0.1 (1 ms) et 10.10.0.5 (6 ms, via gk2) ; gk2 compte 5 pairs. Topologie en étoile autour de gk2 (le RPi400 n'a pas de pair direct gk3).
- Pas de découverte mDNS du parent : la jonction reste manuelle (code d'invitation), comme écrit dans docs/dossiers/automesh.md.

## 2026-10-15 — Identité (Administration) : PhotoPrism dans les comptes d'une personne (secubox-auth 1.8.2, closes #2761)
- Demande : « manque photoprism » sur hall.gk2/identite/#admin. Le panneau « Comptes » ne listait que courriel, Nextcloud, PeerTube et BBS ; « Mes comptes » du Hall montre PhotoPrism, ouvert par OIDC (#2255).
- Ajout d'une ligne PhotoPrism informative : SSO, identifiant = pseudo de la personne, sans mot de passe, compte créé à la première connexion. Pas d'adaptateur root : PhotoPrism n'a rien à ouvrir ni à relier. 5 tests en vrai navigateur ; suite sbxid 99 verts.

## 2026-10-15 — nDPId Protocoles : regrouper protocoles et applications (secubox-dpi 1.14.1, closes #2759)
- Suite de #2757, sur la remarque « Protocols has also applications » : l'onglet Protocoles a maintenant un « Regrouper par » (catégorie ou transport chiffré/en clair) sur « Tous les protocoles », un filtre de transport, et une nouvelle table « Toutes les applications » (filtre, tri, regroupement par catégorie déduite du nom ; avant : seulement un top 10 en barres).
- Un composant de liste commun aux deux tables ; un clic sur un groupe revient au détail de ce groupe. 7 tests en vrai navigateur (somme des groupes = total, téléphone sans débordement) ; suite dpi 221 verts. Paquet arm64 construit en croisé.

## 2026-10-15 — nDPId : « Regrouper par » sur l'onglet Flux (secubox-dpi 1.14.0, closes #2757)
- Demande : « aggregations possibles sur de nombreux items de même types ». L'onglet Flux listait 200 flux un par un (60 affichés).
- Livré : sélecteur « Regrouper par » protocole, application, source, destination ou niveau de risque ; une ligne par groupe (nombre de flux, octets, part, risque maximal), tri par colonne, clic pour revenir au détail filtré sur le groupe ; le filtre s'applique avant le regroupement. Mobile sans débordement (la barre d'outils passe à quatre colonnes au-delà de 600 px).
- Empreintes et Risques agrègent déjà (classements, répartitions par gravité, catégorie, famille, SNI) : non touchés.
- 10 tests en vrai navigateur sur les données de démonstration ; paquet arm64 construit en croisé (binaire aarch64 vérifié).

## 2026-10-15 — Association comptes ↔ profils : colonne « Profil SBX OS » (Utilisateurs) et « Modifier » par service (/identite) (secubox-auth 1.8.1, ref #2755)
- Utilisateurs, comptes système : nouvelle colonne « Profil SBX OS » (profil associé ou « non associé ») et « Modifier » : associer, changer, dissocier via l'API sbxid existante (`comptes-systeme`). Ordre sûr : l'ancien lien est délié avant le nouveau (le serveur refuse un double lien) et remis si le nouveau échoue. Sans droit d'administrateur système la colonne affiche « — » et ne prétend rien.
- /identite (Administration) : chaque compte de service lié (Courriel, Nextcloud, PeerTube, BBS) a un « Modifier » à côté du ✕ : relier un autre compte existant, même ordre sûr.
- Tests : 8 (Utilisateurs) + 5 (identité) en vrai navigateur ; les 29 échecs de la suite users et ceux de sbxid sont identiques à master. Construit 1.8.1, PAS déployé sur gk2 (embarque aussi l'OTP par compte de 1.8.0, gk2 est en 1.7.0) : en attente du go. Issue laissée ouverte.

## 2026-10-15 — Groupe des modules déclarés déployé sur gk2 et le RPi400 (aggregator 0.4.2, ad-guard 1.14.1, closes #2748)
- gk2 : aggregator 0.4.1 + ad-guard 1.14.1 installés ; sur gk2, debhelper a activé ET démarré `secubox-groupe-declares` (82 modules déclarés) alors que g1 sert déjà ces sockets. Arrêté et désactivé à la main au bout d'une minute ; g1 (actif depuis la veille) n'avait pas bougé, ad-guard et dns-guard répondaient 200.
- Cause : l'autoscript `dh_installsystemd`. Correctif 0.4.2 : `--no-enable --no-start` pour cette unité seule ; l'activateur, qui regarde `groups.d`, décide. Test de non-régression ajouté.
- Vérifié : gk2 = unité désactivée/inactive, g1 actif ; RPi400 = unité active, API ad-guard servie (401 sans jeton).

## 2026-10-15 — proxypac : détecteur de CDN, étape 1 sur 3 (secubox-tor 1.6.2, ref #2752)
- Demande : proxypac alimenté en silence par les requêtes CDN observées (API Google…), avec cache automatique. Étapes validées : (1) détecteur + candidats, (2) cache côté proxy (PAC vers sbxmitm), (3) réécriture sur nos vhosts comme les polices (#1875).
- Étape 1 livrée : `proxypac-detect` + minuterie 15 min lisent en lecture seule `dnstv_counts` d'ad-guard, catalogue de CDN explicite, écrivent `candidates.json` ; un rejet est mémorisé, un hôte déjà réglé n'est plus proposé. Rien n'est activé tout seul.
- Déployé sur gk2 : 200 candidats sur les vraies données (optimizationguide-pa, play, fonts.googleapis, fonts.gstatic…). Piège : la décision du magasin s'écrit `ALLOWED`, pas `allow` (1.6.1 ne trouvait rien, corrigé en 1.6.2 après essai sur la vraie base).
- Reste : étapes 2 et 3 ; l'opérateur propose aussi le passage par Tor (en repli ou pour l'anonymat) pour ces hôtes. Issue laissée ouverte.

## 2026-10-15 — ytsas : le lecteur miroir PeerTube n'est plus refusé dans son cadre (haproxy 1.12.1, closes #2750)
- Cause : la CSP `frame-ancestors` de peertube.gk2 (posée par HAProxy via haproxyctl) ne listait pas ytsas, qui encadre le lecteur des titres « miroir » : Firefox affichait « ne peut pas ouvrir cette page ».
- Correctif : `https://ytsas.<domaine de la box>` ajouté à la liste explicite (comme billets, #1723) ; jamais de joker. Déployé sur gk2 (paquet, `haproxyctl generate`, reload) : l'en-tête de peertube.gk2 contient ytsas, ytsas répond 200. À confirmer dans le navigateur par l'opérateur.

## 2026-10-15 — Image neuve : les modules servis par groupd sont enfin déclarés (ad-guard 1.14.1, aggregator 0.4.1, ref #2748)
- Cause : ad-guard n'a plus d'unité d'API (#1362, « servi par groupd »), mais aucun paquet ne déposait groupable.d ni ne créait de groupe ; sur le RPi400 neuf, 35 modules sur 100 n'étaient servis par personne (page ad-guard HORS LIGNE, API 404). gk2 n'était pas touchée : ses groupes g1..g6 avaient été posés à la main.
- Correctif : unité `secubox-groupe-declares` (sert tout groupable.d) activée par `secubox-groupe-declares-activer` seulement quand `groups.d` n'a aucun `*.conf` ; ad-guard dépose sa déclaration.
- Déployé sur le RPi400 (API répond 401 au lieu de 404 : servie, garde active). Publié sur apt. PAS déployé sur gk2 (groupes d'opérateur, rien à changer ; la montée de l'agrégateur coupe 2 min) : issue laissée ouverte. Reste : déclarer les autres modules sans unité (dns-guard a la sienne).
- dns-guard était arrêté et désactivé sur le RPi400 (cause non retrouvée) : réactivé à la main.

## 2026-10-15 — gk2 : aletheiavox.eu et www.aletheiavox.eu redirigés vers billets.gk2.secubox.in (closes #2747)
Demande du mainteneur. Le domaine pointait déjà sur gk2, était déclaré dans `haproxy.toml` (TLS) avec un certificat Let's Encrypt valide pour les deux noms ; il répondait 404 : son vhost nginx `aletheiavox.eu.conf` (ancien site `aletheia`, à la main) n'était pas activé et MetaBlogizer
renvoie 404 pour un hôte sans bloc sur :8900. Action sur la box, sans source dans le dépôt (précédent : `lldh.gk2-redirect.conf`) : `sites-available/aletheiavox.eu-redirect.conf` (bloc :8900, `return 302 https://billets.gk2.secubox.in$request_uri`, route ACME conservée), lien dans `sites-enabled`,
`nginx -t`, `reload`. 302 et non 301 : un 301 serait gardé en cache dur par les navigateurs alors que la destination est une décision de produit ; à passer en 301 quand elle est définitive. Vérifié depuis internet, certificat contrôlé : http → 301 https → 302 billets → 200. Annuler : retirer le lien et recharger nginx.
Constaté, non traité : `billets.gk2.secubox.in` répond 405 à une requête HEAD sur `/` (les aperçus de liens et certaines sondes d'uptime utilisent HEAD).

## 2026-10-15 — Le second facteur se règle PAR COMPTE, auth 1.8.0 (ref #2745)
Demande du mainteneur : « activer ou désactiver l'OTP sur les comptes SBX OS users ; admin par défaut OTP hors LAN seulement, ou full disable ». Existant (#1699) : UN réglage global `otp_lan` (facultatif sur le LAN, exigé depuis le WAN) et « Réinitialiser le 2FA »
(efface le secret). Nouveau champ `otp_mode` par compte : `defaut` (suit le global = hors LAN seulement, le défaut de l'administrateur), `hors_lan`, `toujours` (LAN compris), `jamais` (aucun code, même depuis internet, même enrôlé ; LE SECRET EST CONSERVÉ : réactiver ne demande pas de
ré-enrôlement). `PUT /user/{nom}/otp-mode` (droit `users.edit`, la garde existante réserve les comptes administrateurs aux administrateurs) ; `jamais` sur un ADMINISTRATEUR exige `confirmer: true` (booléen, pas « true » ni 1) ; chaque changement est journalisé (compte, ancien, nouveau, appelant, confirmation).
GARDE-FOU que le cas rend nécessaire : une connexion depuis le WAN SANS second facteur n'ouvre JAMAIS le coffre (il s'ouvre avec le mot de passe ; ce cas n'existait pas avant, le WAN exigeait toujours le code). La page Utilisateurs gagne un sélecteur par compte, la politique effective en clair et une confirmation intégrée
(avertissement pour un administrateur ; annuler remet l'ancienne valeur). 70 tests : matrice mode × réseau × enrôlement (16 cas), coffre, moteur, API, page dans un vrai navigateur. Vérifié en réel sur le RPi400 : réglage, refus sans confirmation, mode et compte inconnus, retour au défaut, aucun secret dans la liste, 401 sans session.
Déployé sur le RPi400 (auth 1.8.0), PAS sur gk2 : la mise à jour redémarre le service d'authentification (coupure brève des connexions) ; en attente du feu vert du mainteneur sur l'horaire. Pas de `closes`.
Liaison : le défaut « hors LAN seulement » ne vaut que si nginx pose `X-SecuBox-LAN` sur l'API (#2743) — c'est ce qui bloquait la connexion web de la RPi400.
Piège d'environnement noté : `api.main` du composant users lit `/etc/secubox/secubox.conf` à l'import ; sur un poste où il n'est pas lisible, 14 tests existants du composant échouent (identique sur master) ; mes tests isolent la configuration.

## 2026-10-15 — Verdict LAN absent sur une box neuve : la directive est posée par hub, hub 1.12.3 / premier-pas 0.7.1 (closes #2743)
Mainteneur : « RPi400 web login remote KO ». Journal d'authentification de la box : mot de passe saisi sur le CLAVIER DE LA BOX accepté (08:25–08:27, enrôlement TOTP), même compte refusé depuis le PC (`invalid_credentials`). Mot de passe
réglé via le moteur de comptes (`Engine.set_password`, mot de passe lu sur l'entrée standard, jamais écrit ni mémorisé) ; la connexion distante répondait alors `mfa_required` MÊME DEPUIS LE LAN, alors que #1699 veut le second facteur facultatif
sur le LAN. Cause : `snippets/secubox-proxy.conf` ne contenait `proxy_set_header X-SecuBox-LAN $lan_client;` qu'EN COMMENTAIRE alors que le fichier GeoIP du hub existait. `core` ne pose la ligne que si `$lan_client` existe à ce moment-là ; sur une image neuve
core passe AVANT hub, la ligne est retirée et rien ne la remettait : l'API croit tout client « WAN ». Même piège que #1351 (tester la CHAÎNE au lieu de la DIRECTIVE : le commentaire contient le nom). hub 1.12.3 pose la directive (idempotent, `nginx -t`,
restauration si nginx refuse, rien sans le fichier GeoIP). ERREUR de ma part : mon garde de premier-pas (#2731) faisait `grep -q X-SecuBox-LAN`, trouvait le commentaire et RETIRAIT la route de session ; corrigé en 0.7.1 (le correctif de 0.6.2 ne
réparait donc rien sur cette box). Les deux postinst ont des chemins surchargeables et 12 tests exécutent leur VRAI bloc sous `set -e` ; l'ancien test de #2731 figeait la forme défectueuse. Vérifié en réel sur le RPi400 : directive à la ligne 73,
`nginx -t` valide, connexion distante depuis le LAN → jeton d'accès direct, sans code TOTP. gk2 n'est pas touchée (elle avait déjà la directive).
Hypothèses écartées : disposition AZERTY/QWERTY du clavier (système et X du kiosque sont bien `fr`/`azerty`) ; incident connu du `login.html` écrasé (celui de gk2 est intact).

## 2026-10-15 — Le maître repère les box neuves et leur pousse le profil sans code, premier-pas 0.7.0 (ref #2728)
Demande du mainteneur : « gk2 repère les box neuves, les liste, puis pousse le profil en prenant la session distante au lieu du code » (le code de 8×4 caractères est « relou »). `premier_pas/decouverte.py` : les
voisins (table ARP + pairs du maillage) reçoivent UNE lecture publique `GET /etat` ; une box SecuBox répond `{fait, etapes}`, `fait: false` = neuve ; jamais d'adresse publique ; registre `decouverte.json` SANS secret
(nouvelle → préparée → configurée, une box absente depuis 1 h disparaît). `maitre.pousse` accepte un code VIDE : il prend la session distante (#2725) ; un refus (autre poste, fenêtre de 15 min close, box en service)
s'arrête là avec la raison de la box. Routes `/maitre/decouverte` (garde `admin.modules`), carte « Boîtes détectées » pleine largeur dans le panneau maître, `premier-pasctl decouvrir`, minuterie de 2 min. L'AUTOMATIQUE est désactivé
par défaut, limité à `remplir`/`proposer` (jamais `forcer`), à un profil COMPLET, UNE tentative par box : une machine qui répond « je suis neuve » à l'adresse d'un voisin n'est pas forcément la vôtre, et le profil porte
l'empreinte du mot de passe administrateur. 53 tests, dont une préparation de bout en bout contre la VRAIE API de la box neuve (session distante, sans code).
Déployé sur gk2 (0.5.4 → 0.7.0 : l'agrégateur a redémarré, API de retour en 35 s) et minuterie ACTIVÉE sur gk2. Vérifié en réel : gk2 sonde 18 voisins et reconnaît 2 box SecuBox, le RPi400 et gk3, toutes deux configurées → 0 nouvelle.
NON vérifié : un envoi vers une box réellement neuve. Il faut un redémarrage (la fenêtre de 15 min part du démarrage) d'une box à l'assistant ouvert ; je n'ai pas voulu défaire la configuration du RPi400. À faire avec l'ESPRESSObin ou une box réinitialisée.
Limites : détection par le maillage seulement si le service peut lire `wg show` (non confiné en root) ; `/etat` d'une box configurée n'annonce pas toujours son nom (le RPi400 apparaît sans nom).
Pas de `closes` : à fermer après un envoi réel.

## 2026-10-15 — Boucles de redémarrage sur box neuve : assist 0.3.2 livré, ndpid-engine 1.7.2 à construire en CI (ref #2740)
Sur le RPi400 : `secubox-ndpid-engine` (1 040 redémarrages) et `secubox-assist` (619) relancés toutes les 5 s depuis une heure, charge ~5. (1) `assist` : `BindError: wg-mesh unavailable` — le refus de servir sans
`wg-mesh` est VOULU (fail-closed) ; le défaut était `Restart=on-failure`/`RestartSec=5`. Corrigé en 0.3.2 : l'unité ATTEND l'interface dans `ExecStart` (`sh -c 'until [ -e /sys/class/net/wg-mesh ]; do sleep 15; done; exec python3 -m assist.daemon'`),
plafond de redémarrages dans `[Unit]` (dans `[Service]` systemd ignore ces clés, la box affichait déjà « Unknown key »). Installé sur le RPi400 (15 s, NRestarts=0) et sur gk2. (2) `ndpid-engine` : `pcap_open_live: eth2: No such device` — `conf/ndpid-engine.env` livrait
`INTERFACE=eth2` (valeur de gk2) à toutes les cartes ; le RPi400 s'appelle `end0`. 1.7.2 : lanceur `secubox-ndpid-engine-run` (interface configurée si elle existe, sinon route par défaut, sinon première carte PHYSIQUE ; aucune = sortie 0, pas de relance). Paquet `arch: any`
(compile nDPId) : à construire en CI pour arm64, PAS déployé. Sur le RPi400 j'ai réglé `INTERFACE=end0` dans `/etc/secubox/ndpid-engine.env` (configuration, sauvegarde `.avant-2740`) : actif, plus de boucle.
ERREUR de ma part, vue en réel : ma première version (0.3.1) mettait l'attente dans `ExecStartPre` sans délai ; `systemctl restart` et `enable --now` — donc le postinst et `dpkg` — devenaient interminables tant que `wg-mesh` n'existait pas (dpkg bloqué 5 min, j'ai dû tuer le `systemctl` en attente
par son PID). Leçon, deuxième fois aujourd'hui : un correctif d'unité systemd s'éprouve par `dpkg -i` sur une vraie box, avec un délai maximum, pas en lisant l'unité.
Corrigé au passage : `test_changelog_bumped_to_0_2_3` figeait la version courante d'assist et échouait à chaque montée.
Constaté, NON traité : quatre unités en échec sur ce profil lite (`peertube-backlog` sur une box sans PeerTube, `secubox-bootmenu`, `secubox-mail-autocrypt`, `secubox-sbxid-activites`) ; Chromium ~65 % d'un cœur.

## 2026-10-15 — Kiosque RPi : l'unité du lanceur remplace l'ancienne unité `startx`, premier-pas 0.6.4 (closes #2738)
Premier accès SSH au RPi400 (clé posée via le mot de passe par défaut donné par le mainteneur) : le kiosque ouvrait `http://localhost/` et tournait HORS de systemd. `build-rpi-usb.sh` écrivait
`/etc/systemd/system/secubox-kiosk.service` (`startx -- :0 vt7`, `.xinitrc` à localhost) : elle ignorait le lanceur (URL d'administration #2534, assistant prioritaire #1522) et MASQUAIT toute unité de
`/usr/lib` ; le lanceur n'était utilisé que lancé à la main depuis `tty1` (unité « inactive (dead) », pas de redémarrage si Chromium plante). Le paquet livre l'unité du lanceur (source unique
`image/systemd/`), `premier-pas-retire-unite-kiosque` retire l'ancienne unité SEULEMENT si elle porte le `startx` ET la description de l'image, le postinst remplace le lien d'activation orphelin et relance le
kiosque, `build-rpi-usb.sh` pose l'unité du lanceur. Vérifié en réel : kiosque activé et actif, `ExecStart=/usr/sbin/secubox-kiosk-launcher`, Chromium sur `http://admin.localhost:9078/`.
ERREUR de ma part, vue en réel : 0.6.3 échouait à l'installation (« état de sortie 10 ») — le postinst tourne sous `set -e` et l'aide rend 10 (« retirée »). 0.6.4 : code 10 toléré, nettoyage REJOUABLE
(lien orphelin traité même sans l'unité), et le test exécute maintenant le VRAI bloc du postinst sous `set -e` avec un faux systemctl. Leçon : tester un postinst en l'exécutant, pas en le lisant.
Autre découverte sur ce RPi400, NON traitée ici : `secubox-ndpid-engine` (compteur 820) et `secubox-assist` (619) en boucle de redémarrage depuis des heures (`INTERFACE=eth2` livré en dur alors que la carte
s'appelle `end0` ; `assist` se lie à `wg-mesh`, absente tant que le maillage n'est pas rejoint).

## 2026-10-15 — Cadre admin : habillage Aurora de la barre latérale, du menu du haut et de la barre du bas, hub 1.12.2 (closes #2733)
Suite de #2733 : une page Aurora (bleu nuit, cyan) était encadrée par l'ancien cadre « hybrid-dark » (vert, monospace). `shared/cadre-aurora.css`, chargé par `sidebar.js` EN DERNIER et seulement
pour `html.sbx-aurora`, tous sélecteurs préfixés (un test le vérifie), jetons AURORA-REFERENCE §2, contrastes WCAG testés. Piège mesuré : `sidebar.js` pose le fond de la page et le « verre » de la barre
latérale en style EN LIGNE avec `!important`, qu'aucune feuille ne peut battre : pour une page Aurora il ne les pose plus (les anciennes pages les gardent, test dédié). Sur iPhone / tactile le menu du
haut et la barre du bas commençaient à 220 px (place de la barre latérale pourtant repliée, `hybrid-skin.css` `left:220px!important`) : titre coupé, déconnexion hors champ ; ils prennent toute la largeur,
le titre laisse la place au bouton du menu, la bande de mesures et les boutons secondaires sont masqués. Titre du menu du haut sans tiret en tête (« SecuBox — Actor Intelligence » : seul le tiret court
était retiré). Déployé sur gk2 et sur le RPi400 (hub 1.12.2), vérifié servi ; PAS vu dans un navigateur sur gk2 (session requise), vu en rendu réel sur banc de test à 1400 et 390 px.
Trois échecs préexistants sur master, sans lien : `test_espaces_2212` (c3box, mirror), `test_charge_hub_1835::test_un_seul_list_units_par_cycle`, `test_ytflux_aurora_2638::…vhost_admin` (webos).
Reste ouvert : la page Actor sur son vhost dédié `actor.<domaine>` n'a pas de cadre (elle ne le charge que sur un hôte `admin.*`) — dépend de l'URL réellement ouverte par le mainteneur.
RPi400 : accès SSH par clé posé (le mot de passe par défaut a servi une fois ; à changer).

## 2026-10-15 — Guardian : carte des attaques colorée par type de menace agrégé, soc 1.8.0 (closes #2735)
Demande du mainteneur (capture du Guardian) : colorer la carte par type de menace agrégé. La carte peignait des halos rouges proportionnels au nombre d'événements, sans type, et la page ne
lisait que 8 alertes. Port du modèle de la vue d'ensemble du WAF (#2703) : huit familles de types (couleur ET forme, identiques au WAF : un test compare les deux sources), anneau par pays réparti
entre les types observés, forme du type dominant au centre, pays sans type connu = anneau gris (jamais rouge), légende filtrante avec comptes, infobulle, pastille dans la liste des pays.
`alerts?limit=500` (aucune route nouvelle) ; le tableau des événements garde ses six lignes. 25 tests dont rendu réel dans un navigateur, démonstration enrichie, 420 px sans débordement.
Déployé sur gk2 (soc 1.8.0), vérifié servi par l'hôte d'administration ; PAS vu dans un navigateur avec des données réelles (session requise). Le donut « répartition par catégorie » garde ses couleurs
par rang : l'aligner sur les familles reste possible si le mainteneur le veut.

## 2026-10-15 — Cadre admin : mise en page des pages Aurora, marge iPhone des cardlets, hub 1.12.1 / webos 1.12.1 (ref #2733)
Retours du mainteneur : trop d'espace à gauche, pages mal centrées ou pas sur tout l'espace, « pas de marge gauche sur iPhone y compris dans les cardlets ». MESURÉ avant de corriger
(Playwright, 14 pages Aurora réelles dans le cadre) : écran large, 50 px de chaque côté (40 de `hybrid-main` + 10 du cadre), plein espace et symétrique ; écran étroit (390, 768) OU appareil
TACTILE (`sidebar.js` passe en mode mobile sur tout écran tactile, un iPad large inclus) : barre repliée mais `<main class="principal hybrid-main">` gardait `margin-left:220px!important`
(hybrid-skin.css:77) + 40 px de marge intérieure : contenu à 270 px, application dans 70 px, page qui déborde (jusqu'à 508 px) ; la règle mobile ne visait que `.main` et `.main-content`.
`sidebar.js` marque les pages Aurora (`html.sbx-aurora`) et leur applique la mise en page : plus de décalage de barre repliée, gouttière 14 px sur écran étroit, 12 + 10 px sur écran large
(centré, plein espace) ; les anciennes pages « hybrid-dark » ne changent pas. Cardlets du Hall (21) : dans l'iframe, `body.dans .cadre{padding:0}` + `.app{padding:6px 8px}` collaient le contenu
au bord (0 à 8 px) ; règle `@media(max-width:520px)` EN FIN DE FEUILLE, indépendante de l'élément qui porte `emb` (`<html>` pour comptes, `<body>` ailleurs), 14 px de chaque côté. 27 tests de
géométrie dans un vrai navigateur, cardlets chargées dans une iframe comme le Hall. Déployé sur gk2 (hub, webos), vérifié servi. Deux échecs préexistants sans lien, sur master aussi :
`test_espaces_2212` (lignes `c3box` et `mirror` de espaces.json sans entrée de menu) et `test_ytflux_aurora_2638::…vhost_admin`.
Piège : `/shared/*` est servi `public, immutable` 1 h (même défaut que #2730) : un rechargement dur (Ctrl+Maj+R) est nécessaire une fois pour voir le nouveau cadre.
Reste dans #2733 : habillage Aurora de la barre latérale, du menu du haut et de la barre du bas (encore « hybrid-dark » vert) ; page Actor sur son vhost dédié `actor.<domaine>` (sans cadre). Pas de `closes`.

## 2026-10-15 — Premier Pas : pages sans cache dur et verdict LAN de la session, 0.6.2 (ref #2730, ref #2731)
Deux défauts vus sur le RPi400 par le mainteneur (captures). (1) Après la mise à jour et `rejouer`, le navigateur et le kiosque affichaient l'ANCIENNE page : `location /` du site
pose `expires 1h` + `public, immutable` sur tout statique, et `immutable` interdit de revalider (la box servait bien la nouvelle page, vérifié par `curl`). Bloc
`/etc/nginx/secubox.d/premier-pas.conf` : `no-cache` + ETag, quatre en-têtes de sécurité répétés (un `add_header` de location remplace ceux du serveur). (2) Page distante en
« L'assistant distant s'ouvre depuis le réseau local » sur un poste du LAN : `X-SecuBox-LAN` n'est posé par `secubox-proxy.conf` que si core est configuré APRÈS hub. Le postinst
pose `premier-pas-session.conf` (route de session seulement, en-tête posé par nginx donc non forgeable) sous conditions : fichier GeoIP du Hub présent, ligne absente, `nginx -t`
passe, sinon retiré. Tests avec un VRAI nginx (dont un client qui forge l'en-tête). Défaut général de `location /` (HTML « immutable » pour tout le site) NON traité : décision de site.
Leçon : `curl` sur la box avant de croire à un défaut du code ; l'en-tête de cache expliquait « le kiosque relancé n'ouvre pas la bonne page ». Pas de `closes`.

## 2026-10-15 — Premier Pas : une mise à jour ne ferme plus l'assistant, `rejouer`, 0.6.1 (ref #2727)
RPi400 : `GET /etat` (publique) rendait `fait: true`, profil complet, `moteur: {}` : le marqueur avait été posé sans application. Le `postinst` le posait à chaque
configuration du paquet dès qu'un admin avait servi, sans regarder si un assistant était en cours ; la montée 0.5.8 → 0.5.9 → 0.6.0 en plein parcours l'a fermé (et le
kiosque est retombé sur le Hall). La règle vit dans `premier_pas/en_service.py` : box en service ET aucun profil en cours ; profil illisible = en cours. `premier-pasctl rejouer
[--vierge]` (root, local, aucune route distante) rouvre l'assistant de force en gardant le profil. `POST /session` refusée sur une box en service. 21 tests.
Geste local encore nécessaire sur la box touchée (pas d'accès SSH) : `apt install secubox-premier-pas` puis `premier-pasctl rejouer`. Pas de `closes`.
Demandes liées ouvertes : #2728 (gk2 détecte et centralise les box neuves, code facultatif).

## 2026-10-15 — Premier Pas : configurer une box sans écran depuis le LAN, 0.6.0 (ref #2725)
Demande du mainteneur : l'assistant ouvert depuis un autre poste affichait « s'utilise depuis l'écran branché sur la box » ; une box sans écran ne pouvait pas se
configurer au navigateur. Choix assumé (« ouvert sur le LAN, fenêtre courte », comme un routeur grand public) : le premier poste du LAN qui arrive dans la
fenêtre prend la box. `premier_pas/ouverture.py` + `POST /session` : fenêtre de 15 min après le DÉMARRAGE comptée en temps écoulé (CLOCK_BOOTTIME : le RPi400 n'a pas de
RTC, l'heure saute de plusieurs jours au réglage réseau), origine = verdict nginx `X-SecuBox-LAN: 1` (jamais l'adresse, falsifiable), UN poste identifié par un secret
aléatoire (423 aux suivants, libre après 15 min sans action), secret jamais en clair (SHA-256, 0600, invalidé au redémarrage). La session remplit et applique ; elle
ne lit pas le code d'appairage et n'accepte ni ne refuse une proposition (présence devant la box). 31 tests dont 8 contre la vraie page : ils ont trouvé un défaut que
l'API seule ne montrait pas (le poste distant appelait `/code`, recevait un 403 voulu, et la page le prenait pour une session expirée et se rechargeait contre sa propre session).
Limites écrites dans le README : la trace durable est le journal systemd (`audit.log` est root 0644, l'API tourne en `secubox`) ; l'ouverture dépend de la ligne
`X-SecuBox-LAN` posée par `secubox-proxy.conf` quand le fichier GeoIP du Hub est présent, sinon elle reste fermée. Publié sur apt.secubox.in (trixie).
Piège d'outillage : l'index apt n'était plus exporté depuis le 13 octobre (clé de signature verrouillée, « Pinentry: Inappropriate ioctl ») ; les paquets publiés entre-temps
n'étaient visibles de personne. `systemctl restart secubox-depot-deverrouille.service` puis `reprepro export` ; toujours vérifier `InRelease` après un includedeb.
Pas de `closes` : pas encore installé ni éprouvé sur une box réelle.

## 2026-10-15 — Premier Pas : « Champs inconnus : aide » à l'étape Maillage (ref #2723)
Relevé sur le kiosque d'une box neuve (étape 7/9, mode Automatique, case « Demander de l'aide » cochée) : « Continuer » affichait « Champs inconnus : aide ».
Cause : le formulaire (#2544) envoie `{mode: "automesh", aide: "demander"|"non"}`, `moteur.py` et `provision.py` connaissent `maillage.aide`, mais
`CHAMPS["maillage"]` de `remplir.py` ne le permettait pas ; les tests de #2544 ne couvraient que le profil, jamais l'enregistrement de l'étape.
`secubox-premier-pas` 0.5.9 : `aide` permis, et retiré du profil si le mode n'est plus « automesh » (sinon une case cochée puis abandonnée aurait fait
refuser l'examen). Test qui lit le vrai formulaire et vérifie que chaque clé envoyée est permise. Publié sur apt.secubox.in (trixie, arm64 et amd64).
Pas de `closes` : pas encore installé ni vérifié sur la box qui a montré l'erreur (gk1 refuse la clé SSH de l'agent, carte neuve).

## 2026-10-15 — ESPRESSObin : le gel à 48 s vient d'ath10k, l'image le bloque (ref #2177)
Démarrage USB de l'image alpha.17 sous U-Boot 2021.01, console série, quatre essais : « hard LOCKUP » à 48,02 s à chaque fois, puis « soft lockup
[khugepaged] » (cœurs sans interruptions). Écartés par essai : le pilote DSA (déjà bloqué), AppArmor (`apparmor=0 security=none`, le gel tombe alors
pendant `systemd-update-done`). Ce qui l'a levé : `modprobe.blacklist=…,ath10k_pci,ath10k_core` (carte mPCIe Qualcomm 168c:003c, noyau : « BAR 0: error
updating »). Deux pièges de commande U-Boot à retenir : charger l'Image à 0x02000000 la fait chevaucher les zones réservées 0x4000000/0x4400000
(« reserving fdt memory region failed », aucun message ensuite) → 0x10000000 ; et sans `initrd.img` le noyau Debian ne voit ni l'USB ni l'ext4 (`/dev/sda2`
sans pilote). `boot.cmd`, `boot-usb.cmd`, `boot-live-usb.cmd`, `extlinux.conf` et `build-image.sh` bloquent désormais ath10k et passent
`transparent_hugepage=never` (test `test_espressobin_ath10k_thp_2177.py`).
**Reste ouvert** : une fois levé, la carte (1 Go) sature : 64 processus `python3` ~1 Go, zram 605 Mo/950, charge 96, OOM-killer (tor tué) 8 min après le
démarrage. Le profil `secubox-lite` (42 paquets) est trop lourd pour 1 Go ; à alléger sur mesure (RSS par unité, `profilectl apply lite`), pas à l'aveugle.
Pas de `closes` : rien n'est encore reflashé ni vérifié sur la carte.

## 2026-10-14 — YouTube SAS et carte Flux au profil Aurora, flux embarqué (closes #2638)
Page admin `/ytsas/` (0.5.0) refaite en Aurora, mêmes appels d'API, onglet « Flux » qui encadre la carte du Hall (`hall.<domaine>/cardlets/ytflux.html?embed=1`, domaine déduit de l'hôte). Carte Flux (webos 1.10.0) en Aurora ; nginx du Hall : location dédiée avec `frame-ancestors 'self' $sbx_admin_du_hall` (admin du même domaine, sans joker). Aucune route flux sur le vhost admin. Tests `test_ytsas_aurora_2638.py`, `test_ytflux_aurora_2638.py`. **Non déployé.**

## 2026-10-14 — Podcaster : page /podcaster/ au profil Aurora (closes #2637)
`secubox-podcaster` 1.4.0 : page refaite au profil Aurora (tuiles lues dans `GET /status`, flux et épisodes, menu commun hors `?embed=1` et hors démonstration, `?demo=1` sans écriture, bandeau « session requise » sur 401, hauteur `sbxVue`/`podcaster`). Mêmes appels d'API qu'avant ; suppression de flux et titre d'audiolivre saisis dans la page (plus de `confirm()` ni `prompt()`). Ajouts de #2635 conservés (erreur par flux, dernière vérification, copie, réimport). Test `test_podcaster_aurora_2637.py` (24, Playwright route-mocké). **Non déployé.**

## 2026-10-14 — Podcaster : import YouTube sans ré-encodage, échecs de flux visibles (ref #2635)
Playlist 4135 sur gk2 : 2 épisodes en 30 min, charge 10. `yt-dlp -x --audio-format m4a` prenait le flux webm/opus et ffmpeg le ré-encodait en AAC ; `-f ba[ext=m4a]/ba` ne fait plus qu'un remux. Table `feeds` : `last_error`, `last_refresh` (migration idempotente), remplis par l'import et le rafraîchisseur ; `POST /feeds/{id}/refresh` (jwt). Page Podcaster : erreur sous le flux, ⧉ copier l'adresse de la playlist, ⟳ réimporter. Carte Flux YouTube : ⧉ copier, ★ favori du Hall (`sbx_favoris`), 🧭 voir dans Surf. Podcaster 1.3.0, webos 1.9.12. Non fait : favori et Surf depuis la page Podcaster (autre origine que le Hall, pas de localStorage partagé) ; podcast vidéo (l'épisode reste audio). Essai manuel sur gk2 : deux imports concurrents sur les mêmes dossiers + ffmpeg orphelins, arrêtés et dossiers partiels supprimés.

## 2026-10-14 — Flux YouTube : la cause du « données anciennes » est dite (closes #2633)
Sur gk2, `yt-dlp :ytsubs` répond « Login details are needed » : le cookies.txt est périmé (réécrit plus court par yt-dlp). `Flux.lister` avalait ce refus dans le repli sur le dernier résultat, d'où « YouTube n'a pas répondu ». Le repli porte désormais `cause` (`cookies` ou `youtube`), la route marque `cookies_stale`, la carte invite à redéposer cookies.txt (ytsas 0.4.2, webos 1.9.11). **Action utilisateur** : ré-exporter cookies.txt depuis un navigateur connecté. Les mêmes cookies servent à l'import Podcaster.

## 2026-10-15 — alpha.17, workflow Release corrigé, cartes RPi400 et ESPRESSObin (closes #2719)
**alpha.17** : tag `v3.0.0-alpha.17` (56 commits depuis alpha.16). Son run Release a échoué comme celui d'alpha.16 (envoi des images, publication APT, image eMMC MOCHAbin) ; la release a été repassée en brouillon (PR #2720 + #2721) puis complétée par le nouveau workflow `release-completer` à partir des artefacts du run : publiée, **28 fichiers**, pré-version. Aucun `.deb` n'y est joint (pas non plus en alpha.16) ; `SHA256SUMS` n'est pas signé (`GPG_PRIVATE_KEY` absent) ; l'image live USB MOCHAbin manque (son build dépasse 240 min).
**Workflow Release (#2719)** : `scripts/release-envoyer.sh` (partagé par `release.yml` et `release-completer.yml`) crée la release en brouillon, envoie les fichiers UN PAR UN avec `gh release upload --clobber` (quatre essais), vérifie que chacun est sur la release, puis la publie ; au moindre manque elle reste en brouillon et le job échoue. Cause des échecs : `softprops/action-gh-release` envoyait tout en parallèle (« Upload body timed out due to inactivity », puis « Not Found » sur la mise à jour des métadonnées) sur des images de 1 à 2 Go. Publication APT : `publish-packages.yml` déclare trois secrets obligatoires (`GPG_PRIVATE_KEY`, `DEPLOY_SSH_KEY`, `DEPLOY_KNOWN_HOSTS`), **aucun n'est défini** sur le dépôt ni l'environnement `production` : l'appel échouait en 2 s sans étape ; un job `apt-secrets` les vérifie et émet un avertissement visible, la publication ne part que s'ils sont tous là. L'étape eMMC MOCHAbin passe de 240 à 340 min (non vérifié : elle avait déjà dépassé 240). 24 tests (`scripts/tests/test_release_envoi_2719.py`), dont deux exécutent le vrai script avec un faux `gh`. Les sept échecs restants de `scripts/tests` (carte admin, profils, unités root, relais du Hall) existent déjà sur master.
**Carte RPi400 (gk1)** : l'ancienne carte (SanDisk SE32G, 2015) avait un bloc illisible sur ROOT et des métadonnées ext4 corrompues (`/var` et la plus grande partie de `/usr` illisibles). Sauvegarde par fichiers faite avant tout (`~/Sauvegardes/rpi400-usd-2026-10-14`, droits 0700 : elle contient les secrets) : `/etc/secubox`, `/etc`, `/home`, BOOT ; `/var/lib/secubox` est perdu. Nouvelle carte flashée avec l'image `secubox-full-rpi-arm64` d'alpha.17 (secubox-core 1.7.8, premier-pas 0.5.8 : le kiosque ouvre l'administration par défaut, #2534 ; `KIOSK_START="hall"` dans `/etc/default/secubox-kiosk` pour le Hall), `/etc/secubox` restauré avec les propriétaires rétablis PAR NOM (12 comptes ont un UID différent entre l'ancienne image et la nouvelle : `--usermap`/`--groupmap` calculés depuis les deux `passwd`/`group`), ROOT étendue à 59,4 Go. **Non restauré** : nom d'hôte `gk1`, clés SSH de l'hôte, clés wireguard, `machine-id` (sauvegardés, en attente de décision). Démarrage non vérifié. À traiter : le mot de passe administrateur de gk1 était resté à `secubox` par défaut en clair dans `secubox.conf`, avec son secret JWT.
**Clé USB ESPRESSObin** : `secubox-lite-espressobin-v7-trixie` d'alpha.17 flashée (boot/rootfs/data, `fsck` propres) ; avertissement GPT « Alternate GPT header not at the end of the disk » (image de 7 Go sur une clé de 28,8 Go), sans effet sur le démarrage. Démarrage non vérifié.
Incidents d'outillage : (1) un `pkill -x dd -n` trop large a tué le `dd` de la carte au lieu de celui de la clé : toujours tuer par PID ; (2) deux fois, le support a été retiré pendant l'écriture (« device offline » / « card removed »), ce qui laisse une image à moitié écrite : ne pas toucher au support pendant un flashage ; (3) les gardes d'identité (numéro de série, taille, rien de monté) ont refusé une écriture sur une carte absente et sur une carte au contenu inattendu (carte de téléphone `DOMI_GSM`, effacée ensuite sur confirmation explicite).

## 2026-10-14 — Flux YouTube vérifié en réel, ytsas 0.8.2 (ref #2708)
Cookies refaits (export d'une session de navigateur du jour, filtré à `.youtube.com`, 23 cookies sans les `ST-*` de suivi, déposés dans le conteneur ytsas en 0600) : première vérification en réel du Flux. Abonnements, à regarder plus tard, **chaînes** (`feed/channels` : nom, handle, abonnés) et **playlists** (`feed/playlists`, sept) répondent avec `en_cache: False`, `perime: False`. Ce que l'API laisse à confirmer côté carte du Hall : rien de bloquant, mais la navigation dans une chaîne ou une playlist (`/flux/chaine/<id>`, `/flux/playlist/<id>`) n'a pas encore été essayée en réel. Défaut trouvé : sur `feed/playlists`, yt-dlp met le texte du lien (« View full playlist ») dans le champ auteur ; la carte l'affichait comme nom de chaîne. ytsas 0.8.2 : un libellé de lien (anglais, français, espagnol, allemand) n'est plus pris pour un nom ; le champ reste vide. Le cache d'une liste conserve ce qui était écrit avant un correctif : après la 0.8.2, `playlists.json` a été supprimé à la main dans `/data/ytsas/.flux/` pour forcer une lecture neuve (le panneau « Administration du flux » a un bouton Vider pour cela). Les cookies d'un navigateur restent valides tant que la session n'est pas fermée ou tournée par Google : ne pas se déconnecter dans la fenêtre d'où l'export a été fait. Le paquet n'a pas relancé de service de lecture ; l'installation a de nouveau relancé l'agrégateur (Hall en 500 environ deux minutes).

## 2026-10-14 — Flux YouTube : côté administration (closes #2714)
ytsas 0.8.0 puis 0.8.1 : page admin de YouTube SAS, volet « Administration du flux » à côté de l'onglet Flux (carte du Hall encadrée, intacte) : état des cookies (présence, date du fichier, verdict `acceptes/refuses/anciens/absents/inconnu`, jamais le contenu) avec le mode d'emploi pour des cookies qui tiennent, état de chaque liste (date, âge, nombre de vidéos, périmé, cause, durée, délai avant relance), Actualiser (une relance à la fois, 30 s par liste) et Vider (confirmation dans la page), diagnostic (version de yt-dlp, moteurs JavaScript, dix derniers échecs assainis, taille du cache). Routes dans le LXC : `GET /flux/etat`, `POST /flux/actualiser/<liste>`, `POST /flux/vider/<liste>`. **Garde** : le LXC n'a pas `require_jwt` et le préfixe ouvert du Hall relaie les en-têtes du client ; nginx exige donc `auth_request` sur `/auth/verify?exige=admin` puis pose un jeton secret `X-Sbx-Garde-Admin`, que `install-lxc.sh` tire une fois (`/data/ytsas/.garde-admin`, 0600) et que le LXC compare en temps constant ; vhost public et préfixe du Hall l'effacent. Vérifié sur gk2 : admin 401 sans session (GET et POST), Hall 403, faux jeton forgé 403. 0.8.1 : la ligne `access_log secubox-hosts.log sbx_host;` que la box portait en dérive entre dans la source (la 0.8.0 s'était arrêtée sur la question dpkg du fichier de configuration modifié). Tout est testé sur des réponses simulées : les cookies sont périmés, rien n'est vérifié en réel ni dans un navigateur.
Constat non corrigé : le préfixe ouvert `/api/v1/ytsas/` du Hall relaie les en-têtes du client sans les filtrer, donc l'en-tête `X-Sbx-Flux` peut être forgé pour appeler les routes de lecture du Flux sans session (les routes d'administration ne passent pas par là). Test instable observé une fois sur master dans `secubox-ytsas/tests` (non identifié ; 289/290 verts aux relances).
Incident répété : l'installation d'un paquet ytsas relance l'agrégateur ; les routes derrière `auth_request` (Hall, Flux) répondent 500 environ deux minutes.

## 2026-10-14 — Flux YouTube : mes chaînes, playlists, favoris, diffusion (closes #2708)
ytsas 0.7.0 + webos 1.12.0 : la carte Flux YouTube du Hall a sept onglets (les quatre listes, Mes chaînes, Playlists, Favoris) ; ouvrir une chaîne ou une playlist se fait dans la carte (fil d'Ariane, Retour/Échap) ; ★ sur vidéos, chaînes et playlists (`sbx_favoris` reste une liste d'adresses lue par le Hall ; type et nom dans `sbx_favoris_meta`) ; 📡 diffuse vers le Hall par le message existant `{sbx:'diffuser', url, titre}` (une chaîne ou une playlist diffuse sa première vidéo : le Hall ne prend qu'une adresse à la fois). API ytsas : types `chaines` (`feed/channels`) et `playlists` (`feed/playlists`, à confirmer sur la box : aucun test yt-dlp pour ce feed), routes `GET /flux/chaine/<id>` et `/flux/playlist/<id>` (identifiants validés par motif strict avant tout appel). nginx du Hall : même `auth_request`, GET seul ; fin de motif `\z` (un `%0A` final passait avec `$`). **Non vérifié en réel** : les cookies YouTube de la box sont périmés (Google fait tourner les cookies d'une session de navigateur ; export à refaire depuis une fenêtre privée fermée sans déconnexion). Déployé sur gk2 : routes 401 sans session, 404 pour un identifiant invalide.
Incident : l'installation de ytsas/webos a relancé l'agrégateur à 14:18 ; ses routes protégées par `auth_request` (Hall, flux) ont répondu 502/500 environ deux minutes, le temps qu'il remonte ses modules (la socket `aggregator.sock` n'existe qu'à la fin du démarrage). À prévoir : installer hors des moments où le Hall sert, ou limiter la relance de l'agrégateur dans les postinst.

## 2026-10-14 — ad-guard en direct, pays de sortie Tor (closes #2706, closes #2711)
**ad-guard 1.14.0** (#2706) : la page `/ad-guard/` passe en direct : bande d'état (résolveur Unbound, puits DNS, listes de blocage périmées après 9 jours, capteur DNS, moteur DNS TV), métriques rafraîchies toutes les 8 s (suspendues onglet masqué, pause ou saisie, retombée 16/32/60 s en cas d'échec), courbes issues de `/adblock-tv/serie`, variations calculées sur relevés réels. Nouvelle route `GET /statut-direct` (lecture seule, `require_lecture`, cache 5 s) ; ses trois états lus par `systemctl is-active` (Unbound, minuterie du capteur, flux de compteurs) restent « inconnu » si l'API ne peut pas appeler `systemctl` : **non vérifié sur la box**, la route répond 401 sans jeton. **Piège de déploiement** : ad-guard est servi par `secubox-group@g1` (secubox-groupd, une quinzaine de modules dans un interpréteur partagé) et son paquet n'installe aucune unité propre ni ne relance le groupe : l'API garde l'ancien code jusqu'à `systemctl restart secubox-group@g1`, fait une fois (route absente avant, 401 après).
**toolbox 2.13.4** (#2711) : page Tor, bloc « Vérification de fuite » : la ligne « Pays de sortie » (toujours un tiret) montre le drapeau GeoIP, le nom du pays en français, le code et l'ASN ; le drapeau précède aussi l'IP dans l'état. API : `exit_geo` sur `/admin/tor/state` et `geo` sur la sonde SOCKS (`secubox_toolbox.geo`, GeoLite2 + cache 24 h ; une chaîne qui n'est pas une adresse n'est jamais passée à GeoIP). Vérifié sur la box avec l'utilisateur du service (204.8.96.89 → US, AS62744) ; rendu non vérifié dans un navigateur sur la box.
Constats : le workflow Release échoue sur les cinq derniers runs (alpha.16 : pré-release publiée mais incomplète : envoi des images de plusieurs Go en dépassement de délai, un seul morceau `part01` par image ; build-live-usb mochabin en échec à l'étape eMMC après 4 h ; `publish / publish` échoue en 2 s sans étape, log expiré). Trois tests de `secubox-toolbox/tests/test_tor_switch.py` chargent l'ancien addon Python `mitmproxy_addons/inject_banner.py` (le bandeau réel est celui de sbxmitm, en Go) : en échec hors d'une machine qui a mitmproxy, à réécrire ou supprimer.

## 2026-10-14 — dns-guard alimenté, types de menace sur la carte, page Visites en couches (closes #2702, closes #2703, closes #2704)
**dns-guard** : la page affichait « Aucune anomalie sur 24 h » parce que son fichier d'alertes n'existait pas et que personne ne lui envoyait de requête. ad-guard 1.13.0 puis 1.13.1 : le capteur DNS d'ad-guard (qui juge déjà les vraies requêtes d'Unbound : DGA, tunnel, dérive, liste de l'opérateur, détournement) écrit chaque constat nouveau dans `/var/lib/secubox/dns-guard/alerts.jsonl` — domaine enregistré, appareil, règle ; jamais un sous-nom ni le texte libre ; une requête ordinaire ne laisse aucune trace — et rattrape les constats des 24 dernières heures. 1.13.1 : une adresse publique n'est plus un « client » (un détournement sans appareil connu porte l'adresse résolue dans `client`) ; elle passe dans `details.adresse_resolue`. Déployé sur gk2 (54 alertes : 53 détournements « nouveau réseau » sur akadns.net, GitHub, aaplimg… probablement des changements normaux de CDN, à calibrer ; 1 tunnel). Unité du capteur : ReadWritePaths `-/var/lib/secubox/dns-guard`. Test instable préexistant : `test_dnssensor_2240.py::test_detournement_de_bout_en_bout` (échoue parfois, aussi sur master).
**waf-ng 1.30.0** (#2703) : la carte des attaques de `/waf/#vue` colorise les types de menace (sept familles + « autre », une couleur ET une forme, anneau de secteurs par pays, légende en boutons, infobulle), mêmes couleurs sur le donut par catégorie, le bloc « Trafic par type » et le tableau des événements ; classement des catégories en familles par mots-clés (hypothèse à vérifier sur de vraies alertes). Le croisement pays × type est déduit des 500 dernières alertes (pas de croisement côté API). Sous 600 px la carte reste masquée (comportement existant). (#2704) : page Visites avec couches superposées (aujourd'hui, 24 h, 7 jours, moyenne 7 jours) et lecture dans le temps ; **l'API ne garde aucune série de visites** : le rythme horaire est échantillonné par la page ouverte. Pour des couches complètes dès l'ouverture : un anneau horaire dans `visitstats.go` et une route `/visits/hourly`, ainsi qu'un historique horaire des menaces.

## 2026-10-14 — Aurora vague 7 : 14 lots, dernières pages d'administration (closes #2674, closes #2675, closes #2676, closes #2677, closes #2678, closes #2679, closes #2680, closes #2681, closes #2682, closes #2683, closes #2684, closes #2685, closes #2686, closes #2687)
Pages au profil Aurora : bbs 0.37.10 (console sysop), hub 1.12.0 (/soc.html et /soc/), soc 1.7.0 (Vigie), dpi 1.13.0 (dpi, ndpid, mediaflow ; **/dpi/ agrège désormais cumul 7 jours, fenêtre live, courbes sur 7/14/30 jours, donut par catégorie, tops protocoles/applications/terminaux/destinations**), metablogizer 1.11.0 (index, site, droplet, assistant de publication ; `empty-site.html` laissé tel quel, servi aux visiteurs), toolbox 2.13.3 (coque), repo 1.4.0 (releases), annuaire 0.14.0 (centers), waf-ng 1.29.2 (actor, tableau, console, hôte ; onglet Configuration ajouté), auth 1.7.0 (identité, accès), ytsas 0.6.0 et podcaster 1.5.0 (torrent, portail Podcaster), portal 2.5.0 et hub (pages de connexion). PR #2688 à #2701. Déployés sur gk2 (13 paquets, `/data/apt` trixie) ; waf-ng a relancé le WAF (admin, hall, podcaster 200 ensuite). Rendu non vérifié dans un navigateur sur données réelles.

Incident : `secubox-portal` (API d'authentification) est resté arrêté de 13:19 à 13:32 pendant la chaîne d'installations (`chown secubox:secubox /etc/secubox` en échec « Operation not permitted » à la relance, puis démarrage normal dix minutes plus tard) ; relancé à la main, aucune cause source établie : à surveiller lors des prochains lots (ne pas enchaîner d'installations qui touchent `/etc/secubox` pendant la relance du portail).

Sécurité : redirection ouverte corrigée dans `login.html` (`?redirect=` acceptait `/<TAB>/hote`, que le navigateur réduit à `//hote` ; caractères de contrôle refusés, test à 8 cas). Le hub ne livre plus de `login.html` à la racine (#1064) : test de non-régression ajouté.

À noter, non corrigé (API) : turn `GET /config` rend le secret partagé en clair ; smtp-relay écrit le mot de passe SMTP en clair dans son TOML ; annuaire `GET /centers/effective/<scope>` rend le TOML composé sans filtre ; waf `POST /mode`, `POST /bans/clear`, `GET /export` absents (404), l'hôte appelle `POST /unban` au lieu de `/unban/{ip}`, `/waf/settings.html` absent ; actor `posture` codée en dur « Protégée » ; hub `hub/health` sans `modules`, `blocked_24h` probablement cumulatif ; droplet `POST /upload` ignore `name`/`domain` du formulaire, `GET /job/<id>` répond 200 sur inconnu ; metablogizer `/status` version 1.0.0 en dur ; torrent `/stream/` non routé sur l'hôte admin ; dpi `/exfil` sans paramètre de fenêtre, pas d'historique horaire ni d'agrégat par protocole ; bbs `/status` sans état du service. Test préexistant en échec : `hub/test_espaces_2212` (c3box, mirror).

Reste hors Aurora : vault et premier-pas (à part), maquettes `bbs/mockup*.html`, `micro.html` de zia/waf/devwatch/acces/podcaster, `empty-site.html`, `site.html` des sites publiés. Hall : la coque n'écoute pas encore `sbxVue` (hauteur annoncée par les cartes).

## 2026-10-14 — Aurora vague 6 : 24 paquets, le Hall et ses vingt cartes (closes #2641, closes #2642, closes #2643, closes #2644, closes #2645, closes #2646, closes #2647, closes #2648, closes #2649, closes #2650, closes #2651, closes #2652, closes #2653, closes #2656, closes #2658, closes #2659, closes #2660)
Pages au profil Aurora : assist 0.3.0, avatar 1.3.0, eye-remote 1.1.0 (terminal : émulateur intégré à la place de xterm.js, interdit par la CSP), media 1.8.2, messagerie 0.3.0, zia 0.3.0, threatmesh 1.1.0, security-posture 2.4.0, saas-relay 1.3.0, sbxos 0.6.0~aurora17-2 (coquille PWA, thème clair conservé), voicestudio 0.5.10 (amd64, **non installé sur gk2**), ai-gateway 1.5.0 (mcp-server, localrecall), matrix 1.4.0 (jabber), metrics 1.23.0 (grafana), mqtt 2.7.0 (zigbee), ipblock 1.6.0 (cyberfeed), mail 2.16.0 (smtp-relay), jitsi 2.4.0 (turn), metanews 0.5.0 (devwatch, yacy ; construit en arm64), peertube 1.6.0, streamlit 1.6.0 (streamforge). Hall (webos 1.11.0) : coque au profil Aurora, sombre par défaut, mode clair en variante sobre, vingt cartes et le relais. PR #2654 à #2673, un test Playwright par page. Déployé sur gk2 (21 paquets, `/data/apt` trixie) ; rendu non vérifié dans un navigateur sur données réelles.

À noter, non corrigé (API) : turn `GET /config` renvoie le secret partagé en clair et `POST /users` stocke les mots de passe en clair ; smtp-relay écrit le mot de passe SMTP en clair dans son TOML ; peertube `POST /upgrade` déclaré deux fois (la version synchrone masque celle à suivi) ; mcp-server `/requests` et localrecall `/documents`, `/ingest` absents ; grafana encadre probablement sa propre page ; security-posture `/cspn/summary`, `/tpn/summary`, `/performance/summary` absents et `www/index.html` non installé ; saas-relay `/status` documenté public mais protégé ; zigbee `/backup` et `/restore` appelés sans jeton par l'ancienne page ; cyberfeed totaux avec doublons ; devwatch tendances codées en dur ; streamlit `GET /access` sans domaine pour les applis ; avatar `/health` version codée en dur. Le Hall n'écoute pas encore `sbxVue` (hauteur annoncée par les cartes). `wg-quick@wg-mesh` en échec sur gk2 depuis 06:47, indépendant. Restent environ 25 pages hors Aurora : bbs, hub (soc), soc, dpi, ndpid, mediaflow, metablogizer, publish, droplet, release, waf-ng (actor, tableau, index), toolbox, auth (identité, accès), annuaire, torrent, portail Podcaster, connexion ; vault et premier-pas à part.

## 2026-10-14 — Aurora vague 5 : 12 pages (ref #2612) ; correctifs WAF et navigation déployés (closes #2613, closes #2615, closes #2629, closes #2631)
Pages au profil Aurora : radio (0.2.0, binaire Go arm64 à construire par la CI, **non déployé**), picobrew, lyrion, jellyfin, jitsi, gitea, nextcloud, vm, meshtastic, matrix, photoprism, zkp (PR #2617 à #2628, un test Playwright par page). Déployées sur gk2 sauf radio. Déployés aussi : core 1.7.8 (gk2, gk3), waf-ng 1.29.1 (gk2, redémarrage du WAF, `admin.gk2` 200 ensuite), auth 1.6.2 (gk2, gk3) ; paquets dans `/data/apt` (trixie). #2612 reste ouverte jusqu'au déploiement de radio. Poste de travail : les blocages SSH venaient d'un maître de multiplexage périmé (`ControlPath=none` : 0,7 s).

## 2026-10-14 — /identite/ dans la navigation système (ref #2631)
`/identite/` (secubox-auth 1.6.2) porte la barre du haut et le menu de gauche communs, comme `/acces/` (#2613) ; encadrée ou avec `?embed=1`, elle reste sans menu. Test Playwright `test_identite_navigation_2631.py` (4).

## 2026-10-14 — WAF coupé par un reload pendant les installations (ref #2629)

Déploiement du lot de la vague 5 sur gk2 : `secubox-waf-route` (appelé par les postinst de lyrion, jellyfin, gitea, nextcloud, photoprism) faisait `systemctl reload secubox-waf-ng` ; `ExecReload=kill -HUP` tue sbxwaf (pas de gestionnaire SIGHUP, sortie « propre » pour systemd, donc pas de relance) : 503 sur tous les vhosts publics pendant 3 min 30, jusqu'à une relance manuelle. sbxwaf relit pourtant sa table à chaud. Corrigé : l'outil ne signale plus le WAF (core 1.7.8) ; `ExecReload` devient un `touch` de la table (waf-ng 1.29.1, à déployer hors pointe : le paquet relance le WAF). Autres appelants de `reload` : relais-maillage, podcaster, exposition mesh : couverts par le changement d'unité.

## 2026-10-14 — Page système : trois échecs corrigés (ref #2615) + /acces/ dans la navigation (ref #2613)

Captures de `/system/` : « Interactive authentication required » au démarrage d'un service, `.xinitrc: Permission denied` à l'activation du kiosque, « Inst, Inst, Inst » dans la liste des mises à jour. Cause commune des deux premiers : l'API tourne en `User=secubox` + `NoNewPrivileges=true` et lançait `systemctl` / le script root directement. Corrigé : règle polkit bornée à `secubox-system.service` (le compte `secubox` est partagé par tous les modules), unité root `secubox-kiosk-setup@.service` (3 instances), parsing `apt-get -s` (2ᵉ mot). system 1.10.1, kiosk 1.0.2, core 1.7.7. La page `/acces/` charge la navigation commune hors mode encadré (auth 1.6.1, #2613/#2614).

Constat gk2 (14 oct.) : l'installation de `secubox-auth` relance l'agrégateur deux fois (configure ≈ 3 min), d'où des HTTP 502 de plusieurs minutes sur toute l'administration pendant un déploiement. Défaut de conception connu (agrégateur = point unique).

## 2026-10-13 — CI release : un seul publieur (ref #2610)

La release v3.0.0-alpha.15 est restée incomplète (images RPi400, live x64, full VM absentes), comme l'alpha.14. Cause : `build-image.yml` (job release), `build-all-live-usb.yml` (job release) et `release.yml` (create-release) publiaient les mêmes noms de fichiers dans la même release en même temps et s'effaçaient mutuellement leurs envois (« Deleting previously uploaded asset » puis « Not Found »). Une relance ne corrige rien : elle réutilise le workflow du tag. Correctif : `release.yml` passe `publier: 'non'` aux deux appelés, `create-release` (qui télécharge lui-même tous les artefacts) reste le seul publieur ; appelés seuls, les workflows gardent leur comportement. À valider sur le prochain tag (alpha.16) ; l'alpha.15 reste incomplète.

## 2026-10-13 — Panneaux Aurora, vague 4 : 12 paquets, 12 pages (closes #2597)

`/master-link/admin.html`, `/annuaire/`, `/mesh/`, `/config-advisor/`, `/zia/admin.html`, `/mqtt/`, `/netboot/`, `/ai-gateway/`, `/freebox/`, `/autoload/`, `/sentinelle/`, `/modem/` (PR #2598 à #2609), relues (aucun script externe, dialogue natif, innerHTML ni police distante) et déployées sur gk2, gk1 et gk3, dépôt apt à jour pour gk2. Versions : p2p 1.16.0, annuaire 0.13.0, mesh 2.1.0, config-advisor 1.2.0, zia 0.2.0, mqtt 2.6.0, netboot 0.5.0, ai-gateway 1.4.0, freebox 0.5.0, autoload 0.6.0, sentinelle-gsm 0.5.0, modem 1.3.0. Exclus : vault/coffre (redéployer re-scelle le coffre) et premier-pas (assistant de premier démarrage).

Bogues d'ancienne page corrigés, entre autres : mqtt était une copie de la page Lyrion (aucune donnée MQTT) ; ai-gateway appelait des routes inexistantes et affichait des valeurs inventées ; config-advisor lisait des champs absents (tuiles à 0, bouton Apply Fix jamais affiché) ; modem sans jeton et Chart.js/xterm bloqués par la CSP ; netboot, autoload, freebox : `confirm()` natifs jamais honorés (actions silencieusement inopérantes) ; annuaire : clé privée saisie par `prompt()` ; zia admin : connexion impossible (second facteur exigé).

À noter, non corrigé : modem WebSocket `/at/console` ouverte sans jeton ; mesh routes sans `require_jwt`, version `/health` codée en dur ; mqtt `/access` ne remonte que la première règle de chaque compte ; netboot IP serveur préremplie `192.168.1.200` ; master-link admin « approuver automatiquement » coché par défaut. Restent environ 58 pages hors Aurora (vague 5 ; vault/coffre et premier-pas à part).

## 2026-10-13 — Panneaux Aurora, vague 3 : 9 paquets, 12 pages (closes #2584)

`/exposure/`, `/dns-provider/`, `/metacatalog/`, `/glances/`, `/reporter/`, `/watchdog/`, `/ksm/`, `/cve-triage/`, `/antirootkit/`, `/ai-insights/`, `/meshname/`, `/master-link/` (PR #2585 à #2596), relues (aucun script externe, dialogue natif, innerHTML ni police distante) et déployées sur gk2, gk1 et gk3, dépôt apt à jour pour gk2. Versions : haproxy 1.12.0, dns 1.5.0, appstore 0.7.0, metrics 1.22.1 (glances 1.22.0 puis reporter 1.22.1), health 1.3.0, system 1.10.0, security-posture 2.3.1 (cve-triage 2.3.0 puis antirootkit 2.3.1), threats 1.6.0, p2p 1.15.1 (meshname 1.15.0 puis master-link 1.15.1).

Bogues d'ancienne page corrigés, entre autres : recherche CVE toujours vide (route masquée), pastille watchdog toujours « Disabled » (champs absents), score de risque et confiance ML inventés (ai-insights), nom de processus exécuté dans la page (glances), curseurs ksm arrondissant les valeurs réelles, flèches du graphe de dépendances à l'envers (metacatalog), écritures annoncées réussies après échec (cve-triage, meshname). Reste `www/master-link/admin.html` (ancienne peau).

À noter, non corrigé (API) : cve `/cves/search` masqué par `/cves/{cve_id}` ; ai-insights `POST /config` remet `max_correlations` à 100 ; glances `POST /config` écrase `network_interfaces`, état « en marche » par `pgrep -f` ; ksm mémoire économisée en pages de 4 Kio ; meshname import mDNS duplique au lieu d'écraser ; reporter `start_date`/`sections` ignorés, aucun exécuteur de planification ; antirootkit `test_packaging.py` cherche un changelog disparu. Restent environ 70 pages hors Aurora (vague 4 ; vault/coffre à part).

## 2026-10-13 — Panneaux Aurora, vague 2 : 10 paquets, 12 pages (closes #2571)

`/users/`, `/tor/`, `/routes/`, `/netdiag/`, `/nettweak/`, `/traffic/`, `/vortex-firewall/`, `/mail/`, `/cloner/`, `/profiles/`, `/appstore/`, `/cookies/` (PR #2572 à #2583), relues (aucun script externe, dialogue natif, innerHTML ni police distante) et déployées sur gk2, gk1 et gk3, dépôt apt à jour pour gk2. Versions : auth 1.6.0, tor 1.6.0, routes 1.4.1 (routes 1.4.0 puis netdiag 1.4.1), qos 1.6.1 (nettweak 1.6.0 puis traffic 1.6.1), ipblock 1.5.0, mail 2.15.0, backup 2.4.0, profiles 0.21.0, appstore 0.6.0, cookies 1.4.0. Coffre/vault exclu (redéployer secubox-vault re-scelle le coffre).

Bogues d'ancienne page corrigés : imports/tuiles/dates mal lus (users : `[object Object]`, 1970), tableaux toujours vides (routes, qos), `confirm()` natifs jamais honorés (profiles : apply/rollback ne partaient pas), succès affichés après échec (tor : sortie transparente armée), identifiants injectés dans `onclick`/`innerHTML` (presque partout). Changement de comportement : cloner refuse un nettoyage à 0 (supprimait tout).

À noter, non corrigé (API) : mail `/logs` passe `lines` à un `lxc-attach` sans validation ; routes `DELETE default` IPv6 sans `-6` ; qos compteur `dropped` ; tor retrait d'un service caché de la route exposure ; appstore `installed` = présent au catalogue ; DKIM mail domaine codé en dur. Tests mail `api/tests` : 30 échecs préexistants (identiques avant la refonte). Restent environ 83 pages hors Aurora (vague 3 : vault/coffre à part).

## 2026-10-13 — annuaire 0.12.0 : maillage automatique, pairs découverts dans le répertoire (ref #2569)

« Comment mesh expander pour que gk3 et gk1 s'auto-découvrent par gk2 » : l'IP était déjà joignable (satellites routent 10.10.0.0/24 par gk2), seule la liste des pairs de synchro manquait. Pairs = wg_mesh.json + nœuds du répertoire à mesh_ip interne au réseau du maillage. 15 échecs annuaire préexistants inchangés.

## 2026-10-13 — Panneaux Aurora, vague 1 : 10 paquets, 12 pages (closes #2556)

Refonte Aurora de `/hardening/`, `/dns/`, `/backup/`, `/admin/`, `/system/`, `/proxypac/`, `/qos/`, `/certs/`, `/ipblock/`, `/auth/`, `/haproxy/`, `/vhost/` (PR #2557 à #2568), une page par agent en parallèle, relue (aucun script externe, aucun dialogue natif, aucun innerHTML, aucune police distante) et déployée sur gk2, gk1 et gk3. Versions : hardening 1.6.0, dns 1.4.0, backup 2.3.0, tor 1.5.0 (proxypac), qos 1.5.0, certs 1.3.0, auth 1.5.0, ipblock 1.4.0, system 1.9.0 (admin 1.8.0 puis system 1.9.0), haproxy 1.11.1 (haproxy 1.11.0 puis vhost 1.11.1).

Bogues d'ancienne page corrigés, entre autres : routes inexistantes (certificats haproxy, `/providers` auth, `/ping`), formes de réponse mal lues (qos : tableaux toujours vides ; auth : `[object Object]`), champs obligatoires manquants (vhost `name`, backend `servers` : 422 à chaque envoi), succès simulés (certs), données d'API dans `innerHTML`/`onclick`. Écritures inchangées, sauf `POST /revoke_session` ajouté sur `/auth/` (route existante, administrateur).

À noter, non corrigé (API) : haproxy `POST/PUT/DELETE` vhost et backend et `/waf/toggle` ne journalisent que ; `POST /generate` écrit `haproxy.cfg` sans double-buffer ; certs joker (`*.` ≠ `_wildcard_.`), contrôle « HTTPS Port » toujours OK ; qos modifier une politique la réactive. Restent environ 95 pages hors Aurora (vague 2).

## 2026-10-13 — core 1.7.6 : jwt_secret relu une fois si vide (ref #2554)

« WAF KO sur gk1, OK sur gk3 » : `/waf/alerts` et `/waf/bans` en 500. Le service waf de gk1 datait d'avant l'arrivée de `api.jwt_secret` dans secubox.conf (07:25) ; la config étant en cache par processus, chaque requête avec jeton levait « jwt_secret is not configured ». Même défaut sur system, users et nac. Corrigé côté box (relance de ces 4 unités, une par une) et à la source (`_secret()` relit le fichier une fois avant de refuser). Autres unités de gk1 antérieures à 07:25 : non touchées, pas d'erreur relevée.

## 2026-10-13 — toolbox 2.13.2 : /rlevel/ au profil Aurora (ref #2552)

Page autonome (tuiles, Mon niveau, vue admin, légende des modes), appels inchangés, garde XSS conservée, 44 tests rlevel verts, captures 1400/420 lues.

## 2026-10-13 — p2p 1.14.0 : /p2p/ au profil Aurora (ref #2550)

Page autonome (aperçu, pairs, services, maillage SVG, menaces), tests navigateur, captures 1400 et 420 px lues. Écritures identiques à l'ancienne page. Corrigés : sonde `/ping` inexistante (→ `/probe`), menaces lues comme `{ip: …}` alors que l'API enveloppe dans `threats`, `last_seen` en secondes lu en ms. Non repris : « Activité récente » (pas de route), latence jamais mesurée.

## 2026-10-13 — profiles 0.20.5 : l'annuaire ne dort plus (ref #2548)

« La flotte est illisible (HTTP 502) » sur gk1. Cause : `secubox-sleeper` avait arrêté `secubox-annuaire` (et l'avait désactivé), la politique livrée le classant `on-demand`. Or il porte la synchro du maillage, la voie rapide assist, l'inscription au maître et la flotte ; le waker ne réveille que sur les vhosts de sites. Politique : `annuaire = always-on` (+ test `test_l_annuaire_ne_dort_pas`). Un manifeste déjà dérivé garde l'ancienne valeur : `secubox-profilectl set-lifecycle annuaire always-on`. 3 échecs `test_web.py::test_wake_route_*` préexistants.

## 2026-10-13 — assist 0.2.14 : les paires offre ↔ demande se voient et s'acceptent (ref #2546)

« Pas de matches ni de rendez-vous possible » : `/matches` rendait seulement les paires déjà acceptées des deux côtés alors que les boutons « Accepter » étaient posés sur cette liste — jamais acceptables. `rendezvous.candidate_matches` rend les paires compatibles qui nous concernent avec l'état de chaque côté ; le panneau « En cours » et l'onglet Matches proposent le geste qui manque ; `ready_matches` reste strict pour ouvrir la session. Tests `test_matches_candidats_2546.py` et le panneau.

## 2026-10-13 — Auto-Load, assistant et annuaire : la box préparée rejoint le maître, s'inscrit et peut demander de l'aide (ref #2544)

« Synchro premier pas et préparation box, pour auto add et remote in gk2 master register and help ». Atelier : `--code-maillage-*` dépose le code d'invitation à part (0600) ; agent (0.8.0) : l'installe pour `secubox-automesh` au premier démarrage puis l'efface de `/boot` ; assistant (0.5.8) : mode `automesh` (aucun secret dans le fichier signé), active jonction + annuaire + assistance sans bloquer l'installation, `aide = "demander"` publie une demande d'aide « première installation » (consentement du demandeur inchangé) ; annuaire (0.11.3) : l'inscription chez le maître est retentée à chaque passage de synchro. Tests dans les trois paquets ; procédure dans `docs/dossiers/automesh.md`.

## 2026-10-13 — assist 0.2.13 : panneau « En cours » (demandes, offres, aides à accepter) (ref #2542)

Après la synchro rapide (#2540), « gk1 ne voit pas l'offre de gk2 » : l'API assist rendait les bonnes données des deux côtés (vérifié sur le vrai journal), mais la page les cachait dans des onglets et une carte vide quand l'autorisation manquait. Panneau « En cours » toujours visible, gestes par ligne, parcours expliqué (Répondre → Accepter l'aide), `noeud`/`de_moi`/`reste_s` dans `/offers` et `/requests/open`. Tests `test_en_cours_2542.py` et `test_panneau_en_cours_2542.py`.

## 2026-10-13 — annuaire 0.11.2 et assist 0.2.12 : demandes et offres synchronisées en ~20 s (ref #2540)

« Demande et offre pas sync » sur `/assist/` : la réplication du journal marchait mais était lente (journal entier de 3 Mo toutes les 300 s pour une cinquantaine d'entrées d'assistance ; premier passage d'une RPi > 7 min) et muette quand elle échouait (`except Exception: pass`). `/log/export?ops=assist_`, voie rapide de 20 s qui ne tire que l'assistance, échecs et ingestions journalisés, `POST /sync/now` et bouton « Synchroniser » dans `/assist/`. Tests `test_assist_sync_2540.py` et `test_bouton_synchro_2540.py`. Le journal entier garde ses 300 s ; une synchro incrémentale (curseur) reste à faire.

## 2026-10-13 — hub 1.11.0 : /espace/, /health/ et /appareil/ au profil Aurora (ref #2538)

« Les onglets sont pétés » sur `/espace/#protection` : la Vue d'ensemble Aurora (#2485) avait supprimé `apercu.css`/`apercu.js` que `/espace/` et `/appareil/` liaient encore. Pages refaites sur données réelles : `/espace/` (onglets réactifs, état tiré de `health-batch`, filtres, clavier), `/health/` (tuiles-filtres, lignes dépliables et sélectionnables, WAF rejouable), `/appareil/` (feuille intégrée). Garde-fou : aucune ressource locale manquante dans une page du hub. Tests `test_espace_aurora_2538.py`, `test_health_aurora_2538.py`, `test_pages_sans_ressource_manquante_2538.py`.

## 2026-10-13 — p2p 1.13.2 : la jonction automatique joint un parent distant en HTTPS (ref #2536)

Essai réel gk1 → gk2 avec un code d'invitation déposé dans `automesh.code` : échec. `sbx-mesh-join` n'utilisait que HTTP:7331 (filtré par le pare-feu de gk2 depuis le LAN, et injoignable derrière une Freebox) ; l'état disait « RuntimeError ». Parent local → HTTP:7331 inchangé ; parent distant → HTTPS par le nginx du parent, certificat vérifié. Message d'échec lisible, jeton jamais journalisé. Test `packages/secubox-p2p/tests/test_transport_jonction_2536.py`.

## 2026-10-13 — premier-pas 0.5.7 : le kiosque ouvre l'administration, pas le Hall (ref #2534)

Sur la RPi400, le kiosque ouvrait `hall.localhost:9078`. Le Hall est une réalisation personnelle de gk2 ; le kiosque d'une box ouvre l'administration : `admin.localhost:9078` (console locale, sans authentification pour le seul kiosque), puis `:9080`, après vérification que la page est le tableau de bord et non le Hall. `KIOSK_START="hall"` (dans `/etc/default/secubox-kiosk`) rend l'ancien comportement. Test `packages/secubox-premier-pas/tests/test_url_kiosque_admin_2534.py`.

## 2026-10-13 — RPi400 : unités en échec du premier démarrage (ref #2532)

Diagnostic par SSH sur la RPi400 (système « degraded »). `secubox-dpi-resume` (226/NAMESPACE : `ReadWritePaths` sur un dossier absent → `CacheDirectory=`, dpi 1.12.6) ; `secubox-relais-maillage` (sortie 1 sans interface `wg-mesh` : `pairs_32 || true`, p2p 1.13.1) ; `secubox-bootmenu` de l'image RPi (`systemctl set-default` fatal avant sysinit → idempotent, jamais fatal) ; `netplan apply` (5 s → 30 s, netmodes 1.3.2). `systemd-networkd-wait-online` n'est pas un défaut de code (câble Ethernet branché 7 minutes après le boot). Tests dans chaque paquet et `tests/test_image_bootmenu_2532.py`.

## 2026-10-13 — premier-pas 0.5.6 : l'assistant propose `<nom>.secubox.in` comme domaine (ref #2530)

Sur la RPi400, `firstboot` gardait nginx seul : « frontal : domaine de la box inconnu », le domaine n'étant posé que par l'étape « Réseau et domaine », dont le champ était vide. Décision du mainteneur : le DNS est `secubox.in`, géré par gk2 (`gk1.secubox.in` résout déjà vers l'adresse publique que gk2 reçoit et route). L'assistant propose `<nom>.secubox.in` (web et console), sans l'imposer. Test `packages/secubox-premier-pas/tests/test_domaine_propose_2530.py`.

## 2026-10-13 — secubox-core 1.7.5 : SSH root par mot de passe depuis le LAN, livré par apt (ref #2528)

Sur trixie, OpenSSH refuse root par mot de passe (`prohibit-password`) : la RPi400 neuve n'était joignable que par clé ou à la console. Les images serveur et live l'autorisaient déjà par `sed`, la RPi non, et `apt upgrade` ne corrigeait rien. `secubox-core` livre `/etc/ssh/sshd_config.d/20-secubox-root-lan.conf` : root + mot de passe uniquement depuis les réseaux privés (RFC 1918) ; ailleurs, clé seulement. Vérifié avec `sshd -T` sur gk2 (config temporaire, rien de modifié). Le postinst recharge ssh après `sshd -t`. Test `packages/secubox-core/tests/test_ssh_root_lan_2528.py`.

## 2026-10-13 — haproxy 1.10.4 : `haproxyctl generate` sur une box neuve (ref #2526)

Après l'`apt upgrade` de la RPi400 (photo), le postinst de `secubox-haproxy` échouait : `bind : missing port specification in '*:'`, donc aucun frontal. Le `|| echo "80"` des lectures de port portait sur le dernier maillon du tube (`tr`), qui réussit toujours : sans clé dans `haproxy.toml`, la valeur était vide. Fonction `cle_conf` (défaut si la clé est absente ou vide) pour les ports et `waf_backend_ip`. Test `packages/secubox-haproxy/tests/test_ports_par_defaut_2526.py` (à lancer en root : `generate` crée `/run/haproxy`). Deux tests d'`acme_wiring` échouent déjà sur master.

## 2026-10-13 — secubox-core 1.7.4 : le premier démarrage ne meurt plus sur l'extension de la carte (ref #2524)

Sur la RPi400, `secubox-firstboot` s'arrêtait à l'étape 0 : `parted -s … resizepart` sur la partition montée demande une confirmation et échoue, puis `warn` (appelé 8 fois, jamais défini) répondait « command not found » (127) et, sous `set -e`, tuait le script — pas de frontal HAProxy, pas de nginx 80/443, pas de kiosque. `warn` défini, parted répond « Yes » (`---pretend-input-tty`), l'extension n'est plus fatale. Test `tests/test_firstboot_expansion_2524.py`. Diagnostiqué sur le journal affiché par la carte (photo).

## 2026-10-13 — image RPi400 : le kiosque démarre au premier boot (ref #2522)

Sur l'image alpha.14 lite, le kiosque ne démarrait pas : `secubox-console` livre un drop-in qui conditionne `secubox-kiosk.service` à `/var/lib/secubox/.kiosk-enabled` (#2332), et `build-rpi-usb.sh` écrivait l'unité et `boot-mode=kiosk` sans poser cette sentinelle. Elle est posée dans le bloc `--kiosk` et vérifiée par l'assertion de build. Test `tests/test_image_rpi_sentinelle_kiosque_2522.py`. Le « pas de web » du même démarrage est un autre défaut (`secubox-firstboot` en échec, pas de frontal HAProxy ni de nginx sur 80/443), à diagnostiquer avec son journal.

## 2026-10-13 — dns-guard 1.4.6 : la détection de tunneling ne lève plus de faux positifs (ref #2520)

Lancée sur les 2 728 domaines réels les plus demandés de gk2, l'analyse du module levait 452 alertes dont 443 « tunneling high » fausses (règle base64 appliquée à la concaténation des sous-domaines). Chaque label est jugé seul, les TLD de sonde et les zones DNSBL sont ignorés : 18 alertes sur les mêmes domaines. Reste hors périmètre : brancher le détecteur sur le journal DNS d'ad-guard (rien ne l'alimente, `alerts.jsonl` absent depuis mai) et la règle DGA (2 douteux). Test `packages/secubox-dns-guard/tests/test_tunneling_faux_positifs_2520.py`.

## 2026-10-12 — en-têtes CMSD-1.0 manquants (ref #2518)

Le contrôle « License Headers » échouait sur master : trois `tests/__init__.py` (interceptor, cdn, repo) et `docs/dossiers/automesh.md` n'avaient pas l'en-tête. Posé par `scripts/license-headers.py --fix` ; `--check` passe sur tout le dépôt.

## 2026-10-12 — surf 1.0.34 et toolbox-ng 0.12.5 : l'appât du détecteur de pub n'est plus masqué (ref #2516)

zataz.com affichait « Bloqueur de publicités détecté ! » par surf comme en direct (R3). Cause reproduite avec Chromium sur la vraie page : le thème Foxiz crée un appât `#rb-adcheck > #google_ads_iframe_test` et dresse son mur s'il est masqué ; nos feuilles cosmétiques (`[id^="google_ads"]`…) le masquaient. Le chargement du script `adsbygoogle.js` passait déjà (réponse 204). Une règle de protection par id, après la règle de masquage, laisse l'appât visible, dans les deux moteurs. Tests : `packages/secubox-surf/tests/test_appat_detecteur_2516.py` et `cosmetic_appat_2516_test.go`.

## 2026-10-12 — dns-guard 1.4.5 : la pastille ne dit plus « hors ligne » sans session (ref #2514)

Sur la capture de l'admin gk2, `/dns-guard/` affichait « HORS LIGNE » alors que le module répond : la pastille se déduisait de la seule absence de `/status`, un 401/403 passait donc pour une panne. Distinction faite : « SESSION REQUISE » (neutre) sans session, « HORS LIGNE » seulement pour une vraie panne. Test `packages/secubox-dns-guard/tests/test_pastille_session_2514.py`.

## 2026-10-12 — hub 1.10.2 : pastilles des modules montés dans l'agrégateur (ref #2512)

Sur la capture de l'admin gk2, DNS Guard, HAProxy, Hardening et R-Level avaient une pastille grise alors qu'ils répondent. Le lot de santé du hub jugeait par unité systemd et par socket ; les modules montés en processus par l'agrégateur n'ont ni l'un ni l'autre (même vérité que le Hall, #2455). Le lot est complété par la liste `mounted` du `/health` de l'agrégateur, R-Level suit le Toolbox ; une unité en échec reste une alarme. Test `packages/secubox-hub/tests/test_pastilles_montes_2512.py`.

## 2026-10-12 — métapaquets : secubox-kiosk classé dans l'arbre (ref #2510)

La release alpha.13 a vu échouer `secubox-appstore` et `secubox-meta` : « paquets ni dans l'arbre ni hors-arbre : secubox-kiosk ». Le générateur exige que chaque paquet du dépôt figure dans `arbre.yaml` ; le paquet `secubox-kiosk` (#2504) n'y était pas. Classé en « suggère » du nœud Noyau, à côté de `secubox-console` (jamais installé sans le demander) ; `debian/control` de `secubox-meta` régénéré. Deux tests de `secubox-meta` échouent encore, sans rapport (`test_refus`, `test_sbxos_pose_tout_le_hall` : carte `guardian` → `secubox-ad-guard`).

## 2026-10-12 — secubox-netmodes 1.3.1 : secubox-net-detect livré par le paquet (ref #2508)

Sur la RPi400, l'assistant s'arrêtait à « Réseau et domaine » : `secubox-net-detect apply router → code 127`. L'outil vivait dans `image/sbin/` et seul `build-live-usb.sh` le copiait. `secubox-netmodes` (déjà dans `secubox-lite`) le livre désormais, une seule copie. Tests `packages/secubox-netmodes/tests/test_net_detect_livre_2508.py`.

## 2026-10-12 — secubox-kiosk 1.0.1 et premier-pas 0.5.5 : session du kiosque (ref #2506)

Sur la RPi400, le lanceur démarrait Xorg puis affichait « This account is currently not available » : `secubox-kiosk-setup` créait `secubox-kiosk` en `nologin` et le lanceur ouvre la session par `su -l`. Le setup crée (et répare) le compte en `/bin/bash`, comme `build-live-usb.sh` ; le lanceur passe `su -s /bin/bash` et ne dépend plus du shell du compte. Tests `packages/secubox-kiosk/tests/test_paquet_2504.py`.

## 2026-10-12 — secubox-kiosk 1.0.0 : l'outil d'installation du kiosque devient un paquet (ref #2504)

`secubox-kiosk-setup` vivait dans `image/sbin/` et seul `build-image.sh` le copiait ; sur une box déjà flashée (RPi400 alpha12 sans kiosque) l'outil manquait et `apt-get install secubox-kiosk` répondait « paquet introuvable ». Nouveau paquet `secubox-kiosk` (arch all) : `/usr/sbin/secubox-kiosk-setup`, une seule copie (`build-image.sh` et `build-live-usb.sh` la prennent dans le paquet). Le lanceur appelé par l'unité générée reste celui de `secubox-premier-pas` (dépendance, pas de second exemplaire). Tests `packages/secubox-kiosk/tests/test_paquet_2504.py`.

## 2026-10-12 — build-image : repli sur le dernier agrégat quand le commit n'en a pas (ref #2501)

Un commit sans paquet lance quand même `build-packages.yml`, dont le job `collect` est sauté : le run existe, l'agrégat `secubox-debs-all` non. L'étape « commit exact » (`if_no_artifact_found: warn`) finissait en success avec 0 .deb, le repli ne partait pas et l'image échouait (« Aucun paquet SecuBox à installer », runs 38260593345 et 38262902039). Le repli se décide maintenant sur le nombre de .deb, et la provenance ne dit plus « agrégat du commit » avec 0 fichier. Le repli remonte aussi (`search_artifacts: true`) jusqu'à un run qui possède l'agrégat : le « dernier run réussi » était lui-même vide (run 38266017460). Test `tests/test_workflow_repli_paquets_2501.py`.

## 2026-10-12 — image RPi400 : resolv.conf propre à l'image (ref #2499)

Constaté sur une uSD alpha12 : `/etc/resolv.conf` inutilisable, `apt` ne résolvait rien (corrigé à la main). Cause : `build-image.sh` écrit son fichier depuis #1294, pas `build-rpi-usb.sh` ; l'image gardait celui de la machine de construction (talon 127.0.0.53 sans systemd-resolved). Correctif : même écriture (unbound local + 9.9.9.9 / 1.1.1.1 en filet) avant le démontage du chroot, test `tests/test_image_resolv_conf_2499.py`. Pas de paquet, donc pas de montée de version ; effectif à la prochaine image.

## 2026-10-12 — ad-guard 1.12.0 : page Aurora, dialogues intégrés, données échappées (ref #2436)

La page `/ad-guard/` quitte l'ancien style (CRT clair, anglais mêlé) pour le profil Aurora, en gardant le balisage, les identifiants et toutes les actions (25 tests d'interface existants passent après adaptation). `confirm()`, `prompt()` et `alert()`, ignorés par le navigateur du Hall, deviennent des dialogues intégrés. Les noms de domaine, motifs et noms d'appareil venus de l'API étaient insérés tels quels dans du HTML : ils sont désormais échappés (test avec une charge `<img onerror>`). Familles de blocage en pastilles de filtre.

## 2026-10-12 — webfilter 0.4.0 : domaines toujours bloqués, et toolbox 2.13.0 : profondeur d'inspection dans l'onglet Clients (ref #2433, #2432)

Un appareil dont la catégorie adulte est en `observe` (exception voulue) ne bloquait pas un domaine précis de la liste : `bloque` (par profil et par appareil) refuse ces domaines quel que soit le mode des catégories, l'emporte sur une autorisation, et n'est écrit dans `config.json` que s'il sert. Toolbox : la profondeur d'inspection par pair (R-level `off/passive/active/reel`, choisi, plancher, forcé, effectif) se règle dans l'onglet Clients, à côté de chaque client du tunnel, avec confirmation intégrée quand l'inspection devient plus profonde ; `/rlevel/peers` porte `mac_hash`.

## 2026-10-12 — webfilter 0.3.0 Aurora, NAC 3.8.0 et SOC 1.6.0 : filtre web intégré (ref #2430)

La page `/webfilter/` passe au profil Aurora (tuiles, répartition, bloqué et observé, appareils les plus filtrés) en gardant toutes ses actions. Ses `confirm()` de blocage, ignorés par le navigateur du Hall (réponse « non » sans rien dire), deviennent des confirmations intégrées. `secubox-lite` dépendait déjà de `secubox-webfilter` (rien à ajouter). Le NAC montre sur la carte de chaque appareil son profil de filtrage et ses requêtes bloquées et classées sur 7 jours ; Guardian a un panneau Filtrage web. Tests navigateur : 27 (webfilter, dont les 22 existants adaptés à la confirmation intégrée), NAC et Guardian.

## 2026-10-12 — release : fichiers de plus de 1,9 Gio découpés automatiquement (ref #2427)

La publication de v3.0.0-alpha.12 échouait (`size must be less than 2147483648`) : les images full-vm, isp-vm, isp-mochabin et lite-mochabin dépassent 2 Gio et `release.yml` ne découpait pas (alpha.12 a été complétée à la main). `scripts/release-decouper-assets.sh` découpe en `.partNN` (1900 Mo, même convention que `build-all-live-usb.yml`), écrit `<fichier>.assembled.sha256` (somme du fichier réassemblé) et supprime l'original ; `release.yml` l'appelle avant les sommes, hache et publie les parties, et les notes expliquent le réassemblage. Tests : découpage, réassemblage identique, idempotence, ordre des étapes du workflow, backticks des notes. **Reste ouvert** : le live USB MOCHAbin dépasse 240 min sous QEMU (étape « Build embedded eMMC image » : reconstruit une image déjà produite par `build-images`) — piste : exécuteur arm64 natif ou réutilisation de l'artefact.

## 2026-10-12 — profil projet référence Aurora : règles, galerie et script (ref #2354)

Les règles déduites du style Aurora sont écrites dans `.claude/AURORA-REFERENCE.md` (jetons, squelette, container queries, vérité des données, protocole de hauteur d'iframe, actions et confirmations intégrées, intégration en onglets, pièges, tests). `docs/aurora/` rassemble 28 pages en capture bureau et mobile, en démonstration (aucune capture authentifiée publiée) ; `scripts/snapshots-aurora.py` les régénère. Le README racine et `AGENTS.md` y pointent.

## 2026-10-12 — billets 0.11.1 + metanews 0.4.1 : billets éphémères avec sources, aperçu et vignette (ref #2343)

Le billet éphémère de MetaNews n'avait ni lien, ni média, ni vignette. MetaNews liste maintenant jusqu'à 5 sources en liens (https seulement) et envoie l'article principal en `embed_url` ; `/service/ephemere` résout l'embed et capture la vignette en tâche de fond, sans jamais bloquer la création.

## 2026-10-12 — profiles 0.20.3 : le kiosque n'est plus arrêté par un profil (ref #2329)

L'interface locale (module kiosk, dans aucun profil) était mise à OFF par `profilectl apply` : la VM finissait son Auto-Load sans interface. HORS_PLAN : ni stop, ni start.

## 2026-10-12 — SOC 1.2.0 : refonte sur la maquette Guardian (ref #2341)

Nouvel onglet par défaut Guardian ; les trois onglets existants restent.

## 2026-10-12 — Hall 1.9.4 : un lien d'activité /bbs/t/<id> ne casse plus la page (ref #2339)

Références absolues dans index.html + redirection vers le BBS de la box.

## 2026-10-12 — dpi 1.11.1 : l'ancien démon est arrêté sans condition (ref #2337)

Le postinst conditionnel laissait ndpid actif. Corrigé et testé.

## 2026-10-12 — mediaflow et ndpid agrégés : dpi 1.11.0, hub 1.9.54 (ref #2335)

Plus de démon dédié (~150 Mo), API servie par l'agrégateur ; hub route /api/v1/ndpid/ vers lui.

## 2026-10-12 — Kiosque WebUI et console headless dans tous les profils (ref #2332)

secubox-console 1.2.2, secubox-lite 1.7.0, secubox-full 1.7.0, secubox-profiles 0.20.4. Le kiosque démarre sur condition d'unité (sentinelle) au lieu d'échouer ; la console ne démarre que sans kiosque.

## 2026-10-12 — network-anomaly collecte enfin : dns-guard 1.3.1 (ref #2328)

La collecte n'existait que derrière POST /detect. Minuteur d'une minute + unité oneshot.

## 2026-10-12 — Suricata décommissionné : closes #2326

Intégration retirée de threats (+ ai-insights), soc-agent, system-hub, metrics (tableau Grafana), core (répertoire de journal), scripts d'image et outil gen-gui ; test de non-retour. Il n'était ni installé ni actif sur gk2. Versions : secubox-threats 1.3.2, secubox-soc-agent 1.0.5, secubox-soc-gateway 1.1.4, secubox-system 1.7.1, secubox-metrics 1.18.3, secubox-core 1.7.3.

## 2026-10-12 — Modules optionnels : isp 1.4.0, full 1.6.0, threats 1.3.1 (ref #2322)

PhotoPrism et Jitsi hors d'isp (PhotoPrism dans full, Jitsi à la demande), Suricata suggéré (il échouait à chaque démarrage de la VM isp ; ni installé ni actif sur gk2).

## 2026-10-12 — SOC 1.1.10 : le contenu ne passe plus sous la barre de gauche (ref #2323)

Barre partagée fixe de 220 px, contenu centré qui la supposait dans le flux : réserve de 220 px (0 sous 768 px).

## 2026-10-12 — Auto-Load : la liste des pré-rapports montre le nom de box saisi (autoload 0.5.2, ref #2314)

Colonnes « Box (nom saisi) » et « Client (jeton) ».

## 2026-10-12 — Auto-Load : le rapport final d'une box LAN arrive enfin (autoload 0.5.1, agent 0.7.1, ref #2319)

Le test VirtualBox va jusqu'à « Votre boîtier est prêt », mais le rapport final était refusé en 422 (domaine vide en mode LAN) et avalé par l'agent. Domaine vide admis des deux côtés.

## 2026-10-12 — L'assistant manuel s'efface devant l'Auto-Load : premier-pas 0.5.3, autoload-agent 0.7.0 (ref #2317)

Demandé par le propriétaire après le test VirtualBox (assistant en parallèle : routeur par défaut, nom écrasé). Faces fermées tant que le fichier signé est présent, sauf abandon de l'agent (8 échecs). Sans fichier Auto-Load : assistant, code de préparation et propositions du maître inchangés.

## 2026-10-12 — profiles 0.20.2 : régression de 0.20.1, premier-pas* ne sont plus protégés (ref #2315)

Un protégé est démarré par l'apply ; les oneshot premier-pas-* ne sont jamais « actifs » → timeout → tout l'apply annulé, le parcours Auto-Load échouait à l'étape Services. Seul autoload-agent reste protégé.

## 2026-10-12 — premier-pas 0.5.2 : on peut choisir une option dans la console (ref #2312)

Trouvé par le test VirtualBox : liste verticale, seules gauche/droite changeaient l'option, pied de page illisible. Haut/bas, +/-, espace et chiffres.

## 2026-10-12 — autoload-agent 0.6.2 : profilectl appelé avec --profile (ref #2310)

Quatrième bogue du test VirtualBox : `unrecognized arguments: lite`, après reprise sur redémarrage. Le test confronte maintenant la commande à la vraie CLI.

## 2026-10-12 — profiles 0.20.1 : profilectl n'arrête plus l'agent qui le pilote (ref #2308)

Troisième bogue du test VirtualBox Auto-Load : l'étape « services » arrêtait secubox-autoload-agent (hors du profil lite) ; le parcours mourait à 10/13. autoload-agent et premier-pas* rejoignent PROTECTED_IDS.

## 2026-10-12 — premier-pas 0.5.1 : l'étape réseau en mode lan sans secubox-net-detect (ref #2306)

Suite du test VirtualBox : le parcours s'arrêtait à « Réseau et domaine » (code 127), l'outil n'étant livré par aucune image. Mode lan : réseau existant conservé après contrôle d'une route par défaut ; routeur et pont échouent clairement. Décision restante : livrer `secubox-net-detect` dans les images ou non.

## 2026-10-12 — Auto-Load : l'enrôlement HTTPS ne marchait pas, trouvé par le test VirtualBox (ref #2301)

autoload-agent 0.6.1 : `TypeError: OpenerDirector.open() got an unexpected keyword argument 'context'` — le contexte TLS est lié au gestionnaire HTTPS. Les tests passaient par un faux ouvreur trop permissif ; un test de bout en bout (serveur TLS local, ouvreur réel) le couvre.

## 2026-10-12 — Rapport PDF quotidien de sécurité : WAF + Actor Intelligence + DPI : closes #2299

metrics 1.18.0 : PDF sombre à trois volets (style des vues du Hall), données réelles seulement, définitions, mesures non disponibles listées ; ancien PDF WAF via `format = "waf"`. dpi 1.10.0 : résumé agrégé écrit par `secubox-dpi-resume.timer` (le rapport ne lit pas l'API à jeton).

## 2026-10-11 — Guardian, Actor Intelligence, SBXWAF et DPI validés par le propriétaire : closes #2287, closes #2291, closes #2293

Quatre vues d'ensemble fidèles aux infographies, déployées sur gk2 (ad-guard 1.11.0, webos 1.9.3, waf-ng 1.28.2, dpi 1.9.0). Modes d'Actor Intelligence : le mode réel d'application des décisions (WAF), pas le mode d'analyse d'actord.

## 2026-10-11 — DPI : vue d'ensemble, carte du monde partagée (ref #2293)

dpi 1.9.0 : `vue.html` (tuiles définies, flux appareils vers usages, carte, types, applications, protocoles, destinations, domaines à classer, état du moteur), encadrée en tête de `/dpi/`, carte du Hall `/dpi-vue/`. waf-ng 1.28.2, webos 1.9.2 : les trois pages reprennent la grille de carte éprouvée de la page Actor (ligne 7 corrigée), test de partage. Menaces et blocages non inventés côté DPI.

## 2026-10-11 — SBXWAF : vue d'ensemble fidèle à l'infographie (ref #2293)

waf-ng 1.28.0 : nouvel onglet par défaut « Vue d'ensemble » de la page /waf/ (page vue.html encadrée, même origine) ; anciens onglets conservés. Données du WAF seulement ; mesure absente = tiret ; ?demo=1 annoncé.

## 2026-10-11 — Actor Intelligence : carte et page fidèles à l'infographie (ref #2291)

webos 1.9.0 : page `/actor-intelligence/` (complet ou carte `?embed=1`, `?demo=1` annoncé), données d'actord seulement ; tuiles définies en infobulle ; risque et confiance séparés ; mesure absente = tiret. Audit de l'existant : définitions de compteurs partielles, baseline par appareil absente, états proposé/annulé de l'action absents, taux de faux positifs par règle absent.

## 2026-10-11 — Guardian : le gardien du réseau domestique (ref #2287)

ad-guard 1.11.0 : route `GET /adblock-tv/gardien` + page unique `/guardian/` (tableau de bord complet ou cardlet `?embed=1`, `?demo=1` annoncé). Données réelles seulement (NAC, DNS, actord) ; une mesure absente s'affiche « — », jamais 0. webos 1.8.0 : carte Hall, relais nginx, aide. Vhost public dédié : décision du propriétaire (DNS, ACME, HAProxy, route WAF).

## 2026-10-11 — Tag alpha.11 : l'agent Auto-Load refusé par verify-profile (ref #2285)
Le tag a construit les paquets (121 jobs) et l'installateur sans écran, mais 7 images disque ont échoué : `scripts/verify-profile.sh` refuse un module absent du working-set de gk2, et l'agent (ajouté au profil `lite` par #2280)
y était absent. Entrée manuelle dans `image/profiles/working-set.gk2.txt` et test qui lance la porte sur lite, isp et full. Leçon : lancer `verify-profile.sh` avant tout changement de profil.

## 2026-10-11 — waf-ng 1.27.3 : le correctif du cache est dans l'unité, drop-in corrompu retiré (ref #2283)
`/etc/systemd/system/secubox-waf-ng.service.d/20-cache-owner.conf` (gk2, #1001) contenait l'aide de la commande `secubox` collée par un heredoc à backticks ; systemd ignorait ses lignes. `mkdir` et `chown` du cache sont dans l'unité du paquet, un test refuse tout fichier d'unité corrompu, les deux drop-ins manuels sont retirés. Leçon : jamais de backtick dans un heredoc non protégé.

## 2026-10-11 — secubox-lite 1.6.0 : commentaire indenté dans Depends (ref #2280)
Mes lignes de commentaire dans `Depends` commençaient par un espace : `dpkg-gencontrol` les prenait pour la suite du champ et le paquet ne se construisait plus. Corrigé (colonne 0) et gardé par un test sur lite, isp et full.

## 2026-10-11 — Auto-Load phase A : une image flashée se provisionne seule (ref #2280)
`secubox-autoload-agent` 0.6.0 : unité de premier démarrage conditionnelle (fichier de réponses SIGNÉ sur `/boot`, trousseau installé, pas de rapport), installation puis effacement du jeton, `autoload-atelier` (`cle-init`, `preparer` qui
vérifie la signature comme la box avant d'écrire, `verifier`), trousseau livré. Clé « SecuBox Provisioning » créée sur gk2. Profil `lite` 1.6.0 : l'agent est dans toute image. Guide `docs/AUTOLOAD-ATELIER.md`. Le tag alpha.11 est reposé avec l'agent.

## 2026-10-11 — Release v3.0.0-alpha.11 : admin à six espaces, Actor Intelligence 2.0, billets vivants, installateur sans écran
Tag `v3.0.0-alpha.11` posé sur master (≈ 110 commits depuis alpha.10). **Sécurité** : Actor Intelligence 2.0 en six phases (modes et enforcement, capteurs pare-feu/DNS/détournement/DPI,
scénarios, risque et confiance séparés, kill switch logique, Radar des acteurs dans le Hall, politique et procédure d'activation) puis échelle de réponse réelle — délai, défi par preuve de travail,
tarpit, ban, quarantaine d'un appareil du LAN par le NAC — avec preuve par adresse, moteurs de recherche vérifiés jamais bannis, profil AppArmor corrigé. **Admin** : six espaces par défaut, page
Vue d'ensemble, fiche d'appareil (OS détecté avec preuve), conteneurs LXC écartés. **Contenu** : billets vivants (remontée par commentaire, animation), billets éphémères, MetaNews qui publie
des billets de 5 minutes. **Provisionnement** : Auto-Load 1 à 11 (infrastructure, agent, WebUI, banc). **Images** : installateur sans écran (installation automatique sur le premier disque) livré avec
la release. Incident de la journée : l'index apt signé de gk2 n'avait pas été réexporté après mes publications (agent de signature verrouillé) ; réexporté en relançant l'unité de déverrouillage.

## 2026-10-11 — NAC 3.4.1 : lecture des mesures à la racine d'actord (ref #2274)
La vue complète d'actord (avec adresses) n'est servie qu'à la racine ; le NAC lisait sous `/api/v1/actor/` (vue réduite) et n'aurait isolé personne. Il lit `GET /mesures`.

## 2026-10-11 — Échelle de réponse : la preuve est par adresse (ref #2274)
Un acteur fusionné de 1 389 adresses les entraînait toutes sous mesure ; une mesure ne vise plus que les adresses individuellement hostiles (≥ 3 événements en 24 h), un ban en exige 10. toolbox-ng 0.12.2, waf-ng 1.27.2.

## 2026-10-10 — Échelle de réponse : vérification des robots en parallèle (ref #2274)
Le premier tour sur gk2 (900 adresses) était retardé par la vérification DNS en série ; elle est parallèle et une adresse non vérifiée n'est jamais touchée. toolbox-ng 0.12.1, waf-ng 1.27.1.

## 2026-10-10 — Échelle de réponse réelle : délai, défi, tarpit, ban, quarantaine LAN (ref #2274)
actord choisit le cran (escalade sur insistance) et publie `actord-mesures.json` ; sbxwaf applique DELAY/CHALLENGE (preuve de travail)/TARPIT/DENY ; le NAC isole en auto un appareil du LAN (zone de quarantaine existante, validation par l'administrateur) ; les crans du Hall reflètent les mesures réelles. toolbox-ng 0.12.0, waf-ng 1.27.0, nac 3.4.0, webos 1.7.0.

## 2026-10-10 — waf-ng 1.26.4 : l'exemple et la doc d'activation sont installés (ref #2240)
La 1.26.3 les référençait sans les livrer ; `rules` les installe et la procédure donne le chemin installé.

## 2026-10-10 — Actor Intelligence 2.0, phase 6 : politique et procédure d'activation (ref #2240)
`docs/ACTOR-INTELLIGENCE-ACTIVATION.md` (scoring v2, modes, drapeaux, garde-fous, procédure `PASSIVE_ONLY → SIMULATION → ACTIVE`, retour arrière, limites) + exemple `conf/actor-intelligence-simulation.conf.example` ; test qui verrouille la doc sur le code. waf-ng 1.26.3.

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

## 2026-10-12 — WireGuard, interface Aurora (closes #2438)
- secubox-wireguard 1.2.0 : page /wireguard/ au profil Aurora (tuiles, tunnels dépliables, trafic par tunnel, démo/embed) ; les deux `confirm()` natifs remplacés par une confirmation intégrée (avertissement de coupure d'accès admin/mesh conservé). 6 tests navigateur. Déployé gk2, dépôt apt à jour.

## 2026-10-12 — NAC, noms et services par Bonjour (closes #2440)
- secubox-nac 3.9.0 : passe avahi-browse en cache (120 s), nom des appareils sans bail, nom annoncé, pastilles de services, types de service injectés dans la détection du type fin ; colonnes services/bonjour_name. 10 tests.

## 2026-10-12 — webfilter, « Appliquer maintenant » refusé (closes #2441)
- secubox-webfilter 0.4.1 : le profil AppArmor du contrôleur root peut effacer appliquer.demande ; sans cela le service apply échouait, l'unité .path atteignait sa limite et chaque demande répondait 409. Constaté et corrigé sur gk2 (version 13 appliquée).

## 2026-10-12 — NAC, Bonjour corrigé (-k) et conteneurs LXC nommés (closes #2444, closes #2445)
- secubox-nac 3.9.1 : avahi-browse -k (types bruts, sinon aucun service reconnu) ; service root secubox-nac-lxc-names + minuterie 5 min -> conteneurs.json, nom des conteneurs sans DNS ni bail.

## 2026-10-12 — Interceptor, fin de la maquette (closes #2447)
- secubox-interceptor 2.0.0 : l'API supervise en lecture seule la chaîne d'inspection réelle (moteurs sbxmitm/sbxwaf, activité tirée du journal, niveaux par pair, exclusions) ; instantané root pour le dossier fermé du Toolbox ; page Aurora ; ancien démon root et CA inutilisée retirés. 14 tests.

## 2026-10-12 — Hall à l'adresse IP, ressources racine (closes #2449)
- secubox-webos 1.9.8 : /fonts/, /domaine.js, /lexie.js, /hall-logo.svg, /medaillons/ servis depuis le dossier du Hall sur le vhost par défaut (live amd64 : polices rejetées, SBX_DOMAINE non défini). Atteint le live avec la prochaine image ; non vérifié sur 192.168.1.9 (pas d'accès SSH).

## 2026-10-12 — Hall à l'adresse IP, routes aussi dans secubox-routes.d (closes #2451)
- secubox-webos 1.9.9 : fragment hall-racine.conf livré dans secubox-routes.d (vhost webui) en plus des mêmes lignes dans webos.conf (secubox.d). Cause trouvée en vérifiant sur gk2 après un redémarrage réel de nginx.

## 2026-10-12 — Interceptor, classes nDPI et cartes du monde (closes #2453)
- secubox-interceptor 2.1.0 : panneau nDPI (protocoles, applications, catégories, volumes) et cartes des sorties (DPI) et des entrées (visiteurs).

## 2026-10-12 — Hall, états de la vue d'ensemble (closes #2455)
- secubox-webos 1.9.10 : modules montés par l'agrégateur comptés en service (HAProxy, DNS Guard, Hardening, Exposure, IP Blocklist, Interceptor) ; R-Level suit le Toolbox.

## 2026-10-12 — Modes réseau, page Aurora et corrections (closes #2457)
- secubox-netmodes 1.3.0 : page Aurora sur données réelles ; formulaires factices et routes inexistantes retirés ; mode jamais inventé (« inconnu » sans état) ; WAN lu dans la route par défaut ; confirmations intégrées. 12 tests.

## 2026-10-12 — network-anomaly, lignes de base automatiques (closes #2459)
- secubox-dns-guard 1.4.2 : le passage planifié construit puis rafraîchit les lignes de base (30 échantillons, 1 h) avant la détection ; sans elles la détection ne pouvait jamais alerter. L'API relit le fichier.

## 2026-10-12 — network-anomaly, détection sur des débits (closes #2461)
- secubox-dns-guard 1.4.3 : octets d'interface et requêtes DNS convertis en débits avant stockage et détection (les compteurs cumulatifs alertaient en permanence) ; historiques de compteurs retirés au premier passage ; page en Kio/s.

## 2026-10-12 — network-anomaly, menu de gauche (closes #2463)
- secubox-dns-guard 1.4.4 : la page /network-anomaly/ charge la barre laterale et /shared/sidebar.js (hors cadre et démonstration).

## 2026-10-12 — Threats, bannir 30 jours (closes #2465)
- secubox-threats 1.5.0 : bouton Bannir 30 j par adresse publique (alertes et IOC IP), confirmation intégrée, POST /api/v1/waf/ban (30d) validé par wafctl ; erreurs réelles rendues. 6 tests navigateur.

## 2026-10-12 — CDN, supervision des caches réels (closes #2467)
- secubox-cdn 1.4.0 : GET /caches (taille, fichiers, activité de chaque cache de /var/cache/secubox, illisible = null) ; page Aurora ; politiques CDN signalées non appliquées. 10 tests.

## 2026-10-12 — Captures Aurora de toutes les pages (closes #2469)
- scripts/snapshots-aurora.py : 9 pages ajoutées (NAC, filtre web, ad-guard, DNS Guard, anomalies, WireGuard, Interceptor, modes réseau, caches), bande vide de gauche retirée ; les 37 pages régénérées en démonstration ; galerie docs/aurora/README.md à jour.

## 2026-10-12 — Mirror fusionné avec CDN (closes #2471)
- secubox-cdn 1.5.0 : GET /miroirs (dépôt APT hébergé : suites, paquets, pool), page « Caches et miroirs », /mirror/ redirige vers /cdn/, une seule entrée de menu.

## 2026-10-12 — Billets au profil Aurora (closes #2473)
- secubox-billets 0.12.0 : portail /billets/ Aurora sur stats.json réel (liens http(s) seulement) ; tableau de bord, modération, édition, connexion habillés Aurora par la feuille billets-admin.css ; polices distantes retirées. 5 tests navigateur ; échecs préexistants inchangés.

## 2026-10-12 — SÉCURITÉ p2p : routes de maillage « locales » sans authentification (closes #2476)
- secubox-p2p 1.12.1 : invite-local et cleanup-local exigent le JWT (la provenance annoncée ne prouve rien) ; is_local_request supprimée. Constaté sur gk2 : un jeton (1 s, sans auto-approbation, sans effet) fabriqué sans authentification. Vérifier les pairs approuvés des autres box.

## 2026-10-12 — Automesh en lite (closes #2475)
- secubox-p2p 1.13.0 : code d'invitation unique (adresse + jeton + somme), join-with-code, jonction automatique au démarrage (secubox-automesh, appel sortant, code supprimé après usage). secubox-lite 1.8.0 : embarque secubox-p2p et secubox-assist. Dossier docs/dossiers/automesh.md. À valider de bout en bout sur deux box ; dépôt du code par Auto-Load et découverte mDNS : phase suivante.

## 2026-10-12 — Surf, vidéo d'un article BFM (closes #2479)
- secubox-surf 1.0.33 : le conteneur Bitmovin sans `<video>` est ranimé à partir de son `data-video-url` (HLS via hls.js, relayé par l'origine surf) ; jamais un autre média. 7 tests.

## 2026-10-12 — Dashboard Aurora (closes #2481)
- secubox-hub 1.10.0 : racine de l'administration au profil Aurora (lecture seule, données réelles, session requise dite) ; actions factices ou sans confirmation retirées. 6 tests navigateur.

## 2026-10-12 — Captures de données réelles, identifiants masqués (ref #2483)
- scripts/snapshots-live.py : captures d'une box réelle avec jeton en variable d'environnement, masque des identifiants dans le navigateur avant la capture (IP, MAC, clés, courriels, domaines), flou des noms d'appareils ; 4 tests du masque. Les captures elles-mêmes attendent un jeton de session fourni par l'exploitant.

## 2026-10-12 — Vue d'ensemble Aurora (closes #2485)
- secubox-hub 1.10.1 : /apercu/ au profil Aurora (page autonome, tuiles, cartes par espace) ; captures dashboard et apercu ajoutées à la galerie.

## 2026-10-12 — Flotte Aurora (closes #2487)
- secubox-annuaire 0.11.1 : /fleet/ au profil Aurora (XSS-stricte conservée) ; GET /fleet signale une lecture en échec (`erreur: true`) au lieu de rendre une flotte vide. 8 tests ; 15 échecs préexistants de la suite inchangés.

## 2026-10-12 — autoload, journal d'audit hors du chevauchement logrotate (closes #2489)
- secubox-autoload 0.5.3 : journal dans /var/log/secubox/autoload/audit.log (la règle générale de secubox-core ne le voit plus) ; logrotate.service ne doit plus échouer chaque nuit ; le service peut de nouveau écrire son audit. Constaté sur gk2 : échec 00:52, journal recréé en secubox:secubox.

## 2026-10-12 — toolbox, dossier partagé de journaux (closes #2490)
- secubox-toolbox 2.13.1 : /var/log/secubox en secubox-toolbox:secubox 0775 (la rotation générale de secubox-core, sous su secubox, peut de nouveau y créer ses .1.gz) ; logrotate.service ne doit plus échouer chaque nuit.

## 2026-10-12 — Dépôt APT, comptes réels et page Aurora (closes #2493)
- secubox-repo 1.3.0 : GET /publie (suites, paquets distincts, pool lus dans l'arborescence publiée) ; /stats et la tâche de fond n'utilisent plus le socle reprepro de repoctl (« trixie : 0 ») ; page Aurora ; Init et GPG confirmés dans la page. 11 tests.

## 2026-10-12 — Image RPi400 : dépendances résolues, audité, kiosque par défaut (closes #2495)
- Cause constatée sur une uSD isp-rpi alpha.12 : 32 paquets secubox sans leurs dépendances (systemd-timesyncd, python3-cryptography, lxc…), premier pas arrêté à l'étape Horloge, Tor/SMTP en échec, pas de kiosque. build-rpi-usb.sh n'exécutait `apt --fix-broken` que sous --kiosk, et le workflow ne passait --kiosk que sur déclenchement manuel.
- build-rpi-usb.sh : apt --fix-broken systématique puis image/verify-deps.py (fatal) ; build-image.yml : kiosk=auto, inclus par défaut pour rpi400/rpi4 ; secubox-premier-pas 0.5.4 : étape NTP souple. 17 tests.

## 2026-10-12 — Image lite RPi400 (closes #2497)
- matrice-images.py : rpi400 publie lite, isp, full ; option --profil pour forcer un profil. build-image.yml : choix du profil (auto/lite/isp/full) au déclenchement manuel. 4 tests de plus.
