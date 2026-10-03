<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# FAQ — pieges recurrents de SecuBox-DEB

Les questions qui reviennent, avec la reponse verifiee.

> ZIA / IA locale : la FAQ **produit** (données, modèle, sécurité, délégation…) vit dans
> `docs/design/ZIA-HALL-POC.md` et le wiki [ZIA-Hall]. Ici, ce sont les pièges de dev/ops.

## Une page HTML servie en mojibake (🛰️ → ðŸ›°, é → Ã©, — → â€")

Le fichier n'a **pas** de `<meta charset="utf-8">`. Piège vécu quand une page vient d'une
**maquette/artefact** : l'artefact ajoute le charset via son wrapper, mais le fichier copié
dans le paquet ne l'a plus, et nginx laisse le navigateur deviner (Latin-1). Parade : mettre
`<!DOCTYPE html>` + `<meta charset="utf-8">` en **tête** de chaque HTML servi (comme
`micro.html`/`admin.html`). Vérifier : `curl … | head -2`.

## Un service redemarre en boucle sans rien dire

Regarder `systemctl show <u> -p NRestarts --value`. Si le compteur est enorme,
c'est presque toujours la socket : `/run/secubox` est en **1777**, on n'y delie
que ce qu'on possede, et une socket laissee par un autre utilisateur rend le
demarrage impossible. Parade : `ExecStartPre=+/bin/rm -f <sa socket>`. **Le `+`
est indispensable** — sans lui la ligne echoue comme le demon.

## Une page web servie perimee apres un deploiement

Le cache media de sbxwaf garde une URL une heure. La parade durable est une
**empreinte du contenu dans l'URL** (`radio.css?v=<hash>`), comme le fait
`secubox-radio`. En depannage, purger l'entree — mais purger le corps SANS son
annexe `.m` produit un pire defaut : sans type stocke, Go devine et repond
`text/plain`, le navigateur jette la feuille.

## `grep` sur une directive systemd

**Inutilisable.** De nombreuses unites portent la directive dans un commentaire
expliquant qu'on ne la declare pas. Toujours
`systemctl show <u> -p <directive> --value`.

## `dch` introuvable

`devscripts` n'est pas installe sur le poste de developpement. Ecrire l'entree
de changelog a la main. Toute source modifiee et redeployee **doit** monter de
version : patch pour une correction, mediane pour une fonctionnalite, majeure
pour une release.

## Un correctif source qui n'atteint pas la board

Verifier que le depot n'est pas **en retard** sur la board : c'etait le cas de
`secubox-antirootkit` (depot 0.1.0, board 0.1.1). Corriger la source telle
quelle aurait ecrase une meilleure version. Comparer avant d'ecrire.

## Le WAF bloque un envoi de fichier

Regarder `waf-threats.log` : une categorie `rce`/`sqli` sur un `POST` de media
est presque toujours un FAUX POSITIF. Les regles cherchent du texte ; les
octets d'une image en contiennent par hasard. sbxwaf s'abstient desormais sur
les corps binaires — si le cas revient, verifier que le `Content-Type` est bien
reconnu par `corpsBinaire()`.

## `pkill -f` tue ma propre session

Le motif figure dans la ligne de commande du shell distant qui l'execute.
Utiliser les PID (`pgrep` puis `kill`), jamais `pkill -f` avec un motif qu'on
vient d'ecrire. Erreur commise trois fois le 2026-08-17.

## Un import de groupe prend des minutes

`secubox-groupd` importe 84 modules : compter plusieurs minutes, pas 40
secondes. Un controle trop precoce conclut a tort a l'echec — c'est ce qui m'a
fait replier trois groupes qui auraient marche.

## Un paquet s'installe mais le binaire ne change pas

Verifier QUEL paquet livre le binaire : `dpkg -S`. Les sources de `sbxwaf`
vivent dans `secubox-toolbox-ng` mais c'est `secubox-waf-ng` qui l'installe.
J'ai construit le mauvais paquet deux fois.

## Un vrai visiteur voit `ERR_CONNECTION_ABORTED`

Ce n'est pas un 403 WAF (qui donnerait une page « SECURITY ALERT ») : le
`waf_ban` nft est un `drop` qui reset le TLS. L'IP est bannie. Le piege : un
**hote a NOUS non route** (l'appli Nextcloud iOS sur `nextcloud.gk2.secubox.in`)
classe `host_anomaly:unrouted` et bannit l'IP — et en **CGNAT mobile** (Free,
Orange…) tous ceux qui partagent cette IP publique tombent avec. Depuis 1.7.6,
un Host sous nos suffixes (`--widget-hosts`) n'est jamais banni (`detect`).
Chercher le vrai coupable dans `waf-threats.log` par UA navigateur/appli, pas par
IP. Voir aussi : notre domaine non route = **route WAF manquante**, pas une
attaque — comparer `grep 'hdr(host) -i' /etc/haproxy/haproxy.cfg` aux cles de
`/etc/secubox/waf/haproxy-routes.json` (l'autorite, hot-reload).

## `pip freeze` d'une image conda : des contraintes qui n'en sont pas

Dans une image conda, `pip freeze` écrit `nom @ file:///home/conda/…` pour les paquets installés par conda.
Un filtre « garder les lignes `==` » les **jette** : le fichier de contraintes paraît complet (111 lignes) mais
laisse numpy, scipy… flotter (numpy 2.4.6 au lieu de 2.3.2, vu pendant l'installation d'essai de VoiceStudio).
Parade : `pip list --format=freeze` (toujours `nom==version`), puis retirer `nvidia-*`, `triton`, `pip`, `wheel`
et le suffixe `+cu128`. Vérifier : `grep -c '^numpy' contraintes.txt`.

## Un moteur répond 200 sans clé en essai local, 401 depuis le LAN

VoiceStudio exempte le **loopback** de la clé d'API : un `curl 127.0.0.1` sans clé donne 200 et fait croire que la
clé n'est pas appliquée. Tester depuis une adresse non-loopback (lier le moteur à l'IP du LAN et l'appeler par
celle-ci). Dans le LXC, les clients arrivent de `10.100.0.1` : la clé est exigée.

## Un test d'API répond 200 sans session sur une route en `require_lecture`

Le `conftest.py` racine arme le mode tableau de bord et l'en-tête LAN pour toutes les suites : une lecture
gardée par `require_lecture` répond donc 200 en test. Tester la **garde** (`route.dependant.dependencies`),
pas le code de retour ; les routes `require_jwt` / `require_personne` refusent toujours (401/403).

## Installer le paquet d'un moteur lourd ne doit pas bloquer dpkg ni couper l'ancien service

Le provisionnement (LXC + pip, 10 à 25 min) part en `--no-block` dans une unité `oneshot` gardée par un marqueur ;
l'ancien service continue de servir, et c'est la commande de bascule (`voicestudioctl basculer`) qui l'arrête, **LXC
prêt**. Le mandataire n'est pas démarré par la postinst tant que l'ancien moteur tient le port.

## `sudo` répond « no new privileges flag is set » alors que l'unité dit `NoNewPrivileges=no`

Certains réglages de durcissement **imposent implicitement** `NoNewPrivileges=yes` (filtres seccomp) : mesuré en les
ajoutant un par un à une unité transitoire (`systemd-run -p …`), `ProtectKernelTunables`, `RestrictSUIDSGID` et
`LockPersonality` suffisent à neutraliser sudo ; `RestrictNamespaces`, `SystemCallFilter`, `MemoryDenyWriteExecute`…
font de même. `ProtectSystem`, `ProtectHome`, `PrivateTmp`, `ProtectControlGroups` et `UMask` sont sans effet.
Les tests unitaires ne peuvent pas le voir : **rejouer le code du module dans une unité transitoire aux réglages
identiques** (`systemd-run --wait --pipe -p User=… -p … python3 -`). Vérifier le service vivant :
`grep NoNewPrivs /proc/$(systemctl show -p MainPID --value <unité>)/status` doit donner `0`.

## Un service sur l'hôte est injoignable alors que son ancienne version (podman) l'était

La chaîne `input` de la base est en `DROP`. Un port publié par podman passe par la redirection (forward) et
**contourne** `input` ; un démon qui écoute sur l'hôte, lui, tombe dessous. Il faut une règle explicite :
`insert rule inet filter input … comment "<module>"` (idempotente, retirée par poignée — jamais de `flush`), et un
fichier `/etc/nftables.d/zz-<module>.nft` qui déclare la table de façon additive avant l'insertion. Vérifier sans
risque dans un espace de noms jetable : `ip netns add t; ip netns exec t nft -f base+fichier`.

## Dans un LXC non privilégié, `journalctl` est vide

`systemd-journald` y échoue (`status=228/SECCOMP`) : aucune entrée, jamais. Lire le fichier de log de l'application
depuis l'hôte (le rootfs et les montages y sont lisibles) plutôt que `lxc-attach … journalctl`.

## `swapon --show` voit du swap mais la box manque de mémoire : le zram n'est pas un swap disque

Le zram est de la RAM comprimée : il se remplit (gk3 : 3,9/3,9 Go) et il faut alors un vrai swap **disque** pour que le noyau puisse évincer
les pages froides. Tester « un swap est actif » sans exclure `/dev/zram*` fait croire que le swap disque existe et ne le crée jamais
(`secubox-tuning-apply` avant 1.2.5). Lire `/proc/swaps` et ne compter que les périphériques hors zram. Sur une box à eMMC/SD le swap va sur le
gros disque (`/data`) ; sur gk3 le SSD est sous `/` et `/data` n'a que 4 Go : repli `/srv/secubox`, jamais une carte (usure).

## « HTTP 504 » alors que le service a bien travaillé : le frontal coupe à 30 s

`timeout server 30s` dans les `defaults` de HAProxy protège tout le parc ; une opération légitimement longue (téléversement de 22 Mo, synthèse
vocale à froid de 110 s) est abandonnée côté client pendant que le serveur continue — et l'usager recommence. Remède propre : une exception
`http-request set-timeout server <durée> if <acl>` **dans le backend** (`set-timeout` n'existe pas ailleurs) pour les chemins exacts concernés,
générée par `haproxyctl` (jamais éditée à la main : `haproxyctl generate` puis `haproxy -c` puis `reload`). Et empiler les délais dans le bon
ordre : module < relais nginx < frontal public (300 s < 330 s < 10 min).

## Une nouvelle section TOML qui porte le nom d'une ancienne clé à plat

Migrer « ancien schéma → nouveau » en testant `if "memoire" in conf` prend la nouvelle SECTION `[memoire]` pour l'ancienne clé `memoire = "4g"` et
réécrit un fichier déjà à jour. Distinguer par le TYPE de la valeur (`isinstance(v, dict)`), et tester la migration sur un fichier déjà migré.

## Pourquoi « Dire » ne rend rien dans VoiceStudio (grand modèle de 110 à 140 s) ?
Le modèle OmniVoice calcule sur CPU : 110 à 140 s par phrase sur gk3, pour 4 s de chargement seulement — garder le modèle en mémoire ne change rien. Une voix Piper française via sherpa-onnx (déjà installé dans le moteur) dit 4,6 s d'audio en 0,9 s. Mesurer AVANT de choisir : `lxc-attach -n voicestudio -P /data/lxc -- /opt/venv/bin/python` avec `sherpa_onnx.OfflineTts`. Le moteur n'a qu'un backend TTS global ; le module garde donc les deux (voix rapide dans un petit serveur à côté, grand modèle pour les voix nommées).

## WebSocket du studio natif refusé en 403 derrière HAProxy
Le moteur (`core/csrf.py: origin_allowed`) compare l'Origin du navigateur (`https://hôte`) à son origine de destination (`http://hôte`, car HAProxy termine le TLS). Sans correction, tout WebSocket échoue en 403 (dictée) alors que l'événement `/ws/events` peut passer. Parade : `map $http_origin` dans nginx qui ramène à http la seule origine exacte du vhost ; ne jamais supprimer ni forcer l'Origin (c'est la protection contre une page tierce qui profiterait du cookie de session).
