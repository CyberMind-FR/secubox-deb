<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
# secubox-premier-pas

SecuBox Premier Pas — first-boot wizard engine and silent profile.

One engine, one profile (profil.toml), four faces: kiosk, console, master panel and silent. premier-pasctl validates a profile step by step (name, clock, admin, network and domain, services, mesh, updates), shows the exact plan, and applies it by driving the existing SecuBox tools (hostnamectl, timedatectl, secubox-users engine, secubox-net-detect, secubox-profilectl, sbx-mesh-join). An incomplete profile is never half-applied: the wizard resumes at the missing step. Never stores a plaintext password.

Also ships secubox-majauto: nightly unattended upgrade of the SecuBox packages only, from the signed apt.secubox.in repository.

Paquet Debian : version `0.4.9-1~bookworm1`, architecture `all`.

## Contenu

- `api/` : API FastAPI
- `exemples/` : fichiers du module
- `kiosque/` : fichiers du module
- `menu.d/` : entrée de menu
- `premier_pas/` : fichiers du module
- `sbin/` : exécutables
- `systemd/` : unités systemd
- `tests/` : tests
- `www/` : interface web

## Exécution

- `secubox-majauto.service` : SecuBox — mises à jour automatiques des paquets SecuBox (#1522), lance `secubox-majauto`
- `secubox-majauto.timer` : SecuBox — mises à jour automatiques, chaque nuit (#1522)
- `secubox-premier-pas-appliquer.path` : SecuBox Premier Pas — une face demande l'application du profil (#1522)
- `secubox-premier-pas-appliquer.service` : SecuBox Premier Pas — application du profil rempli par une face (#1522), lance `premier-pasctl`
- `secubox-premier-pas-console.service` : SecuBox Premier Pas — assistant du premier démarrage, face console (tty1) (#1522), lance `premier-pas-console`
- `secubox-premier-pas.service` : SecuBox — premier démarrage : profil prêt appliqué, sinon assistant (#1522), lance `premier-pasctl`

## API

| Méthode | Route | Garde |
|---|---|---|
| `GET` | `/etat` | aucune |
| `GET` | `/choix` | aucune |
| `POST` | `/session` | verdict LAN de nginx (`X-SecuBox-LAN: 1`), fenêtre de 15 min après le démarrage, un seul poste (0.6.0, #2725) |
| `PUT` | `/etape/{etape}` | jeton local, code d'appairage ou secret de session distante |
| `POST` | `/appliquer` | jeton local ou secret de session distante |
| `GET` | `/code` | jeton local seul |
| `POST` | `/proposition` | aucune |
| `POST` | `/proposition/accepter` | jeton local seul |
| `POST` | `/proposition/refuser` | jeton local seul |
| `GET` | `/maitre/profils` | aucune |
| `GET` | `/maitre/profils/{nom}` | aucune |
| `PUT` | `/maitre/profils/{nom}` | aucune |
| `DELETE` | `/maitre/profils/{nom}` | aucune |
| `GET` | `/maitre/profils/{nom}/export` | aucune |
| `POST` | `/maitre/pousser` | aucune |
| `GET` | `/maitre/distant` | aucune |

Routes relevées dans le code source, relatives au montage du module. « aucune » : pas de garde déclarée à cet endroit de la route.

## Configurer une box sans écran (0.6.0, #2725)

L'assistant ouvert depuis un navigateur du réseau local est le même que celui du kiosque : la page demande une session (`POST /session`) et se déroule
normalement. Choix assumé du mainteneur — ouvert au LAN comme un routeur grand public : **le premier poste du LAN qui arrive dans la fenêtre prend la box**.
Les règles qui en limitent la portée, dans `premier_pas/ouverture.py` :

| Règle | Détail |
|---|---|
| Fenêtre | l'ouverture n'est possible que les **15 premières minutes** après le démarrage de la box. Comptée en temps écoulé depuis le démarrage (horloge monotone), pas en date : une carte sans horloge matérielle saute de plusieurs jours au réglage de l'heure. Elle ne limite que l'ouverture, pas une configuration commencée à la minute 14. Pour rouvrir : redémarrer la box |
| Origine | seul un client que nginx déclare du LAN (`X-SecuBox-LAN: 1`, posé par `secubox-proxy.conf` depuis `$lan_client`). L'adresse IP n'est lue que pour la trace. Sans l'en-tête (Hub absent, hors nginx), l'ouverture reste fermée |
| Un seul poste | le premier reçoit un secret aléatoire, les suivants reçoivent `423` tant que sa session est active (15 min depuis sa dernière action). Le secret, pas l'adresse, identifie le poste |
| Secret | jamais écrit en clair : `session-distante.json` (0600, dans `PREMIER_PAS_DIR`) ne garde que son empreinte SHA-256, l'identifiant de démarrage et la dernière activité. Une session d'avant un redémarrage n'est jamais reprise |
| Périmètre | la session **remplit et applique**. Elle ne lit pas le code d'appairage et n'accepte ni ne refuse une proposition de la box maîtresse : ces gestes prouvent la présence devant la box et restent à l'écran (jeton local) |
| Trace | chaque ouverture et chaque refus part au journal systemd (`secubox.premier-pas`) et, si l'écriture est possible, à `/var/log/secubox/audit.log` (`PREMIER_PAS_AUDIT`). **Limite connue** : l'API tourne en `secubox` et `audit.log` est root 0644 ; la trace durable est donc celle du journal systemd. Le secret n'y figure jamais |

## Rouvrir l'assistant, et ce qui le ferme (0.6.1, #2727)

Le marqueur `/var/lib/secubox/.premier-pas-fait` ferme l'assistant. Le `postinst` ne le pose que pour une box **en service sans assistant en cours**
(`premier_pas/en_service.py` : un admin a déjà servi — mot de passe choisi ou TOTP enrôlé — ET aucun `profil.toml` non vide). Une mise à jour du paquet
en plein parcours ne ferme donc plus l'assistant (elle le faisait : constaté sur un RPi400, `fait: true` avec un profil complet et un moteur vide).

`premier-pasctl rejouer [--vierge]` (root, sur la box) rouvre l'assistant de force : retire le marqueur, l'état du moteur, la demande d'application, la
proposition du maître, la session distante et la trace d'aide ; **garde le profil rempli** (`--vierge` l'efface), puis relance le service et le kiosque.
Aucune route distante pour cela : rouvrir l'assistant d'une box en service, c'est rouvrir sa configuration.
`POST /session` (ouverture distante, #2725) est refusée (409) sur une box en service sans assistant en cours.

## Dépendances SecuBox

`secubox-core`.

## Tests

4 fichier(s) de test. Lancer : `python3 -m pytest packages/secubox-premier-pas`.

## Fichier de réponses Auto-Load (0.5.0, #2184)

`premier_pas/provision.py` : le profil de l'assistant étendu d'une section `[provision]`, pour le provisionnement réseau (parent #2182, cadrage `docs/dossiers/provisionnement-auto-load.md`). Contrairement à l'assistant, qui ignore ce qu'il ne connaît pas, ce mode est **strict** :

- section ou clé inconnue, sous-table, fichier de plus de 64 Kio : refusés ;
- aucun secret en clair : mot de passe = empreinte argon2, jeton = référence `ref:/etc/secubox/secrets/<nom>` (jamais la valeur), jeton d'invitation du maillage refusé ;
- **signature détachée** OpenPGP vérifiée par `gpgv` contre le seul trousseau fourni (`/usr/share/secubox/autoload/provisioning.gpg` par défaut) : fichier modifié, clé inconnue ou signature absente = refus ;
- `mode = "auto"` exige un profil complet (aucun écran pour demander ce qui manque).

    premier-pasctl reponses --fichier reponses.toml --signature reponses.toml.sig [--trousseau K] [--json]   # code 4 : refusé

Exemple : `examples/reponses-autoload.toml`.
