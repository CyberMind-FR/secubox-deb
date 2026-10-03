# secubox-voicestudio — moteur vocal studio dans un LXC natif (#1917)

VoiceStudio (synthèse vocale, reconnaissance, clonage de voix) tourne dans un **LXC Debian dédié** —
jamais podman ni docker. Les autres box le prennent comme moteur distant de `secubox-voice` (Lexie,
mode `mixte` : repli sur le moteur local si VoiceStudio ne répond pas).

> **Licence amont.** VoiceStudio est sous AGPL-3.0, avec des poids par défaut CC-BY-NC. Il reste un
> **processus séparé**, joint par le réseau : ce paquet ne contient aucune de ses sources, il les
> télécharge à l'installation (épinglées, vérifiées) et ne les importe jamais.

```
client (gk2 → maillage, LAN)
   └─► <adresse publiée>:3900     mandataire de l'hôte, activé par socket (secubox-voicestudio-pub.socket)
          ├─ ExecStartPre : voicestudioctl wake    démarre le LXC si besoin, attend /health
          └─ systemd-socket-proxyd ─► 10.100.0.230:3900   (moteur dans le LXC, clé d'API obligatoire)

navigateur ─► nginx ─► /run/secubox/voicestudio.sock   (API du module : administration + usager)
                          └─ sudo -n systemd-run … voicestudioctl api   (UNE porte privilégiée, JSON sur stdin)
```

| | |
|---|---|
| Conteneur | `voicestudio`, Debian bookworm **non privilégié**, `10.100.0.230`, torch **CPU** (aucun GPU requis) |
| Sources | amont `debpalash/VoiceStudio`, **commit ET sha256** épinglés dans le TOML ; l'empreinte est vérifiée AVANT extraction |
| Python | versions tirées de l'image validée (`conf/contraintes.txt`, sans CUDA) |
| Disposition | sources dans `/app`, données dans `/app/omnivoice_data` (montage de `/srv/secubox/voicestudio`) — **même chemin que l'image**, la base SQLite garde des chemins absolus |
| Écoute | moteur sur `10.100.0.230:3900` seulement ; hôte sur `127.0.0.1` + adresses de `[reseau] publier` (LAN, maillage), **jamais le WAN** |
| Pare-feu | la chaîne d'entrée est en DROP : `voicestudioctl appliquer` pose une règle (adresses publiées × sources privées, par poignée, jamais de `flush`) et le fichier `/etc/nftables.d/zz-secubox-voicestudio.nft` ; retirés à la désinstallation (`pare-feu-ferme`) |
| Mémoire | plafond cgroup `[lxc] memoire` (4G), poids CPU `cpu_poids` (50 : cède le pas aux autres services) |
| Mode | `permanent` (défaut : réponse sans délai) ou `demande` (le LXC dort, se réveille au premier appel, 30–60 s à froid) |
| Architecture | **amd64 seulement** (aucune roue torch CPU arm64 validée ici) |
| Interface native | **le studio complet de VoiceStudio**, construit dans le LXC (bun épinglé version + sha256, `bun install --frozen-lockfile` puis `bun run --cwd frontend build`, comme le Dockerfile amont ; bun supprimé ensuite), servie sur `voicestudio.<domaine de la box>` **aux administrateurs seulement** : garde `auth_request` → `/gate` (require_jwt), clé du moteur posée par nginx (snippet root 0600, jamais vue du navigateur), aucun cookie vers le moteur |

## Exposer l'interface native d'une box SANS WAN (gk3)

`voicestudio.<domaine de la box>` est servi par nginx (9080) derrière HAProxy et le WAF **de la box** ; le postinst déclare
le vhost HAProxy et la route WAF comme pour les autres modules à domaine propre. Une box sans WAN (gk3) est atteinte
depuis l'extérieur par le **relais du maillage** (gk2 termine le TLS avec le joker `*.gk3.secubox.in`, son WAF inspecte, puis
relaie vers `10.10.0.5:9080`). Le minuteur horaire de `secubox-relais-maillage` expose les noms des pairs ; pour ne pas
attendre : sur le relais, `secubox-relais-maillage relayer voicestudio.gk3.secubox.in 10.10.0.5`. Vérifié : sans
administrateur, tout chemin répond 401 (même avec une fausse clé ou un faux cookie), aucun contenu du moteur ne fuit.

## Deux interfaces, une API

| Facette | Page | Garde | Contenu |
|---|---|---|---|
| Administration | `/voicestudio/` | `require_jwt` (administrateur réel) | état, démarrer / arrêter / redémarrer, installer, mode, mémoire, CPU, modèle de reconnaissance, adresses publiées, clé d'API (aperçu, renouvellement), essai de voix, journal, sauvegarde |
| Usager | `/voicestudio/usager.html` | `require_personne` (une personne, pas un visiteur ni un appareil invité) | dire un texte, dicter (micro ou fichier), choix de la voix ; annonce honnêtement « le moteur dort » ou « indisponible » |

La page d'usager n'a **aucune** action d'administration ni destructive (parité des fonctions utiles,
asymétrie permise dans le seul sens du destructif — `WEBUI-PANEL-GUIDELINES` § 7).

## API — `/api/v1/voicestudio/…` (socket `/run/secubox/voicestudio.sock`)

| Route | Garde | Rôle |
|---|---|---|
| `GET /health` | publique (sonde) | `{"status":"ok"}` |
| `GET /gate` | `require_jwt` | sous-requête `auth_request` de nginx pour l'interface native : 204 pour un administrateur réel, 401/403 sinon |
| `GET /status` | `require_lecture` | état MINIMAL (installé, actif, endormi, opération) — ni adresses ni IP du conteneur (cache 4 s, échecs compris) |
| `GET /detail` | `require_jwt` | état complet pour le panneau d'administration, sans secret |
| `POST /start` `/stop` `/restart` `/installer` | `require_jwt` | **202** + suivi dans `/status` → `operation` (hors requête : un démarrage à froid dure) |
| `POST /config` | `require_jwt` | `asr`, `memoire`, `cpu_poids`, `mode`, `inactivite_s` — chaque valeur revalidée par le ctl |
| `POST /publier` | `require_jwt` | `{"adresses":["192.168.1.9","10.10.0.5"]}` — IPv4 de la box seulement |
| `GET /cle` · `POST /cle/renouveler` | `require_jwt` | aperçu (4+4 caractères) · nouvelle clé rendue **une fois** |
| `GET /journal?n=` · `POST /sauvegarde` | `require_jwt` | journal du moteur · archive des données (sans les modèles) |
| `GET /voix` · `POST /essai/dire` · `POST /essai/transcrire` | `require_jwt` | essai depuis le panneau d'administration |
| `GET /usager/etat` · `GET /usager/voix` | `require_personne` | état honnête, voix |
| `POST /usager/dire` · `POST /usager/transcrire` | `require_personne` | synthèse (texte ≤ `texte_max`) · dictée (audio ≤ `audio_max_mo`) |

Garde-fous d'usager : un seul calcul à la fois (le suivant attend 20 s puis reçoit 429), débit borné par
personne (20 synthèses / 12 dictées par minute), limites lues dans `[limites]`. Un moteur absent est dit
**503**, jamais masqué par une voix de secours.

## Limites connues (dettes nommées)

- **LAN en clair** : le port 3900 publié sert du HTTP avec la clé en `Bearer` ; il n'est donc publié que sur des
  adresses *non publiques* (refus des adresses globales, vérifié par le ctl) — réseau de confiance (LAN, maillage).
- **Pas de profil AppArmor** livré avec ce paquet (AGENTS.md l'exige pour chaque service) : à écrire et à valider
  en mode `complain` avant `enforce`.
- **Chaîne d'approvisionnement Python** : tarball amont épinglé par sha256, versions épinglées par `contraintes.txt`,
  torch depuis l'index PyTorch seul, `pip check` en fin d'installation ; pas encore de `--require-hashes` sur les
  ~270 dépendances.
- **Utilisateur partagé `secubox`** pour l'API (exception RULES-CODE § 10, nommée et testée).
- Le ctl agit immédiatement (`stop`, `config`, `publier`, `cle-renouveler`) : pas de `--apply` / dry-run.
  Chaque changement est audité ; une seule commande mutante à la fois (`flock`).

## voicestudioctl — la seule surface privilégiée

```
voicestudioctl install            crée le LXC, installe le moteur (10 à 25 min), pousse la clé, bascule depuis podman si besoin
voicestudioctl start|stop|restart
voicestudioctl status [--json]
voicestudioctl config <asr|memoire|cpu_poids|mode|inactivite_s> <valeur>
voicestudioctl publier IP…        adresses de l'hôte où publier le port 3900 (LAN, maillage)
voicestudioctl cle | cle-renouveler
voicestudioctl sauvegarde         archive 0600 dans /var/backups/secubox/voicestudio (3 dernières)
voicestudioctl migrer-conf        crée / convertit /etc/secubox/voicestudio.toml (ancien schéma podman)
voicestudioctl basculer           arrête l'ancien moteur, reprend ses données, démarre le LXC (une fois)
voicestudioctl api                porte du panneau : JSON sur stdin, actions en liste blanche
```

Le panneau n'appelle que `sudo -n /usr/bin/systemd-run --wait --pipe --collect --quiet /usr/sbin/voicestudioctl api`
(un seul argv exact dans `/etc/sudoers.d/secubox-voicestudio`, sans joker). Chaque changement d'état est
écrit dans `/var/log/secubox/audit.log` avec le nom de l'administrateur ; **la clé n'y entre jamais**.

## Configuration — `/etc/secubox/voicestudio.toml`

Créé (ou converti de l'ancien schéma podman, adresses publiées reprises) par `voicestudioctl migrer-conf`.
Ce n'est **pas** un conffile : la mise à jour ne pose aucune question dpkg. Défauts :
`/usr/share/secubox/voicestudio/voicestudio.toml`. La clé d'API n'est jamais dans ce fichier :
`/etc/secubox/secrets/voicestudio/api_key` (0600), poussée dans le LXC par le ctl.

## Mettre à jour le moteur

Une mise à jour est un geste : modifier `[source] commit` et `sha256` (relus), puis
`voicestudioctl reinstaller`. Jamais de « dernière version » flottante.

## Passage depuis l'ancienne version (podman, < 0.2.0)

L'ancien moteur **continue de servir pendant toute l'installation du LXC**. Quand le LXC est prêt,
`voicestudioctl basculer` : arrête l'ancienne unité, reprend le volume podman (copié, **jamais supprimé**),
démarre le LXC, vérifie `/health`. Si le moteur du LXC ne répond pas, le volume d'origine est intact.

## Dépendances

`secubox-core (>= 1.4.0)`, `lxc`, `python3`, `python3-uvicorn`, `python3-httpx`, `python3-multipart`, `sudo`.
Aucune dépendance à podman ni docker (test de dépôt `tests/test_pas_de_docker_1743.py`).

## Tests

```
.venv/bin/pytest packages/secubox-voicestudio/tests      # ctl, API, paquet (une suite par domaine)
```
