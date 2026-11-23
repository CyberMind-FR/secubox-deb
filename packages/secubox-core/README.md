<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# SecuBox Core

Core package for SecuBox-Deb platform. Provides shared libraries, utilities, and base services.

## Components

### Python Library (`secubox_core`)

Shared Python modules for all SecuBox services:

- `auth.py` - JWT authentication helpers ; porteur délégué du pilotage (#3126, L5) : `jeton_pilotage_valide(payload, request)`,
  `module_courant(request)`.
  - **Signature Ed25519 (EdDSA), pas HS256** (R-L5-9, dérogation aux Global Constraints du plan L5 qui prévoyaient
    HS256 avec `jwt_secret`) : les sockets de modules sont souvent en 0666 et `jwt_secret` est lu par tous les modules ;
    un module compromis frapperait un jeton administrateur. Le relais `sbx-pilotage-relais` signe avec sa clé PRIVÉE
    (PEM PKCS#8 Ed25519, 0600, compte du relais, créée par la tâche 2) ; les modules vérifient avec la clé PUBLIQUE
    `/etc/secubox-pilotage/relais.pub` (R-L5-13 : arbre root, HORS de `/etc/secubox` qui appartient au compte
    `secubox` ; dossier root:root 0755, fichier PEM SubjectPublicKeyInfo Ed25519 root:root 0644). Dossier ouvert
    `O_DIRECTORY|O_NOFOLLOW`, fichier par `dir_fd` `O_NOFOLLOW` ; propriétaire root et aucune écriture groupe/autres
    exigés sur l'un et l'autre. Chemin fixe, jamais tiré de la requête (`kid`, `jku`, `jwk` ignorés) ; clé absente,
    douteuse ou invalide : aucun jeton délégué accepté (un avertissement par empreinte du fichier).
  - Réclamations : `aud` = nom court de l'hôte, `exp - iat ≤ 60` (non échu, `iat` sans avance > 5 s),
    `sub` = `pilotage:<acteur>@<maître>` (`^pilotage:[a-z0-9._-]{1,64}@[a-z0-9-]{1,63}$`, cohérent avec la réclamation),
    `pilotage = {acteur, maitre, portee}`, et **`cible`** = le module visé. Le relais normalise l'acteur en minuscules ;
    ici, un acteur hors motif est refusé, jamais converti.
  - `cible` est comparée à l'IDENTITÉ du module qui sert la route : le fichier source de la route résolue sous
    `/usr/lib/secubox/<module>/` (fixé par dpkg, valable dans un processus de groupe, indépendant de la socket). Une
    route de secubox_core n'appartient à aucun module : refus.
  - Bearer seulement, avec l'en-tête `X-SecuBox-Pilotage-Relais` (vidé par `secubox-proxy.conf`, l'agrégateur et
    l'entrée HAProxy). `scope["server"]` est un contrôle de plus : TCP refusé ; socket Unix fournie = celle du module ;
    absent (uvicorn 0.32 de Debian ne le remplit pas pour une socket Unix) = accepté sur signature et `cible`.
  - **Écriture fermée par défaut** (R-L5-12 ; réalise #3279 en version minimale) : en portée `admin`, une méthode
    d'écriture n'est acceptée que si le PAQUET du module la déclare dans
    `/usr/share/secubox/pilotage/routes-ouvertes.d/<module>.toml` (root, sans écriture groupe/autres, même ouverture
    que la clé) : `[[routes]]` avec `methodes = ["POST", …]` (POST, PUT, PATCH, DELETE) et `chemins = ["^/…$", …]`,
    chemins relatifs au module. `valider_routes_ouvertes(texte)` refuse tout motif non ancré ou ouvert (`.` nu, `*`,
    `?`, `|` hors groupe littéral, groupe spécial, classe qui franchit `/`, échappement de classe) : un fichier
    invalide, douteux ou absent n'ouvre RIEN. Le premier segment doit être littéral, et chaque classe est compilée
    telle quelle pour vérifier qu'elle n'accepte pas `/` (`[!-~]`, `[.-0]` refusées). Déclarés en L5 : system, nac,
    ad-guard (freebox : aucune écriture ouverte, ses `confirme` sont posés par la page relayée). Aucune déclaration ne
    recouvre un verbe du ctl L2 (reboot, mise à jour, service, renommage, renouvellement de secrets, kiosque) : ces
    actions passent par les actions du pilotage.
  - Ce n'est pas une session. Portée `lecture` : GET/HEAD seulement (403 sinon) ; portée `admin` : administrateur réel,
    pour les écritures déclarées.
    `est_admin_reel` n'accepte que le payload RENDU par la garde (marque `_PayloadPilotage`, aussi sur
    `request.state.pilotage`), jamais un dict décodé ailleurs ou copié ; `est_personne` est toujours faux.
  - Refusé (403) : modules `MODULES_EXCLUS_PILOTAGE` (auth, vault, portal, assist, premier-pas, users, aggregator,
    pilotage*) ; routes nommées `ROUTES_EXCLUES_PILOTAGE` (WireGuard `/peer/<nom>/config|qr`, `/export/…`) ; tout chemin
    dont un segment, ou un morceau de segment découpé sur tout caractère hors `[a-z0-9]`, est dans
    `SEGMENTS_EXCLUS_PILOTAGE` (comptes, sessions, secrets, jetons, clés, `credential(s)`, `private`, `psk`,
    `restore`…). Une liste d'ouverture déclarée par module la remplacera (#3279).
  - Chaque usage est tracé dans `/var/log/secubox/delegation.log` (ASCII ; acteur, maître, portée, verdict, méthode,
    chemin, module ; jamais le jeton) ; chaque REFUS d'un jeton dont la signature est vérifiée aussi dans
    `/var/log/secubox/audit.log` (`evenement: pilotage_delegue`). Un jeton non vérifié (signature, illisible) n'est
    pas audité : il est compté, et le compte part à la trace et au journal au plus une fois par minute.
- `config.py` - TOML configuration loader
- `logger.py` - Unified logging
- `system.py` - System utilities
- `kiosk.py` - Kiosk mode helpers
- `unites.py` - LE contrôle partagé pour piloter une unité `secubox-*.service` depuis une API : motif, unités protégées (arrêt refusé), `systemctl <action> -- <unité>`, audit JSON (#3258) ; option `avec_unites_debian` (routes `/admin/` seulement) : nginx, haproxy, unbound, ssh réparables, jamais arrêtées

### Services

| Service | Description |
|---------|-------------|
| `secubox-core.service` | Core initialization |
| `secubox-runtime.service` | Runtime directory setup |
| `secubox-led-heartbeat.service` | LED heartbeat indicator |
| `secubox-dns-listes.service` (+ `.path`, `.timer`) | DNS block lists compiled into one tagged Unbound file (#3205) |

### CLI Tools

- `/usr/bin/secubox` - Main SecuBox CLI
- `/usr/bin/secubox-firstboot` - First boot initialization
- `/usr/sbin/secubox-led-heartbeat` - LED heartbeat daemon
- `/usr/sbin/secubox-dns-listes` - `appliquer` (default), `etat`, `compiler FICHIER` (#3205)
- `/usr/sbin/secubox-renouvelle-secrets` - secrets generated on the box itself (#3243)
- `/usr/sbin/secubox-renommer` - the single way to rename a box (#3126 L2, #3242)

## Renommer une box (`secubox-renommer`, 1.8.10, #3126 L2 tâche 5, #3242)

`secubox-renommer [--acteur <login>] <nom>` (root) est le **seul** chemin de renommage : page Système (unité root
`secubox-systeme-renommer@<nom>.service` de secubox-system), premier-pas, pilotage distant
(`secubox-pilotagectl renommer`). Dans l'ordre, chaque étape défaite si une suivante échoue :
ligne `127.0.1.1` de `/etc/hosts` (les autres lignes intactes), `hostname` de la section `[global]` de
`/etc/secubox/secubox.conf`, `hostnamectl set-hostname`, audit `box_renommee {ancien, nouveau, acteur}` (audit
impossible ⇒ tout est rétabli), puis `systemctl try-restart avahi-daemon.service` (échec dit, non bloquant).
Idempotent (`"inchange": true`, non audité), y compris pour un nom actuel réservé (`secubox` de l'installeur).
Un renommage à la fois : verrou attendu 15 s au plus, puis code 1 « renommage déjà en cours ». Un ancien nom hors motif
est rétabli tel quel au retour arrière. Refus : nom hors libellé DNS (code 2), réservé `admin`, `www`, `secubox`,
`localhost` (3), déjà porté par un pair **enrôlé** de `/var/lib/secubox/p2p/peers.json` (4) ; écriture impossible (5)
ou `hostnamectl` en échec (6) : état précédent rétabli. Refus de fond audités `box_renommage_refuse`. Écritures
atomiques sans suivre de lien, droits d'origine gardés, aucun shell. Sortie : une ligne JSON. `SBX_RACINE` (tests)
honorée seulement sans élévation par sudo.

## Secrets propres à la box (`secubox-renouvelle-secrets`, 1.8.5–1.8.7, #3243)

Images built in CI used to carry secrets generated in the chroot (SSH host keys, OIDC signing key, TLS key, p2p
ephemeral WireGuard key and pairing token, machine-id) plus an admin account named after the CI runner: every box of
an image shared them, and the images are public. The tool, root only (run it under
`systemd-run -E SUDO_USER --wait --pipe --collect` so a dropped SSH session cannot interrupt it and the audit still
names the operator):

- no argument: report (date of each secret, origin of the host key, build-host accounts) — changes nothing;
- `--absents`: create the missing ones (first boot of a cleaned image);
- `--tout --oui [--machine-id] [--desactiver NOM]`: regenerate everything through each package's own generator
  (`ssh-keygen -A`, `secubox-oidcctl init`, the `secubox-p2p` postinst, openssl like `secubox-firstboot` step 9), replace
  HAProxy copies of the old TLS key, disable the build-host account first.

Each secret is generated in a root 0700 directory, checked, then put in place by rename; the old one is kept and
restored if generation or checking fails. The TLS key and certificate are placed through a directory descriptor
(`/etc/secubox/tls` belongs to `secubox`: no link is ever followed). `audit.log` names the renewed secrets
(`secret_renouvele`, `compte_desactive`), never a value. The `secubox-p2p` postinst output goes to
`/var/log/secubox-renouvelle-secrets.log` (root 0600, opened without following a link). Recommends `openssh-client` and
`wireguard-tools`.

Exit codes, for firstboot, which is meant to call `--absents` (not wired yet; on first boot `ssh` is started with
`--no-block`):

- `0`: everything is in place (including nothing to do);
- `1`: a secret could not be created or renewed, or the audit could not be written — named on stderr, the old one stays,
  the box keeps booting;
- `2`: usage (argument, not root, `--oui` missing);
- `130`: interrupted (the step in progress is put back).

## Listes DNS compilées (`secubox-dns-listes`, 1.8.0, #3205)

webfilter, adblock and adult no longer write into `/etc/unbound/unbound.conf.d`: each **deposits** its render
(`93-secubox-webfilter.conf`, `95-secubox-adblock.conf`, `96-secubox-adult.conf`) in
`/var/lib/secubox-dns-listes/sources` (`secubox_unbound.depot.deposer_source` / `retirer_source`). The root oneshot
`secubox-dns-listes.service` (AppArmor `/usr/sbin/secubox-dns-listes`, only `CAP_DAC_OVERRIDE` for `audit.log`, `MemoryMax=50%`) then:

1. adopts an old file still present in `unbound.conf.d` (older generator, previous install) as its source;
2. compiles the sources with `secubox_unbound.listes`: one client class per address block that carries a policy
   (`access-control`, `access-control-view`, override target, plus Unbound's built-in `127.0.0.0/8` and `::1`), each
   domain once, `define-tag`/`local-zone-tag` groups, `access-control-tag-action … always_transparent` for exceptions;
   decisions identical to the separate files (bench on gk1 with gk2's real configuration: Unbound 743 → 387 MB,
   145 530 questions, 27 classes);
3. writes `92-secubox-listes.conf` and removes 93/95/96 in **one** transaction (`poser_vues`: one
   `unbound-checkconf`, one reload, full byte-for-byte rollback); the reload only counts once
   `unbound-control status` answers again (#2969).

The tree `/var/lib/secubox-dns-listes` (sources, state, 0600 lock) is root-owned and **outside** `/var/lib/secubox`
(owned by the shared `secubox` account, which could rename and replace a sub-directory); every deposit checks the
directory and its parent (no symlink, owner, not group/world-writable). New ACL elements in the 92 reuse the action and
kept view of the element that covered the class: the compiled file never opens access the old files did not.

Triggers: `secubox-dns-listes.path` (sources **and** `unbound.conf.d`: a new TV view or network changes the classes),
daily timer. The state `/var/lib/secubox-dns-listes/etat.json` (0644) holds `etat` (`applique`, `inchange`,
`en-cours` — left by a killed pass, the next one verifies and reloads —, `erreur`, `sans-unbound`), `stats`,
`adoptes`, `passes`, `t`, `t_echec` and the `signature` of the inputs actually compiled: a pass whose inputs (sources,
what the compiler reads from the context, compiler code, written files) are unchanged does not recompile, a failure on
the same inputs is retried after one hour, a source deposited during a compilation is picked up (up to three passes).

`/etc/secubox/dns-listes.toml`: `mode = "compile"` (default) or `mode = "direct"` (rollback: sources copied unchanged
under their old names, no compilation).

## Accueil du nom de nœud (`secubox-noeud`, 1.8.40, #3821, #3824, #3883)

Le nom nu de la box, `<nœud>.<zone>` (`secubox-domaine`, ex. `gk2.secubox.in`), montre **par défaut** le dé
SecuBox en plein écran, qui tourne sans fin (`/usr/share/secubox/www/noeud/index.html`, profil Aurora : aucune donnée, aucun appel
réseau, aucune ressource extérieure ; quart de vitesse sous `prefers-reduced-motion`, comme le composant).

Il vivait dans secubox-webos (le Hall, optionnel) jusqu'à 1.21.2 ; il est du cœur depuis 1.8.40 (#3883) : une box
**sans** le Hall sert son accueil, et la carte « Nom du nœud » de `/system/` s'affiche. Le moteur et les six faces du dé
(source : `packages/secubox-webos/www/hall/`) sont livrés par ce paquet sous `/usr/share/secubox/www/noeud/`.

`secubox-noeud appliquer` (lancé par le `postinst`) pose :

- le vhost **généré** `/etc/nginx/conf.d/secubox-noeud.conf` sur `:9080` : `location = /` (la page),
  `/_noeud/sbx-dice.js`, `/_noeud/dice/` (moteur et faces du dé, sous `www/noeud/`) et `location = /api/v1/health`
  (relayée à l'ancienne cible s'il y en a une, sinon `{"status": "ok"}` rendu sur place) ; **tout le reste rend 404**
  (#3824) ; `nginx -t` avant tout rechargement, l'ancien fichier revient sinon ;
- la route sbxwaf `<nœud>.<zone> → :9080` (`secubox-waf-route`) : le WAF reste sur le chemin, jamais de contournement ;
- le vhost HAProxy derrière `sbxwaf_inspector`, s'il n'est pas déjà déclaré.

**L'existant gagne** : un `server_name` qui nomme déjà ce domaine (exact ou `.domaine`), ou une route vers une autre
cible qui **sert** « / », et rien n'est posé. Une ancienne cible qui rend **404** à « / » (cas de gk2 : route à la
main vers le serveur sans nom de `:8000`) est reprise : seule sa santé lui est relayée (voir ci-dessous). Aucune
**nouvelle** exposition tant que le mot de passe admin par défaut est actif (#3401, refus audité). Chaque décision
va dans `/var/log/secubox/audit.log` ; état dans `/var/lib/secubox-noeud/etat.json` (root 0600).
Désactiver : `[noeud] accueil = false` dans `/etc/secubox/noeud/noeud.toml`, puis `secubox-noeud appliquer`. `secubox-noeud
retirer` (`prerm`) retire le vhost et rend à une route reprise son ancienne cible ; `secubox-noeud etat` dit ce qui est en place.

### Relais des autres chemins : une option fermée par défaut (#3824)

Le nom public ne sert **que** le dé et `/api/v1/health` (décision du propriétaire : l'API d'administration n'est jamais
exposée par ce nom). Relayer les autres chemins à l'ancienne cible (sur gk2 : `/api/v1/admin/`, `metrics`,
`metablogizer`, `system/metrics` du serveur `eye-remote-api` :8000) est une **option**, `[noeud] relais_api` de
`/etc/secubox/noeud/noeud.toml`, **fausse par défaut** (absente, illisible, refusée ou autre que `true` = fermé). Une montée depuis
1.21.0, qui relayait tout, réécrit donc le vhost **fermé** (audit `vhost regenere`).

L'administrateur l'ouvre ou la ferme depuis la page **Système** (panneau « Nom du nœud ») :

| Méthode | Route | Garde | Effet |
|---|---|---|---|
| GET | `/api/v1/system/noeud/relais` (secubox-system) | `require_jwt` | état : `relais_api`, `relais_actif`, `vhost`, `domaine`, `cible`, `chemins_cible` (les `location` du serveur nginx qui écoute sur la cible), `source_chemins`, `servis`, `mot_de_passe_defaut` |
| POST | `/api/v1/system/noeud/relais` (secubox-system) | `require_jwt` | `{"actif": bool}` ; **409** pour ouvrir tant que le mot de passe admin par défaut est actif (#3401) ; 500 si `nginx -t` refuse (réglage et vhost remis) |

Écritures **sans sudo** : l'API (secubox, `NoNewPrivileges`) dépose `<id>.demande` dans `/run/secubox/noeud`
(root:secubox 1770) ; `secubox-noeud.path` lance `secubox-noeud.service` (oneshot root durci,
exception RULES-CODE § 10) qui exécute `secubox-noeud traite` : `noeud.toml` réécrit atomiquement (seule la clé change,
TOML validé, mode et propriétaire gardés), vhost régénéré (ni la route sbxwaf ni HAProxy ne sont touchées),
`nginx -t` (par `systemd-run`) puis rechargement, audit `relais_api ouvert|ferme|refus|echec` avec l'acteur et les
chemins relayés ; résultat dans `/run/secubox/noeud-resultats/<id>.json` (0640). Les demandes ne sont pas ouvertes
au jeton délégué du pilotage. En ligne de commande (root) : `secubox-noeud relais activer|desactiver [acteur]`,
`secubox-noeud relais etat`.

### Réglages `/etc/secubox/noeud/noeud.toml` et migration depuis secubox-webos (#3883)

```toml
[noeud]
accueil = true      # false : rien n'est posé sur <nœud>.<zone>, ce qui l'avait été est retiré
relais_api = false  # relais des autres chemins vers l'ancienne cible, FERMÉ par défaut
```

Exemple commenté : `/usr/share/secubox-core/noeud.toml.example`. Le dossier `/etc/secubox/noeud/` est **root:root
0755** et le fichier **root:root 0640** : `/etc/secubox` appartient au compte secubox, qui pourrait y remplacer un
fichier. `secubox-noeud` lit et écrit tout par le descripteur de ce dossier (O_NOFOLLOW, fstat, `fchmod` sur le
descripteur, renommage dans le dossier) ; un dossier ou un fichier lié, d'un autre propriétaire que root ou
inscriptible par groupe ou autres est **ignoré** (accueil par défaut, relais FERMÉ, dit sur stderr). Un relais ouvert
n'est servi par `appliquer` que si le mot de passe admin par défaut est prouvé changé (sinon fermé, audit
`relais_api refuse`).

Le `postinst` lance `secubox-noeud migrer` : dossier créé (un chemin `noeud/` qui n'est pas un vrai dossier de root est
refusé bruyamment), puis `noeud.toml` créé **une fois**, s'il est absent, avec les clés booléennes `accueil` et
`relais_api` de la section `[noeud]` de `/etc/secubox/webos.toml` s'il y en a, sinon les défauts. `relais_api = true`
n'est repris que si le mot de passe admin par défaut est prouvé changé (audit `relais_api migre`, sinon posé fermé et
audit `relais_api refuse-migration`). `webos.toml` présent mais illisible : rien n'est créé, nouvel essai au prochain
configure. `webos.toml` n'est jamais modifié et sa section `[noeud]`
n'est plus lue. L'état `/var/lib/secubox-webos-noeud` est repris (déplacé) vers `/var/lib/secubox-noeud` s'il n'existe
pas encore. Le vhost `/etc/nginx/conf.d/secubox-noeud.conf` garde son nom ; celui posé par webos (en-tête
`webos-noeud`) est reconnu comme le nôtre et régénéré. `Breaks/Replaces: secubox-webos (<< 1.21.3~)` : les deux paquets ne
gèrent jamais ce fichier ensemble.

## LED Heartbeat

Visual system status indicator using IS31FL3199 RGB LEDs on MOCHAbin.

### Configuration

Environment variables in systemd service:

```ini
Environment=LED_COLOR=green   # red, green, or blue
Environment=LED_NUM=1         # LED number (1-3)
```

### Pattern

Double-pulse heartbeat pattern:
- ON 150ms → OFF 150ms → ON 150ms → OFF 700ms (repeat)

### Manual Control

```bash
# Start/stop
systemctl start secubox-led-heartbeat
systemctl stop secubox-led-heartbeat

# Test LED manually
echo 255 > /sys/class/leds/green:led1/brightness
echo 0 > /sys/class/leds/green:led1/brightness
```

## Installation

```bash
apt install secubox-core
```

## Dependencies

- python3
- python3-toml
- i2c-tools (for LED control)

## Files

```
/usr/lib/python3/dist-packages/secubox_core/
/usr/bin/secubox
/usr/bin/secubox-firstboot
/usr/sbin/secubox-led-heartbeat
/usr/sbin/secubox-dns-listes
/usr/lib/python3/dist-packages/secubox_unbound/{__init__,listes,depot}.py
/etc/apparmor.d/secubox-dns-listes
/var/lib/secubox-dns-listes/{sources/,etat.json}
/usr/lib/systemd/system/secubox-*.service
/usr/share/secubox-core/nginx/
/etc/nginx/secubox.d/
```

## License

Proprietary - CyberMind / ANSSI CSPN candidate
