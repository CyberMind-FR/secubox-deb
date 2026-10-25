<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# secubox-meet (La Suite Meet en LXC, identité SecuBox par OIDC) — plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Un paquet `secubox-meet` qui provisionne La Suite Meet dans un LXC, l'expose sous `visio.<domaine>` et `livekit.<domaine>`
derrière sbxwaf, connecte ses usagers par le fournisseur OIDC de la box, et laisse l'ouverture des ports média à une décision
explicite de l'administrateur.

**Architecture:** Même patron que `secubox-jitsi` : un actionneur root `meetctl` (seule surface privilégiée, sudoers à verbe
exact), une bibliothèque de provisionnement `install-lxc.sh` lancée en arrière-plan par une unité oneshot, une API FastAPI
dédiée sous l'utilisateur `secubox` (socket `/run/secubox/meet.sock`) qui délègue tout à `meetctl`, une page d'administration
Aurora `/meet/`, deux vhosts nginx hôte sur 9080. Dans le conteneur (Debian trixie, non privilégié, 10.100.0.195) : PostgreSQL,
Redis, `livekit-server`, le backend Django sous gunicorn, le front construit par Node, un nginx interne.

**Tech Stack:** bash (ctl, provisionnement), Python 3 / FastAPI (API hôte), HTML/CSS/JS autonome (page Aurora), nginx, nftables,
LXC 6, systemd ; dans le LXC : Python 3.13 + uv, Node 20 (trixie), PostgreSQL 17, Redis, LiveKit 1.13.10, Meet v1.34.0.

**Spec:** `docs/superpowers/specs/2026-10-25-visio-meet-lxc-oidc-design.md` (lire aussi `docs/OIDC-FOURNISSEUR.md`).

## Global Constraints

- **LXC uniquement**, jamais Docker ni Podman (AGENTS.md, Pattern 11). Conteneur non privilégié (idmap `u 0 100000 65536`).
- Versions figées : Meet **v1.34.0** (tag amont ; le commit est relevé par `gh api repos/suitenumerique/meet/git/ref/tags/v1.34.0` et
  écrit dans `conf/meet.version`), LiveKit **1.13.10** (`livekit_1.13.10_linux_<arch>.tar.gz`, sommes relevées dans `checksums.txt`
  de la release et écrites dans `conf/meet.version` pour arm64 et amd64 ; arm64 = `ff60607e1931ff078576882fa11c087aa5821d635ac0c47f56ff77e203e32006`).
- Adresse du conteneur `10.100.0.195` sur `br-lxc`, nom `meet`, chemin `/data/lxc` ; passerelle `10.100.0.1`.
- Noms publics : `visio.<domaine>` (Meet) et `livekit.<domaine>` (signalisation), obtenus par `secubox-domaine visio` et
  `secubox-domaine livekit` ; **aucun nom de box en dur** (`gk2`, `gk1`) dans un fichier livré, sauf `menu.d` et `FEATURED` du Hall
  qui portent `visio.gk2.secubox.in` comme les autres entrées (réécrit par `secubox-domaine --migrer`).
- Ports média : **7881/TCP** et **7882/UDP**, DNAT vers le conteneur, table `inet secubox-meet`, fichier
  `/etc/nftables.d/secubox-meet-dnat.nft`, **jamais appliqué par le postinst**.
- Secrets : `/etc/secubox/secrets/meet/` (root:root 0700, fichiers 0600) ; jamais dans un TOML versionné, jamais en argv,
  jamais dans un JSON de `status` ni dans un journal.
- Réglages Meet figés : `DJANGO_CONFIGURATION=Production`, `ALLOW_UNREGISTERED_ROOMS=False`, `RESOURCE_DEFAULT_ACCESS_LEVEL=public`,
  `OIDC_RP_CLIENT_ID=meet`, `OIDC_RP_SIGN_ALGO=RS256`, `OIDC_RP_SCOPES="openid email"`, `OIDC_USE_PKCE=True`,
  `OIDC_PKCE_CODE_CHALLENGE_METHOD=S256`, `OIDC_USERINFO_FULLNAME_FIELDS=["name"]`, `OIDC_USERINFO_SHORTNAME_FIELD=nickname`,
  `OIDC_OP_LOGOUT_ENDPOINT` vide, `CELERY_TASK_ALWAYS_EAGER=True` (pas de travailleur Celery : ni enregistrement ni résumé dans ce
  périmètre), `DATA_DIR=/var/lib/meet`, `REDIS_URL=redis://127.0.0.1:6379/1`, `DB_HOST=127.0.0.1`, `LIVEKIT_API_KEY=meet`,
  `LIVEKIT_API_URL=https://livekit.<domaine>`, `LIVEKIT_INTERNAL_URL=http://127.0.0.1:7880`.
- Adresse de rappel OIDC enregistrée **exactement** : `https://visio.<domaine>/api/v1.0/callback/` (barre finale).
- Émetteur OIDC : `https://hall.<domaine>/oidc` ; points d'accès `/authorize`, `/token`, `/userinfo`, `/jwks`.
- API hôte : socket `/run/secubox/meet.sock`, `require_jwt` sur toute écriture, `require_lecture` sur les lectures, AppArmor
  `enforce`, utilisateur `secubox`, `NoNewPrivileges=no` (sudo vers `meetctl` seulement).
- Paquet : `0.1.0-1~trixie1`, `debian/compat` 13, `Standards-Version: 4.6.2`, en-tête SPDX CMSD-1.0 sur tout fichier, pages et
  messages en français, pas de `confirm()`/`alert()`/`innerHTML`, aucune mention de « CyberMind Produits SASU ».
- Pas de `#DEBHELPER#` en toutes lettres dans un commentaire de script de maintenance (jeton substitué partout).
- Tests : `pytest` dans `packages/secubox-meet` (lxc-*, nft, curl, secubox-oidcctl simulés par des exécutables sur `PATH`), jamais
  d'accès réseau ni de root.

## Review Focus

1. **Domaine de la box inconnu** (`secubox-domaine` vide) : le provisionnement s'arrête avant tout `lxc-create`, message clair,
   code 1 — test `test_sans_domaine_refuse` (Tâche 2).
2. **Second `media-expose --apply`** : une seule table, pas de règle dupliquée (table supprimée avant `nft -f`) —
   `test_apply_deux_fois_supprime_la_table_avant` (Tâche 4).
3. **Le secret OIDC ne fuit pas** : `meetctl status` et `oidc-verifier` n'impriment jamais le secret ; fichier 0600 —
   `test_oidc_enregistrer_ecrit_le_secret_0600_et_ne_l_imprime_pas` (Tâche 3).
4. **Écriture sans confirmation ni session** : `POST /media-expose` sans `confirmer: "meet"` → 400, sans jeton → 401 —
   `test_media_expose_exige_jwt_et_confirmation` (Tâche 6).
5. **Retour après redémarrage** : le conteneur a `lxc.start.auto = 1`, la règle nft revit par le fichier dans `/etc/nftables.d`
   (inclus par `nftables.conf`), les unités internes sont `enabled` — `test_config_lxc_demarre_au_boot` (Tâche 2) et
   `test_apply_pose_le_fichier_dans_nftables_d` (Tâche 4).

---

## Arborescence

```
packages/secubox-meet/
├── api/main.py                       API hôte (FastAPI, délègue à meetctl)
├── apparmor/secubox-meet             profil enforce de l'API
├── conf/meet.toml.example            réglages hôte (lxc_name, lxc_ip, domaine facultatif, ports)
├── conf/meet.nft                     DNAT 7881/TCP + 7882/UDP → conteneur (exemple, jamais auto-appliqué)
├── conf/meet.version                 MEET_TAG, MEET_COMMIT, LIVEKIT_VERSION, LIVEKIT_SHA256_ARM64, LIVEKIT_SHA256_AMD64
├── lib/meet/install-lxc.sh           provisionnement idempotent du LXC
├── lib/meet/rendu.sh                 rendu des fichiers de configuration (sourcé par install-lxc.sh, testable à sec)
├── sbin/meetctl                      actionneur root (JSON sur stdout)
├── nginx/visio-vhost.conf            server_name visio.* → nginx du conteneur :80
├── nginx/livekit-vhost.conf          server_name livekit.* → LiveKit :7880 (WebSocket)
├── nginx/meet-routes.conf            /api/v1/meet/ → meet.sock ; /meet/ → page
├── www/meet/index.html               page d'administration Aurora
├── menu.d/625-meet.json
├── debian/{control,rules,changelog,compat,postinst,prerm,postrm,secubox-meet.service,
│           secubox-meet-provision.service,secubox-meet.sudoers,secubox.yaml}
├── README.md
└── tests/{conftest.py,test_meetctl.py,test_rendu.py,test_nft.py,test_api.py,test_page.py,test_paquet.py}
```

Modifiés ailleurs : `packages/secubox-appstore/www/appstore/boutique-fiches.json`, `packages/secubox-webos/www/hall/index.html`
(FEATURED), `packages/secubox-webos/api/aide_cartes.json`, `.claude/MIGRATION-MAP.md`.

---

### Tâche 1 : squelette du paquet et `meetctl` (cycle de vie, état)

**Files:**
- Create: `packages/secubox-meet/sbin/meetctl`, `conf/meet.toml.example`, `conf/meet.version`, `debian/control`, `debian/compat`,
  `debian/changelog`, `debian/rules`, `debian/secubox-meet.sudoers`, `debian/secubox.yaml`, `tests/conftest.py`, `tests/test_meetctl.py`
- Reference: `packages/secubox-jitsi/sbin/jitsictl`, `packages/secubox-jitsi/api/tests/test_jitsictl.py` (simulation de `lxc-info`,
  `lxc-attach`, `curl` par des exécutables sur `PATH`), `packages/secubox-jitsi/debian/rules`.

**Interfaces:**
- Produces: `meetctl status|start|stop|restart|logs <unite> [n]|help`. `status` imprime un JSON :
  `{"module":"meet","version":"0.1.0","installed":bool,"container":"running|stopped|…","domain":str,"livekit_domain":str,
  "lxc_ip":str,"web_reachable":bool,"services":{"postgresql":…,"redis":…,"livekit":…,"meet-backend":…,"nginx":…},
  "media":{"tcp_port":7881,"udp_port":7882,"exposed":bool},"oidc":{"client_registered":bool}}` — jamais de secret.
  Unités internes connues : `postgresql`, `redis-server`, `livekit`, `meet-backend`, `nginx`.
- Variables d'environnement de test : `SECUBOX_MEET_CONFIG`, `SECUBOX_LXC_PATH`, `SECUBOX_MEET_STATE_DIR`, `SECUBOX_MEET_SECRETS_DIR`,
  `SECUBOX_MEET_NFT_SRC`, `SECUBOX_MEET_NFT_DST` (mêmes noms dans les tâches 3 et 4).
- `conf/meet.toml.example` : `lxc_name = "meet"`, `lxc_ip = "10.100.0.195"`, `# domain = ""`, `# livekit_domain = ""`,
  `tcp_port = 7881`, `udp_port = 7882`, `web_port = 80`.

- [ ] **Step 1: Écrire les tests (rouges)** dans `tests/test_meetctl.py` :

```python
def test_status_rapporte_les_cinq_services_separement(tmp_path):
    out = run_ctl(tmp_path, "status", lxc_state="RUNNING", is_active={"livekit": "failed"})
    d = json.loads(out)
    assert d["container"] == "running" and d["services"]["livekit"] == "failed" and d["services"]["nginx"] == "active"
    assert "secret" not in out.lower() and d["media"] == {"tcp_port": 7881, "udp_port": 7882, "exposed": False}

def test_status_sans_conteneur(tmp_path):
    d = json.loads(run_ctl(tmp_path, "status", lxc_state="", rootfs=False))
    assert d["installed"] is False and all(v == "container-down" for v in d["services"].values())

def test_logs_refuse_une_unite_inconnue(tmp_path):
    rc, out = run_ctl_rc(tmp_path, "logs", "sshd")
    assert rc == 2 and json.loads(out)["success"] is False

def test_start_sans_rootfs_echoue_proprement(tmp_path):
    rc, out = run_ctl_rc(tmp_path, "start", rootfs=False)
    assert rc == 1 and json.loads(out)["error"] == "not installed"
```

`run_ctl` (dans `conftest.py`) pose sur `PATH` des faux `lxc-info`, `lxc-attach` (répond à `systemctl is-active <u>` selon `is_active`,
défaut `active`), `lxc-start`, `lxc-stop`, `curl` (exit 7), `nft` (exit 1), `secubox-domaine` (imprime `<label>.exemple.test`), crée
`<lxc_path>/meet/rootfs` si `rootfs`, et lance `sbin/meetctl` avec les variables d'environnement de test.

- [ ] **Step 2: Vérifier l'échec** — `cd packages/secubox-meet && python -m pytest tests/test_meetctl.py -v` → FAIL (`meetctl` absent).
- [ ] **Step 3: Écrire `sbin/meetctl`** (bash, `set -euo pipefail`, `config_get` plat comme jitsictl, `VERSION="0.1.0"`), les verbes de
  cette tâche, `cmd_help`, et les fichiers Debian : `control` (`Depends: secubox-core (>= 1.7.8~), secubox-auth (>= 1.8.9~), lxc, curl,
  sudo, nftables, python3-uvicorn | python3-pip`, `Recommends: nginx`), `rules` (installe `api/`, `www/`, `menu.d/`, `nginx/*-vhost.conf`
  dans `sites-available/{visio,livekit}.conf`, `meet-routes.conf` dans `secubox-routes.d/`, `sbin/meetctl` 755, `lib/meet/*.sh`,
  sudoers 440, exemples `conf/*` dans `/usr/share/doc/secubox-meet/examples/`, unités ; `override_dh_installsystemd` ne gère que
  `secubox-meet.service`), `changelog` `0.1.0-1~trixie1`, `secubox.yaml` (`category: communication`, `tier: standard`,
  socket `/run/secubox/meet.sock`), sudoers `secubox ALL=(root) NOPASSWD: /usr/sbin/meetctl`.
- [ ] **Step 4: Vérifier** — `python -m pytest tests/test_meetctl.py -v` → PASS ; `shellcheck sbin/meetctl` sans erreur.
- [ ] **Step 5: Commit** — `git add packages/secubox-meet && git commit -m "feat(meet): squelette du paquet et meetctl (ref #3154)"`.

---

### Tâche 2 : provisionnement du LXC (`install-lxc.sh`, `rendu.sh`, unité oneshot)

**Files:**
- Create: `lib/meet/install-lxc.sh`, `lib/meet/rendu.sh`, `debian/secubox-meet-provision.service`, `tests/test_rendu.py`
- Modify: `sbin/meetctl` (verbe `install`)
- Reference: `packages/secubox-jitsi/lib/jitsi/install-lxc.sh` (ensure_bridge, ensure_masquerade, clean_partial_lxc, write_lxc_config,
  décalage idmap, sentinelle), `debian/secubox-jitsi-provision.service`.

**Interfaces:**
- Produces: `rendu.sh` expose `rendre_tout <dossier_sortie>` qui écrit, à partir des variables d'environnement `MEET_DOMAIN`,
  `LIVEKIT_DOMAIN`, `LXC_IP`, `DJANGO_SECRET_KEY`, `DB_PASSWORD`, `LIVEKIT_SECRET`, `OIDC_CLIENT_SECRET` (vide admis), `MEET_ISSUER` :
  `livekit.yaml`, `meet.env`, `nginx-meet.conf`, `meet-backend.service`, `livekit.service`, `lxc-config`. `install-lxc.sh` source
  `rendu.sh` ; `SECUBOX_MEET_DRY_RUN=<dossier>` rend les fichiers et sort 0 **avant** tout appel `lxc-*`.
- Sentinelle `/etc/secubox/meet/.lxc-provisioned` ; `meetctl install` lance `install-lxc.sh` et renvoie `{"success":bool}`.

- [ ] **Step 1: Tests (rouges)** dans `tests/test_rendu.py` (lancent `bash lib/meet/install-lxc.sh` avec `SECUBOX_MEET_DRY_RUN=tmp` et
  les variables) :

```python
def test_sans_domaine_refuse(tmp_path):
    rc, err = run_install(tmp_path, domaine="")       # secubox-domaine simulé renvoie vide
    assert rc == 1 and "domaine" in err.lower() and not any(tmp_path.glob("lxc-*"))   # aucun lxc-create tenté (faux lxc-create écrit un témoin)

def test_rendu_livekit_yaml(tmp_path):
    f = rendu(tmp_path)
    y = f["livekit.yaml"]
    assert "port: 7880" in y and "tcp_port: 7881" in y and "udp_port: 7882" in y and "use_external_ip: true" in y
    assert "port_range_start" not in y and "  meet: " in y and "webhooks-livekit" in y and "redis" in y

def test_rendu_env_meet(tmp_path):
    e = dict(l.split("=", 1) for l in rendu(tmp_path)["meet.env"].splitlines() if "=" in l)
    assert e["DJANGO_CONFIGURATION"] == "Production" and e["ALLOW_UNREGISTERED_ROOMS"] == "False"
    assert e["OIDC_OP_AUTHORIZATION_ENDPOINT"] == "https://hall.exemple.test/oidc/authorize"
    assert e["OIDC_RP_SCOPES"] == '"openid email"' and e["OIDC_USE_PKCE"] == "True" and "OIDC_OP_LOGOUT_ENDPOINT" not in e
    assert e["LIVEKIT_API_URL"] == "https://livekit.exemple.test" and e["LIVEKIT_INTERNAL_URL"] == "http://127.0.0.1:7880"
    assert e["DJANGO_ALLOWED_HOSTS"] == "visio.exemple.test" and e["DJANGO_CSRF_TRUSTED_ORIGINS"] == "https://visio.exemple.test"
    assert e["CELERY_TASK_ALWAYS_EAGER"] == "True" and e["DATA_DIR"] == "/var/lib/meet"

def test_rendu_nginx_interne(tmp_path):
    n = rendu(tmp_path)["nginx-meet.conf"]
    assert "root /opt/meet/frontend" in n and "proxy_pass http://127.0.0.1:8000" in n
    assert "/api/" in n and "/admin/" in n and "/static/" in n and "/index.html" in n

def test_config_lxc_demarre_au_boot(tmp_path):
    c = rendu(tmp_path)["lxc-config"]
    assert "lxc.start.auto = 1" in c and "lxc.idmap = u 0 100000 65536" in c and "10.100.0.195/24" in c
    assert "lxc.cgroup2.memory.max = 2147483648" in c and "lxc.net.0.link = br-lxc" in c
```

- [ ] **Step 2: Vérifier l'échec** — `python -m pytest tests/test_rendu.py -v` → FAIL.
- [ ] **Step 3: Écrire `rendu.sh` et `install-lxc.sh`.** Ordre de `main` : `require_cmds` → domaine (sinon `fail`) → `DRY_RUN` (rendu puis
  `exit 0`) → `ensure_dirs` → `ensure_bridge` → `ensure_masquerade` → `create_lxc` (`--dist debian --release trixie`) →
  `write_lxc_config` (idmap, `lxc.start.auto = 1`, `lxc.start.delay = 5`, mémoire 2 Gio) → `start_lxc` → `wait_for_network` →
  `ensure_resolv` → `install_in_lxc` → `mark_provisioned`. `install_in_lxc`, par `lxc-attach -- bash -e`, idempotent :
  `apt-get install postgresql redis-server nginx python3 python3-venv nodejs npm git ca-certificates curl libmagic1 libpango-1.0-0`,
  création `meet` (utilisateur système, `/var/lib/meet`), clone `--depth 1 --branch $MEET_TAG` dans `/opt/meet/src` puis vérification
  du commit `$MEET_COMMIT` (sinon échec), backend : `python3 -m venv /opt/meet/venv && venv/bin/pip install uv && venv/bin/uv sync
  --locked --no-dev` dans `src/backend` ; front : `npm ci --ignore-scripts && npm run build` dans `src/frontend` → `/opt/meet/frontend`
  (= `dist`) ; LiveKit : téléchargement `livekit_$LIVEKIT_VERSION_linux_$(dpkg --print-architecture).tar.gz`, `sha256sum -c` contre
  `conf/meet.version`, binaire dans `/usr/local/bin/livekit-server` ; base : `createuser meet`, `createdb -O meet meet`, mot de passe
  depuis `meet.env` ; `python manage.py migrate`, `collectstatic --noinput`, `compilemessages` ; copie des fichiers rendus
  (`/etc/meet/meet.env` 0640 root:meet, `/etc/livekit/livekit.yaml` 0640 root:livekit, `/etc/nginx/sites-enabled/meet`), unités
  `meet-backend.service` (gunicorn `-b 127.0.0.1:8000 -w 2 meet.wsgi:application`, `EnvironmentFile=/etc/meet/meet.env`) et
  `livekit.service` ; `systemctl enable --now` des cinq. Les secrets sont générés **une fois** sur l'hôte dans
  `$SECRETS_DIR/{django-secret,db-password,livekit-secret}` (0600) et relus à chaque passe. Une `MEET_DOMAIN` différente de celle
  enregistrée dans `$STATE_DIR/domaine` déclenche un nouveau rendu + redémarrage des unités (pas de purge : Meet garde des salles).
- [ ] **Step 4: Écrire `debian/secubox-meet-provision.service`** (copie de l'unité jitsi : `ConditionPathExists=!/etc/secubox/meet/.lxc-provisioned`,
  `TimeoutStartSec=3600`, `Restart=on-failure`, `RestartSec=15min`) et le verbe `meetctl install`.
- [ ] **Step 5: Vérifier** — `python -m pytest tests -v` → PASS ; `shellcheck lib/meet/*.sh`.
- [ ] **Step 6: Commit** — `git commit -m "feat(meet): provisionnement du LXC trixie, rendu des configurations (ref #3154)"`.

---

### Tâche 3 : identité — enregistrement OIDC et vérification depuis le conteneur

**Files:**
- Modify: `sbin/meetctl` (verbes `oidc-enregistrer`, `oidc-verifier`), `lib/meet/install-lxc.sh` (appel de l'enregistrement avant le rendu)
- Test: `tests/test_meetctl.py`
- Reference: `packages/secubox-auth/composants/oidc/sbin/secubox-oidcctl` (`client-add ID --redirect URI --name NOM` imprime le secret
  **une fois** sur stdout, exit ≠ 0 sinon), `docs/OIDC-FOURNISSEUR.md`.

**Interfaces:**
- Produces: `meetctl oidc-enregistrer` → appelle `secubox-oidcctl client-add meet --name Visio --redirect https://visio.<domaine>/api/v1.0/callback/`,
  écrit le secret dans `$SECRETS_DIR/oidc-client-secret` (0600), imprime `{"success":true,"client_id":"meet","redirect_uri":"…"}`.
  Idempotent : si le fichier existe, ne réenregistre pas (`{"success":true,"already":true}`) sauf `--renouveler`.
- `meetctl oidc-verifier` → depuis le conteneur (`lxc-attach -- curl -fsS --max-time 10`) lit `<issuer>/.well-known/openid-configuration`
  et `jwks_uri` ; imprime `{"issuer":…,"discovery":bool,"jwks":bool,"keys":int,"redirect_registered":bool,"hint":str}` ; code 1 si
  la découverte échoue (écart 5 de #3155). Jamais de secret.

- [ ] **Step 1: Tests (rouges)** :

```python
def test_oidc_enregistrer_ecrit_le_secret_0600_et_ne_l_imprime_pas(tmp_path):
    out = run_ctl(tmp_path, "oidc-enregistrer", oidcctl_secret="S3CR3T")   # faux secubox-oidcctl sur PATH
    assert "S3CR3T" not in out and json.loads(out)["redirect_uri"] == "https://visio.exemple.test/api/v1.0/callback/"
    f = tmp_path / "secrets" / "oidc-client-secret"
    assert f.read_text().strip() == "S3CR3T" and oct(f.stat().st_mode & 0o777) == "0o600"
    assert (tmp_path / "appels").read_text().split("\n")[0] == "client-add meet --name Visio --redirect https://visio.exemple.test/api/v1.0/callback/"

def test_oidc_enregistrer_est_idempotent(tmp_path):
    run_ctl(tmp_path, "oidc-enregistrer", oidcctl_secret="A")
    d = json.loads(run_ctl(tmp_path, "oidc-enregistrer", oidcctl_secret="B"))
    assert d["already"] is True and (tmp_path / "secrets" / "oidc-client-secret").read_text().strip() == "A"

def test_oidc_verifier_depuis_le_conteneur(tmp_path):
    d = json.loads(run_ctl(tmp_path, "oidc-verifier", attach_curl={"openid-configuration": DISCOVERY, "jwks": JWKS}))
    assert d["discovery"] and d["jwks"] and d["keys"] == 1 and d["issuer"] == "https://hall.exemple.test/oidc"
    rc, out = run_ctl_rc(tmp_path, "oidc-verifier", attach_curl={})
    assert rc == 1 and json.loads(out)["discovery"] is False and "hosts" in json.loads(out)["hint"]
```

- [ ] **Step 2: Vérifier l'échec** → FAIL (verbes inconnus).
- [ ] **Step 3: Implémenter** les deux verbes ; `install-lxc.sh` appelle `oidc-enregistrer` (par `meetctl`, même hôte) avant `rendre_tout`
  et passe `OIDC_CLIENT_SECRET` au rendu ; l'indice d'échec de `oidc-verifier` nomme la cause probable (« le conteneur ne joint pas
  hall.<domaine> : vérifier la résolution DNS/NAT en épingle ; en dernier recours, une entrée /etc/hosts dans le conteneur vers
  l'adresse LAN du HAProxy qui sert ce nom »).
- [ ] **Step 4: Vérifier** → PASS.
- [ ] **Step 5: Commit** — `git commit -m "feat(meet): client OIDC enregistré par meetctl, vérification depuis le conteneur (ref #3154, #3155)"`.

---

### Tâche 4 : exposition des médias (`meet.nft`, `media-expose`)

**Files:**
- Create: `conf/meet.nft`, `tests/test_nft.py`
- Modify: `sbin/meetctl` (verbe `media-expose [--apply|--revoke]`, champ `media.exposed` du status)
- Reference: `packages/secubox-jitsi/conf/jitsi.nft`, `jitsictl cmd_media_expose`.

**Interfaces:**
- Produces: `conf/meet.nft` = table `inet secubox-meet`, chaîne `prerouting` (`type nat hook prerouting priority dstnat`), deux règles
  `iifname != "br-lxc" tcp dport 7881 counter dnat ip to 10.100.0.195:7881` et `… udp dport 7882 … :7882`. `media-expose --apply`
  copie le fichier vers `$NFT_DST`, `nft delete table inet secubox-meet` puis `nft -f` ; refus de `nft` → fichier retiré, code 1.
  `--revoke` : table supprimée, fichier retiré. Sans argument : `{"file_installed":bool,"rule_live":bool,…}`.

- [ ] **Step 1: Tests (rouges)** :

```python
def test_fichier_nft_deux_regles_vers_le_conteneur():
    t = NFT.read_text()
    assert "table inet secubox-meet" in t and 'iifname != "br-lxc" tcp dport 7881 counter dnat ip to 10.100.0.195:7881' in t
    assert "udp dport 7882 counter dnat ip to 10.100.0.195:7882" in t and "input" not in t.split("table")[1]

def test_apply_pose_le_fichier_dans_nftables_d(tmp_path):
    d = json.loads(run_ctl(tmp_path, "media-expose", "--apply", nft_ok=True))
    assert d["success"] and (tmp_path / "nftables.d" / "secubox-meet-dnat.nft").exists()

def test_apply_deux_fois_supprime_la_table_avant(tmp_path):
    run_ctl(tmp_path, "media-expose", "--apply", nft_ok=True); run_ctl(tmp_path, "media-expose", "--apply", nft_ok=True)
    appels = (tmp_path / "nft-appels").read_text().splitlines()
    assert appels.count("delete table inet secubox-meet") == 2 and all(a.startswith(("delete", "-f", "list")) for a in appels)

def test_apply_refuse_par_nft_ne_laisse_rien(tmp_path):
    rc, out = run_ctl_rc(tmp_path, "media-expose", "--apply", nft_ok=False)
    assert rc == 1 and not (tmp_path / "nftables.d" / "secubox-meet-dnat.nft").exists()
```

- [ ] **Step 2: Vérifier l'échec** → FAIL.
- [ ] **Step 3: Implémenter** `conf/meet.nft` (commentaire d'en-tête : pourquoi une seule chaîne nat suffit, pourquoi `counter`, pourquoi
  non appliqué par le postinst, rappel routeur FAI / DMZ / #3160) et le verbe.
- [ ] **Step 4: Vérifier** → PASS.
- [ ] **Step 5: Commit** — `git commit -m "feat(meet): exposition des médias sur décision, DNAT 7881/TCP 7882/UDP (ref #3154)"`.

---

### Tâche 5 : vhosts hôte, scripts de maintenance, README

**Files:**
- Create: `nginx/visio-vhost.conf`, `nginx/livekit-vhost.conf`, `nginx/meet-routes.conf`, `debian/postinst`, `debian/prerm`,
  `debian/postrm`, `README.md`, `tests/test_paquet.py`
- Reference: `packages/secubox-jitsi/nginx/jitsi-vhost.conf` (WebSocket, `X-Forwarded-Proto https`), `packages/secubox-appstore/debian/postinst`
  (bloc vhost → `nginx -t` → `secubox-waf-route` → `haproxyctl vhost add … sbxwaf_inspector`), `packages/secubox-appstore/nginx/boutique.vhost.conf`
  (en-têtes), `packages/secubox-jitsi/debian/postinst` (provisionnement démarré `--no-block` **après** le bloc debhelper).

**Interfaces:**
- `visio-vhost.conf` : `listen 9080; server_name visio.*;` → `proxy_pass http://10.100.0.195:80;` avec `Host`, `X-Forwarded-For`,
  `X-Forwarded-Proto https`, WebSocket (`map $http_upgrade`), `proxy_read_timeout 900s`, `client_max_body_size 50m`.
- `livekit-vhost.conf` : `server_name livekit.*;` → `proxy_pass http://10.100.0.195:7880;` WebSocket, `proxy_read_timeout 3600s`,
  `proxy_buffering off`.
- `meet-routes.conf` : `location /api/v1/meet/ { rewrite … ; proxy_pass http://unix:/run/secubox/meet.sock; include snippets/secubox-proxy.conf; }`
  et `location /meet/ { alias /usr/share/secubox/www/meet/; try_files $uri $uri/ /meet/index.html; }`.
- `postinst configure` : utilisateur `secubox` ; dossiers (`/etc/secubox/meet` 0755, `/etc/secubox/secrets/meet` 0700 root, `/var/cache/secubox/meet`
  secubox 0755) ; `meet.toml` depuis l'exemple (640 root:secubox) si absent ; `visudo -cf` ; AppArmor (`apparmor_parser -r`, Tâche 7) ;
  liens `sites-enabled/{visio,livekit}.conf` ; `nginx -t` puis, pour chacun des deux domaines (`secubox-domaine visio|livekit`),
  `secubox-waf-route <dom> 9080` et `haproxyctl vhost add <dom> sbxwaf_inspector true` si `haproxy.toml` existe et ne le cite pas,
  `haproxyctl generate` + `reload haproxy` ; sinon retrait des liens et message ; `systemctl enable --now secubox-meet.service` ;
  **après** le bloc debhelper : `enable` + `start --no-block secubox-meet-provision.service`.
- `prerm remove` : `systemctl stop secubox-meet.service secubox-meet-provision.service` ; `meetctl media-expose --revoke || true` ;
  `meetctl stop || true`. `postrm remove|purge` : liens `sites-enabled` retirés, `nginx -t && reload` ; `purge` seulement : `rm -rf
  /etc/secubox/meet /etc/secubox/secrets/meet` et `secubox-oidcctl client-rm meet || true` ; **jamais** le conteneur ni `/data/lxc/meet`
  (données des salles ; retrait par `meetctl destroy` documenté dans le README, hors de ce plan).

- [ ] **Step 1: Tests (rouges)** dans `tests/test_paquet.py` (lecture de fichiers) :

```python
def test_vhosts_jokers_et_websocket():
    v, l = VISIO.read_text(), LIVEKIT.read_text()
    assert "server_name visio.*;" in v and "server_name livekit.*;" in l and "listen 9080;" in v and "listen 9080;" in l
    for t in (v, l):
        assert "proxy_set_header Upgrade $http_upgrade" in t and "X-Forwarded-Proto https" in t and not re.search(r"gk\d", t)
    assert "proxy_pass http://10.100.0.195:80;" in v and "proxy_pass http://10.100.0.195:7880;" in l

def test_postinst_waf_et_haproxy_apres_nginx_t_et_provision_apres_debhelper():
    p = POSTINST.read_text()
    assert p.index("nginx -t") < p.index("secubox-waf-route") < p.index("haproxyctl vhost add") and "sbxwaf_inspector" in p
    assert p.index("#DEBHELPER" + "#") < p.index("secubox-meet-provision.service")
    assert "media-expose --apply" not in p and "nft -f" not in p          # jamais d'ouverture par apt install

def test_postrm_purge_retire_les_secrets_mais_jamais_le_conteneur():
    p = POSTRM.read_text()
    assert "secrets/meet" in p and "client-rm meet" in p and "lxc-destroy" not in p and "/data/lxc" not in p

def test_scripts_de_maintenance_valides():
    for f in (POSTINST, PRERM, POSTRM): assert subprocess.run(["bash", "-n", f]).returncode == 0
    assert "DEBHELPER" not in "".join(l for l in POSTINST.read_text().splitlines() if l.strip().startswith("#"))
```

- [ ] **Step 2: Vérifier l'échec** → FAIL.
- [ ] **Step 3: Écrire** les trois fichiers nginx, les trois scripts, le README (installation, noms, ports à ouvrir sur décision + #3160,
  OIDC, mise à jour : `meetctl install` rejoue le provisionnement après changement de `conf/meet.version`, sauvegarde base par
  `lxc-attach -- sudo -u postgres pg_dump meet`).
- [ ] **Step 4: Vérifier** → PASS ; `dpkg-buildpackage -d -us -uc -b` depuis `packages/secubox-meet` produit le `.deb` (`lintian` non requis).
- [ ] **Step 5: Commit** — `git commit -m "feat(meet): vhosts visio.* et livekit.*, scripts de maintenance (ref #3154)"`.

---

### Tâche 6 : API hôte dédiée (`secubox-meet.service`)

**Files:**
- Create: `api/main.py`, `api/__init__.py`, `debian/secubox-meet.service`, `tests/test_api.py`
- Reference: `packages/secubox-jitsi/api/main.py` (`_run_ctl`, `_ctl_json`, double cache de `/status`, `_borne` 25 s),
  `packages/secubox-appstore/debian/secubox-appstore.service` (unité `User=secubox`, `--uds`), `packages/secubox-appstore/api/main.py`
  (`ACTIONS_CONFIRMEES` : l'appelant réécrit le nom), `packages/secubox-jitsi/api/tests/test_api.py`.

**Interfaces:**
- Routes (préfixe `/api/v1/meet`) : `GET /health` (libre) ; `GET /status` (`require_lecture`, cache 60 s mémoire + fichier
  `/var/cache/secubox/meet/status.json`) ; `GET /media-expose` (`require_lecture`) ; `POST /media-expose` `{action: "apply"|"revoke",
  confirmer: "meet"}` (`require_jwt`) ; `POST /control` `{action: start|stop|restart}` (`require_jwt`) ; `GET /oidc` (`require_jwt`,
  = `meetctl oidc-verifier`) ; `POST /oidc/enregistrer` (`require_jwt`) ; `GET /logs?unit=&lines=` (`require_jwt`, unités connues).
- Unité : `User=secubox`, `ExecStart=/usr/bin/python3 -m uvicorn api.main:app --uds /run/secubox/meet.sock --workers 1`,
  `WorkingDirectory=/usr/lib/secubox/meet`, `NoNewPrivileges=no`, `ProtectHome=yes`, `PrivateTmp=yes`,
  `ReadWritePaths=/run/secubox /var/cache/secubox/meet /var/log/secubox`, `AppArmorProfile=secubox-meet-api` (Tâche 7).

- [ ] **Step 1: Tests (rouges)** (ASGI par `httpx.ASGITransport`, `require_jwt`/`require_lecture` remplacés par des dépendances de test,
  `_run_ctl` remplacé par une fonction qui enregistre les arguments) :

```python
def test_media_expose_exige_jwt_et_confirmation(cli):
    assert cli.post("/media-expose", json={"action": "apply"}, jwt=False).status_code == 401
    assert cli.post("/media-expose", json={"action": "apply"}, jwt=True).status_code == 400
    assert cli.post("/media-expose", json={"action": "apply", "confirmer": "meet"}, jwt=True).status_code == 200
    assert cli.appels[-1] == ("media-expose", "--apply")

def test_control_refuse_une_action_inconnue(cli):
    assert cli.post("/control", json={"action": "destroy"}, jwt=True).status_code == 400 and not cli.appels

def test_status_lecture_cachee(cli):
    cli.get("/status"); cli.get("/status")
    assert cli.appels.count(("status",)) == 1

def test_logs_unite_inconnue_400(cli):
    assert cli.get("/logs?unit=sshd", jwt=True).status_code == 400
```

- [ ] **Step 2: Vérifier l'échec** → FAIL.
- [ ] **Step 3: Implémenter** `api/main.py` (import strict de `secubox_core.auth`, aucun repli) et l'unité.
- [ ] **Step 4: Vérifier** → PASS.
- [ ] **Step 5: Commit** — `git commit -m "feat(meet): API hôte dédiée, délègue à meetctl (ref #3154)"`.

---

### Tâche 7 : page d'administration Aurora, menu, AppArmor

**Files:**
- Create: `www/meet/index.html`, `menu.d/625-meet.json`, `apparmor/secubox-meet`, `tests/test_page.py`
- Modify: `debian/rules` (profil dans `/etc/apparmor.d/`), `debian/postinst` (`apparmor_parser -r`)
- Reference: `packages/secubox-jitsi/www/jitsi/index.html` (page Aurora autonome, `?embed=1`, `?demo=1`, hauteur `sbxVue`),
  `.claude/AURORA-REFERENCE.md`, `packages/secubox-webfilter/apparmor/secubox-webfilter` (forme du profil),
  `packages/secubox-jitsi/api/tests/test_jitsi_aurora_2612.py` (test navigateur avec API simulée).

**Interfaces:**
- Page : tuiles (conteneur, 5 services, médias exposés oui/non, OIDC vérifié), actions `start|stop|restart`, panneau « Ouvrir les ports
  média » avec **confirmation intégrée** (Confirmer/Annuler, envoie `confirmer: "meet"`), « Vérifier l'identité » (GET /oidc), journal
  d'une unité. Messages en français, `—` pour toute mesure absente, bandeau orange en `?demo=1`, aucune action en démonstration.
- `menu.d/625-meet.json` : `{"id":"meet","domain":"visio.gk2.secubox.in","name":"Visio (Meet)","icon":"🎥","path":"/meet/",
  "category":"communication","order":625,"description":"Visioconférence La Suite Meet","theme":"correspondance"}`.
- Profil AppArmor `secubox-meet-api` : lecture `/usr/lib/secubox/meet/**`, python, `/etc/secubox/meet.toml`, `/etc/secubox/secubox.conf`,
  `/etc/secubox/auth.toml`, sessions ; écriture `/var/cache/secubox/meet/**`, `/run/secubox/meet.sock` ; `deny /etc/secubox/secrets/** r` ;
  exécution de `/usr/bin/sudo` (`ux`) pour `meetctl`.

- [ ] **Step 1: Tests (rouges)** dans `tests/test_page.py` :

```python
def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC and not re.findall(r'<script src="(?!/shared/sidebar.js)', SRC)
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick=", "https://", "http://"):
        assert interdit not in SRC
    assert "sbxVue" in SRC and "onglet:'meet'" in SRC and "sbx_token" in SRC and "demo" in SRC

def test_ecritures_portent_la_confirmation():
    assert '"confirmer":"meet"' in SRC.replace(" ", "") and "'/media-expose'" in SRC and "'/control'" in SRC

def test_profil_apparmor_refuse_les_secrets():
    p = APPARMOR.read_text()
    assert "deny /etc/secubox/secrets/** r," in p and "/run/secubox/meet.sock" in p and "profile secubox-meet-api" in p

# navigateur (playwright, API simulée) :
def test_ports_media_exigent_une_confirmation_dans_la_page(navigateur): ...   # clic « Ouvrir » → boutons Confirmer/Annuler, aucun POST avant Confirmer
def test_largeur_telephone_sans_debordement(navigateur): ...                   # 420 px, scrollWidth <= innerWidth
```

- [ ] **Step 2: Vérifier l'échec** → FAIL.
- [ ] **Step 3: Écrire** la page, le menu, le profil, les ajouts `rules`/`postinst`.
- [ ] **Step 4: Vérifier** → PASS ; `apparmor_parser -Q -K apparmor/secubox-meet` (analyse seule) sans erreur si l'outil est présent.
- [ ] **Step 5: Commit** — `git commit -m "feat(meet): page d'administration Aurora, menu, profil AppArmor (ref #3154)"`.

---

### Tâche 8 : Boutique et Hall

**Files:**
- Modify: `packages/secubox-appstore/www/appstore/boutique-fiches.json` (+ changelog `0.10.2`), `packages/secubox-webos/www/hall/index.html`
  (FEATURED), `packages/secubox-webos/api/aide_cartes.json` (+ changelog `1.20.4`), `.claude/MIGRATION-MAP.md`
- Test: `packages/secubox-appstore/tests/test_boutique_3148.py` (fiche), `packages/secubox-webos/tests/test_aide.py` (déjà : chaque carte a son aide)

**Interfaces:**
- Fiche `secubox-meet` : `nom "Visio"`, `resume "Appels vidéo privés"`, `categorie "Communication"`, `detail` (une phrase : visio libre
  de La Suite numérique, hébergée chez vous, connexion par votre compte SecuBox), `ordre 10`, et un champ nouveau `solutions`
  = `[{"paquet":"secubox-jitsi","nom":"Jitsi"},{"paquet":"secubox-meet","nom":"La Suite Meet"}]` que la fiche affiche en ligne
  « Autres solutions : … » (chaque nom cliquable si le paquet est dans le catalogue). `secubox-jitsi` reçoit le même champ.
- Hall : `{id:"visio", label:"Visio", icon:"🎥", color:"#1d5fa8", url:"visio.gk2.secubox.in", admin:"/meet/", h:236, si_present:"meet"}`
  (`si_present` : la carte n'apparaît que si le module est sur la box — vérifier le nom exact du mécanisme dans `index.html`,
  ligne `const cibles = FEATURED.filter(f=>f.si_present)`), aide dans `aide_cartes.json` (rôle, usage, `acces: "session"`).

- [ ] **Step 1: Tests (rouges)** : dans `test_boutique_3148.py`, `test_fiche_visio_et_solutions_alternatives` (fiche présente, `solutions`
  cite les deux paquets, la page affiche « Autres solutions » quand les deux sont au catalogue) ; `test_aide.py` échoue tant que la carte
  `visio` n'a pas d'aide.
- [ ] **Step 2: Vérifier l'échec** → FAIL.
- [ ] **Step 3: Implémenter** (boutique.html : rendu de `solutions` par `textContent`, jamais `innerHTML`).
- [ ] **Step 4: Vérifier** → `python -m pytest tests/test_boutique_3148.py tests/test_boutique_vhost_3150.py -q` et
  `python -m pytest tests/test_aide.py -q` → PASS.
- [ ] **Step 5: Commit** — `git commit -m "feat: fiche Visio avec solutions alternatives, carte Visio du Hall (ref #3154)"`.

---

### Tâche 9 : essai de bout en bout sur gk1 (contrôleur, après fusion — pas un sous-agent)

Pas de code. Exécuté par le contrôleur de session, avec l'accord du propriétaire, après publication des paquets.

- [ ] `apt-get install secubox-meet` sur gk1 ; `journalctl -fu secubox-meet-provision` jusqu'à la sentinelle (compter 15–30 min :
  `npm ci` + `npm run build` sur arm64).
- [ ] `meetctl status` : cinq services `active`, `web_reachable true` ; `meetctl oidc-verifier` : `discovery true, jwks true`.
  Si `discovery false` : appliquer l'indice (`/etc/hosts` du conteneur) et consigner la décision dans la spec.
- [ ] Depuis Internet : `https://visio.gk1.secubox.in/` → page Meet (200, `x-secubox-waf: inspected`) ; « Se connecter » → connexion du
  Hall → retour sur Meet avec le compte de la personne ; `wss://livekit.gk1.secubox.in/rtc` → 101.
- [ ] Depuis la page d'administration : « Ouvrir les ports média » → confirmer → `nft list table inet secubox-meet` montre les deux
  règles ; sur la Freebox, redirections 7881/TCP et 7882/UDP vers gk1 (à la main tant que #3160 n'est pas livré).
- [ ] Deux participants (un sur le LAN, un en 4G) dans une salle : audio et vidéo dans les deux sens ; compteurs `counter` des règles
  nft non nuls. Retirer l'exposition : `media-expose --revoke`, table absente.
- [ ] `HISTORY.md`, `MIGRATION-MAP.md`, `WIP.md` ; fermeture de #3154 par `closes #3154` une fois déployé.

---

## Auto-revue

- **Couverture de la spec** : conteneur et briques (T2), exposition et noms (T5), médias sur décision (T4, T7, T9), identité (T3, T6),
  écarts 5 (T3) ; Boutique et solutions par besoin (T8) ; sécurité : secrets (T2/T3), AppArmor (T7), surface réduite (T4/T5),
  confinement (T2) ; tests et preuves (chaque tâche + T9). Non couvert, volontairement : fédération d'identité (#3157), redirections
  Freebox (#3160), enregistrement/transcription/téléphonie, restriction d'accès par client (facultative d'après la décision 1).
- **Cohérence des noms** : `meetctl` et ses verbes (`status`, `start`, `stop`, `restart`, `logs`, `install`, `oidc-enregistrer`,
  `oidc-verifier`, `media-expose`) sont identiques dans T1, T3, T4, T6, T7 ; adresse `10.100.0.195` et ports `7881/7882` partout ;
  variables d'environnement de test définies en T1 et réutilisées.
- **Décisions prises ici (à valider par le propriétaire)** : pas de travailleur Celery (`CELERY_TASK_ALWAYS_EAGER=True`) ; mémoire du
  conteneur 2 Gio ; front construit **dans le conteneur** avec le Node de trixie (20.19) plutôt qu'à la fabrication du paquet ;
  Meet installé depuis le dépôt Git au tag (commit vérifié) plutôt que depuis une image ; `purge` retire les secrets et le client OIDC
  mais jamais le conteneur ; la confirmation « ports média » vit dans la page d'administration `/meet/` (la Boutique y mène par ⚙️),
  pas dans la Boutique elle-même, dont le vhost ne joint que l'API de l'App Store.
