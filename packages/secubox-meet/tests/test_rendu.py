# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Rendu des configurations du LXC Meet : install-lxc.sh en mode essai à blanc (aucun lxc-*, aucun root)."""
import hashlib
import re
import subprocess
from pathlib import Path

from conftest import _ecrire_exec, _env_ctl, fonction_bash, script_interne

RACINE = Path(__file__).resolve().parents[1]
INSTALL = RACINE / "lib" / "meet" / "install-lxc.sh"
FICHIERS = ("livekit.yaml", "meet.env", "nginx-meet.conf", "meet-backend.service", "livekit.service", "lxc-config", "conteneur-eth0.network")


def run_install(tmp_path, domaine=None):
    """Lance install-lxc.sh en essai à blanc ; renvoie (code, stderr)."""
    env = _env_ctl(tmp_path, domaine=domaine)
    # Un lxc-create qui laisse un témoin : prouve qu'aucun lxc-* n'a été appelé.
    _ecrire_exec(tmp_path / "bin" / "lxc-create", f'#!/bin/bash\ntouch "{tmp_path}/lxc-create.temoin"\n')
    env["SECUBOX_MEET_DRY_RUN"] = str(tmp_path / "rendu")
    env["SECUBOX_MEET_VERSION_FILE"] = str(RACINE / "conf" / "meet.version")
    r = subprocess.run(["bash", str(INSTALL)], capture_output=True, text=True, env=env, timeout=60)
    return r.returncode, r.stderr


def rendu(tmp_path):
    rc, err = run_install(tmp_path)
    assert rc == 0, err
    return {nom: (tmp_path / "rendu" / nom).read_text() for nom in FICHIERS}


def test_sans_domaine_refuse(tmp_path):
    rc, err = run_install(tmp_path, domaine="")
    assert rc == 1 and "domaine" in err.lower()
    assert not any(tmp_path.glob("lxc-*")) and not (tmp_path / "rendu").exists()


def test_rendu_livekit_yaml(tmp_path):
    y = rendu(tmp_path)["livekit.yaml"]
    assert "port: 7880" in y and "tcp_port: 7881" in y and "udp_port: 7882" in y and "use_external_ip: true" in y
    assert "port_range_start" not in y and "  meet: " in y and "webhooks-livekit" in y and "redis" in y


def test_rendu_env_meet(tmp_path):
    e = dict(ligne.split("=", 1) for ligne in rendu(tmp_path)["meet.env"].splitlines() if "=" in ligne)
    assert e["DJANGO_CONFIGURATION"] == "Production" and e["ALLOW_UNREGISTERED_ROOMS"] == "False"
    assert e["OIDC_OP_AUTHORIZATION_ENDPOINT"] == "https://hall.exemple.test/oidc/authorize"
    assert e["OIDC_RP_SCOPES"] == '"openid email"' and e["OIDC_USE_PKCE"] == "True" and "OIDC_OP_LOGOUT_ENDPOINT" not in e
    assert e["LIVEKIT_API_URL"] == "https://livekit.exemple.test" and e["LIVEKIT_INTERNAL_URL"] == "http://127.0.0.1:7880"
    assert e["DJANGO_ALLOWED_HOSTS"] == "visio.exemple.test" and e["DJANGO_CSRF_TRUSTED_ORIGINS"] == "https://visio.exemple.test"
    assert e["CELERY_TASK_ALWAYS_EAGER"] == "True" and e["DATA_DIR"] == "/var/lib/meet"
    # ListValue de Meet découpe sur les virgules : pas de syntaxe JSON.
    assert e["OIDC_USERINFO_FULLNAME_FIELDS"] == "name"


def test_env_secrets_generes_et_coherents(tmp_path):
    f = rendu(tmp_path)
    e = dict(ligne.split("=", 1) for ligne in f["meet.env"].splitlines() if "=" in ligne)
    secrets = tmp_path / "secrets"
    assert len(e["DJANGO_SECRET_KEY"]) >= 50 and len(e["DB_PASSWORD"]) == 32 and len(e["LIVEKIT_API_SECRET"]) == 32
    assert e["OIDC_RP_CLIENT_SECRET"] == ""
    assert f"  meet: {e['LIVEKIT_API_SECRET']}" in f["livekit.yaml"]
    for nom in ("django-secret", "db-password", "livekit-secret"):
        assert ((secrets / nom).stat().st_mode & 0o777) == 0o600
    assert (secrets.stat().st_mode & 0o777) == 0o700
    # Relancé : les secrets sont réutilisés, pas régénérés.
    avant = (secrets / "django-secret").read_text()
    assert run_install(tmp_path)[0] == 0
    assert (secrets / "django-secret").read_text() == avant


def test_secret_oidc_repris_s_il_existe(tmp_path):
    (tmp_path / "secrets").mkdir()
    (tmp_path / "secrets" / "oidc-client-secret").write_text("secretoidc123\n")
    assert "OIDC_RP_CLIENT_SECRET=secretoidc123\n" in rendu(tmp_path)["meet.env"]


def test_rendu_nginx_interne(tmp_path):
    n = rendu(tmp_path)["nginx-meet.conf"]
    assert "root /opt/meet/frontend" in n and "proxy_pass http://127.0.0.1:8000" in n
    assert "/api/" in n and "/admin/" in n and "/static/" in n and "/index.html" in n
    assert "X-Forwarded-Proto" in n and "client_max_body_size 50m" in n


def test_rendu_unites_internes(tmp_path):
    f = rendu(tmp_path)
    b, lk = f["meet-backend.service"], f["livekit.service"]
    assert "User=meet" in b and "EnvironmentFile=/etc/meet/meet.env" in b and "meet.wsgi:application" in b
    assert "After=postgresql.service redis-server.service" in b
    assert "User=livekit" in lk and "--config /etc/livekit/livekit.yaml" in lk and "After=redis-server.service" in lk


def test_config_lxc_demarre_au_boot(tmp_path):
    c = rendu(tmp_path)["lxc-config"]
    assert "lxc.start.auto = 1" in c and "lxc.idmap = u 0 100000 65536" in c and "10.100.0.195/24" in c
    assert "lxc.cgroup2.memory.max = 2147483648" in c and "lxc.net.0.link = br-lxc" in c


def test_meetctl_install_delegue_au_script(tmp_path):
    env = _env_ctl(tmp_path)
    ok = tmp_path / "faux-install.sh"
    _ecrire_exec(ok, "#!/bin/bash\necho journal\nexit 0\n")
    env["SECUBOX_MEET_INSTALL_SCRIPT"] = str(ok)
    r = subprocess.run(["bash", str(RACINE / "sbin" / "meetctl"), "install"], capture_output=True, text=True, env=env)
    assert r.returncode == 0 and r.stdout.strip() == '{"success": true}'
    _ecrire_exec(ok, "#!/bin/bash\nexit 4\n")
    r = subprocess.run(["bash", str(RACINE / "sbin" / "meetctl"), "install"], capture_output=True, text=True, env=env)
    assert r.returncode == 1 and r.stdout.strip() == '{"success": false}'


def test_secret_oidc_enregistre_avant_le_rendu(tmp_path):
    """Avec un meetctl simulé qui pose le secret, le rendu le porte dans meet.env."""
    faux = tmp_path / "meetctl-faux"
    secrets = tmp_path / "secrets"
    _ecrire_exec(faux, f'#!/bin/bash\necho "$*" >> "{tmp_path}/appels-meetctl"\nprintf "%s\\n" "OIDC-S3CR3T" > "{secrets}/oidc-client-secret"\necho \'{{"success":true}}\'\n')
    env = _env_ctl(tmp_path)
    _ecrire_exec(tmp_path / "bin" / "lxc-create", "#!/bin/bash\nexit 0\n")
    env["SECUBOX_MEET_DRY_RUN"] = str(tmp_path / "rendu")
    env["SECUBOX_MEET_VERSION_FILE"] = str(RACINE / "conf" / "meet.version")
    env["SECUBOX_MEETCTL"] = str(faux)
    r = subprocess.run(["bash", str(INSTALL)], capture_output=True, text=True, env=env, timeout=60)
    assert r.returncode == 0, r.stderr
    assert (tmp_path / "appels-meetctl").read_text().strip() == "oidc-enregistrer"
    assert "OIDC_RP_CLIENT_SECRET=OIDC-S3CR3T" in (tmp_path / "rendu" / "meet.env").read_text()
    assert "OIDC-S3CR3T" not in r.stdout + r.stderr


def test_echec_de_l_enregistrement_arrete_le_provisionnement(tmp_path):
    faux = tmp_path / "meetctl-faux"
    _ecrire_exec(faux, "#!/bin/bash\nexit 1\n")
    env = _env_ctl(tmp_path)
    _ecrire_exec(tmp_path / "bin" / "lxc-create", "#!/bin/bash\nexit 0\n")
    env["SECUBOX_MEET_DRY_RUN"] = str(tmp_path / "rendu")
    env["SECUBOX_MEET_VERSION_FILE"] = str(RACINE / "conf" / "meet.version")
    env["SECUBOX_MEETCTL"] = str(faux)
    r = subprocess.run(["bash", str(INSTALL)], capture_output=True, text=True, env=env, timeout=60)
    assert r.returncode == 1 and "OIDC" in r.stderr and not (tmp_path / "rendu").exists()


def test_secret_oidc_vide_apres_enregistrement_est_un_echec(tmp_path):
    faux = tmp_path / "meetctl-faux"
    _ecrire_exec(faux, "#!/bin/bash\nexit 0\n")  # réussit sans rien écrire
    env = _env_ctl(tmp_path)
    (tmp_path / "secrets" / "oidc-client-secret").write_text("")
    _ecrire_exec(tmp_path / "bin" / "lxc-create", "#!/bin/bash\nexit 0\n")
    env["SECUBOX_MEET_DRY_RUN"] = str(tmp_path / "rendu")
    env["SECUBOX_MEET_VERSION_FILE"] = str(RACINE / "conf" / "meet.version")
    env["SECUBOX_MEETCTL"] = str(faux)
    r = subprocess.run(["bash", str(INSTALL)], capture_output=True, text=True, env=env, timeout=60)
    assert r.returncode == 1 and "secret absent ou vide" in r.stderr and not (tmp_path / "rendu").exists()


def test_install_passe_son_domaine_a_meetctl(tmp_path):
    faux = tmp_path / "meetctl-faux"
    secrets = tmp_path / "secrets"
    _ecrire_exec(faux, f'#!/bin/bash\necho "$SECUBOX_MEET_DOMAIN" > "{tmp_path}/domaine-vu"\necho S > "{secrets}/oidc-client-secret"\n')
    env = _env_ctl(tmp_path)
    _ecrire_exec(tmp_path / "bin" / "lxc-create", "#!/bin/bash\nexit 0\n")
    env.update(SECUBOX_MEET_DRY_RUN=str(tmp_path / "rendu"), SECUBOX_MEETCTL=str(faux),
               SECUBOX_MEET_VERSION_FILE=str(RACINE / "conf" / "meet.version"))
    r = subprocess.run(["bash", str(INSTALL)], capture_output=True, text=True, env=env, timeout=60)
    assert r.returncode == 0, r.stderr
    assert (tmp_path / "domaine-vu").read_text().strip() == "visio.exemple.test"


# ── I1 : le webhook de LiveKit passe par le nginx interne, avec l'hôte public et https ──────────────

def test_webhook_livekit_par_le_nginx_interne_avec_l_hote_de_django(tmp_path):
    f = rendu(tmp_path)
    assert 'urls: ["http://127.0.0.1:80/api/v1.0/rooms/webhooks-livekit/"]' in f["livekit.yaml"]
    n = f["nginx-meet.conf"]
    assert "listen 80 default_server;" in n and "server_name _;" in n     # accepte Host: 127.0.0.1
    bloc = n[n.index("location = /api/v1.0/rooms/webhooks-livekit/ {"):]
    bloc = bloc[:bloc.index("}")]
    hote = re.search(r"proxy_set_header Host (\S+);", bloc).group(1)
    e = dict(ligne.split("=", 1) for ligne in f["meet.env"].splitlines() if "=" in ligne)
    assert hote == "visio.exemple.test" and hote in e["DJANGO_ALLOWED_HOSTS"].split(",")
    assert "proxy_set_header X-Forwarded-Proto https;" in bloc and "proxy_pass http://127.0.0.1:8000;" in bloc
    assert "proxy_set_header X-Forwarded-For" in bloc            # les en-têtes du server ne sont plus hérités
    assert "allow 127.0.0.1;" in bloc and "deny all;" in bloc     # seul LiveKit, local, l'appelle


def test_rendu_refuse_un_domaine_qui_casserait_les_configurations(tmp_path):
    rc, err = run_install(tmp_path, domaine="visio.x; deny all")
    assert rc == 1 and "domaine" in err.lower() and not (tmp_path / "rendu").exists()


# ── I2 : le script interne ne relance que les services dont une entrée a changé ────────────────────

TEXTE_INSTALL = INSTALL.read_text()
INTERNE = script_interne(TEXTE_INSTALL)


def _relancer(tmp_path, modifier):
    """Exécute les fonctions réelles du script interne sur des fichiers de test ; renvoie le journal des appels."""
    for nom in ("meet.env", "livekit.yaml", "nginx-meet.conf", "meet-backend.service", "livekit.service", ".livekit"):
        (tmp_path / nom).write_text(nom + "\n")
    journal = tmp_path / "journal"
    bin_ = tmp_path / "bin-interne"
    bin_.mkdir()
    for nom in ("systemctl", "nginx"):
        _ecrire_exec(bin_ / nom, f'#!/bin/bash\necho "{nom} $*" >> "{journal}"\n')
    t = tmp_path
    fonctions = "".join(fonction_bash(INTERNE, n) for n in ("empreinte", "photo", "change", "relancer_si_change"))
    script = f"""set -euo pipefail
{fonctions}
UNITES="{t}/meet-backend.service {t}/livekit.service"
ENTREES_BACKEND="{t}/meet.env {t}/meet-backend.service {t}/.construit-abc"
ENTREES_LIVEKIT="{t}/livekit.yaml {t}/livekit.service {t}/.livekit"
ENTREES_NGINX="{t}/nginx-meet.conf"
AVANT=$(photo $ENTREES_BACKEND $ENTREES_LIVEKIT $ENTREES_NGINX)
cd "{t}"
{modifier}
relancer_si_change "$AVANT"
"""
    r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=30,
                       env={"PATH": f"{bin_}:/usr/bin:/bin"})
    assert r.returncode == 0, r.stderr
    return journal.read_text().splitlines() if journal.exists() else []


def test_rien_de_change_aucun_redemarrage(tmp_path):
    assert _relancer(tmp_path, "true") == []


def test_meet_env_change_relance_le_seul_backend(tmp_path):
    assert _relancer(tmp_path, "echo OIDC_RP_CLIENT_SECRET=nouveau >> meet.env") == ["systemctl try-restart meet-backend"]


def test_code_construit_relance_le_backend(tmp_path):
    assert _relancer(tmp_path, "touch .construit-abc") == ["systemctl try-restart meet-backend"]


def test_livekit_yaml_change_relance_le_seul_livekit(tmp_path):
    assert _relancer(tmp_path, "echo x >> livekit.yaml") == ["systemctl try-restart livekit"]


def test_unite_changee_recharge_systemd_puis_relance(tmp_path):
    assert _relancer(tmp_path, "echo x >> livekit.service") == ["systemctl daemon-reload", "systemctl try-restart livekit"]


def test_nginx_change_recharge_nginx_apres_verification(tmp_path):
    assert _relancer(tmp_path, "echo x >> nginx-meet.conf") == ["nginx -t", "systemctl try-reload-or-restart nginx"]


def test_script_interne_cable_les_entrees_et_la_photo():
    assert 'ENTREES_BACKEND="/etc/meet/meet.env /etc/systemd/system/meet-backend.service /opt/meet/.construit-$MEET_COMMIT"' in INTERNE
    assert 'ENTREES_LIVEKIT="/etc/livekit/livekit.yaml /etc/systemd/system/livekit.service /usr/local/bin/.livekit-$LIVEKIT_VERSION"' in INTERNE
    assert 'ENTREES_NGINX="/etc/nginx/sites-enabled/meet"' in INTERNE
    photo = INTERNE.index("AVANT=$(photo $ENTREES_BACKEND $ENTREES_LIVEKIT $ENTREES_NGINX)")
    relance = INTERNE.index('relancer_si_change "$AVANT"')
    assert photo < INTERNE.index("then construire; fi")
    assert INTERNE.index('touch "/opt/meet/.construit-$MEET_COMMIT"') < relance
    assert relance < INTERNE.index("systemctl enable --now postgresql redis-server livekit meet-backend nginx")
    assert "REDEMARRER" not in TEXTE_INSTALL and "systemctl restart livekit meet-backend" not in INTERNE


def test_rendu_seul_saute_la_construction():
    construire = fonction_bash(INTERNE, "construire")
    for etape in ("apt-get install", "git clone", "npm ci", "uv sync", "livekit-server"):
        assert etape in construire, etape
    base = fonction_bash(INTERNE, "preparer_base")
    assert "manage migrate" in base and "createdb" in base
    assert 'if [ "$RENDRE_SEULEMENT" != 1 ]; then construire; fi' in INTERNE
    assert 'if [ "$RENDRE_SEULEMENT" != 1 ]; then preparer_base; fi' in INTERNE


def _env_rendu_seul(tmp_path, etat_lxc="RUNNING"):
    env = _env_ctl(tmp_path, lxc_state=etat_lxc)
    bin_ = tmp_path / "bin"
    for nom in ("lxc-create", "lxc-start", "ip"):
        _ecrire_exec(bin_ / nom, f'#!/bin/bash\necho "{nom} $*" >> "{tmp_path}/interdits"\n')
    _ecrire_exec(bin_ / "chown", "#!/bin/bash\nexit 0\n")
    # Faux lxc-attach : journalise l'environnement passé au script interne (jamais le script lui-même).
    _ecrire_exec(bin_ / "lxc-attach", f"""#!/bin/bash
for a in "$@"; do [ "$a" = bash ] && break; echo "$a"; done >> "{tmp_path}/attach"
""")
    faux = tmp_path / "meetctl-faux"
    _ecrire_exec(faux, f'#!/bin/bash\necho "APPLIQUER=$SECUBOX_MEET_APPLIQUER" >> "{tmp_path}/appels-meetctl"\n'
                       f'echo OIDC-S3CR3T > "{tmp_path}/secrets/oidc-client-secret"\n')
    env.update(SECUBOX_MEET_RENDRE_SEULEMENT="1", SECUBOX_MEETCTL=str(faux),
               SECUBOX_MEET_VERSION_FILE=str(RACINE / "conf" / "meet.version"))
    return env


def test_rendu_seul_applique_sans_construire_ni_recreer(tmp_path):
    env = _env_rendu_seul(tmp_path)
    r = subprocess.run(["bash", str(INSTALL)], capture_output=True, text=True, env=env, timeout=60)
    assert r.returncode == 0, r.stderr
    attach = (tmp_path / "attach").read_text().splitlines()
    assert "RENDRE_SEULEMENT=1" in attach and not (tmp_path / "interdits").exists()
    assert not (tmp_path / "nft-appels").exists() and not (tmp_path / "etat" / ".lxc-provisioned").exists()
    assert not (tmp_path / "lxc" / "meet" / "rootfs" / "root" / "meet-rendu").exists()
    assert (tmp_path / "appels-meetctl").read_text().strip() == "APPLIQUER=0"
    attendu = hashlib.sha256(b"OIDC-S3CR3T").hexdigest()
    note = tmp_path / "secrets" / ".oidc-applique"
    assert note.read_text().strip() == attendu and note.stat().st_mode & 0o777 == 0o600
    assert "OIDC-S3CR3T" not in r.stdout + r.stderr


def test_rendu_seul_refuse_un_conteneur_arrete(tmp_path):
    env = _env_rendu_seul(tmp_path, etat_lxc="STOPPED")
    r = subprocess.run(["bash", str(INSTALL)], capture_output=True, text=True, env=env, timeout=60)
    assert r.returncode == 1 and "arrêt" in r.stderr and not (tmp_path / "attach").exists()
    assert not (tmp_path / "secrets" / ".oidc-applique").exists()


def test_provisionnement_complet_passe_appliquer_0_a_meetctl():
    assert 'SECUBOX_MEET_APPLIQUER=0 SECUBOX_MEET_DOMAIN="$MEET_DOMAIN"' in TEXTE_INSTALL


# ── BR : br-lxc présent sans 10.100.0.1/24 → échec clair, sans attendre le réseau ──────────────────

def _pont(tmp_path, lien_existe, adresses):
    bin_ = tmp_path / "bin-ip"
    bin_.mkdir()
    _ecrire_exec(bin_ / "ip", f"""#!/bin/bash
echo "ip $*" >> "{tmp_path}/ip-appels"
case "$*" in
  "link show br-lxc") exit {0 if lien_existe else 1} ;;
  *"addr show"*) printf '%s\\n' "{adresses}" ;;
esac
exit 0
""")
    script = ("set -euo pipefail\nLXC_BRIDGE=br-lxc\nLXC_GW=10.100.0.1\n"
              "log() { echo \"LOG $*\"; }\nfail() { echo \"ERREUR : $*\" >&2; exit 1; }\n"
              + fonction_bash(TEXTE_INSTALL, "ensure_bridge") + "ensure_bridge\n")
    r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=10,
                       env={"PATH": f"{bin_}:/usr/bin:/bin"})
    appels = (tmp_path / "ip-appels").read_text().splitlines() if (tmp_path / "ip-appels").exists() else []
    return r, appels


def test_pont_sans_passerelle_echoue_clairement(tmp_path):
    r, appels = _pont(tmp_path, True, "br-lxc           UP             192.168.1.5/24")
    assert r.returncode == 1
    assert "br-lxc n'a pas l'adresse 10.100.0.1/24" in r.stderr and "netplan" in r.stderr and "#3162" in r.stderr
    assert not any(" add " in f" {a} " for a in appels)


def test_pont_adresse_voisine_refusee(tmp_path):
    r, _ = _pont(tmp_path, True, "br-lxc           UP             10.100.0.10/24")
    assert r.returncode == 1


def test_pont_avec_passerelle_accepte(tmp_path):
    r, appels = _pont(tmp_path, True, "br-lxc           UP             10.100.0.1/24")
    assert r.returncode == 0, r.stderr
    assert not any(" add " in f" {a} " for a in appels)


def test_pont_absent_cree_comme_avant(tmp_path):
    r, appels = _pont(tmp_path, False, "")
    assert r.returncode == 0, r.stderr
    assert "ip link add name br-lxc type bridge" in appels and "ip addr add 10.100.0.1/24 dev br-lxc" in appels


# ── m9 : uv ne télécharge jamais d'interpréteur ───────────────────────────────────────────────────

def test_uv_sans_telechargement_d_interpreteur():
    assert "export UV_PYTHON_DOWNLOADS=never" in INTERNE


def test_dossier_partage_des_conteneurs_jamais_reimpose():
    """C1 : /data/lxc héberge tous les conteneurs de la box : créé s'il manque, jamais réattribué."""
    d = fonction_bash(TEXTE_INSTALL, "ensure_dirs")
    assert '[ -d "$LXC_PATH" ] || install -d' in d
    assert not re.search(r'^\s*install -d [^\n]*"\$LXC_PATH"$', d, re.M)


def test_reseau_fixe_du_conteneur(tmp_path):
    # gk1, 2026-10-25 : l'image Debian trixie configure eth0 en DHCP (systemd-networkd) ; br-lxc n'a pas de serveur DHCP,
    # networkd retirait l'adresse posée par LXC et le provisionnement échouait (apt-get 100, puis « n'a pas joint 10.100.0.1 »).
    n = rendu(tmp_path)["conteneur-eth0.network"]
    assert "Name=eth0" in n and "Address=10.100.0.195/24" in n and "Gateway=10.100.0.1" in n
    assert "DHCP" not in n and "LinkLocalAddressing=no" in n


def test_installation_pose_le_reseau_avant_le_demarrage():
    s = (Path(__file__).resolve().parents[1] / "lib" / "meet" / "install-lxc.sh").read_text()
    m = s[s.index("\nmain() {"):]
    assert m.index("ecrire_reseau_conteneur") < m.index("start_lxc") < m.index("wait_for_network")
    f = s[s.index("ecrire_reseau_conteneur() {"):]
    f = f[:f.index("\n}\n")]
    assert "rootfs/etc/systemd/network" in f and "/eth0.network" in f and "100000:100000" in f
    assert "networkctl reload" in f and "networkctl reconfigure eth0" in f   # conteneur déjà démarré (reprise)


def test_redis_sans_espace_de_noms_utilisateur_dans_le_conteneur():
    # gk1, 2026-10-25 : l'unité Debian de redis-server porte PrivateUsers=true, refusé dans un LXC non privilégié
    # (« Failed to set up user namespacing », 217/USER) ; LiveKit et le cache de Meet en dépendent.
    s = (Path(__file__).resolve().parents[1] / "lib" / "meet" / "install-lxc.sh").read_text()
    c = s[s.index("\nconstruire() {"):]
    c = c[:c.index("\n}\n")]
    assert "redis-server.service.d/10-secubox-lxc.conf" in c and "PrivateUsers=no" in c
    assert c.index("apt-get install") < c.index("PrivateUsers=no") < len(c)
    assert "systemctl daemon-reload" in c[c.index("PrivateUsers=no"):]
