# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3583 Tâche 15 — empaquetage : chaque fichier installé par debian/rules existe, profils AppArmor nommés par les
unités (API enforce sans /etc/secubox/**, moteur en complain), route nginx sur le patron SearXNG, postinst (comptes,
dossiers par descripteur, profils chargés avant tout démarrage, preparer avant la relance de l'API), prerm, rotation
du journal, README et wiki."""
import grp
import os
import pwd
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

PAQUET = Path(__file__).resolve().parents[1]
RACINE = PAQUET.parents[1]
RULES = (PAQUET / "debian" / "rules").read_text(encoding="utf-8")
POSTINST = (PAQUET / "debian" / "postinst").read_text(encoding="utf-8")
PRERM = (PAQUET / "debian" / "prerm").read_text(encoding="utf-8")
POSTRM = (PAQUET / "debian" / "postrm").read_text(encoding="utf-8")
PROFIL_API = (PAQUET / "apparmor" / "secubox-ai-api").read_text(encoding="utf-8")
PROFIL_MOTEUR = (PAQUET / "apparmor" / "secubox-ai-moteur").read_text(encoding="utf-8")
NGINX = (PAQUET / "nginx" / "ai.conf").read_text(encoding="utf-8")
LOGROTATE = (PAQUET / "logrotate" / "secubox-ai").read_text(encoding="utf-8")
UNITES = sorted(p.name for p in (PAQUET / "systemd").iterdir())
DEST = "debian/secubox-ai/"


def _code(texte):
    """Sans les commentaires, lignes continuées (« \\ ») rejointes."""
    texte = re.sub(r"\\\n\s*", "", texte)
    return "\n".join(x for x in texte.splitlines() if not x.lstrip().startswith("#"))


def _unite(nom):
    u = {}
    for x in (PAQUET / "systemd" / nom).read_text(encoding="utf-8").splitlines():
        if "=" in x and not x.startswith("#"):
            k, v = x.split("=", 1)
            u.setdefault(k, []).append(v)
    return u


def _installs():
    """(source, cible) de chaque `install -D -m … SRC DEST` et `cp -r SRC DEST` de debian/rules."""
    paires = []
    for x in RULES.splitlines():
        m = re.match(r"\s*install -D -m 0?\d{3,4} (\S+) (\S+)$", x)
        if m:
            paires.append(m.groups())
            continue
        m = re.match(r"\s*cp -r (\S+) (\S+)$", x)
        if m:
            paires.append(m.groups())
    return paires


# ── debian/rules ──

def test_chaque_source_installee_existe():
    paires = _installs()
    assert paires
    for src, cible in paires:
        assert (PAQUET / src.rstrip(".").rstrip("/")).exists(), src
        assert cible.startswith(DEST), cible


@pytest.mark.parametrize("cible", [
    "usr/lib/secubox/ai/", "usr/sbin/secubox-aictl", "usr/share/secubox/www/ai/index.html",
    "usr/share/secubox/menu.d/", "usr/share/secubox/ai/ai.toml.example", "etc/nginx/secubox-routes.d/ai.conf",
    "etc/nginx/secubox.d/ai.conf", "etc/apparmor.d/secubox-ai-api", "etc/apparmor.d/secubox-ai-moteur",
    "etc/logrotate.d/secubox-ai"])
def test_rules_installe(cible):
    assert any(c == DEST + cible for _, c in _installs()), cible


def test_rules_installe_toutes_les_unites():
    installees = {c.rsplit("/", 1)[1] for _, c in _installs() if "/usr/lib/systemd/system/" in c}
    assert installees == set(UNITES) and len(UNITES) == 5


def test_rules_code_sans_cache_et_controleur_executable():
    assert "find debian/secubox-ai/usr/lib/secubox/ai -name __pycache__ -type d -prune -exec rm -rf {} +" in RULES
    assert "install -D -m 0755 sbin/secubox-aictl debian/secubox-ai/usr/sbin/secubox-aictl" in RULES
    # Activation par le postinst seul (après les comptes et les profils) : aucun extrait systemd de debhelper.
    assert re.search(r"^override_dh_installsystemd:\n(?!\t)", RULES + "\n", re.M)


# ── AppArmor ──

def test_profils_nommes_par_les_unites():
    assert _unite("secubox-ai.service")["AppArmorProfile"] == ["secubox-ai-api"]
    assert _unite("secubox-ai-moteur.service")["AppArmorProfile"] == ["secubox-ai-moteur"]
    assert re.search(r"^profile secubox-ai-api \{", PROFIL_API, re.M)
    assert re.search(r"^profile secubox-ai-moteur flags=\(complain\) \{", PROFIL_MOTEUR, re.M)
    assert "complain" not in _code(PROFIL_API)                       # l'API part en enforce


def test_profil_api_jamais_tout_etc_secubox():
    code = _code(PROFIL_API)
    assert not re.search(r"^\s*(owner\s+)?/etc/secubox/\*", code, re.M)
    assert not re.search(r"^\s*(owner\s+)?/etc/secubox/\{", code, re.M)
    lus = re.findall(r"^\s*(/etc/secubox/\S*) (\w+),", code, re.M)
    assert sorted(lus) == sorted([("/etc/secubox/", "r"), ("/etc/secubox/secubox.conf", "r"),
                                  ("/etc/secubox/auth.toml", "r"), ("/etc/secubox/users.json", "r"),
                                  ("/etc/secubox/appareils.json", "r"), ("/etc/secubox/ai.toml", "r"),
                                  ("/etc/secubox/secrets/ai/distant.key", "r")])
    assert "secubox-pilotage" not in code and " Ux," not in code and " ux," not in code and "sudo" not in code


def test_profil_api_chemins_du_module():
    code = _code(PROFIL_API)
    for regle in ("/usr/lib/secubox/ai/** r,", "/var/lib/secubox/ai/** rwk,", "/run/secubox/ai.sock rwk,",
                  "/run/secubox-ai/moteur.sock rw,", "/run/secubox-ai/moteur-etat.json r,",
                  "owner /run/secubox-ai/demandes/* rw,", "@{PROC}/@{pid}/net/if_inet6 r,",
                  "/usr/bin/pdftotext rix,", "/usr/bin/pdfinfo rix,", "deny /var/log/secubox/audit.log w,",
                  "network inet stream,", "network inet6 stream,"):
        assert regle in code, regle
    # Rien d'autre sous /run/secubox-ai : ni moteur.env, ni le verrou du contrôleur.
    run = sorted(re.findall(r"^\s*(?:owner\s+)?(/run/secubox-ai/\S*) \w+,", code, re.M))
    assert run == ["/run/secubox-ai/", "/run/secubox-ai/demandes/", "/run/secubox-ai/demandes/*",
                   "/run/secubox-ai/moteur-etat.json", "/run/secubox-ai/moteur.sock"]
    ecrits = re.findall(r"^\s*(/var/log/secubox/\S+) w,", code, re.M)
    assert sorted(ecrits) == ["/var/log/secubox/delegation.log", "/var/log/secubox/garde-origine.log"]


def test_profil_moteur_borne():
    code = _code(PROFIL_MOTEUR)
    for regle in ("/usr/lib/secubox/zia-llm/llama-server mr,", "/var/lib/secubox/ai/modeles/ r,",
                  "/var/lib/secubox/ai/modeles/*.gguf mr,", "/run/secubox-ai/moteur.sock rw,",
                  "deny /etc/secubox/** rwklx,", "deny network inet,", "deny network inet6,", "deny capability,"):
        assert regle in code, regle
    assert not re.search(r"^\s*/var/lib/secubox/ai/\*\*", code, re.M) and "demandes" not in code
    assert "Tâche 18" in PROFIL_MOTEUR and "enforce" in PROFIL_MOTEUR      # bascule documentée


@pytest.mark.parametrize("profil", ["secubox-ai-api", "secubox-ai-moteur"])
def test_profils_compilent(profil):
    if not shutil.which("apparmor_parser") or not Path("/etc/apparmor.d/tunables/global").exists():
        pytest.skip("apparmor_parser absent")
    r = subprocess.run(["apparmor_parser", "-QT", str(PAQUET / "apparmor" / profil)], timeout=60,
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


# ── nginx ──

def test_nginx_patron_searxng():
    code = _code(NGINX)
    assert "location /api/v1/ai/ {" in code
    assert code.count("rewrite ^/api/v1/ai/(.*)$ /$1 break;") == code.count("proxy_pass ") >= 1
    assert set(re.findall(r"proxy_pass (\S+);", code)) == {"http://unix:/run/secubox/ai.sock"}
    assert "include /etc/nginx/snippets/secubox-proxy.conf;" in code
    # La page /ai/ est servie par la racine statique du vhost (patron SearXNG) : ni alias, ni try_files, ni location.
    for interdit in ("alias", "try_files", "location /ai", "error_page", "server_name", "listen"):
        assert interdit not in code, interdit
    assert any(c == DEST + "usr/share/secubox/www/ai/index.html" for _, c in _installs())


def test_nginx_flux_sans_tampon_et_long():
    bloc = re.search(r"location = /api/v1/ai/essai/flux \{(.*?)\}", _code(NGINX), re.S).group(1)
    assert "proxy_buffering off;" in bloc
    assert int(re.search(r"proxy_read_timeout (\d+)s;", bloc).group(1)) >= 7200


def test_nginx_100_mo_seulement_pour_les_depots():
    code = _code(NGINX)
    grands = {m.group(1) for m in re.finditer(r"location = (\S+) \{[^}]*client_max_body_size 100m;", code, re.S)}
    assert grands == {"/api/v1/ai/documents/fichier", "/api/v1/ai/medias/entree"}
    assert code.count("client_max_body_size 100m;") == 2


def test_nginx_syntaxe(tmp_path):
    if not shutil.which("nginx"):
        pytest.skip("nginx absent")
    snippet = tmp_path / "secubox-proxy.conf"
    snippet.write_text((RACINE / "common" / "nginx" / "secubox-proxy.conf").read_text(encoding="utf-8"))
    (tmp_path / "ai.conf").write_text(NGINX.replace("/etc/nginx/snippets/secubox-proxy.conf", str(snippet)))
    temp = " ".join(f"{d}_temp_path {tmp_path}/{d};" for d in ("client_body", "proxy", "fastcgi", "uwsgi", "scgi"))
    (tmp_path / "nginx.conf").write_text(
        f"pid {tmp_path}/nginx.pid;\nerror_log stderr;\nevents {{}}\nhttp {{ access_log off; {temp}\n"
        f"  server {{ listen 127.0.0.1:65080; include {tmp_path}/ai.conf; }}\n}}\n")
    r = subprocess.run(["nginx", "-t", "-q", "-e", "stderr", "-p", str(tmp_path), "-c", str(tmp_path / "nginx.conf")],
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr


# ── postinst / prerm / postrm ──

def test_scripts_syntaxe():
    for s in ("postinst", "prerm", "postrm"):
        subprocess.run(["sh", "-n", str(PAQUET / "debian" / s)], check=True, timeout=10)


def test_postinst_comptes():
    code = _code(POSTINST)
    assert "addgroup --system secubox-ai" in code and "addgroup --system secubox-ai-moteur" in code
    assert ("adduser --system --ingroup secubox-ai --no-create-home --home /nonexistent "
            "--shell /usr/sbin/nologin secubox-ai") in code
    assert ("adduser --system --ingroup secubox-ai-moteur --no-create-home --home /nonexistent "
            "--shell /usr/sbin/nologin secubox-ai-moteur") in code
    assert "adduser secubox-ai secubox" in code and "adduser secubox-ai-moteur secubox-ai" in code


def test_postinst_dossiers_par_descripteur_sans_tmpfiles():
    code = _code(POSTINST)
    assert "python3 -I - /var/lib/secubox secubox-ai secubox-ai <<'DOSSIERS'" in code
    assert "tmpfiles" not in code
    assert not re.search(r"\bch(own|mod|grp)\b", code.replace("os.fchown", "").replace("os.fchmod", ""))  # par chemin
    # L'état d'exécution n'est jamais remis à zéro.
    for f in ("preferences.toml", "memoire.db", "journal.jsonl"):
        assert f not in code, f


def _dossiers():
    return re.search(r"<<'DOSSIERS'(?:[^\n]*\\\n)*[^\n]*\n(.*?)\nDOSSIERS\n", POSTINST, re.S).group(1)


def _lancer(racine):
    compte = pwd.getpwuid(os.getuid()).pw_name
    groupe = grp.getgrgid(os.getgid()).gr_name
    return subprocess.run([sys.executable, "-I", "-", str(racine), compte, groupe], input=_dossiers(),
                          capture_output=True, text=True, timeout=30)


def test_dossiers_crees_0750_et_etat_garde(tmp_path):
    r = _lancer(tmp_path)
    assert r.returncode == 0, r.stderr
    assert (tmp_path / "ai").stat().st_mode & 0o7777 == 0o750
    assert (tmp_path / "ai" / "modeles").stat().st_mode & 0o7777 == 0o750
    (tmp_path / "ai" / "memoire.db").write_text("garde")
    (tmp_path / "ai" / "modeles" / "m.gguf").write_text("garde")
    os.chmod(tmp_path / "ai", 0o755)
    r = _lancer(tmp_path)                                # mise à jour : dossier resserré, contenu intact
    assert r.returncode == 0, r.stderr
    assert (tmp_path / "ai").stat().st_mode & 0o7777 == 0o750
    assert (tmp_path / "ai" / "memoire.db").read_text() == "garde"
    assert (tmp_path / "ai" / "modeles" / "m.gguf").read_text() == "garde"


@pytest.mark.parametrize("piege", ["ai", "modeles"])
def test_dossiers_lien_jamais_suivi(tmp_path, piege):
    cible = tmp_path / "cible"
    cible.mkdir(mode=0o755)
    racine = tmp_path / "racine"
    racine.mkdir()
    if piege == "ai":
        (racine / "ai").symlink_to(cible)
    else:
        (racine / "ai").mkdir()
        (racine / "ai" / "modeles").symlink_to(cible)
    r = _lancer(racine)
    assert r.returncode != 0
    assert cible.stat().st_mode & 0o7777 == 0o755


def test_postinst_ordre():
    code = _code(POSTINST)
    i = {k: code.index(k) for k in (
        "adduser --system --ingroup secubox-ai-moteur", "<<'DOSSIERS'", "apparmor_parser -r",
        "/usr/sbin/secubox-aictl preparer", "systemctl restart secubox-ai-demandes.path",
        "systemctl restart secubox-ai.service")}
    assert (i["adduser --system --ingroup secubox-ai-moteur"] < i["<<'DOSSIERS'"] < i["apparmor_parser -r"]
            < i["/usr/sbin/secubox-aictl preparer"] < i["systemctl restart secubox-ai-demandes.path"]
            < i["systemctl restart secubox-ai.service"])
    # Les deux profils, chargés avant le premier démarrage (une unité qui nomme un profil absent ne part pas).
    assert 'for _p in secubox-ai-api secubox-ai-moteur; do' in code
    assert 'apparmor_parser -r "/etc/apparmor.d/$_p"' in code
    assert "for _u in secubox-ai-preparer.service secubox-ai-demandes.path secubox-ai.service; do" in code
    assert 'deb-systemd-helper --quiet was-enabled "$_u"' in code
    assert "secubox-ai-moteur.service" not in code.split("for _u in", 1)[1].split("done", 1)[0]


def test_postinst_configuration_au_premier_passage():
    code = _code(POSTINST)
    assert "if [ ! -e /etc/secubox/ai.toml ]" in code
    assert "install -m 0644 -o root -g root /usr/share/secubox/ai/ai.toml.example /etc/secubox/ai.toml" in code


def test_prerm_et_postrm():
    code = _code(PRERM)
    assert "remove|deconfigure)" in code
    assert ("systemctl stop secubox-ai-demandes.path secubox-ai-demandes.service secubox-ai.service "
            "secubox-ai-moteur.service") in code
    post = _code(POSTRM)
    assert post.count("for _u in secubox-ai-preparer.service secubox-ai-demandes.path secubox-ai.service; do") == 2
    assert 'deb-systemd-helper purge "$_u"' in post and 'deb-systemd-helper mask "$_u"' in post
    assert "rm -f /etc/secubox/ai.toml" in post and "/var/lib/secubox/ai" not in post   # données gardées


# ── journal ──

def test_rotation_du_journal():
    code = _code(LOGROTATE)
    assert code.lstrip().startswith("/var/lib/secubox/ai/journal.jsonl {")
    assert "su secubox-ai secubox-ai" in code and "nocreate" in code and "copytruncate" not in code
    assert re.search(r"^\s*maxsize \d+M$", code, re.M) and re.search(r"^\s*rotate \d+$", code, re.M)


# ── documentation ──

def _routes():
    routes = set()
    for f in (PAQUET / "api").glob("*.py"):
        routes |= set(re.findall(r'@(?:routeur|ROUTEUR)\.(get|post|put|delete)\("([^"]+)"', f.read_text()))
    return routes


def test_readme_toutes_les_routes():
    readme = (PAQUET / "README.md").read_text(encoding="utf-8")
    routes = _routes()
    assert len(routes) > 50
    for methode, chemin in routes:
        assert f"`{methode.upper()} {chemin}`" in readme, (methode, chemin)
    for mot in ("/run/secubox/ai.sock", "/etc/secubox/ai.toml", "/var/lib/secubox/ai/preferences.toml",
                "/etc/secubox/secrets/ai/distant.key", "secubox-zia-llm", "en clair", "inertes"):
        assert mot in readme, mot


def test_wiki():
    for langue, mot in (("FR", "Fonctionnalités"), ("EN", "Features")):
        wiki = (RACINE / "wiki" / f"MODULES-{langue}.md").read_text(encoding="utf-8")
        bloc = wiki.split("#### 🧠 SecuBox IA", 1)
        assert len(bloc) == 2, langue
        assert mot in bloc[1].split("####", 1)[0], langue
        assert "| 🧠 **SecuBox IA** |" in wiki, langue
