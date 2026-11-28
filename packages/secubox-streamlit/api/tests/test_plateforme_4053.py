# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#4053 — plateforme Streamlit « complètement bancale » sur gk2, constats et correctifs.

1. Inventaire (streamlit-audit) tué en `timeout` : une copie ancienne de l'unité sous /etc (60 s) masquait celle du
   paquet, et rien ne bornait les lxc-attach. → chaque lecture du conteneur est bornée, résultat partiel déclaré,
   jamais d'attente sans fin ; l'unité borne le tout et n'écrase jamais l'inventaire complet.
2. Veille : `autostart = true` exemptait de la veille ; seule `veille = false` exempte désormais, délai par appli.
3. Onglets Applis/Accès en 504 : `streamlitctl app list` dans la requête (boucle figée). → inventaire en cache.
4. Paramétrage par appli : fiche (GET /app/{nom}), port, veille, démarrage au boot — gardés.
"""
import json
import os
import stat
import subprocess
import time
from pathlib import Path

import pytest

from api import main as api_main
from api import publication as P
from secubox_core.auth import require_jwt, require_lecture

PKG = Path(__file__).resolve().parents[2]
CTL = PKG / "sbin" / "streamlitctl"


def _exe(chemin: Path, texte: str) -> None:
    chemin.write_text(texte)
    chemin.chmod(chemin.stat().st_mode | stat.S_IEXEC)


def _banc(tmp_path, lxc_attach: str, conf: str = ""):
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    _exe(bin_ / "lxc-info", "#!/bin/sh\necho 'State: RUNNING'\n")
    _exe(bin_ / "lxc-attach", lxc_attach)
    apps = tmp_path / "apps"
    apps.mkdir()
    (apps / "files_51.py").write_text("import streamlit\n")
    d = apps / "diapvid"
    d.mkdir()
    (d / "app.py").write_text("import streamlit\n")
    c = tmp_path / "streamlit.toml"
    c.write_text(conf)
    env = {
        "PATH": f"{bin_}:/usr/bin:/bin:/usr/sbin:/sbin",
        "SECUBOX_STREAMLIT_APPS_PATH": str(apps),
        "SECUBOX_STREAMLIT_CONF": str(c),
        "SECUBOX_STREAMLIT_IDLE_DIR": str(tmp_path / "idle"),
        "SECUBOX_STREAMLIT_SHOTS_DIR": str(tmp_path / "shots"),
        "SECUBOX_STREAMLIT_LXC_PATH": str(tmp_path / "lxc"),
    }
    return env, apps, c


LXC_BLOQUE = "#!/bin/sh\nsleep 60\n"
LXC_PS = """#!/bin/sh
case "$*" in
  *"state established"*) echo "@@SBX-PS@@"; echo "python3 -m streamlit run files_51.py --server.port=8530"; echo "@@SBX-SS@@"; echo "Recv-Q Send-Q Local Address:Port Peer Address:Port" ;;
  *"ps -eo args"*) echo "python3 -m streamlit run files_51.py --server.port=8530" ;;
esac
exit 0
"""


# ─── 1. Inventaire : sous-processus bloqué → délai et résultat partiel ─────

def test_audit_avec_lxc_attach_bloque_rend_un_inventaire_partiel_dans_le_delai(tmp_path):
    env, _apps, _c = _banc(tmp_path, LXC_BLOQUE)
    env["SECUBOX_STREAMLIT_LXC_TIMEOUT"] = "1"
    t0 = time.monotonic()
    r = subprocess.run(["bash", str(CTL), "app", "audit"], capture_output=True, text=True, env=env, timeout=40)
    duree = time.monotonic() - t0
    assert r.returncode == 0, r.stderr
    assert duree < 20, f"l'inventaire a attendu le conteneur {duree:.0f} s"
    d = json.loads(r.stdout)
    assert d["summary"]["partiel"] is True
    assert {a["name"] for a in d["apps"]} == {"files_51", "diapvid"}      # le disque reste inventorié
    assert "délai" in r.stderr


def test_audit_complet_et_reglages_par_appli(tmp_path):
    conf = ('[idle]\ntimeout_minutes = 30\n\n[apps.files_51]\nport = "8530"\nautostart = true\nveille_minutes = 10\n\n'
            '[apps.diapvid]\nveille = false\n')
    env, _apps, _c = _banc(tmp_path, LXC_PS, conf)
    r = subprocess.run(["bash", str(CTL), "app", "audit"], capture_output=True, text=True, env=env, timeout=60)
    assert r.returncode == 0, r.stderr
    d = json.loads(r.stdout)
    assert d["summary"]["partiel"] is False and isinstance(d["summary"]["genere_a"], int)
    par = {a["name"]: a for a in d["apps"]}
    assert par["files_51"]["running"] is True and par["files_51"]["port"] == 8530
    assert par["files_51"]["autostart"] is True and par["files_51"]["veille"] is True
    assert par["files_51"]["sleep_after_seconds"] == 600 and par["files_51"]["veille_minutes"] == 10
    assert par["diapvid"]["veille"] is False and par["diapvid"]["sleep_after_seconds"] == 0


def test_unite_d_inventaire_bornee_et_double_tampon():
    u = (PKG / "debian" / "streamlit-audit.service").read_text()
    assert "timeout -k 10 240 /usr/sbin/streamlitctl app audit" in u
    assert "[ -s /var/cache/secubox/streamlit/.audit.tmp ]" in u          # un résultat vide n'écrase rien
    assert "rm -f /var/cache/secubox/streamlit/.audit.tmp" in u           # le temporaire ne traîne plus
    assert "python3 -I -m json.tool /var/cache/secubox/streamlit/.audit.tmp" in u   # JSON tronqué : rien n'est remplacé
    assert "TimeoutStartSec=300" in u
    assert "OnUnitActiveSec=30min" in (PKG / "debian" / "streamlit-audit.timer").read_text()


def test_postinst_retire_les_copies_anciennes_sous_etc():
    p = (PKG / "debian" / "postinst").read_text()
    assert "/etc/systemd/system/$_u" in p and "dpkg -S" in p
    assert "streamlit-avant-4053" in p                                    # sauvegarde avant retrait
    assert p.index("streamlit-avant-4053") < p.index("systemctl enable --now streamlit-audit.timer")


# ─── 2. Veille : une appli inactive est arrêtée ────────────────────────────

def _idle(tmp_path, conf, lxc=LXC_PS, minutes_inactive=20, timeout_ctl=None):
    env, _apps, _c = _banc(tmp_path, lxc, conf)
    if timeout_ctl:
        env["SECUBOX_STREAMLIT_LXC_TIMEOUT"] = timeout_ctl
    idle = tmp_path / "idle"
    idle.mkdir()
    f = idle / "files_51.state"
    f.write_text("")
    ts = time.time() - minutes_inactive * 60
    os.utime(f, (ts, ts))
    return subprocess.run(["bash", str(CTL), "app", "idle-check"], capture_output=True, text=True, env=env, timeout=60)


def test_veille_arrete_une_appli_autostart_inactive_au_dela_de_son_delai(tmp_path):
    r = _idle(tmp_path, '[idle]\ntimeout_minutes = 30\n\n[apps.files_51]\nport = "8530"\nautostart = true\n'
                        'veille_minutes = 10\n')
    assert r.returncode == 0, r.stderr
    assert "idle-stop: files_51 (idle" in r.stdout and ">= 600s" in r.stdout


def test_veille_respecte_le_delai_commun_sans_reglage_propre(tmp_path):
    r = _idle(tmp_path, '[idle]\ntimeout_minutes = 30\n\n[apps.files_51]\nport = "8530"\n')
    assert "idle-stop: files_51" not in r.stdout and "idle=1" in r.stdout


def test_veille_desactivee_par_appli(tmp_path):
    r = _idle(tmp_path, '[idle]\ntimeout_minutes = 1\n\n[apps.files_51]\nveille = false\n')
    assert "idle-stop: files_51" not in r.stdout and "veille désactivée" in r.stdout


def test_veille_avec_conteneur_bloque_n_arrete_rien_et_se_termine(tmp_path):
    t0 = time.monotonic()
    r = _idle(tmp_path, '[idle]\ntimeout_minutes = 1\n', lxc=LXC_BLOQUE, timeout_ctl="1")
    assert time.monotonic() - t0 < 20
    assert r.returncode == 0 and "idle-stop" not in r.stdout


def test_verbe_veille_ecrit_le_toml_et_audite(tmp_path, monkeypatch):
    apps = tmp_path / "apps"
    apps.mkdir()
    (apps / "files_51.py").write_text("import streamlit\n")
    conf = tmp_path / "streamlit.toml"
    conf.write_text('[apps.files_51]\nport = "8530"\nautostart = true\n')
    audit = tmp_path / "audit.log"
    monkeypatch.setenv("SECUBOX_STREAMLIT_AUDIT", str(audit))
    monkeypatch.setenv("SECUBOX_STREAMLIT_VERROU", str(tmp_path / "verrou" / "v.lock"))
    base = ["--conf", str(conf), "--apps", str(apps), "veille", "files_51"]
    assert P.main(base + ["--actif", "oui", "--minutes", "15", "--par", "admin", "--apply"]) == 0
    v = P.applis_declarees(conf.read_text())["files_51"]
    assert v["veille"] is True and v["veille_minutes"] == 15 and v["autostart"] is True
    assert P.main(base + ["--actif", "non", "--minutes", "0", "--apply"]) == 0
    v = P.applis_declarees(conf.read_text())["files_51"]
    assert v["veille"] is False and "veille_minutes" not in v
    lignes = [json.loads(x) for x in audit.read_text().splitlines()]
    assert lignes[0]["action"] == "veille" and lignes[0]["par"] == "admin"
    assert P.main(["--conf", str(conf), "--apps", str(apps), "veille", "absente", "--actif", "oui"]) == P.INCONNUE
    assert P.main(base + ["--actif", "oui", "--minutes", "999999"]) == P.ARGUMENT


@pytest.mark.parametrize("args", [["app", "veille", "x", "peut-etre"], ["app", "veille", "x", "on", "abc"],
                                  ["app", "veille", "../x", "on"], ["app", "veille", "x", "on", "--par", "-r"]])
def test_ctl_refuse_les_arguments_de_veille_invalides(args, tmp_path):
    env, _a, _c = _banc(tmp_path, LXC_PS)
    r = subprocess.run(["bash", str(CTL), *args], capture_output=True, text=True, env=env, timeout=30)
    assert r.returncode == 64, r.stdout + r.stderr


# ─── 3. API : inventaire en cache, routes de paramétrage gardées ───────────

@pytest.fixture
def cache(tmp_path, monkeypatch):
    f = tmp_path / "audit.json"
    f.write_text(json.dumps({"apps": [
        {"name": "files_51", "entrypoint": "files_51.py", "running": True, "state": "running", "port": 8530,
         "domain": "files_51.gk2.secubox.in", "autostart": True, "veille": True, "veille_minutes": 0,
         "sleep_after_seconds": 1800, "last_active": 1, "issues": []},
        {"name": "diapvid", "entrypoint": "app.py", "running": False, "state": "sleeping", "port": 0, "issues": []},
        {"name": "mauvais nom!", "running": True}], "summary": {"total": 3, "partiel": False}}))
    conf = tmp_path / "streamlit.toml"
    conf.write_text('[idle]\ntimeout_minutes = 20\n\n[apps.files_51]\nport = "8530"\nautostart = true\n\n'
                    '[apps.diapvid]\ndomaine_retire = "diapvid.gk2.secubox.in"\ndepubliee = "2026-10-29T03:30:17Z"\n\n'
                    '[instances.files_51]\napp = "files_51"\nport = 8530\ndomain = "files_51.gk2.secubox.in"\n')
    monkeypatch.setattr(api_main, "APPS_AUDIT_CACHE", f)
    monkeypatch.setattr(api_main, "STREAMLIT_CONF", conf)
    monkeypatch.setattr(api_main, "domaine_box", lambda: "gk2.secubox.in")

    def interdit(*a, **k):
        raise AssertionError(f"sous-processus dans une lecture : {a}")
    monkeypatch.setattr(api_main, "_run_ctl", interdit)
    return f


def test_apps_et_access_lisent_l_inventaire_sans_sous_processus(cache):
    d = api_main.list_apps()
    assert [a["name"] for a in d["apps"]] == ["files_51", "diapvid"]
    assert d["apps"][0]["running"] is True and d["apps"][0]["port"] == 8530
    acc = api_main.access()["access"]
    assert {(a["type"], a["name"]) for a in acc} == {("app", "files_51"), ("instance", "files_51")}


def test_instances_lues_dans_le_toml_en_ligne_d_apres_l_inventaire(cache):
    ins = api_main.list_instances()["instances"]
    assert ins == [{"id": "files_51", "app": "files_51", "port": 8530, "enabled": True,
                    "domain": "files_51.gk2.secubox.in", "geree": False, "running": True}]


def test_fiche_d_une_appli(cache, monkeypatch):
    f = api_main.get_app("diapvid")
    assert f["domaine_retire"] == "diapvid.gk2.secubox.in" and f["depubliee"].startswith("2026-10-29")
    assert f["veille_commune_minutes"] == 20 and f["publications"] == []
    g = api_main.get_app("files_51")
    assert g["autostart"] is True and g["port_declare"] == 8530 and g["publications"][0]["nom_public"] == "files_51"
    with pytest.raises(api_main.HTTPException) as e:
        api_main.get_app("absente")
    assert e.value.status_code == 404


def test_veille_et_autostart_passent_par_le_ctl(monkeypatch):
    appels = []

    def ctl_ok(*args, **k):
        appels.append(args)
        if args[1] == "autostart":
            return {"code": 0, "actions": [{"autostart": True, "blocked": False}]}
        return {"code": 0, "veille": False, "veille_minutes": None}
    monkeypatch.setattr(api_main, "_ctl_ok", ctl_ok)
    r = api_main.set_veille("files_51", api_main.ReglageVeille(actif=False, minutes=0), user={"sub": "admin"})
    assert r["veille"] is False
    assert appels[0] == ("app", "veille", "files_51", "off", "0", "--par", "admin", "--apply")
    api_main.set_autostart("files_51", api_main.ReglageAutostart(actif=True), user={"sub": "admin"})
    assert appels[1] == ("app", "autostart", "files_51", "on", "--apply")
    with pytest.raises(api_main.HTTPException) as e:
        api_main.set_veille("files_51", api_main.ReglageVeille(actif=True, minutes=-1), user={})
    assert e.value.status_code == 400
    with pytest.raises(api_main.HTTPException):
        api_main.set_veille("../x", api_main.ReglageVeille(), user={})


def test_changer_le_port_d_une_appli_en_ligne_la_redemarre_et_la_publication_suit(cache, monkeypatch):
    appels = []
    monkeypatch.setattr(api_main, "_attribuer_port", lambda n, p: {"port": 8540, "source": "demande"})
    monkeypatch.setattr(api_main, "_run_ctl", lambda *a, **k: appels.append(a) or {"code": 0})
    monkeypatch.setattr(api_main, "_publication_apres", lambda n, u, nom="": {"publiee": True, "domaine": "x"})
    r = api_main.set_port("files_51", api_main.ReglagePort(port=8540), user={"sub": "admin"})
    assert appels == [("app", "stop", "files_51"), ("app", "start", "files_51", "8540")]
    assert r["port"] == 8540 and r["redemarrage"] == {"ok": True} and r["publication"]["publiee"] is True
    appels.clear()
    r = api_main.set_port("diapvid", api_main.ReglagePort(port=0), user={"sub": "admin"})
    assert appels == [] and r["redemarrage"] is None and r["publication"] is None   # endormie, non publiée
    with pytest.raises(api_main.HTTPException) as e:
        api_main.set_port("files_51", api_main.ReglagePort(port=80), user={})
    assert e.value.status_code == 400


def _gardes(methode, chemin):
    route = next(r for r in api_main.router.routes if r.path == chemin and methode in r.methods)
    return [d.call for d in route.dependant.dependencies] + [d.dependency for d in route.dependencies]


@pytest.mark.parametrize("chemin", ["/app/{name}/port", "/app/{name}/veille", "/app/{name}/autostart"])
def test_routes_de_parametrage_gardees_par_require_jwt(chemin):
    assert require_jwt in _gardes("POST", chemin)


@pytest.mark.parametrize("chemin", ["/app/{name}", "/instances", "/apps", "/access"])
def test_lectures_gardees_par_require_lecture(chemin):
    assert require_lecture in _gardes("GET", chemin)


def test_journaux_reserves_a_l_administrateur():
    assert require_jwt in _gardes("GET", "/app/{name}/logs")


# ─── 4. Panneau : fiche accessible depuis les listes ───────────────────────

def test_panneau_fiche_et_instances():
    src = (PKG / "www" / "streamlit" / "index.html").read_text(encoding="utf-8")
    for r in ("id=\"fiche\"", "ouvrirFiche(", "data-fiche", "'/port'", "'/veille'", "'/autostart'",
              "'/logs?lines=100'", "'/unpublish'", "id=\"fInst\"", "supprimerInstance", "ficheDemo"):
        assert r in src, r
    assert "innerHTML" not in src and "confirm(" not in src
