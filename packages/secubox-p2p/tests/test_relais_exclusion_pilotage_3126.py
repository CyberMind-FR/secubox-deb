# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3126 L5 (R-L5-27, R-L5-30) : une box passée « distante » est servie par le pilotage du maître ; relais-maillage ne relaie
plus SON nom admin.<box> (liste d'exclusion root écrite par secubox-pilotage-vhost), et seulement celui-là.

Tests de COMPORTEMENT : le VRAI script tourne sans root sous une racine substituée (SBX_RELAIS_ESSAI, ignorée en root) ;
wg, curl, dig, haproxyctl, nft… sont des doublures sur PATH, la table des routes et haproxy.toml sont de vrais fichiers."""
import fcntl
import json
import os
import subprocess
import time
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "sbin" / "secubox-relais-maillage"
ADMIN = "admin.gk5.secubox.in"
HALL = "hall.gk5.secubox.in"
IP5, IP4 = "10.10.0.5", "10.10.0.4"
PUB = "203.0.113.7"


def _script(p: Path, corps: str):
    p.write_text("#!/bin/bash\n" + corps)
    p.chmod(0o755)


class Relais:
    def __init__(self, tmp: Path):
        self.r = tmp / "racine"
        self.bin = tmp / "bin"
        self.py = tmp / "py" / "secubox_core"
        self.journal = tmp / "appels.log"
        for d in ("etc/secubox/waf", "data/haproxy/certs", "var/lib/secubox/p2p", "var/log/secubox", "etc/nginx/conf.d",
                  "etc/nftables.d", "var/lib/secubox/ports-publics.d", "var/lib/secubox-pilotage-pages"):
            (self.r / d).mkdir(parents=True, exist_ok=True)
        os.chmod(self.r / "var/lib/secubox-pilotage-pages", 0o755)
        self.routes = self.r / "etc/secubox/waf/haproxy-routes.json"
        self.routes.write_text(json.dumps({"hall.gk2.secubox.in": ["127.0.0.1", 9080]}))
        self.toml = self.r / "etc/secubox/haproxy.toml"
        self.toml.write_text('mode = "native"\n')
        (self.r / "data/haproxy/certs/*.gk5.secubox.in.pem").write_text("joker")
        (self.r / "var/lib/secubox/p2p/wg_mesh.json").write_text(json.dumps({"peers": [
            {"name": "gk5", "mesh_ip": IP5, "public_key": "K5"}, {"name": "gk4", "mesh_ip": IP4, "public_key": "K4"}]}))
        self.excl = self.r / "var/lib/secubox-pilotage-pages/exclusions-relais.json"
        self.verrou = self.r / "var/lib/secubox-pilotage-pages/verrou-relais.lock"
        self.py.mkdir(parents=True)
        (self.py / "__init__.py").write_text("")
        (self.py / "auth.py").write_text("def domaine_box():\n    return 'gk2.secubox.in'\n")
        self.bin.mkdir()
        log = f'echo "$(basename "$0") $*" >> {self.journal}\n'
        _script(self.bin / "wg", log + f'printf "K5\\t{IP5}/32\\nK4\\t{IP4}/32\\n"\n')
        _script(self.bin / "dig", log + f"echo {PUB}\n")
        noms = json.dumps({"domaine": "gk5.secubox.in", "noms": [ADMIN, HALL]})
        _script(self.bin / "curl", log + f"""
case "$*" in
  */public/noms*) echo '{noms}' ;;
  */public/ports*) echo 404 ;;
  *) if [ -e {self.r}/MUET ]; then echo 000; else echo 200; fi ;;
esac
""")
        _script(self.bin / "haproxyctl", log + f"""
case "$1 $2" in
  "vhost add") printf '\\n[vhosts.%s]\\ndomain = "%s"\\nbackend = "%s"\\nenabled = true\\nssl = true\\n' "$(echo "$3" | tr '.-' '__')" "$3" "$4" >> {self.toml} ;;
  "vhost remove") python3 - {self.toml} "$3" <<'PY'
import re, sys
t = open(sys.argv[1]).read()
open(sys.argv[1], "w").write(re.sub(r"\\n\\[vhosts\\." + re.escape(sys.argv[2]) + r"\\][^\\[]*", "\\n", t))
PY
  ;;
esac
exit 0
""")
        for n in ("certbot", "systemctl", "nft", "sleep", "nginx"):
            _script(self.bin / n, log + "exit 0\n")
        _script(self.bin / "ss", "exit 0\n")

    def env(self, **extra):
        e = {"PATH": f"{self.bin}:{os.environ['PATH']}", "PYTHONPATH": str(self.py.parent), "SBX_RELAIS_ESSAI": str(self.r)}
        e.update(extra)
        return e

    def lancer(self, *args, **extra):
        return subprocess.run(["bash", str(SCRIPT), *args], capture_output=True, text=True, env=self.env(**extra), timeout=60)

    def popen(self, *args, **extra):
        return subprocess.Popen(["bash", str(SCRIPT), *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                env=self.env(**extra))

    def exclure(self, noms, mode=0o644):
        self.excl.write_text(json.dumps({"noms": noms}))
        os.chmod(self.excl, mode)

    def table(self):
        return json.loads(self.routes.read_text())

    def vhosts(self):
        return self.toml.read_text().count("domain = ")

    def appels(self):
        return self.journal.read_text().splitlines() if self.journal.exists() else []


@pytest.fixture
def rel(tmp_path):
    return Relais(tmp_path)


# --- effet de l'exclusion (I4) -------------------------------------------------------------------------------------

def test_synchroniser_sans_exclusion_relaie_les_deux_noms(rel):
    r = rel.lancer("synchroniser")
    assert r.returncode == 0, r.stdout + r.stderr
    t = rel.table()
    assert t[ADMIN] == [IP5, 9080] and t[HALL] == [IP5, 9080]


def test_synchroniser_exclu_jamais_recree_autres_noms_relayes(rel):
    rel.exclure([ADMIN])
    for _ in range(3):   # plusieurs passes : ni recréé, ni « périmé » d'une passe à l'autre
        r = rel.lancer("synchroniser")
        assert r.returncode == 0, r.stdout + r.stderr
    t = rel.table()
    assert ADMIN not in t and t[HALL] == [IP5, 9080]
    assert f'domain = "{ADMIN}"' not in rel.toml.read_text()


def test_synchroniser_ne_retire_jamais_le_nom_tenu_par_le_pilotage(rel):
    t = rel.table()
    t[ADMIN] = ["127.0.0.1", 9080]    # posé par le pilotage (nginx du maître)
    rel.routes.write_text(json.dumps(t))
    rel.exclure([ADMIN])
    for _ in range(2):
        assert rel.lancer("synchroniser").returncode == 0
    assert rel.table()[ADMIN] == ["127.0.0.1", 9080]


def test_relayer_refuse_le_nom_exclu_et_accepte_les_autres(rel):
    rel.exclure([ADMIN])
    r = rel.lancer("relayer", ADMIN, IP5, "9080")
    assert r.returncode == 1 and "pilotage" in r.stderr
    assert ADMIN not in rel.table() and rel.vhosts() == 0
    assert rel.lancer("relayer", HALL, IP5, "9080").returncode == 0
    assert rel.table()[HALL] == [IP5, 9080]


@pytest.mark.parametrize("cas", ["absent", "inscriptible", "lien", "lien_dur", "illisible"])
def test_fichier_d_exclusion_absent_ou_non_sur(rel, cas):
    """Absent : rien d'exclu (box sans pilotage). Présent mais non sûr (inscriptible, lien, lien dur, illisible) : dans le
    doute, AUCUN nom admin.<box> n'est créé (jamais deux vhosts pour un nom) et aucun n'est retiré ; les autres noms suivent."""
    if cas == "inscriptible":
        rel.exclure([], mode=0o666)
    elif cas == "lien":
        cible = rel.r / "ailleurs.json"
        cible.write_text(json.dumps({"noms": []}))
        rel.excl.symlink_to(cible)
    elif cas == "lien_dur":
        rel.exclure([])
        os.link(rel.excl, rel.r / "double.json")
    elif cas == "illisible":
        rel.excl.write_text("{pas du json")
        os.chmod(rel.excl, 0o644)
    r = rel.lancer("synchroniser")
    assert r.returncode == 0, r.stdout + r.stderr
    t = rel.table()
    assert t[HALL] == [IP5, 9080]
    if cas == "absent":
        assert t[ADMIN] == [IP5, 9080]
    else:
        assert ADMIN not in t
        assert rel.lancer("relayer", ADMIN, IP5, "9080").returncode == 1


def test_nom_non_admin_jamais_exclu_meme_liste(rel):
    rel.exclure([ADMIN, HALL])
    assert rel.lancer("synchroniser").returncode == 0
    assert rel.table()[HALL] == [IP5, 9080] and ADMIN not in rel.table()


# --- pair d'une box (I1) -------------------------------------------------------------------------------------------

def test_pair_de_rend_l_ip_maillee_de_la_box(rel):
    r = rel.lancer("pair-de", "gk5")
    assert r.returncode == 0 and r.stdout.strip() == IP5
    assert rel.lancer("pair-de", "gk4").stdout.strip() == IP4
    assert rel.lancer("pair-de", "gk9").returncode == 1
    assert rel.lancer("pair-de", "../x").returncode != 0


def test_pair_de_refuse_nom_double_ou_hors_wg(rel):
    etat = rel.r / "var/lib/secubox/p2p/wg_mesh.json"
    etat.write_text(json.dumps({"peers": [{"name": "gk5", "mesh_ip": IP5}, {"name": "gk5", "mesh_ip": IP4}]}))
    assert rel.lancer("pair-de", "gk5").returncode == 1
    etat.write_text(json.dumps({"peers": [{"name": "gk5", "mesh_ip": "10.10.0.9"}]}))   # absent des allowed-ips de wg-mesh
    assert rel.lancer("pair-de", "gk5").returncode == 1


# --- rétablissement sans sonde (I3) --------------------------------------------------------------------------------

def test_relayer_sans_sonde_retablit_un_pair_muet(rel):
    (rel.r / "MUET").touch()
    assert rel.lancer("relayer", ADMIN, IP5, "9080").returncode == 1     # la sonde refuse un pair muet
    assert ADMIN not in rel.table()
    rel.journal.unlink()
    r = rel.lancer("relayer", "--sans-sonde", ADMIN, IP5, "9080")
    assert r.returncode == 0, r.stdout + r.stderr
    assert rel.table()[ADMIN] == [IP5, 9080]
    assert rel.toml.read_text().count(f'domain = "{ADMIN}"') == 1
    assert any(x.startswith("haproxyctl generate") for x in rel.appels())
    assert not any(x.startswith("curl") or x.startswith("dig") for x in rel.appels())


def test_relayer_sans_sonde_garde_les_controles(rel):
    rel.exclure([ADMIN])
    assert rel.lancer("relayer", "--sans-sonde", ADMIN, IP5, "9080").returncode == 1
    rel.excl.unlink()
    assert rel.lancer("relayer", "--sans-sonde", ADMIN, "192.168.1.5", "9080").returncode == 1
    assert ADMIN not in rel.table()


# --- verrou commun avec le pilotage (I2) ---------------------------------------------------------------------------

def _tenir(rel):
    fd = os.open(rel.verrou, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX)
    return fd


@pytest.mark.parametrize("verbe", [("relayer", HALL, IP5, "9080"), ("retirer", HALL), ("synchroniser",)])
def test_passe_du_relais_attend_le_verrou_commun(rel, verbe):
    if verbe[0] == "retirer":
        rel.routes.write_text(json.dumps({HALL: [IP5, 9080]}))
    avant = rel.routes.read_text()
    fd = _tenir(rel)          # le pilotage bascule
    try:
        p = rel.popen(*verbe)
        time.sleep(1.5)
        assert p.poll() is None, p.communicate()
        assert rel.routes.read_text() == avant          # rien réécrit pendant le basculement
        assert not any(x.startswith("haproxyctl") for x in rel.appels())
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
    out, errs = p.communicate(timeout=60)
    assert p.returncode == 0, out + errs
    assert rel.routes.read_text() != avant


def test_verrou_herite_du_pilotage_ne_bloque_pas(rel):
    fd = _tenir(rel)
    try:
        p = subprocess.run(["bash", str(SCRIPT), "relayer", "--sans-sonde", ADMIN, IP5, "9080"], capture_output=True, text=True,
                           env=rel.env(SECUBOX_VERROU_FD=str(fd)), pass_fds=(fd,), timeout=30)
        assert p.returncode == 0, p.stdout + p.stderr
        assert rel.table()[ADMIN] == [IP5, 9080]
    finally:
        os.close(fd)


def test_descripteur_herite_etranger_ignore(rel, tmp_path):
    autre = os.open(tmp_path / "autre.lock", os.O_RDWR | os.O_CREAT, 0o600)
    fd = _tenir(rel)
    try:
        p = subprocess.Popen(["bash", str(SCRIPT), "retirer", HALL], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             env=rel.env(SECUBOX_VERROU_FD=str(autre)), pass_fds=(autre,))
        time.sleep(1.5)
        assert p.poll() is None          # un descripteur qui n'est pas le verrou commun ne dispense de rien
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
        os.close(autre)
    p.communicate(timeout=60)


def test_verrou_commun_lien_refuse(rel, tmp_path):
    (tmp_path / "ailleurs.lock").write_text("")
    rel.verrou.symlink_to(tmp_path / "ailleurs.lock")
    r = rel.lancer("relayer", HALL, IP5, "9080")
    assert r.returncode == 1 and "verrou" in r.stderr
    assert HALL not in rel.table()


def test_sbx_relais_essai_ignoree_en_root():
    texte = SCRIPT.read_text()
    assert '[ "$(id -u)" -ne 0 ] && [ -n "${SBX_RELAIS_ESSAI:-}" ]' in texte
