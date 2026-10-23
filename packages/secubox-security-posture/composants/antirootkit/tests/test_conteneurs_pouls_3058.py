# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3058 — exécutions conteneurisées ignorées, uid lu pour de bon, point de contrôle réamorcé, pouls du démon, AppArmor.

Constat gk2 (2026-10-23) : sur 219 lignes du journal d'exécution, 218 portaient « uid 4294967295 » — c'était l'auid
(« unset ») : l'expression `.*?uid=` s'arrêtait sur `auid=`. Les alertes étaient des exécutions vues DEPUIS des conteneurs
LXC (`/usr/bin/php8.2`, `/memfd:lxc-attach`), dont le chemin n'existe pas sur l'hôte. Et le journal était figé depuis le
28 juillet : `ausearch --checkpoint` sortait en code 10 (inode du point de contrôle disparu à la rotation d'audit.log) et le
démon prenait ce code pour « rien de neuf »."""
import json
import os
import stat
import subprocess
import time
from pathlib import Path

from api import execwatch
from api.daemon import make_log_fn
from api.pouls import Pouls

RACINE = Path(__file__).resolve().parents[1]
CTL = RACINE / "sbin" / "secubox-antirootkitctl"

PHP = (
    'type=SYSCALL msg=audit(1792736138.975:19332556): arch=c00000b7 syscall=221 success=yes exit=0 a0=aaab22ab50c8 '
    'a1=aaab22ab1a40 a2=aaab22abcfd0 a3=0 items=3 ppid=3506104 pid=3506105 auid=4294967295 uid=100033 gid=100033 '
    'euid=100033 suid=100033 fsuid=100033 egid=100033 sgid=100033 fsgid=100033 tty=(none) ses=4294967295 comm="php" '
    'exe="/usr/bin/php8.2" subj=lxc-container-default-cgns key="sbx_exec"\n'
    'type=EXECVE msg=audit(1792736138.975:19332556): argc=1 a0="php"'
)
ZIGBEE = PHP.replace("subj=lxc-container-default-cgns", "subj=lxc-zigbee_</data/lxc>//&:lxc-zigbee_<-data-lxc>:unconfined").replace(":19332556", ":19332557")
HOTE = (
    'type=SYSCALL msg=audit(1792736138.807:19332547): arch=c00000b7 syscall=221 success=yes exit=0 a0=aaab031858f0 '
    'a1=aaab03192420 a2=aaab03183270 a3=ffffb4c5bb60 items=3 ppid=3506087 pid=3506089 auid=4294967295 uid=0 gid=0 '
    'euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) ses=4294967295 comm="lxc-attach" exe="/usr/bin/lxc-attach" '
    'subj=lxc-attach key="sbx_exec"\ntype=EXECVE msg=audit(1792736138.807:19332547): argc=1 a0="lxc-attach"'
)
INCONNU = HOTE.replace("exe=\"/usr/bin/lxc-attach\"", "exe=\"/tmp/.x\"").replace("subj=lxc-attach", "subj=unconfined").replace(":19332547", ":19332548")


# ── parseur ────────────────────────────────────────────────────────────────────

def test_l_uid_est_l_uid_et_pas_l_auid():
    e = execwatch.parse_ausearch(PHP)[0]
    assert e.uid == 100033, "uid= ne doit pas s'arrêter sur auid="
    assert e.auid == 4294967295 and e.subj == "lxc-container-default-cgns"


def test_un_conteneur_se_reconnait_a_son_etiquette_apparmor_lxc():
    assert execwatch.parse_ausearch(PHP)[0].conteneur is True
    assert execwatch.parse_ausearch(ZIGBEE)[0].conteneur is True
    # lxc-attach est un outil de l'HÔTE (son profil porte son nom) ; unconfined aussi
    assert execwatch.parse_ausearch(HOTE)[0].conteneur is False
    assert execwatch.parse_ausearch(INCONNU)[0].conteneur is False


def test_un_evenement_sans_etiquette_n_est_pas_un_conteneur():
    e = execwatch.ExecEvent(pid=1, ppid=1, uid=0, exe="/tmp/x", argv=[], success=True)
    assert e.conteneur is False and e.subj is None


# ── décision et journal ────────────────────────────────────────────────────────

def test_une_execution_conteneurisee_n_est_ni_signalee_ni_jailee():
    e = execwatch.parse_ausearch(PHP)[0]
    assert execwatch.decide(e, allow=set(), is_backed_fn=lambda p: False) == "conteneur"
    jails, logs = [], []
    n = execwatch.run_once([e], set(), lambda p: False, lambda ev: jails.append(ev.pid), lambda ev, d: logs.append(d))
    assert n == 0 and jails == [] and logs == ["conteneur"]


def test_une_execution_hote_inconnue_reste_signalee():
    e = execwatch.parse_ausearch(INCONNU)[0]
    assert execwatch.decide(e, allow=set(), is_backed_fn=lambda p: False) == "jail"


def test_le_journal_ne_garde_pas_les_conteneurs(tmp_path):
    from api.alertstore import AlertStore
    from api.execlog import ExecLog
    log = ExecLog(str(tmp_path / "e.db"))
    astore = AlertStore(str(tmp_path / "a.db"))
    f = make_log_fn(log, astore)
    f(execwatch.parse_ausearch(PHP)[0], "conteneur")
    assert log.count() == 0 and astore.recent(10) == []
    f(execwatch.parse_ausearch(INCONNU)[0], "jail")
    assert log.count() == 1 and len(astore.recent(10)) == 1


# ── pouls ──────────────────────────────────────────────────────────────────────

def test_le_pouls_compte_et_s_ecrit_atomiquement(tmp_path):
    chemin = tmp_path / "pouls.json"
    p = Pouls(str(chemin), now=lambda: 1000.0)
    p.passage(vus=5, conteneurs=3, signales=1, dernier_evenement=990.0)
    p.passage(vus=0, conteneurs=0, signales=0, dernier_evenement=None)
    d = json.loads(chemin.read_text())
    assert d["ts"] == 1000.0 and d["passages"] == 2
    assert d["evenements"] == 5 and d["conteneurs_ignores"] == 3 and d["signales"] == 1
    assert d["dernier_evenement"] == 990.0, "un passage vide n'efface pas le dernier événement vu"
    assert not list(tmp_path.glob("*.tmp")), "écriture par fichier temporaire puis renommage"


def test_le_pouls_garde_les_totaux_apres_redemarrage(tmp_path):
    chemin = tmp_path / "pouls.json"
    Pouls(str(chemin), now=lambda: 1.0).passage(vus=10, conteneurs=4, signales=2, dernier_evenement=1.0)
    p2 = Pouls(str(chemin), now=lambda: 2.0)
    p2.passage(vus=1, conteneurs=0, signales=0, dernier_evenement=2.0)
    d = json.loads(chemin.read_text())
    assert d["evenements"] == 11 and d["conteneurs_ignores"] == 4 and d["passages"] == 2


def test_le_pouls_note_un_reamorcage_du_point_de_controle(tmp_path):
    chemin = tmp_path / "pouls.json"
    p = Pouls(str(chemin), now=lambda: 5.0)
    p.reamorcage()
    assert json.loads(chemin.read_text())["reamorcages"] == 1


def test_le_statut_de_l_api_porte_le_pouls_et_dit_quand_le_demon_est_aveugle(tmp_path):
    from fastapi.testclient import TestClient

    from api.alertstore import AlertStore
    from api.execlog import ExecLog
    from api.main import create_app
    chemin = tmp_path / "pouls.json"
    now = time.time()
    chemin.write_text(json.dumps({"ts": now - 4, "passages": 9, "evenements": 99, "conteneurs_ignores": 80, "signales": 3,
                                  "reamorcages": 1, "dernier_evenement": now - 6}))
    app = create_app(execlog=ExecLog(str(tmp_path / "e.db"), check_same_thread=False), alertstore=AlertStore(str(tmp_path / "a.db")), pouls_path=str(chemin))
    s = TestClient(app).get("/status").json()
    assert s["execlog_rows"] == 0
    assert s["pouls"]["conteneurs_ignores"] == 80 and s["pouls"]["aveugle"] is False and s["pouls"]["age_s"] < 30
    chemin.write_text(json.dumps({"ts": now - 600, "passages": 9, "evenements": 99, "conteneurs_ignores": 0, "signales": 0,
                                  "reamorcages": 0, "dernier_evenement": now - 900}))
    s = TestClient(app).get("/status").json()
    assert s["pouls"]["aveugle"] is True, "pas de passage depuis 10 min : le démon ne regarde plus rien"
    chemin.unlink()
    s = TestClient(app).get("/status").json()
    assert s["pouls"] is None and s["execlog_rows"] == 0, "sans pouls : null, jamais une erreur"


# ── ctl : point de contrôle périmé ─────────────────────────────────────────────

FAUX_AUSEARCH = """#!/usr/bin/env bash
# ausearch factice : un point de contrôle « stale » (inode disparu) sort en 10, comme le vrai ; sinon il l'écrit.
printf '%s\\n' "$*" >> "$FAUX_JOURNAL"
ck=""
while [ $# -gt 0 ]; do if [ "$1" = "--checkpoint" ]; then ck="$2"; fi; shift; done
if [ -f "$ck" ] && grep -q stale "$ck"; then exit 10; fi
echo "fresh" > "$ck"
exit 0
"""


def _ctl(tmp_path, ck_contenu):
    faux = tmp_path / "bin"
    faux.mkdir()
    a = faux / "ausearch"
    a.write_text(FAUX_AUSEARCH)
    a.chmod(a.stat().st_mode | stat.S_IXUSR)
    ck = tmp_path / "ausearch.checkpoint"
    if ck_contenu is not None:
        ck.write_text(ck_contenu)
    env = dict(os.environ, PATH=f"{faux}:{os.environ['PATH']}", FAUX_JOURNAL=str(tmp_path / "appels"),
               ANTIROOTKIT_CHECKPOINT=str(ck), ANTIROOTKIT_AUDIT=str(tmp_path / "audit.log"))
    r = subprocess.run(["bash", str(CTL), "execscan"], capture_output=True, text=True, env=env)
    return r, ck, tmp_path / "audit.log"


def test_execscan_reamorce_un_point_de_controle_perime_au_lieu_de_rester_aveugle(tmp_path):
    r, ck, audit = _ctl(tmp_path, "stale")
    assert r.returncode == 0 and r.stdout == ""
    assert ck.read_text().strip() == "fresh", "le point de contrôle périmé est remplacé et la lecture reprend"
    assert "checkpoint" in audit.read_text().lower() and "reamorce" in audit.read_text().lower()
    assert (tmp_path / "appels").read_text().count("--checkpoint") == 2


def test_execscan_normal_ne_reamorce_pas(tmp_path):
    r, ck, audit = _ctl(tmp_path, "fresh")
    assert r.returncode == 0 and ck.read_text().strip() == "fresh"
    assert (tmp_path / "appels").read_text().count("--checkpoint") == 1
    assert not audit.exists()


# ── AppArmor et paquet ─────────────────────────────────────────────────────────

PROFIL = RACINE / "apparmor" / "secubox-antirootkit"
API_UNITE = RACINE / "debian" / "secubox-antirootkit.service"
DEMON_UNITE = RACINE / "systemd" / "sbx-antirootkitd.service"
RULES = RACINE.parents[1] / "debian" / "rules"
POSTINST = RACINE / "debian" / "postinst"


def test_le_profil_apparmor_confine_l_api_et_le_demon_sans_ouvrir_les_secrets():
    p = PROFIL.read_text()
    assert "profile secubox-antirootkit-api" in p and "profile secubox-antirootkit-daemon" in p
    assert p.count("deny /etc/secubox/secrets/** r,") == 2
    api, demon = p.split("profile secubox-antirootkit-daemon", 1)
    assert "/run/secubox/antirootkit.sock rwk," in api
    assert "/usr/bin/sudo" not in api, "l'API ne lance rien : pas de sudo"
    assert "/var/lib/dpkg/info/*.list r," in demon and "/usr/bin/sudo Ux," in demon
    for texte in (api, demon):
        assert "/var/lib/secubox/antirootkit/** rwk," in texte
        assert "capability" not in texte, "aucune capacité : tout acte privilégié passe par le ctl sous sudo"


def test_les_unites_appliquent_le_profil_sans_jamais_empecher_le_demarrage():
    a = [ligne.strip() for ligne in API_UNITE.read_text().splitlines()]
    d = [ligne.strip() for ligne in DEMON_UNITE.read_text().splitlines()]
    # le « - » : profil non chargé ou AppArmor absent = l'unité démarre quand même (sans confinement), pas de panne
    assert "AppArmorProfile=-secubox-antirootkit-api" in a
    assert "AppArmorProfile=-secubox-antirootkit-daemon" in d


def test_le_paquet_installe_et_charge_le_profil():
    assert "composants/antirootkit/apparmor/secubox-antirootkit" in RULES.read_text()
    assert "etc/apparmor.d/secubox-antirootkit" in RULES.read_text()
    p = POSTINST.read_text()
    assert "apparmor_parser -r /etc/apparmor.d/secubox-antirootkit" in p
    # chargé AVANT le démarrage des unités
    assert p.index("apparmor_parser") < p.index("systemctl restart secubox-antirootkit.service")
