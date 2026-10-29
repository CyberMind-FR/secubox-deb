# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3126 L2 tâche 5 (D3) et #3242 — secubox-renommer : LE renommage d'une box, en un seul endroit.

hostnamectl seul laissait l'ancien nom dans /etc/hosts (127.0.1.1) et dans secubox.conf (gk3, #1544), et Avahi
annonçait encore l'ancien nom (#1556). La page Système, premier-pas et le pilotage distant passent désormais tous par
cet outil root. L'outil réel est lancé sans root sous une racine substituée (SBX_RACINE, R-L2-8) ; hostnamectl et
systemctl sont des faux placés en tête du PATH (honoré seulement sous SBX_RACINE)."""
import json
import os
import subprocess
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1]
OUTIL = PKG / "sbin" / "secubox-renommer"
DELAI = 60

FAUX_HOSTNAMECTL = """#!/bin/sh
# faux hostnamectl : note l'argv ; « set-hostname <nom> » écrit etc/hostname comme le vrai (échoue si $FAUX_HN_ECHEC)
printf '%s\\n' "$*" >> "$FAUX_APPELS"
[ -z "$FAUX_HN_ECHEC" ] || exit 1
[ "$1" = set-hostname ] && printf '%s\\n' "$2" > "$SBX_RACINE/etc/hostname"
exit 0
"""

FAUX_SYSTEMCTL = """#!/bin/sh
printf 'systemctl %s\\n' "$*" >> "$FAUX_APPELS"
[ -z "$FAUX_AVAHI_ECHEC" ] || exit 1
exit 0
"""

HOSTS = ("127.0.0.1\tlocalhost\n127.0.1.1\tsecubox-live\n# secubox-live : nom de l'image\n"
         "::1\tlocalhost ip6-localhost ip6-loopback\n10.10.0.1\tgk2 gk2.secubox.in\n")
CONF = ('# SecuBox\n\n[global]\nhostname = "secubox-live"\ntimezone = "Europe/Paris"\n\n[api]\n'
        'jwt_secret = "SECRET-JWT-0451"\n\n[mail]\nhostname = "mail"\n')


class Banc:
    def __init__(self, tmp_path: Path):
        self.r = tmp_path / "racine"
        for d in ("etc/secubox", "var/log/secubox", "var/lib/secubox/p2p", "run"):
            (self.r / d).mkdir(parents=True)
        (self.r / "etc/hosts").write_text(HOSTS)
        (self.r / "etc/hostname").write_text("secubox-live\n")
        (self.r / "etc/secubox/secubox.conf").write_text(CONF)
        (self.r / "etc/secubox/secubox.conf").chmod(0o640)
        (self.r / "var/log/secubox/audit.log").write_text("")
        faux = tmp_path / "faux"
        faux.mkdir()
        for nom, corps in (("hostnamectl", FAUX_HOSTNAMECTL), ("systemctl", FAUX_SYSTEMCTL)):
            (faux / nom).write_text(corps)
            (faux / nom).chmod(0o755)
        self.appels_f = tmp_path / "appels"
        self.env = {k: v for k, v in os.environ.items() if not k.startswith(("SUDO_", "SBX_"))}
        self.env.update(PATH=f"{faux}:/usr/bin:/bin", SBX_RACINE=str(self.r), FAUX_APPELS=str(self.appels_f))

    def run(self, *args, env=None):
        e = dict(self.env)
        e.update(env or {})
        p = subprocess.run([str(OUTIL), *args], env=e, capture_output=True, text=True, timeout=DELAI)
        lignes = p.stdout.strip().splitlines()
        assert len(lignes) <= 1, p.stdout
        return p.returncode, (json.loads(lignes[0]) if lignes else None), p

    def appels(self):
        return self.appels_f.read_text().splitlines() if self.appels_f.exists() else []

    def audit(self):
        a = self.r / "var/log/secubox/audit.log"
        return [json.loads(x) for x in a.read_text().splitlines() if x.strip()]

    def etat(self):
        return {n: (self.r / n).read_bytes() for n in ("etc/hosts", "etc/hostname", "etc/secubox/secubox.conf")}

    def pairs(self, *noms):
        """peers.json du maillage, vu par la box : pairs enrôlés (empreinte et jonction) et une découverte mDNS."""
        pairs = [{"name": n, "mesh_ip": f"10.10.0.{i + 2}", "fingerprint": f"fp{i}", "joined_via": "invite"}
                 for i, n in enumerate(noms)]
        pairs.append({"name": "decouvert", "mesh_ip": "10.10.0.99"})          # non authentifiée : ne bloque rien
        (self.r / "var/lib/secubox/p2p/peers.json").write_text(json.dumps({"peers": pairs}))


@pytest.fixture
def banc(tmp_path):
    return Banc(tmp_path)


def test_renommer_ecrit_hosts_conf_et_hostname(banc):
    rc, sortie, p = banc.run("--acteur", "gk2admin", "gk5")
    assert rc == 0, p.stderr
    assert sortie == {"ok": True, "ancien": "secubox-live", "nouveau": "gk5"}
    hosts = (banc.r / "etc/hosts").read_text()
    assert "127.0.1.1\tgk5" in hosts.splitlines()
    assert "secubox-live" not in hosts.replace("# secubox-live", "")          # les commentaires restent tels quels
    assert "10.10.0.1\tgk2 gk2.secubox.in" in hosts and "127.0.0.1\tlocalhost" in hosts
    conf = (banc.r / "etc/secubox/secubox.conf").read_text()
    assert '[global]\nhostname = "gk5"\n' in conf
    assert 'hostname = "mail"' in conf and "SECRET-JWT-0451" in conf        # seul [global] change, le reste intact
    assert (banc.r / "etc/secubox/secubox.conf").stat().st_mode & 0o777 == 0o640   # droits gardés
    assert banc.appels() == ["set-hostname gk5", "systemctl try-restart avahi-daemon.service"]
    evts = banc.audit()
    assert len(evts) == 1
    e = evts[0]
    assert e["evenement"] == "box_renommee" and e["ancien"] == "secubox-live" and e["nouveau"] == "gk5"
    assert e["acteur"] == "gk2admin"
    assert "SECRET" not in (banc.r / "var/log/secubox/audit.log").read_text()
    # aucun temporaire laissé
    assert sorted(x.name for x in (banc.r / "etc").iterdir()) == ["hostname", "hosts", "secubox"]
    assert sorted(x.name for x in (banc.r / "etc/secubox").iterdir()) == ["secubox.conf"]


def test_renommer_idempotent(banc):
    assert banc.run("gk5")[0] == 0
    avant = banc.etat()
    rc, sortie, p = banc.run("gk5")
    assert rc == 0, p.stderr
    assert sortie == {"ok": True, "ancien": "gk5", "nouveau": "gk5", "inchange": True}
    assert banc.etat() == avant
    assert len(banc.audit()) == 1                                            # rien de changé : rien d'audité


def test_renommer_rattrape_hosts_oublie(banc):
    """Le piège de gk3 : hostnamectl a déjà posé le nom, /etc/hosts et secubox.conf ont gardé l'ancien."""
    (banc.r / "etc/hostname").write_text("gk3\n")
    rc, sortie, p = banc.run("gk3")
    assert rc == 0, p.stderr
    assert "127.0.1.1\tgk3" in (banc.r / "etc/hosts").read_text().splitlines()
    assert 'hostname = "gk3"' in (banc.r / "etc/secubox/secubox.conf").read_text()
    assert sortie.get("inchange") is None and banc.audit()[0]["evenement"] == "box_renommee"


def test_renommer_refuse_un_nom_pris(banc):
    banc.pairs("gk2", "gk3")
    avant = banc.etat()
    rc, sortie, _ = banc.run("gk3")
    assert rc == 4 and sortie == {"ok": False, "erreur": "nom déjà pris au maillage", "code": 4}
    assert banc.etat() == avant and banc.appels() == []
    assert [e["evenement"] for e in banc.audit()] == ["box_renommage_refuse"]
    assert banc.audit()[0]["refus"] == "nom déjà pris au maillage"
    # une découverte mDNS non authentifiée ne réserve aucun nom
    assert banc.run("decouvert")[0] == 0


def test_renommer_refuse_nom_invalide_ou_reserve(banc):
    avant = banc.etat()
    for nom in ("Box_1", "-box", "a" * 64, "gk5.local", "", "gk 5"):
        rc, sortie, _ = banc.run(nom)
        assert rc == 2 and sortie["ok"] is False, nom
    for nom in ("admin", "www", "secubox", "localhost"):
        rc, sortie, _ = banc.run(nom)
        assert rc == 3 and sortie == {"ok": False, "erreur": "nom réservé", "code": 3}, nom
    for argv in ([], ["gk5", "en-trop"], ["--acteur"], ["--acteur", "Admin", "gk5"]):
        assert banc.run(*argv)[0] == 2, argv
    assert banc.etat() == avant and banc.appels() == []


def test_renommer_retablit_si_hostnamectl_echoue(banc):
    avant = banc.etat()
    rc, sortie, _ = banc.run("gk5", env={"FAUX_HN_ECHEC": "1"})
    assert rc == 6 and sortie == {"ok": False, "erreur": "hostnamectl en échec (état précédent rétabli)", "code": 6}
    assert banc.etat() == avant
    assert [e["evenement"] for e in banc.audit()] == ["box_renommage_refuse"]


def test_renommer_retablit_si_audit_impossible(banc):
    """Une décision non auditée n'a pas lieu : hosts, secubox.conf et le nom reviennent à l'état d'avant."""
    a = banc.r / "var/log/secubox/audit.log"
    a.unlink()
    a.mkdir()                                                    # le journal n'est plus un fichier ordinaire
    avant = banc.etat()
    rc, sortie, _ = banc.run("gk5")
    assert rc == 1 and sortie["ok"] is False
    assert banc.etat() == avant
    assert banc.appels()[:2] == ["set-hostname gk5", "set-hostname secubox-live"]


def test_renommer_avahi_absent_ne_bloque_pas(banc):
    rc, sortie, p = banc.run("gk5", env={"FAUX_AVAHI_ECHEC": "1"})
    assert rc == 0 and sortie["ok"] is True
    assert "avahi" in p.stderr.lower()


def test_renommer_ne_suit_pas_les_liens(banc, tmp_path):
    cible = tmp_path / "ailleurs"
    cible.write_text("127.0.1.1\tsecubox-live\n")
    (banc.r / "etc/hosts").unlink()
    (banc.r / "etc/hosts").symlink_to(cible)
    rc, sortie, _ = banc.run("gk5")
    assert rc == 5 and sortie["ok"] is False
    assert cible.read_text() == "127.0.1.1\tsecubox-live\n" and (banc.r / "etc/hosts").is_symlink()
    assert banc.appels() == []
    # secubox.conf (dossier du compte partagé secubox) remplacé par un lien : refusé de même, hosts rétabli
    (banc.r / "etc/hosts").unlink()
    (banc.r / "etc/hosts").write_text(HOSTS)
    conf = banc.r / "etc/secubox/secubox.conf"
    conf.unlink()
    conf.symlink_to(cible)
    rc, _, _ = banc.run("gk5")
    assert rc == 5 and (banc.r / "etc/hosts").read_text() == HOSTS and cible.read_text().startswith("127.0.1.1")


def test_renommer_root_seulement(banc):
    env = {k: v for k, v in banc.env.items() if k != "SBX_RACINE"}
    p = subprocess.run([str(OUTIL), "gk5"], env=env, capture_output=True, text=True, timeout=DELAI)
    if os.geteuid() != 0:
        assert p.returncode == 2 and "root" in p.stderr
    # SBX_RACINE n'est jamais honorée sous une élévation par sudo (R-L2-8)
    rc, _, p = banc.run("gk5", env={"SUDO_UID": str(os.geteuid() + 1)})
    assert rc == 2 and "SBX_RACINE ignorée" in p.stderr
    assert banc.appels() == []


def test_renommer_sans_shell_et_installe():
    src = OUTIL.read_text()
    assert src.startswith("#!/usr/bin/python3 -I\n# SPDX-License-Identifier: LicenseRef-CMSD-1.0")
    assert "shell=True" not in src and "/bin/sh" not in src and "os.system" not in src
    assert "/usr/bin/hostnamectl" in src and "/usr/bin/systemctl" in src
    regles = (PKG / "debian" / "rules").read_text()
    assert "install -D -m 0755 sbin/secubox-renommer debian/secubox-core/usr/sbin/secubox-renommer" in regles
