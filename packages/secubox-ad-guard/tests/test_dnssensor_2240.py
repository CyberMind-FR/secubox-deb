# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2240 : le passage du capteur DNS, de bout en bout — magasin SQLite réel, vrai socket Unix, enveloppes lues côté actord."""
import importlib.machinery
import importlib.util
import json
import random
import socket
import sqlite3
import string
import threading
from pathlib import Path

import pytest

SBIN = Path(__file__).resolve().parents[1] / "sbin" / "secubox-adguard-dnssensor"
NOW = 1_800_000_000
JOUR = "2027-01-15"                      # NOW = 2027-01-15 ; la base utilise des jours antérieurs
TV = "192.168.1.60"


@pytest.fixture()
def capteur(tmp_path, monkeypatch):
    monkeypatch.setenv("SECUBOX_ADGUARD_TV_ETAT", str(tmp_path))
    monkeypatch.setenv("SECUBOX_ACTORD_SOCKET", str(tmp_path / "a.sock"))
    monkeypatch.setenv("SECUBOX_DNS_MALVEILLANTS", str(tmp_path / "liste.txt"))
    loader = importlib.machinery.SourceFileLoader("dnssensor_mod", str(SBIN))
    spec = importlib.util.spec_from_loader("dnssensor_mod", loader)
    m = importlib.util.module_from_spec(spec)
    loader.exec_module(m)
    return m


def magasin(tmp_path, recents, counts=()):
    cx = sqlite3.connect(tmp_path / "dnstv.db")
    cx.executescript("""CREATE TABLE dnstv_counts (jour TEXT, client TEXT, domaine TEXT, categorie TEXT DEFAULT '', decision TEXT, hits INTEGER, PRIMARY KEY (jour, client, domaine, decision));
    CREATE TABLE dnstv_recents (ts INTEGER, client TEXT, domaine TEXT, qtype TEXT DEFAULT '', decision TEXT, categorie TEXT DEFAULT '');""")
    cx.executemany("INSERT INTO dnstv_recents(ts,client,domaine,qtype,decision) VALUES (?,?,?,?,?)", recents)
    cx.executemany("INSERT INTO dnstv_counts(jour,client,domaine,decision,hits) VALUES (?,?,?,?,?)", counts)
    cx.commit()
    cx.close()


def serveur(chemin):
    recu, srv = [], socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(chemin)
    srv.listen(4)

    def boucle():
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            buf = b""
            while True:
                d = c.recv(4096)
                if not d:
                    break
                buf += d
            recu.extend(json.loads(l) for l in buf.splitlines() if l)
            c.close()
    threading.Thread(target=boucle, daemon=True).start()
    return recu, srv


def alea(n, graine):
    r = random.Random(graine)
    return "".join(r.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def test_un_domaine_dga_est_depose_en_enveloppe_et_pas_deux_fois(tmp_path, capteur):
    magasin(tmp_path, [(NOW - i * 10, TV, alea(16, i) + ".com", "A", "ALLOWED") for i in range(5)])
    recu, srv = serveur(str(tmp_path / "a.sock"))
    assert capteur.principal([], now=NOW) == 0
    assert capteur.principal([], now=NOW + 60) == 0           # même constat : dédoublonné
    srv.close()
    assert len(recu) == 1 and recu[0]["sensor"] == "dns" and recu[0]["rule_id"] == "dns.dga" and recu[0]["src_ip"] == TV


def test_trafic_ordinaire_ne_depose_rien_meme_avec_beaucoup_de_requetes(tmp_path, capteur):
    magasin(tmp_path, [(NOW - i, TV, d, "A", "ALLOWED") for i, d in enumerate(["www.netflix.com", "api.france.tv"] * 200)])
    recu, srv = serveur(str(tmp_path / "a.sock"))
    capteur.principal([], now=NOW)
    srv.close()
    assert recu == []


def test_domaine_normal_connu_dont_le_trafic_derive(tmp_path, capteur):
    counts = [(f"2027-01-{d:02d}", TV, "www.exemple.fr", "ALLOWED", 40) for d in (10, 11, 12, 13)]
    magasin(tmp_path, [(NOW - i, TV, "www.exemple.fr", "A", "ALLOWED") for i in range(600)], counts)
    recu, srv = serveur(str(tmp_path / "a.sock"))
    capteur.principal([], now=NOW)
    srv.close()
    assert [e["rule_id"] for e in recu] == ["dns.drift.spike"] and recu[0]["path_shape"] == "dns:exemple.fr"


def test_liste_de_l_operateur(tmp_path, capteur):
    (tmp_path / "liste.txt").write_text("# mes domaines\nmauvais.example  # vu dans un rapport\n")
    magasin(tmp_path, [(NOW - 5, TV, "x.mauvais.example", "A", "ALLOWED")])
    recu, srv = serveur(str(tmp_path / "a.sock"))
    capteur.principal([], now=NOW)
    srv.close()
    assert [e["rule_id"] for e in recu] == ["dns.listed"]


def test_socket_absent_ne_perd_pas_le_constat(tmp_path, capteur, capsys):
    magasin(tmp_path, [(NOW - i * 10, TV, alea(16, i) + ".com", "A", "ALLOWED") for i in range(5)])
    assert capteur.principal([], now=NOW) == 0
    assert "impossible" in capsys.readouterr().err and not (tmp_path / "dnssensor-etat.json").exists()   # rien mémorisé : on réessaie
    recu, srv = serveur(str(tmp_path / "a.sock"))
    capteur.principal([], now=NOW + 60)
    srv.close()
    assert len(recu) == 1


def test_sans_magasin_rien_a_faire(tmp_path, capteur):
    assert capteur.principal([], now=NOW) == 0


def test_dry_run_n_envoie_ni_ne_memorise(tmp_path, capteur, capsys):
    magasin(tmp_path, [(NOW - i * 10, TV, alea(16, i) + ".com", "A", "ALLOWED") for i in range(5)])
    recu, srv = serveur(str(tmp_path / "a.sock"))
    assert capteur.principal(["--dry-run"], now=NOW) == 0
    srv.close()
    sortie = json.loads(capsys.readouterr().out)
    assert recu == [] and not (tmp_path / "dnssensor-etat.json").exists() and sortie[0]["rule"] == "dns.dga"


def test_l_empaquetage_installe_unite_minuterie_exemple_et_gere_activation():
    pkg = Path(__file__).resolve().parents[1]
    rules, post, prerm = [(pkg / "debian" / n).read_text() for n in ("rules", "postinst", "prerm")]
    assert "sbin/secubox-adguard-dnssensor" in rules and "secubox-ad-guard-dnssensor.timer" in rules and "dns-malveillants.txt.example" in rules
    assert "enable --now secubox-ad-guard-dnssensor.timer" in post and "disable --now secubox-ad-guard-dnssensor.timer" in prerm
    unite = (pkg / "debian" / "secubox-ad-guard-dnssensor.service").read_text()
    sans_com = "\n".join(l for l in unite.splitlines() if not l.lstrip().startswith("#"))
    assert "User=secubox" in sans_com and "SupplementaryGroups=actord-ingest" in sans_com and "RestrictAddressFamilies=AF_UNIX" in sans_com
    assert "User=root" not in sans_com and "NoNewPrivileges=yes" in sans_com and "ConditionPathExists=/run/secubox/actord.sock" in sans_com
