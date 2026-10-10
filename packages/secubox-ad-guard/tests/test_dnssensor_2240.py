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


# ── détournement d'un domaine normal : de la collecte au dépôt ─────────────────────────────────────────────────────────────────────────────────
def _faux_ctl(tmp_path, sortie):
    ctl = tmp_path / "ctl"
    ctl.write_text(f"#!/bin/sh\n[ \"$1\" = cache-dump ] || exit 9\ncat <<'EOF'\n{sortie}EOF\n")
    ctl.chmod(0o755)
    sudo = tmp_path / "sudo"
    sudo.write_text("#!/bin/sh\n[ \"$1\" = -n ] || exit 8\nshift\nexec \"$@\"\n")                # faux sudo : exige -n, exécute le reste
    sudo.chmod(0o755)
    return ctl, sudo


def test_collecter_revalide_et_range_l_instantane(tmp_path, capteur, monkeypatch):
    ctl, sudo = _faux_ctl(tmp_path, "www.exemple.org\t93.184.216.34\nmauvais nom\t1.2.3.4\nx.exemple.org\tpas-une-ip\nv6.exemple.org\t2606:2800::1\n")
    monkeypatch.setattr(capteur, "CTL", str(ctl))
    monkeypatch.setattr(capteur, "SUDO", str(sudo))
    assert capteur.collecter() == 0
    assert (tmp_path / "cache-reponses.tsv").read_text() == "v6.exemple.org\t2606:2800::1\nwww.exemple.org\t93.184.216.34\n"


def test_collecter_ctl_en_echec_ne_casse_rien(tmp_path, capteur, monkeypatch, capsys):
    monkeypatch.setattr(capteur, "CTL", str(tmp_path / "absent"))
    monkeypatch.setattr(capteur, "SUDO", "/bin/false")
    assert capteur.collecter() == 0 and not (tmp_path / "cache-reponses.tsv").exists() and "refusé" in capsys.readouterr().err


def test_detournement_de_bout_en_bout(tmp_path, capteur, monkeypatch):
    import os
    import time as _t
    # historique de requêtes : « exemple.org » demandé 4 jours de suite ; l'appareil TV l'a demandé tout à l'heure
    counts = [(f"2027-01-{d:02d}", TV, "www.exemple.org", "ALLOWED", 40) for d in (10, 11, 12, 13)]
    magasin(tmp_path, [(NOW - 30, TV, "www.exemple.org", "A", "ALLOWED")], counts)
    monkeypatch.setattr(capteur, "asn_resolveur", lambda: (lambda ip: {"93.184.216.34": 15133, "151.101.1.1": 54113}.get(ip)))
    tsv = tmp_path / "cache-reponses.tsv"
    for k in range(4):                                                 # quatre jours de référence : même ASN
        tsv.write_text("www.exemple.org\t93.184.216.34\n")
        os.utime(tsv, (NOW - (4 - k) * 86400, NOW - (4 - k) * 86400))
        capteur.FRAICHEUR_REPONSES_S = 10**12
        capteur.principal([], now=NOW - (4 - k) * 86400)
    recu, srv = serveur(str(tmp_path / "a.sock"))
    tsv.write_text("www.exemple.org\t151.101.1.1\n")                    # soudain un autre ASN
    os.utime(tsv, (NOW, NOW))
    capteur.principal([], now=NOW)
    srv.close()
    assert [e["rule_id"] for e in recu] == ["dns.hijack.new_net"] and recu[0]["src_ip"] == "151.101.1.1" and recu[0]["path_shape"] == "dns:exemple.org"


def test_instantane_perime_ne_juge_rien(tmp_path, capteur):
    import os
    magasin(tmp_path, [(NOW - 30, TV, "www.exemple.org", "A", "ALLOWED")])
    tsv = tmp_path / "cache-reponses.tsv"
    tsv.write_text("www.exemple.org\t151.101.1.1\n")
    os.utime(tsv, (NOW - 3 * 3600, NOW - 3 * 3600))
    assert capteur.lire_reponses(NOW) is None


def test_controleur_root_cache_dump_imprime_et_n_ecrit_rien(tmp_path, monkeypatch, capsys):
    import stat
    control = tmp_path / "control"
    control.write_text("#!/bin/sh\n[ \"$1\" = dump_cache ] || exit 9\nprintf 'www.exemple.org.\\t300\\tIN\\tA\\t93.184.216.34\\nwww.exemple.org.\\t300\\tIN\\tCNAME\\tx.\\n'\n")
    control.chmod(control.stat().st_mode | stat.S_IXUSR)
    for k, v in {"SECUBOX_ADGUARD_TV_CONTROL": control, "SECUBOX_ADGUARD_TV_AUDIT": tmp_path / "audit.log", "SECUBOX_ADGUARD_TV_SANS_ROOT": "1",
                 "SECUBOX_ADGUARD_TV_ETAT": tmp_path, "SECUBOX_ADGUARD_TV_APPLIQUE": tmp_path / "racine" / "applique.json"}.items():
        monkeypatch.setenv(k, str(v))
    loader = importlib.machinery.SourceFileLoader("ctl_mod", str(SBIN.parent / "secubox-adguard-tv"))
    spec = importlib.util.spec_from_loader("ctl_mod", loader)
    m = importlib.util.module_from_spec(spec)
    loader.exec_module(m)
    avant = sorted(p.name for p in tmp_path.iterdir())
    assert m.main(["secubox-adguard-tv", "cache-dump"]) == 0
    assert capsys.readouterr().out == "www.exemple.org\t93.184.216.34\n"
    assert sorted(p.name for p in tmp_path.iterdir()) == avant            # aucun fichier écrit par le contrôleur


def test_sudoers_et_unite_de_collecte():
    pkg = Path(__file__).resolve().parents[1]
    assert "secubox-adguard-tv cache-dump" in (pkg / "sudoers.d" / "secubox-adguard-tv").read_text()
    u = "\n".join(l for l in (pkg / "debian" / "secubox-ad-guard-dnsdump.service").read_text().splitlines() if not l.lstrip().startswith("#"))
    assert "User=secubox" in u and "User=root" not in u and "ExecStart=/usr/sbin/secubox-adguard-dnssensor --collecter" in u
    rules = (pkg / "debian" / "rules").read_text()
    assert "secubox-ad-guard-dnsdump.timer" in rules and "secubox-ad-guard-dnsdump.timer" in (pkg / "debian" / "postinst").read_text()
