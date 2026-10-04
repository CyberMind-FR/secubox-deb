# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""POC « DNS AdBlock TV » (#1943) contre un VRAI Unbound (banc local 127.0.0.x, sans Internet). Sauté si le binaire `unbound` est absent."""
import importlib.util
import shutil
import time
from pathlib import Path

import pytest

from api import dnstv

pytestmark = pytest.mark.skipif(shutil.which("unbound") is None, reason="binaire unbound absent")
ICI = Path(__file__).resolve().parents[1]


def _charge(nom):
    spec = importlib.util.spec_from_file_location(nom.replace("-", "_"), ICI / "tools" / f"{nom}.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


lab = _charge("dns-limits-lab")


@pytest.fixture(scope="module")
def rapport():
    return lab.executer()


def test_a_et_b_un_domaine_distinct_est_bloquable_en_block_pas_en_observe(rapport):
    for k in ("A", "B"):
        assert rapport["cas"][k]["observe"] == "NOERROR" and rapport["cas"][k]["block"] == "NXDOMAIN", rapport["cas"][k]


def test_c_pub_et_video_sur_le_meme_nom_le_dns_est_insuffisant(rapport):
    c = rapport["cas"]["C"]
    assert c["observe"] == "NOERROR" and c["block"] == "NXDOMAIN" and "AUSSI la vidéo" in c["verdict"]


def test_d_pub_dans_le_flux_rien_a_bloquer(rapport):
    d = rapport["cas"]["D"]
    assert d["block"] == "NOERROR" and d["classe"] is None


def test_e_et_f_ip_codee_en_dur_et_doh_contournent_la_box(rapport):
    assert rapport["cas"]["E"]["lignes_journal_ajoutees"] == 0
    f = rapport["cas"]["F"]
    assert f["resolu_par_externe"] == "NOERROR" and f["requetes_vues_par_la_boite"] == 0


def test_g_domaine_partage_faux_positif(rapport):
    assert rapport["cas"]["G"]["block"] == "NXDOMAIN" and "faux positif" in rapport["cas"]["G"]["verdict"]


def test_isolement_le_poc_n_altere_pas_le_puits_de_production_des_autres_clients(rapport):
    i = rapport["cas"]["isolement"]
    assert i["client_hors_perimetre"] == "NXDOMAIN" and i["tv_observe"] == "NOERROR"


def test_un_site_ordinaire_reste_resolu_en_block(rapport):
    assert rapport["cas"]["ordinaire"]["block"] == "NOERROR"


def test_le_journal_reel_d_unbound_est_compris_par_l_analyseur(rapport):
    j = rapport["cas"]["journal_reel"]
    assert j["evenements"] >= 8 and j["decisions"]["BLOCKED"] >= 4 and j["decisions"]["ALLOWED"] >= 4
    assert {"127.0.0.2", "127.0.0.3"} <= set(j["clients"])


def test_resolution_autorisee_et_blocage_de_bout_en_bout_jusqu_aux_compteurs(tmp_path):
    """Vrai Unbound -> vrai journal -> analyseur -> compteurs : ce que le démon d'alimentation fait en service."""
    banc = lab.Banc()
    etat = {"actif": True, "clients": [{"ip": lab.TV_BLOCK, "nom": "tv", "mode": "block"}]}
    try:
        banc.demarrer(etat)
        for _ in range(3):
            assert lab.resoudre(lab.TV_BLOCK, "ads.cdn-pub.sbxlab")["rcode"] == "NXDOMAIN"
        assert lab.resoudre(lab.TV_BLOCK, "news.sbxlab")["rcode"] == "NOERROR"
        lignes = lab.lignes_journal(banc)
    finally:
        banc.arreter()
    m = dnstv.Magasin(tmp_path / "t.db")
    cl = dnstv.Classifieur(lab.LISTES_BANC)
    nb = _suivre(lignes, m, cl)
    s = m.statistiques(client=lab.TV_BLOCK)
    assert nb >= 4 and s["par_decision"].get("BLOCKED") == 3 and s["classes_bloques"] == {"advertising": 3}
    assert m.top("BLOCKED", client=lab.TV_BLOCK)[0]["domaine"] == "ads.cdn-pub.sbxlab"


def _suivre(lignes, m, cl):
    import importlib.machinery
    loader = importlib.machinery.SourceFileLoader("dnsfeed", str(ICI / "sbin" / "secubox-adguard-dnsfeed"))
    spec = importlib.util.spec_from_loader("dnsfeed", loader)
    feed = importlib.util.module_from_spec(spec)
    loader.exec_module(feed)
    return feed.suivre(iter(lignes), m, cl, recharger=lambda: cl)


def _amont_en_erreur(port):
    """Faux amont qui répond SERVFAIL à tout (un amont MUET, lui, fait attendre Unbound longtemps sans rien journaliser)."""
    import socket
    import struct
    import threading
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", port))
    s.settimeout(0.2)
    arret = threading.Event()

    def boucle():
        while not arret.is_set():
            try:
                q, src = s.recvfrom(512)
            except OSError:
                continue
            s.sendto(q[:2] + struct.pack("!H", 0x8182) + q[4:6] + b"\x00\x00\x00\x00\x00\x00" + q[12:], src)
    th = threading.Thread(target=boucle, daemon=True)
    th.start()
    return lambda: (arret.set(), th.join(1), s.close())


def test_upstream_en_erreur_est_compte_comme_upstream_error(tmp_path):
    """Un amont qui répond SERVFAIL : jamais compté comme BLOCKED ni comme ALLOWED."""
    arreter = _amont_en_erreur(5390)
    banc = lab.Banc()
    try:
        drop = dnstv.rendre_unbound({"actif": True, "clients": [{"ip": lab.TV_BLOCK, "nom": "tv", "mode": "block"}]}, lab.LISTES_BANC)
        conf = lab._conf_base(lab.P_BOITE, str(banc.dir / "boite.pid")).rstrip("\n") + "\n" + drop.replace("server:\n", "", 1)
        conf += 'forward-zone:\n    name: "."\n    forward-addr: 127.0.0.1@5390\n'
        banc._lancer("boite", conf, banc.journal)
        for _ in range(50):
            if banc.journal.exists() and "start of service" in banc.journal.read_text(errors="replace"):
                break
            time.sleep(0.1)
        r = lab.resoudre(lab.TV_BLOCK, "news.sbxlab")
        assert r["rcode"] == "SERVFAIL"
        time.sleep(0.5)
        an = dnstv.Analyseur()
        evts = [e for e in (an.ligne(ligne) for ligne in banc.journal.read_text(errors="replace").splitlines()) if e]
    finally:
        banc.arreter()
        arreter()
    assert evts and evts[-1].decision == "UPSTREAM_ERROR" and evts[-1].rcode == "SERVFAIL"
    m = dnstv.Magasin(tmp_path / "t.db")
    m.ajouter([(e, None) for e in evts])
    assert m.statistiques()["par_decision"] == {"UPSTREAM_ERROR": 1}


def test_l_outil_client_voit_le_blocage_avec_une_reference():
    outil = _charge("dns-tv-test")
    banc = lab.Banc()
    etat = {"actif": True, "clients": [{"ip": "127.0.0.1", "nom": "ici", "mode": "block"}]}
    try:
        banc.demarrer(etat)
        box, ref = f"127.0.0.1#{lab.P_BOITE}", f"127.0.0.1#{lab.P_EXTERNE}"
        assert outil.statut(outil.interroger(box, "ads.cdn-pub.sbxlab"), outil.interroger(ref, "ads.cdn-pub.sbxlab")) == "BLOCKED"
        assert outil.statut(outil.interroger(box, "news.sbxlab"), outil.interroger(ref, "news.sbxlab")) == "ALLOWED"
    finally:
        banc.arreter()


# ── #1954 : application des règles du mode auto À CHAUD, sur un vrai Unbound jetable ───────────────────────────────────────
import shutil
import socket
import subprocess as _sp
import time as _t


@pytest.mark.skipif(not (shutil.which("unbound") and shutil.which("unbound-control") and shutil.which("dig")), reason="unbound/dig absents")
def test_ajout_retrait_a_chaud(tmp_path):
    """Mesuré sur Unbound 1.17.1 (gk2) : view_local_zone prend effet tout de suite, et le retrait rend la main à la zone parente."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    d = tmp_path
    (d / "u.conf").write_text(f'''server:
    interface: 127.0.0.1@{port}
    access-control: 127.0.0.0/8 allow
    access-control-view: 127.0.0.2/32 sbx-t
    pidfile: {d}/u.pid
    directory: {d}
    use-syslog: no
    logfile: {d}/u.log
view:
    name: "sbx-t"
    local-zone: "." transparent
    local-zone: "sbx." transparent
    local-data: "hote.sbx. 60 IN A 192.0.2.1"
remote-control:
    control-enable: yes
    control-interface: {d}/ctl.sock
    control-use-cert: no
''')
    ctl = ["unbound-control", "-c", str(d / "u.conf"), "-s", str(d / "ctl.sock")]

    def etat():
        r = _sp.run(["dig", "+time=2", "+tries=1", "-b", "127.0.0.2", "-p", str(port), "@127.0.0.1", "hote.sbx"], capture_output=True, text=True)
        return "NXDOMAIN" if "NXDOMAIN" in r.stdout else ("NOERROR" if "192.0.2.1" in r.stdout else r.stdout[-200:])

    _sp.run(["unbound", "-c", str(d / "u.conf")], check=True)
    try:
        for _ in range(20):
            if (d / "ctl.sock").exists():
                break
            _t.sleep(0.2)
        assert etat() == "NOERROR"
        _sp.run([*ctl, "view_local_zone", "sbx-t", "hote.sbx.", "always_nxdomain"], check=True, capture_output=True)
        assert etat() == "NXDOMAIN"
        _sp.run([*ctl, "view_local_zone_remove", "sbx-t", "hote.sbx."], check=True, capture_output=True)
        assert etat() == "NOERROR"
    finally:
        _sp.run([*ctl, "stop"], capture_output=True)


@pytest.mark.skipif(not (shutil.which("unbound") and shutil.which("unbound-control") and shutil.which("dig")), reason="unbound/dig absents")
def test_puits_complet_et_regles_de_la_vue(tmp_path):
    """#1959, mesuré sur Unbound 1.17.1 (gk2) : `view-first: yes` garde le puits global ET applique les règles de la vue ; la vue transparente cache le puits."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    d = tmp_path
    (d / "u.conf").write_text(f'''server:
    interface: 127.0.0.1@{port}
    access-control: 127.0.0.0/8 allow
    access-control-view: 127.0.0.3/32 sbx-vf
    access-control-view: 127.0.0.4/32 sbx-transparent
    pidfile: {d}/u.pid
    directory: {d}
    use-syslog: no
    logfile: {d}/u.log
    local-zone: "bloque.sbx." always_nxdomain
    local-zone: "ok.sbx." static
    local-data: "ok.sbx. 60 IN A 192.0.2.7"
view:
    name: "sbx-vf"
    view-first: yes
    local-zone: "regle.sbx." always_nxdomain
view:
    name: "sbx-transparent"
    local-zone: "." transparent
    local-zone: "regle.sbx." always_nxdomain
remote-control:
    control-enable: yes
    control-interface: {d}/ctl.sock
    control-use-cert: no
''')
    ctl = ["unbound-control", "-c", str(d / "u.conf"), "-s", str(d / "ctl.sock")]

    def etat(source, nom):
        r = _sp.run(["dig", "+time=2", "+tries=1", "-b", source, "-p", str(port), "@127.0.0.1", nom], capture_output=True, text=True)
        return "NXDOMAIN" if "NXDOMAIN" in r.stdout else ("NOERROR" if "192.0.2.7" in r.stdout else r.stdout[-120:])

    _sp.run(["unbound", "-c", str(d / "u.conf")], check=True)
    try:
        for _ in range(20):
            if (d / "ctl.sock").exists():
                break
            _t.sleep(0.2)
        assert etat("127.0.0.3", "bloque.sbx") == "NXDOMAIN"            # le puits global s'applique
        assert etat("127.0.0.3", "ok.sbx") == "NOERROR"                 # et sert ce qu'il sert (repli sur les zones globales)
        assert etat("127.0.0.3", "regle.sbx") == "NXDOMAIN"             # la règle de la vue s'ajoute
        assert etat("127.0.0.4", "ok.sbx") == "NXDOMAIN"                # vue transparente : le puits global est caché
        _sp.run([*ctl, "view_local_zone", "sbx-vf", "chaud.sbx.", "always_nxdomain"], check=True, capture_output=True)
        assert etat("127.0.0.3", "chaud.sbx") == "NXDOMAIN" and etat("127.0.0.3", "ok.sbx") == "NOERROR"    # l'ajout à chaud marche aussi
    finally:
        _sp.run([*ctl, "stop"], capture_output=True)
