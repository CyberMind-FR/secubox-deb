# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Lot 4 (#3374), passe 3 : cibles hors EROFS, replis au-delà de 500 découvertes, base antérieure migrée, marge d'ingestion du curseur,
refus d'arrêt espacés, fichier nft lien retiré, résultat publié en 0640."""
import sqlite3
from pathlib import Path

from api import dnstv, dnstv_contournement as C, dnstv_dpi as D
from test_dnstv_ctl_api import ctl, monde  # noqa: F401
from test_dnstv_dpi_ctl_3374 import dpi  # noqa: F401
from test_dnstv_contournement_3374 import etat as etat_c, nft  # noqa: F401
from test_dnstv_dpi_moteur_3374 import Rep, dossier, lancer, ndpid_occupe, charge_etat, _module_auto  # noqa: F401

PKG = Path(__file__).resolve().parents[1]
MAC = "aa:bb:cc:00:00:01"
NOW = 1_800_000_000


def test_tmpfiles_du_dossier_des_cibles_sous_un_parent_root():
    t = (PKG.parent / "secubox-toolbox-ng" / "tmpfiles" / "zz-secubox-dpi.conf").read_text()
    assert "d /run/secubox/sbxdpi-cibles 0750 root secubox-toolbox" in t
    core = (PKG.parent / "secubox-core" / "tmpfiles.d" / "secubox.conf").read_text()
    assert "d /run/secubox 1777 root root" in core                     # parent root : pas de « unsafe path transition »


def test_dpi_cibles_oserror_auditee_sans_trace(dpi, monkeypatch, capsys):  # noqa: F811
    bloc = dpi["tmp"] / "pas-un-dossier"
    bloc.write_text("x")
    monkeypatch.setenv("SECUBOX_ADGUARD_TV_CIBLES", str(bloc / "cibles.json"))
    assert ctl(dpi, "dpi-cibles") == 1
    sortie = capsys.readouterr()
    assert "Traceback" not in sortie.err + sortie.out
    assert "dpi-cibles-echec" in (dpi["tmp"] / "audit.log").read_text()


def test_replis_nouveaux_trouves_au_dela_de_500_decouvertes(dossier):  # noqa: F811
    m = D.MagasinDPI(dossier / "dpi-appareils.db")
    m.ajouter_decouvertes(MAC, [{"type": "repli", "domaine": f"vieux{i}.example", "categorie": "PUBLICITE", "ts": i, "refus_ts": i}
                                for i in range(600)])
    for i in range(600):
        m.marquer(MAC, f"vieux{i}.example", "candidat")
    m.ajouter_decouvertes(MAC, [{"type": "repli", "domaine": "metaproxy.francetvpub.fr", "categorie": "PUBLICITE", "ts": 9999,
                                 "refus_ts": 9999}])
    etat, _ = dnstv.lire_etat()
    replis, vus = _module_auto().replis_du_passage(etat)
    assert [d["domaine"] for d in replis["tv-salon"]] == ["metaproxy.francetvpub.fr"]


def test_base_anterieure_a_la_passe_2_mise_de_cote(tmp_path):
    f = tmp_path / "d.db"
    with sqlite3.connect(f) as cx:
        cx.execute("CREATE TABLE flux (mac TEXT NOT NULL, minute INTEGER NOT NULL, appli TEXT NOT NULL, categorie_ndpi TEXT, hote TEXT, "
                   "port INTEGER, distant TEXT, flux INTEGER, octets INTEGER, sans_dns INTEGER, dns_chiffre INTEGER, "
                   "PRIMARY KEY (mac, minute, appli, hote, port, distant))")
    m = D.MagasinDPI(f)
    assert m.corrompue_recreee and (tmp_path / "d.db.corrompue").exists()
    m.ingerer([{"mac": MAC, "minute": 1, "local": "192.168.1.50", "proto": "tcp", "appli": "TLS", "hote": "x.example", "port": 443,
                "distant": "", "flux": 1, "octets": 1}])
    with sqlite3.connect(f) as cx:
        assert cx.execute("PRAGMA auto_vacuum").fetchone()[0] == 2


class FauxDNS:
    def __init__(self, evts):
        self.evts = evts

    def evenements(self, clients, depuis, limite=20000):
        return [e for e in self.evts if e["client"] in clients and e["ts"] >= depuis]


def test_curseur_garde_60_s_de_marge_d_ingestion(tmp_path):
    evts = [{"ts": NOW - 50, "client": "192.168.1.50", "domaine": "pagead2.googlesyndication.com", "decision": "BLOCKED"}]
    etat = {"actif": True, "clients": [{"ip": "192.168.1.50", "nom": "TV", "mode": "auto", "mac": MAC}]}
    m = D.MagasinDPI(tmp_path / "d.db")
    dns = FauxDNS(evts)
    args = dict(voisins={}, sbxdpi_texte=None, conntrack_texte=None, resolus=set(), box=set(), doh=(set(), set()))
    D.passage(etat, dns, m, lambda d: "PUBLICITE" if "pagead" in d else "PUBLICITE", NOW, **args)
    evts.append({"ts": NOW - 47, "client": "192.168.1.50", "domaine": "metaproxy.francetvpub.fr", "decision": "ALLOWED"})  # arrivé en retard
    D.passage(etat, dns, m, lambda d: "PUBLICITE", NOW + 60, **args)
    assert [d["domaine"] for d in m.decouvertes()] == ["metaproxy.francetvpub.fr"]


def test_refus_d_arret_espaces(dossier):  # noqa: F811
    appels = []
    for k in range(0, 20):
        lancer(dossier, appels, charge=(9.0, 9.0, 9.0), now=NOW + 60 * k, cpu=ndpid_occupe, rc_arret=2)
    assert appels.count("ndpid-arreter") == 1                           # une tentative, puis 30 min de silence


def test_m5_fichier_nft_lien_retire_et_audite(nft):  # noqa: F811
    f = nft["tmp"] / "nftables.d" / "zz-secubox-adguard-contournement.nft"
    f.parent.mkdir(parents=True, exist_ok=True)
    autre = nft["tmp"] / "ailleurs.nft"
    autre.write_text("table inet x {}\n")
    f.symlink_to(autre)
    dnstv.ecrire_etat(etat_c(), nft["etat"])
    ctl(nft, "apply")
    assert not f.is_symlink() and autre.read_text() == "table inet x {}\n"
    assert "contournement-invalide" in (nft["tmp"] / "audit.log").read_text()


def test_resultat_publie_en_0640(nft):  # noqa: F811
    dnstv.ecrire_etat(etat_c(), nft["etat"])
    ctl(nft, "apply")
    assert (nft["etat"] / C.FICHIER_RESULTAT).stat().st_mode & 0o777 == 0o640
