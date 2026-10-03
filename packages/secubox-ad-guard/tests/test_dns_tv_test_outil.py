# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""tools/dns-tv-test.py : l'outil de test côté CLIENT, contre de faux serveurs DNS locaux (aucun accès Internet)."""
import importlib.util
import json
import socket
import struct
import threading
from pathlib import Path

import pytest

OUTIL = Path(__file__).resolve().parents[1] / "tools" / "dns-tv-test.py"
spec = importlib.util.spec_from_file_location("dns_tv_test", OUTIL)
t = importlib.util.module_from_spec(spec)
spec.loader.exec_module(t)


class FauxDNS:
    """Serveur UDP : `table` nom -> (rcode, [adresses]) ; un nom absent de la table = pas de réponse (délai dépassé)."""

    def __init__(self, table):
        self.table = table
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.sock.settimeout(0.2)
        self.stop = False
        self.th = threading.Thread(target=self._boucle, daemon=True)
        self.th.start()

    def _boucle(self):
        while not self.stop:
            try:
                q, src = self.sock.recvfrom(512)
            except OSError:
                continue
            i, nom = 12, []
            while q[i]:
                nom.append(q[i + 1:i + 1 + q[i]].decode())
                i += 1 + q[i]
            nom = ".".join(nom)
            if nom not in self.table:
                continue
            rcode, adr = self.table[nom]
            quest = q[12:i + 5]
            rep = struct.pack("!HHHHHH", struct.unpack("!H", q[:2])[0], 0x8180 | rcode, 1, len(adr), 0, 0) + quest
            for a in adr:
                rep += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(a)
            self.sock.sendto(rep, src)

    @property
    def adresse(self):
        return f"127.0.0.1#{self.port}"

    def fin(self):
        self.stop = True
        self.th.join(1)
        self.sock.close()


@pytest.fixture
def serveurs():
    box = FauxDNS({"ads.example": (3, []), "ok.example": (0, ["93.184.216.34"]), "puits.example": (0, ["0.0.0.0"]),
                   "absent.example": (3, []), "panne.example": (2, [])})
    ref = FauxDNS({"ads.example": (0, ["7.7.7.7"]), "ok.example": (0, ["93.184.216.34"]), "puits.example": (0, ["8.8.4.4"]),
                   "absent.example": (3, [])})
    yield box, ref
    box.fin()
    ref.fin()


def test_requete_et_reponse_dns_sur_le_fil():
    q = t.construire("www.example.com", "A", 4242)
    assert q[:2] == struct.pack("!H", 4242) and q.endswith(b"\x00\x00\x01\x00\x01")
    with pytest.raises(ValueError):
        t.analyser(b"\x00" * 5, 1)
    with pytest.raises(ValueError):
        t.analyser(struct.pack("!HHHHHH", 9, 0x8180, 0, 0, 0, 0), 1)                  # mauvais identifiant : réponse d'un autre


def test_autorise_bloque_nxdomain_non_tranche_et_erreur(serveurs, capsys):
    box, ref = serveurs
    st = {n: t.statut(t.interroger(box.adresse, n, delai=0.5), t.interroger(ref.adresse, n, delai=0.5)) for n in
          ("ok.example", "ads.example", "puits.example", "absent.example", "panne.example")}
    assert st == {"ok.example": "ALLOWED", "ads.example": "BLOCKED", "puits.example": "BLOCKED",
                  "absent.example": "NXDOMAIN", "panne.example": "ERROR"}               # absent : NXDOMAIN aussi chez la référence


def test_sans_reference_un_nxdomain_n_est_pas_affirme_comme_blocage(serveurs):
    box, _ = serveurs
    assert t.statut(t.interroger(box.adresse, "ads.example", delai=0.5), None) == "NXDOMAIN"


def test_delai_depasse_est_une_erreur_pas_un_blocage(serveurs):
    box, _ = serveurs
    r = t.interroger(box.adresse, "muet.example", delai=0.3)
    assert r["rcode"] == "ERROR" and t.statut(r, None) == "ERROR"


def test_rapport_json_et_liste(serveurs, tmp_path):
    box, ref = serveurs
    liste = tmp_path / "d.txt"
    liste.write_text("# commentaire\nok.example\nads.example # pub\n\n")
    rap = tmp_path / "reports" / "dns-test.json"
    code = t.main(["--serveur", box.adresse, "--reference", ref.adresse, "--list", str(liste), "--rapport", str(rap), "--delai", "0.5"])
    d = json.loads(rap.read_text())
    assert code == 0 and d["serveur"] == box.adresse and d["resume"] == {"ALLOWED": 1, "BLOCKED": 1, "NXDOMAIN": 0, "ERROR": 0}
    assert [r["domaine"] for r in d["resultats"]] == ["ok.example", "ads.example"] and "avertissement" in d
    assert all(r["ms"] >= 0 for r in d["resultats"])


def test_aucun_domaine_est_une_erreur_d_usage():
    with pytest.raises(SystemExit):
        t.main(["--serveur", "127.0.0.1"])


# ── tools/tv-before-after.py : le calcul de phase (pur, sans réseau) ─────────────────────────────────────────────────
def _avant_apres():
    spec2 = importlib.util.spec_from_file_location("tv_ba", OUTIL.parent / "tv-before-after.py")
    m = importlib.util.module_from_spec(spec2)
    spec2.loader.exec_module(m)
    return m


def test_la_phase_est_la_difference_de_deux_releves_pas_un_total():
    m = _avant_apres()
    avant = m.releve_vers_dict([{"domaine": "ads.example", "categorie": "advertising", "decision": "ALLOWED", "hits": 10}])
    apres = m.releve_vers_dict([{"domaine": "ads.example", "categorie": "advertising", "decision": "ALLOWED", "hits": 14},
                                {"domaine": "ads.example", "categorie": "advertising", "decision": "BLOCKED", "hits": 3},
                                {"domaine": "ok.example", "categorie": "", "decision": "ALLOWED", "hits": 5}])
    d = m.difference(avant, apres)
    assert {(x["domaine"], x["decision"]): x["hits"] for x in d} == {("ads.example", "ALLOWED"): 4, ("ads.example", "BLOCKED"): 3, ("ok.example", "ALLOWED"): 5}
    r = m.resumer(d)
    assert r["requetes"] == 12 and r["bloques"] == 3 and r["domaines_advertising"] == 1 and r["resolus_advertising"] == 4


def test_le_rapport_ne_prete_aucun_chiffre_a_la_phase_non_mesurable_ni_sans_mesure():
    m = _avant_apres()
    assert "POC non validé sur flux Freebox réel" in m.rapport_markdown({"phases": {}})
    md = m.rapport_markdown({"phases": {"A": {"ip": "192.168.1.50", "mode": "DNS habituel", "note": "tout marche", "duree_s": 300}}})
    assert "non mesurable côté box" in md and "tout marche" in md
    assert "réduction des domaines publicitaires/tracking résolus par DNS" in md


def test_apprentissage_differentiel_propose_ce_qui_n_apparait_qu_avec_les_pubs():
    m = _avant_apres()
    essentiel = [{"domaine": "video.cdn.example", "categorie": "", "decision": "ALLOWED", "hits": 40},
                 {"domaine": "api.chaine.example", "categorie": "", "decision": "ALLOWED", "hits": 5}]
    pubs = essentiel + [{"domaine": "ads.reseau-pub.example", "categorie": "advertising", "decision": "ALLOWED", "hits": 9},
                        {"domaine": "cmp.consent.example", "categorie": "", "decision": "ALLOWED", "hits": 3},
                        {"domaine": "ads.reseau-pub.example", "categorie": "advertising", "decision": "ALLOWED", "hits": 2}]
    c = m.candidats(essentiel, pubs, {"cmp.consent.example": "custom"})
    assert [x["domaine"] for x in c] == ["ads.reseau-pub.example", "cmp.consent.example"]
    assert c[0]["hits"] == 11 and c[0]["connu_des_listes"] == "advertising" and c[1]["connu_des_listes"] == "custom"
    assert all(x["domaine"] not in ("video.cdn.example", "api.chaine.example") for x in c)         # le flux par défaut n'est JAMAIS proposé


def test_apprentissage_publicite_sur_le_meme_domaine_que_la_video_ne_donne_rien():
    """Cas C : la limite du DNS reste visible — aucun candidat n'est inventé."""
    m = _avant_apres()
    meme = [{"domaine": "video.studio.example", "categorie": "", "decision": "ALLOWED", "hits": 50}]
    assert m.candidats(meme, meme + [{"domaine": "video.studio.example", "categorie": "", "decision": "ALLOWED", "hits": 20}]) == []


def test_les_phases_e_et_p_sont_en_observe_jamais_en_block():
    m = _avant_apres()
    assert m.MODES["E"] == "observe" and m.MODES["P"] == "observe"


def test_les_compteurs_de_plusieurs_adresses_du_meme_appareil_s_additionnent():
    m = _avant_apres()
    v4 = [{"domaine": "cloudreplay.example", "categorie": "", "decision": "ALLOWED", "hits": 3}]
    v6 = [{"domaine": "cloudreplay.example", "categorie": "", "decision": "ALLOWED", "hits": 5},
          {"domaine": "track.example", "categorie": "tracking", "decision": "BLOCKED", "hits": 2}]
    assert m.releve_vers_dict(v4 + v6) == {("cloudreplay.example", "ALLOWED"): ("", 8), ("track.example", "BLOCKED"): ("tracking", 2)}


def test_le_mode_local_pose_son_chemin_avant_d_importer_la_bibliotheque():
    """Régression du premier usage sur gk2 : `from api import dnstv` ne doit jamais précéder l'ajout du chemin."""
    src = (OUTIL.parent / "tv-before-after.py").read_text()
    debut = src[src.index("def main("):]
    assert debut.index("chemin_local()") < debut.index("from api import dnstv")
