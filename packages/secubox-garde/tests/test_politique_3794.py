# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3794 — politique de décision de secubox-garde (pure, sans E/S)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "common"))

from garde.politique import Decision, Signal, decider  # noqa: E402

T = 1_000_000
MAC = "aa:bb:cc:dd:ee:01"
REGL = {"automatique": True, "quarantaines_max": 3}


def sig(type_, ip="192.168.1.20", mac=MAC, ts=T - 10, regle="r"):
    return Signal("test", type_, ip, mac, "ex.test", regle, ts)


def run(signaux, actives=(), liberations=None, recidives=None, protegees=None, reglages=None):
    return decider(list(signaux), list(actives), liberations or {}, recidives or {},
                   protegees or (lambda ip: False), reglages or REGL, T)


def test_malicious_seul_isole():
    dec, al = run([sig("malicious")])
    assert len(dec) == 1 and dec[0].menace == "infection" and dec[0].signe == "malicious"
    assert dec[0].cible == MAC and dec[0].fin == T + 86400


def test_dga_seul_signale_sans_action():
    dec, _ = run([sig("dga")])
    assert len(dec) == 1 and dec[0].menace == "signale" and dec[0].fin == dec[0].debut
    dec, _ = run([sig("high_rate")])
    assert dec[0].menace == "signale"


def test_deux_familles_en_une_heure():
    dec, _ = run([sig("dga", ts=T - 1800), sig("exfiltration", ts=T - 100)])
    assert len(dec) == 1 and dec[0].menace == "infection"
    assert dec[0].signe == "dga+exfiltration"


def test_deux_familles_espacees_de_deux_heures_signale():
    dec, _ = run([sig("dga", ts=T - 7300), sig("exfiltration", ts=T - 100)])
    assert dec and all(d.menace == "signale" for d in dec)


def test_ban_duree_croissante_et_plafond():
    ip = "8.8.4.4"
    for n, attendu in ((0, 14400), (2, 230400), (9, 2592000)):
        dec, _ = run([sig("intrusion", ip=ip, mac=None)], recidives={ip: n})
        assert len(dec) == 1 and dec[0].menace == "intrusion"
        assert dec[0].fin - dec[0].debut == attendu


def test_jamais_adresse_privee_ni_maillage():
    for ip in ("192.168.1.5", "10.100.0.3", "fd00::1", "127.0.0.1", "169.254.1.1", "224.0.0.1"):
        dec, _ = run([sig("intrusion", ip=ip, mac=None)])
        assert dec == [], ip
    dec, _ = run([sig("intrusion", ip="8.8.4.4", mac=None)], protegees=lambda ip: True)
    assert dec == []


def test_liberee_pas_de_nouvelle_quarantaine_7j():
    lib = {(MAC, "malicious"): T + 5 * 86400}
    dec, _ = run([sig("malicious")], liberations=lib)
    assert dec == []
    lib = {(MAC, "malicious"): T - 1}
    dec, _ = run([sig("malicious")], liberations=lib)
    assert len(dec) == 1


def test_deja_active_pas_de_doublon():
    act = Decision("infection", MAC, MAC, "192.168.1.20", "m", "malicious", T - 100, T + 1000)
    dec, _ = run([sig("malicious")], actives=[act])
    assert dec == []


def test_plafond_quarantaines():
    act = [Decision("infection", f"aa:00:00:00:00:0{i}", f"aa:00:00:00:00:0{i}", "192.168.1.9",
                    "m", "malicious", T - 100, T + 1000) for i in range(3)]
    dec, al = run([sig("malicious")], actives=act)
    assert dec == [] and len(al) == 1 and "masse anormal" in al[0]


def test_mode_alerte_seule():
    dec, _ = run([sig("malicious"), sig("intrusion", ip="8.8.4.4", mac=None)],
                 reglages={"automatique": False})
    assert len(dec) == 2 and all(d.menace == "signale" and d.fin == d.debut for d in dec)
    assert {"infection", "intrusion"} <= {d.motif.split(":")[0].strip() for d in dec}


def test_tunnel_est_evasion_pas_infection():
    for t in ("tunneling", "doh"):
        dec, _ = run([sig(t)])
        assert len(dec) == 1 and dec[0].menace == "evasion" and dec[0].signe == t
        assert dec[0].fin == T + 86400


def test_infection_jamais_ip_publique():
    dec, _ = run([sig("malicious", ip="8.8.4.4")])
    assert dec == []
    dec, _ = run([sig("tunneling", ip="8.8.4.4", mac=None)])
    assert dec == []


def test_infection_jamais_maillage():
    dec, _ = run([sig("malicious", ip="10.100.0.7", mac=None)])
    assert dec == []


def test_liberation_bloque_les_familles_qui_se_recoupent():
    lib = {(MAC, "malicious"): T + 86400}
    dec, _ = run([sig("dga", ts=T - 50), sig("malicious", ts=T - 40)], liberations=lib)
    assert dec == []
    lib = {(MAC, "dga+exfiltration"): T + 86400}
    dec, _ = run([sig("exfiltration", ts=T - 50), sig("malicious", ts=T - 40)], liberations=lib)
    assert dec == []


def test_liberation_ne_bloque_pas_une_famille_differente():
    lib = {(MAC, "dga+exfiltration"): T + 86400}
    dec, _ = run([sig("malicious")], liberations=lib)
    assert len(dec) == 1 and dec[0].menace == "infection"


def test_toute_ip_vue_est_controlee():
    dec, _ = run([sig("malicious", ip="192.168.1.20"), sig("dga", ip="192.168.1.21")],
                 protegees=lambda ip: ip == "192.168.1.21")
    assert dec == []


def test_exfiltration_seule_signalee():
    dec, _ = run([sig("exfiltration")])
    assert len(dec) == 1 and dec[0].menace == "signale" and dec[0].signe == "exfiltration"


PREF = {"automatique": True, "quarantaines_max": 3, "lan_prefixes": ["2a01:e0a:dec:c4e0::/64"]}


def test_ipv6_globale_du_lan_reconnue():
    dec, _ = run([sig("malicious", ip="2a01:e0a:dec:c4e0::95")], reglages=PREF)
    assert len(dec) == 1 and dec[0].menace == "infection"
    dec, _ = run([sig("malicious", ip="2a01:e0a:dec:c4e0::95")])
    assert dec == []


def test_ipv6_hors_prefixe_ignoree_sans_ecarter_lipv4():
    dec, _ = run([sig("malicious"), sig("malicious", ip="2001:4860::1")], reglages=PREF)
    assert len(dec) == 1 and dec[0].menace == "infection" and dec[0].ip == "192.168.1.20"


def test_prefixe_invalide_ignore():
    reg = dict(PREF, lan_prefixes=["pas-un-cidr", "2a01:e0a:dec:c4e0::/64"])
    dec, _ = run([sig("malicious", ip="2a01:e0a:dec:c4e0::95")], reglages=reg)
    assert len(dec) == 1
    dec, _ = run([sig("malicious")], reglages=dict(PREF, lan_prefixes=["zzz"]))
    assert len(dec) == 1


def test_detournement_seul_signale_jamais_infection():
    dec, _ = run([sig("detournement")])
    assert [d.menace for d in dec] == ["signale"] and dec[0].signe == "detournement"


def test_inconnu_seul_signale():
    dec, _ = run([sig("inconnu")])
    assert [d.menace for d in dec] == ["signale"]


def test_detournement_plus_dga_infection():
    dec, _ = run([sig("detournement", ts=T - 50), sig("dga", ts=T - 40)])
    assert len(dec) == 1 and dec[0].menace == "infection" and dec[0].signe == "detournement+dga"
