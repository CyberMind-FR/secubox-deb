# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#2417 — le comportement affiché pour chaque zone est celui des règles nftables, et rien de plus."""
import pathlib
import re

from api import zones_info

RACINE = pathlib.Path(__file__).resolve().parents[1]
NFT = (RACINE / "nft" / "secubox-nac.nft").read_text(encoding="utf-8")
PRIVES = "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16"


def _regles(ensemble):
    return [l.strip() for l in NFT.splitlines() if f"@{ensemble}" in l and not l.strip().startswith("#")]


def test_quarantaine_ne_laisse_passer_que_dns_et_dhcp_vers_la_box():
    r = _regles("quarantine_zone")
    assert any("udp dport { 53, 67, 68 } return" in l for l in r)
    assert any("drop" in l and "quarantaine" in l for l in r)
    z = zones_info.ZONES_COMPORTEMENT["quarantine"]
    assert (z["internet"], z["lan"], z["box_dns_dhcp"]) == ("non", "non", "partiel")


def test_iot_et_invites_sont_isoles_du_lan_prive_mais_ont_internet():
    for nom in ("iot", "guest"):
        r = _regles(f"{nom}_zone")
        assert any(f"ip daddr {{ {PRIVES} }}" in l and "drop" in l for l in r), nom
        z = zones_info.ZONES_COMPORTEMENT[nom]
        assert (z["internet"], z["lan"]) == ("oui", "non")


def test_bloque_est_refuse_dans_les_deux_sens():
    r = _regles("blocked")
    assert sum("drop" in l for l in r) >= 3                   # entrée box, sortie, entrée en transit
    assert zones_info.ZONES_COMPORTEMENT["blocked"]["isolement"] == "total"


def test_lan_et_lxc_n_ont_aucune_regle_de_restriction():
    for nom in ("lan_allowed", "lxc_zone"):
        assert not any("drop" in l for l in _regles(nom)), nom
    assert zones_info.ZONES_COMPORTEMENT["lan"]["isolement"] == "aucun"


def test_les_zones_du_nac_sont_toutes_decrites():
    from api import main
    assert set(main.ZONES) | {"blocked"} == set(zones_info.ZONES_COMPORTEMENT)


def test_options_inexistantes_annoncees_indisponibles_et_absentes_des_regles():
    noms = " ".join(o["nom"] for o in zones_info.INDISPONIBLE).lower()
    assert "dns hole" in noms and "parking" in noms and "repli" in noms
    assert not re.search(r"\b(dnat|redirect|tproxy)\b", NFT)      # rien ne détourne le trafic : la liste dit vrai
    assert any("Toolbox" in h["ou"] for h in zones_info.HORS_ZONE)  # Tor et VPN : par client, pas par zone
