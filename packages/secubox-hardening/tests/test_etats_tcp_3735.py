# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3735 : épuisement d'états TCP (fenêtre nulle, clôtures bloquées, STOMP, SYN porteurs de données)."""
import importlib.machinery
import importlib.util
import json
import re
from pathlib import Path

PAQUET = Path(__file__).resolve().parents[1]
SYSCTL = (PAQUET / "conf" / "99-secubox-hardening.conf").read_text()
NFT = (PAQUET / "nft" / "secubox-wan-guard.nft").read_text()

_chargeur = importlib.machinery.SourceFileLoader("tcp_etats", str(PAQUET / "sbin" / "secubox-tcp-etats"))
_spec = importlib.util.spec_from_loader("tcp_etats", _chargeur)
te = importlib.util.module_from_spec(_spec)
_chargeur.exec_module(te)


def _valeur(cle):
    m = re.search(rf"^-?{re.escape(cle)}\s*=\s*(\S+)", SYSCTL, re.M)
    return m and m.group(1)


# ── noyau ───────────────────────────────────────────────────────────────
def test_clotures_et_orphelins_bornes():
    assert int(_valeur("net.ipv4.tcp_fin_timeout")) <= 20
    assert int(_valeur("net.ipv4.tcp_orphan_retries")) in (1, 2, 3)    # 0 vaut 8 pour le noyau
    assert int(_valeur("net.ipv4.tcp_max_orphans")) <= 16384
    assert int(_valeur("net.ipv4.tcp_max_syn_backlog")) >= 2048


def test_conntrack_raccourci_et_tolerant_au_module_absent():
    for cle, maxi in (("net.netfilter.nf_conntrack_tcp_timeout_fin_wait", 30),
                      ("net.netfilter.nf_conntrack_tcp_timeout_close_wait", 30),
                      ("net.netfilter.nf_conntrack_tcp_timeout_last_ack", 30),
                      ("net.netfilter.nf_conntrack_tcp_timeout_established", 86400)):
        assert re.search(rf"^-{re.escape(cle)}\s*=", SYSCTL, re.M), cle      # « - » : ignoré si conntrack absent
        assert int(_valeur(cle)) <= maxi, cle


# ── pare-feu ────────────────────────────────────────────────────────────
def test_syn_porteurs_de_donnees_refuses_v4_et_v6():
    for iface in ("eth2", "br-lan"):
        assert re.search(rf'iifname "{iface}" tcp flags & \(syn \| ack\) == syn ip length > 80 counter drop', NFT), iface
        assert re.search(rf'iifname "{iface}" tcp flags & \(syn \| ack\) == syn ip6 length > 60 counter drop', NFT), iface


def test_plafond_de_connexions_par_adresse_publique():
    assert re.search(r"set connexions4 \{[^}]*type ipv4_addr[^}]*flags dynamic", NFT, re.S)
    assert re.search(r'iifname "eth2" tcp flags & \(syn \| ack\) == syn ip saddr != \{ 10\.0\.0\.0/8, 172\.16\.0\.0/12, '
                     r'192\.168\.0\.0/16, 100\.64\.0\.0/10, 127\.0\.0\.0/8 \} add @connexions4 \{ ip saddr ct count over (\d+) \} '
                     r'counter drop', NFT)
    n = int(re.search(r"ct count over (\d+)", NFT).group(1))
    assert 128 <= n <= 1024


# ── détecteur ───────────────────────────────────────────────────────────
SS = """State      Recv-Q Send-Q Local Address:Port  Peer Address:Port Process
ESTAB      0      0      192.168.1.200:443   203.0.113.9:51000
\t cubic wscale:7,7 rto:204 snd_wnd:0 rcv_space:14600
FIN-WAIT-2 0      0      192.168.1.200:443   203.0.113.9:51001
\t cubic rto:204 snd_wnd:64000
FIN-WAIT-1 0      1      192.168.1.200:443   203.0.113.9:51002
\t cubic rto:204 snd_wnd:0
CLOSE-WAIT 1      0      192.168.1.200:25    198.51.100.4:40000
\t cubic snd_wnd:64000
ESTAB      0      0      192.168.1.200:22    192.168.1.10:50000
\t cubic snd_wnd:0
ESTAB      0      0      [2a01:db8::1]:443   [2001:db8::7]:5000
\t cubic snd_wnd:0
"""


def test_lecture_de_ss_par_adresse_publique():
    r = te.par_adresse(SS)
    assert r["203.0.113.9"] == {"fenetre_nulle": 2, "cloture": 2, "total": 3}
    # CLOSE-WAIT : c'est NOTRE application qui n'a pas fermé, pas l'autre bout (un serveur IMAP distant serait banni)
    assert r["198.51.100.4"] == {"fenetre_nulle": 0, "cloture": 0, "total": 1}
    assert r["2001:db8::7"] == {"fenetre_nulle": 1, "cloture": 0, "total": 1}
    assert "192.168.1.10" not in r                      # LAN : jamais compté ni banni


def test_seuls_nos_ports_de_service_comptent():
    """Une connexion que gk2 OUVRE vers l'extérieur (port local éphémère) n'est jamais une preuve contre le distant."""
    r = te.par_adresse(SS, ports_serveur={25, 22})
    assert "203.0.113.9" not in r and "2001:db8::7" not in r and r["198.51.100.4"]["total"] == 1


def test_seuil_et_suspects():
    r = {"203.0.113.9": {"fenetre_nulle": 30, "cloture": 2, "total": 40},
         "198.51.100.4": {"fenetre_nulle": 0, "cloture": 25, "total": 26},
         "203.0.113.50": {"fenetre_nulle": 3, "cloture": 3, "total": 300}}
    s = te.suspects(r, seuil=20)
    assert [x["ip"] for x in s] == ["203.0.113.9", "198.51.100.4"]
    assert s[0]["motif"] == "fenetre_nulle" and s[1]["motif"] == "cloture"


def test_impact_lit_sockstat_et_conntrack(tmp_path):
    (tmp_path / "sockstat").write_text("sockets: used 1331\nTCP: inuse 154 orphan 3 tw 82 alloc 282 mem 372\n")
    (tmp_path / "count").write_text("1785\n")
    (tmp_path / "max").write_text("262144\n")
    i = te.impact(tmp_path / "sockstat", tmp_path / "count", tmp_path / "max")
    assert i == {"orphelins": 3, "tcp_memoire_pages": 372, "tcp_en_usage": 154,
                 "conntrack": 1785, "conntrack_max": 262144, "conntrack_pct": 0.7}


def test_tour_bannit_journalise_et_n_insiste_pas(tmp_path):
    bans, lignes = [], []
    etat = tmp_path / "etat.json"
    journal = tmp_path / "menaces.log"
    kw = dict(etat=etat, journal=journal, seuil=20, bannir=lambda ip: bans.append(ip) or (True, "ok"),
              impact_fn=lambda: {"orphelins": 0}, maintenant=1794700000)
    ss = "\n".join(["State Recv-Q Send-Q Local Peer"] +
                   [f"FIN-WAIT-2 0 0 192.168.1.200:443 203.0.113.9:{50000 + i}\n\t snd_wnd:0" for i in range(25)])
    te.tour(ss, **kw)
    te.tour(ss, **dict(kw, maintenant=1794700060))            # toujours là une minute plus tard : déjà banni
    assert bans == ["203.0.113.9"]
    e = json.loads(journal.read_text().splitlines()[0])
    assert e["category"] == "tcp_etats:fenetre_nulle" and e["client_ip"] == "203.0.113.9" and e["action"] == "banned"
    assert e["tool"] == "secubox-tcp-etats"
    r = json.loads(etat.read_text())
    assert r["suspects"][0]["ip"] == "203.0.113.9" and r["impact"] == {"orphelins": 0}


def test_unite_et_minuterie_livrees():
    rules = (PAQUET / "debian" / "rules").read_text()
    assert "secubox-tcp-etats" in rules
    unite = (PAQUET / "systemd" / "secubox-tcp-etats.service").read_text()
    assert "ExecStart=/usr/sbin/secubox-tcp-etats" in unite and "Type=oneshot" in unite
    assert "OnUnitActiveSec=1min" in (PAQUET / "systemd" / "secubox-tcp-etats.timer").read_text()
