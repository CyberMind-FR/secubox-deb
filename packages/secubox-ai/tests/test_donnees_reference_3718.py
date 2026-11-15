# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3718 : le jeu de référence de la veille V2 est assez riche ET ne laisse rien fuir de gk2."""
import collections
import ipaddress
import json
import re
from pathlib import Path

D = Path(__file__).resolve().parent / "donnees"
FICHIERS = ("menaces.jsonl", "bans.jsonl", "reevaluations.jsonl", "ai-ban.jsonl")
DOC4 = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
DOC6 = ipaddress.ip_network("2001:db8::/32")


def lignes(nom):
    return [json.loads(x) for x in (D / nom).read_text(encoding="utf-8").splitlines() if x.strip()]


def tout_le_texte():
    return "".join((D / n).read_text(encoding="utf-8") for n in FICHIERS + ("campagnes.json",))


def test_au_moins_200_evenements():
    n = sum(len(lignes(f)) for f in FICHIERS) + len(json.loads((D / "campagnes.json").read_text())["candidats"])
    assert n >= 200


def test_chaque_famille_vue_sur_gk2_est_presente():
    cats = collections.Counter(e["category"] for e in lignes("menaces.jsonl"))
    for f in ("host_anomaly:unrouted", "auth_smtp:sasl_failed", "recon_crawler", "scanners", "robots",
              "host_anomaly:ip_literal", "honeypot", "waf_fingerprint", "host_anomaly:dga", "body-inspect-skipped"):
        assert cats[f] >= 1, f
    assert any(e["client_ip"] == "local" for e in lignes("menaces.jsonl"))
    bans = [b["cat"] for b in lignes("bans.jsonl")]
    for prefixe in ("leurre:", "mesure:", "campagne:", "host_anomaly", "scanners", "honeypot"):
        assert any(c.startswith(prefixe) for c in bans), prefixe
    assert any("|prolonge" in c for c in bans)
    assert {r["decision"] for r in lignes("reevaluations.jsonl")} == {"RELEASE", "EXTEND"}
    assert {e["type"] for e in lignes("ai-ban.jsonl")} >= {"ban", "annule"}


def test_un_bloc_cas_sur_garde_sa_structure():
    """≥ 20 adresses distinctes bannies dans 203.0.113.0/24 : le cas sûr de #3716 se rejoue sur ce jeu."""
    ips = {b["ip"] for b in lignes("bans.jsonl") if b["ip"].startswith("203.0.113.")}
    assert len(ips) >= 20


def test_doublons_exacts_reels_conserves():
    cles = collections.Counter((e["timestamp"], e["client_ip"], e["category"], e["host"], e["path"])
                               for e in lignes("menaces.jsonl"))
    assert max(cles.values()) >= 3


def test_toute_adresse_est_de_documentation():
    for f in FICHIERS:
        for e in lignes(f):
            for k in ("client_ip", "ip", "cible"):
                v = e.get(k)
                if not v or v == "local":
                    continue
                a = ipaddress.ip_network(v, strict=False)
                assert (a.subnet_of(DOC6) if a.version == 6 else any(a.subnet_of(d) for d in DOC4)), (f, v)
    for v in re.findall(r"(?<![\w./:-])(\d{1,3}(?:\.\d{1,3}){3})(?![\w.])", tout_le_texte()):
        a = ipaddress.ip_address(v)
        assert not a.is_global or any(a in d for d in DOC4), v


def test_rien_du_proprietaire_ni_de_ses_box():
    t = tout_le_texte().lower()
    for mot in ("secubox.in", "cybermind", "gk0", "gk1", "gk2", "gk3", "gk6", "kerma", "freebox"):
        assert mot not in t, mot


def test_comptes_smtp_remplaces():
    for e in lignes("menaces.jsonl"):
        if e["category"].startswith("auth_smtp"):
            assert re.fullmatch(r"compte-\d+", e["path"]), e["path"]


def test_noms_des_services_du_proprietaire_remplaces():
    """Sous example.net, une étiquette est générique, `svc-N`, `boxN`, tirée au hasard, ou de forme gardée (`_`)."""
    ok = re.compile(r"(www|mail|smtp|imap|apt|autoconfig|autodiscover|openpgpkey|\*|admin|svc-\d+|box\d+"
                    r"|[a-z0-9]{12,}|[a-z0-9]+(_[a-z0-9]+)+)")
    for e in lignes("menaces.jsonl"):
        h = e["host"]
        if h.endswith(".example.net"):
            for etiquette in h[: -len(".example.net")].split("."):
                assert ok.fullmatch(etiquette), h
