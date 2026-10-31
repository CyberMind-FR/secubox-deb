# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3338 volet 4 — verbe `installer <paquet>` : la boutique du maître installe une app sur une box du parc.

Installation SEULEMENT (apt-get install --no-remove : jamais un paquet retiré au passage), paquet secubox-* présent
dans le dépôt de la box, opération longue exclusive, sans délai imposé à apt, accord du détenteur pour une box cliente
(lié à CE paquet), refus sous mains liées, audit."""
import pytest

from test_pilotagectl import Banc

FAUX_APT_CACHE = """#!/bin/sh
# faux apt-cache : « show <paquet> » réussit si le paquet est listé dans $FAUX_APT_DEPOT
[ "$1" = "show" ] || exit 2
for p in "$@"; do :; done
grep -qx "$p" "$FAUX_APT_DEPOT" 2>/dev/null
"""


@pytest.fixture
def banc(tmp_path):
    b = Banc(tmp_path)
    faux = tmp_path / "faux" / "apt-cache"
    faux.write_text(FAUX_APT_CACHE)
    faux.chmod(0o755)
    b.depot = tmp_path / "depot"
    b.depot.write_text("secubox-jellyfin\nsecubox-radio\n")
    b.env["FAUX_APT_DEPOT"] = str(b.depot)
    return b


@pytest.mark.parametrize("argv", [["installer"], ["installer", "nginx"], ["installer", "secubox-Jelly"],
                                  ["installer", "secubox-a;reboot"], ["installer", "secubox-" + "a" * 49],
                                  ["installer", "secubox-jellyfin", "en-trop"], ["installer", "--force"]])
def test_argv_invalide(banc, argv):
    rc, _, _ = banc.run(*argv, agent=True)
    assert rc == 2
    assert banc.lancements() == []


def test_installe_sans_retrait_ni_delai(banc):
    rc, s, _ = banc.run("installer", "secubox-jellyfin", agent=True)
    assert rc == 0 and s["ok"] is True, s
    (lance,) = banc.lancements()
    assert f"--unit=secubox-pilotage-op-{s['job']}" in lance
    assert "apt-get" in lance and " install " in lance and "--no-remove" in lance and lance.endswith("secubox-jellyfin")
    assert "remove " not in lance.replace("--no-remove", "") and "purge" not in lance and "autoremove" not in lance
    assert "RuntimeMaxSec" not in lance and "timeout" not in lance
    assert any(a.get("action") == "installer" and a.get("nom") == "secubox-jellyfin" for a in banc.audit())


def test_absent_du_depot_refuse(banc):
    rc, s, _ = banc.run("installer", "secubox-inconnu", agent=True)
    assert rc == 0 and s == {"ok": False, "refus": "paquet absent du dépôt"}
    assert banc.lancements() == []


def test_mains_liees_refuse(banc):
    banc.run("mains-liees", "on")
    rc, s, _ = banc.run("installer", "secubox-jellyfin", agent=True)
    assert s["ok"] is False and s["refus"] == "mains liées"
    assert banc.lancements() == []


def test_operation_longue_exclusive(banc):
    _, s1, _ = banc.run("maj-paquets", agent=True)
    rc, s, _ = banc.run("installer", "secubox-jellyfin", agent=True)
    assert s == {"ok": False, "refus": "opération en cours", "job": s1["job"]}


def test_box_cliente_accord_lie_au_paquet(banc):
    banc.cliente()
    _, s, _ = banc.run("installer", "secubox-jellyfin", agent=True)
    assert s["ok"] is False and s["refus"] == "consentement requis"
    ident = s["consentement"]
    banc.run("consentement", "accepter", ident)
    # l'accord donné pour jellyfin ne vaut pas pour radio
    _, s2, _ = banc.run("installer", "secubox-radio", agent=True)
    assert s2["refus"] == "consentement requis" and s2["consentement"] != ident
    _, s3, _ = banc.run("installer", "secubox-jellyfin", agent=True)
    assert s3["ok"] is True
    assert banc.lancements()[-1].endswith("secubox-jellyfin")


def test_formule_de_la_box_respectee(banc):
    """Volet 3 côté box : sous abonnement, seul un paquet du profil de la formule s'installe (même demandé par le
    maître) ; abonnement inactif ou illisible : rien."""
    import json
    prof = banc.r / "etc/secubox/profiles"
    prof.mkdir(parents=True, exist_ok=True)
    (prof / "lite.toml").write_text('name = "lite"\non = ["radio"]\n')
    ab = banc.r / "etc/secubox/abonnement.json"
    ab.write_text(json.dumps({"formule": "Léger", "profil": "lite", "statut": "actif"}))
    _, s, _ = banc.run("installer", "secubox-jellyfin", agent=True)
    assert s == {"ok": False, "refus": "hors de la formule de la box"}
    _, s, _ = banc.run("installer", "secubox-radio", agent=True)
    assert s["ok"] is True
    banc.actifs.write_text("")
    ab.write_text(json.dumps({"formule": "Léger", "profil": "lite", "statut": "suspendu"}))
    _, s, _ = banc.run("installer", "secubox-radio", agent=True)
    assert s == {"ok": False, "refus": "abonnement inactif"}
    ab.write_text("{illisible")
    _, s, _ = banc.run("installer", "secubox-radio", agent=True)
    assert s == {"ok": False, "refus": "abonnement illisible"}
