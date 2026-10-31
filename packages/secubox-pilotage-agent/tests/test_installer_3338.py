# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3338 volet 4 — verbe `installer <paquet>` : la boutique du maître installe une app sur une box du parc.

Installation SEULEMENT (apt-get install --no-remove --no-install-recommends, sans délai) d'une app PUBLIÉE de la
boutique (catalogue de l'appstore : catégorie grand public ou fiche, jamais système, socle, protégé, fonction, service,
pilotage, exposure, assist), dont la version candidate vient du dépôt SecuBox ; formule de l'abonnement de la box
(fail-closed, sauf marqueur abonnement-libre) ; opération longue exclusive ; accord du détenteur lié au paquet ;
refus sous mains liées ; audit."""
import json

import pytest

from test_pilotagectl import Banc

FAUX_APT_CACHE = """#!/bin/sh
# faux apt-cache policy : candidat + table des versions, origine prise dans $FAUX_APT_ORIGINE
[ "$1" = "policy" ] || exit 2
p="$2"
if grep -qx "$p" "$FAUX_APT_DEPOT" 2>/dev/null; then
  printf '%s:\\n  Installed: (none)\\n  Candidate: 1.0-1~trixie1\\n  Version table:\\n     1.0-1~trixie1 500\\n        500 %s trixie/main arm64 Packages\\n' "$p" "$FAUX_APT_ORIGINE"
  [ -z "$FAUX_APT_ORIGINE2" ] || printf '        500 %s trixie/main arm64 Packages\\n' "$FAUX_APT_ORIGINE2"
else
  printf '%s:\\n  Installed: (none)\\n  Candidate: (none)\\n' "$p"
fi
"""

CATALOGUE = {"modules": [{"name": "secubox-jellyfin", "category": "media"}, {"name": "secubox-radio", "category": "media"},
                         {"name": "secubox-hub", "category": "system"}, {"name": "secubox-gitea", "category": "misc"},
                         {"name": "secubox-assist", "category": "apps"}, {"name": "secubox-exposure", "category": "apps"},
                         {"name": "secubox-fonction-maitre", "category": "apps"}, {"name": "secubox-service-x", "category": "apps"},
                         {"name": "secubox-pilotage", "category": "apps"}, {"name": "secubox-vault", "category": "apps"},
                         {"name": "secubox-lyrion", "category": "apps"}]}
FICHES = {"secubox-gitea": {"nom": "Gitea"}, "secubox-cache": {"nom": "x", "cacher": True}}


@pytest.fixture
def banc(tmp_path):
    b = Banc(tmp_path)
    faux = tmp_path / "faux" / "apt-cache"
    faux.write_text(FAUX_APT_CACHE)
    faux.chmod(0o755)
    b.depot = tmp_path / "depot"
    b.depot.write_text("\n".join(m["name"] for m in CATALOGUE["modules"]) + "\n")
    b.env["FAUX_APT_DEPOT"] = str(b.depot)
    b.env["FAUX_APT_ORIGINE"] = "https://apt.secubox.in"
    cat = b.r / "usr/share/secubox/appstore/catalog.json"
    cat.parent.mkdir(parents=True, exist_ok=True)
    cat.write_text(json.dumps(CATALOGUE))
    fi = b.r / "usr/share/secubox/www/appstore/boutique-fiches.json"
    fi.parent.mkdir(parents=True, exist_ok=True)
    fi.write_text(json.dumps(FICHES))
    (b.r / "etc/secubox").mkdir(parents=True, exist_ok=True)
    (b.r / "etc/secubox/abonnement-libre").write_text("")
    (b.r / "etc/secubox/abonnement-libre").chmod(0o644)
    return b


@pytest.mark.parametrize("argv", [["installer"], ["installer", "nginx"], ["installer", "secubox-Jelly"],
                                  ["installer", "secubox-a;reboot"], ["installer", "secubox-" + "a" * 49],
                                  ["installer", "secubox-jellyfin", "en-trop"], ["installer", "--force"]])
def test_argv_invalide(banc, argv):
    rc, _, _ = banc.run(*argv, agent=True)
    assert rc == 2
    assert banc.lancements() == []


def test_installe_sans_retrait_ni_recommandes_ni_delai(banc):
    rc, s, _ = banc.run("installer", "secubox-jellyfin", agent=True)
    assert rc == 0 and s["ok"] is True, s
    (lance,) = banc.lancements()
    assert f"--unit=secubox-pilotage-op-{s['job']}" in lance
    assert "apt-get" in lance and " install " in lance and "--no-remove" in lance and "--no-install-recommends" in lance
    assert lance.endswith("secubox-jellyfin")
    assert "purge" not in lance and "autoremove" not in lance
    assert "RuntimeMaxSec" not in lance and "timeout" not in lance
    assert any(a.get("action") == "installer" and a.get("nom") == "secubox-jellyfin" for a in banc.audit())


@pytest.mark.parametrize("paquet,motif", [
    ("secubox-hub", "pas une app de la boutique"),                 # catégorie système
    ("secubox-inconnu", "pas une app de la boutique"),             # absent du catalogue
    ("secubox-cache", "pas une app de la boutique"),               # fiche « cacher »
    ("secubox-assist", "paquet réservé"),
    ("secubox-exposure", "paquet réservé"),
    ("secubox-fonction-maitre", "paquet réservé"),
    ("secubox-service-x", "paquet réservé"),
    ("secubox-pilotage", "paquet réservé"),
    ("secubox-vault", "paquet réservé"),                           # socle
    ("secubox-lyrion", "paquet réservé"),                          # protégé (modules.d)
])
def test_liste_blanche_des_apps_de_la_boutique(banc, paquet, motif):
    banc.module("lyrion", ["secubox-lyrion.service"], True)
    rc, s, _ = banc.run("installer", paquet, agent=True)
    assert s == {"ok": False, "refus": motif}, paquet
    assert banc.lancements() == []


def test_fiche_vaut_publication(banc):
    rc, s, _ = banc.run("installer", "secubox-gitea", agent=True)
    assert s["ok"] is True, s


def test_catalogue_absent_refuse(banc):
    (banc.r / "usr/share/secubox/appstore/catalog.json").unlink()
    _, s, _ = banc.run("installer", "secubox-jellyfin", agent=True)
    assert s == {"ok": False, "refus": "pas une app de la boutique"}


def test_absent_du_depot_refuse(banc):
    banc.depot.write_text("secubox-radio\n")
    _, s, _ = banc.run("installer", "secubox-jellyfin", agent=True)
    assert s == {"ok": False, "refus": "paquet absent du dépôt SecuBox"}
    assert banc.lancements() == []


@pytest.mark.parametrize("origine,ok", [("https://apt.secubox.in", True), ("file:/var/www/apt.secubox.in", True),
                                        ("file:/data/apt", True), ("file:/tmp/apt", False), ("file:/", False),
                                        ("http://deb.debian.org/debian", False), ("https://evil.example/apt.secubox.in.x", False)])
def test_origine_du_candidat(banc, origine, ok):
    banc.env["FAUX_APT_ORIGINE"] = origine
    _, s, _ = banc.run("installer", "secubox-jellyfin", agent=True)
    assert (s["ok"] is True) if ok else (s == {"ok": False, "refus": "paquet absent du dépôt SecuBox"}), (origine, s)


def test_mains_liees_refuse(banc):
    banc.run("mains-liees", "on")
    _, s, _ = banc.run("installer", "secubox-jellyfin", agent=True)
    assert s["ok"] is False and s["refus"] == "mains liées"
    assert banc.lancements() == []


def test_operation_longue_exclusive(banc):
    _, s1, _ = banc.run("maj-paquets", agent=True)
    _, s, _ = banc.run("installer", "secubox-jellyfin", agent=True)
    assert s == {"ok": False, "refus": "opération en cours", "job": s1["job"]}


def test_box_cliente_accord_lie_au_paquet(banc):
    banc.cliente()
    _, s, _ = banc.run("installer", "secubox-jellyfin", agent=True)
    assert s["ok"] is False and s["refus"] == "consentement requis"
    ident = s["consentement"]
    banc.run("consentement", "accepter", ident)
    _, s2, _ = banc.run("installer", "secubox-radio", agent=True)
    assert s2["refus"] == "consentement requis" and s2["consentement"] != ident
    _, s3, _ = banc.run("installer", "secubox-jellyfin", agent=True)
    assert s3["ok"] is True
    assert banc.lancements()[-1].endswith("secubox-jellyfin")


def test_toutes_les_origines_du_candidat_doivent_etre_secubox(banc):
    banc.env["FAUX_APT_ORIGINE2"] = "http://deb.debian.org/debian"
    _, s, _ = banc.run("installer", "secubox-jellyfin", agent=True)
    assert s == {"ok": False, "refus": "paquet absent du dépôt SecuBox"}
    banc.env["FAUX_APT_ORIGINE2"] = "file:/data/apt"
    _, s, _ = banc.run("installer", "secubox-jellyfin", agent=True)
    assert s["ok"] is True, s


def _sans_libre(banc):
    (banc.r / "etc/secubox/abonnement-libre").unlink()


def test_libre_maitre_du_parc(banc):
    _sans_libre(banc)
    (banc.r / "var/lib/dpkg/info").mkdir(parents=True, exist_ok=True)
    (banc.r / "var/lib/dpkg/info/secubox-fonction-maitre.list").write_text("")
    _, s, _ = banc.run("installer", "secubox-jellyfin", agent=True)
    assert s["ok"] is True, s


def test_libre_box_du_proprietaire(banc):
    import time
    _sans_libre(banc)
    d = banc.r / "etc/secubox-pilotage"
    d.mkdir(parents=True, exist_ok=True)
    f = d / "proprietaire"
    f.write_text(f"{int(time.time()) - 5}\n")
    f.chmod(0o644)
    _, s, _ = banc.run("installer", "secubox-jellyfin", agent=True)
    assert s == {"ok": False, "refus": "aucun abonnement sur cette box"}     # échu : pas un signal
    f.write_text(f"{int(time.time()) + 3600}\n")
    _, s, _ = banc.run("installer", "secubox-jellyfin", agent=True)
    assert s["ok"] is True, s


def test_formule_de_la_box_fail_closed(banc):
    """Box cliente, demandes locales (sans accord du détenteur à recueillir).
    Sous abonnement, seul un paquet du profil (nom de fichier) de la formule s'installe ; sans abonnement ni marqueur
    abonnement-libre : rien ; abonnement inactif ou illisible : rien."""
    (banc.r / "etc/secubox/abonnement-libre").unlink()
    banc.cliente()                       # box cliente (canal wg-autoload) : jamais le drapeau « proprietaire »
    banc.run("etat", agent=True)         # reprojection : le drapeau de la box du propriétaire tombe
    assert not (banc.r / "etc/secubox-pilotage/proprietaire").exists()
    _, s, _ = banc.run("installer", "secubox-radio")
    assert s == {"ok": False, "refus": "aucun abonnement sur cette box"}
    prof = banc.r / "etc/secubox/profiles"
    prof.mkdir(parents=True, exist_ok=True)
    (prof / "lite.toml").write_text('name = "autre-nom"\non = ["radio"]\n')
    ab = banc.r / "etc/secubox/abonnement.json"
    ab.write_text(json.dumps({"formule": "Léger", "profil": "lite", "statut": "actif"}))
    _, s, _ = banc.run("installer", "secubox-jellyfin")
    assert s == {"ok": False, "refus": "hors de la formule de la box"}
    _, s, _ = banc.run("installer", "secubox-radio")
    assert s["ok"] is True
    banc.actifs.write_text("")
    ab.write_text(json.dumps({"formule": "Léger", "profil": "lite", "statut": "suspendu"}))
    _, s, _ = banc.run("installer", "secubox-radio")
    assert s == {"ok": False, "refus": "abonnement inactif"}
    ab.write_text("{illisible")
    _, s, _ = banc.run("installer", "secubox-radio")
    assert s == {"ok": False, "refus": "abonnement illisible"}
