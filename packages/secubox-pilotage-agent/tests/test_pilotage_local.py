# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3126 L2, tâche 4 : secubox-pilotage, commande locale du détenteur (root, texte en français).

Elle appelle le ctl et ne décide rien elle-même. Sous SBX_RACINE (tests, appelant non élevé par sudo), elle appelle le
ctl voisin (sbin/secubox-pilotagectl) avec le même banc que test_pilotagectl ; sinon, /usr/sbin/secubox-pilotagectl,
et seulement en root."""
import json
import os
import re
import subprocess
import time

import pytest

from test_pilotagectl import AGENT, DELAI, PKG, Banc

CMD = PKG / "sbin" / "secubox-pilotage"


@pytest.fixture
def banc(tmp_path):
    return Banc(tmp_path)


def local(banc, *args, env=None):
    e = dict(banc.env)
    e.update(env or {})
    p = subprocess.run([str(CMD), *args], env=e, capture_output=True, text=True, timeout=DELAI)
    return p.returncode, p.stdout, p.stderr


def test_refuse_sans_root(banc):
    sans = {k: v for k, v in banc.env.items() if k != "SBX_RACINE"}
    p = subprocess.run([str(CMD), "etat"], env=sans, capture_output=True, text=True, timeout=DELAI)
    if os.getuid() == 0:
        pytest.skip("lancé en root")
    assert p.returncode == 1 and p.stdout == ""
    assert "root" in p.stderr and "sudo secubox-pilotage" in p.stderr
    # SBX_RACINE n'ouvre rien quand sudo a élevé un autre compte
    rc, out, err = local(banc, "etat", env={"SUDO_UID": str(os.getuid() + 1)})
    assert rc == 1 and "root" in err


def test_usage(banc):
    for argv in ([], ["inconnu"], ["accepter"], ["mains-liees", "peut-etre"], ["support"], ["support", "ouvrir", "s1"],
                 ["accepter", "../x"], ["etat", "en-trop"]):
        rc, out, err = local(banc, *argv)
        assert rc == 2 and "usage" in err.lower(), (argv, rc, out, err)


def test_etat_affiche(banc):
    rc, out, err = local(banc, "etat")
    assert rc == 0, err
    assert "Mains liées" in out and ": non" in out
    assert "wg-mesh" in out and "box du propriétaire" in out
    assert "Support" in out and "aucun" in out
    assert "0 en attente" in out
    assert "arrêté" in out                                  # faux systemctl : l'agent est inactif
    banc.cliente()
    banc.run("reboot", agent=True)
    banc.run("support", "ouvrir", "s-01", "45", agent=True)
    rc, out, _ = local(banc, "etat")
    assert "wg-autoload" in out and "box cliente" in out
    assert "1 en attente" in out
    assert "s-01" in out and "attend votre accord" in out and "secubox-pilotage support accepter s-01" in out


def test_etat_sans_ancre(tmp_path):
    rc, out, _ = local(Banc(tmp_path, ancree=False), "etat")
    assert rc == 0 and "aucune ancre vérifiée" in out


def test_accepter_et_refuser_un_consentement(banc):
    banc.cliente()
    _, s, _ = banc.run("reboot", agent=True)
    ident = s["consentement"]
    rc, out, _ = local(banc, "consentements")
    assert rc == 0 and ident in out and "en attente" in out and "reboot" in out
    assert re.search(r"expire dans (23 h 5[0-9]|24 h 00) min", out), out          # 24 h, à la seconde près
    rc, out, err = local(banc, "accepter", ident, env={"SUDO_USER": "gerald"})
    assert rc == 0 and "accepté" in out, err
    rc, sortie, _ = banc.run("reboot", agent=True)
    assert sortie["ok"] is True                                     # l'accord est consommé par la demande suivante
    # (le reboot lancé est une opération exclusive : la demande suivante porte sur un service)
    argv = ("service", "redemarrer", "secubox-lyrion.service")
    _, s2, _ = banc.run(*argv, agent=True)
    rc, out, _ = local(banc, "refuser", s2["consentement"])
    assert rc == 0 and "refusé" in out
    _, sortie, _ = banc.run(*argv, agent=True)
    assert sortie["refus"] == "consentement requis" and sortie["consentement"] != s2["consentement"]
    # décisions auditées en local, avec le login de l'humain (sudo) comme acteur
    decisions = [e for e in banc.audit() if e["evenement"] == "consentement"]
    assert [(e["decision"], e["origine"]) for e in decisions] == [("accepte", "local"), ("refuse", "local")]
    assert decisions[0]["acteur"] == "gerald"
    # un refus du ctl est dit, code 1
    rc, out, err = local(banc, "accepter", ident)
    assert rc == 1 and "déjà décidé" in err


def test_expiration_a_24_h_affichee(banc):
    banc.cliente()
    _, s, _ = banc.run("reboot", agent=True)
    f = banc.r / "var/lib/secubox-pilotagectl/consentements.json"
    liste = json.loads(f.read_text())
    liste[0]["expire"] = int(time.time()) - 1
    f.write_text(json.dumps(liste))
    rc, out, _ = local(banc, "consentements")
    assert rc == 0 and s["consentement"] in out and "expiré" in out and "en attente" not in out
    rc, out, _ = local(banc, "etat")
    assert "0 en attente" in out
    rc, out, err = local(banc, "accepter", s["consentement"])
    assert rc == 1 and "expiré" in err
    assert [e["evenement"] for e in banc.audit()].count("consentement_expire") == 1


def test_bascule_des_mains_liees(banc):
    rc, out, _ = local(banc, "mains-liees", "on")
    assert rc == 0 and "posées" in out
    _, pol, _ = banc.run("politique", "reboot", agent=True)
    assert pol["raison"] == "mains liées"
    rc, out, _ = local(banc, "etat")
    assert "Mains liées" in out and ": oui" in out
    rc, out, _ = local(banc, "mains-liees", "off")
    assert rc == 0 and "levées" in out
    _, pol, _ = banc.run("politique", "reboot", agent=True)
    assert pol["autorise"] is True
    assert [e["etat"] for e in banc.audit() if e["evenement"] == "mains_liees"] == ["on", "off"]
    assert all(e["origine"] == "local" for e in banc.audit() if e["evenement"] == "mains_liees")


def test_support_accepte_puis_ferme_en_local(banc):
    banc.run("support", "ouvrir", "s-01", "45", agent=True)
    rc, out, _ = local(banc, "support", "accepter", "s-01")
    assert rc == 0 and "s-01" in out and "ouvert" in out and "45 min" in out
    rc, out, _ = local(banc, "etat")
    assert "ouvert" in out and "s-01" in out and "reste" in out
    # sans identifiant : la session en cours
    rc, out, _ = local(banc, "support", "fermer")
    assert rc == 0 and "s-01" in out and "fermé" in out
    rc, out, err = local(banc, "support", "fermer")
    assert rc == 1 and "aucun support" in err.lower()
    banc.run("support", "ouvrir", "s-02", agent=True)
    rc, out, _ = local(banc, "support", "refuser", "s-02")
    assert rc == 0 and "refusé" in out
    fermes = [e for e in banc.audit() if e["evenement"] == "support_ferme"]
    assert len(fermes) == 1 and fermes[0]["origine"] == "local"


def test_jamais_d_appel_sous_l_identite_de_l_agent(banc):
    """Un SUDO_USER égal au compte de l'agent ne devient ni acteur ni origine « maître »."""
    banc.cliente()
    _, s, _ = banc.run("reboot", agent=True)
    rc, out, err = local(banc, "accepter", s["consentement"], env={"SUDO_USER": AGENT})
    assert rc == 0, err
    decision = next(e for e in banc.audit() if e["evenement"] == "consentement")
    assert decision["origine"] == "local" and decision["acteur"] != AGENT
