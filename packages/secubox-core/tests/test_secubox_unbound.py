# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""secubox_unbound (D4, #2050) : l'UNIQUE endroit qui écrit une vue Unbound, la valide, la recharge et revient en arrière.

Auparavant, webfilter-ctl et dns-lan en avaient chacun une copie (commande, écriture atomique, checkconf, reload, audit). Bibliothèque en stdlib
seulement, sans effet de bord à l'import : elle est chargée par des assistants root sous AppArmor, qui ne doivent pas tirer FastAPI ni la config."""
import json
import os
import stat
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "common"))
import secubox_unbound as U  # noqa: E402


class Faux(U.SystemeUnbound):
    MODULE = "test"

    def __init__(self, verif=(True, ""), recharge_ok=True):
        self.verif, self.recharge_ok, self.appels, self.lignes = verif, recharge_ok, [], []

    def verifier_unbound(self):
        self.appels.append("verifier")
        return self.verif

    def recharger_unbound(self):
        self.appels.append("recharger")
        if not self.recharge_ok:
            raise self.ERREUR("reload a échoué")

    def audit(self, action, detail=""):
        self.lignes.append((action, detail))


def test_ecriture_atomique_pose_le_contenu_et_le_mode(tmp_path):
    f = tmp_path / "a.conf"
    U.ecrire_atomique(f, "x\n", 0o640)
    assert f.read_text() == "x\n" and stat.S_IMODE(f.stat().st_mode) == 0o640
    assert not [p for p in tmp_path.iterdir() if p.name.startswith(".")], "aucun fichier temporaire ne reste"


def test_ecriture_atomique_n_ecrase_pas_si_l_ecriture_echoue(tmp_path, monkeypatch):
    f = tmp_path / "a.conf"
    f.write_text("ancien")
    monkeypatch.setattr(os, "replace", lambda *a, **k: (_ for _ in ()).throw(OSError("disque plein")))
    with pytest.raises(OSError):
        U.ecrire_atomique(f, "nouveau")
    assert f.read_text() == "ancien" and not [p for p in tmp_path.iterdir() if p.name.startswith(".")]


def test_commande_rend_ok_et_la_fin_de_la_sortie(tmp_path):
    assert U.commande(["/bin/echo", "salut"], 5) == (True, "salut")
    ok, sortie = U.commande(["/bin/sh", "-c", "echo erreur >&2; exit 3"], 5)
    assert ok is False and "erreur" in sortie
    ok, sortie = U.commande(["/nexiste/pas"], 5)
    assert ok is False and "pas" in sortie
    ok, sortie = U.commande(["/bin/sleep", "5"], 1)
    assert ok is False and "délai" in sortie


def test_poser_vue_identique_ne_recharge_rien(tmp_path):
    f, s = tmp_path / "v.conf", Faux()
    f.write_text("a\n")
    assert U.poser_vue(f, "a\n", s) == "inchange" and s.appels == []


def test_poser_vue_nouvelle_verifie_puis_recharge(tmp_path):
    f, s = tmp_path / "v.conf", Faux()
    assert U.poser_vue(f, "a\n", s) == "applique"
    assert f.read_text() == "a\n" and s.appels == ["verifier", "recharger"]


def test_une_verification_refusee_restaure_octet_pour_octet(tmp_path):
    f, s = tmp_path / "v.conf", Faux(verif=(False, "syntax error"))
    f.write_bytes(b"ancien\n")
    with pytest.raises(U.ErreurUnbound, match="syntax error"):
        U.poser_vue(f, "nouveau\n", s)
    assert f.read_bytes() == b"ancien\n" and s.appels == ["verifier"], "pas de reload sur une config refusée"


def test_un_reload_qui_echoue_restaure_et_recharge_l_ancienne(tmp_path):
    f, s = tmp_path / "v.conf", Faux(recharge_ok=False)
    f.write_text("ancien\n")
    with pytest.raises(U.ErreurUnbound):
        U.poser_vue(f, "nouveau\n", s)
    assert f.read_text() == "ancien\n"
    assert s.appels == ["verifier", "recharger", "recharger"], "l'ancienne vue est rechargée, sinon Unbound garde la nouvelle en mémoire"


def test_un_premier_fichier_refuse_est_supprime(tmp_path):
    f, s = tmp_path / "v.conf", Faux(verif=(False, "non"))
    with pytest.raises(U.ErreurUnbound):
        U.poser_vue(f, "x\n", s)
    assert not f.exists()


def test_la_classe_d_erreur_est_remplacable_pour_les_appelants_existants(tmp_path):
    class MonErreur(RuntimeError):
        pass

    class Mien(Faux):
        ERREUR = MonErreur

    f, s = tmp_path / "v.conf", Mien(verif=(False, "non"))
    with pytest.raises(MonErreur):
        U.poser_vue(f, "x\n", s)


def test_audit_reel_ecrit_une_ligne_json_en_ajout(tmp_path):
    journal = tmp_path / "audit.log"

    class Reel(U.SystemeUnbound):
        MODULE = "webfilter-ctl"
        AUDIT = journal

    Reel().audit("applique", "3 zones")
    Reel().audit("restaure", "x" * 500)
    lignes = [json.loads(l) for l in journal.read_text().splitlines()]
    assert lignes[0]["module"] == "webfilter-ctl" and lignes[0]["action"] == "applique" and lignes[0]["detail"] == "3 zones"
    assert len(lignes[1]["detail"]) == 300


def test_audit_qui_echoue_ne_bloque_pas_l_operation(tmp_path, capsys):
    class Reel(U.SystemeUnbound):
        MODULE = "m"
        AUDIT = tmp_path / "absent" / "audit.log"

    Reel().audit("a")
    assert "audit non écrit" in capsys.readouterr().err


def test_l_import_n_a_aucun_effet_de_bord_et_reste_en_stdlib():
    src = (Path(U.__file__)).read_text()
    for interdit in ("fastapi", "secubox_core", "requests", "httpx"):
        assert f"import {interdit}" not in src and f"from {interdit}" not in src


def test_seule_la_sous_classe_redemarrable_sait_redemarrer():
    assert not hasattr(U.SystemeUnbound, "redemarrer_unbound"), "un assistant de listes ne redémarre jamais Unbound"
    assert hasattr(U.SystemeUnboundRedemarrable, "redemarrer_unbound")
    assert issubclass(U.SystemeUnboundRedemarrable, U.SystemeUnbound)


def test_ecriture_atomique_refuse_un_lien_symbolique(tmp_path):
    cible = tmp_path / "cible"
    cible.write_text("intact")
    lien = tmp_path / "vue.conf"
    lien.symlink_to(cible)
    with pytest.raises(U.ErreurUnbound, match="lien symbolique"):
        U.ecrire_atomique(lien, "x")
    assert cible.read_text() == "intact", "on n'écrit jamais à travers un lien posé par un autre"


def test_ecriture_atomique_peut_lever_la_classe_d_erreur_de_l_appelant(tmp_path):
    class Mienne(RuntimeError):
        pass

    lien = tmp_path / "v"
    lien.symlink_to(tmp_path / "x")
    with pytest.raises(Mienne):
        U.ecrire_atomique(lien, "x", erreur=Mienne)


def test_fsync_dossier_ne_leve_pas(tmp_path):
    U.fsync_dossier(tmp_path)
    U.fsync_dossier(tmp_path / "absent")


def test_le_paquet_core_installe_la_bibliotheque():
    rules = (Path(__file__).resolve().parents[1] / "debian" / "rules").read_text()
    assert "common/secubox_unbound" in rules


# ── ecrire_verifier (écrit + vérifie, SANS recharger) et retirer_vue : les gestes dont ad-guard a besoin ────────────────────────────────
def test_ecrire_verifier_pose_et_verifie_sans_recharger(tmp_path):
    f, s = tmp_path / "v.conf", Faux()
    assert U.ecrire_verifier(f, "a\n", s) == "ecrit"
    assert f.read_text() == "a\n" and s.appels == ["verifier"], "le rechargement est décidé par l'appelant (règles à chaud)"


def test_ecrire_verifier_identique_ne_fait_rien(tmp_path):
    f, s = tmp_path / "v.conf", Faux()
    f.write_text("a\n")
    assert U.ecrire_verifier(f, "a\n", s) == "inchange" and s.appels == []


def test_ecrire_verifier_refuse_restaure(tmp_path):
    f, s = tmp_path / "v.conf", Faux(verif=(False, "mauvais"))
    f.write_bytes(b"ancien\n")
    with pytest.raises(U.ErreurUnbound, match="mauvais"):
        U.ecrire_verifier(f, "x\n", s)
    assert f.read_bytes() == b"ancien\n"


def test_retirer_vue_supprime_verifie_et_recharge(tmp_path):
    f, s = tmp_path / "v.conf", Faux()
    f.write_text("a\n")
    assert U.retirer_vue(f, s) == "retire"
    assert not f.exists() and s.appels == ["verifier", "recharger"]


def test_retirer_une_vue_absente_ne_recharge_rien(tmp_path):
    s = Faux()
    assert U.retirer_vue(tmp_path / "absente.conf", s) == "absent" and s.appels == []


def test_retirer_vue_dont_la_verification_echoue_remet_la_vue(tmp_path):
    f, s = tmp_path / "v.conf", Faux(verif=(False, "non"))
    f.write_bytes(b"gardee\n")
    with pytest.raises(U.ErreurUnbound):
        U.retirer_vue(f, s)
    assert f.read_bytes() == b"gardee\n" and s.appels == ["verifier"]


def test_ecriture_atomique_cree_le_dossier_manquant(tmp_path):
    f = tmp_path / "nouveau" / "dossier" / "v.conf"
    U.ecrire_atomique(f, "x\n")
    assert f.read_text() == "x\n"
