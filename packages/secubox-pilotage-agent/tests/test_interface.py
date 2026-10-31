# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3302 : bascule d'interface locale ⇄ distante pilotée par le maître (verbe `interface` du ctl root).

Même banc que test_pilotagectl.py (ctl réel en sous-processus sous SBX_RACINE, faux systemd-run et systemctl), plus un
faux secubox-profilectl qui note ses appels et peut échouer pour un profil donné."""
import json

import pytest

from test_pilotagectl import Banc

FAUX_PROFILECTL = """#!/bin/sh
# faux secubox-profilectl : note l'argv ; échoue (rc 2) si le profil demandé est dans $FAUX_PROFILECTL_ECHEC
printf '%s\\n' "$*" >> "$FAUX_PROFILECTL_APPELS"
profil=""
prec=""
for a in "$@"; do [ "$prec" = --profile ] && profil="$a"; prec="$a"; done
case " $FAUX_PROFILECTL_ECHEC " in *" $profil "*) echo '{"status": "rolled_back"}'; exit 2 ;; esac
echo '{"status": "applied"}'
exit 0
"""


class BancInterface(Banc):
    def __init__(self, tmp_path, actif="minimal"):
        super().__init__(tmp_path)
        faux = tmp_path / "faux" / "secubox-profilectl"
        faux.write_text(FAUX_PROFILECTL)
        faux.chmod(0o755)
        self.appels_profilectl = tmp_path / "profilectl"
        self.env["FAUX_PROFILECTL_APPELS"] = str(self.appels_profilectl)
        prof = self.r / "etc/secubox/profiles"
        prof.mkdir(parents=True)
        for nom in ("minimal", "distante", "full"):
            (prof / f"{nom}.toml").write_text(f'name = "{nom}"\n')
        if actif is not None:
            (prof / "active").write_text(actif + "\n")
            (prof / "active").chmod(0o600)              # comme l'écriture atomique du panneau (mkstemp)

    def profilectl(self):
        return self.appels_profilectl.read_text().splitlines() if self.appels_profilectl.exists() else []

    def actif(self):
        return (self.r / "etc/secubox/profiles/active").read_text().strip()

    def etat_interface(self):
        f = self.r / "var/lib/secubox-pilotagectl/interface.json"
        return json.loads(f.read_text()) if f.exists() else None

    def evenements(self, prefixe="interface_"):
        return [e for e in self.audit() if e["evenement"].startswith(prefixe)]

    def basculer_distante(self):
        """Demande du maître puis unité transitoire : la box attend la confirmation."""
        rc, sortie, p = self.run("--acteur", "gk2admin", "interface", "distante", agent=True)
        assert rc == 0 and sortie["ok"] is True, (sortie, p.stderr)
        rc, fin, p = self.run("_interface", sortie["job"])
        assert rc == 0 and fin["ok"] is True, (fin, p.stderr)
        self.finir(sortie["job"])
        return sortie["job"]

    def finir(self, job):
        """ExecStopPost de l'unité transitoire, comme PID 1 le lance : libère l'opération exclusive."""
        rc, _, p = self.run("_fin", job, env={"SERVICE_RESULT": "success", "EXIT_STATUS": "0"})
        assert rc == 0, p.stderr


@pytest.fixture
def bi(tmp_path):
    return BancInterface(tmp_path)


def test_argv_invalide(bi):
    for argv in (["interface"], ["interface", "ailleurs"], ["interface", "distante", "en-trop"],
                 ["interface", "Distante"], ["_interface"], ["_interface", "../x"], ["_interface-garde", "zz"],
                 ["politique", "interface"]):
        assert bi.run(*argv, agent=True)[0] == 2, argv
    assert bi.lancements() == []


def test_distante_memorise_le_retour_et_lance_une_unite_bornee(bi):
    rc, sortie, p = bi.run("--acteur", "gk2admin", "interface", "distante", agent=True)
    assert rc == 0 and sortie["ok"] is True and len(sortie["job"]) == 16, p.stderr
    job = sortie["job"]
    lance = bi.lancements()[-1]
    assert f"--unit=secubox-pilotage-op-{job}" in lance and "--property=RuntimeMaxSec=1800" in lance
    assert lance.endswith(f"-- /usr/sbin/secubox-pilotagectl _interface {job}")
    e = bi.etat_interface()
    assert (e["job"], e["sens"], e["precedent"], e["etat"]) == (job, "distante", "minimal", "en_cours")
    assert bi.profilectl() == []                     # rien n'est appliqué avant l'unité transitoire
    demande = [x for x in bi.audit() if x["evenement"] == "pilotage_demande"][-1]
    assert (demande["verbe"], demande["action"], demande["acteur"]) == ("interface", "interface-distante", "gk2admin")


def test_unite_distante_applique_puis_arme_l_homme_mort(bi):
    job = bi.basculer_distante()
    assert bi.profilectl() == ["apply --profile distante --yes --json"]
    assert bi.actif() == "distante"
    e = bi.etat_interface()
    assert e["etat"] == "a_confirmer" and e["echeance"] >= e["bascule"]
    garde = bi.lancements()[-1]
    # armée AVANT l'apply : l'échéance couvre l'apply (900 s) puis le délai de confirmation (600 s par défaut)
    assert "--on-active=1500" in garde and f"--unit=secubox-pilotage-garde-{job}" in garde
    assert garde.endswith(f"-- /usr/sbin/secubox-pilotagectl _interface-garde {job}")
    assert [x["evenement"] for x in bi.evenements()] == ["interface_basculee"]


def test_delai_de_garde_configurable_et_borne(bi):
    conf = bi.r / "etc/secubox-pilotage/interface.toml"
    conf.parent.mkdir(parents=True, exist_ok=True)
    conf.write_text("delai_garde_s = 300\n")
    conf.chmod(0o644)
    bi.basculer_distante()
    assert "--on-active=1200" in bi.lancements()[-1]


def test_delai_hors_bornes_rend_le_defaut(tmp_path):
    bi = BancInterface(tmp_path)
    conf = bi.r / "etc/secubox-pilotage/interface.toml"
    conf.parent.mkdir(parents=True, exist_ok=True)
    conf.write_text("delai_garde_s = 5\n")
    conf.chmod(0o644)
    bi.basculer_distante()
    assert "--on-active=1500" in bi.lancements()[-1]


def test_echec_d_apply_rend_le_profil_precedent(bi):
    bi.env["FAUX_PROFILECTL_ECHEC"] = "distante"
    rc, sortie, _ = bi.run("interface", "distante", agent=True)
    rc, fin, _ = bi.run("_interface", sortie["job"])
    assert rc == 1                                   # l'unité finit en échec : _fin l'audite, le maître le voit
    assert bi.profilectl() == ["apply --profile distante --yes --json", "apply --profile minimal --yes --json"]
    assert bi.actif() == "minimal" and bi.etat_interface()["etat"] == "echec"
    retour = bi.evenements("interface_retour")[-1]
    assert retour["cause"] == "apply" and retour["profil"] == "minimal"
    assert f"stop secubox-pilotage-garde-{sortie['job']}.timer" in bi.lancements()     # garde armée puis désarmée


def test_confirmation_du_maitre_arrete_la_garde(bi):
    job = bi.basculer_distante()
    rc, sortie, _ = bi.run("interface", "confirmer", agent=True)
    assert rc == 0 and sortie == {"ok": True, "confirme": True}
    assert bi.etat_interface()["etat"] == "confirme"
    assert f"stop secubox-pilotage-garde-{job}.timer" in bi.lancements()
    assert bi.evenements("interface_confirmee")
    # rien à confirmer ensuite : refus propre, pas d'erreur
    rc, sortie, _ = bi.run("interface", "confirmer", agent=True)
    assert rc == 0 and sortie == {"ok": False, "refus": "rien à confirmer"}
    # la garde, si elle part quand même, ne défait rien
    rc, _, _ = bi.run("_interface-garde", job)
    assert rc == 0 and bi.actif() == "distante" and len(bi.profilectl()) == 1


def test_homme_mort_rend_l_interface_locale(bi):
    job = bi.basculer_distante()
    rc, sortie, p = bi.run("_interface-garde", job)
    assert rc == 0 and sortie["ok"] is True, p.stderr
    assert bi.profilectl()[-1] == "apply --profile minimal --yes --json"
    assert bi.actif() == "minimal" and bi.etat_interface()["etat"] == "retour"
    assert bi.evenements("interface_retour")[-1]["cause"] == "homme-mort"


def test_homme_mort_rattrape_une_unite_tuee_en_plein_apply(bi):
    """L'unité transitoire meurt (RuntimeMaxSec, coupure) avant d'écrire « a_confirmer » : la garde rend quand même le profil."""
    rc, sortie, _ = bi.run("interface", "distante", agent=True)
    assert bi.etat_interface()["etat"] == "en_cours"
    rc, r, p = bi.run("_interface-garde", sortie["job"])
    assert rc == 0 and r["retour"] is True, p.stderr
    assert bi.profilectl() == ["apply --profile minimal --yes --json"] and bi.etat_interface()["etat"] == "retour"


def test_garde_non_armee_pas_de_bascule(bi):
    rc, sortie, _ = bi.run("interface", "distante", agent=True)
    rc, fin, _ = bi.run("_interface", sortie["job"], env={"FAUX_RUN_ECHEC": "1"})
    assert rc == 1 and bi.profilectl() == [] and bi.etat_interface()["etat"] == "echec"


def test_garde_d_un_autre_job_ne_fait_rien(bi):
    bi.basculer_distante()
    rc, _, _ = bi.run("_interface-garde", "0123456789abcdef")
    assert rc == 0 and len(bi.profilectl()) == 1 and bi.etat_interface()["etat"] == "a_confirmer"


def test_retour_en_locale_demande_par_le_maitre(bi):
    ancien = bi.basculer_distante()
    bi.run("interface", "confirmer", agent=True)
    rc, sortie, _ = bi.run("interface", "locale", agent=True)
    assert rc == 0 and sortie["ok"] is True
    e = bi.etat_interface()
    assert (e["sens"], e["precedent"], e["etat"]) == ("locale", "minimal", "en_cours")
    rc, fin, _ = bi.run("_interface", sortie["job"])
    assert rc == 0 and bi.profilectl()[-1] == "apply --profile minimal --yes --json"
    assert bi.actif() == "minimal" and bi.etat_interface()["etat"] == "locale"
    assert f"stop secubox-pilotage-garde-{ancien}.timer" in bi.lancements()
    assert bi.evenements("interface_retour")[-1]["cause"] == "demande"


def test_locale_pendant_l_attente_de_confirmation_desarme_la_garde(bi):
    ancien = bi.basculer_distante()
    rc, sortie, _ = bi.run("interface", "locale", agent=True)
    assert rc == 0 and sortie["ok"] is True
    # la garde de l'ancien job ne voit plus « a_confirmer » : elle ne rejoue pas un second retour
    bi.run("_interface-garde", ancien)
    assert len(bi.profilectl()) == 1


def test_distante_refusee_pendant_une_attente(bi):
    bi.basculer_distante()
    rc, sortie, _ = bi.run("interface", "distante", agent=True)
    assert rc == 0 and sortie["refus"] == "bascule en attente de confirmation"


def test_sans_profil_de_retour_rien_n_est_lance(tmp_path):
    bi = BancInterface(tmp_path, actif=None)
    rc, sortie, _ = bi.run("interface", "distante", agent=True)
    assert rc == 0 and sortie == {"ok": False, "refus": "profil de retour inconnu"}
    assert bi.lancements() == []


def test_profil_de_retour_configure(tmp_path):
    bi = BancInterface(tmp_path, actif="distante")    # box déjà allégée à la main : `active` ne dit rien du retour
    conf = bi.r / "etc/secubox-pilotage/interface.toml"
    conf.parent.mkdir(parents=True, exist_ok=True)
    conf.write_text('profil_retour = "full"\n')
    conf.chmod(0o644)
    rc, sortie, _ = bi.run("interface", "locale", agent=True)
    assert rc == 0 and sortie["ok"] is True and bi.etat_interface()["precedent"] == "full"


def test_profil_de_retour_inexistant_refuse(tmp_path):
    bi = BancInterface(tmp_path, actif="inconnu")
    rc, sortie, _ = bi.run("interface", "distante", agent=True)
    assert sortie == {"ok": False, "refus": "profil de retour inconnu"}


def test_mains_liees_refusent(bi):
    bi.run("mains-liees", "on")
    for sens in ("distante", "locale", "confirmer"):
        rc, sortie, _ = bi.run("interface", sens, agent=True)
        assert rc == 0 and sortie["refus"] == "mains liées", sens
    assert bi.lancements() == []


def test_box_cliente_exige_l_accord(bi):
    bi.cliente()
    rc, sortie, _ = bi.run("interface", "distante", agent=True)
    assert rc == 0 and sortie["refus"] == "consentement requis"
    assert bi.lancements() == []
    bi.run("consentement", "accepter", sortie["consentement"])
    rc, sortie, _ = bi.run("interface", "distante", agent=True)
    assert rc == 0 and sortie["ok"] is True


def test_internes_refuses_depuis_l_agent(bi):
    job = bi.basculer_distante()
    for verbe in ("_interface", "_interface-garde"):
        rc, sortie, _ = bi.run(verbe, job, agent=True)
        assert rc == 0 and sortie == {"ok": False, "refus": "local seulement"}, verbe
    assert len(bi.profilectl()) == 1


def test_interface_est_exclusive(bi):
    rc, a, _ = bi.run("interface", "distante", agent=True)
    rc, b, _ = bi.run("maj-paquets", agent=True)
    assert b == {"ok": False, "refus": "opération en cours", "job": a["job"]}


def test_politique_connait_les_actions(bi):
    for action in ("interface-distante", "interface-locale", "interface-confirmer"):
        rc, sortie, _ = bi.run("politique", action, agent=True)
        assert rc == 0 and sortie["autorise"] is True, action
