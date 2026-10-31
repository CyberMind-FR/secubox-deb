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
if [ "$1" = status ]; then
  [ -n "$FAUX_PROFILECTL_STATUS_ECHEC" ] && exit 3
  if [ -n "$FAUX_PROFILECTL_STATUS" ]; then printf '%s\\n' "$FAUX_PROFILECTL_STATUS"; else
    echo '{"modules": [{"id": "hub", "on": true}, {"id": "visio", "on": true}, {"id": "group@distante", "on": false, "enabled": false, "active": false}, {"id": "auth", "on": true}, {"id": "jellyfin", "on": false, "enabled": true, "active": false}]}'
  fi
  exit 0
fi
profil=""
prec=""
for a in "$@"; do [ "$prec" = --profile ] && profil="$a"; prec="$a"; done
[ -n "$FAUX_PROFILECTL_COPIE" ] && [ -n "$profil" ] && cat "$FAUX_PROFILES/$profil.toml" > "$FAUX_PROFILECTL_COPIE" 2>/dev/null
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
        self.env["FAUX_PROFILES"] = str(self.r / "etc/secubox/profiles")
        prof = self.r / "etc/secubox/profiles"
        prof.mkdir(parents=True)
        for nom in ("minimal", "distante", "full"):
            (prof / f"{nom}.toml").write_text(f'name = "{nom}"\n')
        if actif is not None:
            (prof / "active").write_text(actif + "\n")
            (prof / "active").chmod(0o600)              # comme l'écriture atomique du panneau (mkstemp)

    def allegee(self):
        """Marqueur de secubox-profiles : la box est réellement en profil léger (posé après nginx -t)."""
        m = self.r / "var/lib/secubox-profiles/allegement/actif"
        m.parent.mkdir(parents=True, exist_ok=True)
        m.write_text("")

    def garde_c(self):
        """Ligne de lancement de la garde réarmée à la fin de l'apply (« -c »)."""
        return [x for x in self.lancements() if "secubox-pilotage-garde-" in x and "-c " in x][-1]

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
    for argv in (["interface"], ["interface", "ailleurs"], ["interface", "distante", "en-trop"], ["interface", "confirmer"],
                 ["interface", "confirmer", "../x"], ["interface", "locale", "0123456789abcdef"], ["_interface-reprise", "x"],
                 ["interface", "Distante"], ["_interface"], ["_interface", "../x"], ["_interface-garde", "zz"],
                 ["politique", "interface"]):
        assert bi.run(*argv, agent=True)[0] == 2, argv
    assert bi.lancements() == []


def test_distante_memorise_le_retour_et_lance_une_unite_bornee(bi):
    rc, sortie, p = bi.run("--acteur", "gk2admin", "interface", "distante", agent=True)
    assert rc == 0 and sortie["ok"] is True and len(sortie["job"]) == 16, p.stderr
    job = sortie["job"]
    lance = bi.lancements()[-1]
    assert f"--unit=secubox-pilotage-op-{job}" in lance and "--property=RuntimeMaxSec=1980" in lance   # #3349 : relevé + apply + retour + marge
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
    garde = bi.garde_c()
    assert f"stop secubox-pilotage-garde-{job}.timer" in bi.lancements()        # la première, après la seconde
    # armée AVANT l'apply (900 s d'apply + délai), puis RÉARMÉE à la fin de l'apply pour le seul délai de confirmation
    premiere = [x for x in bi.lancements() if "--on-active=1500" in x]
    assert premiere and f"--unit=secubox-pilotage-garde-{job} " in premiere[0] + " "
    assert "--on-active=600" in garde and f"--unit=secubox-pilotage-garde-{job}-c" in garde
    assert garde.endswith(f"-- /usr/sbin/secubox-pilotagectl _interface-garde {job}")
    assert [x["evenement"] for x in bi.evenements()] == ["interface_basculee"]


def test_delai_de_garde_configurable_et_borne(bi):
    conf = bi.r / "etc/secubox-pilotage/interface.toml"
    conf.parent.mkdir(parents=True, exist_ok=True)
    conf.write_text("delai_garde_s = 300\n")
    conf.chmod(0o644)
    bi.basculer_distante()
    assert "--on-active=300" in bi.garde_c()


def test_delai_hors_bornes_rend_le_defaut(tmp_path):
    bi = BancInterface(tmp_path)
    conf = bi.r / "etc/secubox-pilotage/interface.toml"
    conf.parent.mkdir(parents=True, exist_ok=True)
    conf.write_text("delai_garde_s = 5\n")
    conf.chmod(0o644)
    bi.basculer_distante()
    assert "--on-active=600" in bi.garde_c()


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
    rc, sortie, _ = bi.run("interface", "confirmer", job, agent=True)
    assert rc == 0 and sortie == {"ok": True, "confirme": True}
    assert bi.etat_interface()["etat"] == "confirme"
    assert f"stop secubox-pilotage-garde-{job}.timer" in bi.lancements()
    assert bi.evenements("interface_confirmee")
    # rien à confirmer ensuite : refus propre, pas d'erreur
    rc, sortie, _ = bi.run("interface", "confirmer", job, agent=True)
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
    bi.run("interface", "confirmer", ancien, agent=True)
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


def test_sans_profil_de_retour_un_instantane_est_pris(tmp_path):
    """#3349 : sans profil de retour connu, la bascule photographie l'état réel (modules allumés selon secubox-profilectl
    status) en un profil « instantane » (copie root 0600 dans l'état du ctl, profil 0644 lu par profilectl) AVANT la garde
    et l'apply du profil léger ; le retour l'applique à l'identique."""
    bi = BancInterface(tmp_path, actif=None)
    rc, sortie, p = bi.run("interface", "distante", agent=True)
    assert rc == 0 and sortie["ok"] is True, (sortie, p.stderr)
    assert bi.etat_interface()["precedent"] == "instantane"
    assert bi.profilectl() == []                     # rien avant l'unité transitoire
    job = sortie["job"]
    rc, fin, p = bi.run("_interface", job)
    assert rc == 0 and fin["ok"] is True, (fin, p.stderr)
    assert bi.profilectl() == ["status --json", "apply --profile distante --yes --json"]
    assert bi.etat_interface()["precedent"] == f"instantane-{job}"      # lié à CETTE bascule
    prof = bi.r / f"etc/secubox/profiles/instantane-{job}.toml"
    texte = prof.read_text()
    assert f'name = "instantane-{job}"' in texte and '"hub"' in texte and '"visio"' in texte and '"auth"' in texte
    assert '"jellyfin"' in texte                     # activé mais endormi : gardé (jamais désactivé au retour)
    assert "group@distante" not in texte
    copie = bi.r / f"var/lib/secubox-pilotagectl/instantane-{sortie['job']}.toml"
    assert copie.read_text() == texte and (copie.stat().st_mode & 0o777) == 0o600
    assert any(e["evenement"] == "interface_instantane" for e in bi.audit())


def test_homme_mort_rend_l_instantane(tmp_path):
    bi = BancInterface(tmp_path, actif=None)
    job = bi.basculer_distante()
    rc, _, p = bi.run("_interface-garde", job)
    assert rc == 0, p.stderr
    assert bi.profilectl()[-1] == f"apply --profile instantane-{job} --yes --json"
    assert bi.etat_interface()["etat"] == "retour"
    # retour réussi : le profil photographié est retiré, et `active` rendu à son absence d'origine
    assert not (bi.r / f"etc/secubox/profiles/instantane-{job}.toml").exists()
    assert not (bi.r / "etc/secubox/profiles/active").exists()


def test_retour_reecrit_le_profil_depuis_la_copie_root(tmp_path):
    """Le dossier profiles est au compte secubox : avant chaque apply de retour, le profil est réécrit depuis la copie
    root 0600 ; une altération entre-temps est écrasée."""
    bi = BancInterface(tmp_path, actif=None)
    job = bi.basculer_distante()
    prof = bi.r / f"etc/secubox/profiles/instantane-{job}.toml"
    prof.write_text(f'name = "instantane-{job}"\non = []\n')            # altéré : couperait tout
    seen = bi.r / "vu.txt"
    bi.env["FAUX_PROFILECTL_COPIE"] = str(seen)
    rc, _, p = bi.run("_interface-garde", job)
    assert rc == 0, p.stderr
    assert '"hub"' in seen.read_text()


def test_retour_refuse_sans_la_copie_root(tmp_path):
    bi = BancInterface(tmp_path, actif=None)
    job = bi.basculer_distante()
    (bi.r / f"var/lib/secubox-pilotagectl/instantane-{job}.toml").unlink()
    n = len(bi.profilectl())
    bi.run("_interface-garde", job)
    assert len(bi.profilectl()) == n                 # aucun apply sans la copie root


def test_actif_instantane_refait_un_releve(tmp_path):
    bi = BancInterface(tmp_path, actif="instantane-0123456789abcdef")
    (bi.r / "etc/secubox/profiles/instantane-0123456789abcdef.toml").write_text('name = "instantane-0123456789abcdef"\n')
    rc, sortie, _ = bi.run("interface", "distante", agent=True)
    assert sortie["ok"] is True and bi.etat_interface()["precedent"] == "instantane"


def test_instantane_illisible_pas_de_bascule(tmp_path):
    bi = BancInterface(tmp_path, actif=None)
    bi.env["FAUX_PROFILECTL_STATUS_ECHEC"] = "1"
    rc, sortie, _ = bi.run("interface", "distante", agent=True)
    assert rc == 0 and sortie["ok"] is True
    rc, _, _ = bi.run("_interface", sortie["job"])
    assert rc == 1 and "apply --profile distante --yes --json" not in bi.profilectl()
    assert bi.etat_interface()["etat"] == "echec"
    assert not any("secubox-pilotage-garde-" in x for x in bi.lancements())


def test_instantane_vide_refuse(tmp_path):
    bi = BancInterface(tmp_path, actif=None)
    bi.env["FAUX_PROFILECTL_STATUS"] = '{"modules": [{"id": "x", "on": false}, {"id": "../evil", "on": true}]}'
    rc, sortie, _ = bi.run("interface", "distante", agent=True)
    rc, _, _ = bi.run("_interface", sortie["job"])
    assert rc == 1 and bi.etat_interface()["etat"] == "echec"
    assert not list((bi.r / "etc/secubox/profiles").glob("instantane*.toml"))


def test_profil_connu_reste_prioritaire_sur_l_instantane(bi):
    rc, sortie, _ = bi.run("interface", "distante", agent=True)
    assert bi.etat_interface()["precedent"] == "minimal"
    bi.run("_interface", sortie["job"])
    assert "status --json" not in bi.profilectl()


def test_profil_de_retour_configure(tmp_path):
    bi = BancInterface(tmp_path, actif="distante")    # box déjà allégée à la main : `active` ne dit rien du retour
    bi.allegee()
    conf = bi.r / "etc/secubox-pilotage/interface.toml"
    conf.parent.mkdir(parents=True, exist_ok=True)
    conf.write_text('profil_retour = "full"\n')
    conf.chmod(0o644)
    rc, sortie, _ = bi.run("interface", "locale", agent=True)
    assert rc == 0 and sortie["ok"] is True and bi.etat_interface()["precedent"] == "full"


def test_profil_de_retour_inexistant_donne_un_instantane(tmp_path):
    bi = BancInterface(tmp_path, actif="inconnu")
    rc, sortie, _ = bi.run("interface", "distante", agent=True)
    assert sortie["ok"] is True and bi.etat_interface()["precedent"] == "instantane"


def test_mains_liees_refusent(bi):
    bi.run("mains-liees", "on")
    for argv in (["distante"], ["locale"], ["confirmer", "0123456789abcdef"]):
        rc, sortie, _ = bi.run("interface", *argv, agent=True)
        assert rc == 0 and sortie["refus"] == "mains liées", argv
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


def test_confirmation_d_une_autre_bascule_refusee_et_auditee(bi):
    """I1 : la confirmation porte le job ; une confirmation tardive d'une ancienne bascule ne désarme pas la courante."""
    bi.basculer_distante()
    rc, sortie, _ = bi.run("interface", "confirmer", "0123456789abcdef", agent=True)
    assert rc == 0 and sortie == {"ok": False, "refus": "confirmation d'une autre bascule"}
    assert bi.etat_interface()["etat"] == "a_confirmer"
    assert any(e.get("refus") == "confirmation d'une autre bascule" for e in bi.audit() if e["evenement"] == "pilotage_refus")


def test_retour_en_locale_en_echec_garde_reprise(bi):
    """I2 : l'ancienne garde n'est désarmée qu'après un retour réussi ; en échec, une garde est réarmée pour réessayer."""
    ancien = bi.basculer_distante()
    rc, sortie, _ = bi.run("interface", "locale", agent=True)
    bi.env["FAUX_PROFILECTL_ECHEC"] = "minimal"
    rc, fin, _ = bi.run("_interface", sortie["job"])
    assert rc == 1
    assert f"stop secubox-pilotage-garde-{ancien}-c.timer" not in bi.lancements()
    assert bi.etat_interface()["etat"] == "a_reprendre"
    assert any(f"--unit=secubox-pilotage-garde-{sortie['job']}" in x for x in bi.lancements())
    assert bi.evenements("interface_echec")
    bi.env.pop("FAUX_PROFILECTL_ECHEC")
    rc, r, _ = bi.run("_interface-garde", sortie["job"])
    assert rc == 0 and r["retour"] is True and bi.etat_interface()["etat"] == "retour" and bi.actif() == "minimal"


def test_locale_refusee_sans_bascule_distante(bi):
    """M2 : rien à défaire (aucune bascule, ou déjà revenue) : refus, rien n'est lancé."""
    rc, sortie, _ = bi.run("interface", "locale", agent=True)
    assert sortie == {"ok": False, "refus": "aucune interface distante en place"}
    job = bi.basculer_distante()
    bi.run("_interface-garde", job)                  # retour automatique : etat « retour »
    rc, sortie, _ = bi.run("interface", "locale", agent=True)
    assert sortie == {"ok": False, "refus": "aucune interface distante en place"}


def test_actif_garde_proprietaire_et_mode(bi):
    """M1 : `active` réécrit avec le mode d'origine (0600 du panneau), jamais élargi."""
    bi.basculer_distante()
    import stat as st_
    assert st_.S_IMODE((bi.r / "etc/secubox/profiles/active").stat().st_mode) == 0o600


def test_reprise_au_demarrage_echeance_passee(bi):
    """B1 : la garde transitoire ne survit pas au redémarrage ; la reprise rend le profil si l'échéance est passée."""
    job = bi.basculer_distante()
    f = bi.r / "var/lib/secubox-pilotagectl/interface.json"
    e = json.loads(f.read_text())
    e["echeance"] = 1
    f.write_text(json.dumps(e))
    rc, r, p = bi.run("_interface-reprise")
    assert rc == 0 and r["retour"] is True, p.stderr
    assert bi.actif() == "minimal" and bi.etat_interface()["etat"] == "retour"
    assert job


def test_reprise_au_demarrage_rearme_le_temps_restant(bi):
    job = bi.basculer_distante()
    e = bi.etat_interface()
    import time
    restant = e["echeance"] - int(time.time())
    rc, r, p = bi.run("_interface-reprise")
    assert rc == 0 and r == {"ok": True, "retour": False, "rearmee": True}, p.stderr
    dernier = bi.lancements()[-1]
    s = int(dernier.split("--on-active=")[1].split()[0])
    assert restant - 5 <= s <= restant and f"secubox-pilotage-garde-{job}-r" in dernier
    assert len(bi.profilectl()) == 1


def test_reprise_bascule_inachevee_au_demarrage(bi):
    """Coupure en plein apply : etat « en_cours » au démarrage ⇒ retour immédiat."""
    rc, sortie, _ = bi.run("interface", "distante", agent=True)
    rc, r, _ = bi.run("_interface-reprise")
    assert rc == 0 and r["retour"] is True and bi.etat_interface()["etat"] == "retour"


def test_reprise_sans_rien_a_faire(bi):
    assert bi.run("_interface-reprise")[1] == {"ok": True, "retour": False, "rearmee": False}
    assert bi.run("_interface-reprise", agent=True)[1] == {"ok": False, "refus": "local seulement"}


def test_unite_de_reprise_livree():
    from pathlib import Path
    pkg = Path(__file__).resolve().parents[1]
    u = (pkg / "systemd" / "secubox-pilotage-interface-reprise.service").read_text()
    assert "Type=oneshot" in u and "ExecStart=/usr/sbin/secubox-pilotagectl _interface-reprise" in u
    assert "WantedBy=multi-user.target" in u
    assert "secubox-pilotage-interface-reprise.service" in (pkg / "debian" / "rules").read_text()
    assert "enable secubox-pilotage-interface-reprise.service" in (pkg / "debian" / "postinst").read_text()


def test_retour_en_locale_coupe_rattrape(bi):
    """Retour en locale interrompu (redémarrage, RuntimeMaxSec) : une garde de CE job est armée avant l'apply, et la
    reprise au démarrage reprend le retour."""
    bi.basculer_distante()
    rc, sortie, _ = bi.run("interface", "locale", agent=True)
    job = sortie["job"]
    # l'unité de retour démarre, arme sa garde, puis meurt avant la fin de l'apply : simulé par un apply qui « pend »
    bi.env["FAUX_PROFILECTL_ECHEC"] = "minimal"
    bi.run("_interface", job)
    assert any(f"--unit=secubox-pilotage-garde-{job} " in x + " " for x in bi.lancements())
    # état laissé « en_cours » (unité tuée) : la reprise refait le retour
    f = bi.r / "var/lib/secubox-pilotagectl/interface.json"
    e = json.loads(f.read_text())
    e["etat"] = "en_cours"
    f.write_text(json.dumps(e))
    bi.env.pop("FAUX_PROFILECTL_ECHEC")
    rc, r, p = bi.run("_interface-reprise")
    assert rc == 0 and r["retour"] is True, p.stderr
    assert bi.actif() == "minimal" and bi.etat_interface()["etat"] == "retour"


def test_garde_de_retour_reprend_un_retour_inacheve(bi):
    bi.basculer_distante()
    rc, sortie, _ = bi.run("interface", "locale", agent=True)
    rc, r, _ = bi.run("_interface-garde", sortie["job"])       # unité de retour jamais finie
    assert rc == 0 and r["retour"] is True and bi.actif() == "minimal"


def test_a_reprendre_sans_garde_repris_au_demarrage(bi):
    """Échec du retour ET de l'armement de sa garde : l'état reste « a_reprendre », la reprise au démarrage la réarme."""
    bi.basculer_distante()
    rc, sortie, _ = bi.run("interface", "locale", agent=True)
    bi.env.update(FAUX_PROFILECTL_ECHEC="minimal", FAUX_RUN_ECHEC="1")
    rc, _, _ = bi.run("_interface", sortie["job"])
    assert rc == 1 and bi.etat_interface()["etat"] == "a_reprendre"
    assert [e.get("garde") for e in bi.evenements("interface_echec")][-1] == "non_armee"
    bi.env.pop("FAUX_RUN_ECHEC")
    rc, r, p = bi.run("_interface-reprise")
    assert rc == 0 and r["rearmee"] is True, p.stderr


def test_unite_de_reprise_ordonnee_et_durcie():
    from pathlib import Path
    u = (Path(__file__).resolve().parents[1] / "systemd" / "secubox-pilotage-interface-reprise.service").read_text()
    assert "After=local-fs.target network-online.target nginx.service" in u and "Wants=network-online.target" in u
    assert "NoNewPrivileges=yes" in u and "PrivateTmp=yes" in u


def test_retour_en_echec_rearme_sous_un_autre_nom(bi):
    """La garde du retour (armée avant l'apply) porte déjà le nom de base : le réarmement d'a_reprendre prend « -c » puis
    arrête la première ; jamais « non_armee » à tort, échéance = délai seul."""
    bi.basculer_distante()
    rc, sortie, _ = bi.run("interface", "locale", agent=True)
    job = sortie["job"]
    bi.env.update(FAUX_PROFILECTL_ECHEC="minimal", FAUX_RUN_UNIQUE="1")
    rc, _, _ = bi.run("_interface", job)
    assert rc == 1 and bi.etat_interface()["etat"] == "a_reprendre"
    assert [e.get("garde") for e in bi.evenements("interface_echec")][-1] == "armee"
    c = [x for x in bi.lancements() if f"--unit=secubox-pilotage-garde-{job}-c " in x + " "]
    assert c and "--on-active=600" in c[-1]
    assert f"stop secubox-pilotage-garde-{job}.timer" in bi.lancements()
