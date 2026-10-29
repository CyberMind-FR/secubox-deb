# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3126 L2, tâche 1 : secubox-pilotagectl, ctl root de la box, et sa politique.

Le ctl réel est lancé en sous-processus, sans root, sous une racine substituée (SBX_RACINE, honorée parce que l'appelant
est le processus lui-même, jamais un compte élevé par sudo). systemd-run et systemctl sont des faux placés en tête du
PATH (honoré seulement sous SBX_RACINE). L'appel « depuis l'agent » est simulé par SUDO_USER=secubox-pilotage-agent,
comme sudo le pose ; sans lui, l'appel est local (le détenteur, root, sur la box)."""
import json
import os
import subprocess
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1]
CTL = PKG / "sbin" / "secubox-pilotagectl"
AGENT = "secubox-pilotage-agent"
DELAI = 60

FAUX_SYSTEMD_RUN = """#!/bin/sh
# faux systemd-run : note l'argv (une ligne), puis « démarre » l'unité nommée par --unit=
printf '%s\\n' "$*" >> "$FAUX_LANCES"
for a in "$@"; do
  case "$a" in --unit=*) printf '%s.service\\n' "${a#--unit=}" >> "$FAUX_ACTIFS" ;; esac
done
exit 0
"""

FAUX_SYSTEMCTL = """#!/bin/sh
# faux systemctl : « show -p ActiveState --value <unité> » → active si l'unité figure dans $FAUX_ACTIFS
unite=""
for a in "$@"; do unite="$a"; done
if [ "$1" = show ]; then
  if grep -qx "$unite" "$FAUX_ACTIFS" 2>/dev/null; then echo active; else echo inactive; fi
  exit 0
fi
printf '%s\\n' "$*" >> "$FAUX_LANCES"
exit 0
"""


class Banc:
    def __init__(self, tmp_path: Path):
        self.r = tmp_path / "racine"
        for d in ("etc/secubox/modules.d", "etc/secubox/secrets/p2p", "var/log/secubox", "var/lib", "sys/class/net"):
            (self.r / d).mkdir(parents=True)
        (self.r / "var/log/secubox/audit.log").write_text("")
        (self.r / "etc/secubox/secrets/p2p/pair.token").write_text("SECRET-FICHIER-0451")
        # box du propriétaire par défaut : relié au maillage wg-mesh
        (self.r / "sys/class/net/wg-mesh").mkdir()
        faux = tmp_path / "faux"
        faux.mkdir()
        for nom, corps in (("systemd-run", FAUX_SYSTEMD_RUN), ("systemctl", FAUX_SYSTEMCTL)):
            (faux / nom).write_text(corps)
            (faux / nom).chmod(0o755)
        self.lances = tmp_path / "lances"
        self.actifs = tmp_path / "actifs"
        self.env = {k: v for k, v in os.environ.items() if not k.startswith(("SUDO_", "SBX_"))}
        self.env.update(PATH=f"{faux}:/usr/bin:/bin", SBX_RACINE=str(self.r),
                        FAUX_LANCES=str(self.lances), FAUX_ACTIFS=str(self.actifs))

    def cliente(self):
        (self.r / "sys/class/net/wg-mesh").rmdir()
        (self.r / "sys/class/net/wg-autoload").mkdir()

    def run(self, *args, agent=False, env=None):
        e = dict(self.env)
        if agent:
            e["SUDO_USER"] = AGENT
        e.update(env or {})
        p = subprocess.run([str(CTL), *args], env=e, capture_output=True, text=True, timeout=DELAI)
        lignes = p.stdout.strip().splitlines()
        assert len(lignes) <= 1, p.stdout
        sortie = json.loads(lignes[0]) if lignes else None
        return p.returncode, sortie, p

    def lancements(self):
        return self.lances.read_text().splitlines() if self.lances.exists() else []

    def audit(self):
        a = self.r / "var/log/secubox/audit.log"
        return [json.loads(ligne) for ligne in a.read_text().splitlines() if ligne.strip()]

    def module(self, ident, unites, protege):
        (self.r / f"etc/secubox/modules.d/{ident}.toml").write_text(
            f'id = "{ident}"\ncategory = "system"\nruntime = "native"\nexposure = "lan"\n'
            f'units = {json.dumps(unites)}\nprotected = {"true" if protege else "false"}\n')


@pytest.fixture
def banc(tmp_path):
    return Banc(tmp_path)


ACTIONS = ("releve", "reboot", "maj-paquets", "service-demarrer", "service-arreter", "service-redemarrer",
           "renommer", "renouveler-secrets", "support-ouvrir", "support-fermer")


def test_argv_invalide_rend_2(banc):
    invalides = [
        ["service", "redemarrer", "../etc"],
        [],
        ["inconnu"],
        ["reboot", "en-trop"],
        ["maj-paquets", "--force"],
        ["service", "tuer", "secubox-foo.service"],
        ["service", "redemarrer"],
        ["service", "redemarrer", "secubox-foo.service", "en-trop"],
        ["service", "redemarrer", "secubox-foo.service; reboot"],
        ["service", "redemarrer", "nginx.service"],
        ["service", "redemarrer", "secubox-foo.socket"],
        ["service", "redemarrer", "secubox-" + "a" * 70 + ".service"],
        ["service", "redemarrer", "secubox-Foo.service"],
        ["renommer", "Box_1"],
        ["renommer", "-box"],
        ["renommer", "a" * 64],
        ["support", "ouvrir"],
        ["support", "detruire", "s1"],
        ["support", "ouvrir", "../s1"],
        ["consentement", "accepter", "../x"],
        ["consentement", "peut-etre", "0123456789abcdef"],
        ["mains-liees", "peut-etre"],
        ["mains-liees"],
        ["ancre-verifier", "x"],
        ["politique"],
        ["politique", "tout-casser"],
        ["renouveler-secrets", "--machine-id"],
    ]
    for argv in invalides:
        rc, sortie, p = banc.run(*argv, agent=True)
        assert rc == 2, (argv, rc, p.stdout, p.stderr)
        assert sortie == {"ok": False, "refus": "argv invalide"}, argv
    assert banc.lancements() == []
    # chaque refus est audité, sans recopier l'argv refusé
    refus = [e for e in banc.audit() if e["evenement"] == "pilotage_refus"]
    assert len(refus) == len(invalides)
    assert all(e["refus"] == "argv invalide" for e in refus)
    assert not any("../" in json.dumps(e) for e in banc.audit())


def test_verbes_valides_acceptes_ou_non_disponibles(banc):
    """R-L2-1 : argv validé pour toute la liste fermée ; ancre-verifier, support, renommer « non disponible » (code 0)."""
    for argv in (["ancre-verifier"], ["support", "ouvrir", "s-01"], ["support", "fermer", "s-01"], ["renommer", "box-2"]):
        rc, sortie, _ = banc.run(*argv, agent=True)
        assert rc == 0 and sortie == {"ok": False, "refus": "non disponible"}, argv
    assert banc.lancements() == []
    for action in ACTIONS:
        rc, sortie, _ = banc.run("politique", action, agent=True)
        assert rc == 0 and set(sortie) == {"autorise", "consentement", "raison"}, action


def test_unite_protegee_refusee(banc):
    banc.module("auth", ["secubox-auth.service"], True)
    banc.module("vault", ["secubox-vault.service"], False)      # id du socle : protégé quoi que dise le manifeste
    banc.module("lyrion", ["secubox-lyrion.service"], False)
    for unite in ("secubox-auth.service", "secubox-vault.service", "secubox-core.service", "secubox-aggregator.service"):
        for verbe in ("demarrer", "arreter", "redemarrer"):
            rc, sortie, _ = banc.run("service", verbe, unite, agent=True)
            assert rc == 0 and sortie == {"ok": False, "refus": "unité protégée"}, (verbe, unite)
    assert banc.lancements() == []
    rc, sortie, _ = banc.run("service", "redemarrer", "secubox-lyrion.service", agent=True)
    assert rc == 0 and sortie["ok"] is True and len(sortie["job"]) == 16
    lance = banc.lancements()
    assert len(lance) == 1 and lance[0].endswith("-- /usr/bin/systemctl restart secubox-lyrion.service")


def test_agent_ne_se_coupe_pas(banc):
    for verbe in ("arreter", "redemarrer", "demarrer"):
        rc, sortie, _ = banc.run("service", verbe, "secubox-pilotage-agent.service", agent=True)
        assert rc == 0 and sortie == {"ok": False, "refus": "unité de l'agent"}, verbe
    assert banc.lancements() == []


def test_mains_liees_refuse_tout_sauf_releve(banc):
    rc, sortie, _ = banc.run("mains-liees", "on")
    assert rc == 0 and sortie == {"ok": True, "mains_liees": True}
    drapeau = banc.r / "etc/secubox/pilotage/mains-liees"
    assert drapeau.is_file() and (drapeau.stat().st_mode & 0o022) == 0      # projection lue par l'agent (L1)
    for action in ACTIONS:
        _, pol, _ = banc.run("politique", action, agent=True)
        if action == "releve":
            assert pol["autorise"] is True, pol
        else:
            assert pol == {"autorise": False, "consentement": False, "raison": "mains liées"}, action
    for argv in (["reboot"], ["maj-paquets"], ["renouveler-secrets"], ["service", "demarrer", "secubox-lyrion.service"]):
        rc, sortie, _ = banc.run(*argv, agent=True)
        assert rc == 0 and sortie == {"ok": False, "refus": "mains liées"}, argv
    assert banc.lancements() == []
    # local seulement : l'agent ne délie pas les mains (ni ne les lie), refus audité
    rc, sortie, _ = banc.run("mains-liees", "off", agent=True)
    assert rc == 0 and sortie == {"ok": False, "refus": "local seulement"}
    assert any(e["evenement"] == "pilotage_refus" and e["refus"] == "local seulement" for e in banc.audit())
    # le compte partagé secubox peut retirer la projection sous /etc/secubox : l'état root fait foi
    drapeau.unlink()
    _, pol, _ = banc.run("politique", "reboot", agent=True)
    assert pol["autorise"] is False and pol["raison"] == "mains liées"
    rc, sortie, _ = banc.run("mains-liees", "off")
    assert rc == 0 and sortie == {"ok": True, "mains_liees": False}
    _, pol, _ = banc.run("politique", "reboot", agent=True)
    assert pol["autorise"] is True
    bascules = [e["etat"] for e in banc.audit() if e["evenement"] == "mains_liees"]
    assert bascules == ["on", "off"]


def test_cliente_exige_un_consentement(banc):
    _, pol, _ = banc.run("politique", "reboot", agent=True)
    assert pol == {"autorise": True, "consentement": False, "raison": "box du propriétaire"}
    banc.cliente()
    for action, attendu in (("reboot", True), ("maj-paquets", True), ("service-arreter", True),
                            ("service-redemarrer", True), ("renommer", True), ("renouveler-secrets", True),
                            ("support-ouvrir", True), ("service-demarrer", False), ("releve", False)):
        _, pol, _ = banc.run("politique", action, agent=True)
        assert pol["autorise"] is True and pol["consentement"] is attendu, (action, pol)
    # la demande crée un consentement en attente, une seule fois ; rien n'est lancé
    rc, sortie, _ = banc.run("reboot", agent=True)
    assert rc == 0 and sortie["ok"] is False and sortie["refus"] == "consentement requis"
    ident = sortie["consentement"]
    assert len(ident) == 16
    _, encore, _ = banc.run("reboot", agent=True)
    assert encore["consentement"] == ident
    assert banc.lancements() == []
    # l'agent ne consent pas à la place du détenteur
    rc, sortie, _ = banc.run("consentement", "accepter", ident, agent=True)
    assert sortie == {"ok": False, "refus": "local seulement"}
    rc, sortie, _ = banc.run("consentement", "accepter", ident)
    assert rc == 0 and sortie == {"ok": True, "consentement": ident, "decision": "accepte"}
    # accord consommé une fois : l'action part, la suivante redemande
    rc, sortie, _ = banc.run("reboot", agent=True)
    assert rc == 0 and sortie["ok"] is True
    assert len(banc.lancements()) == 1 and "systemctl reboot" in banc.lancements()[0]
    _, apres, _ = banc.run("reboot", agent=True)
    assert apres["refus"] == "consentement requis" and apres["consentement"] != ident
    # le détenteur refuse : rien ne part
    rc, sortie, _ = banc.run("consentement", "refuser", apres["consentement"])
    assert sortie["decision"] == "refuse"
    assert len(banc.lancements()) == 1
    evts = [e["evenement"] for e in banc.audit()]
    assert evts.count("consentement_demande") == 2 and evts.count("consentement") == 2
    # l'accord vaut pour CETTE action : un service démarré ne demande rien, un autre service redemande
    rc, sortie, _ = banc.run("service", "demarrer", "secubox-lyrion.service", agent=True)
    assert sortie["ok"] is True


def test_mains_liees_annule_les_consentements(banc):
    banc.cliente()
    _, s1, _ = banc.run("reboot", agent=True)
    _, s2, _ = banc.run("service", "redemarrer", "secubox-lyrion.service", agent=True)
    ids = {s1["consentement"], s2["consentement"]}
    assert len(ids) == 2
    rc, sortie, _ = banc.run("mains-liees", "on")
    assert sortie["ok"] is True
    annules = {e["consentement"] for e in banc.audit() if e["evenement"] == "consentement_annule"}
    assert annules == ids
    banc.run("mains-liees", "off")
    for ident in ids:
        rc, sortie, _ = banc.run("consentement", "accepter", ident)
        assert rc == 0 and sortie == {"ok": False, "refus": "consentement annulé", "consentement": ident}
    # rien n'a été lancé, et une nouvelle demande crée un nouveau consentement
    assert banc.lancements() == []
    _, s3, _ = banc.run("reboot", agent=True)
    assert s3["consentement"] not in ids


def test_ctl_une_operation_longue_a_la_fois(banc):
    rc, s1, _ = banc.run("maj-paquets", agent=True)
    assert rc == 0 and s1["ok"] is True
    job = s1["job"]
    lance = banc.lancements()
    assert len(lance) == 1
    # systemd-run --collect, unité nommée par le job, SANS délai imposé (jamais de timeout sur apt)
    assert "--collect" in lance[0] and f"--unit=secubox-pilotage-op-{job}" in lance[0]
    assert "RuntimeMaxSec" not in lance[0] and "--wait" not in lance[0] and "timeout" not in lance[0]
    assert "apt-get" in lance[0] and "dist-upgrade" not in lance[0] and "autoremove" not in lance[0]
    for argv in (["renouveler-secrets"], ["maj-paquets"], ["reboot"]):
        rc, sortie, _ = banc.run(*argv, agent=True)
        assert rc == 0 and sortie == {"ok": False, "refus": "opération en cours", "job": job}, argv
    assert len(banc.lancements()) == 1
    # l'opération est finie (unité ramassée) : la suivante part
    banc.actifs.write_text("")
    rc, s2, _ = banc.run("renouveler-secrets", agent=True)
    assert rc == 0 and s2["ok"] is True and s2["job"] != job
    assert "secubox-renouvelle-secrets --tout --oui" in banc.lancements()[-1]


def test_audit_sans_valeur_secrete(banc):
    secret_env = "SECRET-ENV-7731"
    env = {"PILOTAGE_JETON": secret_env, "SBX_JETON": secret_env}
    banc.cliente()
    banc.run("reboot", agent=True, env=env)
    banc.run("service", "redemarrer", "SECRET-ARGV-9902", agent=True, env=env)
    banc.run("renommer", "SECRET_ARGV_9902", agent=True, env=env)
    banc.run("mains-liees", "on", env=env)
    banc.run("mains-liees", "off", env=env)
    banc.run("service", "demarrer", "secubox-lyrion.service", agent=True, env=env)
    texte = (banc.r / "var/log/secubox/audit.log").read_text()
    assert "SECRET" not in texte and "9902" not in texte and "0451" not in texte
    lignes = banc.audit()
    permis = {"ts", "module", "evenement", "box", "verbe", "action", "unite", "acteur", "origine", "job", "resultat",
              "refus", "consentement", "decision", "etat"}
    assert lignes and all(set(e) <= permis for e in lignes), [set(e) - permis for e in lignes]
    assert all(e["module"] == "pilotage" for e in lignes)
    # demande, refus, consentement et résultat : chacun sa ligne
    evts = {e["evenement"] for e in lignes}
    assert {"pilotage_demande", "pilotage_refus", "consentement_demande", "mains_liees", "pilotage_resultat"} <= evts
    demande = next(e for e in lignes if e["evenement"] == "pilotage_demande")
    assert demande["origine"] == "maitre" and demande["acteur"] == AGENT


def test_racine_ignoree_hors_appelant_de_meme_identite(banc):
    """SBX_RACINE n'est honorée que si l'appelant est le processus lui-même (root lancé par root, ou test sans
    privilège) : jamais quand sudo a élevé un autre compte (SUDO_UID différent)."""
    autre = str(os.getuid() + 1)
    rc, sortie, p = banc.run("mains-liees", "on", env={"SUDO_UID": autre})
    assert rc == 2 and "root" in p.stderr
    assert "SBX_RACINE" in p.stderr                                  # nommée comme ignorée, jamais sa valeur
    assert not (banc.r / "etc/secubox/pilotage").exists()
    sans = {k: v for k, v in banc.env.items() if k != "SBX_RACINE"}
    p = subprocess.run([str(CTL), "politique", "reboot"], env=sans, capture_output=True, text=True, timeout=DELAI)
    if os.getuid() != 0:
        assert p.returncode == 2 and "root" in p.stderr


def test_etat_root_non_fiable_refuse_tout(banc):
    """L'arbre d'état du ctl (consentements, mains liées, opération) est root 0700 : sinon tout est refusé."""
    etat = banc.r / "var/lib/secubox-pilotagectl"
    etat.mkdir(mode=0o777)
    etat.chmod(0o777)
    rc, sortie, _ = banc.run("reboot", agent=True)
    assert rc == 1 and sortie == {"ok": False, "erreur": "état non fiable"}
    _, pol, _ = banc.run("politique", "releve", agent=True)
    assert pol["autorise"] is False
    assert banc.lancements() == []
