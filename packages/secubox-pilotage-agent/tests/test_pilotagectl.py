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
# faux systemd-run : note l'argv (une ligne), puis « démarre » l'unité nommée par --unit= (échoue si $FAUX_RUN_ECHEC)
[ -z "$FAUX_RUN_ECHEC" ] || exit 1
printf '%s\\n' "$*" >> "$FAUX_LANCES"
# avec --on-active=, comme le vrai : seule la minuterie est active pendant le délai, le service ne l'est pas encore
suffixe=service
for a in "$@"; do case "$a" in --on-active=*) suffixe=timer ;; esac; done
for a in "$@"; do
  case "$a" in --unit=*) printf '%s.%s\\n' "${a#--unit=}" "$suffixe" >> "$FAUX_ACTIFS" ;; esac
done
exit 0
"""

FAUX_SYSTEMCTL = """#!/bin/sh
# faux systemctl : « show -p ActiveState --value <unité> » → active si l'unité figure dans $FAUX_ACTIFS ;
# « show -p LoadState --value -- <unité> » → not-found si elle figure dans $FAUX_ABSENTES, sinon loaded
unite=""
for a in "$@"; do unite="$a"; done
if [ "$1" = show ] && [ "$3" = LoadState ]; then
  if grep -qx "$unite" "$FAUX_ABSENTES" 2>/dev/null; then echo not-found; else echo loaded; fi
  exit 0
fi
if [ "$1" = show ]; then
  if grep -qx "$unite" "$FAUX_ACTIFS" 2>/dev/null; then echo active; else echo inactive; fi
  exit 0
fi
printf '%s\\n' "$*" >> "$FAUX_LANCES"
exit 0
"""


FAUX_WG = """#!/bin/sh
# faux wg : « show <interface> allowed-ips » → note l'argv, rend $FAUX_WG_SORTIE (échoue si $FAUX_WG_ECHEC)
printf '%s\\n' "$*" >> "$FAUX_WG_APPELS"
[ -z "$FAUX_WG_ECHEC" ] || exit 1
[ "$1" = show ] && [ "$3" = allowed-ips ] || exit 2
cat "$FAUX_WG_SORTIE" 2>/dev/null
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
        for nom, corps in (("systemd-run", FAUX_SYSTEMD_RUN), ("systemctl", FAUX_SYSTEMCTL), ("wg", FAUX_WG)):
            (faux / nom).write_text(corps)
            (faux / nom).chmod(0o755)
        self.lances = tmp_path / "lances"
        self.actifs = tmp_path / "actifs"
        self.absentes = tmp_path / "absentes"
        self.wg_sortie = tmp_path / "wg-sortie"
        self.wg_appels = tmp_path / "wg-appels"
        self.env = {k: v for k, v in os.environ.items() if not k.startswith(("SUDO_", "SBX_"))}
        self.env.update(PATH=f"{faux}:/usr/bin:/bin", SBX_RACINE=str(self.r),
                        FAUX_LANCES=str(self.lances), FAUX_ACTIFS=str(self.actifs),
                        FAUX_ABSENTES=str(self.absentes), FAUX_WG_SORTIE=str(self.wg_sortie),
                        FAUX_WG_APPELS=str(self.wg_appels))

    def cliente(self):
        (self.r / "sys/class/net/wg-mesh").rmdir()
        (self.r / "sys/class/net/wg-autoload").mkdir()

    def ancre(self, cle=None, brut=None):
        """Ancre du maître d'une box du propriétaire (/etc/secubox/p2p/ancre-maitre.json, posée au flash)."""
        f = self.r / "etc/secubox/p2p/ancre-maitre.json"
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(brut if brut is not None else json.dumps(
            {"cle_publique": cle, "adresse": "192.168.1.1", "nom": "gk2", "empreinte": "0123456789abcdef"}))
        f.chmod(0o644)                                   # comme ancre.ecrire (secubox-p2p) et sbx-netflash

    def tunnel_autoload(self, cle_hub):
        """Configuration wg-autoload posée à l'enrôlement par secubox-autoload-agent (clé du hub = hub.pub)."""
        f = self.r / "etc/wireguard/wg-autoload.conf"
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text("# GÉNÉRÉ par secubox-autoload-agent — ne pas éditer (#2189).\n[Interface]\nAddress = 10.64.0.9/32\n"
                     "PostUp = wg set %i private-key /etc/secubox/secrets/autoload-wg.key\n\n[Peer]\n"
                     f"PublicKey = {cle_hub}\nEndpoint = admin.gk2.secubox.in:51820\nAllowedIPs = 10.64.0.1/32\n"
                     "PersistentKeepalive = 25\n")
        f.chmod(0o600)

    def pairs(self, *lignes):
        """Sortie de `wg show <interface> allowed-ips` : « clé<TAB>préfixes »."""
        self.wg_sortie.write_text("".join(f"{c}\t{p}\n" for c, p in lignes))

    def appels_wg(self):
        return self.wg_appels.read_text().splitlines() if self.wg_appels.exists() else []

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
        ["--acteur"],
        ["--acteur", "gk2admin"],
        ["--acteur", "Admin", "reboot"],
        ["--acteur", "9admin", "reboot"],
        ["--acteur", "a" * 65, "reboot"],
        ["--acteur", "x", "--acteur", "y", "reboot"],
        ["reboot", "--acteur", "x"],
        ["_fin"],
        ["_fin", "../x"],
        ["_fin", "0123456789abcdef", "en-trop"],
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
    """R-L2-1 : argv validé pour toute la liste fermée ; support, renommer « non disponible » (code 0) ; ancre-verifier
    est livré (tâche 2) : sans ancre, il rend ok faux, raison « absente »."""
    rc, sortie, _ = banc.run("ancre-verifier", agent=True)
    assert rc == 0 and sortie == {"ok": False, "raison": "absente"}
    for argv in (["support", "ouvrir", "s-01"], ["support", "fermer", "s-01"], ["renommer", "box-2"]):
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
    for unite in ("secubox-pilotage-agent.service", "secubox-pilotage-agent.timer", "secubox-pilotage-agent@x.service"):
        for verbe in ("arreter", "redemarrer", "demarrer"):
            rc, sortie, _ = banc.run("service", verbe, unite, agent=True)
            assert rc == 0 and sortie == {"ok": False, "refus": "unité de l'agent"}, (verbe, unite)
    assert banc.lancements() == []


def test_unites_du_ctl_refusees(banc):
    """I2 : jamais une unité secubox-pilotage-op-* (couper l'unité d'un apt en cours laisserait dpkg à moitié configuré)."""
    rc, s, _ = banc.run("maj-paquets", agent=True)
    job = s["job"]
    for unite in (f"secubox-pilotage-op-{job}.service", "secubox-pilotage-op-x.timer", "secubox-pilotage-op-a@b.service",
                  "secubox-pilotage-op-.service"):
        for verbe in ("arreter", "redemarrer", "demarrer"):
            rc, sortie, _ = banc.run("service", verbe, unite, agent=True)
            assert rc == 0 and sortie == {"ok": False, "refus": "unité du ctl"}, (verbe, unite)
            rc, sortie, _ = banc.run("service", verbe, unite)          # même en local
            assert sortie == {"ok": False, "refus": "unité du ctl"}, (verbe, unite)
    assert len(banc.lancements()) == 1


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
    # M6 : le reboot est une opération exclusive ; sa fin (ExecStopPost) la libère
    _fin(banc, sortie["job"], "success", "exited", "0")
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
              "refus", "consentement", "decision", "etat", "rc"}
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
    # M5 : le refus est audité après la demande
    evts = [(e["evenement"], e.get("refus")) for e in banc.audit()]
    assert evts == [("pilotage_demande", None), ("pilotage_refus", "état non fiable")]
    _, pol, _ = banc.run("politique", "releve", agent=True)
    assert pol["autorise"] is False
    assert banc.lancements() == []


def _fin(banc, job, service_result, exit_code, exit_status, **kw):
    env = {"SERVICE_RESULT": service_result, "EXIT_CODE": exit_code, "EXIT_STATUS": exit_status}
    return banc.run("_fin", job, env=env, **kw)


def test_fin_d_operation_auditee(banc):
    """R-L2-11 : chaque unité transitoire porte ExecStopPost=… _fin <job> ; _fin audite succès ou échec et libère
    l'opération longue. Interne : refusé depuis l'agent."""
    rc, s1, _ = banc.run("maj-paquets", agent=True)
    job = s1["job"]
    assert f"--property=ExecStopPost=/usr/sbin/secubox-pilotagectl _fin {job}" in banc.lancements()[0]
    rc, s2, _ = banc.run("service", "demarrer", "secubox-lyrion.service", agent=True)
    assert f"--property=ExecStopPost=/usr/sbin/secubox-pilotagectl _fin {s2['job']}" in banc.lancements()[1]
    # l'agent ne clôt pas une opération à la place de systemd
    rc, sortie, _ = _fin(banc, job, "success", "exited", "0", agent=True)
    assert rc == 0 and sortie == {"ok": False, "refus": "local seulement"}
    rc, sortie, _ = banc.run("maj-paquets", agent=True)
    assert sortie["refus"] == "opération en cours"
    # fin réelle (PID 1, root, sans SUDO_*) : succès audité, opération libérée même si l'unité n'est pas encore ramassée
    rc, sortie, _ = _fin(banc, job, "success", "exited", "0")
    assert rc == 0 and sortie == {"ok": True, "job": job, "resultat": "succes"}
    fins = [e for e in banc.audit() if e["evenement"] == "pilotage_resultat" and e.get("resultat") in ("succes", "echec")]
    assert len(fins) == 1 and fins[0]["job"] == job and fins[0]["rc"] == "0" and fins[0]["verbe"] == "maj-paquets"
    rc, s3, _ = banc.run("renouveler-secrets", agent=True)
    assert s3["ok"] is True
    # échec : code de sortie gardé (nombre seulement)
    rc, sortie, _ = _fin(banc, s3["job"], "exit-code", "exited", "100")
    assert sortie["resultat"] == "echec"
    rc, sortie, _ = _fin(banc, s2["job"], "signal", "killed", "TERM; rm -rf /")
    assert sortie["resultat"] == "echec"
    fins = [e for e in banc.audit() if e["evenement"] == "pilotage_resultat" and e.get("resultat") == "echec"]
    assert [e.get("rc") for e in fins] == ["100", None]
    assert "rm -rf" not in (banc.r / "var/log/secubox/audit.log").read_text()
    # une fin d'un autre job ne libère pas l'opération en cours
    rc, s4, _ = banc.run("maj-paquets", agent=True)
    _fin(banc, "0123456789abcdef", "success", "exited", "0")
    rc, sortie, _ = banc.run("maj-paquets", agent=True)
    assert sortie == {"ok": False, "refus": "opération en cours", "job": s4["job"]}


def test_reboot_bloque_les_operations_longues(banc):
    """M6 : le reboot (différé de 5 s) est enregistré comme opération : rien de long ne démarre pendant ce délai."""
    rc, s, _ = banc.run("reboot", agent=True)
    assert s["ok"] is True
    rc, sortie, _ = banc.run("maj-paquets", agent=True)
    assert sortie == {"ok": False, "refus": "opération en cours", "job": s["job"]}


def test_consentement_seulement_pour_une_unite_existante(banc):
    """M10 : pas de consentement en attente pour une unité inconnue de systemd."""
    banc.cliente()
    banc.absentes.write_text("secubox-fantome.service\n")
    rc, sortie, _ = banc.run("service", "redemarrer", "secubox-fantome.service", agent=True)
    assert rc == 0 and sortie == {"ok": False, "refus": "unité inconnue"}
    assert not any(e["evenement"] == "consentement_demande" for e in banc.audit())
    assert banc.lancements() == []


def test_expiration_auditee_une_seule_fois(banc):
    """M10 : un consentement expiré est audité une fois, pas à chaque appel (même sur un chemin qui n'écrit rien)."""
    banc.cliente()
    _, s, _ = banc.run("reboot", agent=True)
    _, s2, _ = banc.run("maj-paquets", agent=True)
    banc.run("consentement", "accepter", s2["consentement"])
    f = banc.r / "var/lib/secubox-pilotagectl/consentements.json"
    liste = json.loads(f.read_text())
    next(c for c in liste if c["id"] == s["consentement"])["expire"] = 1
    f.write_text(json.dumps(liste))
    # l'accord de maj-paquets est trouvé, mais le lancement échoue : avant correction, rien n'était réécrit
    for _ in range(2):
        rc, sortie, _ = banc.run("maj-paquets", agent=True, env={"FAUX_RUN_ECHEC": "1"})
        assert rc == 1 and sortie == {"ok": False, "erreur": "lancement impossible"}
    banc.run("consentement", "accepter", s["consentement"])
    assert [e["evenement"] for e in banc.audit()].count("consentement_expire") == 1


def test_gabarit_exige_le_consentement_sur_cliente(banc):
    """R-L2-13 : sur une box cliente, une unité gabarit (« @ ») exige l'accord, même pour démarrer."""
    rc, sortie, _ = banc.run("service", "demarrer", "secubox-foo@bar.service", agent=True)
    assert sortie["ok"] is True                                     # box du propriétaire : libre
    banc.cliente()
    rc, sortie, _ = banc.run("service", "demarrer", "secubox-foo@bar.service", agent=True)
    assert sortie["refus"] == "consentement requis"
    rc, sortie, _ = banc.run("service", "demarrer", "secubox-lyrion.service", agent=True)
    assert sortie["ok"] is True


def test_acteur_du_maitre_audite(banc):
    """R-L2-14 : --acteur <login> en tête de l'argv ; absent, l'acteur d'un appel de l'agent vaut son compte."""
    rc, sortie, _ = banc.run("--acteur", "gk2admin", "service", "demarrer", "secubox-lyrion.service", agent=True)
    assert rc == 0 and sortie["ok"] is True
    rc, sortie, _ = banc.run("--acteur", "_ops.x-1", "politique", "reboot", agent=True)
    assert rc == 0 and sortie["autorise"] is True
    banc.run("--acteur", "gk2admin", "renouveler-secrets", agent=True)
    assert "--setenv=SUDO_USER=gk2admin" in banc.lancements()[-1]
    _fin(banc, banc.lancements()[-1].split("--unit=secubox-pilotage-op-")[1][:16], "success", "exited", "0")
    banc.run("reboot", agent=True)
    demandes = [e for e in banc.audit() if e["evenement"] == "pilotage_demande"]
    assert [e["acteur"] for e in demandes] == ["gk2admin", "gk2admin", AGENT]
    assert all(e["origine"] == "maitre" for e in demandes)


# --- Tâche 2 : vérification de l'ancre (D1) -------------------------------------------------------------------------

CLE_MAITRE = "mAiTrE" + "A" * 37 + "="          # 44 caractères : forme d'une clé publique WireGuard
CLE_AUTRE = "aUtRe" + "B" * 38 + "="
CLE_PAIR = "pAiR" + "C" * 39 + "="


def refus_ancre(banc):
    return [e for e in banc.audit() if e["evenement"] == "pilotage_refus" and e.get("verbe") == "ancre-verifier"]


def test_ancre_conforme(banc):
    """Box du propriétaire : le pair de wg-mesh qui porte 10.10.0.1 a la clé de ancre-maitre.json → ok vrai, depuis
    l'agent (lecture permise), sans refus audité. Box cliente : wg-autoload, clé du hub posée à l'enrôlement."""
    banc.ancre(CLE_MAITRE)
    banc.pairs((CLE_PAIR, "10.10.0.7/32"), (CLE_MAITRE, "10.10.0.0/24 192.168.50.0/24"))
    rc, sortie, p = banc.run("ancre-verifier", agent=True)
    assert rc == 0 and sortie == {"ok": True}, p.stderr
    assert banc.appels_wg() == ["show wg-mesh allowed-ips"]
    assert refus_ancre(banc) == []
    banc.cliente()
    banc.tunnel_autoload(CLE_MAITRE)
    banc.pairs((CLE_MAITRE, "10.64.0.1/32"))
    rc, sortie, p = banc.run("ancre-verifier", agent=True)
    assert rc == 0 and sortie == {"ok": True}, p.stderr
    assert banc.appels_wg()[-1] == "show wg-autoload allowed-ips"
    assert refus_ancre(banc) == [] and banc.lancements() == []


def test_ancre_differente_refuse(banc):
    """Le pair qui porte l'adresse du maître n'a pas la clé de l'ancre → ok faux, raison « differente », refus
    « ancre différente » audité. Le pair retenu est celui que WireGuard choisirait : le préfixe le plus long qui
    contient l'adresse du maître ; aucun pair ne la porte → différente aussi (le maître ancré n'est pas joignable)."""
    banc.ancre(CLE_MAITRE)
    differente = {"ok": False, "raison": "differente"}
    banc.pairs((CLE_AUTRE, "10.10.0.0/24"))
    assert banc.run("ancre-verifier", agent=True)[:2] == (0, differente)
    # un pair qui s'approprie 10.10.0.1/32 l'emporte sur le /24 légitime : refusé
    banc.pairs((CLE_MAITRE, "10.10.0.0/24"), (CLE_AUTRE, "10.10.0.1/32"))
    assert banc.run("ancre-verifier", agent=True)[:2] == (0, differente)
    for lignes in (((CLE_MAITRE, "10.10.1.0/24"),), ((CLE_MAITRE, "(none)"),)):
        banc.pairs(*lignes)
        assert banc.run("ancre-verifier", agent=True)[:2] == (0, differente), lignes
    refus = refus_ancre(banc)
    assert [e["refus"] for e in refus] == ["ancre différente"] * 4
    assert all(e["origine"] == "maitre" for e in refus)
    # aucune clé recopiée dans l'audit
    texte = (banc.r / "var/log/secubox/audit.log").read_text()
    assert "mAiTrE" not in texte and "aUtRe" not in texte
    # box cliente : le hub vu dans wg-autoload n'est pas celui posé à l'enrôlement
    banc.cliente()
    banc.tunnel_autoload(CLE_MAITRE)
    banc.pairs((CLE_AUTRE, "10.64.0.1/32"))
    assert banc.run("ancre-verifier", agent=True)[:2] == (0, differente)


def test_ancre_absente_rend_absente(banc):
    """R-L2-19 : aucune ancre posée (box du propriétaire jointe à la main, sans ancre-maitre.json ; box cliente sans
    configuration wg-autoload) → ok faux, raison « absente », code 0, refus « ancre absente » audité ; wg n'est pas
    interrogé (rien à comparer). L'agent garde alors le canal en lecture et refuse toute action."""
    banc.pairs((CLE_MAITRE, "10.10.0.0/24 10.64.0.1/32"))
    rc, sortie, _ = banc.run("ancre-verifier", agent=True)
    assert rc == 0 and sortie == {"ok": False, "raison": "absente"}
    banc.cliente()
    rc, sortie, _ = banc.run("ancre-verifier", agent=True)
    assert rc == 0 and sortie == {"ok": False, "raison": "absente"}
    assert banc.appels_wg() == []
    assert [e["refus"] for e in refus_ancre(banc)] == ["ancre absente", "ancre absente"]
    assert banc.lancements() == []


def test_ancre_illisible_jamais_vraie(banc):
    """Toute erreur de lecture (JSON invalide, clé mal formée, lien, droits d'écriture du groupe ou des autres
    (R-L2-20), wg en échec, sortie de wg illisible, configuration wg-autoload non root) rend ok faux, raison
    « illisible », code 0, avec un refus « ancre illisible » audité ; jamais ok vrai."""
    banc.pairs((CLE_MAITRE, "10.10.0.0/24"))
    resultats = []

    def verdict(env=None):
        rc, sortie, _ = banc.run("ancre-verifier", agent=True, env=env)
        resultats.append((rc, sortie))

    f = banc.r / "etc/secubox/p2p/ancre-maitre.json"
    for brut in ("{pas du json", json.dumps({"cle_publique": "courte"}), json.dumps(["x"]),
                 json.dumps({"adresse": "10.0.0.1"}), json.dumps({"cle_publique": CLE_MAITRE + "\n"})):
        banc.ancre(brut=brut)
        verdict()
    # ancre inscriptible par le groupe ou les autres (R-L2-20 : root ou secubox, sans écriture groupe/autres)
    banc.ancre(CLE_MAITRE)
    for mode in (0o664, 0o646):
        f.chmod(mode)
        verdict()
    f.chmod(0o644)
    # ancre par lien symbolique (le dossier /etc/secubox appartient au compte partagé secubox) : jamais suivie
    vraie = banc.r / "ancre-ailleurs.json"
    vraie.write_text(json.dumps({"cle_publique": CLE_MAITRE}))
    f.unlink()
    f.symlink_to(vraie)
    verdict()
    f.unlink()
    banc.ancre(CLE_MAITRE)
    verdict(env={"FAUX_WG_ECHEC": "1"})                  # wg en échec
    banc.pairs(("pas-une-cle", "10.10.0.0/24"))           # sortie de wg illisible
    verdict()
    banc.pairs((CLE_MAITRE, "10.10.0.0/33"))
    verdict()
    # box cliente : configuration wg-autoload inscriptible par d'autres, ou sans pair
    banc.cliente()
    banc.pairs((CLE_MAITRE, "10.64.0.1/32"))
    banc.tunnel_autoload(CLE_MAITRE)
    (banc.r / "etc/wireguard/wg-autoload.conf").chmod(0o622)
    verdict()
    (banc.r / "etc/wireguard/wg-autoload.conf").write_text("[Interface]\nAddress = 10.64.0.9/32\n")
    (banc.r / "etc/wireguard/wg-autoload.conf").chmod(0o600)
    verdict()
    assert all(r == (0, {"ok": False, "raison": "illisible"}) for r in resultats), resultats
    assert [e["refus"] for e in refus_ancre(banc)] == ["ancre illisible"] * len(resultats)
    assert banc.lancements() == []
