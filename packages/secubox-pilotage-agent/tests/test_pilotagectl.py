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
# $FAUX_CASSE : ce fichier d'état devient un dossier non vide pendant le lancement (l'écriture qui suit échoue,
# comme sur un disque plein)
if [ -n "$FAUX_CASSE" ]; then rm -f "$FAUX_CASSE"; mkdir -p "$FAUX_CASSE/x"; fi
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
[ -z "$FAUX_SYSTEMCTL_ECHEC" ] || exit 1
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


CLE_MAITRE = "mAiTrE" + "A" * 37 + "="          # 44 caractères : forme d'une clé publique WireGuard
CLE_AUTRE = "aUtRe" + "B" * 38 + "="
CLE_PAIR = "pAiR" + "C" * 39 + "="


class Banc:
    def __init__(self, tmp_path: Path, ancree=True):
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
        self.ancree = ancree
        if ancree:
            self.ancrer()

    def ancrer(self):
        """R-L2-21/26 : une ancre vérifiée par le ctl (canal enregistré) est le préalable de toute demande du maître.
        Pose l'ancre du canal courant (wg-mesh, ou wg-autoload sur une box cliente) et la fait vérifier, comme l'agent."""
        if (self.r / "sys/class/net/wg-autoload").exists():
            self.tunnel_autoload(CLE_MAITRE)
            self.pairs((CLE_MAITRE, "10.64.0.1/32"))
        else:
            self.ancre(CLE_MAITRE)
            self.pairs((CLE_MAITRE, "10.10.0.0/24"))
        rc, sortie, p = self.ancre_verifier()
        assert (rc, sortie) == (0, {"ok": True}), p.stderr
        self.wg_appels.unlink(missing_ok=True)

    def ancre_verifier(self, env=None):
        """`ancre-verifier <interface>` comme l'agent l'appelle : l'interface de son canal (R-L2-23)."""
        canal = "wg-autoload" if (self.r / "sys/class/net/wg-autoload").exists() else "wg-mesh"
        return self.run("ancre-verifier", canal, agent=True, env=env)

    def cliente(self):
        (self.r / "sys/class/net/wg-mesh").rmdir()
        (self.r / "sys/class/net/wg-autoload").mkdir()
        if self.ancree:
            self.ancrer()                                # le canal vérifié devient wg-autoload : box cliente

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

    def run(self, *args, agent=False, env=None, entree=""):
        e = dict(self.env)
        if agent:
            e["SUDO_USER"] = AGENT
        e.update(env or {})
        p = subprocess.run([str(CTL), *args], env=e, capture_output=True, text=True, timeout=DELAI, input=entree)
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


@pytest.fixture
def banc_nu(tmp_path):
    """Sans ancre vérifiée (tâche 2 et R-L2-21)."""
    return Banc(tmp_path, ancree=False)


ACTIONS = ("releve", "reboot", "maj-paquets", "service-demarrer", "service-arreter", "service-redemarrer",
           "renommer", "renouveler-secrets", "support-ouvrir", "support-fermer", "maillage-rejoindre")


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
        ["ancre-verifier"],
        ["ancre-verifier", "wg-mesh", "en-trop"],
        ["ancre-verifier", "wg-mesh0"],
        ["ancre-verifier", "eth0"],
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
        # tâche 4 : support (durée entière de 1 à 240, sans zéro de tête), etat sans argument
        ["support", "ouvrir", "s1", "0"],
        ["support", "ouvrir", "s1", "241"],
        ["support", "ouvrir", "s1", "030"],
        ["support", "ouvrir", "s1", "30.5"],
        ["support", "ouvrir", "s1", "-5"],
        ["support", "ouvrir", "s1", "30", "en-trop"],
        ["support", "fermer", "s1", "30"],
        ["support", "accepter"],
        ["support", "accepter", "s1", "30"],
        ["support", "refuser", "../s1"],
        ["etat", "en-trop"],
        # tâche 5 : le code de maillage-rejoindre passe par l'entrée standard, jamais par l'argv
        ["maillage-rejoindre", "sbxmesh1.SECRET-ARGV.abcd"],
        ["_rejoindre"],
        ["_rejoindre", "../x"],
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


def test_verbes_valides_acceptes_ou_non_disponibles(banc_nu):
    """R-L2-1 : argv validé pour toute la liste fermée ; renommer livré (tâche 5) ; ancre-verifier est livré
    (tâche 2) : sans ancre, il rend ok faux, raison « absente » ; support (tâche 4) : sans ancre, refusé au maître."""
    banc = banc_nu
    rc, sortie, _ = banc.ancre_verifier()
    assert rc == 0 and sortie == {"ok": False, "raison": "absente"}
    for argv in (["support", "ouvrir", "s-01"], ["renommer", "box-2"], ["maillage-rejoindre"], ["support", "ouvrir", "s-01", "240"], ["support", "fermer", "s-01"]):
        rc, sortie, _ = banc.run(*argv, agent=True)
        assert rc == 0 and sortie == {"ok": False, "refus": "ancre non vérifiée"}, argv
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
    etat.mkdir(mode=0o777, exist_ok=True)                # déjà créé par la vérification de l'ancre
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
    assert f"--property=ExecStopPost=+/usr/sbin/secubox-pilotagectl _fin {job}" in banc.lancements()[0]
    rc, s2, _ = banc.run("service", "demarrer", "secubox-lyrion.service", agent=True)
    assert f"--property=ExecStopPost=+/usr/sbin/secubox-pilotagectl _fin {s2['job']}" in banc.lancements()[1]
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

def refus_ancre(banc):
    return [e for e in banc.audit() if e["evenement"] == "pilotage_refus" and e.get("verbe") == "ancre-verifier"]


def test_ancre_conforme(banc_nu):
    """Box du propriétaire : le pair de wg-mesh qui porte 10.10.0.1 a la clé de ancre-maitre.json → ok vrai, depuis
    l'agent (lecture permise), sans refus audité. Box cliente : wg-autoload, clé du hub posée à l'enrôlement."""
    banc = banc_nu
    banc.ancre(CLE_MAITRE)
    banc.pairs((CLE_PAIR, "10.10.0.7/32"), (CLE_MAITRE, "10.10.0.0/24 192.168.50.0/24"))
    rc, sortie, p = banc.ancre_verifier()
    assert rc == 0 and sortie == {"ok": True}, p.stderr
    assert banc.appels_wg() == ["show wg-mesh allowed-ips"]
    assert refus_ancre(banc) == []
    banc.cliente()
    banc.tunnel_autoload(CLE_MAITRE)
    banc.pairs((CLE_MAITRE, "10.64.0.1/32"))
    rc, sortie, p = banc.ancre_verifier()
    assert rc == 0 and sortie == {"ok": True}, p.stderr
    assert banc.appels_wg()[-1] == "show wg-autoload allowed-ips"
    assert refus_ancre(banc) == [] and banc.lancements() == []


def test_ancre_differente_refuse(banc_nu):
    """Le pair qui porte l'adresse du maître n'a pas la clé de l'ancre → ok faux, raison « differente », refus
    « ancre différente » audité. Le pair retenu est celui que WireGuard choisirait : le préfixe le plus long qui
    contient l'adresse du maître ; aucun pair ne la porte → différente aussi (le maître ancré n'est pas joignable)."""
    banc = banc_nu
    banc.ancre(CLE_MAITRE)
    differente = {"ok": False, "raison": "differente"}
    banc.pairs((CLE_AUTRE, "10.10.0.0/24"))
    assert banc.ancre_verifier()[:2] == (0, differente)
    # un pair qui s'approprie 10.10.0.1/32 l'emporte sur le /24 légitime : refusé
    banc.pairs((CLE_MAITRE, "10.10.0.0/24"), (CLE_AUTRE, "10.10.0.1/32"))
    assert banc.ancre_verifier()[:2] == (0, differente)
    for lignes in (((CLE_MAITRE, "10.10.1.0/24"),), ((CLE_MAITRE, "(none)"),)):
        banc.pairs(*lignes)
        assert banc.ancre_verifier()[:2] == (0, differente), lignes
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
    assert banc.ancre_verifier()[:2] == (0, differente)


def test_ancre_absente_rend_absente(banc_nu):
    """R-L2-19 : aucune ancre posée (box du propriétaire jointe à la main, sans ancre-maitre.json ; box cliente sans
    configuration wg-autoload) → ok faux, raison « absente », code 0, refus « ancre absente » audité ; wg n'est pas
    interrogé (rien à comparer). L'agent garde alors le canal en lecture et refuse toute action."""
    banc = banc_nu
    banc.pairs((CLE_MAITRE, "10.10.0.0/24 10.64.0.1/32"))
    rc, sortie, _ = banc.ancre_verifier()
    assert rc == 0 and sortie == {"ok": False, "raison": "absente"}
    banc.cliente()
    rc, sortie, _ = banc.ancre_verifier()
    assert rc == 0 and sortie == {"ok": False, "raison": "absente"}
    assert banc.appels_wg() == []
    assert [e["refus"] for e in refus_ancre(banc)] == ["ancre absente", "ancre absente"]
    assert banc.lancements() == []


def test_ancre_illisible_jamais_vraie(banc_nu):
    """Toute erreur de lecture (JSON invalide, clé mal formée, lien, droits d'écriture du groupe ou des autres
    (R-L2-20), wg en échec, sortie de wg illisible, configuration wg-autoload non root) rend ok faux, raison
    « illisible », code 0, avec un refus « ancre illisible » audité ; jamais ok vrai."""
    banc = banc_nu
    banc.pairs((CLE_MAITRE, "10.10.0.0/24"))
    resultats = []

    def verdict(env=None):
        rc, sortie, _ = banc.ancre_verifier(env=env)
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


def test_ancre_canal_incoherent_illisible(banc_nu):
    """R-L2-23 : le ctl vérifie l'interface du canal que l'agent utilise (argument fermé) ; wg-mesh suppose
    ancre-maitre.json, wg-autoload la configuration cliente. L'ancre de l'autre canal présente seule → « illisible »
    (jamais « absente », qui garderait la lecture) ; wg-mesh présente mais sans adresse ne trompe plus le choix."""
    banc = banc_nu
    banc.pairs((CLE_MAITRE, "10.10.0.0/24 10.64.0.1/32"))
    banc.ancre(CLE_MAITRE)                                  # box du propriétaire, ancre posée
    rc, sortie, _ = banc.run("ancre-verifier", "wg-autoload", agent=True)
    assert rc == 0 and sortie == {"ok": False, "raison": "illisible"}
    assert banc.appels_wg() == []
    (banc.r / "etc/secubox/p2p/ancre-maitre.json").unlink()
    banc.tunnel_autoload(CLE_MAITRE)                        # configuration cliente seule, wg-mesh encore présente
    rc, sortie, _ = banc.run("ancre-verifier", "wg-mesh", agent=True)
    assert rc == 0 and sortie == {"ok": False, "raison": "illisible"}
    # le canal réellement utilisé (wg-autoload, wg-mesh sans adresse) est vérifié, quoi qu'en dise /sys/class/net
    rc, sortie, _ = banc.run("ancre-verifier", "wg-autoload", agent=True)
    assert rc == 0 and sortie == {"ok": True}
    assert banc.appels_wg() == ["show wg-autoload allowed-ips"]
    assert [e["refus"] for e in refus_ancre(banc)] == ["ancre illisible", "ancre illisible"]


def test_ancre_sortie_wg_non_utf8_auditee(banc_nu):
    """M2 : une sortie de wg non décodable (ou toute exception imprévue) rend « illisible », code 0, et l'échec est
    audité — jamais une « erreur interne » muette."""
    banc = banc_nu
    banc.ancre(CLE_MAITRE)
    banc.wg_sortie.write_bytes(CLE_MAITRE.encode() + b"\t10.10.0.0/24 \xff\xfe\n")
    rc, sortie, _ = banc.ancre_verifier()
    assert rc == 0 and sortie == {"ok": False, "raison": "illisible"}
    assert [e["refus"] for e in refus_ancre(banc)] == ["ancre illisible"]


# --- Tâche 3 : défense en profondeur (R-L2-21, R-L2-26) et lecture de la fin d'une opération --------------------------

def test_agir_refuse_sans_ancre_verifiee(banc_nu):
    """R-L2-21 : tant qu'aucune ancre n'est vérifiée, le ctl refuse lui-même toute demande d'origine maître (agir et
    politique), et l'audit du refus nomme le verbe. Une demande locale n'est pas concernée."""
    banc = banc_nu
    for argv in (["reboot"], ["maj-paquets"], ["renouveler-secrets"], ["service", "demarrer", "secubox-lyrion.service"]):
        rc, sortie, _ = banc.run("--acteur", "gk2admin", *argv, agent=True)
        assert rc == 0 and sortie == {"ok": False, "refus": "ancre non vérifiée"}, argv
    rc, pol, _ = banc.run("politique", "reboot", agent=True)
    assert rc == 0 and pol == {"autorise": False, "consentement": False, "raison": "ancre non vérifiée"}
    assert banc.lancements() == []
    refus = [e for e in banc.audit() if e["evenement"] == "pilotage_refus" and e.get("refus") == "ancre non vérifiée"]
    assert [e["verbe"] for e in refus] == ["reboot", "maj-paquets", "renouveler-secrets", "service", "politique"]
    assert all(e["origine"] == "maitre" for e in refus) and refus[0]["acteur"] == "gk2admin"
    # en local, le détenteur agit sans ancre
    rc, sortie, _ = banc.run("service", "demarrer", "secubox-lyrion.service")
    assert rc == 0 and sortie["ok"] is True
    # ancre vérifiée : l'action part ; une vérification qui échoue ensuite retire le canal enregistré
    banc.ancrer()
    rc, sortie, _ = banc.run("service", "demarrer", "secubox-lyrion.service", agent=True)
    assert sortie["ok"] is True
    banc.pairs((CLE_AUTRE, "10.10.0.0/24"))
    assert banc.ancre_verifier()[1] == {"ok": False, "raison": "differente"}
    rc, sortie, _ = banc.run("service", "demarrer", "secubox-lyrion.service", agent=True)
    assert sortie == {"ok": False, "refus": "ancre non vérifiée"}


def test_canal_verifie_enregistre_par_le_ctl(banc_nu):
    """R-L2-26 : après chaque ancre-verifier réussi, le canal vérifié est écrit (état root, écriture atomique)."""
    banc = banc_nu
    banc.ancrer()
    f = banc.r / "var/lib/secubox-pilotagectl/ancre.json"
    etat = json.loads(f.read_text())
    assert etat["canal"] == "wg-mesh" and isinstance(etat["verifie"], int)
    assert (f.stat().st_mode & 0o077) == 0
    assert not [n for n in os.listdir(f.parent) if n.startswith(".")]     # aucun temporaire laissé
    # ancre absente ensuite : canal retiré
    (banc.r / "etc/secubox/p2p/ancre-maitre.json").unlink()
    assert banc.ancre_verifier()[1] == {"ok": False, "raison": "absente"}
    assert not f.exists()


def test_nature_lue_dans_le_canal_verifie(banc):
    """R-L2-26 : la nature de la box se lit dans le canal enregistré (wg-autoload = cliente), jamais dans la seule
    présence de wg-mesh : une box qui porte wg-mesh mais dont l'agent parle par wg-autoload est cliente."""
    (banc.r / "sys/class/net/wg-autoload").mkdir()            # wg-mesh ET wg-autoload présentes
    banc.ancrer()                                             # l'agent a vérifié wg-autoload
    assert (banc.r / "sys/class/net/wg-mesh").exists()
    _, pol, _ = banc.run("politique", "reboot", agent=True)
    assert pol == {"autorise": True, "consentement": True, "raison": "box cliente : accord du détenteur"}
    rc, sortie, _ = banc.run("reboot", agent=True)
    assert sortie["refus"] == "consentement requis"
    # canal enregistré périmé (plus de 2 h sans revérification) : plus d'action du maître
    f = banc.r / "var/lib/secubox-pilotagectl/ancre.json"
    f.write_text(json.dumps({"canal": "wg-mesh", "verifie": 1}))
    rc, sortie, _ = banc.run("reboot", agent=True)
    assert sortie == {"ok": False, "refus": "ancre non vérifiée"}
    # canal enregistré illisible : jamais propriétaire par défaut
    f.write_text(json.dumps({"canal": "eth0", "verifie": 2**40}))
    rc, sortie, _ = banc.run("reboot", agent=True)
    assert sortie == {"ok": False, "refus": "ancre non vérifiée"}


def test_etat_operation_lu_par_l_agent(banc):
    """Lecture de la fin d'une opération (l'unité --collect est ramassée : son code n'est plus lisible par systemctl) :
    `etat-operation <job>`, permis depuis l'agent, en lecture seule, audité (pilotage_lecture)."""
    rc, s, _ = banc.run("maj-paquets", agent=True)
    job = s["job"]
    rc, sortie, _ = banc.run("etat-operation", job, agent=True)
    assert rc == 0 and sortie == {"ok": True, "job": job, "etat": "en_cours"}
    banc.actifs.write_text("")
    _fin(banc, job, "exit-code", "exited", "100")
    rc, sortie, _ = banc.run("etat-operation", job, agent=True)
    assert rc == 0 and sortie == {"ok": True, "job": job, "etat": "termine", "verbe": "maj-paquets", "resultat": "echec",
                                  "rc": 100}
    rc, s2, _ = banc.run("service", "demarrer", "secubox-lyrion.service", agent=True)
    _fin(banc, s2["job"], "signal", "killed", "TERM")
    rc, sortie, _ = banc.run("etat-operation", s2["job"], agent=True)
    assert sortie == {"ok": True, "job": s2["job"], "etat": "termine", "verbe": "service", "resultat": "echec",
                      "rc": None}
    rc, sortie, _ = banc.run("etat-operation", "0123456789abcdef", agent=True)
    assert rc == 0 and sortie == {"ok": True, "job": "0123456789abcdef", "etat": "inconnu"}
    lectures = [e for e in banc.audit() if e["evenement"] == "pilotage_lecture"]
    assert [e["job"] for e in lectures] == [job, job, s2["job"], "0123456789abcdef"]
    assert all(e["verbe"] == "etat-operation" and e["origine"] == "maitre" for e in lectures)
    # lecture seule : rien de lancé, l'opération n'est ni libérée ni touchée
    assert len(banc.lancements()) == 2
    for argv in (["etat-operation"], ["etat-operation", "../x"], ["etat-operation", job, "en-trop"]):
        rc, sortie, _ = banc.run(*argv, agent=True)
        assert rc == 2 and sortie == {"ok": False, "refus": "argv invalide"}, argv


# --- Tâche 3, tour de correction (R-L2-28) --------------------------------------------------------------------------

def test_fin_auditee_meme_si_fins_illisible(banc):
    """M1 : un fins.json illisible n'empêche jamais l'audit de la fin d'une opération (repartir d'une liste vide)."""
    rc, s, _ = banc.run("maj-paquets", agent=True)
    fins = banc.r / "var/lib/secubox-pilotagectl/fins.json"
    fins.write_text("{pas du json")
    rc, sortie, p = _fin(banc, s["job"], "success", "exited", "0")
    assert rc == 0 and sortie == {"ok": True, "job": s["job"], "resultat": "succes"}, p.stderr
    assert "fins.json" in p.stderr                                  # anomalie journalisée
    fin = [e for e in banc.audit() if e["evenement"] == "pilotage_resultat" and e.get("resultat") == "succes"]
    assert len(fin) == 1 and fin[0]["job"] == s["job"] and fin[0]["verbe"] == "maj-paquets"
    # l'opération exclusive est libérée, et la fin est relue par etat-operation
    rc, sortie, _ = banc.run("etat-operation", s["job"], agent=True)
    assert sortie["etat"] == "termine" and sortie["resultat"] == "succes"


def test_ecriture_des_fins_manquee_apres_lancement(banc):
    """M2 : l'opération est partie ; une écriture de fins.json qui échoue ensuite (disque plein) ne change pas la
    réponse : {"ok": true, "job"}, « lance » audité, écriture manquée journalisée."""
    fins = banc.r / "var/lib/secubox-pilotagectl/fins.json"
    rc, sortie, p = banc.run("service", "demarrer", "secubox-lyrion.service", agent=True,
                             env={"FAUX_CASSE": str(fins)})
    assert rc == 0 and sortie["ok"] is True and len(sortie["job"]) == 16, (sortie, p.stderr)
    assert "fins.json" in p.stderr
    lances = [e for e in banc.audit() if e["evenement"] == "pilotage_resultat" and e.get("resultat") == "lance"]
    assert len(lances) == 1 and lances[0]["job"] == sortie["job"]
    assert len(banc.lancements()) == 1
    assert not [n for n in os.listdir(fins.parent) if n.startswith(".")]   # aucun temporaire laissé


def test_ecriture_de_l_operation_manquee_apres_lancement(banc):
    """R-L2-29 : operation.json qui ne s'écrit pas APRÈS un lancement réussi → réponse ok, « lance » audité,
    écriture manquée journalisée, aucun temporaire laissé."""
    etat = banc.r / "var/lib/secubox-pilotagectl"
    rc, sortie, p = banc.run("maj-paquets", agent=True, env={"FAUX_CASSE": str(etat / "operation.json")})
    assert rc == 0 and sortie["ok"] is True and len(sortie["job"]) == 16, (sortie, p.stderr)
    assert "operation.json" in p.stderr
    lances = [e for e in banc.audit() if e["evenement"] == "pilotage_resultat" and e.get("resultat") == "lance"]
    assert len(lances) == 1 and lances[0]["job"] == sortie["job"]
    assert not [n for n in os.listdir(etat) if n.startswith(".")]


def test_consentement_non_consomme_apres_lancement(banc):
    """R-L2-29 : l'accord est trouvé, l'action part, mais consentements.json ne s'écrit pas : réponse ok, « lance »
    audité, et l'anomalie (accord qui pourrait resservir) journalisée et auditée, sans nouvel essai."""
    banc.cliente()
    _, s, _ = banc.run("reboot", agent=True)
    ident = s["consentement"]
    banc.run("consentement", "accepter", ident)
    etat = banc.r / "var/lib/secubox-pilotagectl"
    rc, sortie, p = banc.run("reboot", agent=True, env={"FAUX_CASSE": str(etat / "consentements.json")})
    assert rc == 0 and sortie["ok"] is True and len(sortie["job"]) == 16, (sortie, p.stderr)
    assert "consentements.json" in p.stderr
    evts = banc.audit()
    anomalie = [e for e in evts if e["evenement"] == "consentement_non_consomme"]
    assert len(anomalie) == 1 and anomalie[0]["consentement"] == ident and anomalie[0]["job"] == sortie["job"]
    assert not any(e["evenement"] == "consentement_utilise" for e in evts)
    lances = [e for e in evts if e["evenement"] == "pilotage_resultat" and e.get("resultat") == "lance"]
    assert len(lances) == 1 and lances[0]["job"] == sortie["job"]


def test_ecriture_avant_lancement_refuse_toujours(banc):
    """R-L2-29 : une écriture d'état AVANT le lancement qui échoue refuse : rien ne part (consentement en attente)."""
    banc.cliente()
    etat = banc.r / "var/lib/secubox-pilotagectl"
    (etat / "consentements.json").mkdir()
    (etat / "consentements.json" / "x").mkdir()
    rc, sortie, _ = banc.run("reboot", agent=True)
    assert rc != 0 and sortie["ok"] is False
    assert banc.lancements() == []


# --- Tâche 4 : support, état lu par l'agent et par la commande locale ------------------------------------------------

PERMIS_AUDIT = {"ts", "module", "evenement", "box", "verbe", "action", "unite", "acteur", "origine", "job", "resultat",
                "refus", "consentement", "decision", "etat", "rc", "support", "duree_min", "fin", "op"}


def lire_support(banc):
    return json.loads((banc.r / "var/lib/secubox-pilotagectl/support.json").read_text())


def ecrire_support(banc, sup):
    (banc.r / "var/lib/secubox-pilotagectl/support.json").write_text(json.dumps(sup))


def test_support_ouvert_apres_accord_local(banc):
    """Le maître demande, la box accepte en local : le support s'ouvre pour la durée demandée (bornée à 240 min)."""
    rc, sortie, _ = banc.run("--acteur", "gk2admin", "support", "ouvrir", "s-01", "45", agent=True)
    assert rc == 0 and sortie == {"ok": False, "refus": "consentement requis", "support": "s-01"}
    # redemandé : même réponse, pas de seconde demande auditée
    _, encore, _ = banc.run("support", "ouvrir", "s-01", "45", agent=True)
    assert encore == sortie
    # l'agent n'accepte pas à la place du détenteur
    rc, sortie, _ = banc.run("support", "accepter", "s-01", agent=True)
    assert rc == 0 and sortie == {"ok": False, "refus": "local seulement"}
    rc, sortie, _ = banc.run("support", "refuser", "s-01", agent=True)
    assert sortie == {"ok": False, "refus": "local seulement"}
    avant = int(__import__("time").time())
    rc, sortie, _ = banc.run("support", "accepter", "s-01")
    assert rc == 0 and sortie["ok"] is True and sortie["support"] == "s-01" and sortie["etat"] == "ouvert"
    assert avant + 45 * 60 <= sortie["fin"] <= avant + 45 * 60 + 60
    sup = lire_support(banc)
    assert sup["id"] == "s-01" and sup["etat"] == "ouvert" and sup["duree_min"] == 45
    # déjà ouvert : ni seconde ouverture ni seconde décision
    _, sortie, _ = banc.run("support", "ouvrir", "s-01", agent=True)
    assert sortie == {"ok": False, "refus": "support déjà ouvert", "support": "s-01"}
    _, sortie, _ = banc.run("support", "accepter", "s-01")
    assert sortie == {"ok": False, "refus": "support déjà décidé", "support": "s-01"}
    assert banc.lancements() == []                                  # jamais de shell ni d'unité lancée
    evts = banc.audit()
    assert all(set(e) <= PERMIS_AUDIT for e in evts), [set(e) - PERMIS_AUDIT for e in evts]
    demandes = [e for e in evts if e["evenement"] == "support_demande"]
    assert len(demandes) == 1 and demandes[0]["support"] == "s-01" and demandes[0]["duree_min"] == 45
    assert demandes[0]["acteur"] == "gk2admin" and demandes[0]["origine"] == "maitre"
    ouverts = [e for e in evts if e["evenement"] == "support_ouvert"]
    assert len(ouverts) == 1 and ouverts[0]["origine"] == "local" and ouverts[0]["fin"] == sortie_fin(banc)


def sortie_fin(banc):
    return lire_support(banc)["fin"]


def test_support_duree_par_defaut_et_maximum(banc):
    """30 min par défaut, 240 au plus (241 : argv invalide, voir test_argv_invalide_rend_2)."""
    banc.run("support", "ouvrir", "s-01", agent=True)
    assert lire_support(banc)["duree_min"] == 30
    banc.run("support", "refuser", "s-01")
    banc.run("support", "ouvrir", "s-02", "240", agent=True)
    _, sortie, _ = banc.run("support", "accepter", "s-02")
    sup = lire_support(banc)
    assert sup["duree_min"] == 240 and sup["fin"] - sup["ouvert"] == 240 * 60


def test_support_refuse_par_le_detenteur(banc):
    banc.run("support", "ouvrir", "s-01", agent=True)
    rc, sortie, _ = banc.run("support", "refuser", "s-01")
    assert rc == 0 and sortie == {"ok": True, "support": "s-01", "etat": "refuse"}
    _, sortie, _ = banc.run("support", "accepter", "s-01")
    assert sortie == {"ok": False, "refus": "support déjà décidé", "support": "s-01"}
    assert [e["evenement"] for e in banc.audit() if e["evenement"].startswith("support_")] == [
        "support_demande", "support_refuse"]


def test_support_une_session_a_la_fois(banc):
    banc.run("support", "ouvrir", "s-01", agent=True)
    _, sortie, _ = banc.run("support", "ouvrir", "s-02", agent=True)
    assert sortie == {"ok": False, "refus": "support déjà en cours", "support": "s-01"}
    _, sortie, _ = banc.run("support", "accepter", "s-02")
    assert sortie == {"ok": False, "refus": "support inconnu", "support": "s-02"}
    banc.run("support", "accepter", "s-01")
    _, sortie, _ = banc.run("support", "ouvrir", "s-02", agent=True)
    assert sortie == {"ok": False, "refus": "support déjà en cours", "support": "s-01"}
    # fermé : une nouvelle demande remplace l'ancienne session
    banc.run("support", "fermer", "s-01")
    _, sortie, _ = banc.run("support", "ouvrir", "s-02", agent=True)
    assert sortie == {"ok": False, "refus": "consentement requis", "support": "s-02"}


def test_support_ferme_des_deux_cotes(banc):
    """Révocable des deux côtés : par le maître (agent) comme par le détenteur (local), audité avec l'origine."""
    banc.run("support", "ouvrir", "s-01", agent=True)
    banc.run("support", "accepter", "s-01")
    rc, sortie, _ = banc.run("--acteur", "gk2admin", "support", "fermer", "s-01", agent=True)
    assert rc == 0 and sortie == {"ok": True, "support": "s-01", "etat": "ferme"}
    _, sortie, _ = banc.run("support", "fermer", "s-01")
    assert sortie == {"ok": False, "refus": "support déjà fermé", "support": "s-01"}
    banc.run("support", "ouvrir", "s-02", agent=True)
    banc.run("support", "accepter", "s-02")
    rc, sortie, _ = banc.run("support", "fermer", "s-02")
    assert rc == 0 and sortie == {"ok": True, "support": "s-02", "etat": "ferme"}
    # une demande encore en attente se ferme aussi (le maître la retire)
    banc.run("support", "ouvrir", "s-03", agent=True)
    _, sortie, _ = banc.run("support", "fermer", "s-03", agent=True)
    assert sortie["ok"] is True and lire_support(banc)["etat"] == "ferme"
    _, sortie, _ = banc.run("support", "fermer", "s-09", agent=True)
    assert sortie == {"ok": False, "refus": "support inconnu", "support": "s-09"}
    fermes = [(e["support"], e["origine"]) for e in banc.audit() if e["evenement"] == "support_ferme"]
    assert fermes == [("s-01", "maitre"), ("s-02", "local"), ("s-03", "maitre")]


def test_support_expire_seul(banc):
    """La session ouverte expire à sa fin (et une demande non décidée en 24 h) : auditée une seule fois, à la première
    lecture qui suit (l'agent lit l'état à chaque sondage)."""
    banc.run("support", "ouvrir", "s-01", agent=True)
    banc.run("support", "accepter", "s-01")
    sup = lire_support(banc)
    sup["fin"] = int(__import__("time").time()) - 1
    ecrire_support(banc, sup)
    for _ in range(2):
        rc, etat, _ = banc.run("etat", agent=True)
        assert rc == 0 and etat["support"]["etat"] == "expire"
    _, sortie, _ = banc.run("support", "fermer", "s-01", agent=True)
    assert sortie == {"ok": False, "refus": "support déjà fermé", "support": "s-01"}
    # demande en attente depuis plus de 24 h
    banc.run("support", "ouvrir", "s-02", agent=True)
    sup = lire_support(banc)
    sup["expire"] = 1
    ecrire_support(banc, sup)
    _, sortie, _ = banc.run("support", "accepter", "s-02")
    assert sortie == {"ok": False, "refus": "support expiré", "support": "s-02"}
    expires = [e["support"] for e in banc.audit() if e["evenement"] == "support_expire"]
    assert expires == ["s-01", "s-02"]


def test_mains_liees_interdisent_et_ferment_le_support(banc):
    banc.run("support", "ouvrir", "s-01", agent=True)
    banc.run("support", "accepter", "s-01")
    banc.run("mains-liees", "on")
    assert lire_support(banc)["etat"] == "ferme"
    _, sortie, _ = banc.run("support", "ouvrir", "s-02", agent=True)
    assert sortie == {"ok": False, "refus": "mains liées"}
    # même en local, aucune ouverture sous mains liées
    _, sortie, _ = banc.run("support", "ouvrir", "s-02")
    assert sortie == {"ok": False, "refus": "mains liées"}
    banc.run("mains-liees", "off")
    banc.run("support", "ouvrir", "s-03", agent=True)
    banc.run("mains-liees", "on")
    assert lire_support(banc)["etat"] == "annule"
    _, sortie, _ = banc.run("support", "accepter", "s-03")
    assert sortie == {"ok": False, "refus": "mains liées"}
    banc.run("mains-liees", "off")
    _, sortie, _ = banc.run("support", "accepter", "s-03")          # annulée : les mains déliées ne la rouvrent pas
    assert sortie == {"ok": False, "refus": "support annulé", "support": "s-03"}
    fermes = [(e["evenement"], e["support"]) for e in banc.audit() if e["evenement"] in ("support_ferme", "support_annule")]
    assert fermes == [("support_ferme", "s-01"), ("support_annule", "s-03")]


def test_etat_lu_par_l_agent_sans_audit(banc):
    """Verbe de lecture `etat` (agent et local) : mains liées, canal vérifié, consentements, support. Non audité
    (sondé par l'agent) ; seuls les changements qu'il constate (expirations) le sont."""
    rc, etat, _ = banc.run("etat", agent=True)
    assert rc == 0 and etat == {"ok": True, "mains_liees": False, "consentements": [], "support": None}
    _, etat, _ = banc.run("etat")                                   # en local : canal, box et unité de l'agent
    assert etat["canal"] == "wg-mesh" and etat["box"] and "agent" in etat
    banc.cliente()
    _, s, _ = banc.run("reboot", agent=True)
    banc.run("support", "ouvrir", "s-01", "60", agent=True)
    banc.run("mains-liees", "on")
    n = len(banc.audit())
    rc, etat, _ = banc.run("etat", agent=True)
    assert rc == 0 and etat["mains_liees"] is True
    assert etat["consentements"] == [{"id": s["consentement"], "etat": "annule"}]
    assert etat["support"] == {"id": "s-01", "etat": "annule"}
    rc, etat, _ = banc.run("etat")
    assert etat["canal"] == "wg-autoload"
    assert [(c["id"], c["action"], c["etat"]) for c in etat["consentements"]] == [(s["consentement"], "reboot", "annule")]
    assert set(etat["consentements"][0]) <= {"id", "action", "unite", "etat", "cree", "expire", "decide"}
    assert etat["support"] == {"id": "s-01", "etat": "annule", "duree_min": 60, "cree": etat["support"]["cree"],
                               "expire": etat["support"]["expire"]}
    assert len(banc.audit()) == n                                   # lecture : aucune ligne d'audit
    # en local : l'état de l'unité de l'agent en plus (faux systemctl : inactive)
    rc, etat, _ = banc.run("etat")
    assert rc == 0 and etat["agent"] == "inactive"


def test_etat_expire_les_consentements_a_24_h(banc):
    """Un consentement en attente expire à 24 h : la lecture le marque « expire », audité une seule fois."""
    banc.cliente()
    _, s, _ = banc.run("reboot", agent=True)
    _, etat, _ = banc.run("etat")
    c = etat["consentements"][0]
    assert c["etat"] == "en_attente" and c["expire"] - c["cree"] == 24 * 3600
    f = banc.r / "var/lib/secubox-pilotagectl/consentements.json"
    liste = json.loads(f.read_text())
    liste[0]["expire"] = int(__import__("time").time()) - 1
    f.write_text(json.dumps(liste))
    for _ in range(2):
        _, etat, _ = banc.run("etat", agent=True)
        assert etat["consentements"][0]["etat"] == "expire"
    assert [e["consentement"] for e in banc.audit() if e["evenement"] == "consentement_expire"] == [s["consentement"]]
    _, sortie, _ = banc.run("consentement", "accepter", s["consentement"])
    assert sortie == {"ok": False, "refus": "consentement expiré", "consentement": s["consentement"]}


def test_etat_sans_arbre_d_etat(banc_nu):
    """Box neuve (aucun état root encore) : etat répond sans rien créer."""
    rc, etat, _ = banc_nu.run("etat", agent=True)
    assert rc == 0 and etat["ok"] is True and etat["consentements"] == [] and etat["support"] is None
    rc, etat, _ = banc_nu.run("etat")
    assert rc == 0 and etat["canal"] is None
    assert not (banc_nu.r / "var/lib/secubox-pilotagectl").exists()


def test_mains_liees_posees_malgre_un_support_illisible(banc):
    """Lier les mains ne dépend pas de l'état du support : un support.json illisible n'empêche ni la pose ni son audit
    (et aucune session ne peut s'ouvrir sur un état non fiable)."""
    (banc.r / "var/lib/secubox-pilotagectl/support.json").write_text("{pas du json")
    rc, sortie, p = banc.run("mains-liees", "on")
    assert rc == 0 and sortie == {"ok": True, "mains_liees": True}, p.stderr
    assert "support" in p.stderr
    assert [e["etat"] for e in banc.audit() if e["evenement"] == "mains_liees"] == ["on"]
    banc.run("mains-liees", "off")
    rc, sortie, _ = banc.run("support", "ouvrir", "s-01", agent=True)
    assert rc == 1 and sortie == {"ok": False, "erreur": "état non fiable"}


# --- Tâche 4, relecture tour 1 ---------------------------------------------------------------------------------------

def test_mains_liees_posees_malgre_des_consentements_illisibles(banc):
    """I2 : miroir de test_mains_liees_posees_malgre_un_support_illisible pour consentements.json : drapeau, projection
    et audit `mains_liees on`, sans toucher aux consentements."""
    f = banc.r / "var/lib/secubox-pilotagectl/consentements.json"
    f.write_text("{pas du json")
    rc, sortie, p = banc.run("mains-liees", "on")
    assert rc == 0 and sortie == {"ok": True, "mains_liees": True}, p.stderr
    assert "consentements" in p.stderr
    assert (banc.r / "etc/secubox/pilotage/mains-liees").is_file()
    evts = banc.audit()
    assert [e["etat"] for e in evts if e["evenement"] == "mains_liees"] == ["on"]
    assert not any(e["evenement"] == "pilotage_refus" for e in evts)
    assert f.read_text() == "{pas du json"


def test_etat_minimal_pour_le_maitre(banc):
    """M1 : depuis l'agent, `etat` ne rend que le nécessaire : mains liées, {id, etat} des consentements non terminaux
    ou décidés depuis moins d'une heure, {id, etat, fin} du support."""
    banc.cliente()
    _, s1, _ = banc.run("reboot", agent=True)
    _, s2, _ = banc.run("maj-paquets", agent=True)
    _, s3, _ = banc.run("service", "redemarrer", "secubox-lyrion.service", agent=True)
    banc.run("consentement", "refuser", s2["consentement"])
    banc.run("consentement", "refuser", s3["consentement"])
    f = banc.r / "var/lib/secubox-pilotagectl/consentements.json"
    liste = json.loads(f.read_text())
    next(c for c in liste if c["id"] == s3["consentement"])["decide"] = int(__import__("time").time()) - 7200
    f.write_text(json.dumps(liste))
    banc.run("support", "ouvrir", "s-01", agent=True)
    banc.run("support", "accepter", "s-01")
    rc, etat, _ = banc.run("etat", agent=True)
    assert rc == 0 and set(etat) == {"ok", "mains_liees", "consentements", "support"}
    assert etat["consentements"] == [{"id": s1["consentement"], "etat": "en_attente"},
                                     {"id": s2["consentement"], "etat": "refuse"}]
    assert set(etat["support"]) == {"id", "etat", "fin"} and etat["support"]["etat"] == "ouvert"
    # en local : tout (affichage du détenteur)
    _, local, _ = banc.run("etat")
    assert {"box", "canal", "agent"} <= set(local) and len(local["consentements"]) == 3


def test_etat_rend_toujours_les_mains_liees(banc):
    """M2 : une section illisible est marquée « illisible », mains_liees est toujours rendu."""
    banc.run("mains-liees", "on")
    (banc.r / "var/lib/secubox-pilotagectl/consentements.json").write_text("{pas du json")
    (banc.r / "var/lib/secubox-pilotagectl/support.json").write_text("[]")
    for agent in (True, False):
        rc, etat, _ = banc.run("etat", agent=agent)
        assert rc == 0 and etat["ok"] is True and etat["mains_liees"] is True, etat
        assert etat["consentements"] == "illisible" and etat["support"] == "illisible"


def test_audit_du_support_porte_l_operation(banc_nu):
    """M5 : `op` dans l'audit d'un support (demande et refus), y compris « ancre non vérifiée »."""
    banc = banc_nu
    banc.run("support", "fermer", "s-01", agent=True)
    banc.ancrer()
    banc.run("support", "ouvrir", "s-01", agent=True)
    banc.run("support", "accepter", "s-01", agent=True)
    lignes = [e for e in banc.audit() if e.get("verbe") == "support"]
    assert [(e["evenement"], e.get("op"), e.get("refus")) for e in lignes] == [
        ("pilotage_demande", "fermer", None), ("pilotage_refus", "fermer", "ancre non vérifiée"),
        ("pilotage_demande", "ouvrir", None), ("pilotage_refus", "ouvrir", "consentement requis"),
        ("pilotage_demande", "accepter", None), ("pilotage_refus", "accepter", "local seulement")]
    assert all(set(e) <= PERMIS_AUDIT | {"op"} for e in banc.audit())


# ── Tâche 5 : renommer (D3) et maillage-rejoindre (R-L2-2) ─────────────────────────────────────────────────────────────

import base64  # noqa: E402
import hashlib  # noqa: E402


def code_maillage(jeton="ab" * 32, adresse="192.168.1.1"):
    """Un vrai code sbxmesh1 (format de secubox-p2p api/automesh.encoder : base64url du JSON, somme sha256[:4])."""
    charge = base64.urlsafe_b64encode(json.dumps({"a": adresse, "t": jeton}, separators=(",", ":")).encode()).decode()
    charge = charge.rstrip("=")
    return f"sbxmesh1.{charge}.{hashlib.sha256(charge.encode()).hexdigest()[:4]}"


def test_renommer_lance_secubox_renommer_borne(banc):
    """Box du propriétaire : le ctl lance /usr/sbin/secubox-renommer (chemin absolu) dans une unité transitoire à durée
    bornée (RuntimeMaxSec), hors de l'espace de montage de l'agent ; la fin est auditée par _fin comme toute opération."""
    rc, sortie, p = banc.run("--acteur", "gk2admin", "renommer", "gk5", agent=True)
    assert rc == 0 and sortie["ok"] is True and len(sortie["job"]) == 16, p.stderr
    lance = banc.lancements()[-1]
    assert "--property=RuntimeMaxSec=120" in lance
    for prop in ("NoNewPrivileges=yes", "ProtectSystem=strict", "ReadWritePaths=/etc /run /var/log/secubox",
                 "ProtectHome=yes", "PrivateTmp=yes"):
        assert f"--property={prop}" in lance, prop
    assert f"--unit=secubox-pilotage-op-{sortie['job']}" in lance
    assert lance.endswith("-- /usr/sbin/secubox-renommer --acteur gk2admin gk5")
    assert [e["evenement"] for e in banc.audit() if e.get("verbe") == "renommer"] == ["pilotage_demande",
                                                                                       "pilotage_resultat"]
    # sans --acteur : le compte de l'agent ; un nom invalide n'atteint jamais l'outil
    rc, sortie, _ = banc.run("renommer", "gk6", agent=True)
    assert banc.lancements()[-1].endswith("-- /usr/sbin/secubox-renommer --acteur secubox-pilotage-agent gk6")
    assert banc.run("renommer", "GK6", agent=True)[0] == 2
    # l'outil vient de secubox-core 1.8.10
    assert "secubox-core (>= 1.8.10~)" in (CTL.parents[1] / "debian" / "control").read_text()


def test_renommer_box_cliente_exige_l_accord(banc):
    banc.cliente()
    rc, sortie, _ = banc.run("renommer", "gk5", agent=True)
    assert rc == 0 and sortie["refus"] == "consentement requis"
    assert banc.lancements() == []
    banc.run("consentement", "accepter", sortie["consentement"])
    rc, sortie, _ = banc.run("renommer", "gk5", agent=True)
    assert rc == 0 and sortie["ok"] is True
    assert banc.lancements()[-1].endswith("/usr/sbin/secubox-renommer --acteur secubox-pilotage-agent gk5")


def test_maillage_rejoindre_lit_le_code_sur_l_entree_standard(banc):
    code = code_maillage()
    rc, sortie, p = banc.run("--acteur", "gk2admin", "maillage-rejoindre", agent=True, entree=code + "\n")
    assert rc == 0 and sortie["ok"] is True, p.stderr
    job = sortie["job"]
    lance = banc.lancements()[-1]
    assert lance.endswith(f"-- /usr/sbin/secubox-pilotagectl _rejoindre {job}") and "RuntimeMaxSec=300" in lance
    depot = banc.r / f"var/lib/secubox-pilotagectl/rejoindre-{job}.code"
    assert depot.read_text() == code and depot.stat().st_mode & 0o777 == 0o600
    # puis l'unité transitoire (PID 1, root, locale) dépose le code pour secubox-automesh et le lance
    (banc.r / "var/lib/secubox/p2p").mkdir(parents=True)
    (banc.r / "var/lib/secubox/p2p/automesh.json").write_text('{"statut": "approuve", "debut": 1}')
    rc, sortie, p = banc.run("_rejoindre", job)
    assert rc == 0 and sortie == {"ok": True, "job": job}, p.stderr
    automesh = banc.r / "var/lib/secubox/p2p/automesh.code"
    assert automesh.read_text() == code and automesh.stat().st_mode & 0o777 == 0o600
    assert not depot.exists()                                       # usage unique
    assert not (banc.r / "var/lib/secubox/p2p/automesh.json").exists()   # un ancien « debut » expirerait le code neuf
    assert banc.lancements()[-1] == "start secubox-automesh.service"
    assert [e["resultat"] for e in banc.audit() if e["evenement"] == "maillage_rejoindre"] == ["succes"]
    # rejouer le même job : plus de code
    rc, sortie, _ = banc.run("_rejoindre", job)
    assert rc == 1 and sortie["ok"] is False


def test_maillage_rejoindre_refus(banc):
    for entree in ("", "pas-un-code", "sbxmesh1.abc.0000", code_maillage() + "x", "sbxmesh1." + "a" * 700 + ".abcd"):
        rc, sortie, _ = banc.run("maillage-rejoindre", agent=True, entree=entree)
        assert rc == 0 and sortie == {"ok": False, "refus": "code invalide"}, entree
    assert banc.lancements() == []
    # jonction en échec : la transitoire échoue (code 1), sa fin sera auditée « echec » par _fin
    rc, sortie, _ = banc.run("maillage-rejoindre", agent=True, entree=code_maillage())
    (banc.r / "var/lib/secubox/p2p").mkdir(parents=True)
    rc, s2, _ = banc.run("_rejoindre", sortie["job"], env={"FAUX_SYSTEMCTL_ECHEC": "1"})
    assert rc == 1 and s2["ok"] is False
    assert [e["resultat"] for e in banc.audit() if e["evenement"] == "maillage_rejoindre"] == ["echec"]
    # _rejoindre est interne : refusé depuis l'agent
    rc, s3, _ = banc.run("_rejoindre", "0123456789abcdef", agent=True)
    assert rc == 0 and s3 == {"ok": False, "refus": "local seulement"}
    # box cliente (canal wg-autoload) : hors maillage, refusé sans consentement
    banc.cliente()
    rc, s4, _ = banc.run("maillage-rejoindre", agent=True, entree=code_maillage())
    assert rc == 0 and s4 == {"ok": False, "refus": "box cliente : hors maillage"}
    _, pol, _ = banc.run("politique", "maillage-rejoindre", agent=True)
    assert pol["autorise"] is False


def test_maillage_rejoindre_sous_mains_liees(banc):
    banc.run("mains-liees", "on")
    rc, sortie, _ = banc.run("maillage-rejoindre", agent=True, entree=code_maillage())
    assert rc == 0 and sortie == {"ok": False, "refus": "mains liées"}
    assert banc.lancements() == [] and not list((banc.r / "var/lib/secubox-pilotagectl").glob("rejoindre-*"))


def test_code_jamais_journalise(banc):
    """R-L2-2 : le code (il porte le jeton de jonction) ne figure ni dans l'argv capturé (systemd-run, systemctl), ni dans
    l'audit, ni dans les journaux (stderr du ctl = journal de l'unité), ni dans les sorties ; il n'existe que dans l'état
    root 0600 du ctl, puis dans automesh.code (root 0600)."""
    jeton = "f00dcafe" * 8
    code = code_maillage(jeton)
    sorties = []
    rc, sortie, p = banc.run("--acteur", "gk2admin", "maillage-rejoindre", agent=True, entree=code)
    sorties += [p.stdout, p.stderr]
    (banc.r / "var/lib/secubox/p2p").mkdir(parents=True)
    banc.run("maillage-rejoindre", agent=True, entree=code)          # un second dépôt, jamais repris
    _, s, p = banc.run("_rejoindre", sortie["job"], env={"FAUX_SYSTEMCTL_ECHEC": "1"})
    sorties += [p.stdout, p.stderr]
    banc.run("_fin", sortie["job"], env={"SERVICE_RESULT": "exit-code", "EXIT_STATUS": "1"})
    _, _, p = banc.run("maillage-rejoindre", agent=True, entree=code + "corrompu")
    sorties += [p.stdout, p.stderr]
    traces = "\n".join(sorties + banc.lancements()) + (banc.r / "var/log/secubox/audit.log").read_text()
    for morceau in (code, jeton, code.split(".")[1][:24]):
        assert morceau not in traces
    assert all(set(e) <= PERMIS_AUDIT for e in banc.audit())


# ── Tâche 5, tour 1 (R-L2-36) ─────────────────────────────────────────────────────────────────────────────────────────

def test_fin_hors_bac_a_sable_pour_toute_unite_transitoire(banc):
    """C1 : ExecStopPost s'exécute dans l'espace de montage de l'unité ; sous ProtectSystem=strict (renommage), l'état
    du ctl y est en lecture seule et _fin n'auditait rien. Chaque ExecStopPost du ctl porte « + » (hors bac à sable),
    ou alors le bac à sable de l'unité laisse l'état du ctl en écriture."""
    banc.module("lyrion", ["secubox-lyrion.service"], False)
    demandes = [("reboot",), ("service", "redemarrer", "secubox-lyrion.service"), ("renommer", "gk5")]
    for d in demandes:
        rc, s, _ = banc.run(*d, agent=True)
        assert rc == 0 and s["ok"] is True, d
        banc.actifs.write_text("")
    rc, s, _ = banc.run("maillage-rejoindre", agent=True, entree=code_maillage())
    assert s["ok"] is True
    banc.actifs.write_text("")
    for argv in (("maj-paquets",), ("renouveler-secrets",)):
        rc, s, _ = banc.run(*argv, agent=True)
        assert s["ok"] is True, argv
        banc.actifs.write_text("")
    lances = [x for x in banc.lancements() if "--unit=secubox-pilotage-op-" in x]
    assert len(lances) == 6
    for lance in lances:
        stop = [a for a in lance.split(" --") if a.startswith("property=ExecStopPost=")]
        assert len(stop) == 1, lance
        sacre = stop[0].startswith("property=ExecStopPost=+/usr/sbin/secubox-pilotagectl _fin ")
        etat_ecrivable = "ProtectSystem=strict" not in lance or "/var/lib/secubox-pilotagectl" in lance
        assert sacre or etat_ecrivable, lance
        assert sacre, lance                          # R-L2-36 : « + » partout, bac à sable ou non


def test_fin_auditee_meme_si_le_code_ne_peut_etre_retire(banc):
    """C1 (robustesse) : une OSError au retrait de rejoindre-<job>.code (EROFS, EISDIR…) est journalisée, jamais avant
    l'audit de la fin."""
    rc, s, _ = banc.run("reboot", agent=True)
    job = s["job"]
    bloque = banc.r / f"var/lib/secubox-pilotagectl/rejoindre-{job}.code"
    bloque.mkdir()
    (bloque / "x").write_text("")                    # unlink → IsADirectoryError / EPERM : pas FileNotFoundError
    rc, sortie, p = banc.run("_fin", job, env={"SERVICE_RESULT": "success", "EXIT_STATUS": "0"})
    assert rc == 0 and sortie == {"ok": True, "job": job, "resultat": "succes"}, p.stderr
    assert [e["resultat"] for e in banc.audit() if e["evenement"] == "pilotage_resultat" and e.get("job") == job][-1] \
        == "succes"
    assert "rejoindre" in p.stderr


def test_rejoindre_retire_l_ancien_etat_avant_d_ecrire_le_code(banc):
    """M4 : automesh.json d'abord retiré ; s'il ne peut l'être, aucun code n'est déposé (sinon secubox-automesh lirait
    le code neuf avec l'ancien « debut » et le ferait expirer)."""
    rc, s, _ = banc.run("maillage-rejoindre", agent=True, entree=code_maillage())
    p2p = banc.r / "var/lib/secubox/p2p"
    (p2p / "automesh.json").mkdir(parents=True)
    (p2p / "automesh.json" / "x").write_text("")
    rc, sortie, _ = banc.run("_rejoindre", s["job"])
    assert rc == 1 and sortie["ok"] is False
    assert not (p2p / "automesh.code").exists()
    assert banc.lancements()[-1] != "start secubox-automesh.service"
