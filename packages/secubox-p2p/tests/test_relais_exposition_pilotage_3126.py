# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3126 L5 tâche 6 (E4) : relais des noms d'une box sans webos. Pour un pair connu du pilotage du maître, les noms viennent du
plan d'exposition écrit par le service (/var/lib/secubox/pilotage/exposition.json : Device.X_SECUBOX_Exposure de l'agent) ;
sinon (absent, illisible, non sûr, périmé, pair inconnu) l'ancien chemin webos/public/noms. Déclarations d'agents distants :
revalidées ; admin.<box> d'une box « distante » jamais publié (R-L5-27).

Tests de COMPORTEMENT du vrai script sous racine substituée (SBX_RELAIS_ESSAI), doublures sur PATH (voir test 3126 voisin)."""
import json
import os
import time

import pytest

from .test_relais_exclusion_pilotage_3126 import ADMIN, HALL, IP4, IP5, Relais, _script

MEET = "meet.gk5.secubox.in"


class RelaisPilote(Relais):
    def __init__(self, tmp):
        super().__init__(tmp)
        self.dossier = self.r / "var/lib/secubox/pilotage"
        self.dossier.mkdir(parents=True)
        self.plan = self.dossier / "exposition.json"
        log = f'echo "$(basename "$0") $*" >> {self.journal}\n'
        noms = json.dumps({"domaine": "gk5.secubox.in", "noms": [ADMIN, HALL]})
        # SANS_WEBOS : la box ne sert pas /public/noms (box légère) — curl n'obtient rien
        _script(self.bin / "curl", log + f"""
case "$*" in
  */public/noms*) [ -e {self.r}/SANS_WEBOS ] || echo '{noms}' ;;
  */public/ports*) echo 404 ;;
  *) echo 200 ;;
esac
""")

    def sans_webos(self):
        (self.r / "SANS_WEBOS").write_text("")

    def ecrire_plan(self, noms=(HALL, MEET), box="gk5", adresse=IP5, distante=False, releve_le=None, brut=None, **extra):
        entree = {"adresse": adresse, "box": box, "distante": distante, "noms": list(noms), "ports": [7881],
                  "releve_le": time.time() if releve_le is None else releve_le, **extra}
        self.plan.write_text(brut if brut is not None else json.dumps({"version": 1, "boxes": [entree]}))
        os.chmod(self.plan, 0o640)


@pytest.fixture
def rel(tmp_path):
    return RelaisPilote(tmp_path)


def sync(rel):
    r = rel.lancer("synchroniser")
    assert r.returncode == 0, r.stdout + r.stderr
    return r


def test_box_sans_webos_noms_relayes_depuis_le_pilotage(rel):
    rel.sans_webos()
    rel.ecrire_plan()
    r = sync(rel)
    t = rel.table()
    assert t[HALL] == [IP5, 9080] and t[MEET] == [IP5, 9080]
    assert ADMIN not in t
    assert "pilotage" in r.stdout


def test_pilotage_prime_sur_webos_pour_un_pair_connu(rel):
    rel.ecrire_plan(noms=(MEET,))
    sync(rel)
    t = rel.table()
    assert t[MEET] == [IP5, 9080] and HALL not in t and ADMIN not in t


def test_pilotage_absent_ancien_chemin(rel):
    sync(rel)
    t = rel.table()
    assert t[ADMIN] == [IP5, 9080] and t[HALL] == [IP5, 9080] and MEET not in t


def test_pilotage_absent_et_sans_webos_rien(rel):
    rel.sans_webos()
    sync(rel)
    assert set(rel.table()) == {"hall.gk2.secubox.in"}


@pytest.mark.parametrize("cas", ["json_invalide", "version", "perime", "lien", "inscriptible", "pair_inconnu", "nom_autre_box",
                                 "geant", "pas_un_fichier", "boxes_pas_liste"])
def test_plan_mauvais_ancien_chemin(rel, cas):
    if cas == "json_invalide":
        rel.ecrire_plan(brut="{pas du json")
    elif cas == "version":
        rel.ecrire_plan(brut=json.dumps({"version": 2, "boxes": []}))
    elif cas == "perime":           # analogue d'un contrôleur qui ne répond plus : relevé de plus de 24 h
        rel.ecrire_plan(releve_le=time.time() - 2 * 86400)
    elif cas == "lien":
        cible = rel.r / "ailleurs.json"
        cible.write_text(json.dumps({"version": 1, "boxes": [{"adresse": IP5, "box": "gk5", "distante": False, "noms": [MEET],
                                                               "ports": [], "releve_le": time.time()}]}))
        rel.plan.symlink_to(cible)
    elif cas == "inscriptible":
        rel.ecrire_plan()
        os.chmod(rel.plan, 0o666)
    elif cas == "pair_inconnu":
        rel.ecrire_plan(adresse=IP4, box="gk4", noms=("meet.gk4.secubox.in",))
    elif cas == "nom_autre_box":    # le pilotage dit gk7 pour l'IP de gk5 (wg_mesh.json) : désaccord, on ne choisit pas
        rel.ecrire_plan(box="gk7", noms=("meet.gk7.secubox.in",))
    elif cas == "geant":
        rel.ecrire_plan(brut=" " * (2 << 20))
    elif cas == "pas_un_fichier":
        rel.plan.mkdir()
    elif cas == "boxes_pas_liste":
        rel.ecrire_plan(brut=json.dumps({"version": 1, "boxes": {"a": 1}}))
    sync(rel)
    t = rel.table()
    assert t[ADMIN] == [IP5, 9080] and t[HALL] == [IP5, 9080] and MEET not in t
    assert "meet.gk4.secubox.in" not in t and "meet.gk7.secubox.in" not in t


def test_noms_invalides_ou_hors_domaine_ignores(rel):
    rel.sans_webos()
    rel.ecrire_plan(noms=(MEET, "hall.gk2.secubox.in", "hub.gk4.secubox.in", "evil.com", "a.b.gk5.secubox.in",
                          "HUB.gk5.secubox.in", "x" * 41 + ".gk5.secubox.in", "-x.gk5.secubox.in", "gk5.secubox.in",
                          "wpad.gk5.secubox.in", 7, None, "a b.gk5.secubox.in", "z.gk5.secubox.in;rm"))
    sync(rel)
    assert set(rel.table()) == {"hall.gk2.secubox.in", MEET}


def test_plan_trop_de_noms_borne(rel):
    rel.sans_webos()
    rel.ecrire_plan(noms=[f"s{i}.gk5.secubox.in" for i in range(200)])
    sync(rel)
    assert len([n for n in rel.table() if n.endswith(".gk5.secubox.in")]) == 64


def test_box_distante_admin_jamais_publie(rel):
    rel.sans_webos()
    rel.ecrire_plan(noms=(ADMIN, HALL), distante=True)   # aucune exclusion posée encore : la déclaration suffit
    for _ in range(2):
        sync(rel)
    t = rel.table()
    assert ADMIN not in t and t[HALL] == [IP5, 9080]
    assert f'domain = "{ADMIN}"' not in rel.toml.read_text()


def test_box_distante_admin_existant_jamais_retire(rel):
    """Le basculement (secubox-pilotage-vhost) seul déplace admin.<box> : la synchronisation ne le retire pas non plus."""
    t = rel.table()
    t[ADMIN] = [IP5, 9080]
    rel.routes.write_text(json.dumps(t))
    rel.ecrire_plan(noms=(HALL,), distante=True)
    for _ in range(2):
        sync(rel)
    assert rel.table()[ADMIN] == [IP5, 9080]


def test_exclusion_du_pilotage_toujours_honoree(rel):
    rel.sans_webos()
    rel.ecrire_plan(noms=(ADMIN, HALL))
    rel.exclure([ADMIN])
    sync(rel)
    t = rel.table()
    assert ADMIN not in t and t[HALL] == [IP5, 9080]


def test_ports_du_plan_jamais_relayes(rel):
    """Device.X_SECUBOX_Exposure.Ports = tous les ports TCP en écoute de la box (ni protocole ni module, ni décision de
    publier) : jamais relayés ; les ports restent ceux que la box publie (webos/public/ports)."""
    rel.ecrire_plan(ports=[5432, 7881])
    sync(rel)
    etat = rel.r / "var/lib/secubox/p2p/relais-ports.json"
    assert not etat.exists() or "5432" not in etat.read_text()


def test_synchroniser_tient_le_verrou_commun_pendant_la_lecture_du_plan(rel):
    import fcntl
    rel.ecrire_plan()
    rel.verrou.touch()
    os.chmod(rel.verrou, 0o600)
    with open(rel.verrou) as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        p = rel.popen("synchroniser")
        time.sleep(1.0)
        assert p.poll() is None          # attend le verrou : rien lu ni écrit
        assert MEET not in rel.table()
        fcntl.flock(f, fcntl.LOCK_UN)
        out, err = p.communicate(timeout=60)
    assert p.returncode == 0, out + err
    assert rel.table()[MEET] == [IP5, 9080]
