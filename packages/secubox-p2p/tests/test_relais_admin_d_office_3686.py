# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3686 — admin.<box> d'un pair vivant exposé d'office par la synchronisation du relais, quelle que soit la source des
autres noms (webos, plan du pilotage, jonction), s'il répond vraiment ; jamais retiré ensuite. Gardes inchangées : domaine
tenu par un autre (dont le vhost de pilotage du maître), exclusion du pilotage, box distante, pair muet ou à valider, plan
rejeté. Et le journal exact d'un pair sans webos à /public/ports (page HTML du serveur nginx par défaut, pas « illisible »).

Tests de COMPORTEMENT du vrai script sous racine substituée (SBX_RELAIS_ESSAI), doublures sur PATH (voir tests 3126)."""
import json
import time

import pytest

from .test_relais_exclusion_pilotage_3126 import ADMIN, HALL, IP4, IP5, _script
from .test_relais_exposition_pilotage_3126 import MEET, RelaisPilote

PAGE_MAUVAIS_DOMAINE = "<!DOCTYPE html><html><body>Mauvais domaine</body></html>"


class RelaisAdmin(RelaisPilote):
    """Doublure curl plus fidèle : un pair SANS webos répond 200 et la page HTML « mauvais domaine » (default_server de
    webui.conf) à hall.localhost, pour /public/noms comme pour /public/ports ; admin.<box> répond le code de ADMIN_CODE."""

    def __init__(self, tmp):
        super().__init__(tmp)
        self.noms_webos([ADMIN, HALL])
        _script(self.bin / "curl", f"""echo "curl $*" >> {self.journal}
out=""; hote=""; url=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    -H) hote="$2"; shift 2 ;;
    -w|--max-time|--resolve) shift 2 ;;
    -*) shift ;;
    *) url="$1"; shift ;;
  esac
done
ecrire() {{ if [ -n "$out" ] && [ "$out" != /dev/null ]; then printf '%s' "$1" > "$out"; else printf '%s' "$1"; fi; }}
case "$url" in
  */public/noms) if [ -e {self.r}/SANS_WEBOS ]; then ecrire '{PAGE_MAUVAIS_DOMAINE}'; else ecrire "$(cat {self.r}/NOMS.json)"; fi; exit 0 ;;
  */public/ports) if [ -e {self.r}/SANS_WEBOS ]; then ecrire '{PAGE_MAUVAIS_DOMAINE}'; else ecrire '{{"ports": []}}'; fi; echo 200; exit 0 ;;
esac
case "$hote" in
  "Host: admin."*) cat {self.r}/ADMIN_CODE 2>/dev/null || echo 200 ;;
  *) echo 200 ;;
esac
""")

    def noms_webos(self, noms, domaine="gk5.secubox.in"):
        (self.r / "NOMS.json").write_text(json.dumps({"domaine": domaine, "noms": list(noms)}))

    def admin_repond(self, code):
        (self.r / "ADMIN_CODE").write_text(f"{code}\n")

    def audit(self):
        f = self.r / "var/log/secubox/audit.log"
        return f.read_text() if f.exists() else ""


@pytest.fixture
def rel(tmp_path):
    return RelaisAdmin(tmp_path)


def sync(rel, **extra):
    r = rel.lancer("synchroniser", **extra)
    assert r.returncode == 0, r.stdout + r.stderr
    return r


def _sondes_admin(rel):
    return [a for a in rel.appels() if a.startswith("curl") and f"Host: {ADMIN}" in a]


# --- le constat de gk7 : pair connu du pilotage, plan sans admin --------------------------------------------------

def test_pilotage_plan_sans_admin_admin_qui_repond_expose(rel):
    rel.sans_webos()
    rel.ecrire_plan(noms=(HALL, MEET))
    r = sync(rel)
    t = rel.table()
    assert t[ADMIN] == [IP5, 9080] and t[HALL] == [IP5, 9080] and t[MEET] == [IP5, 9080]
    assert "ajouté d'office (pilotage)" in r.stdout
    assert f'"evenement":"relaye","nom":"{ADMIN}"' in rel.audit()


def test_pilotage_plan_vide_admin_seul_expose(rel):
    rel.sans_webos()
    rel.ecrire_plan(noms=())
    sync(rel)
    assert rel.table()[ADMIN] == [IP5, 9080]


@pytest.mark.parametrize("code", ["000", "404", "500", "503"])
def test_pilotage_plan_sans_admin_admin_qui_ne_repond_pas_rien(rel, code):
    rel.sans_webos()
    rel.admin_repond(code)
    rel.ecrire_plan(noms=(HALL, MEET))
    sync(rel)
    t = rel.table()
    assert ADMIN not in t and t[HALL] == [IP5, 9080] and t[MEET] == [IP5, 9080]
    assert f'domain = "{ADMIN}"' not in rel.toml.read_text()


def test_webos_qui_ne_publie_pas_admin_expose_s_il_repond(rel):
    rel.noms_webos([HALL])
    r = sync(rel)
    assert rel.table()[ADMIN] == [IP5, 9080]
    assert "ajouté d'office (webos)" in r.stdout


def test_webos_qui_publie_admin_aucune_sonde_en_plus(rel):
    sync(rel)
    assert rel.table()[ADMIN] == [IP5, 9080]
    # seule la sonde ordinaire de cmd_relayer, pas la sonde d'office en plus
    assert len(_sondes_admin(rel)) == 1


# --- jamais retiré ensuite ----------------------------------------------------------------------------------------

def test_admin_d_office_jamais_retire_source_pilotage(rel):
    rel.sans_webos()
    rel.ecrire_plan(noms=(HALL,))
    sync(rel)
    assert rel.table()[ADMIN] == [IP5, 9080]
    rel.admin_repond("000")
    for _ in range(3):
        sync(rel)
    assert rel.table()[ADMIN] == [IP5, 9080]


def test_admin_d_office_jamais_retire_source_webos(rel):
    """Le retrait #3132 (deux relevés) vaut pour les noms que webos ne publie plus : jamais pour admin.<box>."""
    rel.noms_webos([HALL])
    sync(rel)
    assert rel.table()[ADMIN] == [IP5, 9080]
    rel.admin_repond("000")
    for _ in range(3):
        r = sync(rel)
    t = rel.table()
    assert t[ADMIN] == [IP5, 9080] and t[HALL] == [IP5, 9080]
    assert f"retiré : {ADMIN}" not in r.stdout
    assert "relais_retire" not in rel.audit()


def test_admin_d_office_jamais_retire_source_jonction(rel):
    rel.sans_webos()                       # ni webos ni plan : jonction (#3638)
    sync(rel)
    assert set(rel.table()) == {"hall.gk2.secubox.in", ADMIN}
    rel.admin_repond("000")
    for _ in range(3):
        sync(rel)
    assert rel.table()[ADMIN] == [IP5, 9080]


def test_jonction_admin_muet_rien_ni_joker_ni_certificat(rel):
    rel.sans_webos()
    rel.admin_repond("000")
    (rel.r / "data/haproxy/certs/*.gk5.secubox.in.pem").unlink()
    sync(rel)
    assert set(rel.table()) == {"hall.gk2.secubox.in"}
    assert not [a for a in rel.appels() if a.startswith("dig") and "gk5" in a]


# --- gardes --------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("cible", [["192.168.1.200", 9080], [IP4, 9080], ["127.0.0.1", 9080]])
def test_admin_deja_servi_ailleurs_rien_touche(rel, cible):
    """Cas de gk5 et gk6 sur gk2 : admin.<box> servi par le vhost de pilotage du maître (192.168.1.200:9080)."""
    rel.sans_webos()
    rel.ecrire_plan(noms=(HALL,))
    t = rel.table()
    t[ADMIN] = cible
    rel.routes.write_text(json.dumps(t))
    toml_avant = rel.toml.read_text()
    r = sync(rel)
    t = rel.table()
    assert t[ADMIN] == cible and HALL not in t
    assert rel.toml.read_text() == toml_avant
    assert "refusé" in r.stdout and "relais_domaine_refuse" in rel.audit()
    assert not _sondes_admin(rel)


def test_admin_exclu_par_le_pilotage_rien_touche(rel):
    rel.sans_webos()
    rel.ecrire_plan(noms=(HALL,))
    rel.exclure([ADMIN])
    r = sync(rel)
    t = rel.table()
    assert ADMIN not in t and t[HALL] == [IP5, 9080]
    assert "servi par le pilotage du maître" in r.stdout
    assert not _sondes_admin(rel)


def test_box_distante_admin_jamais_d_office(rel):
    rel.sans_webos()
    rel.ecrire_plan(noms=(HALL,), distante=True)
    for _ in range(2):
        sync(rel)
    t = rel.table()
    assert ADMIN not in t and t[HALL] == [IP5, 9080]
    assert not _sondes_admin(rel)


def test_admin_exclu_par_l_administrateur_jamais_d_office(rel):
    rel.sans_webos()
    rel.ecrire_plan(noms=(HALL,))
    (rel.r / "etc/secubox/relais-maillage.toml").write_text('exclure = ["wpad", "boot", "admin"]\n')
    sync(rel)
    assert ADMIN not in rel.table()


@pytest.mark.parametrize("cas", ["version", "nom_autre_box", "perime"])
def test_plan_rejete_ou_en_desaccord_rien_meme_si_admin_repond(rel, cas):
    rel.sans_webos()
    if cas == "version":
        rel.ecrire_plan(brut=json.dumps({"version": 2, "boxes": []}))
    elif cas == "nom_autre_box":
        rel.ecrire_plan(box="gk7", noms=("meet.gk7.secubox.in",))
    else:
        rel.ecrire_plan(releve_le=time.time() - 2 * 86400)
    sync(rel)
    assert set(rel.table()) == {"hall.gk2.secubox.in"}
    assert not _sondes_admin(rel)


def test_pair_a_valider_rien(rel):
    rel.sans_webos()
    rel.ecrire_plan(noms=(HALL,))
    etat = rel.r / "var/lib/secubox/p2p/wg_mesh.json"
    etat.write_text(json.dumps({"peers": [{"name": "gk5", "mesh_ip": IP5, "public_key": "K5", "a_valider": True},
                                          {"name": "gk4", "mesh_ip": IP4, "public_key": "K4"}]}))
    r = sync(rel)
    assert set(rel.table()) == {"hall.gk2.secubox.in"}
    assert "à valider" in r.stdout and not _sondes_admin(rel)


def test_pair_muet_rien(rel):
    rel.sans_webos()
    rel.ecrire_plan(noms=(HALL,))
    maintenant = int(time.time())
    _script(rel.bin / "wg", f"""echo "wg $*" >> {rel.journal}
case "$*" in
  *latest-handshakes*) printf "K5\\t{maintenant - 4 * 86400}\\nK4\\t{maintenant - 30}\\n" ;;
  *) printf "K5\\t{IP5}/32\\nK4\\t{IP4}/32\\n" ;;
esac
""")
    sync(rel)
    assert set(rel.table()) == {"hall.gk2.secubox.in"}
    assert not _sondes_admin(rel)


@pytest.mark.parametrize("box", ["admin", "hall", "www", "secubox"])
def test_nom_de_box_reserve_jamais_d_office(rel, box):
    """Pair webos qui annonce <réservé>.secubox.in : jamais admin.<réservé>.secubox.in d'office."""
    rel.noms_webos([f"meet.{box}.secubox.in"], domaine=f"{box}.secubox.in")
    sync(rel)
    assert f"admin.{box}.secubox.in" not in rel.table()


def test_domaine_webos_hors_zone_du_relais_jamais_d_office(rel):
    rel.noms_webos(["meet.exemple.org"], domaine="exemple.org")
    sync(rel)
    assert "admin.exemple.org" not in rel.table()


# --- « liste de ports illisible » : le journal exact d'un pair sans webos ------------------------------------------

def test_pair_sans_webos_ports_page_html_journal_exact_rien_retire(rel):
    rel.sans_webos()
    rel.ecrire_plan(noms=(HALL,))
    etat = rel.r / "var/lib/secubox/p2p/relais-ports.json"
    etat.write_text(json.dumps({"udp/7882": {"ip": IP5, "module": "meet"}}))
    r = sync(rel)
    assert "page HTML au lieu de la liste de ports (pas de webos sur ce pair) — rien ajouté ni retiré" in r.stdout
    assert "liste de ports illisible" not in r.stdout
    assert json.loads(etat.read_text()) == {"udp/7882": {"ip": IP5, "module": "meet"}}
