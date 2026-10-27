# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""secubox-adguard-adult-sync (#2964, suite de #2962) : exception adulte par
appareil, sans lever le filtrage pubs/trackers.

`local-zone-override`, UNE ENTRÉE PAR DOMAINE (#2979, corrige #2973/#2976).
Vérifié en direct sur gk2 avec un Unbound propre : contrairement à
`local-zone` (qui couvre tout son sous-arbre), `local-zone-override` ne
couvre QUE le nom exact donné — avec une seule entrée sur l'apex, l'apex
résolvait pour l'IP exemptée mais ses sous-domaines restaient bloqués.
Une `view:` avec `view-first: yes` (#2976) a aussi été vérifiée en direct
et NE SURCHARGE PAS un `always_nxdomain` global pour la même zone —
abandonnée.

#3205 : le rendu est DÉPOSÉ comme source de secubox-dns-listes, qui compile, vérifie, recharge (et attend qu'Unbound
réponde, #2969) et revient en arrière ; le script ne touche plus ni Unbound ni sa configuration."""
import importlib.machinery
import importlib.util
import sys
import types
from pathlib import Path

import pytest

ICI = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ICI.parents[1] / "common"))
from secubox_unbound import depot as D  # noqa: E402

SCRIPT = ICI / "sbin" / "secubox-adguard-adult-sync"

HOSTS_ADULTE = (
    "0.0.0.0 cam-adulte.example\n"
    "0.0.0.0 tube-adulte.example\n"
    "# un commentaire\n"
    "127.0.0.1 deja-bloque.example\n"
)


@pytest.fixture
def mod(tmp_path, monkeypatch):
    fl = types.ModuleType("secubox_filterlists")
    fl.OUT_DNS = tmp_path / "dns-domains.txt"
    fl.OUT_DNS.write_text("pub.example\ntracker.example\ndeja-bloque.example\n")
    monkeypatch.setitem(sys.modules, "secubox_filterlists", fl)
    loader = importlib.machinery.SourceFileLoader("adult_sync_test", str(SCRIPT))
    spec = importlib.util.spec_from_loader("adult_sync_test", loader)
    m = importlib.util.module_from_spec(spec)
    loader.exec_module(m)
    m.GENERAL_DNS = fl.OUT_DNS
    m.CACHE = tmp_path / "ad-guard" / "adult-source-cache.txt"
    m.ADULT_DOMAINS = tmp_path / "ad-guard" / "adult-domains.txt"
    m.EXEMPT_IP = tmp_path / "ad-guard" / "adult-exempt-ip.txt"
    m.SOURCE = tmp_path / "sources" / "96-secubox-adult.conf"
    m.STATUS = tmp_path / "ad-guard" / "adult-sinkhole-status.json"
    m.STATE = tmp_path / "ad-guard" / "adult-sinkhole.enabled"
    m.DATA_DIR = tmp_path / "ad-guard"
    m.DATA_DIR.mkdir(parents=True, exist_ok=True)
    m._fetch = lambda force=False: HOSTS_ADULTE
    return m


def test_parse_hosts_lit_le_format_hosts_et_ignore_les_commentaires():
    from importlib.machinery import SourceFileLoader
    import importlib.util as iu
    loader = SourceFileLoader("adult_sync_parse", str(SCRIPT))
    spec = iu.spec_from_loader("adult_sync_parse", loader)
    m = iu.module_from_spec(spec)
    loader.exec_module(m)
    assert m.parse_hosts(HOSTS_ADULTE) == {
        "cam-adulte.example", "tube-adulte.example", "deja-bloque.example",
    }


def test_la_synchronisation_depose_la_source(mod):
    st = mod.do_sync()
    assert st["ok"] is True and st["adult"] == 3 and st["source"] == "depose"
    assert st["application"] == "secubox-dns-listes" and "reloaded" not in st
    assert "cam-adulte.example" in mod.SOURCE.read_text()
    assert mod.do_sync()["source"] == "inchange"


def test_le_rendu_avec_exemptions_est_accepte_par_le_compilateur(mod, tmp_path):
    mod.EXEMPT_IP.parent.mkdir(parents=True, exist_ok=True)
    mod.EXEMPT_IP.write_text("192.168.1.3\n")
    mod.do_sync()
    acl = tmp_path / "10-acl.conf"                                   # le LAN autorisé, comme sur une box
    acl.write_text("server:\n    access-control: 192.168.0.0/16 allow\n")
    texte, stats = D.listes.compiler([mod.SOURCE], [acl])
    assert '"cam-adulte.example." always_nxdomain' in texte and "192.168.1.3/32" in texte and stats["etiquettes"] >= 1


def test_un_domaine_deja_bloque_par_le_general_nest_pas_redeclare(mod):
    # "deja-bloque.example" est dans le sinkhole GÉNÉRAL (fixture) ET dans la
    # source adulte : le déclarer une 2e fois en `local-zone` ferait refuser
    # la config par Unbound (deux `local-zone` pour le même nom).
    mod.do_sync()
    texte = mod.SOURCE.read_text()
    assert texte.count('local-zone: "deja-bloque.example."') == 0


def test_sans_appareil_exempte_aucun_override(mod):
    mod.do_sync()
    assert "local-zone-override" not in mod.SOURCE.read_text()


def test_appareil_exempte_recoit_un_override_par_domaine_adulte_individuel(mod):
    # #2979 : local-zone-override ne couvre QUE le nom exact — un override
    # par domaine, jamais un ancêtre partagé (#2973, cassé) ni une vue
    # (#2976, cassée — view-first:yes ne surcharge pas always_nxdomain).
    mod.EXEMPT_IP.parent.mkdir(parents=True, exist_ok=True)
    mod.EXEMPT_IP.write_text("192.168.1.3\n")
    st = mod.do_sync()
    texte = mod.SOURCE.read_text()
    assert st["exempt_ip"] == 1
    assert "view:" not in texte and "access-control-view" not in texte
    assert 'local-zone-override: "cam-adulte.example." 192.168.1.3 always_transparent' in texte
    assert 'local-zone-override: "tube-adulte.example." 192.168.1.3 always_transparent' in texte
    # Le sinkhole général (pub.example, tracker.example) n'est PAS redéclaré
    # — il reste bloqué pour cet appareil par le drop-in général existant.
    assert "pub.example" not in texte
    assert "tracker.example" not in texte


def test_apex_et_sous_domaine_recoivent_chacun_leur_propre_override(mod):
    # Constat gk2 en direct : avec une seule entrée sur l'apex,
    # "chaturbate.com" résolvait pour l'IP exemptée mais
    # "www.chaturbate.com" restait NXDOMAIN. Chaque nom a besoin de sa
    # propre entrée — aucun ne « couvre » l'autre.
    mod._fetch = lambda force=False: (
        "0.0.0.0 chaturbate.com\n0.0.0.0 www.chaturbate.com\n0.0.0.0 ads.chaturbate.com\n"
    )
    mod.EXEMPT_IP.parent.mkdir(parents=True, exist_ok=True)
    mod.EXEMPT_IP.write_text("192.168.1.3\n")
    mod.do_sync()
    texte = mod.SOURCE.read_text()
    overrides = {ligne.strip() for ligne in texte.splitlines() if ligne.strip().startswith("local-zone-override:")}
    assert overrides == {
        'local-zone-override: "chaturbate.com." 192.168.1.3 always_transparent',
        'local-zone-override: "www.chaturbate.com." 192.168.1.3 always_transparent',
        'local-zone-override: "ads.chaturbate.com." 192.168.1.3 always_transparent',
    }


def test_un_depot_refuse_est_annonce(mod, tmp_path):
    mod.SOURCE.parent.mkdir(parents=True)
    mod.SOURCE.symlink_to(tmp_path / "ailleurs")
    st = mod.do_sync()
    assert st["ok"] is False and "lien symbolique" in st["error"] and not (tmp_path / "ailleurs").exists()


def test_desactiver_retire_la_source(mod):
    mod.do_sync()
    st = mod.do_disable()
    assert st["ok"] is True and st["enabled"] is False and st["source"] == "retire" and not mod.SOURCE.exists()
    assert mod.do_disable()["source"] == "absent"


# ── Verrou (#2979 bis) : deux synchros ne se chevauchent jamais (cache de la
# source adulte, liste des domaines, source déposée). Depuis #3205, le script
# ne parle plus à Unbound : c'est secubox-dns-listes, seul, qui recharge.

def test_verrou_exclusif_refuse_une_seconde_synchro_concurrente(mod):
    with mod._verrou():
        with pytest.raises(mod.ERREUR_VERROU):
            with mod._verrou(bloquant=False):
                pass
    with mod._verrou(bloquant=False):  # libéré après la sortie du with
        pass


def test_do_sync_echoue_proprement_si_une_synchro_est_deja_en_cours(mod):
    with mod._verrou():
        st = mod.do_sync()
    assert st["ok"] is False and "en cours" in st["error"]
    assert not mod.SOURCE.exists()  # rien n'est déposé pendant que le verrou était pris


def test_source_injoignable_sans_cache_echoue_proprement(mod):
    mod._fetch = lambda force=False: None
    st = mod.do_sync()
    assert st["ok"] is False and "unreachable" in st["error"]


def test_le_script_ne_touche_plus_unbound():
    """#2969 (attendre qu'Unbound soit revenu) vit désormais dans secubox_unbound.depot.SystemeListes."""
    src = SCRIPT.read_text()
    for interdit in ("unbound.conf.d", "unbound-control", "unbound-checkconf", "poser_vue", "retirer_vue", "systemctl"):
        assert interdit not in src, interdit


def test_une_adresse_exemptee_invalide_est_ignoree(mod):
    mod.EXEMPT_IP.parent.mkdir(parents=True, exist_ok=True)
    mod.EXEMPT_IP.write_text("192.168.1.3\nfaux\n300.1.1.1\n")
    assert mod._exempt_ips() == ["192.168.1.3"]
    mod.do_sync()
    D.listes.compiler([mod.SOURCE], [])
