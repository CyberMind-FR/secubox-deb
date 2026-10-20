# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""secubox-adguard-adult-sync (#2964, suite de #2962) : exception adulte par
appareil, sans lever le filtrage pubs/trackers.

Contrairement à `ip-allowlist.txt` (bypass complet via une vue Unbound vide),
un appareil exempté ici garde le sinkhole général — par une `view:` PARTAGÉE
avec `view-first: yes` (#2976, même motif que le moteur TV auto, #1954/#1959) :
un domaine ABSENT de la vue retombe automatiquement sur le puits général, nul
besoin de le redéclarer (l'erreur de #2969, qui l'a fait en pure perte —
drop-in monté à 49 Mo, rechargement d'~1 min, DNS indisponible pour tout le
réseau). La vue ne contient QUE les domaines adultes, UNE SEULE FOIS (jamais
par IP exemptée)."""
import importlib.machinery
import importlib.util
import sys
import types
from pathlib import Path
from unittest import mock

import pytest

ICI = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ICI.parents[1] / "common"))
import secubox_unbound as U  # noqa: E402

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
    m.DROPIN = tmp_path / "unbound.d" / "96-secubox-adult.conf"
    m.STATUS = tmp_path / "ad-guard" / "adult-sinkhole-status.json"
    m.STATE = tmp_path / "ad-guard" / "adult-sinkhole.enabled"
    m._fetch = lambda force=False: HOSTS_ADULTE
    return m


class Faux(U.SystemeUnbound):
    MODULE = "adguard-adult-sync"

    def __init__(self, verif=(True, ""), recharge_ok=True):
        self.verif, self.recharge_ok, self.appels = verif, recharge_ok, []

    def verifier_unbound(self):
        self.appels.append("verifier")
        return self.verif

    def recharger_unbound(self):
        self.appels.append("recharger")
        if not self.recharge_ok:
            raise self.ERREUR("reload a échoué")

    def audit(self, action, detail=""):
        pass


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


def test_la_synchronisation_pose_verifie_et_recharge(mod):
    s = Faux()
    st = mod.do_sync(systeme=s)
    assert st["ok"] is True and st["adult"] == 3 and st["reloaded"] is True
    assert "cam-adulte.example" in mod.DROPIN.read_text()
    assert s.appels == ["verifier", "recharger"]


def test_un_domaine_deja_bloque_par_le_general_nest_pas_redeclare(mod):
    # "deja-bloque.example" est dans le sinkhole GÉNÉRAL (fixture) ET dans la
    # source adulte : le déclarer une 2e fois en `local-zone` ferait refuser
    # la config par Unbound (deux `local-zone` pour le même nom).
    mod.do_sync(systeme=Faux())
    texte = mod.DROPIN.read_text()
    assert texte.count('local-zone: "deja-bloque.example."') == 0


def test_sans_appareil_exempte_aucune_vue(mod):
    mod.do_sync(systeme=Faux())
    assert "view:" not in mod.DROPIN.read_text()


def test_zone_effective_remonte_au_plus_proche_ancetre_declare(mod):
    zones = {"chaturbate.com", "autre.example"}
    assert mod._zone_effective("www.chaturbate.com", zones) == "chaturbate.com"
    assert mod._zone_effective("ads.chaturbate.com", zones) == "chaturbate.com"
    assert mod._zone_effective("chaturbate.com", zones) == "chaturbate.com"
    # Aucun ancêtre déclaré : le nom reste sa propre zone.
    assert mod._zone_effective("isole.example", zones) == "isole.example"


def test_appareil_exempte_sur_un_sous_domaine_recoit_la_zone_de_l_apex(mod):
    # Constat gk2 (#2973) : Unbound bloque "www.chaturbate.com." via la zone
    # "chaturbate.com." (couvre tout son sous-arbre) — une entrée posée sur
    # "www.chaturbate.com." lui-même n'est JAMAIS consultée. L'apex doit
    # recevoir l'entrée de la vue, pas chaque sous-domaine séparément.
    mod._fetch = lambda force=False: (
        "0.0.0.0 chaturbate.com\n0.0.0.0 www.chaturbate.com\n0.0.0.0 ads.chaturbate.com\n"
    )
    mod.EXEMPT_IP.parent.mkdir(parents=True, exist_ok=True)
    mod.EXEMPT_IP.write_text("192.168.1.3\n")
    mod.do_sync(systeme=Faux())
    texte = mod.DROPIN.read_text()
    vue = texte.split('name: "sbx-adult-allow"')[1]
    zones = [ligne for ligne in vue.splitlines() if ligne.strip().startswith("local-zone:")]
    assert zones == ['    local-zone: "chaturbate.com." always_transparent']


def test_appareil_exempte_a_une_vue_partagee_sans_redeclarer_le_general(mod):
    # #2976 : view-first:yes fait retomber automatiquement sur le puits
    # général tout domaine ABSENT de la vue — #2969 redéclarait
    # "général - adulte" dans la vue, en pure perte (49 Mo sur gk2).
    mod.EXEMPT_IP.parent.mkdir(parents=True, exist_ok=True)
    mod.EXEMPT_IP.write_text("192.168.1.3\n")
    st = mod.do_sync(systeme=Faux())
    texte = mod.DROPIN.read_text()
    assert st["exempt_ip"] == 1
    assert "access-control-view: 192.168.1.3 sbx-adult-allow" in texte
    assert texte.count('name: "sbx-adult-allow"') == 1
    assert "view-first: yes" in texte
    vue = texte.split('name: "sbx-adult-allow"')[1]
    assert 'local-zone: "cam-adulte.example." always_transparent' in vue
    assert 'local-zone: "tube-adulte.example." always_transparent' in vue
    # Le sinkhole général (pub.example, tracker.example) n'est PAS redéclaré
    # dans la vue — view-first:yes s'en charge tout seul.
    assert "pub.example" not in vue
    assert "tracker.example" not in vue


def test_deux_ip_exemptees_partagent_la_meme_vue_une_seule_fois(mod):
    # Le coût de la vue ne doit JAMAIS dépendre du nombre d'IP exemptées.
    mod.EXEMPT_IP.parent.mkdir(parents=True, exist_ok=True)
    mod.EXEMPT_IP.write_text("192.168.1.3\n192.168.1.4\n")
    st = mod.do_sync(systeme=Faux())
    texte = mod.DROPIN.read_text()
    assert st["exempt_ip"] == 2
    assert texte.count('name: "sbx-adult-allow"') == 1
    assert texte.count('local-zone: "cam-adulte.example." always_transparent') == 1
    assert "access-control-view: 192.168.1.3 sbx-adult-allow" in texte
    assert "access-control-view: 192.168.1.4 sbx-adult-allow" in texte


def test_une_config_refusee_remet_l_ancienne_octet_pour_octet(mod):
    mod.DROPIN.parent.mkdir(parents=True)
    mod.DROPIN.write_bytes(b"# ancienne vue\n")
    st = mod.do_sync(systeme=Faux(verif=(False, "syntax error")))
    assert st["ok"] is False and "unbound-checkconf" in st["error"]
    assert mod.DROPIN.read_bytes() == b"# ancienne vue\n"


def test_un_rechargement_qui_echoue_restaure_et_ne_redemarre_jamais(mod):
    mod.DROPIN.parent.mkdir(parents=True)
    mod.DROPIN.write_bytes(b"# ancienne vue\n")
    s = Faux(recharge_ok=False)
    st = mod.do_sync(systeme=s)
    assert st["ok"] is False and mod.DROPIN.read_bytes() == b"# ancienne vue\n"
    assert not hasattr(mod.Systeme, "redemarrer_unbound")


def test_desactiver_retire_la_vue_et_recharge(mod):
    mod.do_sync(systeme=Faux())
    s = Faux()
    st = mod.do_disable(systeme=s)
    assert st["ok"] is True and st["enabled"] is False and not mod.DROPIN.exists()
    assert s.appels == ["verifier", "recharger"]


def test_source_injoignable_sans_cache_echoue_proprement(mod):
    mod._fetch = lambda force=False: None
    st = mod.do_sync(systeme=Faux())
    assert st["ok"] is False and "unreachable" in st["error"]


# ── La vraie Systeme (#2969) : `unbound-control reload` rend la main dès le
# signal accepté — `recharger_unbound` doit ATTENDRE que `systemctl
# is-active` redevienne « active » avant de rendre la main, au lieu de
# croire le rechargement terminé. ──────────────────────────────────────────

def test_recharger_unbound_attend_que_le_service_redevienne_actif(mod):
    etats = iter(["reloading", "reloading", "active"])
    appels = []

    def _commande(args, delai):
        appels.append(args)
        if args[-1] == "reload":
            return True, ""
        if args == ["systemctl", "is-active", "unbound"]:
            return True, next(etats)
        raise AssertionError(args)

    s = mod.Systeme()
    with mock.patch.object(mod._unbound, "commande", side_effect=_commande), \
         mock.patch.object(mod.time, "sleep"):
        s.recharger_unbound()
    # 1 reload + 3 sondes (deux "reloading" avant le "active").
    assert sum(1 for a in appels if a[-1] == "reload") == 1
    assert appels.count(["systemctl", "is-active", "unbound"]) == 3


def test_recharger_unbound_leve_si_le_service_ne_redevient_jamais_actif(mod):
    def _commande(args, delai):
        if args[-1] == "reload":
            return True, ""
        if args == ["systemctl", "is-active", "unbound"]:
            return True, "reloading"
        raise AssertionError(args)

    s = mod.Systeme()
    horloge = iter([0, 10, 9999])  # 1er appel < fin, puis dépasse l'attente
    with mock.patch.object(mod._unbound, "commande", side_effect=_commande), \
         mock.patch.object(mod.time, "sleep"), \
         mock.patch.object(mod.time, "time", side_effect=lambda: next(horloge)):
        with pytest.raises(RuntimeError, match="n'est pas revenu actif"):
            s.recharger_unbound()
