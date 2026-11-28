# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#4040 — les règles apprises (regles-appliquer, chaque minute) se posent à chaud SOUS le verrou des listes DNS.

Un fast_reload de secubox-dns-listes qui a lu l'ancien drop-in effacerait au basculement une zone posée en mémoire entre-temps,
et l'instantané la croirait appliquée. Verrou occupé : rien n'est posé ni noté, la minute suivante refait la différence."""
import contextlib

from test_dnstv_auto_rendu import charger_ctl, faux, preparer, regles_essai


def _occupe(etat):
    @contextlib.contextmanager
    def v(_delai=10.0):
        yield etat["libre"]
    return v


def test_verrou_occupe_differe_puis_applique(monkeypatch, tmp_path):
    faux(tmp_path, "checkconf")
    ctl = faux(tmp_path, "unbound-control")
    mod = charger_ctl(monkeypatch, tmp_path, ctl)
    preparer(tmp_path, regles_essai("a.example.com"))
    mod.appliquer()
    (tmp_path / "unbound-control.log").unlink(missing_ok=True)
    etat = {"libre": False}
    monkeypatch.setattr(mod, "_verrou_depot", _occupe(etat))
    preparer(tmp_path, regles_essai("a.example.com", "b.example.com"))
    avant = (tmp_path / "applique.json").read_text()
    assert mod.regles_appliquer() == 0
    assert not (tmp_path / "unbound-control.log").exists()                 # rien posé pendant le rechargement des listes
    assert (tmp_path / "applique.json").read_text() == avant              # instantané intact : la différence reste due
    assert 'local-zone: "b.example.com." always_nxdomain' in (tmp_path / "94.conf").read_text()   # persisté (prochain fast_reload)
    etat["libre"] = True
    assert mod.regles_appliquer() == 0
    journal = (tmp_path / "unbound-control.log").read_text()
    assert "view_local_zone sbx-tv-auto-tv-banc b.example.com. always_nxdomain" in journal and "reload" not in journal
