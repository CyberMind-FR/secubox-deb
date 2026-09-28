# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Le coffre des accès, par PERSONNE (#1562)."""
import json
import os

from secubox_core import coffre as K

U = "fd980586-ccb5-43de-9af6-faeae690bb42"


def test_cle_de_personne_et_refus(monkeypatch, tmp_path):
    assert K.cle_personne(U) == f"p-{U}"
    for mauvais in ("", "../etc", "gek", None):
        assert K.cle_personne(mauvais) is None


def test_pose_machine_0700_0600(monkeypatch, tmp_path):
    monkeypatch.setenv("SECUBOX_WEBOS_ACCES", str(tmp_path))
    assert K.pose_machine(U, "mail", "gek@secubox.in", "s3cr3t")
    d = tmp_path / f"p-{U}"
    assert oct(os.stat(d).st_mode)[-3:] == "700" and oct(os.stat(d / "mail.json").st_mode)[-3:] == "600"
    v = json.loads((d / "mail.json").read_text())
    assert v["voie"] == "machine" and v["compte"] == "gek@secubox.in" and v["qui"] == f"p-{U}"
    assert not K.pose_machine(U, "../x", "a", "b") and not K.pose_machine("pas-un-uuid!", "mail", "a", "b")


def test_reprise_d_un_coffre_d_appareil(monkeypatch, tmp_path):
    """Deux appareils, une personne : l'ancien coffre est DÉPLACÉ, jamais écrasé."""
    monkeypatch.setenv("SECUBOX_WEBOS_ACCES", str(tmp_path))
    a = tmp_path / "sbx-3704f0234ea3"
    a.mkdir()
    (a / "mastodon.json").write_text(json.dumps({"svc": "mastodon", "qui": "sbx-3704f0234ea3", "secret": "tok"}))
    (a / "mail.json").write_text(json.dumps({"svc": "mail", "secret": "ancien"}))
    (a / "nextcloud.flux.json").write_text("{}")                      # jeton de flux : reste
    K.pose_machine(U, "mail", "gek@secubox.in", "machine")
    assert K.reprend("sbx-3704f0234ea3", f"p-{U}") == 1
    b = tmp_path / f"p-{U}"
    assert json.loads((b / "mastodon.json").read_text())["qui"] == f"p-{U}"
    assert json.loads((b / "mail.json").read_text())["secret"] == "machine"          # pas écrasé
    assert not (a / "mastodon.json").exists() and (a / "mail.json").exists()        # déplacé / laissé
    assert K.reprend("sbx-3704f0234ea3", f"p-{U}") == 0                               # idempotent
