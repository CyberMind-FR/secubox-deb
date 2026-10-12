# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#2489 — le journal d'audit d'autoload ne chevauche plus la règle logrotate générale de secubox-core.

Dans le dossier commun, `/var/log/secubox/*.log` (secubox-core, su secubox) et `autoload-audit.log` (secubox-autoload) se chevauchaient : logrotate refusait (« duplicate log entry »),
logrotate.service échouait chaque nuit, et la règle générale recréait le journal en secubox:secubox, que le service ne pouvait plus écrire."""
import fnmatch
import re
from pathlib import Path

RACINE = Path(__file__).resolve().parents[1]
NOUVEAU = "/var/log/secubox/autoload/audit.log"
ANCIEN = "autoload-audit.log"
GENERALE = "/var/log/secubox/*.log"                      # secubox-core/logrotate.d/secubox


def _lire(rel):
    return (RACINE / rel).read_text(encoding="utf-8")


def test_le_journal_n_est_plus_vu_par_la_regle_generale():
    # fnmatch.fnmatch laisse `*` franchir les `/` : on borne à la portée plate de logrotate (une seule composante)
    assert not re.fullmatch(r"/var/log/secubox/[^/]*\.log", NOUVEAU)
    assert re.fullmatch(r"/var/log/secubox/[^/]*\.log", "/var/log/secubox/autoload-audit.log")           # l'ancien chemin, lui, chevauchait
    assert fnmatch.fnmatch(NOUVEAU, "/var/log/secubox/autoload/*.log")


def test_aucune_reference_a_l_ancien_chemin_hors_historique():
    for rel in ("systemd/secubox-autoload.service", "autoload/jetons.py", "apparmor/secubox-autoload-api", "logrotate.d/secubox-autoload", "README.md"):
        s = _lire(rel)
        assert ANCIEN not in s or rel == "debian/postinst", rel
    assert NOUVEAU in _lire("systemd/secubox-autoload.service") and NOUVEAU in _lire("apparmor/secubox-autoload-api") and "/var/log/secubox/autoload/audit.log" in _lire("autoload/jetons.py")


def test_la_rotation_a_son_propre_compte_et_son_dossier():
    r = _lire("logrotate.d/secubox-autoload")
    assert r.lstrip().startswith("# ") and "/var/log/secubox/autoload/*.log {" in r and "su secubox-autoload secubox" in r and "create 0640 secubox-autoload secubox" in r


def test_le_service_peut_ecrire_son_dossier_et_le_profil_apparmor_aussi():
    assert "/var/log/secubox/autoload " in _lire("systemd/secubox-autoload.service") + " "
    assert "/var/log/secubox/autoload/ r," in _lire("apparmor/secubox-autoload-api")


def test_postinst_cree_le_dossier_migre_l_ancien_journal_et_donne_le_bon_proprietaire():
    p = _lire("debian/postinst")
    assert "install -d -o secubox-autoload -g secubox -m 0750 /var/log/secubox/autoload" in p
    assert "mv /var/log/secubox/autoload-audit.log /var/log/secubox/autoload/audit.log" in p
    assert "chown secubox-autoload:secubox /var/log/secubox/autoload/audit.log" in p
