# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3206 — le relais assure lui-même le joker DNS d'un pair (« *.<domaine-du-pair> A <ip publique> ») par le module DNS
d'ici, AVANT le certificat joker. Vécu sur gk4 (2026-10-27) : le défi DNS-01 a créé _acme-challenge.gk4.secubox.in, le
joker parent *.secubox.in ne couvrait plus admin.gk4… et le relais refusait 19 noms (« résout vers rien ») jusqu'à la
création à la main de *.gk4 chez Gandi. Délai de l'unité porté de 15 à 45 min (une vingtaine de noms sur gk2 saturé)."""
import re
import subprocess
from pathlib import Path

RACINE = Path(__file__).resolve().parents[1]
SCRIPT = RACINE / "sbin" / "secubox-relais-maillage"
TEXTE = SCRIPT.read_text()
UNITE = (RACINE / "systemd" / "secubox-relais-maillage.service").read_text()


def _fonction(nom):
    debut = TEXTE.index(f"{nom}() {{")
    fin = TEXTE.index("\n}\n", debut) + 3
    return TEXTE[debut:fin]


def test_joker_dns_avant_le_certificat():
    sync = TEXTE[TEXTE.index("cmd_synchroniser() {"):]
    i_dns = sync.index('dns_joker_assure "$dpair" "$pub" "${dom#*.}" "$ip"')
    i_cert = re.search(r'(?<!dns_)joker_assure "\$dpair"', sync).start()      # le certificat, pas dns_joker_assure
    assert i_dns < i_cert


def test_outil_surchargeable_pour_les_essais():
    assert re.search(r'^DNS_JOKER="\$\{SECUBOX_DNS_JOKER:-/usr/sbin/secubox-dns-joker\}"(\s+#.*)?$', TEXTE, re.M)


def _executer(tmp_path, sortie_outil, code_outil=0, resout=True):
    outil = tmp_path / "secubox-dns-joker"
    outil.write_text(f"#!/bin/bash\necho \"$@\" >> {tmp_path}/appels\nprintf '%s\\n' '{sortie_outil}'\nexit {code_outil}\n")
    outil.chmod(0o755)
    harnais = "\n".join([
        "set -u",
        f'DNS_JOKER="{outil}"',
        "PAS_DNS=0",
        "ATTENTE_DNS_PAS=3",
        'log() { echo "LOG $*"; }',
        f"resout_vers() {{ return {0 if resout else 1}; }}",
        f'audit_relais() {{ echo "$@" >> {tmp_path}/audit; }}',
        _fonction("dns_joker_assure"),
        'dns_joker_assure gk4.secubox.in 82.67.100.75 secubox.in 10.10.0.9; echo "RC $?"',
    ])
    r = subprocess.run(["bash", "-c", harnais], capture_output=True, text=True, timeout=20)
    appels = (tmp_path / "appels").read_text() if (tmp_path / "appels").exists() else ""
    return r.stdout, appels


def test_cree_puis_attend_la_propagation(tmp_path):
    out, appels = _executer(tmp_path, '{"etat": "cree", "nom": "*.gk4"}')
    assert appels.strip() == "assurer gk4.secubox.in 82.67.100.75 secubox.in"     # zone parente du relais
    assert (tmp_path / "audit").read_text().strip() == "joker_dns_cree *.gk4.secubox.in 10.10.0.9"
    assert "créé chez le registraire" in out and "hall.gk4.secubox.in → 82.67.100.75" in out
    assert out.strip().endswith("RC 0")


def test_deja_juste_sans_attente(tmp_path):
    out, _ = _executer(tmp_path, '{"etat": "inchange", "nom": "*.gk4"}')
    assert "créé" not in out and out.strip().endswith("RC 0")


def test_propagation_lente_ne_bloque_pas(tmp_path):
    out, _ = _executer(tmp_path, '{"etat": "cree", "nom": "*.gk4"}', resout=False)
    assert "prochaine synchronisation" in out and out.strip().endswith("RC 0")


def test_refus_dit_et_rend_1(tmp_path):
    out, _ = _executer(tmp_path, '{"erreur": "*.gk4.secubox.in existe déjà vers 203.0.113.9 : jamais écrasé"}', code_outil=3)
    assert "non assuré" in out and "jamais écrasé" in out and out.strip().endswith("RC 1")


def test_sans_module_dns_rend_1_en_silence(tmp_path):
    harnais = "\n".join(["set -u", f'DNS_JOKER="{tmp_path}/absent"', 'log() { echo "LOG $*"; }',
                         "resout_vers() { return 0; }", "audit_relais() { :; }", "PAS_DNS=0", "ATTENTE_DNS_PAS=1",
                         _fonction("dns_joker_assure"),
                         'dns_joker_assure gk4.secubox.in 82.67.100.75 secubox.in 10.10.0.9; echo "RC $?"'])
    r = subprocess.run(["bash", "-c", harnais], capture_output=True, text=True, timeout=20)
    assert r.stdout.strip() == "RC 1"


def test_delai_de_l_unite():
    assert re.search(r"^TimeoutStartSec=45min$", UNITE, re.M)


def test_zone_autorisee_est_la_zone_parente_du_relais():
    """gk2.secubox.in → secubox.in : ${dom#*.} retire le premier libellé du domaine du relais."""
    r = subprocess.run(["bash", "-c", 'dom=gk2.secubox.in; echo "${dom#*.}"'], capture_output=True, text=True)
    assert r.stdout.strip() == "secubox.in"


def test_appel_borne_dans_le_temps():
    assert 'timeout 180 "$DNS_JOKER" assurer' in _fonction("dns_joker_assure")
