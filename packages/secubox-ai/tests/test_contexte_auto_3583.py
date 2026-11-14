# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Tests du contexte automatique et du lecteur GGUF (#3583), sur des fichiers GGUF synthétiques."""
import struct

import pytest

from api import contexte_auto as ca


def _s(t):
    b = t.encode()
    return struct.pack("<Q", len(b)) + b


def _kv(cle, valeur):
    """Encode une paire ; types déduits : int -> u32, str -> chaîne, list[int] -> tableau u32, ('u64', n)."""
    if isinstance(valeur, tuple):
        return _s(cle) + struct.pack("<IQ", 10, valeur[1])
    if isinstance(valeur, str):
        return _s(cle) + struct.pack("<I", 8) + _s(valeur)
    if isinstance(valeur, list):
        return (_s(cle) + struct.pack("<IIQ", 9, 4, len(valeur))
                + b"".join(struct.pack("<I", x) for x in valeur))
    return _s(cle) + struct.pack("<II", 4, valeur)


def ecrire_gguf(chemin, meta, remplissage=0, extra=b""):
    corps = b"".join(_kv(k, v) for k, v in meta.items()) + extra
    chemin.write_bytes(b"GGUF" + struct.pack("<IQQ", 3, 0, len(meta)) + corps + b"\0" * remplissage)
    return chemin


QWEN = {"general.architecture": "qwen35", "qwen35.block_count": 33, "qwen35.attention.head_count_kv": 4,
        "qwen35.attention.key_length": 256, "qwen35.attention.value_length": 256,
        "qwen35.full_attention_interval": 4}
LLAMA = {"general.architecture": "llama", "llama.block_count": 28, "llama.attention.head_count_kv": 8,
         "llama.attention.key_length": 128, "llama.attention.value_length": 128}


def test_kv_qwen35_hybride(tmp_path):
    assert ca.kv_par_jeton(ecrire_gguf(tmp_path / "q.gguf", QWEN))[0] == 32768


def test_kv_llama_sans_intervalle(tmp_path):
    assert ca.kv_par_jeton(ecrire_gguf(tmp_path / "l.gguf", LLAMA))[0] == 114688


def test_lire_meta_saute_les_autres_cles(tmp_path):
    meta = {"a.tableau": [1, 2, 3], "a.chaine": "bonjour", "a.u64": ("u64", 7), "cible": 42,
            "general.architecture": "llama"}
    f = ecrire_gguf(tmp_path / "m.gguf", meta)
    assert ca.lire_meta_gguf(f, {"cible", "a.tableau", "absente"}) == {"cible": 42, "a.tableau": [1, 2, 3]}
    assert ca.lire_meta_gguf(f, {"a.chaine"}) == {"a.chaine": "bonjour"}


def test_contexte_borne_haut_et_bas(tmp_path):
    f = ecrire_gguf(tmp_path / "l.gguf", LLAMA)
    assert ca.contexte_auto(f, 10**6, 10**6) == 32768
    assert ca.contexte_auto(f, 100, 10**6) == 4096
    assert ca.contexte_auto(f, 10**6, 0) == 4096


def test_contexte_intermediaire_arrondi_au_millier(tmp_path):
    f = ecrire_gguf(tmp_path / "l.gguf", LLAMA)  # 114 688 o/jeton, poids ~ 0 Mo
    # budget = min(1912 - 512, ...) = 1400 Mo -> 1400 Mo / 112 Kio = 12800 jetons
    assert ca.contexte_auto(f, 1912, 10**6) == 12288


def test_contexte_plafonne_par_le_modele(tmp_path):
    f = ecrire_gguf(tmp_path / "l.gguf", {**LLAMA, "llama.context_length": 8192})
    assert ca.contexte_auto(f, 10**6, 10**6) == 8192


def test_entete_illisible(tmp_path):
    f = tmp_path / "x.gguf"
    f.write_bytes(b"pas du gguf du tout")
    assert ca.kv_par_jeton(f) == (None, None)
    assert ca.contexte_auto(f, 10**6, 10**6) == 4096
    assert ca.contexte_auto(tmp_path / "absent.gguf", 10**6, 10**6) == 4096


@pytest.mark.parametrize("entete", [
    b"GGUF" + struct.pack("<IQQ", 3, 0, 10**12),                      # nombre de paires absurde
    b"GGUF" + struct.pack("<IQQ", 3, 0, 1) + struct.pack("<Q", 10**12),  # clé géante
    b"GGUF" + struct.pack("<IQQ", 3, 0, 1) + _s("k") + struct.pack("<IIQ", 9, 4, 10**15),  # tableau géant
    b"GGUF" + struct.pack("<IQQ", 3, 0, 1) + _s("k") + struct.pack("<II", 99, 0),  # type inconnu
    b"GGUF" + struct.pack("<IQQ", 3, 0, 2) + _s("k") + struct.pack("<II", 4, 1),  # tronqué
])
def test_fichier_malforme_rejete(tmp_path, entete):
    f = tmp_path / "m.gguf"
    f.write_bytes(entete)
    with pytest.raises(ValueError):
        ca.lire_meta_gguf(f, {"zz"})


def test_chaine_geante_sautee_sans_lecture(tmp_path):
    corps = _s("grosse") + struct.pack("<I", 8) + struct.pack("<Q", 10**12)
    f = tmp_path / "g.gguf"
    f.write_bytes(b"GGUF" + struct.pack("<IQQ", 3, 0, 1) + corps)
    with pytest.raises(ValueError):
        ca.lire_meta_gguf(f, {"grosse"})
