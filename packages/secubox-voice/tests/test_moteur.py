# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

"""Le contrat de moteur (#1287).

On teste deux choses que l'on ne peut pas se permettre de rater : qu'un nom de
voix ne puisse pas servir à lire un fichier arbitraire, et qu'un moteur absent
se DISE absent au lieu de se taire.
"""
import asyncio

import pytest

from api.moteur import (MoteurDistant, MoteurIndisponible, MoteurLocal,
                        construire)


def lance(coro):
    return asyncio.run(coro)


# ── Le défaut est local, et ce n'est pas négociable ──────────────────────────

def test_defaut_est_local_jamais_distant():
    """Un défaut « distant » enverrait l'audio du micro chez un tiers dès
    l'installation. C'est le genre de défaut qu'on verrouille par un test."""
    assert isinstance(construire({}), MoteurLocal)
    assert isinstance(construire({"moteur": "n'importe quoi"}), MoteurLocal)
    assert isinstance(construire({"moteur": "distant", "distant": {"url": "http://x"}}),
                      MoteurDistant)


# ── Traversée de chemin par le nom de voix ───────────────────────────────────

@pytest.mark.parametrize("mechant", [
    "../../../../etc/passwd",
    "../../secrets/jwt",
    "/etc/shadow",
    "..",
])
def test_nom_de_voix_ne_sort_jamais_du_repertoire(tmp_path, mechant):
    voix = tmp_path / "voix"
    voix.mkdir()
    (voix / "lexie-fr.onnx").write_bytes(b"x")
    # Une cible plausible juste au-dessus : si la garde cède, elle est atteignable.
    (tmp_path / "passwd.onnx").write_bytes(b"secret")

    m = MoteurLocal(piper="piper", voix_dir=str(voix),
                    whisper="whisper-cli", modele_asr=str(tmp_path / "absent"))
    with pytest.raises(MoteurIndisponible):
        m._voix_fichier(mechant)


def test_nom_de_voix_legitime_est_resolu(tmp_path):
    voix = tmp_path / "voix"
    voix.mkdir()
    (voix / "lexie-fr.onnx").write_bytes(b"x")
    m = MoteurLocal(piper="piper", voix_dir=str(voix),
                    whisper="whisper-cli", modele_asr=str(tmp_path / "absent"))
    assert m._voix_fichier("lexie-fr").name == "lexie-fr.onnx"


# ── Un moteur absent le DIT ──────────────────────────────────────────────────

def test_moteur_local_incomplet_se_declare_et_nomme_ce_qui_manque(tmp_path):
    m = MoteurLocal(piper="binaire-qui-n-existe-pas", voix_dir=str(tmp_path),
                    whisper="autre-binaire-absent", modele_asr=str(tmp_path / "rien"))
    e = lance(m.etat())
    assert e.tts is False and e.asr is False
    # Le message doit être ACTIONNABLE : il finira affiché dans la fenêtre de
    # Lexie, donc il doit dire quoi installer et où.
    assert "synthèse" in e.detail and "reconnaissance" in e.detail
    assert "binaire-qui-n-existe-pas" in e.detail


def test_synthese_sans_piper_leve_indisponible_et_ne_rend_pas_de_silence(tmp_path):
    m = MoteurLocal(piper="binaire-absent", voix_dir=str(tmp_path),
                    whisper="w", modele_asr=str(tmp_path / "rien"))
    with pytest.raises(MoteurIndisponible):
        lance(m.dire("bonjour", "lexie-fr", "wav"))


def test_local_refuse_un_format_qu_il_ne_produit_pas(tmp_path):
    """Rendre du WAV étiqueté mp3 serait pire qu'un refus : l'appelant croirait
    avoir ce qu'il a demandé."""
    voix = tmp_path / "voix"
    voix.mkdir()
    (voix / "lexie-fr.onnx").write_bytes(b"x")
    m = MoteurLocal(piper="/bin/true", voix_dir=str(voix),
                    whisper="w", modele_asr=str(tmp_path / "rien"))
    with pytest.raises(MoteurIndisponible) as e:
        lance(m.dire("bonjour", "lexie-fr", "mp3"))
    assert "WAV" in str(e.value)


# ── Distant non configuré ────────────────────────────────────────────────────

def test_distant_sans_url_ne_tente_aucun_appel():
    m = MoteurDistant(url="", modele_tts="t", modele_asr="a")
    e = lance(m.etat())
    assert e.joignable is False and "voice.toml" in e.detail
    with pytest.raises(MoteurIndisponible):
        lance(m.dire("bonjour", "v", "wav"))
    with pytest.raises(MoteurIndisponible):
        lance(m.transcrire(b"\x00", "a.wav"))


def test_distant_ne_journalise_jamais_la_cle():
    """La clé ne doit apparaître ni dans repr, ni dans l'état affiché."""
    m = MoteurDistant(url="http://hote:3900", modele_tts="t", modele_asr="a",
                      cle="SECRET-A-NE-PAS-FUIR")
    assert "SECRET-A-NE-PAS-FUIR" not in repr(m)
    assert "SECRET-A-NE-PAS-FUIR" not in str(m.__dict__.get("url"))
    # Elle doit en revanche bien être posée en en-tête quand elle existe.
    assert m._entetes()["Authorization"].endswith("SECRET-A-NE-PAS-FUIR")
    assert MoteurDistant(url="u", modele_tts="t", modele_asr="a")._entetes() == {}
