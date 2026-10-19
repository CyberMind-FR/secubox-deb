# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#2948 — gk2 héberge apt.secubox.in sans jamais le consommer lui-même : gpg-setup doit exporter
la clé publique même quand elle existait déjà (cas réel de gk2), et `local-source` doit écrire
une source apt locale (file://) signée avec cette clé."""
import os
import subprocess
from pathlib import Path

PKG = Path(__file__).resolve().parents[1]
REPOCTL = PKG / "sbin" / "repoctl"


def _env(tmp_path, **extra):
    base = tmp_path / "base"
    out = tmp_path / "out"
    env = dict(os.environ, REPO_BASE=str(base), REPO_OUT=str(out), GPG_EMAIL="test-2948@secubox.in")
    env.update(extra)
    return env, base, out


def _gpg_rapide(env, base):
    """Génère une clé de test (ed25519, rapide) directement dans GPG_HOME — on ne passe pas par
    `repoctl gpg-setup` pour cette étape : on veut tester son chemin « la clé existe déjà »,
    pas sa génération (RSA 4096 est bien trop lente pour un test)."""
    gpg_home = base / "gpg"
    gpg_home.mkdir(parents=True)
    gpg_home.chmod(0o700)
    subprocess.run(
        ["gpg", "--homedir", str(gpg_home), "--batch", "--passphrase", "", "--quick-generate-key",
         env["GPG_EMAIL"], "ed25519", "sign", "0"],
        env=env, check=True, capture_output=True, text=True,
    )


def test_gpg_setup_exporte_la_cle_meme_si_elle_existe_deja(tmp_path):
    env, base, out = _env(tmp_path)
    _gpg_rapide(env, base)
    r = subprocess.run(["bash", str(REPOCTL), "gpg-setup"], env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert "already exists" in r.stdout
    assert (out / "secubox-keyring.gpg").exists() and (out / "secubox-keyring.gpg.bin").exists()
    assert (out / "secubox-keyring.gpg").read_text().startswith("-----BEGIN PGP PUBLIC KEY BLOCK-----")


def test_local_source_ecrit_la_source_et_le_trousseau(tmp_path):
    env, base, out = _env(tmp_path)
    _gpg_rapide(env, base)
    keyring_dir = tmp_path / "keyrings"
    sources_file = tmp_path / "sources.list.d" / "secubox-local.list"
    env["APT_KEYRING_DIR"] = str(keyring_dir)
    env["APT_SOURCES_FILE"] = str(sources_file)
    r = subprocess.run(["bash", str(REPOCTL), "local-source"], env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert (keyring_dir / "secubox-apt.gpg").is_file() and (keyring_dir / "secubox-apt.gpg").stat().st_size > 0
    texte = sources_file.read_text()
    assert f"file:{out} bookworm main" in texte and f"file:{out} trixie main" in texte
    assert f"signed-by={keyring_dir}/secubox-apt.gpg" in texte


def test_local_source_refuse_sans_cle(tmp_path):
    env, base, out = _env(tmp_path)
    base.mkdir(parents=True)
    r = subprocess.run(["bash", str(REPOCTL), "local-source"], env=env, capture_output=True, text=True)
    assert r.returncode != 0 and "GPG key not found" in (r.stdout + r.stderr)
