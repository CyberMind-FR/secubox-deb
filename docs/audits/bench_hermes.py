#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Banc d'essai de `secubox_core.crypto.hermes` — mêmes mesures sur chaque machine.

Méthode, énoncée pour que le chiffre soit lisible :
  · chaque opération est chauffée avant d'être mesurée (JIT d'OpenSSL, caches,
    montée en fréquence) ;
  · on rapporte la MEDIANE de plusieurs séries, pas la meilleure valeur — le
    meilleur temps flatte la machine au repos et ne dit rien d'un service qui
    tourne ;
  · le nombre d'itérations est calibré par opération pour que chaque série dure
    assez longtemps à être stable sans immobiliser la box ;
  · le débit est calculé sur la taille du CLAIR, tag et nonce exclus.
"""
from __future__ import annotations

import json
import os
import platform
import statistics
import sys
import tempfile
import time

# PYTHONPATH d'abord (arbre de développement), paquet installé ensuite : un
# `secubox_core` système plus ancien, sans sous-module `crypto`, masquerait
# sinon celui qu'on veut mesurer.
try:
    from secubox_core.crypto import hermes as H
except ImportError:
    sys.path.append("/usr/lib/python3/dist-packages")
    from secubox_core.crypto import hermes as H  # type: ignore


def _chrono(fn, iters: int, series: int = 5) -> float:
    """Secondes par opération (médiane des séries)."""
    for _ in range(max(1, iters // 10)):      # chauffe
        fn()
    mesures = []
    for _ in range(series):
        t = time.perf_counter()
        for _ in range(iters):
            fn()
        mesures.append((time.perf_counter() - t) / iters)
    return statistics.median(mesures)


def machine() -> dict:
    cpu, mhz, cores = "?", "", os.cpu_count()
    try:
        with open("/proc/cpuinfo", encoding="utf-8") as fh:
            for ligne in fh:
                if ligne.startswith(("model name", "Model", "Hardware", "CPU part")) and cpu == "?":
                    cpu = ligne.split(":", 1)[1].strip()
                if ligne.startswith("cpu MHz") and not mhz:
                    mhz = ligne.split(":", 1)[1].strip()
    except OSError:
        pass
    try:
        with open("/sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq", encoding="utf-8") as fh:
            mhz = str(int(fh.read().strip()) // 1000)
    except OSError:
        pass
    import cryptography
    from cryptography.hazmat.backends.openssl.backend import backend
    return {
        "hote": platform.node(),
        "arch": platform.machine(),
        "cpu": cpu,
        "coeurs": cores,
        "mhz_max": mhz,
        "noyau": platform.release(),
        "python": platform.python_version(),
        "cryptography": cryptography.__version__,
        "openssl": backend.openssl_version_text(),
    }


def mesures() -> dict:
    out: dict = {}

    # ── clés et sessions ────────────────────────────────────────────────
    out["identity_generate"] = _chrono(H.Identity.generate, 200)

    a, b = H.Identity.generate(), H.Identity.generate()
    pb = bytes.fromhex(b.public_hex())
    out["session_establish"] = _chrono(lambda: H.Session.establish(a, pb), 200)

    s_a = H.Session.establish(a, pb)
    out["confirmation"] = _chrono(s_a.confirmation, 500)
    out["derive_key_material"] = _chrono(
        lambda: H.derive_key_material(b"\x00" * 32, info=b"banc", length=32), 2000)

    with tempfile.TemporaryDirectory() as d:
        i = 0

        def _save():
            nonlocal i
            i += 1
            a.save(os.path.join(d, f"k{i}.pem"))
        out["identity_save"] = _chrono(_save, 100)
        chemin = os.path.join(d, "k1.pem")
        out["identity_load"] = _chrono(lambda: H.Identity.load(chemin), 200)

    # ── chiffrement authentifié, par taille de message ──────────────────
    s_b = H.Session.establish(b, bytes.fromhex(a.public_hex()))
    tailles = [64, 1024, 16 * 1024, 256 * 1024, 1024 * 1024]
    iters = {64: 3000, 1024: 3000, 16 * 1024: 800, 256 * 1024: 120, 1024 * 1024: 40}
    out["aead"] = {}
    for n in tailles:
        clair = os.urandom(n)
        s_a._envois = 0
        enc = _chrono(lambda: s_a.encrypt(clair, b"aad"), iters[n])
        paquet = s_a.encrypt(clair, b"aad")
        dec = _chrono(lambda: s_b.decrypt(paquet, b"aad"), iters[n])
        out["aead"][n] = {"encrypt_s": enc, "decrypt_s": dec}
    return out


if __name__ == "__main__":
    print(json.dumps({"machine": machine(), "mesures": mesures()}, ensure_ascii=False))
