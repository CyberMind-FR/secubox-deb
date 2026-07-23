# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""La série Z n'accepte que HTTPS. Une terminaison TLS absente ou mal câblée
rend l'appareil inutilisable sans message d'erreur exploitable."""
import subprocess
from pathlib import Path

CTL = str(Path(__file__).resolve().parents[1] / "sbin" / "picobrewctl")

def _emit() -> str:
    p = subprocess.run(["bash", CTL, "__emit-nginx"], capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    return p.stdout

def test_nginx_terminates_tls_on_443():
    cfg = _emit()
    assert "listen 443 ssl" in cfg
    assert "ssl_certificate" in cfg and "ssl_certificate_key" in cfg

def test_nginx_proxies_to_the_local_flask_app():
    cfg = _emit()
    assert "proxy_pass http://127.0.0.1:80" in cfg

def test_nginx_does_not_bind_80_which_would_loop_onto_itself():
    """Flask occupe déjà :80 (comportement upstream attendu par Pico/Zymatic).
    Faire écouter nginx sur :80 tout en proxifiant vers 127.0.0.1:80 le ferait
    se parler à lui-même — boucle infinie. nginx ne prend QUE le 443."""
    assert "listen 80" not in _emit()
