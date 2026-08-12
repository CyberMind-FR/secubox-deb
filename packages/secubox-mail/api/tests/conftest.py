"""pytest conftest — make secubox_core importable when running locally
out of the source tree (no system-wide install)."""
import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[4]
COMMON = REPO_ROOT / "common"
if COMMON.is_dir() and str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

# Une config ILLISIBLE n'est pas une config absente (#1014).
#
# `secubox_core.config` teste `Path.exists()` puis ouvre le fichier : sur un
# poste de developpement, `/etc/secubox/secubox.conf` existe mais appartient a
# root, si bien que `exists()` repond oui et `open()` leve `PermissionError` a
# l'IMPORT du module teste. Toute la suite echouait alors a la collecte, sans
# rapport avec le code teste.
#
# On pre-remplit le cache du module : la valeur par defaut qu'il aurait choisie
# lui-meme s'il n'avait trouve aucun fichier.
try:
    open("/etc/secubox/secubox.conf", "rb").close()
except OSError:
    from secubox_core import config as _cfg
    if _cfg._CONFIG is None:
        _cfg._CONFIG = {
            "global": {"hostname": "secubox", "board": "unknown"},
            "api": {"socket_dir": "/tmp/secubox", "jwt_secret": "dev-secret"},
            "mail": {},
        }
