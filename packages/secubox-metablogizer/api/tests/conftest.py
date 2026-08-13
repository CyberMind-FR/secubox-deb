
# Une config ILLISIBLE n'est pas une config absente (#1016).
#
# `secubox_core.config` teste `Path.exists()` puis ouvre le fichier : sur un
# poste de developpement, `/etc/secubox/secubox.conf` existe mais appartient a
# root, si bien que `exists()` repond oui et `open()` leve `PermissionError` a
# l'IMPORT du module teste. On pre-remplit donc le cache avec la valeur par
# defaut que le module aurait choisie s'il n'avait trouve aucun fichier.
try:
    open("/etc/secubox/secubox.conf", "rb").close()
except OSError:
    from secubox_core import config as _cfg
    if _cfg._CONFIG is None:
        _cfg._CONFIG = {
            "global": {"hostname": "secubox", "board": "unknown"},
            "api": {"socket_dir": "/tmp/secubox", "jwt_secret": "dev-secret"},
            "metablogizer": {},
        }
