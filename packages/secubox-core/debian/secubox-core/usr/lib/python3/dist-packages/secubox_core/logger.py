"""
secubox_core.logger — Logging structuré JSON vers journald/stderr
=================================================================
Usage :
    log = get_logger("crowdsec")
    log.info("Ban appliqué: %s", ip)
    log.warning("Échec connexion LAPI")
    log.error("Timeout netifyd socket")
"""
from __future__ import annotations
import json
import logging
import os
import sys
import time


class _JsonFormatter(logging.Formatter):
    """Formate chaque log en JSON sur une ligne (parseable par journald)."""

    def format(self, record: logging.LogRecord) -> str:
        doc = {
            "ts":      int(time.time()),
            "level":   record.levelname,
            "module":  record.name,
            "msg":     record.getMessage(),
        }
        if record.exc_info:
            doc["exc"] = self.formatException(record.exc_info)
        return json.dumps(doc, ensure_ascii=False)


def get_logger(name: str, level: str | None = None) -> logging.Logger:
    """
    Retourne un logger nommé `secubox.<name>`.
    Level par défaut : WARNING en prod, DEBUG si SECUBOX_DEBUG=1.
    """
    full_name = f"secubox.{name}"
    log = logging.getLogger(full_name)

    if log.handlers:
        return log  # déjà configuré

    # Level
    if level is None:
        level = "DEBUG" if os.environ.get("SECUBOX_DEBUG") else "WARNING"
    log.setLevel(getattr(logging, level.upper(), logging.WARNING))

    # Handler vers stderr (capturé par journald via systemd)
    h = logging.StreamHandler(sys.stderr)
    h.setFormatter(_JsonFormatter())
    log.addHandler(h)
    log.propagate = False

    return log
