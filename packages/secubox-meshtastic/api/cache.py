# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""SecuBox-Deb :: meshtastic — double-cache (in-mem + state.json + bg thread)."""
from __future__ import annotations
import copy, json, os, tempfile, threading
from pathlib import Path
from typing import Callable


class StateCache:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
        self._mem: dict = {}

    def update(self, state: dict) -> None:
        with self._lock:
            self._mem = copy.deepcopy(state)
            self._write_atomic(self._mem)

    def get(self) -> dict:
        with self._lock:
            if self._mem:
                return copy.deepcopy(self._mem)
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {"radio": "absent"}

    def start_refresh(self, producer: Callable[[], dict], interval: float,
                      stop: threading.Event) -> None:
        threading.Thread(target=self._refresh_loop, args=(producer, interval, stop),
                         daemon=True).start()

    def _refresh_loop(self, producer, interval, stop) -> None:
        while not stop.is_set():
            try:
                self.update(producer())
            except Exception:
                pass
            stop.wait(interval)

    def _write_atomic(self, state: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".state-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(state, f)
            os.replace(tmp, self.path)
        except BaseException:
            try: os.unlink(tmp)
            except FileNotFoundError: pass
            raise
