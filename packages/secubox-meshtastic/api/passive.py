# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""SecuBox-Deb :: meshtastic — passive capture (packet log + census + stats)."""
from __future__ import annotations
import base64
import json
from pathlib import Path
from .model import Packet


class PassiveCapture:
    def __init__(self, log_path: Path) -> None:
        self.log_path = Path(log_path)
        self._census: dict[str, dict] = {}
        self._chan: dict[int, dict] = {}

    def record(self, p: Packet, now: float, decrypted: bool) -> None:
        line = {"ts": now, "from": p.from_id, "to": p.to_id, "channel": p.channel,
                "portnum": p.portnum, "rssi": p.rssi, "snr": p.snr, "hop": p.hop,
                "decrypted": decrypted}
        if decrypted and p.decoded is not None:
            line["payload"] = p.decoded
        # Le recensement est mis a jour AVANT l'ecriture. Auparavant l'ordre
        # etait inverse : une ecriture qui echouait faisait remonter
        # l'exception et le recensement n'etait jamais atteint — le
        # « census » restait vide alors que les paquets arrivaient bien.
        c = self._census.setdefault(p.from_id, {"id": p.from_id, "first_heard": now,
                                                "last_heard": now, "packets": 0,
                                                "rssi": p.rssi, "snr": p.snr})
        c["last_heard"] = now
        c["packets"] += 1
        c["rssi"], c["snr"] = p.rssi, p.snr
        cs = self._chan.setdefault(p.channel, {"packets": 0, "decrypted": 0})
        cs["packets"] += 1
        cs["decrypted"] += 1 if decrypted else 0
        self._append(line)

    def census(self) -> list[dict]:
        return list(self._census.values())

    def channel_stats(self) -> dict[int, dict]:
        return dict(self._chan)

    @staticmethod
    def _encodable(o):
        """Rend serialisable ce que json ne sait pas ecrire.

        Les paquets Meshtastic portent leur charge utile en OCTETS bruts.
        `json.dumps` levait donc une TypeError sur chaque paquet, le journal
        restait vide et le recensement inatteignable.
        """
        if isinstance(o, (bytes, bytearray)):
            return base64.b64encode(bytes(o)).decode("ascii")
        return repr(o)

    def _append(self, obj: dict) -> None:
        # Une ecriture qui echoue ne doit jamais faire perdre la reception :
        # le journal passif est un confort, pas le coeur du module.
        try:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            with self.log_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(obj, default=self._encodable) + "\n")
        except (OSError, ValueError, TypeError):
            pass
