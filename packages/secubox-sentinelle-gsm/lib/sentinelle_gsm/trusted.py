# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gerald Kerma <devel@cybermind.fr>

"""
Trusted phones registry — HMAC-hashed IMSI mapping to operator-owned
device labels. Persisted to /etc/secubox/sentinelle-gsm/trusted.json.

Privacy: plaintext IMSI is accepted ONLY by `add()` and is hashed via
the existing Anonymizer before any storage call. No function ever
returns a plaintext IMSI. The on-disk JSON holds only hashes.

Storage rationale: JSON (stdlib) instead of TOML. `python3-tomli-w`
(the only writer for the new tomllib reader) is not in Debian bookworm
— ships first in trixie. python3-toml (legacy) writes TOML but is
deprecated. JSON is stdlib, atomically renderable, and human-grep-able,
which is what a trusted-phones registry needs.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

from sentinelle_gsm.observer import Anonymizer


@dataclass
class TrustedPhone:
    id: str
    imsi_hash: str
    label: str
    added_at: float


class TrustedRegistry:
    def __init__(self, path: Path, anonymizer: Anonymizer):
        self.path = Path(path)
        self._anon = anonymizer
        self._phones: dict[str, TrustedPhone] = {}
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        raw = self.path.read_text()
        if not raw.strip():
            return
        data = json.loads(raw)
        for entry in data.get("phones", []):
            p = TrustedPhone(
                id=entry["id"],
                imsi_hash=entry["imsi_hash"],
                label=entry.get("label", ""),
                added_at=entry.get("added_at", time.time()),
            )
            self._phones[p.id] = p

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"phones": [asdict(p) for p in self._phones.values()]}
        self.path.write_text(json.dumps(payload, indent=2, sort_keys=True))
        self.path.chmod(0o640)

    def add(self, plaintext_imsi: str, label: str) -> TrustedPhone:
        """Hash the plaintext IMSI, persist the hash + label, discard plaintext.

        Hash representation: `imsi.encode("ascii").hex()` so the resulting
        token matches the canonical form produced by the L3 decoder's
        paging-request path (l3_decode._parse_paging() anonymizes
        `plaintext_bytes.hex()` where `plaintext_bytes = digits.encode("ascii")`).
        This is what enables trusted-phone lookup against paged-subscriber
        hashes in the consume loop.
        """
        if not plaintext_imsi.isdigit() or not (14 <= len(plaintext_imsi) <= 15):
            raise ValueError("IMSI must be 14 or 15 digits")
        imsi_hash = self._anon.anonymize(plaintext_imsi.encode("ascii").hex())
        phone = TrustedPhone(
            id=str(uuid.uuid4()),
            imsi_hash=imsi_hash,
            label=label,
            added_at=time.time(),
        )
        self._phones[phone.id] = phone
        self._save()
        # `plaintext_imsi` goes out of scope here
        return phone

    def list(self) -> list[TrustedPhone]:
        return list(self._phones.values())

    def get_by_id(self, phone_id: str) -> Optional[TrustedPhone]:
        return self._phones.get(phone_id)

    def lookup_by_hash(self, imsi_hash: str) -> Optional[TrustedPhone]:
        """Detector calls this when a paging request matches an IMSI hash."""
        for p in self._phones.values():
            if p.imsi_hash == imsi_hash:
                return p
        return None

    def delete(self, phone_id: str) -> bool:
        if phone_id not in self._phones:
            return False
        del self._phones[phone_id]
        self._save()
        return True
