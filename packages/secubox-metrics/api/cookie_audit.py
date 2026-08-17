# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: CookieAuditAggregator
Reconciles the mitmproxy Set-Cookie ledger (server) with browser snapshots
(client) and produces a per-vhost RGPD / ePrivacy compliance report.

Sources:
  - "http" : seen in mitmproxy ledger, not in any browser snapshot.
  - "js"   : seen in a browser snapshot but NEVER in a Set-Cookie response
             header. Posed by client-side JavaScript → requires prior consent
             unless strictly necessary (LCEN art. 82 / ePrivacy).
  - "both" : seen in both — classification still drives the verdict.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

log = logging.getLogger("secubox.cookie_audit")

DEFAULT_CACHE_PATH = Path("/var/cache/secubox/metrics/cookie-audit.json")
DEFAULT_LEDGER = "/var/log/secubox/cookie-audit/server.jsonl"
DEFAULT_INGEST_DIR = "/var/lib/secubox/cookie-audit/ingest"


class Classifier:
    """Maps a cookie name to a RGPD category via regex patterns.

    Categories are checked in the order:
    strictly_necessary → functional → analytics → marketing.
    First match wins; unmatched names get the ``unclassified`` label.
    """

    CATEGORIES = ("strictly_necessary", "functional", "analytics", "marketing")

    def __init__(self, rules: dict):
        self._compiled: dict = {}
        for cat in self.CATEGORIES:
            patterns = rules.get(cat, []) or []
            self._compiled[cat] = [re.compile(p) for p in patterns]

    def classify(self, name: str) -> str:
        for cat in self.CATEGORIES:
            for rx in self._compiled[cat]:
                if rx.search(name):
                    return cat
        return "unclassified"


def classify_cookie(name: str, rules: dict) -> str:
    return Classifier(rules).classify(name)


class CookieAuditAggregator:
    def __init__(self, cfg: dict, cache_path: Optional[Path] = None):
        self.cfg = cfg
        self.cache_path = Path(cache_path) if cache_path else DEFAULT_CACHE_PATH
        self._payload: dict = {"enabled": False, "hosts": []}
        # ── ETAT DE LECTURE INCREMENTALE (#1045) ────────────────────────────
        # Le registre est APPEND-ONLY : ce qui a ete lu au cycle precedent ne
        # peut plus changer. On retient donc ou l'on s'est arrete, et le
        # resultat deja construit.
        #
        # Mesure qui a motive ce changement : 35 082 lignes relues chaque
        # minute pour en retenir 25 — 99,9 % du travail jete, et refait
        # indefiniment. Le fichier ne grandit que de ~6 ko par minute.
        self._ledger_cle: tuple | None = None   # (dev, inode) : detecte la rotation
        self._ledger_pos: int = 0               # octets deja consommes
        self._ledger_out: dict = {}             # {vhost: {cookie: dernier enreg.}}
        # Ingest : 166 fichiers dont la plupart n'ont pas bouge depuis des mois.
        # On garde le resultat par fichier, reutilise tant que mtime ET taille
        # sont inchanges.
        self._ingest_cache: dict = {}           # {chemin: (mtime, taille, resultat)}

    def current(self) -> dict:
        if self._payload.get("hosts") or self._payload.get("enabled"):
            return dict(self._payload)
        if self.cache_path.exists():
            try:
                return json.loads(self.cache_path.read_text())
            except Exception:
                pass
        return {"enabled": False, "hosts": []}

    async def run_forever(self) -> None:
        while True:
            try:
                self._payload = await self.refresh_once()
            except Exception as e:
                log.warning("refresh_once raised: %s", e)
            await asyncio.sleep(60)

    async def refresh_once(self) -> dict:
        if not self.cfg.get("enabled"):
            self._payload = {"enabled": False, "hosts": []}
            self._persist(self._payload)
            return self._payload
        ledger_path = Path(self.cfg.get("ledger_path", DEFAULT_LEDGER))
        ingest_dir = Path(self.cfg.get("ingest_dir", DEFAULT_INGEST_DIR))
        classifier = Classifier(self.cfg.get("classifier", {}))
        # HORS DE LA BOUCLE D'EVENEMENTS (#1045). Ces deux lectures sont
        # synchrones et peuvent durer : tant qu'elles tournaient sur la boucle,
        # les endpoints HTTP du module etaient bloques pendant tout ce temps —
        # le motif qui a deja produit des 502. `live_hosts` deleguait deja au
        # pool de threads ; il n'y avait aucune raison que celui-ci ne le fasse
        # pas.
        server, browser = await asyncio.to_thread(
            self._lire_sources, ledger_path, ingest_dir)
        hosts = self._reconcile(server, browser, classifier)
        payload = {
            "enabled": True,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "hosts": hosts,
            "summary": self._summarize(hosts),
        }
        self._persist(payload)
        self._payload = payload
        return payload

    def _lire_sources(self, ledger_path: Path, ingest_dir: Path) -> tuple:
        """Les deux lectures, ensemble, dans UN seul aller-retour de thread.

        Deux `to_thread` separes auraient double le cout de bascule pour un
        gain nul : elles sont sequentielles de toute facon.
        """
        return self._read_ledger(ledger_path), self._read_ingest(ingest_dir)

    def _read_ledger(self, path: Path) -> dict:
        """Return {vhost: {cookie_name: latest server record}}.

        LECTURE INCREMENTALE (#1045). Le journal est append-only : les lignes
        deja lues ne changeront plus, et seul le dernier enregistrement par
        (vhost, cookie) est conserve. Relire le fichier entier a chaque cycle
        refaisait donc indefiniment un travail dont 99,9 % etait jete.

        TROIS SITUATIONS, ET UNE SEULE EST LE CAS COURANT :

        * fichier inchange ou simplement rallonge -> on ne decode que les
          octets neufs, et on les fusionne dans le resultat deja construit ;
        * fichier remplace (rotation logrotate : l'inode change) ou tronque
          (taille inferieure a notre position) -> on repart de zero, comme le
          faisait l'ancienne version a chaque cycle. Le resultat est alors
          identique a ce qu'elle produisait ;
        * fichier absent -> resultat vide, et l'etat est remis a zero pour ne
          pas ressusciter d'anciennes valeurs si le fichier reapparait.
        """
        if not path.exists():
            self._ledger_cle, self._ledger_pos, self._ledger_out = None, 0, {}
            return {}
        try:
            st = path.stat()
            cle = (st.st_dev, st.st_ino)
            # ROTATION OU TRONCATURE : on ne peut pas continuer une lecture
            # dans un fichier qui n'est plus le meme. On repart du debut, et
            # on OUBLIE l'accumule — c'est ce que faisait l'ancienne version,
            # qui ne voyait jamais que le fichier courant. Conserver l'historique
            # serait sans doute mieux, mais changerait la sortie.
            if cle != self._ledger_cle or st.st_size < self._ledger_pos:
                self._ledger_cle, self._ledger_pos, self._ledger_out = cle, 0, {}
            if st.st_size == self._ledger_pos:
                return self._ledger_out          # rien de neuf : cas le plus courant

            with path.open("rb") as fh:
                fh.seek(self._ledger_pos)
                brut = fh.read(st.st_size - self._ledger_pos)

            # UNE LIGNE PARTIELLE NE SE DECODE PAS. Le producteur ecrit pendant
            # qu'on lit : sans cette coupure, la derniere ligne serait tronquee,
            # rejetee comme illisible, et PERDUE — puisqu'on ne la relirait
            # jamais. On s'arrete au dernier saut de ligne complet.
            coupe = brut.rfind(b"\n")
            if coupe < 0:
                return self._ledger_out          # pas encore une ligne entiere
            consomme, brut = coupe + 1, brut[:coupe + 1]
            self._ledger_pos += consomme

            for line in brut.decode("utf-8", "replace").splitlines():
                if not line.strip():
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                vhost = (rec.get("vhost") or "").strip()
                name = (rec.get("name") or "").strip()
                if not vhost or not name:
                    continue
                self._ledger_out.setdefault(vhost, {})[name] = rec
        except Exception as e:
            log.warning("ledger read failed: %s", e)
        return self._ledger_out

    def _read_ingest(self, ingest_dir: Path) -> dict:
        """Return {vhost: {cookie_name: set(value_hash)}} across all snapshots.

        CACHE PAR FICHIER (#1045). Contrairement au registre, ces instantanes
        sont reecrits en entier — on ne peut donc pas lire par offset. Mais ils
        bougent rarement : sur la board, 166 fichiers pour 13 Mo, dont la
        plupart n'ont pas ete modifies depuis des mois, etaient integralement
        redecodes chaque minute.

        Un fichier est redecode uniquement si son mtime OU sa taille a change.
        La taille en plus du mtime : deux ecritures dans la meme seconde ne
        changent pas toujours le mtime, et le fichier serait alors servi
        perime.
        """
        out: dict = {}
        if not ingest_dir.exists():
            self._ingest_cache = {}
            return out
        vus = set()
        for f in ingest_dir.glob("*.jsonl"):
            cle = str(f)
            vus.add(cle)
            try:
                st = f.stat()
                signature = (st.st_mtime_ns, st.st_size)
                cache = self._ingest_cache.get(cle)
                if cache is not None and cache[0] == signature:
                    partiel = cache[1]
                else:
                    partiel = self._decode_ingest(f)
                    self._ingest_cache[cle] = (signature, partiel)
            except Exception as e:
                log.warning("ingest read failed for %s: %s", f, e)
                continue
            # LA FUSION NE TOUCHE PAS AU CACHE : on alimente les ensembles de
            # `out`, jamais ceux qui sont retenus. Les modifier ferait deriver
            # le cache a chaque cycle, silencieusement.
            for host, cookies in partiel.items():
                bucket = out.setdefault(host, {})
                for n, valeurs in cookies.items():
                    bucket.setdefault(n, set()).update(valeurs)
        # Un fichier disparu ne doit pas rester en memoire.
        for mort in set(self._ingest_cache) - vus:
            del self._ingest_cache[mort]
        return out

    @staticmethod
    def _decode_ingest(f: Path) -> dict:
        """Decode UN instantane : {host: {cookie: set(value_hash)}}."""
        partiel: dict = {}
        for line in f.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            host = (rec.get("host") or "").strip()
            if not host:
                continue
            bucket = partiel.setdefault(host, {})
            for c in rec.get("cookies", []) or []:
                n = (c.get("name") or "").strip()
                if not n:
                    continue
                bucket.setdefault(n, set()).add(c.get("value_hash") or "")
        return partiel

    def _reconcile(self, server: dict, browser: dict, classifier: Classifier) -> list:
        all_hosts = sorted(set(server) | set(browser))
        out: list = []
        for vhost in all_hosts:
            srv = server.get(vhost, {})
            brw = browser.get(vhost, {})
            names = sorted(set(srv) | set(brw))
            cookies = []
            for n in names:
                s_rec = srv.get(n)
                b_hashes = brw.get(n)
                if s_rec and b_hashes:
                    source = "both"
                elif s_rec:
                    source = "http"
                else:
                    source = "js"
                cat = classifier.classify(n)
                violation = (source == "js" and cat != "strictly_necessary")
                cookies.append({
                    "name": n,
                    "source": source,
                    "category": cat,
                    "secure": bool(s_rec.get("secure")) if s_rec else None,
                    "httponly": bool(s_rec.get("httponly")) if s_rec else None,
                    "samesite": (s_rec.get("samesite") if s_rec else None),
                    "rgpd_violation": violation,
                })
            out.append({
                "vhost": vhost,
                "cookies": cookies,
                "violation_count": sum(1 for c in cookies if c["rgpd_violation"]),
            })
        return out

    def _summarize(self, hosts: list) -> dict:
        by_cat = {c: 0 for c in (*Classifier.CATEGORIES, "unclassified")}
        violations = 0
        hosts_with_violations = 0
        for h in hosts:
            local_violation = False
            for c in h["cookies"]:
                by_cat[c["category"]] = by_cat.get(c["category"], 0) + 1
                if c["rgpd_violation"]:
                    violations += 1
                    local_violation = True
            if local_violation:
                hosts_with_violations += 1
        return {
            "host_count": len(hosts),
            "hosts_with_violations": hosts_with_violations,
            "violation_count": violations,
            "by_category": by_cat,
        }

    def _persist(self, payload: dict) -> None:
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            self.cache_path.write_text(json.dumps(payload, separators=(",", ":")))
        except Exception as e:
            log.warning("persist failed: %s", e)
