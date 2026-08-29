# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: DevWatch — sonde GitHub (API publique, sans token).

Le navigateur ne parle JAMAIS à GitHub : la carte vit sous `connect-src 'self'`
et rien ne doit apprendre à github.com qui regarde la box. C'est CE module,
serveur-à-serveur, qui interroge l'API REST publique — anonyme, ~60 requêtes/h,
largement absorbées par le cache (une passe ≈ 8 appels, toutes les ~20 min).

Aucune donnée n'est inventée ICI : on ne rend que ce que GitHub rapporte. La
couche de vulgarisation (temps, coût, carbone) est calculée AILLEURS (metrics.py)
et clairement étiquetée « estimation ». La séparation est volontaire : la sonde
reste un miroir fidèle du dépôt.
"""
from __future__ import annotations

import asyncio
import re
from datetime import datetime, timezone
from typing import Any, Optional

import httpx

API = "https://api.github.com"
UA = "SecuBox-DevWatch/1.0 (+https://secubox.in)"


def _headers(token: str = "") -> dict:
    h = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": UA,
    }
    # Un token n'est PAS requis (public, 60/h). S'il est fourni via l'admin, il
    # ne vit qu'ici, en mémoire — jamais journalisé, jamais renvoyé au client.
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


_LAST = re.compile(r'[?&]page=(\d+)>;\s*rel="last"')


def _last_page(resp: httpx.Response) -> Optional[int]:
    """Nombre de la DERNIÈRE page (en-tête Link).

    Avec `per_page=1`, ce nombre EST le total d'éléments — c'est ainsi qu'on
    compte commits/contributeurs/tags sans tout télécharger. Absent quand il n'y
    a qu'une page : l'appelant retombe alors sur la longueur du corps.
    """
    m = _LAST.search(resp.headers.get("link", ""))
    return int(m.group(1)) if m else None


def _iso(s: str) -> Optional[datetime]:
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return None


class GitHub:
    """Client minimal, défensif : une panne d'un appel n'emporte pas la passe."""

    def __init__(self, owner: str, repo: str, token: str = "", timeout: float = 12.0):
        self.owner = owner
        self.repo = repo
        self.token = token
        self.timeout = timeout
        self.rate_left: Optional[int] = None

    async def _get(self, cli: httpx.AsyncClient, path: str, **params) -> Optional[httpx.Response]:
        try:
            r = await cli.get(API + path, params=params, headers=_headers(self.token))
        except Exception:
            return None
        # On retient le quota restant pour le dire à l'admin (transparence).
        rl = r.headers.get("x-ratelimit-remaining")
        if rl is not None:
            try:
                self.rate_left = int(rl)
            except ValueError:
                pass
        return r

    async def activity_only(self) -> Optional[list]:
        """Un SEUL appel à /stats/commit_activity — pour la reprise économe.

        La première demande jamais faite sur un dépôt fait générer l'agrégat par
        GitHub (202, corps vide) ; une fois calculé il est mis en cache et rendu
        en 200 pour toujours. Rejouer TOUTE la collecte pendant cette attente
        gaspillerait le quota (60/h anonyme) : on ne retente que CET appel.
        Rend la liste des semaines si prête, sinon None (encore en calcul).
        """
        base = f"/repos/{self.owner}/{self.repo}"
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as cli:
            r = await self._get(cli, base + "/stats/commit_activity")
            if r is not None and r.status_code == 200:
                data = r.json()
                if isinstance(data, list) and data:
                    return [{"week": w.get("week", 0), "total": w.get("total", 0),
                             "days": w.get("days", [])} for w in data[-30:]]
        return None

    async def collect(self) -> dict:
        """Une passe complète. Rend un dict de FAITS bruts (jamais d'estimation)."""
        base = f"/repos/{self.owner}/{self.repo}"
        out: dict[str, Any] = {
            "owner": self.owner,
            "repo": self.repo,
            "ok": False,
            "fetched_at": datetime.now(timezone.utc).isoformat(),
        }
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as cli:
            # 1) Métadonnées du dépôt.
            r = await self._get(cli, base)
            if r is None or r.status_code != 200:
                out["error"] = f"repo {r.status_code if r else 'net'}"
                out["rate_left"] = self.rate_left
                return out
            meta = r.json()
            out.update(
                description=meta.get("description") or "",
                stars=meta.get("stargazers_count", 0),
                forks=meta.get("forks_count", 0),
                watchers=meta.get("subscribers_count", 0),
                open_issues_and_prs=meta.get("open_issues_count", 0),
                default_branch=meta.get("default_branch", "main"),
                created_at=meta.get("created_at", ""),
                pushed_at=meta.get("pushed_at", ""),
                html_url=meta.get("html_url", ""),
                language=meta.get("language") or "",
            )

            # 2) Total de commits sur la branche par défaut (Link rel=last).
            r = await self._get(cli, base + "/commits", per_page=1, sha=out["default_branch"])
            total = None
            latest = []
            if r is not None and r.status_code == 200:
                total = _last_page(r) or 1
                # Derniers commits (une 2e requête, plus riche).
                r2 = await self._get(cli, base + "/commits", per_page=6, sha=out["default_branch"])
                if r2 is not None and r2.status_code == 200:
                    for c in r2.json():
                        commit = c.get("commit", {})
                        author = commit.get("author", {}) or {}
                        gh_author = c.get("author") or {}
                        msg = (commit.get("message") or "").split("\n", 1)[0]
                        latest.append({
                            "sha": (c.get("sha") or "")[:7],
                            "message": msg,
                            "date": author.get("date", ""),
                            "login": gh_author.get("login") or author.get("name") or "?",
                        })
            out["commits_total"] = total
            out["latest_commits"] = latest

            # 3) Activité hebdomadaire (52 semaines) — série + tendances.
            #    L'API CALCULE ces stats en tâche de fond : le premier appel rend
            #    202 (« repasse dans un instant »), le corps est vide. On réessaie
            #    quelques fois, brièvement — sinon la cadence resterait à plat
            #    jusqu'à la prochaine passe (20 min), et « aujourd'hui » à 0.
            weeks = []
            for attempt in range(2):  # un coup + un essai ; la reprise de fond fait le reste
                r = await self._get(cli, base + "/stats/commit_activity")
                if r is not None and r.status_code == 200:
                    data = r.json()
                    if isinstance(data, list) and data:
                        for w in data[-30:]:
                            weeks.append({"week": w.get("week", 0), "total": w.get("total", 0),
                                          "days": w.get("days", [])})
                        break
                if r is not None and r.status_code == 202 and attempt == 0:
                    await asyncio.sleep(1.5)  # GitHub génère l'agrégat ; court répit
                    continue
                break
            out["weeks"] = weeks
            out["weeks_pending"] = not weeks  # dit à l'appelant de repasser tôt (fond)

            # 4) Contributeurs (compte via Link rel=last, anonymes compris).
            r = await self._get(cli, base + "/contributors", per_page=1, anon="1")
            if r is not None and r.status_code == 200:
                out["contributors"] = _last_page(r) or len(r.json() or [])
            else:
                out["contributors"] = None

            # 5) Releases (compte + dernière + LISTE récente pour l'évolution).
            r = await self._get(cli, base + "/releases", per_page=12)
            rel_count, latest_rel, recent = None, None, []
            if r is not None and r.status_code == 200:
                rel_count = _last_page(r)
                arr = r.json()
                if rel_count is None:
                    rel_count = len(arr)
                for x in arr:
                    recent.append({
                        "tag": x.get("tag_name", ""),
                        "name": x.get("name") or x.get("tag_name", ""),
                        "published_at": x.get("published_at", ""),
                        "url": x.get("html_url", ""),
                        "prerelease": bool(x.get("prerelease")),
                    })
                if arr:
                    x = arr[0]
                    latest_rel = {
                        "tag": x.get("tag_name", ""),
                        "name": x.get("name") or x.get("tag_name", ""),
                        "published_at": x.get("published_at", ""),
                        "url": x.get("html_url", ""),
                        "body": (x.get("body") or "").strip()[:280],
                    }
            out["releases_total"] = rel_count
            out["latest_release"] = latest_rel
            out["releases_recent"] = recent  # plus récente en tête

            # 6) Tags (compte).
            r = await self._get(cli, base + "/tags", per_page=1)
            out["tags_total"] = (_last_page(r) if (r and r.status_code == 200) else None)

            # 7) PR ouvertes (pour séparer issues « pures » des PR).
            r = await self._get(cli, base + "/pulls", state="open", per_page=1)
            open_prs = None
            if r is not None and r.status_code == 200:
                open_prs = _last_page(r)
                if open_prs is None:
                    open_prs = len(r.json())
            out["open_prs"] = open_prs
            if open_prs is not None and out.get("open_issues_and_prs") is not None:
                out["open_issues"] = max(0, out["open_issues_and_prs"] - open_prs)
            else:
                out["open_issues"] = out.get("open_issues_and_prs")

            # 8) Latence de revue : moyenne (merge - ouverture) sur les dernières
            #    PR fusionnées. Best-effort — une seule page, borné.
            r = await self._get(cli, base + "/pulls", state="closed", sort="updated",
                                direction="desc", per_page=20)
            lat = []
            if r is not None and r.status_code == 200:
                for p in r.json():
                    if not p.get("merged_at"):
                        continue
                    a, b = _iso(p.get("created_at", "")), _iso(p.get("merged_at", ""))
                    if a and b and b >= a:
                        lat.append((b - a).total_seconds() / 3600.0)
            out["review_latency_h"] = (sum(lat) / len(lat)) if lat else None

            # 9) Chantiers ouverts (issues, hors PR) — pour la liste « évolutions
            #    résiduelles ». On lit les labels et on classe la priorité.
            r = await self._get(cli, base + "/issues", state="open", sort="updated",
                                direction="desc", per_page=12)
            issues = []
            if r is not None and r.status_code == 200:
                for it in r.json():
                    if it.get("pull_request"):
                        continue  # l'API issues inclut les PR : on les écarte
                    labels = [l.get("name", "") for l in (it.get("labels") or [])]
                    issues.append({
                        "number": it.get("number"),
                        "title": (it.get("title") or "").strip()[:120],
                        "labels": labels,
                        "comments": it.get("comments", 0),
                        "updated_at": it.get("updated_at", ""),
                        "url": it.get("html_url", ""),
                    })
            out["issues"] = issues

        out["ok"] = True
        out["rate_left"] = self.rate_left
        return out
