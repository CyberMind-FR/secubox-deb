# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox-ytsas :: engine.py
CyberMind — https://cybermind.fr

Bounded yt-dlp job runner. Mirrors the torrent Engine's role: kick a fetch,
track live progress, never block the event loop. yt-dlp is driven as an async
subprocess (asyncio.create_subprocess_exec) — a metadata probe first
(`yt-dlp -j --no-download`) then a `--newline` download whose progress lines
are parsed as they arrive. Concurrency is bounded (default 2) by a semaphore.

Cookie vault: when /var/lib/secubox/ytsas/cookies.txt exists it is passed with
`--cookies` so age-restricted / members / private videos work. A gated failure
surfaces a CLEAR status ("auth requise — dépose tes cookies" / "cookies
périmés"), never a raw yt-dlp traceback, and flips a `cookies_stale` flag the
/cookies/status route reports.
"""

import asyncio
import hashlib
import json
import os
import re
import time

# Progress lines from `yt-dlp --newline`: "[download]  12.3% of ...".
_PROGRESS_RE = re.compile(r"\[download\]\s+([\d.]+)%")

# Signatures that mean "this needs (fresh) cookies", not a generic failure.
# Matched against yt-dlp stderr so the user gets an actionable status.
_AUTH_RE = re.compile(
    r"(sign in to confirm|confirm your age|age[- ]restricted|"
    r"members[- ]only|available to this channel's members|"
    r"private video|login required|requires? authentication|"
    r"this video is only available|use --cookies|--cookies-from-browser|"
    r"not a bot|account (?:cookies|credentials))",
    re.IGNORECASE,
)

# A "no usable format" failure is, in practice, most often an age-restricted /
# private / geo-gated video: without auth yt-dlp gets a stripped manifest with no
# downloadable format. When we have NO cookies yet, steer the user to the cookie
# vault instead of showing the cryptic raw format error.
_FORMAT_RE = re.compile(
    r"requested format (?:is )?not available|no video formats found|"
    r"only images are available|requested format is not available",
    re.IGNORECASE,
)

_VIDEO_EXTS = (".mp4", ".webm", ".mkv", ".m4v", ".mov", ".avi", ".flv", ".ts")


class EngineError(Exception):
    """Generic yt-dlp failure carrying a user-safe message (no traceback)."""


class AuthRequired(EngineError):
    """yt-dlp failed because cookies are missing or stale (gated content)."""


def _sha1(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8", "replace")).hexdigest()


class Engine:
    def __init__(self, download_dir, library, cookie_path, max_active=2,
                 ytdlp_bin="yt-dlp"):
        self.download_dir = download_dir
        self.library = library
        self.cookie_path = cookie_path
        self.ytdlp_bin = ytdlp_bin
        self._sem = asyncio.Semaphore(max_active)
        # Live per-id job state for /list and /status. Never persisted (the
        # library row is the source of truth for what exists on disk); this
        # holds only the volatile progress/status of the current process.
        #   { id: {progress: float, status: str, title: str, error: str|None} }
        self.jobs = {}
        # Flipped True when a gated download fails WHILE cookies are present —
        # i.e. the cookies are stale. Cleared on a fresh cookie upload.
        self.cookies_stale = False

    # ------------------------------------------------------------------ helpers
    def _cookie_args(self):
        if self.cookie_path and os.path.isfile(self.cookie_path):
            return ["--cookies", self.cookie_path]
        return []

    def _has_cookies(self):
        return bool(self.cookie_path and os.path.isfile(self.cookie_path))

    def active(self):
        """Number of jobs currently downloading (bounded by the semaphore)."""
        return sum(1 for j in self.jobs.values() if j.get("status") == "downloading")

    @staticmethod
    def _pick_file(item_dir):
        """Largest video file produced in item_dir, else largest file, else None."""
        best = None
        best_len = -1
        try:
            names = os.listdir(item_dir)
        except OSError:
            return None
        vids = [n for n in names if n.lower().endswith(_VIDEO_EXTS)]
        candidates = vids or names
        for n in candidates:
            p = os.path.join(item_dir, n)
            try:
                if not os.path.isfile(p):
                    continue
                sz = os.path.getsize(p)
            except OSError:
                continue
            if sz > best_len:
                best_len = sz
                best = p
        return best

    # --------------------------------------------------------------- metadata
    async def _probe(self, url):
        """Fetch id + title without downloading. Raises AuthRequired/EngineError."""
        argv = [self.ytdlp_bin, "-j", "--no-download", "--no-playlist",
                # YouTube gates real formats behind a JS "n challenge"; deno alone
                # is skipped without the EJS solver script — pull it from GitHub so
                # actual video/audio formats are returned (else "only images").
                "--remote-components", "ejs:github",
                *self._cookie_args(), url]
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE)
            out, err = await asyncio.wait_for(proc.communicate(), timeout=120)
        except asyncio.TimeoutError:
            raise EngineError("délai dépassé — le site ne répond pas")
        except FileNotFoundError:
            raise EngineError("yt-dlp introuvable dans le conteneur")
        if proc.returncode != 0:
            self._raise_for_stderr(err.decode("utf-8", "replace"))
        try:
            meta = json.loads(out.decode("utf-8", "replace").splitlines()[0])
        except (ValueError, IndexError):
            raise EngineError("métadonnées illisibles")
        vid = str(meta.get("id") or "").strip() or _sha1(url)
        title = (meta.get("title") or "").strip() or vid
        return vid, title

    def _raise_for_stderr(self, stderr):
        """Map a non-zero yt-dlp exit to a user-safe exception (no traceback)."""
        tail = stderr.strip().splitlines()
        msg = tail[-1] if tail else "échec yt-dlp"
        if _AUTH_RE.search(stderr):
            if self._has_cookies():
                self.cookies_stale = True
                raise AuthRequired("cookies périmés — ré-exporte tes cookies")
            raise AuthRequired("auth requise — dépose tes cookies")
        # "No usable format" is, in practice, gated content (age/private/geo).
        if _FORMAT_RE.search(stderr):
            if self._has_cookies():
                self.cookies_stale = True
                raise AuthRequired(
                    "aucun format disponible — vidéo âge-restreinte/privée et tes "
                    "cookies ne l'autorisent pas : ré-exporte des cookies frais "
                    "d'un compte connecté (18+) dans le panneau Authentification")
            raise AuthRequired(
                "aucun format disponible — souvent une vidéo âge-restreinte/privée : "
                "dépose ton cookies.txt (panneau Authentification)")
        # Trim to keep any surfaced message short and non-leaky.
        raise EngineError(msg[:200])

    # -------------------------------------------------------------------- add
    async def add(self, url):
        """Probe metadata, insert the library row, kick the background download.

        Returns {id, title, status} on a successful queue. Raises AuthRequired
        / EngineError (both user-safe) if even the metadata probe fails, so the
        API can answer with a clear status instead of a raw error.
        """
        vid, title = await self._probe(url)
        item_dir = os.path.join(self.download_dir, vid)
        os.makedirs(item_dir, exist_ok=True)
        self.library.add(id=vid, url=url, title=title, path=item_dir)
        self.jobs[vid] = {"progress": 0.0, "status": "downloading",
                          "title": title, "error": None,
                          "started_at": int(time.time())}
        # Fire-and-forget: the download runs under the semaphore in the
        # background; /list and /status reflect progress as it advances.
        asyncio.create_task(self._download(vid, url, item_dir))
        return {"id": vid, "title": title, "status": "downloading"}

    async def _download(self, vid, url, item_dir):
        async with self._sem:
            job = self.jobs.get(vid)
            if job is None:
                return
            # Output template inside the per-id dir; predictable id-based name.
            out_tmpl = os.path.join(item_dir, "%(id)s.%(ext)s")
            argv = [
                # --newline (one progress line per update) WITHOUT --no-progress,
                # else yt-dlp emits no "[download] N%" lines and the bar sticks at 0.
                self.ytdlp_bin, "--newline", "--no-playlist",
                "--restrict-filenames",
                # Pull the EJS solver so YouTube's n-challenge yields real formats.
                "--remote-components", "ejs:github",
                "-f", "bv*+ba/b",
                "--merge-output-format", "mp4",
                "-o", out_tmpl,
                *self._cookie_args(),
                url,
            ]
            try:
                proc = await asyncio.create_subprocess_exec(
                    *argv, stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE)
            except FileNotFoundError:
                job.update(status="error", error="yt-dlp introuvable")
                return
            stderr_buf = []
            # Drain stdout line-by-line for progress; buffer stderr for errors.
            async def _read_progress():
                assert proc.stdout is not None
                while True:
                    line = await proc.stdout.readline()
                    if not line:
                        break
                    m = _PROGRESS_RE.search(line.decode("utf-8", "replace"))
                    if m:
                        try:
                            job["progress"] = float(m.group(1))
                        except ValueError:
                            pass

            async def _read_err():
                assert proc.stderr is not None
                while True:
                    line = await proc.stderr.readline()
                    if not line:
                        break
                    stderr_buf.append(line.decode("utf-8", "replace"))

            await asyncio.gather(_read_progress(), _read_err())
            rc = await proc.wait()
            stderr = "".join(stderr_buf)
            if rc == 0:
                path = self._pick_file(item_dir) or item_dir
                job.update(status="complete", progress=100.0, error=None)
                self.library.set_complete(vid, 1, path=path)
                return
            # Non-zero: classify. Gated → auth status; else generic (kept row,
            # complete=0, so the user can retry after uploading cookies).
            if _AUTH_RE.search(stderr):
                if self._has_cookies():
                    self.cookies_stale = True
                    job.update(status="auth_required",
                               error="cookies périmés — ré-exporte tes cookies")
                else:
                    job.update(status="auth_required",
                               error="auth requise — dépose tes cookies")
            else:
                tail = stderr.strip().splitlines()
                job.update(status="error",
                           error=(tail[-1] if tail else "échec du téléchargement")[:200])

    def job(self, vid):
        """Live job state for an id, or None if no job ran this session."""
        return self.jobs.get(vid)
