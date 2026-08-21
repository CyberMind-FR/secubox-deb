# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""
SecuBox-Deb :: Podcaster URL importer (yt-dlp → podcaster [+ PeerTube + billets])

Productises the one-off playlist importer: given any yt-dlp-supported URL (a
YouTube video or playlist, or a TV/radio page like RTBF), enumerate its entries
and, per entry:
  1. download the video (<=720p) + extract audio (stream copy → m4a)
  2. (optional) upload the video to a PeerTube channel (unlisted) → watch URL
  3. add a podcaster episode (local audio, state=done)
  4. (optional) create a published billet: description + source + stream links

Runs OFF the event loop (the caller uses asyncio.to_thread). Single job at a
time; live progress in the module-level `JOB` dict. PeerTube credentials are
read from a root-only secret, never hard-coded.
"""
import json
import os
import re
import secrets
import sqlite3
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from secubox_core.logger import get_logger
from . import store

log = get_logger("podcaster.importer")

PT_SECRET = Path("/etc/secubox/secrets/peertube-import.json")
# Netscape cookies.txt pour vaincre le « confirm you're not a bot » / âge-restreint
# de YouTube ; passé à chaque appel yt-dlp quand un candidat est présent.
#
# MÊMES COOKIES QUE YTSAS (#1100). podcaster tourne en root sur l'hôte : il peut
# lire le coffre à cookies de ytsas dans le rootfs de sa LXC — coffre unique où
# l'admin dépose et rafraîchit les cookies via le panneau ytsas. On le réutilise
# tel quel (lecture directe, toujours à jour, aucune copie à périmer) plutôt que
# d'entretenir un second exemplaire.
YT_COOKIES = Path("/etc/secubox/secrets/yt-cookies.txt")
YTSAS_COOKIES_HOST = Path(os.environ.get(
    "YTSAS_COOKIES_HOST",
    "/data/lxc/ytsas/rootfs/var/lib/secubox/ytsas/cookies.txt"))


def _cookies_file() -> Path | None:
    """Premier fichier de cookies présent ET non vide, par ordre de priorité :
    override d'environnement, secret propre à podcaster, puis coffre de ytsas.
    Un fichier vide est IGNORÉ — un cookies.txt tronqué ne doit pas masquer une
    source valable en aval."""
    candidates: list[Path] = []
    env = os.environ.get("PODCASTER_YT_COOKIES")
    if env:
        candidates.append(Path(env))
    candidates += [YT_COOKIES, YTSAS_COOKIES_HOST]
    for p in candidates:
        try:
            if p.is_file() and p.stat().st_size > 0:
                return p
        except OSError:
            continue
    return None
BILLETS_DB = "/var/lib/secubox/billets/billets.db"
BILLETS_PUBLIC = os.environ.get("BILLETS_PUBLIC_URL", "https://billets.gk2.secubox.in")
PODCASTER_PUBLIC = os.environ.get("PODCASTER_PUBLIC_URL", "https://podcaster.gk2.secubox.in")

_B32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

# Single in-flight import job; polled by GET /import/status.
JOB: dict = {"running": False, "url": None, "total": 0, "done": 0,
             "current": "", "errors": [], "feed_id": None, "started": 0,
             "finished": 0, "log": []}


def _jlog(msg: str) -> None:
    log.info(msg)
    JOB["log"] = (JOB["log"] + [f"{datetime.now().strftime('%H:%M:%S')} {msg}"])[-40:]


def _ulid() -> str:
    t = int(time.time() * 1000)
    ts = "".join(_B32[(t >> (10 * (5 - i))) & 0x1F] for i in range(6))
    return ts + "".join(secrets.choice(_B32) for _ in range(20))


def _slugify(s: str, extra: str = "") -> str:
    base = re.sub(r"[^a-z0-9]+", "-", (s or "").lower()).strip("-")[:60] or "item"
    return f"{base}-{extra}" if extra else base


def _run(cmd, timeout=None):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def _ytdlp(args, timeout=None):
    """yt-dlp with the resolved cookies file spliced in when one is present."""
    cmd = ["yt-dlp"]
    ck = _cookies_file()
    if ck:
        cmd += ["--cookies", str(ck)]
    return _run(cmd + args, timeout=timeout)


# ── PeerTube ────────────────────────────────────────────────────────
def _pt_conf() -> dict | None:
    try:
        return json.loads(PT_SECRET.read_text())
    except Exception:
        return None


def _pt_token(conf: dict) -> str | None:
    h = f"Host: {conf['host']}"
    r = _run(["curl", "-s", "--max-time", "20", "-H", h, f"{conf['base']}/api/v1/users/token",
              "--data-urlencode", f"client_id={conf['client_id']}",
              "--data-urlencode", f"client_secret={conf['client_secret']}",
              "--data-urlencode", "grant_type=password",
              "--data-urlencode", f"username={conf['username']}",
              "--data-urlencode", f"password={conf['password']}"], timeout=25)
    try:
        return json.loads(r.stdout)["access_token"]
    except Exception:
        _jlog("peertube auth failed")
        return None


def _pt_upload(conf: dict, token: str, vpath: Path, title: str, desc: str):
    h = f"Host: {conf['host']}"
    r = _run(["curl", "-s", "--max-time", "3600",
              "-H", f"Authorization: Bearer {token}", "-H", h,
              "-F", f"channelId={conf['channel']}", "-F", f"name={title[:120]}",
              "-F", f"privacy={conf.get('privacy', 2)}", "-F", f"description={desc[:9000]}",
              "-F", "commentsEnabled=false", "-F", "downloadEnabled=true",
              "-F", f"videofile=@{vpath}", f"{conf['base']}/api/v1/videos/upload"], timeout=3700)
    try:
        return json.loads(r.stdout)["video"]["shortUUID"]
    except Exception:
        _jlog(f"peertube upload failed: {r.stdout[-160:]}")
        return None


# ── billets ─────────────────────────────────────────────────────────
def _add_billet(title, desc, source_url, pt_watch, pod_audio):
    now = datetime.now(timezone.utc).isoformat()
    bid = _ulid()
    slug = _slugify(title, bid[-6:].lower())
    parts = [(desc or "").strip()[:4000], "\n\n---\n"]
    if source_url:
        parts.append(f"\n🎬 **Source :** {source_url}\n")
    if pt_watch:
        parts.append(f"\n📺 **Vidéo (PeerTube) :** {pt_watch}\n")
    if pod_audio:
        parts.append(f"\n🎧 **Audio (Podcaster) :** {pod_audio}\n")
    body = "".join(parts)
    con = sqlite3.connect(BILLETS_DB, timeout=30)
    try:
        con.execute("PRAGMA journal_mode=WAL")
        con.execute(
            "INSERT INTO billet(id,created_at,updated_at,published_at,body,ref_url,embed_url,"
            "slug,status,style) VALUES(?,?,?,?,?,?,?,?, 'published','default')",
            (bid, now, now, now, body, source_url or None, pt_watch or None, slug))
        con.commit()
    finally:
        con.close()
    # podcaster runs as root; hand the billets DB back to secubox so billets can write.
    for suf in ("", "-wal", "-shm"):
        p = BILLETS_DB + suf
        if os.path.exists(p):
            _run(["chown", "secubox:secubox", p])
    return slug


# ── download + cover ────────────────────────────────────────────────
def _extract_cover(thumb: Path, dest: Path) -> bool:
    try:
        from PIL import Image
        im = Image.open(str(thumb)).convert("RGB")
        im.thumbnail((600, 600))
        dest.parent.mkdir(parents=True, exist_ok=True)
        im.save(str(dest), "JPEG", quality=85)
        return True
    except Exception:
        return False


def _download(vid: str, workdir: Path, want_video: bool):
    d = workdir / vid
    d.mkdir(parents=True, exist_ok=True)
    url = f"https://www.youtube.com/watch?v={vid}" if re.fullmatch(r"[\w-]{6,20}", vid) else vid
    apath = d / f"{vid}.m4a"
    vpath = d / f"{vid}.mp4"
    if want_video:
        if not vpath.exists():
            _ytdlp(["--no-warnings", "-f",
                  "bv*[height<=720][ext=mp4]+ba[ext=m4a]/b[height<=720]",
                  "--merge-output-format", "mp4", "--write-info-json",
                  "--write-thumbnail", "--convert-thumbnails", "jpg",
                  "-o", str(d / f"{vid}.%(ext)s"), url], timeout=2400)
        if vpath.exists() and not apath.exists():
            _run(["ffmpeg", "-y", "-i", str(vpath), "-vn", "-c:a", "copy", str(apath)], timeout=900)
            if not apath.exists():
                _run(["ffmpeg", "-y", "-i", str(vpath), "-vn", "-c:a", "aac", "-b:a", "128k",
                      str(apath)], timeout=1800)
    else:
        if not apath.exists():
            _ytdlp(["--no-warnings", "-x", "--audio-format", "m4a",
                  "--write-info-json", "--write-thumbnail", "--convert-thumbnails", "jpg",
                  "-o", str(d / f"{vid}.%(ext)s"), url], timeout=1800)
    info = {}
    ij = d / f"{vid}.info.json"
    if ij.exists():
        try:
            info = json.loads(ij.read_text())
        except Exception:
            info = {}
    thumb = next((p for p in (d / f"{vid}.jpg", d / f"{vid}.webp") if p.exists()), None)
    return (vpath if vpath.exists() else None), (apath if apath.exists() else None), info, thumb


def _enumerate(url: str):
    """Return [{id,title,playlist}] for a playlist OR a single video/URL.
    `--dump-single-json` yields one object: playlists carry an `entries` array,
    a single video is the video dict itself."""
    r = _ytdlp(["--flat-playlist", "--dump-single-json", "--no-warnings", url], timeout=120)
    try:
        obj = json.loads(r.stdout)
    except Exception:
        obj = None
    if not isinstance(obj, dict):
        err = [l for l in (r.stderr or "").splitlines() if l.strip()]
        if err:
            _jlog(f"yt-dlp: {err[-1][:180]}")
        return []
    entries = obj.get("entries")
    if entries is None:  # single video / URL
        if obj.get("id"):
            return [{"id": obj["id"], "title": obj.get("title") or obj["id"],
                     "playlist": obj.get("playlist_title")}]
        return []
    series = obj.get("title")
    out = []
    for j in entries:
        if j and j.get("id"):
            out.append({"id": j["id"], "title": j.get("title") or j["id"], "playlist": series})
    return out


# ── job runner (blocking; call via asyncio.to_thread) ───────────────
def run_import(url: str, media_dir: str, mirror_peertube: bool, create_billets: bool):
    JOB.update({"running": True, "url": url, "total": 0, "done": 0, "current": "",
                "errors": [], "feed_id": None, "started": int(time.time()),
                "finished": 0, "log": []})
    # Stage on the SAME real filesystem as the media store. media_dir is usually
    # a symlink onto the SSD (…/media -> /data/secubox/podcaster/media); taking
    # .parent BEFORE resolving lands the staging back on the eMMC root — which is
    # exactly how a large YouTube import filled the root fs to 99% and stalled
    # (staging on eMMC, store on SSD). .resolve() follows the symlink so staging
    # and store share the SSD. Durable: it derives from the real path, so a
    # package reinstall that re-lays the symlink cannot revert it.
    workdir = Path(media_dir).resolve().parent / "youtube-import"
    try:
        entries = _enumerate(url)
        if not entries:
            _jlog("nothing found at that URL")
            return
        JOB["total"] = len(entries)
        series = entries[0].get("playlist") or entries[0]["title"]
        # IDENTITE PAR L'URL SOURCE, le slug n'est qu'un repli.
        #
        # Le slug vient du TITRE rendu par yt-dlp, qui varie selon l'URL
        # fournie : `playlist?list=Y` et `watch?v=X&list=Y` designent la meme
        # serie mais donnent des titres — donc des slugs — differents. Le
        # 2026-08-07, un import lance depuis une URL `watch` a cree un second
        # flux « le-bureau-des-complots » a cote de « bureau-des-complots » et
        # retelecharge 34 episodes, soit 2,3 Go.
        existing = store.feed_by_site(url)
        feed_url = existing["url"] if existing else f"youtube:{_slugify(series)}"
        if existing:
            _jlog(f"flux existant retrouve par son URL source : {feed_url}")
        _jlog(f"{len(entries)} item(s): {series}")

        conf = _pt_conf() if mirror_peertube else None
        token = _pt_token(conf) if conf else None
        if mirror_peertube and not token:
            _jlog("peertube mirror requested but auth unavailable — skipping video upload")

        # feed
        # `site` porte l'URL SOURCE. Sans elle le flux est un cul-de-sac :
        # son url propre n'est qu'un slug (`youtube:<serie>`), et aucun
        # rafraichissement ulterieur ne sait quoi re-interroger. C'est ce qui a
        # fige les series importees — plus rien depuis le 2026-07-25.
        store.add_feed(feed_url, {"title": series,
                                  "description": f"Import: {series}",
                                  "site": url})
        fid = None
        for f in store.list_feeds():
            if f["url"] == feed_url:
                fid = f["id"]
                break
        JOB["feed_id"] = fid

        # Episodes deja connus, lus UNE fois : le saut doit avoir lieu AVANT le
        # telechargement. L'insertion est certes idempotente
        # (INSERT OR IGNORE sur guid), mais le fichier est telecharge avant
        # d'y arriver — un reimport retelechargerait la serie entiere, ce qui
        # interdisait tout rafraichissement automatique.
        known = store.known_guids(fid)

        for i, e in enumerate(entries):
            vid, title = e["id"], e["title"]
            if f"yt:{vid}" in known:
                JOB["done"] = JOB.get("done", 0) + 1
                continue
            JOB["current"] = f"{i+1}/{len(entries)}: {title[:60]}"
            _jlog(JOB["current"])
            try:
                vpath, apath, info, thumb = _download(vid, workdir, want_video=mirror_peertube)
                if not apath:
                    JOB["errors"].append(f"{title[:40]}: download failed")
                    continue
                desc = info.get("description") or ""
                up_ts = int(time.time())
                if info.get("upload_date"):
                    try:
                        up_ts = int(datetime.strptime(info["upload_date"], "%Y%m%d")
                                    .replace(tzinfo=timezone.utc).timestamp())
                    except Exception:
                        pass
                duration = info.get("duration_string") or ""

                # feed cover from first thumbnail
                if i == 0 and thumb and fid:
                    cov = Path(media_dir) / str(fid) / "cover.jpg"
                    if _extract_cover(thumb, cov):
                        con = sqlite3.connect(store.DB_PATH, timeout=30)
                        con.execute("UPDATE feeds SET image=? WHERE id=?",
                                    (f"/api/v1/podcaster/feeds/{fid}/cover", fid))
                        con.commit(); con.close()

                pt_watch = None
                if token and conf and vpath:
                    su = _pt_upload(conf, token, vpath, title, desc)
                    if su:
                        pt_watch = f"{conf['watch']}/w/{su}"

                # podcaster episode
                con = sqlite3.connect(store.DB_PATH, timeout=30)
                con.execute("PRAGMA journal_mode=WAL")
                con.execute(
                    "INSERT OR IGNORE INTO episodes(feed_id,guid,title,description,pubdate,"
                    "enclosure,mime,bytes,duration,local_path,state,progress) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?, 'done',100)",
                    (fid, f"yt:{vid}", title[:200], desc, up_ts, f"local:{apath}",
                     "audio/mp4", apath.stat().st_size, duration, str(apath)))
                con.execute("UPDATE episodes SET state='done',progress=100,local_path=? "
                            "WHERE feed_id=? AND guid=?", (str(apath), fid, f"yt:{vid}"))
                epid = con.execute("SELECT id FROM episodes WHERE feed_id=? AND guid=?",
                                   (fid, f"yt:{vid}")).fetchone()[0]
                con.commit(); con.close()
                pod_audio = f"{PODCASTER_PUBLIC}/api/v1/podcaster/media/{epid}"

                if create_billets:
                    src = f"https://www.youtube.com/watch?v={vid}"
                    slug = _add_billet(title, desc, src, pt_watch, pod_audio)
                    _jlog(f"  billet /b/{slug}")

                JOB["done"] += 1
            except Exception as ex:  # noqa: BLE001
                _jlog(f"  ERROR {vid}: {ex}")
                JOB["errors"].append(f"{title[:40]}: {str(ex)[:120]}")
        # ownership so podcaster(root) media stays secubox-readable
        _run(["chown", "-R", "secubox:secubox", media_dir])
        _run(["chown", "-R", "secubox:secubox", str(workdir)])
        _jlog(f"done: {JOB['done']}/{JOB['total']} imported")
    finally:
        JOB["running"] = False
        JOB["finished"] = int(time.time())
