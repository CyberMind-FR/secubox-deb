# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox-netboot (#737, Phase 2)
Provisioning réseau + overlay U-Boot. API de suivi/contrôle.
CyberMind — https://cybermind.fr

Servi en STANDALONE (socket /run/secubox/netboot.sock) car les opérations sont
privilégiées (fw_setenv) et bloquantes — jamais in-process dans l'aggregator.
Aucune opération destructive (overlay apply/revert, flash) sans confirm=true.
"""
from fastapi import FastAPI, APIRouter, Depends, HTTPException
from pydantic import BaseModel
import asyncio
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from secubox_core.auth import router as auth_router, require_jwt

app = FastAPI(title="secubox-netboot", version="0.2.0", root_path="/api/v1/netboot")

PROBE = "/usr/sbin/secubox-netboot-probe"
OVERLAY = "/usr/sbin/secubox-netboot-overlay"
TRIGGERS = "/usr/sbin/secubox-netboot-triggers"
SERVE = "/usr/sbin/secubox-netboot-serve"          # rôle SERVEUR (TFTP+HTTP)
PUBLISH = "/usr/sbin/secubox-netboot-publish"
SHADOW = Path("/boot/secubox-netboot/shadow")
CATALOG = Path("/var/lib/secubox/netboot/images.json")     # catalogue release signées
PROFILES = Path("/var/lib/secubox/netboot/profiles.json")  # profils board (remote config)
STAGING = Path("/var/lib/secubox/netboot/staging")         # artefacts buildés par image
AUDIT = Path("/var/log/secubox/netboot/audit.log")


@app.get("/health")
async def health():
    """Public health check (sidebar status)."""
    return {"status": "ok", "module": "netboot"}


app.include_router(auth_router, prefix="/auth")
router = APIRouter()


async def _run(*argv: str, timeout: int = 60) -> Dict[str, Any]:
    """Run a privileged sbin helper; return {rc, stdout, stderr}."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return {"rc": proc.returncode,
                "stdout": (out or b"").decode("utf-8", "ignore"),
                "stderr": (err or b"").decode("utf-8", "ignore")}
    except asyncio.TimeoutError:
        return {"rc": 124, "stdout": "", "stderr": f"timeout after {timeout}s"}
    except FileNotFoundError:
        return {"rc": 127, "stdout": "", "stderr": f"helper absent: {argv[0]}"}


def _json_or_raw(s: str) -> Any:
    try:
        return json.loads(s)
    except Exception:
        return {"raw": s.strip()}


# ── lecture (read-only) ──────────────────────────────────────────────────────

@router.get("/probe")
async def probe(user=Depends(require_jwt)):
    """Détection read-only du board/boot-stack (board, média, capacités U-Boot)."""
    r = await _run(PROBE, timeout=30)
    return {"probe": _json_or_raw(r["stdout"]), "error": r["stderr"] or None}


@router.get("/status")
async def status(user=Depends(require_jwt)):
    """État de l'overlay (env_ok, overlay_active, bootcount, backup usine)."""
    r = await _run(OVERLAY, "status", timeout=20)
    return {"status": _json_or_raw(r["stdout"]), "error": r["stderr"] or None}


@router.get("/inventory")
async def inventory(user=Depends(require_jwt)):
    """Vue board = probe + état overlay (1 board ici ; multi-board en P3)."""
    p = await _run(PROBE, timeout=30)
    s = await _run(OVERLAY, "status", timeout=20)
    return {"board": _json_or_raw(p["stdout"]), "overlay": _json_or_raw(s["stdout"])}


@router.get("/images")
async def images(user=Depends(require_jwt)):
    """Catalogue des images release signées (version, board, url, sig)."""
    if CATALOG.exists():
        try:
            return {"images": json.loads(CATALOG.read_text())}
        except Exception:
            pass
    return {"images": []}


@router.get("/audit")
async def audit(limit: int = 200, user=Depends(require_jwt)):
    """Journal d'audit (append-only) — derniers événements."""
    if not AUDIT.exists():
        return {"audit": []}
    try:
        lines = AUDIT.read_text(errors="ignore").splitlines()[-limit:]
        return {"audit": list(reversed(lines))}
    except Exception:
        return {"audit": []}


# ── contrôle (gated par confirm=true) ────────────────────────────────────────

class OverlayAction(BaseModel):
    confirm: bool = False     # sans confirm → DRY-RUN uniquement


@router.post("/overlay/apply")
async def overlay_apply(req: OverlayAction, user=Depends(require_jwt)):
    """Pose l'overlay 2ᵉ U-Boot. confirm=false → DRY-RUN ; confirm=true → --commit.
    Refusé si l'env n'est pas calibré ou le FIT shadow non signé (côté helper)."""
    args = [OVERLAY, "apply"] + (["--commit"] if req.confirm else [])
    r = await _run(*args, timeout=120)
    if r["rc"] != 0 and req.confirm:
        raise HTTPException(409, r["stderr"].strip() or "apply échoué")
    await _run(TRIGGERS, "post-overlay", timeout=30)
    return {"committed": req.confirm, "result": r["stdout"], "error": r["stderr"] or None}


@router.post("/overlay/revert")
async def overlay_revert(req: OverlayAction, user=Depends(require_jwt)):
    """Retire l'overlay → restaure l'amorce usine. confirm=true requis pour agir."""
    args = [OVERLAY, "revert"] + (["--commit"] if req.confirm else [])
    r = await _run(*args, timeout=60)
    if r["rc"] != 0 and req.confirm:
        raise HTTPException(409, r["stderr"].strip() or "revert échoué")
    return {"committed": req.confirm, "result": r["stdout"], "error": r["stderr"] or None}


@router.post("/overlay/persist")
async def overlay_persist(req: OverlayAction, user=Depends(require_jwt)):
    """Verrouille l'overlay en amorce PERMANENTE (après validation au banc) : retire
    le compteur de révocation, garde le repli usine runtime. confirm=true requis."""
    args = [OVERLAY, "persist"] + (["--commit"] if req.confirm else [])
    r = await _run(*args, timeout=60)
    if r["rc"] != 0 and req.confirm:
        raise HTTPException(409, r["stderr"].strip() or "persist échoué")
    return {"committed": req.confirm, "result": r["stdout"], "error": r["stderr"] or None}


@router.post("/overlay/confirm-healthy")
async def overlay_confirm_healthy(user=Depends(require_jwt)):
    """Marque le boot courant comme sain (bootcount=0)."""
    r = await _run(OVERLAY, "confirm-healthy", timeout=20)
    return {"ok": r["rc"] == 0, "error": r["stderr"] or None}


@router.get("/shadow")
async def shadow(user=Depends(require_jwt)):
    """Contenu du shadow buffer (artefacts overlay prêts à poser)."""
    items = []
    if SHADOW.exists():
        for p in sorted(SHADOW.glob("*")):
            items.append({"name": p.name, "size": p.stat().st_size})
    return {"shadow_dir": str(SHADOW), "items": items}


# ── rôle SERVEUR : HTTP/TFTP + profils board (remote config WebUI) ───────────

def _load_profiles() -> List[Dict[str, Any]]:
    if PROFILES.exists():
        try:
            return json.loads(PROFILES.read_text())
        except Exception:
            pass
    return []


def _save_profiles(rows: List[Dict[str, Any]]) -> None:
    PROFILES.parent.mkdir(parents=True, exist_ok=True)
    tmp = PROFILES.with_suffix(".tmp")
    tmp.write_text(json.dumps(rows, indent=2))
    tmp.replace(PROFILES)


def _norm_id(mac: str) -> str:
    return "".join(c for c in (mac or "").lower() if c in "0123456789abcdef")


BOOT_LEVELS = ("B0", "B1", "B2", "B3")   # cf. docs/BOOT-LEVELS.md (source × validation)


class BoardProfile(BaseModel):
    id: str                       # MAC (les ':' sont retirés) — clé board
    model: Optional[str] = None   # mochabin | espressobin-v7 | ...
    image: Optional[str] = None   # version d'image assignée (clé du catalogue)
    boot_level: str = "B0"        # B0 local | B1 tftp-brut | B2 http-signé | B3 install-signé
    srv: Optional[str] = None     # serveur de boot (IP/host) ; None → DHCP serverip
    note: Optional[str] = None


@router.get("/server")
async def server_status(user=Depends(require_jwt)):
    """État du rôle serveur de boot (tftpd, nginx /sbxboot, boards publiées)."""
    r = await _run(SERVE, "status", timeout=20)
    return {"server": _json_or_raw(r["stdout"]), "error": r["stderr"] or None}


@router.post("/server/up")
async def server_up(user=Depends(require_jwt)):
    """Active ce host comme source de boot (racines + tftpd-hpa). Non-invasif:
    n'écrit aucun env U-Boot, ne pose aucun overlay sur ce host."""
    r = await _run(SERVE, "up", timeout=60)
    if r["rc"] != 0:
        raise HTTPException(500, r["stderr"].strip() or "serve up échoué")
    return {"server": _json_or_raw(r["stdout"])}


BOARD_DIR = Path("/usr/share/secubox/netboot/board")


@router.get("/boards")
async def boards(user=Depends(require_jwt)):
    """Modèles de board supportés (depuis board/<name>/), avec leurs adresses de
    chargement — alimente le sélecteur de modèle des profils."""
    out: List[Dict[str, Any]] = []
    if BOARD_DIR.exists():
        for d in sorted(BOARD_DIR.iterdir()):
            if not (d / "addrs.env").exists():
                continue
            addrs = {}
            for line in (d / "addrs.env").read_text(errors="ignore").splitlines():
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    v = v.split("#", 1)[0].strip()   # retire un commentaire inline
                    addrs[k.strip()] = v
            out.append({"model": d.name, "defconfig": addrs.get("DEFCONFIG"),
                        "overlay_load": addrs.get("OVERLAY_LOAD"),
                        "has_fragment": (d / "uboot.fragment").exists()})
    return {"boards": out}


@router.get("/profiles")
async def profiles_list(user=Depends(require_jwt)):
    """Profils board (remote config) : id, modèle, image assignée, mode, serveur."""
    return {"profiles": _load_profiles()}


@router.post("/profiles")
async def profiles_upsert(p: BoardProfile, user=Depends(require_jwt)):
    """Crée/met à jour un profil board (clé = id MAC normalisé)."""
    pid = _norm_id(p.id)
    if not pid:
        raise HTTPException(422, "id (MAC) invalide")
    if p.boot_level not in BOOT_LEVELS:
        raise HTTPException(422, f"boot_level invalide (attendu {BOOT_LEVELS})")
    rows = _load_profiles()
    p.id = pid
    rows = [r for r in rows if _norm_id(r.get("id", "")) != pid]
    rows.append(p.model_dump())
    rows.sort(key=lambda r: r.get("id", ""))
    _save_profiles(rows)
    return {"ok": True, "profile": p.model_dump()}


@router.delete("/profiles/{board_id}")
async def profiles_delete(board_id: str, user=Depends(require_jwt)):
    pid = _norm_id(board_id)
    rows = [r for r in _load_profiles() if _norm_id(r.get("id", "")) != pid]
    _save_profiles(rows)
    return {"ok": True}


class PublishReq(BaseModel):
    board_id: str
    image: Optional[str] = None   # défaut = image du profil


@router.post("/publish")
async def publish(req: PublishReq, user=Depends(require_jwt)):
    """Publie les artefacts (boot.fit signé + repli TFTP) d'une board depuis le
    staging de l'image assignée. Le staging est produit par build-uboot-overlay.sh
    + l'étape de signature d'image (build-image CI)."""
    pid = _norm_id(req.board_id)
    prof = next((r for r in _load_profiles() if _norm_id(r.get("id", "")) == pid), None)
    if not prof:
        raise HTTPException(404, "profil board inconnu")
    level = prof.get("boot_level", "B0")
    if level == "B0":
        raise HTTPException(409, "profil en B0 (boot local) — rien à publier (sourcer un niveau B1/B2/B3)")
    image = req.image or prof.get("image")
    if not image:
        raise HTTPException(422, "aucune image assignée à cette board")
    img_dir = STAGING / image
    boot_fit = img_dir / "boot.fit"
    args = [PUBLISH, "--id", pid]
    if level in ("B2", "B3"):
        # niveau SIGNÉ : boot.fit requis (cohérence niveau ↔ validation)
        if not boot_fit.exists():
            raise HTTPException(409, f"niveau {level} exige un boot.fit signé absent ({boot_fit}) — builder/signer d'abord")
        args += ["--boot-fit", str(boot_fit)]
        # B3 : l'image release signée est servie à l'installeur (servie telle quelle)
    else:  # B1 : binaires bruts (TFTP), aucune signature
        for opt, name in (("--kernel", "Image"), ("--dtb", "board.dtb"), ("--initrd", "initrd.img")):
            f = img_dir / name
            if f.exists():
                args += [opt, str(f)]
        if "--kernel" not in args:
            raise HTTPException(409, f"aucun artefact B1 (Image/dtb/initrd) pour '{image}' dans {img_dir}")
    r = await _run(*args, timeout=180)
    if r["rc"] != 0:
        raise HTTPException(500, r["stderr"].strip() or "publish échoué")
    await _run(TRIGGERS, "on-image-published", f"BOARD={pid}", f"IMAGE_VER={image}", timeout=30)
    return {"ok": True, "board": pid, "image": image, "result": r["stdout"]}


app.include_router(router)
