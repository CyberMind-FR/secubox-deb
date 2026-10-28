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
from fastapi import FastAPI, APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
import asyncio
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import ipaddress
import logging
import os
import re
import stat
import time

from . import lot

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
CTL_LOT = "/usr/sbin/secubox-netboot-lot"                  # lot de flash signé (#3100)


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
    """État du rôle serveur de boot (tftpd, vhost de boot :8099, boards publiées)."""
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


# ── netbooter une box : le live servi, lu dans son boot.cmd (#3100) ──────────

TFTP_ROOT = Path("/srv/secubox/netboot/tftp")
HTTP_ROOT = Path("/srv/secubox/netboot/http")
_RE_NOM_LIVE = re.compile(r"[a-z0-9][a-z0-9-]{0,39}")
_RE_IMAGE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.img\.(gz|xz)")   # .xz : images de la release (#3233)
_LIRE_MAX = 64 * 1024


def _lire_court(f: Path) -> Optional[str]:
    """Fichier ordinaire seulement : un lien symbolique n'est pas suivi, une FIFO ne bloque pas (service root)."""
    try:
        fd = os.open(f, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        return os.read(fd, _LIRE_MAX).decode("utf-8", errors="replace")
    except OSError:
        return None
    finally:
        os.close(fd)


def _images_live(d: Path) -> List[Dict[str, Any]]:
    """images.txt du live (« nom taille sha256 [taille_décompressée] » par ligne, #3233) ; noms douteux et lignes
    illisibles écartés."""
    out: List[Dict[str, Any]] = []
    for ligne in (_lire_court(d / "images.txt") or "").splitlines():
        mots = ligne.split()
        # [0-9] et non isdigit() : un chiffre Unicode (« ² ») passerait isdigit() puis ferait échouer int() (500)
        if len(mots) not in (3, 4) or not _RE_IMAGE.fullmatch(mots[0]) or not re.fullmatch(r"[0-9]{1,15}", mots[1]) \
                or not re.fullmatch(r"[0-9a-f]{64}", mots[2]) or (len(mots) == 4 and not re.fullmatch(r"[0-9]{1,15}", mots[3])):
            continue
        out.append({"nom": mots[0], "taille": int(mots[1]), "sha256": mots[2],
                    "signee": (d / (mots[0] + ".sig")).is_file(),
                    "taille_brute": int(mots[3]) if len(mots) == 4 else None})
        if len(out) >= 50:
            break
    return out


_CLE_USB = "cle-usb.img.gz"
_RE_CMD_USB = re.compile(r"^(tester|autoflash)\t([ -~]{1,200})$")
_RE_SHA_USB = re.compile(r"^sha256\t([0-9a-f]{64})$")
# Rôle et commande recoupés : une ligne « tester » qui chargerait autoflash.scr serait affichée comme sans danger.
_SCRIPT_DU_ROLE = {"tester": "boot-usb.scr", "autoflash": "autoflash.scr"}


def _cle_usb(d: Path) -> Tuple[Optional[Dict[str, Any]], List[Dict[str, str]]]:
    """Clé USB « finale » publiée à côté du live (#3233, build-cle-finale.sh) : l'image système qui tourne sur la clé
    pour les tests, et qui s'écrit sur l'eMMC (autoflash). cle-usb.txt : « sha256<TAB>empreinte » et
    « tester|autoflash<TAB>commande » ; tout autre rôle, toute commande qui ne charge pas le script de son rôle et toute
    ligne trop longue ou non imprimable sont écartés."""
    f = d / _CLE_USB
    try:
        if d.is_symlink() or not f.is_file():
            return None, []
        taille = f.stat().st_size
    except OSError as e:
        logging.getLogger("secubox.netboot").warning("clé USB du live %s illisible : %s", d.name, e)
        return None, []
    cle: Dict[str, Any] = {"nom": _CLE_USB, "taille": taille, "signee": (d / (_CLE_USB + ".sig")).is_file(),
                           "sha256": None, "cle_publique": (d / "netboot-image.pub").is_file()}
    cmds = []
    for ligne in (_lire_court(d / "cle-usb.txt") or "").splitlines():
        m = _RE_SHA_USB.fullmatch(ligne)
        if m:
            cle["sha256"] = m.group(1)
            continue
        m = _RE_CMD_USB.fullmatch(ligne)
        if m and _SCRIPT_DU_ROLE[m.group(1)] in m.group(2) and len(cmds) < 4:
            cmds.append({"role": m.group(1), "commande": m.group(2)})
    return cle, cmds


def live_infos() -> List[Dict[str, Any]]:
    """Un live = un dossier TFTP qui porte un boot.cmd. Les commandes U-Boot à taper sont celles que le
    boot.cmd généré documente en tête (« #   … ») : la page dit exactement ce que la box exécutera."""
    lives: List[Dict[str, Any]] = []
    try:
        dossiers = sorted(p for p in TFTP_ROOT.iterdir()
                          if not p.is_symlink() and p.is_dir() and _RE_NOM_LIVE.fullmatch(p.name))
    except OSError:
        return lives
    for d in dossiers:
        texte = _lire_court(d / "boot.cmd")
        if texte is None:
            continue
        serveur = re.search(r"^setenv serverip (\S+)\s*$", texte, re.M)
        fetch = re.search(r"\bfetch=(http://\S+)/filesystem\.squashfs\b", texte)
        titre = re.search(r"^# SecuBox ([^\n—]{1,40}?) — live", texte, re.M)
        console = re.search(r"\bconsole=([A-Za-z0-9,]{1,32})\b", texte)
        cle, cmds_usb = _cle_usb(HTTP_ROOT / d.name)
        lives.append({
            "nom": d.name,
            "titre": titre.group(1) if titre else None,
            "console": console.group(1) if console else None,
            "usb": cle,
            "commandes_usb": cmds_usb,
            "serveur": serveur.group(1) if serveur else None,
            "http_base": fetch.group(1) if fetch else None,
            "commandes": re.findall(r"^#   (\S.*?)\s*$", texte, re.M),
            "squashfs": (HTTP_ROOT / d.name / "filesystem.squashfs").is_file(),
            "images": _images_live(HTTP_ROOT / d.name),
        })
    return lives


@router.get("/live")
async def live(user=Depends(require_jwt)):
    """Lives netboot servis par ce maître : commandes U-Boot, base HTTP, images eMMC signées."""
    return {"lives": await asyncio.to_thread(live_infos)}


# ── lot de flash (#3100) ─────────────────────────────────────────────────────

class FlashPrepare(BaseModel):
    nom: str
    mot_de_passe: Optional[str] = None


@router.post("/flash/prepare")
async def flash_prepare(body: FlashPrepare, user=Depends(require_jwt)):
    """Prépare le (re)flash de la box `nom` pour 24 h : seule une préparation autorise le code de
    reflash qui remplace la clé du pair de ce nom. Mot de passe facultatif (sinon la console du live
    le demande) ; s'il est donné, seule son empreinte argon2 est gardée."""
    if not lot.nom_valide(body.nom):
        raise HTTPException(400, "nom de box invalide")
    if body.mot_de_passe is not None and len(body.mot_de_passe) < 12:
        raise HTTPException(400, "mot de passe trop court (12 caractères au moins)")
    await asyncio.to_thread(lot.enregistrer_preparation, body.nom, body.mot_de_passe or None)
    try:
        await asyncio.to_thread(lot.audit, "flash_prepare", nom=body.nom,
                                avec_mot_de_passe=bool(body.mot_de_passe),
                                par=(user or {}).get("sub") if isinstance(user, dict) else None)
    except OSError:
        logging.getLogger("secubox.netboot").error("audit de la préparation de flash impossible")
    return {"ok": True, "nom": body.nom, "expire_dans": lot.DUREE_PREPARATION}


_LAN = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
_REFUSES = [ipaddress.ip_network(n) for n in ("10.100.0.0/24", "10.0.3.0/24", "10.10.0.0/24")]  # ponts conteneurs, maillage
_LOT_MAX, _LOT_FENETRE, _LOT_ADRESSES = 6, 3600, 1024
_LOT_COMPTEURS: Dict[str, List[float]] = {}


def _lan(adresse: str) -> bool:
    try:
        a = ipaddress.ip_address(adresse)
    except ValueError:
        return False
    return any(a in n for n in _LAN)


def _lot_admis(adresse: str, maintenant: Optional[float] = None) -> bool:
    """Au plus 6 lots par heure et par adresse (en mémoire)."""
    t = time.monotonic() if maintenant is None else maintenant
    for a in [a for a, v in _LOT_COMPTEURS.items() if not v or t - v[-1] >= _LOT_FENETRE]:
        del _LOT_COMPTEURS[a]
    if adresse not in _LOT_COMPTEURS:
        while len(_LOT_COMPTEURS) >= _LOT_ADRESSES:       # le plus ancien est évincé
            del _LOT_COMPTEURS[min(_LOT_COMPTEURS, key=lambda a: _LOT_COMPTEURS[a][-1])]
    vus = [x for x in _LOT_COMPTEURS.get(adresse, []) if t - x < _LOT_FENETRE]
    if len(vus) >= _LOT_MAX:
        _LOT_COMPTEURS[adresse] = vus
        return False
    vus.append(t)
    _LOT_COMPTEURS[adresse] = vus
    return True


def _adresse_serveur_valide(adresse: str) -> bool:
    """Adresse du maître admise dans un code : IPv4 privée, hors boucle locale, ponts et maillage."""
    try:
        a = ipaddress.ip_address(adresse)
    except ValueError:
        return False
    return (a.version == 4 and a.is_private and not a.is_loopback
            and not any(a in n for n in _REFUSES))


async def _adresse_serveur(request: Request, client: str) -> Optional[str]:
    """L'adresse du maître que le live a réellement jointe : $server_addr posé par le vhost :8099,
    sinon la source de la route vers le client (`ip route get`). None : sbx-mesh-invite choisira."""
    a = (request.headers.get("x-secubox-adresse-serveur") or "").strip()
    if _adresse_serveur_valide(a):
        return a
    r = await _run("ip", "-o", "route", "get", client, timeout=5)
    if r["rc"] == 0:
        mots = r["stdout"].split()
        if "src" in mots and mots.index("src") + 1 < len(mots):
            a = mots[mots.index("src") + 1]
            if _adresse_serveur_valide(a):
                return a
    return None


@router.get("/lot-flash")
async def lot_flash(nom: str, request: Request):
    """Lot signé pour le live en cours de flash. Servi par le port 8099 (LAN seulement, X-Real-IP posé par nginx)."""
    if request.headers.get("x-secubox-netboot-lot") != "1":     # posé par le seul vhost :8099
        raise HTTPException(404, "Not Found")
    adresse = request.headers.get("x-real-ip", "")
    if not _lan(adresse):
        raise HTTPException(403, "réservé au réseau local")
    if any(ipaddress.ip_address(adresse) in n for n in _REFUSES):
        try:
            await asyncio.to_thread(lot.audit, "lot_flash_refuse", adresse=adresse, raison="pont conteneur ou maillage")
        except OSError:
            pass
        raise HTTPException(403, "adresse non admise (conteneur ou maillage)")
    if not lot.nom_valide(nom):
        raise HTTPException(400, "nom de box invalide")
    if not _lot_admis(adresse):
        raise HTTPException(429, "trop de demandes")
    serveur = await _adresse_serveur(request, adresse)
    r = await _run(CTL_LOT, nom, *(("--adresse", serveur) if serveur else ()), timeout=45)
    if r["rc"] != 0:
        logging.getLogger("secubox.netboot").error("lot de flash refusé pour %s (rc=%s)", nom, r["rc"])
        raise HTTPException(502, "lot de flash indisponible")
    try:
        sortie = json.loads(r["stdout"])
    except ValueError:
        raise HTTPException(502, "lot de flash illisible")
    if not isinstance(sortie, dict) or not isinstance(sortie.get("lot"), str):
        raise HTTPException(502, "lot de flash illisible")
    flash = bool(sortie.pop("flash", False))       # la préparation a été prise par secubox-netboot-lot
    try:
        await asyncio.to_thread(lot.audit, "lot_flash_servi", nom=nom, adresse=adresse, flash=flash,
                                adresse_maitre=serveur)
    except OSError:
        logging.getLogger("secubox.netboot").error("audit du lot de flash impossible")
    return sortie


app.include_router(router)
